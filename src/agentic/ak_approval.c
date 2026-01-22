/*
 * Authority Kernel - Approval Workflow Implementation
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Human-in-the-loop approval for sensitive operations.
 */

#include "ak_approval.h"
#include "ak_audit.h"
#include "ak_compat.h"

/* ============================================================
 * STATE
 * ============================================================ */

static struct {
  heap h;
  table pending; /* id -> ak_approval_request_t* */
  table by_run;  /* run_id -> list of requests */
  /*
   * CONCURRENCY FIX (BUG-013): next_id must use atomic operations.
   * Multiple threads may call ak_approval_request() concurrently.
   * Use volatile + __sync_fetch_and_add() for thread-safe increment.
   */
  volatile u64 next_id;
  u64 default_timeout_ms;
  ak_approval_notify_handler notify_callback;
  boolean initialized;
} approval_state;

/* Default timeout: 5 minutes */
#define AK_APPROVAL_DEFAULT_TIMEOUT_MS (5 * 60 * 1000)

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

void ak_approval_init(heap h) {
  if (!h)
    return;
  approval_state.h = h;
  approval_state.pending = allocate_table(h, identity_key, pointer_equal);
  approval_state.by_run = allocate_table(h, key_from_pointer, pointer_equal);
  if (approval_state.pending == INVALID_ADDRESS ||
      approval_state.by_run == INVALID_ADDRESS)
    return;
  approval_state.next_id = 1;
  approval_state.default_timeout_ms = AK_APPROVAL_DEFAULT_TIMEOUT_MS;
  approval_state.notify_callback = 0;
  approval_state.initialized = true;
}

/* ============================================================
 * REQUEST MANAGEMENT
 * ============================================================ */

ak_approval_request_t *ak_approval_request(heap h, ak_agent_context_t *ctx,
                                           ak_request_t *req,
                                           buffer justification) {
  if (!approval_state.initialized)
    return 0;

  if (!ctx || !req)
    return 0;

  ak_approval_request_t *ar = allocate(h, sizeof(ak_approval_request_t));
  if (ar == INVALID_ADDRESS)
    return 0;

  runtime_memset((u8 *)ar, 0, sizeof(ak_approval_request_t));

  /* Identity - use atomic increment for thread safety (BUG-013 fix) */
  ar->id = __sync_fetch_and_add(&approval_state.next_id, 1);
  runtime_memcpy(ar->run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
  runtime_memcpy(ar->agent_id, ctx->pid, AK_TOKEN_ID_SIZE);

  /* Operation details */
  ar->op = req->op;

  /* Clone request JSON */
  if (req->args) {
    ar->request_json = allocate_buffer(h, buffer_length(req->args));
    if (ar->request_json == INVALID_ADDRESS) {
      deallocate(h, ar, sizeof(ak_approval_request_t));
      return 0;
    }
    buffer_write(ar->request_json, buffer_ref(req->args, 0),
                 buffer_length(req->args));
  }

  /* Clone justification */
  if (justification) {
    ar->justification = allocate_buffer(h, buffer_length(justification));
    if (ar->justification == INVALID_ADDRESS) {
      if (ar->request_json)
        deallocate_buffer(ar->request_json);
      deallocate(h, ar, sizeof(ak_approval_request_t));
      return 0;
    }
    buffer_write(ar->justification, buffer_ref(justification, 0),
                 buffer_length(justification));
  }

  /* Timing */
  ar->requested_ms = now(CLOCK_ID_MONOTONIC) / MILLION;
  ar->timeout_ms = approval_state.default_timeout_ms;
  ar->decided_ms = 0;

  /* Status */
  ar->status = AK_APPROVAL_PENDING;

  /* Add to pending table */
  table_set(approval_state.pending, (void *)ar->id, ar);

  /* Log the approval request */
  /* ak_audit_log_approval_request(ar); */

  /* Notify external systems of the new approval request */
  if (approval_state.notify_callback)
    apply(approval_state.notify_callback, ar);

  return ar;
}

void ak_approval_set_callback(ak_approval_request_t *request,
                              ak_approval_decision_handler cb, void *data) {
  if (!request)
    return;

  request->on_decision = cb;
  request->callback_data = data;
}

ak_approval_status_t ak_approval_check(u64 request_id) {
  if (!approval_state.initialized)
    return AK_APPROVAL_TIMEOUT;

  ak_approval_request_t *ar =
      table_find(approval_state.pending, (void *)request_id);
  if (!ar)
    return AK_APPROVAL_TIMEOUT; /* Not found, treat as expired */

  /* Check for timeout */
  if (ar->status == AK_APPROVAL_PENDING && ar->timeout_ms > 0) {
    u64 now_ms = now(CLOCK_ID_MONOTONIC) / MILLION;
    if (ar->requested_ms > 0 && now_ms > ar->requested_ms + ar->timeout_ms) {
      ar->status = AK_APPROVAL_TIMEOUT;
      ar->decided_ms = now_ms;

      /* Invoke decision callback with timeout status */
      if (ar->on_decision)
        apply(ar->on_decision, ar, AK_APPROVAL_TIMEOUT, ar->callback_data);
    }
  }

  return ar->status;
}

ak_approval_status_t ak_approval_wait(u64 request_id, u64 timeout_ms) {
  /*
   * Non-blocking poll implementation (production design).
   *
   * This function implements a non-blocking polling approach which is the
   * preferred design for the approval workflow. Blocking would tie up kernel
   * resources and create potential deadlock scenarios in async environments.
   *
   * Usage patterns:
   * 1. Callback-based (recommended): Use ak_approval_set_callback() for async
   *    notification when the decision is made. The callback will be invoked
   *    with the final status.
   *
   * 2. Polling-based: Call ak_approval_check() or this function periodically
   *    to check the current status. The timeout_ms parameter here does NOT
   *    cause blocking; it only updates the request's timeout if provided.
   *
   * The non-blocking design integrates well with event-driven kernels and
   * avoids resource starvation issues that blocking waits can cause.
   */
  if (!approval_state.initialized)
    return AK_APPROVAL_TIMEOUT;

  ak_approval_request_t *ar =
      table_find(approval_state.pending, (void *)request_id);
  if (!ar)
    return AK_APPROVAL_TIMEOUT;

  /* Update request timeout if caller specified a different value */
  if (timeout_ms > 0 && timeout_ms != ar->timeout_ms)
    ar->timeout_ms = timeout_ms;

  /* Check and return current status (triggers timeout callback if expired) */
  return ak_approval_check(request_id);
}

s64 ak_approval_cancel(u64 request_id) {
  if (!approval_state.initialized)
    return -1;

  ak_approval_request_t *ar =
      table_find(approval_state.pending, (void *)request_id);
  if (!ar)
    return AK_E_CAP_MISSING;

  if (ar->status != AK_APPROVAL_PENDING)
    return AK_E_POLICY_DENY; /* Already decided */

  ar->status = AK_APPROVAL_CANCELLED;
  ar->decided_ms = now(CLOCK_ID_MONOTONIC) / MILLION;

  /* Invoke decision callback with cancelled status */
  if (ar->on_decision)
    apply(ar->on_decision, ar, AK_APPROVAL_CANCELLED, ar->callback_data);

  return 0;
}

/* ============================================================
 * DECISION MAKING
 * ============================================================ */

static s64 make_decision(u64 request_id, ak_approval_status_t decision,
                         const char *reviewer_id, buffer note) {
  if (!approval_state.initialized)
    return -1;

  ak_approval_request_t *ar =
      table_find(approval_state.pending, (void *)request_id);
  if (!ar)
    return AK_E_CAP_MISSING;

  if (ar->status != AK_APPROVAL_PENDING)
    return AK_E_POLICY_DENY; /* Already decided */

  /* Set status */
  ar->status = decision;
  ar->decided_ms = now(CLOCK_ID_MONOTONIC) / MILLION;

  /* Copy reviewer info */
  if (reviewer_id) {
    u64 len = runtime_strlen(reviewer_id);
    if (len >= sizeof(ar->reviewer_id))
      len = sizeof(ar->reviewer_id) - 1;
    runtime_memcpy(ar->reviewer_id, reviewer_id, len);
    ar->reviewer_id[len] = '\0';
  }

  /* Clone note */
  if (note) {
    ar->reviewer_note = allocate_buffer(approval_state.h, buffer_length(note));
    if (ar->reviewer_note != INVALID_ADDRESS)
      buffer_write(ar->reviewer_note, buffer_ref(note, 0), buffer_length(note));
  }

  /* Log the decision */
  /* ak_audit_log_approval_decision(ar); */

  /* Invoke decision callback with the final status */
  if (ar->on_decision)
    apply(ar->on_decision, ar, decision, ar->callback_data);

  return 0;
}

s64 ak_approval_grant(u64 request_id, const char *reviewer_id, buffer note) {
  return make_decision(request_id, AK_APPROVAL_GRANTED, reviewer_id, note);
}

s64 ak_approval_deny(u64 request_id, const char *reviewer_id, buffer note) {
  return make_decision(request_id, AK_APPROVAL_DENIED, reviewer_id, note);
}

/* ============================================================
 * QUERY
 * ============================================================ */

void ak_approval_list_pending(u8 *run_id, ak_approval_iterator cb) {
  if (!approval_state.initialized || !cb)
    return;

  table_foreach(approval_state.pending, id, ar_ptr) {
    (void)id; /* unused - we iterate by value */
    ak_approval_request_t *ar = (ak_approval_request_t *)ar_ptr;
    if (!ar)
      continue;

    /* Skip if not pending */
    if (ar->status != AK_APPROVAL_PENDING)
      continue;

    /* Filter by run_id if provided */
    if (run_id) {
      if (runtime_memcmp(ar->run_id, run_id, AK_TOKEN_ID_SIZE) != 0)
        continue;
    }

    /* Invoke iterator callback; stop if it returns false */
    if (!apply(cb, ar))
      break;
  }
}

ak_approval_request_t *ak_approval_get(u64 request_id) {
  if (!approval_state.initialized)
    return 0;

  return table_find(approval_state.pending, (void *)request_id);
}

u64 ak_approval_pending_count(void) {
  if (!approval_state.initialized)
    return 0;

  u64 count = 0;
  table_foreach(approval_state.pending, id, ar_ptr) {
    (void)id; /* unused - we iterate by value */
    ak_approval_request_t *ar = (ak_approval_request_t *)ar_ptr;
    if (ar->status == AK_APPROVAL_PENDING)
      count++;
  }
  return count;
}

void ak_approval_free(u64 request_id) {
  if (!approval_state.initialized)
    return;

  ak_approval_request_t *ar =
      table_find(approval_state.pending, (void *)request_id);
  if (!ar)
    return;

  /* Remove from pending table */
  table_set(approval_state.pending, (void *)request_id, 0);

  /* Deallocate buffers */
  if (ar->request_json)
    deallocate_buffer(ar->request_json);
  if (ar->justification)
    deallocate_buffer(ar->justification);
  if (ar->reviewer_note)
    deallocate_buffer(ar->reviewer_note);

  /* Deallocate the request structure */
  deallocate(approval_state.h, ar, sizeof(ak_approval_request_t));
}

/* ============================================================
 * CONFIGURATION
 * ============================================================ */

void ak_approval_set_default_timeout(u64 timeout_ms) {
  if (!approval_state.initialized)
    return;
  approval_state.default_timeout_ms = timeout_ms;
}

void ak_approval_set_notify_callback(ak_approval_notify_handler cb) {
  if (!approval_state.initialized)
    return;
  approval_state.notify_callback = cb;
}
