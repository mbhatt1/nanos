/*
 * Authority Kernel - Approval Workflow
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Provides human-in-the-loop approval for sensitive operations.
 * When policy returns AK_POLICY_REQUIRE_APPROVAL, the operation
 * is queued for external approval before proceeding.
 *
 * SECURITY: This implements defense-in-depth by requiring human
 * confirmation for potentially dangerous operations.
 */

#ifndef AK_APPROVAL_H
#define AK_APPROVAL_H

#include "ak_types.h"

/* ============================================================
 * APPROVAL STATUS
 * ============================================================ */

typedef enum ak_approval_status {
  AK_APPROVAL_PENDING,   /* Awaiting decision */
  AK_APPROVAL_GRANTED,   /* Approved by reviewer */
  AK_APPROVAL_DENIED,    /* Rejected by reviewer */
  AK_APPROVAL_TIMEOUT,   /* Expired without decision */
  AK_APPROVAL_CANCELLED, /* Cancelled by requester */
} ak_approval_status_t;

/* Forward declaration for closure types */
struct ak_approval_request;

/*
 * Closure type for approval decision callbacks.
 * Called when a decision is made (granted, denied, timeout, or cancelled).
 *
 * @param request   The approval request
 * @param status    The final status
 * @param data      User-provided callback data
 */
closure_type(ak_approval_decision_handler, void,
             struct ak_approval_request *request, ak_approval_status_t status,
             void *data);

/*
 * Closure type for approval notification callbacks.
 * Called when a new approval request is created.
 *
 * @param request   The newly created approval request
 */
closure_type(ak_approval_notify_handler, void,
             struct ak_approval_request *request);

/*
 * Closure type for iterating over approval requests.
 * Called for each matching request during enumeration.
 *
 * @param request   The approval request
 * @return          true to continue iteration, false to stop
 */
closure_type(ak_approval_iterator, boolean,
             struct ak_approval_request *request);

/* ============================================================
 * APPROVAL REQUEST
 * ============================================================ */

typedef struct ak_approval_request {
  /* Identity */
  u64 id; /* Unique request ID */
  u8 run_id[AK_TOKEN_ID_SIZE];
  u8 agent_id[AK_TOKEN_ID_SIZE];

  /* Operation details */
  u16 op;               /* Syscall number */
  buffer request_json;  /* Full request for review */
  buffer justification; /* Why this operation is needed */
  buffer context;       /* Additional context for reviewer */

  /* Timing */
  u64 requested_ms;
  u64 timeout_ms;
  u64 decided_ms; /* When decision was made (0 if pending) */

  /* Status */
  ak_approval_status_t status;

  /* Reviewer info (if decided) */
  char reviewer_id[64]; /* Who approved/denied */
  buffer reviewer_note; /* Optional note from reviewer */

  /* Callback - invoked when a decision is made */
  ak_approval_decision_handler on_decision;
  void *callback_data;

  /* Linkage for pending queue */
  struct ak_approval_request *next;
} ak_approval_request_t;

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

/* Initialize approval subsystem */
void ak_approval_init(heap h);

/* ============================================================
 * REQUEST MANAGEMENT
 * ============================================================ */

/*
 * Create approval request.
 *
 * @param h             Heap for allocation
 * @param ctx           Agent context requesting approval
 * @param req           Original request requiring approval
 * @param justification Why this operation is needed
 * @return              Request handle, or NULL on failure
 */
ak_approval_request_t *ak_approval_request(heap h, ak_agent_context_t *ctx,
                                           ak_request_t *req,
                                           buffer justification);

/*
 * Set callback for when decision is made.
 *
 * @param request       Approval request
 * @param cb            Callback closure (ak_approval_decision_handler)
 * @param data          User data passed to callback
 */
void ak_approval_set_callback(ak_approval_request_t *request,
                              ak_approval_decision_handler cb, void *data);

/*
 * Check approval status (non-blocking).
 *
 * @param request_id    Request ID to check
 * @return              Current status
 */
ak_approval_status_t ak_approval_check(u64 request_id);

/*
 * Wait for approval (blocking).
 *
 * @param request_id    Request ID to wait for
 * @param timeout_ms    Maximum wait time (0 = use request timeout)
 * @return              Final status
 */
ak_approval_status_t ak_approval_wait(u64 request_id, u64 timeout_ms);

/*
 * Cancel pending approval request.
 *
 * @param request_id    Request ID to cancel
 * @return              0 on success, error code on failure
 */
s64 ak_approval_cancel(u64 request_id);

/* ============================================================
 * DECISION MAKING (for supervisors/reviewers)
 * ============================================================ */

/*
 * Grant approval.
 *
 * @param request_id    Request ID to approve
 * @param reviewer_id   Identifier of reviewer
 * @param note          Optional note explaining decision
 * @return              0 on success, error code on failure
 */
s64 ak_approval_grant(u64 request_id, const char *reviewer_id, buffer note);

/*
 * Deny approval.
 *
 * @param request_id    Request ID to deny
 * @param reviewer_id   Identifier of reviewer
 * @param note          Optional note explaining decision
 * @return              0 on success, error code on failure
 */
s64 ak_approval_deny(u64 request_id, const char *reviewer_id, buffer note);

/* ============================================================
 * QUERY
 * ============================================================ */

/*
 * Get pending approvals for a run.
 *
 * @param run_id        Run ID to query (NULL for all)
 * @param cb            Iterator callback for each pending request
 *                      Returns true to continue, false to stop
 */
void ak_approval_list_pending(u8 *run_id, ak_approval_iterator cb);

/*
 * Get approval request by ID.
 *
 * @param request_id    Request ID to retrieve
 * @return              Request, or NULL if not found
 */
ak_approval_request_t *ak_approval_get(u64 request_id);

/*
 * Get count of pending approvals.
 */
u64 ak_approval_pending_count(void);

/* ============================================================
 * CONFIGURATION
 * ============================================================ */

/*
 * Set default timeout for approval requests.
 *
 * @param timeout_ms    Default timeout (0 = no timeout)
 */
void ak_approval_set_default_timeout(u64 timeout_ms);

/*
 * Set notification callback for new requests.
 *
 * Called when a new approval request is created, allowing
 * external systems to be notified (e.g., send alert).
 *
 * @param cb            Notification callback closure
 */
void ak_approval_set_notify_callback(ak_approval_notify_handler cb);

#endif /* AK_APPROVAL_H */
