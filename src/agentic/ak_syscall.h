/*
 * Authority Kernel - Syscall Dispatcher
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Central syscall handler implementing all four invariants:
 *   INV-1: No-Bypass (all effects through syscalls)
 *   INV-2: Capability (every effectful syscall validated)
 *   INV-3: Budget (admission control)
 *   INV-4: Log Commitment (audit before response)
 *
 * SECURITY CRITICAL: This is the enforcement boundary.
 * All agent requests pass through here.
 */

#ifndef AK_SYSCALL_H
#define AK_SYSCALL_H

#include "ak_audit.h"
#include "ak_capability.h"
#include "ak_heap.h"
#include "ak_ipc.h"
#include "ak_policy.h"
#include "ak_types.h"

/* ============================================================
 * SYSCALL DISPATCHER INITIALIZATION
 * ============================================================ */

/*
 * Initialize Authority Kernel subsystem.
 *
 * Must be called during kernel startup.
 * Initializes all components: capabilities, audit, heap, policy.
 */
void ak_init(heap h);

/*
 * Shutdown Authority Kernel subsystem.
 *
 * Flushes audit log, cleans up resources.
 */
void ak_shutdown(void);

/*
 * Main syscall handler for Authority Kernel syscalls (1024-1100).
 *
 * Called from the main syscall dispatcher when call number is in AK range.
 * Dispatches to appropriate handler based on syscall number.
 *
 * Returns: sysreturn (0 on success, negative errno on failure)
 */
sysreturn ak_syscall_handler(u64 call, u64 arg0, u64 arg1, u64 arg2, u64 arg3,
                             u64 arg4, u64 arg5);

/* ============================================================
 * AGENT CONTEXT MANAGEMENT
 * ============================================================ */

/*
 * Create agent context (called when agent connects).
 *
 * Each agent gets:
 *   - Unique PID
 *   - Initial capability set
 *   - Budget tracker
 *   - Sequence tracker
 */
ak_agent_context_t *ak_context_create(heap h, u8 *pid, ak_policy_t *policy);

/*
 * Destroy agent context (called on agent exit).
 *
 * SECURITY: Revokes all capabilities for the run.
 */
void ak_context_destroy(heap h, ak_agent_context_t *ctx);

/*
 * Create new run within agent context.
 *
 * Returns run_id for the new run.
 */
void ak_context_new_run(ak_agent_context_t *ctx, u8 *run_id_out);

/*
 * Get current run_id.
 */
void ak_context_get_run_id(ak_agent_context_t *ctx, u8 *run_id_out);

/*
 * Get root agent context (for network enforcement).
 *
 * Returns the singleton root context for the Nanos process.
 * Used by ak_net_enforce.c to check capabilities.
 *
 * Returns NULL if AK not initialized.
 */
ak_agent_context_t *ak_get_root_context(void);

/* ============================================================
 * MAIN SYSCALL DISPATCH
 * ============================================================
 * SECURITY CRITICAL: This is the single entry point.
 */

/*
 * Dispatch syscall request.
 *
 * Processing pipeline:
 *   1. Parse request
 *   2. Validate frame (anti-replay)
 *   3. Verify capability (INV-2)
 *   4. Check policy budget (INV-3)
 *   5. Execute operation
 *   6. Log to audit (INV-4)
 *   7. Return response
 *
 * Returns: response structure (caller must free)
 *
 * SECURITY: Response is ONLY returned after audit log sync.
 */
ak_response_t *ak_dispatch(ak_agent_context_t *ctx, ak_request_t *req);

/*
 * Dispatch from raw buffer (parses request first).
 */
ak_response_t *ak_dispatch_raw(ak_agent_context_t *ctx, buffer raw_request);

/* ============================================================
 * INDIVIDUAL SYSCALL HANDLERS
 * ============================================================
 * Internal handlers - not directly exposed.
 */

/* Heap operations */
ak_response_t *ak_handle_read(ak_agent_context_t *ctx, ak_request_t *req);
ak_response_t *ak_handle_alloc(ak_agent_context_t *ctx, ak_request_t *req);
ak_response_t *ak_handle_write(ak_agent_context_t *ctx, ak_request_t *req);
ak_response_t *ak_handle_delete(ak_agent_context_t *ctx, ak_request_t *req);
ak_response_t *ak_handle_query(ak_agent_context_t *ctx, ak_request_t *req);

/* Batch operations */
ak_response_t *ak_handle_batch(ak_agent_context_t *ctx, ak_request_t *req);
ak_response_t *ak_handle_commit(ak_agent_context_t *ctx, ak_request_t *req);

/* Tool/API calls */
ak_response_t *ak_handle_call(ak_agent_context_t *ctx, ak_request_t *req);
/* ak_handle_inference is declared in ak_inference.h */

/* Agent management */
ak_response_t *ak_handle_spawn(ak_agent_context_t *ctx, ak_request_t *req);
ak_response_t *ak_handle_send(ak_agent_context_t *ctx, ak_request_t *req);
ak_response_t *ak_handle_recv(ak_agent_context_t *ctx, ak_request_t *req);
ak_response_t *ak_handle_respond(ak_agent_context_t *ctx, ak_request_t *req);

/* Assertions */
ak_response_t *ak_handle_assert(ak_agent_context_t *ctx, ak_request_t *req);

/* ============================================================
 * CAPABILITY OPERATIONS
 * ============================================================ */

/*
 * Grant capability to agent.
 *
 * SECURITY: Only the kernel can grant root capabilities.
 * Agents can only delegate (attenuate) their own caps.
 */
s64 ak_grant_capability(ak_agent_context_t *ctx, ak_cap_type_t type,
                        const char *resource, const char **methods, u32 ttl_ms,
                        u32 rate_limit, u32 rate_window_ms);

/*
 * Revoke capability.
 */
void ak_revoke_capability(ak_agent_context_t *ctx, u8 *tid);

/*
 * Revoke all capabilities for current run.
 */
void ak_revoke_run(ak_agent_context_t *ctx);

/* ============================================================
 * RESPONSE HELPERS
 * ============================================================ */

/*
 * Create success response.
 */
ak_response_t *ak_response_success(heap h, ak_request_t *req, buffer result);

/*
 * Create error response.
 */
ak_response_t *ak_response_error(heap h, ak_request_t *req, s64 error_code);

/*
 * Free response.
 */
void ak_response_destroy(heap h, ak_response_t *res);

/* ============================================================
 * VALIDATION HELPERS
 * ============================================================ */

/*
 * Validate request structure.
 *
 * Checks:
 *   - Required fields present
 *   - Op code valid
 *   - PID/run_id match context
 */
s64 ak_validate_request(ak_agent_context_t *ctx, ak_request_t *req);

/*
 * Check anti-replay (sequence number).
 *
 * Returns:
 *   0           - Valid
 *   AK_E_REPLAY - Replay detected
 */
s64 ak_check_replay(ak_agent_context_t *ctx, ak_request_t *req);

/*
 * Validate capability for request.
 *
 * Returns:
 *   0                   - Valid
 *   AK_E_CAP_*          - Capability error
 */
s64 ak_validate_capability(ak_agent_context_t *ctx, ak_request_t *req);

/*
 * Check policy allows request.
 *
 * Returns:
 *   0                   - Allowed
 *   AK_E_POLICY_DENIED  - Denied
 *   AK_E_BUDGET_EXCEEDED - Over budget
 */
s64 ak_check_policy(ak_agent_context_t *ctx, ak_request_t *req);

/* ============================================================
 * AUDIT INTEGRATION
 * ============================================================ */

/*
 * Log request/response to audit log.
 *
 * SECURITY: Must complete before response is sent.
 */
s64 ak_log_operation(ak_agent_context_t *ctx, ak_request_t *req,
                     ak_response_t *res);

/* ============================================================
 * STATISTICS
 * ============================================================ */

typedef struct ak_dispatch_stats {
  u64 total_requests;
  u64 successful_requests;
  u64 failed_requests;
  u64 replay_attempts;
  u64 capability_failures;
  u64 policy_denials;
  u64 budget_exceeded;

  /* Per-op counts */
  u64 op_counts[16];
} ak_dispatch_stats_t;

void ak_get_dispatch_stats(ak_dispatch_stats_t *stats);

/* ============================================================
 * ERROR RECOVERY
 * ============================================================ */

/*
 * Handle agent crash/unexpected exit.
 *
 * SECURITY:
 *   - Revokes all capabilities for the run
 *   - Logs crash event
 *   - Cleans up pending transactions
 */
void ak_handle_agent_crash(ak_agent_context_t *ctx);

/*
 * Handle timeout (agent not responding).
 */
void ak_handle_agent_timeout(ak_agent_context_t *ctx);

#endif /* AK_SYSCALL_H */
