/*
 * Authority Kernel - Deny UX Interface
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Owner: Agent C
 *
 * This file defines the user experience interfaces for handling
 * denied operations, including:
 *   - AK_SYS_LAST_ERROR syscall for retrieving last denial info
 *   - Rate-limited denial logging
 *   - Errno mapping for POSIX compatibility
 *   - Suggested policy snippet generation
 *
 * The goal is to make denial experiences actionable - users should
 * understand WHY something was denied and HOW to fix it.
 */

#ifndef AK_DENY_UX_H
#define AK_DENY_UX_H

#include "ak_effects.h"

/* ============================================================
 * SYSCALL NUMBERS (from ak_effects.h, repeated for clarity)
 * ============================================================ */

/* These are defined in ak_effects.h but repeated here for reference:
 *
 * #define AK_SYS_LAST_ERROR       1040
 * #define AK_SYS_TRACE_RING_READ  1041
 * #define AK_SYS_POLICY_SUGGEST   1042
 * #define AK_SYS_SET_MODE         1043
 * #define AK_SYS_GET_SUGGESTIONS  1044
 */

/* Record control commands for ak_sys_record_control */
#define AK_RECORD_CMD_ENABLE    0   /* Enable recording (AK_MODE_RECORD) */
#define AK_RECORD_CMD_DISABLE   1   /* Disable recording (AK_MODE_SOFT) */
#define AK_RECORD_CMD_CLEAR     2   /* Clear recorded effects */
#define AK_RECORD_CMD_COUNT     3   /* Get count of recorded effects */

/* ============================================================
 * LAST ERROR JSON FORMAT
 * ============================================================
 *
 * AK_SYS_LAST_ERROR returns JSON in this format:
 *
 * {
 *   "op": "FS_OPEN",
 *   "target": "/etc/passwd",
 *   "reason": "NO_CAP",
 *   "reason_code": 2,
 *   "errno": 13,
 *   "missing_cap": "fs.read",
 *   "suggested_snippet": "[[fs.allow]]\npath = \"/etc/passwd\"\nread = true",
 *   "trace_id": "abc123def456",
 *   "timestamp_ms": 1705123456789,
 *   "detail": "No matching fs.read capability for path"
 * }
 */

/* Maximum size of JSON output from AK_SYS_LAST_ERROR */
#define AK_LAST_ERROR_MAX_JSON  2048

/* ============================================================
 * DENY UX SYSCALL HANDLERS
 * ============================================================ */

/*
 * ak_sys_last_error - Get information about the last denied operation.
 *
 * Returns JSON describing the most recent denial for the current thread.
 * This allows applications to provide actionable error messages to users.
 *
 * Parameters:
 *   buf     - Buffer to receive JSON response
 *   buf_len - Size of buffer
 *
 * Returns:
 *   >= 0    - Number of bytes written to buf
 *   -EINVAL - Invalid parameters
 *   -ENOENT - No denial recorded
 *   -ERANGE - Buffer too small (partial data written)
 *
 * The returned JSON includes:
 *   - op: Operation type (e.g., "FS_OPEN", "NET_CONNECT")
 *   - target: Canonical target that was denied
 *   - reason: Human-readable reason code
 *   - reason_code: Numeric reason for programmatic handling
 *   - errno: POSIX errno equivalent
 *   - missing_cap: What capability was missing
 *   - suggested_snippet: Copy-paste snippet for ak.toml
 *   - trace_id: Correlation ID for logs
 *   - timestamp_ms: When the denial occurred
 *   - detail: Detailed explanation
 */
sysreturn ak_sys_last_error(u8 *buf, u64 buf_len);

/*
 * ak_sys_trace_ring_read - Read from the trace ring buffer.
 *
 * Returns recent authorization decisions (both allows and denies)
 * from a bounded ring buffer. Useful for debugging and auditing.
 *
 * Parameters:
 *   buf     - Buffer to receive entries
 *   buf_len - Size of buffer
 *   offset  - Pointer to offset (updated on return)
 *
 * Returns:
 *   >= 0    - Number of bytes written
 *   -EINVAL - Invalid parameters
 *   -EAGAIN - No new entries
 *
 * Note: This is rate-limited to prevent DoS.
 */
sysreturn ak_sys_trace_ring_read(u8 *buf, u64 buf_len, u64 *offset);

/*
 * ak_sys_policy_suggest - Get accumulated policy suggestions.
 *
 * When running in RECORD mode, the kernel accumulates denied
 * operations and generates policy suggestions. This syscall
 * retrieves those suggestions.
 *
 * Parameters:
 *   buf     - Buffer to receive suggestions (TOML format)
 *   buf_len - Size of buffer
 *
 * Returns:
 *   >= 0    - Number of bytes written
 *   -EINVAL - Invalid parameters
 *   -ENOENT - No suggestions recorded
 *   -ENOSYS - RECORD mode not enabled
 */
sysreturn ak_sys_policy_suggest(u8 *buf, u64 buf_len);

/*
 * ak_sys_set_mode - Set the routing mode.
 *
 * Parameters:
 *   mode - New mode (AK_MODE_OFF, AK_MODE_SOFT, AK_MODE_HARD, AK_MODE_RECORD)
 *
 * Returns:
 *   0       - Success
 *   -EINVAL - Invalid mode
 *   -EPERM  - Mode change not permitted
 */
sysreturn ak_sys_set_mode(u64 mode);

/*
 * ak_sys_get_suggestions - Get accumulated policy suggestions from record mode.
 *
 * When the context is in AK_MODE_RECORD, denied effects are recorded but
 * allowed to proceed. This syscall retrieves a complete policy document
 * that would allow all recorded effects.
 *
 * Parameters:
 *   buf     - Buffer to receive policy document
 *   buf_len - Size of buffer
 *   format  - Output format: 0 = JSON (policy.json), 1 = TOML (ak.toml)
 *
 * Returns:
 *   >= 0    - Number of bytes written
 *   -EINVAL - Invalid parameters
 *   -EPERM  - No context or record mode not initialized
 *   -ENOENT - No effects recorded
 *   -ERANGE - Buffer too small
 */
sysreturn ak_sys_get_suggestions(u8 *buf, u64 buf_len, u64 format);

/*
 * ak_sys_record_control - Control record mode state.
 *
 * Parameters:
 *   cmd - Command to execute:
 *         AK_RECORD_CMD_ENABLE  (0) - Enable recording (AK_MODE_RECORD)
 *         AK_RECORD_CMD_DISABLE (1) - Disable recording (AK_MODE_SOFT)
 *         AK_RECORD_CMD_CLEAR   (2) - Clear recorded effects
 *         AK_RECORD_CMD_COUNT   (3) - Get count of recorded effects
 *
 * Returns:
 *   >= 0    - Success (for COUNT, returns number of recorded effects)
 *   -EINVAL - Invalid command
 *   -EPERM  - No context
 *   -ENOMEM - Allocation failed (for ENABLE)
 */
sysreturn ak_sys_record_control(u64 cmd);

/* ============================================================
 * DENY LOGGING
 * ============================================================ */

/*
 * Rate limiting configuration for deny logging.
 *
 * To prevent log flooding, denials are rate-limited per effect type.
 * The first N denials within a window are logged, then suppressed.
 */

/* Rate limit window in nanoseconds (1 second) */
#define AK_DENY_LOG_WINDOW_NS   (1000000000ULL)

/* Maximum denials to log per effect category per window */
#define AK_DENY_LOG_MAX_PER_CAT 10

/* Total maximum denials to log per window */
#define AK_DENY_LOG_MAX_TOTAL   50

/*
 * ak_deny_log_init - Initialize the deny logging subsystem.
 *
 * Called during ak_effects_init().
 */
void ak_deny_log_init(void);

/*
 * ak_deny_log_entry - Log a denial (rate-limited).
 *
 * Logs the denial if rate limits allow. Format:
 *   AK DENY <op> <target> missing <cap>. Fix: <snippet> (trace=<id>)
 *
 * Parameters:
 *   req      - The denied request
 *   decision - The denial decision
 *
 * Returns:
 *   true  - Entry was logged
 *   false - Rate-limited (not logged)
 */
boolean ak_deny_log_entry(const ak_effect_req_t *req,
                          const ak_decision_t *decision);

/*
 * ak_deny_log_get_suppressed - Get count of suppressed log entries.
 *
 * Returns number of denials that were not logged due to rate limiting
 * in the current window.
 */
u64 ak_deny_log_get_suppressed(void);

/*
 * ak_deny_log_reset - Reset rate limiting counters.
 *
 * Called when window expires or manually for testing.
 */
void ak_deny_log_reset(void);

/* ============================================================
 * ERRNO MAPPING
 * ============================================================ */

/*
 * ak_deny_to_errno - Map denial to appropriate POSIX errno.
 *
 * The mapping depends on both the effect type and the reason:
 *
 * Filesystem effects:
 *   - EACCES: Permission denied (missing capability)
 *   - EPERM: Operation not permitted (policy/revoked)
 *   - ENOSPC: Budget exceeded
 *
 * Network effects:
 *   - ECONNREFUSED: Connection refused (missing capability)
 *   - ENETUNREACH: Network unreachable (policy mismatch)
 *   - EAGAIN: Rate limited
 *
 * Tool/Agentic effects:
 *   - EPERM: Operation not permitted
 *   - ENOSPC: Budget exceeded
 *   - EAGAIN: Rate limited
 *
 * Parameters:
 *   op     - Effect operation type
 *   reason - Denial reason code
 *
 * Returns:
 *   Appropriate POSIX errno value
 */
int ak_deny_to_errno(ak_effect_op_t op, ak_deny_reason_t reason);

/* ============================================================
 * SUGGESTION GENERATION
 * ============================================================ */

/*
 * ak_suggest_for_fs - Generate policy suggestion for filesystem effect.
 *
 * Parameters:
 *   req     - The denied request
 *   buf     - Buffer for suggestion
 *   buf_len - Buffer size
 *
 * Returns:
 *   Number of bytes written (excluding null terminator)
 */
int ak_suggest_for_fs(const ak_effect_req_t *req, char *buf, u32 buf_len);

/*
 * ak_suggest_for_net - Generate policy suggestion for network effect.
 *
 * Parameters:
 *   req     - The denied request
 *   buf     - Buffer for suggestion
 *   buf_len - Buffer size
 *
 * Returns:
 *   Number of bytes written
 */
int ak_suggest_for_net(const ak_effect_req_t *req, char *buf, u32 buf_len);

/*
 * ak_suggest_for_tool - Generate policy suggestion for tool effect.
 *
 * Parameters:
 *   req     - The denied request
 *   buf     - Buffer for suggestion
 *   buf_len - Buffer size
 *
 * Returns:
 *   Number of bytes written
 */
int ak_suggest_for_tool(const ak_effect_req_t *req, char *buf, u32 buf_len);

/*
 * ak_suggest_for_infer - Generate policy suggestion for inference effect.
 *
 * Parameters:
 *   req     - The denied request
 *   buf     - Buffer for suggestion
 *   buf_len - Buffer size
 *
 * Returns:
 *   Number of bytes written
 */
int ak_suggest_for_infer(const ak_effect_req_t *req, char *buf, u32 buf_len);

/* ============================================================
 * TRACE RING BUFFER
 * ============================================================ */

/* Trace ring entry for recording authorization decisions */
typedef struct ak_trace_entry {
    u64 timestamp_ns;           /* When the decision was made */
    u64 trace_id;               /* Correlation ID */
    ak_effect_op_t op;          /* Operation type */
    boolean allowed;            /* Was it allowed? */
    ak_deny_reason_t reason;    /* If denied, why */
    char target[128];           /* Truncated target */
    char missing_cap[AK_MAX_CAPSTR];
} ak_trace_entry_t;

/* Trace ring configuration */
#define AK_TRACE_RING_SIZE      256     /* Number of entries */
#define AK_TRACE_RING_ENTRY_SIZE sizeof(ak_trace_entry_t)

/*
 * ak_trace_ring_init - Initialize the trace ring buffer.
 *
 * Parameters:
 *   h - Heap for allocation
 */
void ak_trace_ring_init(heap h);

/*
 * ak_trace_ring_push - Add an entry to the trace ring.
 *
 * Parameters:
 *   req      - The request
 *   decision - The decision
 */
void ak_trace_ring_push(const ak_effect_req_t *req,
                        const ak_decision_t *decision);

/*
 * ak_trace_ring_read - Read entries from the trace ring.
 *
 * Parameters:
 *   entries     - Array to receive entries
 *   max_entries - Maximum entries to read
 *   offset      - Starting offset (updated on return)
 *
 * Returns:
 *   Number of entries read
 */
u32 ak_trace_ring_read(ak_trace_entry_t *entries, u32 max_entries,
                       u64 *offset);

/* ============================================================
 * RECORD MODE SUGGESTIONS
 * ============================================================ */

/*
 * Record mode accumulates denied operations and generates
 * policy suggestions that can be exported.
 */

/*
 * ak_record_init - Initialize record mode.
 *
 * Parameters:
 *   h - Heap for allocation
 */
void ak_record_init(heap h);

/*
 * ak_record_deny - Record a denial for suggestion generation.
 *
 * Parameters:
 *   req      - The denied request
 *   decision - The denial decision
 */
void ak_record_deny(const ak_effect_req_t *req,
                    const ak_decision_t *decision);

/*
 * ak_record_export - Export accumulated suggestions as TOML.
 *
 * Parameters:
 *   buf     - Buffer for output
 *   buf_len - Buffer size
 *
 * Returns:
 *   Number of bytes written
 */
u64 ak_record_export(char *buf, u64 buf_len);

/*
 * ak_record_clear - Clear accumulated suggestions.
 */
void ak_record_clear(void);

/*
 * ak_record_count - Get number of accumulated denials.
 */
u32 ak_record_count(void);

/* ============================================================
 * DENY UX INITIALIZATION
 * ============================================================ */

/*
 * ak_deny_ux_init - Initialize the deny UX subsystem.
 *
 * Called during effects initialization.
 *
 * Parameters:
 *   h - Heap for allocations
 */
void ak_deny_ux_init(heap h);

/*
 * ak_deny_ux_shutdown - Shutdown the deny UX subsystem.
 */
void ak_deny_ux_shutdown(void);

/* ============================================================
 * HELPER: OPERATION NAME STRINGS
 * ============================================================ */

/*
 * ak_effect_op_to_string - Get string name for effect operation.
 *
 * Parameters:
 *   op - Effect operation
 *
 * Returns:
 *   Static string name (e.g., "FS_OPEN", "NET_CONNECT")
 */
const char *ak_effect_op_to_string(ak_effect_op_t op);

/*
 * ak_deny_reason_to_string - Get string name for denial reason.
 *
 * Parameters:
 *   reason - Denial reason code
 *
 * Returns:
 *   Static string name (e.g., "NO_CAP", "BUDGET_EXCEEDED")
 */
const char *ak_deny_reason_to_string(ak_deny_reason_t reason);

#endif /* AK_DENY_UX_H */
