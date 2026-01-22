/*
 * Authority Kernel - Effects API
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * COORDINATOR-OWNED: This file defines the canonical effects interface.
 * ALL agents MUST code to these exact signatures.
 * NO changes without COORDINATOR approval.
 *
 * The Effects API is the single point of authority enforcement.
 * All effectful operations MUST flow through ak_authorize_and_execute().
 */

#ifndef AK_EFFECTS_H
#define AK_EFFECTS_H

#include "ak_types.h"

/* Forward declarations for network types (if not already defined) */
#ifndef _SYS_SOCKET_H
struct sockaddr;
#ifndef socklen_t
typedef u32 socklen_t;
#endif
#endif

/* Forward declaration for pid_t if not defined */
#ifndef pid_t
typedef s32 pid_t;
#endif

/* ============================================================
 * EFFECT OPERATION TYPES
 * ============================================================
 * Effect categories use high nibble:
 *   0x01xx - Filesystem
 *   0x02xx - Network
 *   0x03xx - Process
 *   0x04xx - Agentic (tools, wasm, inference)
 */

typedef enum ak_effect_op {
  /* Filesystem effects */
  AK_E_FS_OPEN = 0x0100,   /* Open file for read/write */
  AK_E_FS_UNLINK = 0x0101, /* Delete file */
  AK_E_FS_RENAME = 0x0102, /* Rename/move file */
  AK_E_FS_MKDIR = 0x0103,  /* Create directory */
  AK_E_FS_RMDIR = 0x0104,  /* Remove directory */
  AK_E_FS_STAT = 0x0105,   /* Stat file (may be unmediated) */

  /* Network effects */
  AK_E_NET_CONNECT = 0x0200,     /* Outbound TCP/UDP connection */
  AK_E_NET_DNS_RESOLVE = 0x0201, /* DNS resolution (P0 REQUIRED) */
  AK_E_NET_BIND = 0x0202,        /* Bind to local port */
  AK_E_NET_LISTEN = 0x0203,      /* Listen for incoming connections */
  AK_E_NET_ACCEPT = 0x0204,      /* Accept connection (may use listen cap) */

  /* Process effects (P2) */
  AK_E_PROC_SPAWN = 0x0300,  /* Fork/exec new process */
  AK_E_PROC_SIGNAL = 0x0301, /* Send signal to process */
  AK_E_PROC_WAIT = 0x0302,   /* Wait for child process */

  /* Agentic effects */
  AK_E_TOOL_CALL = 0x0400,   /* Execute registered tool */
  AK_E_WASM_INVOKE = 0x0401, /* Run WASM module */
  AK_E_INFER = 0x0402,       /* LLM inference request */
  AK_E_AGENT_SEND = 0x0403,  /* Send message to another agent */
} ak_effect_op_t;

/* ============================================================
 * BUFFER SIZE LIMITS
 * ============================================================
 * All buffers are bounded to prevent resource exhaustion.
 */

#define AK_MAX_TARGET 512  /* Max canonical target string */
#define AK_MAX_PARAMS 4096 /* Max params JSON size */
#define AK_MAX_CAPSTR 64   /* Max capability string (e.g., "fs.read") */
#define AK_MAX_SUGGEST 512 /* Max suggested snippet size */
#define AK_MAX_DETAIL 256  /* Max detail message size */

/* ============================================================
 * EFFECT REQUEST STRUCTURE
 * ============================================================
 * Input to ak_authorize_and_execute().
 * Contains all information needed for authorization decision.
 */

typedef struct ak_effect_req {
  /* Operation type */
  ak_effect_op_t op;

  /* Tracing */
  u64 trace_id; /* Unique ID for correlation */

  /* Identity */
  pid_t pid; /* Process ID */
  u64 tid;   /* Thread ID (or 0 if N/A) */

  /* Canonical target string (bounded):
   *
   * FS operations:
   *   - Absolute normalized path: "/app/data/file.txt"
   *   - No ".." or "." after normalization
   *   - Symlinks NOT resolved in P0 (lexical)
   *
   * NET_CONNECT:
   *   - IP form:  "ip:1.2.3.4:443"
   *   - DNS form: "dns:example.com:443"
   *   - IPv6:     "ip:[::1]:8080"
   *
   * NET_DNS_RESOLVE:
   *   - Domain only: "dns:example.com"
   *
   * NET_BIND/LISTEN:
   *   - "ip:0.0.0.0:8080" or "ip:[::]:8080"
   *
   * TOOL_CALL:
   *   - "tool:<name>:<version>" e.g., "tool:http_get:1.0"
   *
   * WASM_INVOKE:
   *   - "wasm:<module>:<function>"
   *
   * INFER:
   *   - "model:<name>:<version>" e.g., "model:gpt-4:latest"
   */
  char target[AK_MAX_TARGET];

  /* Operation-specific parameters (JSON, bounded) */
  u8 params[AK_MAX_PARAMS];
  u32 params_len;

  /* Budget request (for operations that consume resources) */
  struct {
    u64 cpu_ns;  /* CPU time budget (0 = no limit request) */
    u64 wall_ns; /* Wall time budget */
    u64 bytes;   /* Byte budget (I/O, memory) */
    u64 tokens;  /* Token budget (LLM) */
  } budget;

  /* Flags */
  u32 flags;
#define AK_REQ_FLAG_NONBLOCK 0x0001 /* Non-blocking operation */
#define AK_REQ_FLAG_NOAUDIT 0x0002  /* Skip audit (for data-plane) */
#define AK_REQ_FLAG_RECORD 0x0004   /* Record for suggestion even if denied */

} ak_effect_req_t;

/* ============================================================
 * DENY REASON CODES
 * ============================================================
 * Stable enum for programmatic handling of denials.
 */

typedef enum ak_deny_reason {
  AK_DENY_NONE = 0,             /* Not denied (internal) */
  AK_DENY_NO_POLICY = 1,        /* No policy loaded */
  AK_DENY_NO_CAP = 2,           /* Missing required capability */
  AK_DENY_CAP_EXPIRED = 3,      /* Capability has expired */
  AK_DENY_PATTERN_MISMATCH = 4, /* Target doesn't match any pattern */
  AK_DENY_BUDGET_EXCEEDED = 5,  /* Would exceed budget */
  AK_DENY_RATE_LIMITED = 6,     /* Rate limit exceeded */
  AK_DENY_TAINT = 7,            /* Taint policy violation */
  AK_DENY_REVOKED = 8,          /* Capability was revoked */
  AK_DENY_MODE = 9,             /* Operation not allowed in current mode */
  AK_DENY_BOOT_CAPSULE = 10,    /* Boot capsule restriction */
} ak_deny_reason_t;

/* ============================================================
 * AUTHORIZATION DECISION STRUCTURE
 * ============================================================
 * Output from ak_authorize_and_execute().
 * Contains decision and actionable information for denials.
 */

typedef struct ak_decision {
  /* The decision */
  boolean allow;

  /* Reason for denial (if !allow) */
  ak_deny_reason_t reason_code;

  /* POSIX errno equivalent for syscall returns */
  int errno_equiv;

  /* What capability was missing (for actionable denies) */
  char missing_cap[AK_MAX_CAPSTR];

  /* Suggested policy snippet (copy-paste into ak.toml) */
  char suggested_snippet[AK_MAX_SUGGEST];

  /* Trace ID (echoed from request) */
  u64 trace_id;

  /* Human-readable detail message */
  char detail[AK_MAX_DETAIL];

  /* Timing (for metrics) */
  u64 decision_ns; /* Time to make decision */

} ak_decision_t;

/* ============================================================
 * ROUTING MODES
 * ============================================================ */

typedef enum ak_mode {
  AK_MODE_OFF = 0,  /* Legacy minimal debug mode */
  AK_MODE_SOFT = 1, /* POSIX routed + enforced (DEFAULT) */
  AK_MODE_HARD = 2, /* Raw effectful syscalls denied */
  AK_MODE_RECORD =
      3, /* Record denials, allow operations for batch suggestions */
} ak_mode_t;

/* ============================================================
 * RECORD MODE - ACCUMULATE DENIALS FOR BATCH SUGGESTIONS
 * ============================================================
 * When mode is AK_MODE_RECORD, denied effects are recorded but
 * the operation is allowed to proceed. This enables running a
 * program to discover ALL effects it needs, then generating a
 * complete policy.
 */

typedef struct ak_recorded_effect {
  ak_effect_op_t op;               /* Operation type */
  char target[AK_MAX_TARGET];      /* Canonical target */
  char suggested_rule[256];        /* Suggested policy rule */
  u64 count;                       /* Times this effect was recorded */
  struct ak_recorded_effect *next; /* Linked list for hash bucket */
} ak_recorded_effect_t;

/* Forward declaration for record state */
struct ak_record_state;

/* ============================================================
 * LAST DENY STRUCTURE
 * ============================================================
 * Stored per-thread for AK_SYS_LAST_ERROR retrieval.
 */

typedef struct ak_last_deny {
  ak_effect_op_t op;
  char target[AK_MAX_TARGET];
  char missing_cap[AK_MAX_CAPSTR];
  char suggested_snippet[AK_MAX_SUGGEST];
  u64 trace_id;
  int errno_equiv;
  u64 timestamp_ns;
  ak_deny_reason_t reason;
} ak_last_deny_t;

/* ============================================================
 * CONTEXT STRUCTURE
 * ============================================================
 * Per-thread AK enforcement context.
 */

typedef struct ak_ctx {
  /* Link to existing agent context */
  ak_agent_context_t *agent;

  /* Current routing mode */
  ak_mode_t mode;

  /* Last denial (for AK_SYS_LAST_ERROR) */
  ak_last_deny_t last_deny;

  /* Policy (V2 deny-by-default) */
  struct ak_policy_v2 *policy;

  /* Boot capsule state */
  boolean boot_capsule_active;
  boolean boot_capsule_dropped;

  /* Trace ID counter */
  u64 trace_counter;

  /* Record mode accumulator (for suggestions) */
  struct ak_record_state *record;

} ak_ctx_t;

/* ============================================================
 * THE SINGLE AUTHORITY GATE
 * ============================================================
 *
 * ak_authorize_and_execute() is THE ONLY function through which
 * effectful operations may be authorized.
 *
 * Flow:
 *   1. Validate request structure
 *   2. Canonicalize target (if not already)
 *   3. Check policy for authorization
 *   4. If denied:
 *      a. Populate decision_out with reason + suggestion
 *      b. Update last_deny
 *      c. Rate-limited log message
 *      d. Return negative errno
 *   5. If allowed:
 *      a. Execute the operation (or return to caller for execution)
 *      b. Audit log (control-plane) or ring buffer (data-plane)
 *      c. Return success
 *
 * Parameters:
 *   ctx         - Per-thread AK context
 *   req         - Effect request (must have canonical target)
 *   decision_out - Authorization decision (always populated)
 *   retval_out  - Syscall return value (for allowed operations)
 *
 * Returns:
 *   0           - Authorized (retval_out has result)
 *   -EACCES     - Denied (permission)
 *   -EPERM      - Denied (capability)
 *   -ECONNREFUSED - Denied (network)
 *   -EINVAL     - Invalid request
 *   Other       - Operation-specific error
 */
int ak_authorize_and_execute(ak_ctx_t *ctx, const ak_effect_req_t *req,
                             ak_decision_t *decision_out, long *retval_out);

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

/*
 * Initialize effects subsystem.
 *
 * PRECONDITIONS:
 *   - h must be a valid heap
 *   - Must be called exactly once before any other effects functions
 *
 * POSTCONDITIONS:
 *   - Effects subsystem is ready for use
 *   - Global statistics are zeroed
 *
 * Parameters:
 *   h - Heap for internal allocations (must not be NULL or INVALID_ADDRESS)
 */
void ak_effects_init(heap h);

/*
 * Shutdown effects subsystem.
 *
 * PRECONDITIONS:
 *   - ak_effects_init() was called successfully
 *
 * POSTCONDITIONS:
 *   - All internal state is cleaned up
 *   - No further effects operations are possible
 */
void ak_effects_shutdown(void);

/* ============================================================
 * CONTEXT MANAGEMENT
 * ============================================================ */

/*
 * Get context for current thread.
 *
 * RETURNS:
 *   - Current thread's AK context, or NULL if not set
 *
 * Thread safety: Safe to call from any thread.
 */
ak_ctx_t *ak_ctx_current(void);

/*
 * Create new context.
 *
 * PRECONDITIONS:
 *   - h must be valid heap or NULL (uses module default)
 *
 * POSTCONDITIONS:
 *   - Returns valid context or NULL on failure
 *   - Context is NOT automatically set as current
 *
 * Parameters:
 *   h     - Heap for allocation (may be NULL to use default)
 *   agent - Agent context to link to (may be NULL)
 *
 * Returns:
 *   New context on success, NULL on allocation failure
 *
 * ERRORS:
 *   Returns NULL if heap allocation fails
 */
ak_ctx_t *ak_ctx_create(heap h, ak_agent_context_t *agent);

/*
 * Destroy context.
 *
 * PRECONDITIONS:
 *   - ctx may be NULL (no-op)
 *   - If non-NULL, ctx must be valid context from ak_ctx_create()
 *
 * POSTCONDITIONS:
 *   - ctx memory is freed and zeroed
 *   - ctx must not be used after this call
 *   - If ctx was current thread's context, it is cleared
 *
 * Parameters:
 *   h   - Heap used for allocation (or NULL for auto)
 *   ctx - Context to destroy (may be NULL)
 *
 * SECURITY: Clears sensitive data before free.
 */
void ak_ctx_destroy(heap h, ak_ctx_t *ctx);

/*
 * Set current context for thread.
 *
 * PRECONDITIONS:
 *   - ctx may be NULL (clears current context)
 *   - If non-NULL, ctx must be valid
 *
 * POSTCONDITIONS:
 *   - Calling thread's context is set to ctx
 *
 * Parameters:
 *   ctx - Context to set (NULL to clear)
 *
 * Thread safety: Only affects calling thread.
 */
void ak_ctx_set_current(ak_ctx_t *ctx);

/*
 * Set routing mode.
 *
 * PRECONDITIONS:
 *   - ctx must be valid context (NULL is no-op)
 *   - mode must be valid AK_MODE_* value
 *
 * POSTCONDITIONS:
 *   - ctx->mode is updated to new mode
 *   - AK_MODE_OFF only allowed if CONFIG_AK_ALLOW_MODE_OFF defined
 *
 * Parameters:
 *   ctx  - Context to modify (NULL is no-op)
 *   mode - New routing mode (AK_MODE_OFF, AK_MODE_SOFT, AK_MODE_HARD)
 *
 * ERRORS:
 *   Silently ignores invalid mode or NULL ctx
 */
void ak_ctx_set_mode(ak_ctx_t *ctx, ak_mode_t mode);

/*
 * Get current mode.
 *
 * PRECONDITIONS:
 *   - ctx may be NULL
 *
 * RETURNS:
 *   - ctx->mode if ctx is valid
 *   - AK_MODE_OFF if ctx is NULL
 *
 * Parameters:
 *   ctx - Context to query (may be NULL)
 */
ak_mode_t ak_ctx_get_mode(ak_ctx_t *ctx);

/* ============================================================
 * BOOT CAPSULE
 * ============================================================ */

/* Check if boot capsule is still active */
boolean ak_ctx_boot_capsule_active(ak_ctx_t *ctx);

/* Drop boot capsule (after policy load) */
void ak_ctx_drop_boot_capsule(ak_ctx_t *ctx);

/* ============================================================
 * TRACE ID GENERATION
 * ============================================================ */

/* Generate new trace ID */
u64 ak_trace_id_generate(ak_ctx_t *ctx);

/* ============================================================
 * EFFECT REQUEST BUILDERS
 * ============================================================
 * Helper functions to build effect requests from syscall arguments.
 */

/* File operations */
int ak_effect_from_open(ak_effect_req_t *req, ak_ctx_t *ctx, const char *path,
                        int flags, int mode);
int ak_effect_from_openat(ak_effect_req_t *req, ak_ctx_t *ctx, int dirfd,
                          const char *path, int flags, int mode);
int ak_effect_from_unlink(ak_effect_req_t *req, ak_ctx_t *ctx,
                          const char *path);
int ak_effect_from_rename(ak_effect_req_t *req, ak_ctx_t *ctx,
                          const char *oldpath, const char *newpath);
int ak_effect_from_mkdir(ak_effect_req_t *req, ak_ctx_t *ctx, const char *path,
                         int mode);

/* Network operations */
int ak_effect_from_connect(ak_effect_req_t *req, ak_ctx_t *ctx,
                           const struct sockaddr *addr, socklen_t addrlen);
int ak_effect_from_bind(ak_effect_req_t *req, ak_ctx_t *ctx,
                        const struct sockaddr *addr, socklen_t addrlen);
int ak_effect_from_listen(ak_effect_req_t *req, ak_ctx_t *ctx, int fd,
                          int backlog);
int ak_effect_from_dns_resolve(ak_effect_req_t *req, ak_ctx_t *ctx,
                               const char *hostname);

/* Process operations */
int ak_effect_from_spawn(ak_effect_req_t *req, ak_ctx_t *ctx,
                         const char *program, const char **argv, u32 flags);
int ak_effect_from_signal(ak_effect_req_t *req, ak_ctx_t *ctx, pid_t target_pid,
                          int signum);
int ak_effect_from_wait(ak_effect_req_t *req, ak_ctx_t *ctx, pid_t target_pid,
                        int options);

/* Agentic operations */
int ak_effect_from_tool_call(ak_effect_req_t *req, ak_ctx_t *ctx,
                             const char *tool_name, const char *version,
                             const u8 *args, u32 args_len);
int ak_effect_from_wasm_invoke(ak_effect_req_t *req, ak_ctx_t *ctx,
                               const char *module, const char *function,
                               const u8 *args, u32 args_len);
int ak_effect_from_infer(ak_effect_req_t *req, ak_ctx_t *ctx, const char *model,
                         const char *version, u64 max_tokens);

/* ============================================================
 * CANONICALIZATION
 * ============================================================ */

/* Canonicalize filesystem path (relative -> absolute, normalize) */
int ak_canonicalize_path(const char *path, char *out, u32 out_len,
                         const char *cwd);

/* Canonicalize network address to target string */
int ak_canonicalize_sockaddr(const struct sockaddr *addr, socklen_t len,
                             char *out, u32 out_len);

/* ============================================================
 * DENY UX
 * ============================================================ */

/* Get last denial for current thread */
const ak_last_deny_t *ak_get_last_deny(ak_ctx_t *ctx);

/* Clear last denial */
void ak_clear_last_deny(ak_ctx_t *ctx);

/* Generate suggested snippet for an effect */
void ak_generate_suggestion(const ak_effect_req_t *req, char *snippet,
                            u32 max_len);

/* ============================================================
 * HARD MODE SUPPORT
 * ============================================================
 * In HARD mode (AK_MODE_HARD), raw effectful syscalls are denied.
 * Only syscalls made through the AK effects API are allowed.
 *
 * These functions manage a per-thread flag that indicates whether
 * the current syscall is part of an authorized AK API call.
 */

/*
 * Check if currently executing within an authorized effect.
 *
 * Used by routing functions to determine if a syscall should be
 * allowed in HARD mode.
 *
 * RETURNS:
 *   true  - Currently inside ak_authorize_and_execute() after authorization
 *   false - Raw syscall not through AK API
 */
boolean ak_is_in_authorized_effect(void);

/*
 * Set the authorized effect flag.
 *
 * Called by ak_authorize_and_execute() to mark that subsequent
 * syscalls are authorized.
 *
 * Parameters:
 *   value - true when entering authorized execution, false when exiting
 */
void ak_set_in_authorized_effect(boolean value);

/* ============================================================
 * SYSCALL NUMBERS (NEW)
 * ============================================================ */

#define AK_SYS_LAST_ERROR 1040      /* Get last deny info */
#define AK_SYS_TRACE_RING_READ 1041 /* Read trace ring (optional) */
#define AK_SYS_POLICY_SUGGEST 1042  /* Get suggestions (record mode) */
#define AK_SYS_SET_MODE 1043        /* Set routing mode */
#define AK_SYS_GET_SUGGESTIONS                                                 \
  1044 /* Get accumulated policy suggestions (JSON) */

/* ============================================================
 * STATISTICS
 * ============================================================ */

typedef struct ak_effects_stats {
  u64 total_requests;
  u64 allowed;
  u64 denied;
  u64 by_op[16];        /* Per-op counts */
  u64 deny_reasons[16]; /* Per-reason counts */
} ak_effects_stats_t;

void ak_effects_get_stats(ak_effects_stats_t *stats);

/* ============================================================
 * STREAMING SESSION TYPES (for ak_stream.h integration)
 * ============================================================
 * These types provide a simplified view of streaming sessions
 * for use in the effects API. Full streaming functionality is
 * in ak_stream.h.
 */

/* Streaming session types */
typedef enum ak_effects_stream_type {
  AK_EFFECTS_STREAM_SSE = 1,    /* Server-Sent Events */
  AK_EFFECTS_STREAM_WEBSOCKET,  /* WebSocket */
  AK_EFFECTS_STREAM_LLM_TOKENS, /* LLM token stream */
} ak_effects_stream_type_t;

/* Streaming session summary (for effects tracking) */
typedef struct ak_effects_stream_session {
  u64 session_id;
  ak_effects_stream_type_t type;
  u64 bytes_sent;
  u64 bytes_limit; /* Budget limit */
  u64 chunks_sent;
  u64 tokens_sent; /* For LLM streams */
  u64 tokens_limit;
  boolean active;
  u64 start_ns;
  u64 last_chunk_ns;
} ak_effects_stream_session_t;

/* Forward declaration for full streaming API (see ak_stream.h) */
struct ak_stream_session_full;

#endif /* AK_EFFECTS_H */
