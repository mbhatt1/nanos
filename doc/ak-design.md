# Authority Kernel (AK) Design Document

**Version:** 1.0
**Date:** 2026-01-16
**Status:** ACTIVE - Team Contract in Effect

This document defines the shared interfaces, hook points, and ownership boundaries for the deny-by-default Authority Kernel migration.

---

## 1. Architecture Overview

### 1.1 Core Principle: Single Authority Gate

All authority-bearing operations MUST flow through ONE enforcement function:

```c
int ak_authorize_and_execute(ak_ctx_t *ctx,
                             const ak_effect_req *req,
                             ak_decision *decision_out,
                             long *retval_out);
```

- POSIX syscalls are a **compatibility frontend** that translate into AK effects
- Default is **DENY-BY-DEFAULT**: if policy cannot prove allow, deny the effect
- Agentic primitives (tools, WASM, inference) are first-class effects

### 1.2 Effect Model

Every effectful operation is expressed as an **AK Effect** with:
- Canonical target (absolute path, normalized sockaddr, tool identity)
- Trace ID for correlation
- Budget constraints
- Policy-checkable parameters

---

## 2. Concrete Hook Points (Existing Codebase)

### 2.1 Syscall Entry / Dispatcher

| Component | File | Function | Notes |
|-----------|------|----------|-------|
| Main POSIX dispatcher | `src/unix/syscall.c:194` | `read()`, `write()`, etc. | Routes to fdesc operations |
| AK integration check | `src/unix/syscall.c:6-9` | `#ifdef CONFIG_AK_ENABLED` | Existing conditional include |
| AK syscall handler | `src/agentic/ak_nanos.c:88` | `ak_syscall_handler()` | Handles syscalls 1024-1100 |
| AK init | `src/agentic/ak_nanos.c:39` | `ak_nanos_init()` | Called from kernel startup |
| AK dispatch | `src/agentic/ak_syscall.c` | `ak_dispatch()` | 7-stage validation pipeline |

### 2.2 Process/Thread Structures

| Component | File | Line | Notes |
|-----------|------|------|-------|
| Thread struct | `src/unix/unix_internal.h:324-376` | `struct thread` | Per-thread state |
| Process forward decl | `src/unix/unix.h` | `typedef struct process *process` | Process handle |
| Agent context | `src/agentic/ak_types.h:411-444` | `struct ak_agent_context` | AK per-agent state |
| Current context | `src/agentic/ak_nanos.c:32` | `__thread ak_agent_context_t *current_context` | TLS context |

### 2.3 Network Syscall Registration

| Component | File | Function | Notes |
|-----------|------|----------|-------|
| Socket creation | `src/net/netsyscall.c` | Dispatches via `struct sock` | lwIP-based |
| Connect | `src/net/netsyscall.c:125` | `netsock_connect()` | TCP/UDP connect |
| Bind | `src/net/netsyscall.c:122` | `netsock_bind()` | Port binding |
| Listen | `src/net/netsyscall.c:124` | `netsock_listen()` | Server listen |
| Socket struct | `src/net/netsyscall.c:84-107` | `struct netsock` | Per-socket state |

### 2.4 Filesystem Operations

| Component | File | Function | Notes |
|-----------|------|----------|-------|
| Open | `src/unix/syscall.c` | `open()`, `openat()` | File descriptor creation |
| Read | `src/unix/syscall.c:194` | `read()` | Via fdesc |
| Write | `src/unix/syscall.c` | `write()` | Via fdesc |
| Unlink | `src/fs/` | `unlink()` | File deletion |
| Mkdir | `src/fs/` | `mkdir()` | Directory creation |
| Rename | `src/fs/` | `rename()` | File move |

### 2.5 Existing AK Syscall Base Dispatch

| Component | File | Notes |
|-----------|------|-------|
| Syscall numbers | `src/agentic/ak_types.h:27-60` | 1024-1037 defined |
| Handler dispatch | `src/agentic/ak_syscall.c` | Switch on op code |
| Heap operations | `ak_handle_read/alloc/write/delete` | CRUD on typed heap |
| Tool calls | `ak_handle_call` | AK_SYS_CALL (1028) |
| Inference | `ak_handle_inference` (in ak_inference.h) | AK_SYS_INFERENCE (1037) |

### 2.6 Policy Stubs & Audit Subsystem

| Component | File | Notes |
|-----------|------|-------|
| Policy structure | `src/agentic/ak_policy.h:116-143` | Budget, tool/domain rules |
| Policy load | `src/agentic/ak_policy.c` | JSON/YAML parsing |
| Audit log | `src/agentic/ak_audit.h:264` | Hash-chained entries |
| Audit append | `ak_audit_append()` | Synchronous fsync |
| Audit verify | `ak_audit_verify()` | Chain verification |

### 2.7 WASM Hooks / Tool Registry

| Component | File | Notes |
|-----------|------|-------|
| Module struct | `src/agentic/ak_wasm.h:34-74` | Bytecode, limits, signature |
| Tool struct | `src/agentic/ak_wasm.h:82-109` | Named exports with caps |
| Exec context | `src/agentic/ak_wasm.h:147-184` | Per-invocation state |
| Host functions | `src/agentic/ak_wasm_host.c` | FS/NET host calls |

### 2.8 Path Canonicalization

| Component | File | Function | Notes |
|-----------|------|----------|-------|
| Path sanitize | `src/agentic/ak_sanitize.h:99` | `ak_sanitize_path()` | Remove .., null bytes |
| URL sanitize | `src/agentic/ak_sanitize.h` | `ak_sanitize_url()` | URL normalization |
| Taint levels | `src/agentic/ak_types.h:169-177` | `enum ak_taint` | 0=trusted, 100=untrusted |

---

## 3. Team Contract: Shared Interfaces

ALL agents MUST code to these exact signatures. No deviations without COORDINATOR approval.

### 3.1 Effects API (New - to be added)

**File:** `src/agentic/ak_effects.h` (NEW)

```c
/* Effect operation types */
typedef enum ak_effect_op {
    /* Filesystem effects */
    AK_E_FS_OPEN        = 0x0100,
    AK_E_FS_UNLINK      = 0x0101,
    AK_E_FS_RENAME      = 0x0102,
    AK_E_FS_MKDIR       = 0x0103,

    /* Network effects */
    AK_E_NET_CONNECT    = 0x0200,
    AK_E_NET_DNS_RESOLVE = 0x0201,  /* P0 REQUIRED */
    AK_E_NET_BIND       = 0x0202,
    AK_E_NET_LISTEN     = 0x0203,

    /* Process effects */
    AK_E_PROC_SPAWN     = 0x0300,   /* P2 */

    /* Agentic effects */
    AK_E_TOOL_CALL      = 0x0400,
    AK_E_WASM_INVOKE    = 0x0401,
    AK_E_INFER          = 0x0402,
} ak_effect_op_t;

/* Maximum sizes for bounded buffers */
#define AK_MAX_TARGET     512
#define AK_MAX_PARAMS     4096
#define AK_MAX_CAPSTR     64
#define AK_MAX_SUGGEST    512
#define AK_MAX_DETAIL     256

/* Effect request (input to authorization) */
typedef struct ak_effect_req {
    ak_effect_op_t op;
    u64 trace_id;
    pid_t pid;
    tid_t tid;

    /* Canonical target string (bounded):
     * - FS: absolute normalized path
     * - NET_CONNECT: "ip:1.2.3.4:443" OR "dns:example.com:443"
     * - NET_DNS_RESOLVE: "dns:example.com"
     * - TOOL: "tool:<name>:<version>"
     * - INFER: "model:<name>:<version>"
     */
    char target[AK_MAX_TARGET];

    /* Compact encoded params (JSON) */
    u8 params[AK_MAX_PARAMS];
    u32 params_len;

    /* Budgets/limits */
    struct {
        u64 cpu_ns;
        u64 wall_ns;
        u64 bytes;
        u64 tokens;
    } budget;
} ak_effect_req_t;

/* Authorization decision (output) */
typedef struct ak_decision {
    boolean allow;
    int reason_code;              /* Stable enum */
    int errno_equiv;              /* EACCES/EPERM/etc for POSIX compat */
    char missing_cap[AK_MAX_CAPSTR];   /* e.g., "fs.read", "net.connect" */
    char suggested_snippet[AK_MAX_SUGGEST]; /* Copy/paste into ak.toml */
    u64 trace_id;
    char detail[AK_MAX_DETAIL];   /* User-readable */
} ak_decision_t;

/* Reason codes */
typedef enum ak_deny_reason {
    AK_DENY_NO_POLICY       = 1,
    AK_DENY_NO_CAP          = 2,
    AK_DENY_CAP_EXPIRED     = 3,
    AK_DENY_PATTERN_MISMATCH = 4,
    AK_DENY_BUDGET_EXCEEDED = 5,
    AK_DENY_RATE_LIMITED    = 6,
    AK_DENY_TAINT           = 7,
} ak_deny_reason_t;
```

### 3.2 Core Authorization Function (New)

**File:** `src/agentic/ak_effects.c` (NEW)

```c
/*
 * THE SINGLE AUTHORITY GATE
 *
 * All effectful operations MUST pass through this function.
 * Returns: 0 on success, negative errno on failure
 *
 * If denied:
 *   - decision_out->allow = false
 *   - decision_out contains reason, missing_cap, suggested_snippet
 *   - last_deny is updated (for AK_SYS_LAST_ERROR)
 *   - Rate-limited log message printed
 */
int ak_authorize_and_execute(
    ak_ctx_t *ctx,
    const ak_effect_req_t *req,
    ak_decision_t *decision_out,
    long *retval_out
);

/* Initialize effects subsystem */
void ak_effects_init(heap h);

/* Generate trace ID */
u64 ak_trace_id_generate(void);

/* Build effect request from POSIX args */
int ak_effect_from_open(ak_effect_req_t *req, const char *path, int flags);
int ak_effect_from_connect(ak_effect_req_t *req, const struct sockaddr *addr, socklen_t len);
int ak_effect_from_unlink(ak_effect_req_t *req, const char *path);
/* ... etc for other syscalls */
```

### 3.3 Per-Thread Context Extension

**File:** `src/agentic/ak_context.h` (NEW)

```c
/* Extended context for deny-by-default enforcement */
typedef struct ak_ctx {
    ak_agent_context_t *agent;    /* Existing agent context */

    /* Routing mode */
    enum {
        AK_MODE_OFF,              /* Legacy minimal debug */
        AK_MODE_SOFT,             /* Default: POSIX routed + enforced */
        AK_MODE_HARD,             /* Raw syscalls denied */
    } mode;

    /* Last denial (for AK_SYS_LAST_ERROR) */
    struct ak_last_deny {
        ak_effect_op_t op;
        char target[AK_MAX_TARGET];
        char missing_cap[AK_MAX_CAPSTR];
        char suggested_snippet[AK_MAX_SUGGEST];
        u64 trace_id;
        int errno_equiv;
        u64 timestamp_ns;
    } last_deny;

    /* Policy pointer */
    struct ak_policy_v2 *policy;  /* New deny-by-default policy */

    /* Boot capsule state */
    boolean boot_capsule_active;
    boolean boot_capsule_dropped;
} ak_ctx_t;

/* Get context for current thread */
ak_ctx_t *ak_ctx_current(void);

/* Set routing mode */
void ak_ctx_set_mode(ak_ctx_t *ctx, int mode);

/* Boot capsule management */
void ak_ctx_drop_boot_capsule(ak_ctx_t *ctx);
boolean ak_ctx_boot_capsule_active(ak_ctx_t *ctx);
```

### 3.4 Policy V2 (Deny-by-Default)

**File:** `src/agentic/ak_policy_v2.h` (NEW)

```c
/* P0 Policy: JSON-based, deny-by-default */
typedef struct ak_policy_v2 {
    heap h;

    /* Identity */
    u8 policy_hash[AK_HASH_SIZE];
    u64 loaded_ms;

    /* FS capabilities (patterns) */
    struct ak_fs_rule {
        char pattern[256];        /* Glob pattern */
        boolean read;
        boolean write;
        struct ak_fs_rule *next;
    } *fs_rules;

    /* Net capabilities */
    struct ak_net_rule {
        char pattern[256];        /* "dns:*.example.com" or "ip:10.0.0.0/8:*" */
        boolean connect;
        boolean bind;
        boolean listen;
        struct ak_net_rule *next;
    } *net_rules;

    /* DNS capabilities (P0 REQUIRED) */
    struct ak_dns_rule {
        char pattern[256];        /* "*.example.com" */
        boolean allow;
        struct ak_dns_rule *next;
    } *dns_rules;

    /* Tool capabilities */
    struct ak_tool_rule_v2 {
        char name_pattern[64];    /* "tool:*" or "tool:http_*" */
        boolean allow;
        struct ak_tool_rule_v2 *next;
    } *tool_rules;

    /* WASM capabilities */
    struct ak_wasm_rule {
        char module_pattern[64];
        char *allowed_hostcalls[32];
        u32 hostcall_count;
        struct ak_wasm_rule *next;
    } *wasm_rules;

    /* Inference capabilities */
    struct ak_infer_rule {
        char model_pattern[64];
        u64 max_tokens;
        struct ak_infer_rule *next;
    } *infer_rules;

    /* Budgets */
    struct {
        u64 cpu_ns;
        u64 wall_ns;
        u64 bytes;
        u64 tokens;
        u64 tool_calls;
    } budgets;

    /* Profiles (P0: simple include) */
    char **included_profiles;
    u32 profile_count;
} ak_policy_v2_t;

/* Load policy from JSON buffer */
ak_policy_v2_t *ak_policy_v2_load(heap h, buffer json);

/* Load from initrd path */
ak_policy_v2_t *ak_policy_v2_load_file(heap h, const char *path);

/* Check effect against policy */
boolean ak_policy_v2_check(ak_policy_v2_t *p, const ak_effect_req_t *req,
                           ak_decision_t *decision_out);

/* Generate suggested snippet for denied effect */
void ak_policy_v2_suggest(const ak_effect_req_t *req, char *snippet, u32 max_len);
```

### 3.5 Deny UX Syscalls (New)

**File:** `src/agentic/ak_deny_ux.h` (NEW)

```c
/* New syscall numbers */
#define AK_SYS_LAST_ERROR       1040  /* Get last deny info */
#define AK_SYS_TRACE_RING_READ  1041  /* Optional: read trace ring */
#define AK_SYS_POLICY_SUGGEST   1042  /* Optional: dump suggestions */

/* Get last denial information */
sysreturn ak_sys_last_error(u8 *buf, u64 buf_len);

/* Read trace ring buffer (bounded, rate-limited) */
sysreturn ak_sys_trace_ring_read(u8 *buf, u64 buf_len, u64 *offset);

/* Get accumulated policy suggestions (for RECORD mode) */
sysreturn ak_sys_policy_suggest(u8 *buf, u64 buf_len);
```

### 3.6 POSIX Routing (Integration Points)

**File:** `src/agentic/ak_posix_route.h` (NEW)

```c
/* Route POSIX syscalls into AK effects */

/* File operations */
sysreturn ak_route_open(const char *path, int flags, int mode);
sysreturn ak_route_openat(int dirfd, const char *path, int flags, int mode);
sysreturn ak_route_unlink(const char *path);
sysreturn ak_route_rename(const char *old, const char *new);
sysreturn ak_route_mkdir(const char *path, int mode);

/* Network operations */
sysreturn ak_route_connect(int fd, const struct sockaddr *addr, socklen_t len);
sysreturn ak_route_bind(int fd, const struct sockaddr *addr, socklen_t len);
sysreturn ak_route_listen(int fd, int backlog);

/* DNS resolution hook */
sysreturn ak_route_dns_resolve(const char *hostname, struct addrinfo **res);

/* Called from main syscall dispatcher */
boolean ak_should_route_syscall(u64 syscall_num);
sysreturn ak_route_syscall(u64 syscall_num, u64 arg0, u64 arg1,
                           u64 arg2, u64 arg3, u64 arg4, u64 arg5);
```

---

## 4. File Ownership Boundaries

| File/Module | Owner | Notes |
|-------------|-------|-------|
| `src/agentic/ak_effects.h` | **COORDINATOR** | Shared interface - NO changes without approval |
| `src/agentic/ak_effects.c` | **COORDINATOR** | Core authorize function |
| `src/agentic/ak_context.h` | **Agent A** | Per-thread context, modes |
| `src/agentic/ak_context.c` | **Agent A** | Context lifecycle |
| `src/agentic/ak_policy_v2.h` | **Agent B** | Policy schema |
| `src/agentic/ak_policy_v2.c` | **Agent B** | Policy loading/matching |
| `src/agentic/ak_deny_ux.h` | **Agent C** | Deny UX interfaces |
| `src/agentic/ak_deny_ux.c` | **Agent C** | Last deny, suggestions |
| `src/agentic/ak_posix_route.h` | **Agent D** | POSIX routing |
| `src/agentic/ak_posix_route.c` | **Agent D** | Syscall hooks |
| `src/agentic/ak_agentic.h` | **Agent E** | Tool/WASM/Infer effects |
| `src/agentic/ak_agentic.c` | **Agent E** | Agentic effect handlers |
| `test/unit/ak_*.c` | **Agent F** | Unit tests |
| `test/runtime/ak_*.c` | **Agent F** | Integration tests |
| `examples/agentic_demo/` | **Agent F** | Demo application |
| `tools/smoke.sh` | **Agent F** | Smoke test script |

---

## 5. Merge Order

### Phase 1 (Foundations)
1. **Agent A**: `ak_context.h/c` - Context + modes + boot capsule
2. **Agent C**: `ak_effects.h/c` skeleton + last_deny + rate limit
3. **Agent B**: `ak_policy_v2.h/c` - JSON policy bootstrap
4. **Agent F**: Test scaffolding + smoke script skeleton

**Merge Order:** A → C → B → F

### Phase 2 (Enforce Real Effects)
1. **Agent B**: FS/NET policy patterns + DNS cap + profiles
2. **Agent D**: Route open/openat/connect into `ak_authorize_and_execute()`
3. **Agent C**: Suggested snippet generator + ring buffer
4. **Agent F**: Integration tests for allow/deny

**Merge Order:** B/C → D → F

### Phase 3 (Agentic Primitives)
1. **Agent E**: TOOL_CALL/WASM_INVOKE/INFER effects + registry
2. **Agent B/C**: Extend policy schema + budgets
3. **Agent F**: agentic_demo + agentic tests

**Merge Order:** B/C → E → F

### Phase 4 (Finalization)
1. **COORDINATOR**: Integration, docs, final test run

---

## 6. Interface Change Request Process

If any agent needs an interface change:

1. Add entry to `docs/ak-design.md` under "Interface Change Requests" section
2. **STOP** and wait for COORDINATOR to update Team Contract
3. Resume work after COORDINATOR approval

### Interface Change Requests

(None currently)

---

## 7. Canonicalization Specification

### 7.1 Filesystem Paths

- Convert relative → absolute using process cwd
- Normalize `.` and `..` segments
- **P0 Decision:** Lexical canonicalization (pre-resolve)
  - Symlinks are NOT resolved in P0
  - Policy matches on the literal path string after normalization
- Never match policy on raw user pointer strings

### 7.2 Network Addresses

- Normalize IPv4-mapped IPv6 to IPv4 (::ffff:a.b.c.d → a.b.c.d)
- Treat loopback variants consistently (127.x.x.x, ::1)
- Include port always (deny if port=0 unless policy allows)
- Format: `ip:<addr>:<port>` or `dns:<host>:<port>`

### 7.3 DNS Story (P0 Required)

- `AK_E_NET_DNS_RESOLVE` effect for DNS resolution
- Policy cap: `net.dns` with domain patterns
- If `net.connect` uses `dns:host:port`, DNS resolution MUST be separately gated

---

## 8. Build Configuration

### 8.1 Enable AK Effects

```make
# In vars.mk or Makefile
CFLAGS += -DCONFIG_AK_ENABLED=1
CFLAGS += -DCONFIG_AK_EFFECTS=1
CFLAGS += -DAK_DEFAULT_MODE=AK_MODE_SOFT
```

### 8.2 Policy Embedding (P1)

```make
# Build-time TOML→JSON compilation (P1)
# Automatically invoked by make, no manual steps
policy.json: ak.toml
	$(TOOLS)/ak-compile $< $@

# Embed into initrd
INITRD_FILES += /ak/policy.json:policy.json
```

---

## 9. Security Invariants

1. **INV-DENY**: Deny-by-default always active after boot capsule drop
2. **INV-SINGLE**: `ak_authorize_and_execute()` is the ONLY authority gate
3. **INV-CANONICAL**: All targets canonicalized before policy match
4. **INV-BOUNDED**: All buffers have fixed maximum sizes
5. **INV-AUDIT**: Denied effects are logged (rate-limited for data-plane)
6. **INV-NO-BYPASS**: Tools/WASM/Infer cannot bypass AK for FS/NET

---

## 10. Test Requirements

### Unit Tests (run on host)
- Pattern matching logic
- JSON policy parsing
- Canonicalization functions
- Decision engine logic

### Integration Tests (run in unikernel)
- Allow/deny with policy
- Mode switching (OFF/SOFT/HARD)
- Last deny retrieval
- Boot capsule drop

### Smoke Test
- `./tools/smoke.sh` must pass
- Boots image, runs test app, verifies deny behavior

