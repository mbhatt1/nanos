# Authority Kernel

The Authority Kernel (AK) is the security subsystem that enforces deny-by-default access control for AI agents.

## Design Principles

### 1. Single Authority Gate

All effectful operations pass through ONE function:

```c
int ak_authorize_and_execute(
    ak_ctx_t *ctx,
    const ak_effect_req_t *req,
    ak_decision_t *decision_out,
    long *retval_out
);
```

This ensures consistent policy enforcement across all code paths.

### 2. Deny-by-Default

If policy cannot explicitly prove an operation is allowed, it is denied:

- Missing policy = fail closed
- Unknown operation = denied
- Ambiguous match = denied

### 3. Effects, Not Syscalls

POSIX syscalls are translated into **effects** for policy evaluation:

```c
typedef enum ak_effect_op {
    /* Filesystem effects */
    AK_E_FS_OPEN        = 0x0100,
    AK_E_FS_UNLINK      = 0x0101,
    AK_E_FS_RENAME      = 0x0102,
    AK_E_FS_MKDIR       = 0x0103,

    /* Network effects */
    AK_E_NET_CONNECT    = 0x0200,
    AK_E_NET_DNS_RESOLVE = 0x0201,
    AK_E_NET_BIND       = 0x0202,
    AK_E_NET_LISTEN     = 0x0203,

    /* Agentic effects */
    AK_E_TOOL_CALL      = 0x0400,
    AK_E_WASM_INVOKE    = 0x0401,
    AK_E_INFER          = 0x0402,
} ak_effect_op_t;
```

## Request Validation Pipeline

Every request passes through these stages:

```
┌─────────────┐
│   RECEIVE   │  Read request
└──────┬──────┘
       ↓
┌─────────────┐
│  1. PARSE   │  Validate syntax
└──────┬──────┘
       ↓
┌─────────────┐
│  2. SCHEMA  │  Validate structure
└──────┬──────┘
       ↓
┌─────────────┐
│ 3. SEQUENCE │  Anti-replay check
└──────┬──────┘
       ↓
┌─────────────┐
│4. CAPABILITY│  HMAC verification
└──────┬──────┘
       ↓
┌─────────────┐
│  5. POLICY  │  Rule evaluation
└──────┬──────┘
       ↓
┌─────────────┐
│  6. BUDGET  │  Resource check
└──────┬──────┘
       ↓
┌─────────────┐
│  7. TAINT   │  Information flow
└──────┬──────┘
       ↓
┌─────────────┐
│  8. EXECUTE │  Perform operation
└──────┬──────┘
       ↓
┌─────────────┐
│   9. LOG    │  Audit (before response)
└──────┬──────┘
       ↓
┌─────────────┐
│ 10. RESPOND │  Return result
└─────────────┘
```

Failure at any stage = immediate rejection.

## Syscall Numbers

Authority Kernel uses syscall numbers 1024-1100:

```c
/* Category: STATE */
#define AK_SYS_READ             1024    /* Read heap object */
#define AK_SYS_ALLOC            1025    /* Allocate new object */
#define AK_SYS_WRITE            1026    /* Patch object (CAS) */
#define AK_SYS_DELETE           1027    /* Soft-delete object */

/* Category: TOOLS */
#define AK_SYS_CALL             1028    /* Execute tool */
#define AK_SYS_BATCH            1029    /* Atomic batch */

/* Category: AUDIT */
#define AK_SYS_COMMIT           1030    /* Force log commit */
#define AK_SYS_QUERY            1031    /* Query audit log */

/* Category: CONTROL */
#define AK_SYS_SPAWN            1032    /* Create child agent */
#define AK_SYS_SEND             1033    /* Send message */
#define AK_SYS_RECV             1034    /* Receive message */
#define AK_SYS_ASSERT           1035    /* Assert predicate */

/* Category: OUTPUT */
#define AK_SYS_RESPOND          1036    /* Send response */

/* Category: COGNITIVE */
#define AK_SYS_INFERENCE        1037    /* LLM gateway */

/* Category: DENY UX */
#define AK_SYS_LAST_ERROR       1040    /* Get last denial */
```

## Error Codes

```c
/* Protocol errors: -4000 to -4099 */
#define E_FRAME_TOO_LARGE       (-4001)
#define E_SCHEMA_INVALID        (-4002)

/* Capability errors: -4100 to -4199 */
#define E_CAP_MISSING           (-4100)
#define E_CAP_INVALID           (-4101)
#define E_CAP_EXPIRED           (-4102)
#define E_CAP_SCOPE             (-4103)
#define E_CAP_REVOKED           (-4104)
#define E_CAP_RATE              (-4105)

/* Policy errors: -4200 to -4299 */
#define E_REPLAY                (-4200)
#define E_POLICY_DENY           (-4201)
#define E_APPROVAL_REQUIRED     (-4202)
#define E_TAINT                 (-4203)

/* Resource errors: -4300 to -4399 */
#define E_BUDGET_EXCEEDED       (-4300)
#define E_RATE_LIMIT            (-4301)
```

## Context Structure

Each thread has an Authority Kernel context:

```c
typedef struct ak_ctx {
    ak_agent_context_t *agent;    /* Agent state */

    /* Routing mode */
    enum {
        AK_MODE_OFF,              /* Legacy mode */
        AK_MODE_SOFT,             /* POSIX routed + enforced */
        AK_MODE_HARD,             /* Raw syscalls denied */
    } mode;

    /* Last denial (for AK_SYS_LAST_ERROR) */
    struct ak_last_deny {
        ak_effect_op_t op;
        char target[512];
        char missing_cap[64];
        char suggested_snippet[512];
        u64 trace_id;
    } last_deny;

    /* Policy pointer */
    struct ak_policy_v2 *policy;

    /* Boot capsule state */
    boolean boot_capsule_active;
    boolean boot_capsule_dropped;
} ak_ctx_t;
```

## Canonicalization

All targets are canonicalized before policy matching:

### Filesystem Paths

- Convert relative to absolute using process cwd
- Normalize `.` and `..` segments
- Lexical canonicalization (symlinks not resolved in P0)

### Network Addresses

- Normalize IPv4-mapped IPv6 to IPv4
- Consistent loopback handling
- Format: `ip:<addr>:<port>` or `dns:<host>:<port>`

### DNS

- Separate `net.dns` capability for resolution
- `net.connect` with `dns:` prefix requires prior DNS authorization

## Security Invariants

The Authority Kernel enforces these invariants:

| ID | Invariant | Description |
|----|-----------|-------------|
| INV-DENY | Deny-by-default | Active after boot capsule drop |
| INV-SINGLE | Single Gate | `ak_authorize_and_execute()` is the only path |
| INV-CANONICAL | Canonicalization | Targets normalized before match |
| INV-BOUNDED | Bounded Buffers | Fixed maximum sizes |
| INV-AUDIT | Audit Logging | Denied effects logged (rate-limited) |
| INV-NO-BYPASS | No Bypass | Tools/WASM cannot skip AK |

See [Security Invariants](/security/invariants) for complete documentation.
