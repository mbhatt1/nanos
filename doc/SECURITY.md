# Authority Security Model

## Invariants

Authority enforces four security invariants. Violation of any invariant is a P0 incident.

### INV-1: No-Bypass

All external I/O occurs through kernel-mediated syscalls.

```
For all agents A, for all IO operations O:
    O is external => O passes through kernel syscall interface
```

The unikernel architecture eliminates bypass vectors: no raw sockets, no direct hardware access, no process escape.

### INV-2: Capability

Every effectful syscall requires a valid, non-revoked capability whose scope subsumes the request.

```
For all syscalls S where effect(S) = true:
    exists capability C such that:
        valid(C) AND NOT revoked(C) AND scope(C) contains resource(S)
```

Validation requirements:
- HMAC-SHA256 signature verification (constant-time)
- Token ID not in revocation set
- Resource pattern matches request target
- TTL not expired
- Rate limit not exceeded
- Run ID matches current execution

### INV-3: Budget

Resource consumption never exceeds declared budgets.

```
For all operations O with cost c:
    let current = sum of completed costs
    let budget = declared limit

    PRE:  current + c <= budget
    POST: current' = current + c

    If PRE fails: reject with E_BUDGET_EXCEEDED
```

Budget dimensions:
- LLM tokens (input/output)
- Tool calls
- Wall time (ms)
- Heap objects
- File I/O (bytes)
- Network I/O (bytes)

### INV-4: Log Commitment

Every state transition appends a hash-chained audit entry.

```
For all state transitions from S to S':
    exists log entry E such that:
        E.prev_hash = hash(log[n-1])
        E.this_hash = SHA256(E.prev_hash || canonical(E))
        log' = log ++ [E]
        Response sent only after fsync(log)
```

Properties:
- Append-only: no deletions, no modifications
- Tamper-evident: broken chain detected immediately
- Non-repudiation: request hash proves agent action

## Capability System

### Token Structure

```c
struct ak_capability {
    u8  type;                 // NET=1, FS=2, TOOL=3, SECRETS=4, INFERENCE=5
    u8  resource[256];        // Pattern with wildcards
    u8  methods[8][32];       // Allowed operations
    u64 issued_ms;            // Issuance timestamp
    u32 ttl_ms;               // Time to live
    u32 rate_limit;           // Max requests per window
    u8  run_id[16];           // Bound execution ID
    u8  mac[32];              // HMAC-SHA256(key, token_data)
};
```

### Verification

```c
s64 ak_capability_validate(ak_capability_t *cap,
                           ak_cap_type_t required_type,
                           const char *resource,
                           const char *method,
                           u8 *run_id);
```

Returns 0 on success, negative error on failure:
- `AK_E_CAP_INVALID`: Signature verification failed
- `AK_E_CAP_EXPIRED`: TTL exceeded
- `AK_E_CAP_REVOKED`: Token in revocation set
- `AK_E_CAP_SCOPE`: Resource/method mismatch
- `AK_E_CAP_RUN_ID`: Run ID mismatch
- `AK_E_CAP_RATE`: Rate limit exceeded

### Revocation

Immediate revocation via token ID:

```c
void ak_capability_revoke(u8 *token_id);
boolean ak_capability_is_revoked(u8 *token_id);
```

Revocation persists across kernel restart via audit log replay.

## Audit Log

### Entry Format

```c
struct ak_audit_entry {
    u64 seq;                  // Monotonic sequence
    u8  pid[16];              // Agent ID
    u8  run_id[16];           // Execution ID
    u16 op;                   // Operation code
    u64 timestamp_ns;         // Nanosecond timestamp
    u8  req_hash[32];         // SHA-256(request)
    u8  res_hash[32];         // SHA-256(response)
    u8  prev_hash[32];        // Hash of previous entry
    u8  this_hash[32];        // SHA-256(prev_hash || entry)
};
```

### Hash Chain

```
Entry[0]: prev_hash = zeros, this_hash = SHA256(zeros || E0)
Entry[n]: prev_hash = Entry[n-1].this_hash
          this_hash = SHA256(prev_hash || canonical(En))
```

Verification:

```c
boolean ak_audit_verify(u64 from_seq, u64 to_seq);
```

### Anchoring

Periodic anchors for efficient verification:

```c
struct ak_audit_anchor {
    u64 seq;                  // Anchor sequence
    u8  merkle_root[32];      // Merkle root of entries
    u64 timestamp_ns;
};
```

## Policy Engine

### Format

```json
{
  "version": "1.0",
  "fs": {
    "read": ["pattern", ...],
    "write": ["pattern", ...]
  },
  "net": {
    "dns": ["domain", ...],
    "connect": ["target", ...]
  },
  "tools": {
    "allow": ["name", ...],
    "deny": ["name", ...]
  },
  "budgets": {
    "tokens": 100000,
    "tool_calls": 50
  }
}
```

### Pattern Matching

Filesystem patterns:
- `/app/**` - recursive match
- `/tmp/*.log` - single-level wildcard
- `/etc/config.json` - exact match

Network targets:
- `dns:*.example.com` - DNS resolution
- `ip:10.0.0.0/8:*` - CIDR with port wildcard
- `dns:api.github.com:443` - specific host/port

### Evaluation

```c
boolean ak_policy_check(ak_policy_t *policy,
                        ak_effect_op_t op,
                        const char *target,
                        ak_decision_t *decision);
```

Deny-by-default: if no rule matches, deny.

## Threat Model

### In Scope

| Threat | Mitigation |
|--------|------------|
| Prompt injection | Capability scope limits blast radius |
| Tool misuse | WASM sandbox + capability gating |
| Resource exhaustion | Budget enforcement |
| Audit tampering | Hash chain integrity |
| Capability forgery | HMAC-SHA256 signatures |
| Replay attacks | Run ID binding + sequence numbers |
| Privilege escalation | Single-process unikernel |

### Out of Scope

- Hardware attacks (side channels, fault injection)
- Hypervisor compromise
- Cryptographic breaks (SHA-256, HMAC)
- Kernel memory corruption (requires separate hardening)

## Fail-Closed Design

All validation functions deny by default:

```c
// Default deny pattern
s64 validate_request(request_t *req) {
    if (!req) return -EINVAL;
    if (!valid_capability(req->cap)) return -EACCES;
    if (!policy_allows(req)) return -EPERM;
    if (!budget_available(req)) return -ENOSPC;
    // ... explicit allow only after all checks pass
    return 0;
}
```

Ambiguous cases are denied. Unknown operations are denied.

## Incident Response

If invariant violation detected:

1. Halt agent execution
2. Revoke all active capabilities
3. Preserve audit log for forensics
4. Patch and verify before restart

Severity levels:

| Level | Definition | Response |
|-------|------------|----------|
| P0 | Invariant violation in production | Immediate |
| P1 | Invariant violation in staging | 4 hours |
| P2 | Test failure on invariant | 24 hours |

## Contact

Security issues: security@nanovms.com
