# Authority Kernel

**The Security Layer Powering Authority Nanos**

## Overview

The Authority Kernel (AK) is the security subsystem that makes **Authority Nanos** the premier unikernel for AI agents. It implements a capability-based security model with comprehensive audit logging, ensuring that autonomous agents operate within strictly defined boundaries while maintaining complete auditability.

Authority Nanos = Nanos unikernel + Authority Kernel subsystem

## Security Invariants

The Authority Kernel enforces four fundamental security invariants:

### INV-1: No-Bypass Invariant
> Every external effect occurs through a kernel-mediated syscall.

The unikernel boundary ensures no direct hardware or network access bypasses the kernel.

### INV-2: Capability Invariant
> Every effectful syscall must carry a valid, non-revoked capability whose scope subsumes the request.

```c
s64 ak_capability_validate(
    ak_capability_t *cap,
    ak_cap_type_t required_type,
    const char *resource,
    const char *method,
    u8 *run_id
);
```

### INV-3: Budget Invariant
> The sum of in-flight and committed costs never exceeds budget.

Admission control prevents resource exhaustion:
```c
s64 ak_budget_reserve(ak_budget_tracker_t *tracker,
                      ak_resource_type_t type, u64 amount);
```

### INV-4: Log Commitment Invariant
> Each committed transition appends a log entry whose hash chain validates from genesis to head.

Tamper-evident audit log with hash chain:
```c
s64 ak_audit_append(u8 *pid, u8 *run_id, u16 op,
                    u8 *req_hash, u8 *res_hash, u8 *policy_hash);
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Agent Process                          │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                   Agent Code                         │   │
│  │  • LLM Inference       • Tool Execution             │   │
│  │  • State Management    • Communication              │   │
│  └────────────────────────┬────────────────────────────┘   │
│                           │ AK Syscalls (1024-1100)        │
├───────────────────────────┼─────────────────────────────────┤
│                           ▼                                 │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              Authority Kernel                        │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐            │   │
│  │  │Capability│ │  Audit   │ │  Policy  │            │   │
│  │  │  System  │ │   Log    │ │  Engine  │            │   │
│  │  └──────────┘ └──────────┘ └──────────┘            │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐            │   │
│  │  │  Typed   │ │   IPC    │ │ Syscall  │            │   │
│  │  │   Heap   │ │Transport │ │ Dispatch │            │   │
│  │  └──────────┘ └──────────┘ └──────────┘            │   │
│  └─────────────────────────────────────────────────────┘   │
│                    Nanos Kernel                             │
└─────────────────────────────────────────────────────────────┘
```

## Syscall Interface

| Number | Name | Description |
|--------|------|-------------|
| 1024 | READ | Read object from typed heap |
| 1025 | ALLOC | Allocate new heap object |
| 1026 | WRITE | Update object with JSON Patch |
| 1027 | DELETE | Soft-delete object |
| 1028 | QUERY | Query objects by predicate |
| 1029 | BATCH | Atomic batch operations |
| 1030 | COMMIT | Checkpoint audit log |
| 1031 | CALL | Invoke tool in WASM sandbox |
| 1032 | SPAWN | Create child agent |
| 1033 | SEND | Send message to agent |
| 1034 | RECV | Receive messages |
| 1035 | RESPOND | Send response to orchestrator |
| 1036 | ASSERT | Record assertion |
| 1037 | INFERENCE | Invoke LLM |

## Components

### Capability System (`ak_capability.h/c`)
- HMAC-SHA256 signed tokens
- Scope-based access control
- Key rotation with grace period
- Constant-time verification
- Immediate revocation

### Typed Heap (`ak_heap.h/c`)
- Versioned objects with CAS semantics
- JSON Schema validation
- RFC 6902 JSON Patch support
- Transaction support for BATCH
- Taint tracking

### Audit Log (`ak_audit.h/c`)
- Hash-chained entries
- Crash recovery
- External anchoring
- Replay bundle support

### Policy Engine (`ak_policy.h/c`)
- JSON/YAML policy format
- Budget enforcement
- Tool allowlists
- Domain restrictions
- Taint flow rules

### IPC Transport (`ak_ipc.h/c`)
- Framed protocol with CRC-32C
- Sequence-based replay protection
- JSON serialization

### Syscall Dispatcher (`ak_syscall.h/c`)
- Central enforcement point
- 10-stage validation pipeline
- Per-operation handlers

## Configuration

### Policy Format (JSON)

```json
{
  "version": "1.0",
  "budgets": {
    "tokens": 100000,
    "calls": 50,
    "inference_ms": 60000,
    "file_bytes": 10485760
  },
  "tools": {
    "allow": ["file_read", "http_get"],
    "deny": ["shell_exec"]
  },
  "domains": {
    "allow": ["*.github.com"],
    "deny": ["*.internal"]
  }
}
```

## Security Considerations

### Fail-Closed Design
All validation functions return denial by default:
- Unknown capability → denied
- Missing policy → denied
- Taint violation → denied

### Timing Attack Resistance
Capability verification uses constant-time comparison:
```c
static boolean constant_time_compare(u8 *a, u8 *b, u64 len)
{
    u8 result = 0;
    for (u64 i = 0; i < len; i++)
        result |= a[i] ^ b[i];
    return result == 0;
}
```

### Capability Revocation
Revocation is immediate and persistent:
- Stored in revocation map
- Survives kernel restart
- Logged to audit trail

### Audit Log Integrity
Hash chain prevents undetected tampering:
```
hash[n] = SHA256(hash[n-1] || entry[n])
```

## Testing

### Unit Tests
```c
void test_capability_verify(void);
void test_heap_cas_semantics(void);
void test_audit_chain_integrity(void);
void test_policy_evaluation(void);
```

### Integration Tests
```c
void test_full_syscall_pipeline(void);
void test_batch_atomicity(void);
void test_revocation_propagation(void);
```

### Security Tests
```c
void test_replay_detection(void);
void test_capability_forgery(void);
void test_taint_flow_blocking(void);
void test_budget_exhaustion(void);
```

## License

Apache-2.0

## References

- [Authority Nanos Main Documentation](/)
- [Authority Kernel Design](./ak-design.md)
- [Security Invariants](./invariants.md)
- [Threat Model](./ak-threat-model.md)
- [Authority Nanos FAQ](/faq.md)
- [Nanos Unikernel](https://github.com/nanovms/nanos)
- [RFC 6902: JSON Patch](https://tools.ietf.org/html/rfc6902)
- [JSON Schema](https://json-schema.org/)
