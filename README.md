# Authority

A security kernel for autonomous agents.

## Overview

Authority is a unikernel that enforces four security invariants for AI agents executing in production environments. It provides cryptographic capability tokens, hash-chained audit logs, and admission-controlled resource budgets.

Built on [Nanos](https://github.com/nanovms/nanos).

## Security Invariants

| Invariant | Statement |
|-----------|-----------|
| **INV-1** | All external I/O occurs through kernel-mediated syscalls |
| **INV-2** | Every effectful syscall requires a valid, non-revoked capability |
| **INV-3** | Resource consumption never exceeds declared budgets |
| **INV-4** | Every state transition appends a hash-chained audit entry |

These are not guidelines. They are mathematical properties the kernel enforces.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Agent Process                          │
├─────────────────────────────────────────────────────────────┤
│                    Authority Kernel                         │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│  │Capability│ │  Audit   │ │  Policy  │ │  Budget  │       │
│  │  System  │ │   Log    │ │  Engine  │ │  Control │       │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘       │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│  │  Typed   │ │   LLM    │ │   WASM   │ │  Syscall │       │
│  │   Heap   │ │ Gateway  │ │ Sandbox  │ │ Dispatch │       │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘       │
├─────────────────────────────────────────────────────────────┤
│                      Nanos Kernel                           │
└─────────────────────────────────────────────────────────────┘
```

## Syscall Interface

| Number | Name | Description |
|--------|------|-------------|
| 1024 | `AK_SYS_READ` | Read object from typed heap |
| 1025 | `AK_SYS_ALLOC` | Allocate heap object |
| 1026 | `AK_SYS_WRITE` | Update object (CAS semantics) |
| 1027 | `AK_SYS_DELETE` | Delete object |
| 1028 | `AK_SYS_QUERY` | Query objects |
| 1029 | `AK_SYS_BATCH` | Atomic batch operations |
| 1030 | `AK_SYS_COMMIT` | Checkpoint audit log |
| 1031 | `AK_SYS_CALL` | Execute tool in WASM sandbox |
| 1032 | `AK_SYS_SPAWN` | Create child agent |
| 1033 | `AK_SYS_SEND` | Send message |
| 1034 | `AK_SYS_RECV` | Receive messages |
| 1035 | `AK_SYS_RESPOND` | Return response |
| 1036 | `AK_SYS_ASSERT` | Record assertion |
| 1037 | `AK_SYS_INFERENCE` | Invoke LLM |

## Policy Format

```json
{
  "version": "1.0",
  "fs": {
    "read": ["/app/**", "/lib/**"],
    "write": ["/tmp/**"]
  },
  "net": {
    "dns": ["api.example.com"],
    "connect": ["dns:api.example.com:443"]
  },
  "tools": {
    "allow": ["http_get", "file_read"],
    "deny": ["shell_exec"]
  },
  "budgets": {
    "tokens": 100000,
    "tool_calls": 50,
    "wall_time_ms": 300000
  }
}
```

## Capability Token

```c
typedef struct ak_capability {
    ak_cap_type_t type;       // NET, FS, TOOL, SECRETS, INFERENCE
    char resource[256];       // Pattern: "https://*.github.com/*"
    char methods[8][32];      // Allowed operations
    u64 issued_ms;
    u32 ttl_ms;
    u32 rate_limit;
    u8 run_id[16];            // Bound to specific execution
    u8 mac[32];               // HMAC-SHA256 signature
} ak_capability_t;
```

Capabilities are unforgeable (HMAC), revocable, time-limited, and rate-limited.

## Audit Log Entry

```c
typedef struct ak_audit_entry {
    u64 seq;                  // Monotonic sequence number
    u8 pid[16];               // Agent ID
    u8 run_id[16];            // Execution ID
    u16 op;                   // Operation code
    u8 req_hash[32];          // SHA-256 of request
    u8 res_hash[32];          // SHA-256 of response
    u8 prev_hash[32];         // Previous entry hash
    u8 this_hash[32];         // SHA-256(prev_hash || entry)
} ak_audit_entry_t;
```

The hash chain is append-only and tamper-evident.

## Build

```bash
# Prerequisites (macOS)
brew install nasm go wget qemu
brew tap nanovms/homebrew-qemu
brew install nanovms/homebrew-qemu/qemu

# Build kernel
make PLATFORM=pc

# Run tests
make -C test/unit && make -C test/unit test
```

## Configuration

Compile-time options in `src/agentic/ak_config.h`:

```c
#define AK_ENABLE_WASM              1       // WASM sandbox
#define AK_ENABLE_TAINT             1       // Information flow tracking
#define AK_ENABLE_STATE_SYNC        1       // Ephemeral VM state sync
#define AK_KEY_ROTATION_MS          86400000  // 24 hours
#define AK_MAX_HEAP_OBJECTS         100000
#define AK_MAX_AGENTS               64
```

Runtime policy loaded from `/ak/policy.json` in the image.

## Components

| Component | Files | Description |
|-----------|-------|-------------|
| Capability System | `ak_capability.h/c` | HMAC-SHA256 tokens, revocation, rate limiting |
| Audit Log | `ak_audit.h/c` | Hash-chained entries, crash recovery, anchoring |
| Typed Heap | `ak_heap.h/c` | Versioned objects, CAS semantics, taint tracking |
| Policy Engine | `ak_policy.h/c`, `ak_policy_v2.h/c` | JSON/TOML parsing, pattern matching |
| LLM Gateway | `ak_inference.h/c` | Local (virtio-serial) and external API routing |
| WASM Sandbox | `ak_wasm.h/c`, `ak_wasm_host.c` | Tool execution with capability gating |
| Syscall Dispatch | `ak_syscall.h/c` | 10-stage validation pipeline |
| IPC Transport | `ak_ipc.h/c` | Framed protocol, replay protection |

## Testing

```bash
# Unit tests (510+ tests)
make -C test/unit test

# Authority Kernel tests
./output/test/unit/bin/ak_capability_test
./output/test/unit/bin/ak_audit_test
./output/test/unit/bin/ak_syscall_test
./output/test/unit/bin/ak_wasm_test
```

## Platforms

- x86_64: KVM (Linux), HVF (macOS), QEMU
- ARM64: Raspberry Pi 4, AWS Graviton, Azure Ampere

## License

Apache-2.0

## Documentation

All documentation has been consolidated into the VitePress site:

- **[Complete Documentation](https://authority-nanos.dev)** - Full documentation site
- **[Getting Started](https://authority-nanos.dev/getting-started/)** - Installation and first steps
- **[Security Invariants](https://authority-nanos.dev/design/invariants.md)** - The four mathematical guarantees
- **[Design Documents](https://authority-nanos.dev/design/)** - Architecture and specifications
- **[Testing Guide](https://authority-nanos.dev/testing/)** - Unit tests, integration tests, and fuzzing
- **[Contributing Guide](https://authority-nanos.dev/guide/contributing.md)** - How to contribute

## References

- [Authority Kernel Source](src/agentic/)
- [Nanos Documentation](https://nanovms.gitbook.io/ops/)
- [GitHub Repository](https://github.com/nanovms/authority-nanos)
