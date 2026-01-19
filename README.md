# Authority Nanos

Authority Kernel for secure AI agent execution, built on [Nanos](https://github.com/nanovms/nanos).

## What This Is

Authority Nanos is a unikernel that enforces kernel-level security for autonomous AI agents. It provides:

- **Cryptographic Capabilities** - Unforgeable HMAC-signed tokens for resource access
- **Audit Logging** - Hash-chained append-only log of all operations
- **Resource Budgets** - Hard kernel-enforced limits on tokens, tool calls, and wall-time
- **Policy Enforcement** - File system, network, and tool access controlled by policy
- **Typed Heap** - Type-safe object storage with optimistic locking (CAS semantics)

Security is **enforced by the kernel**, not by application logic or configuration.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│              Agent Process (Python, Node.js, etc)           │
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

## Python Support

Authority Nanos includes a Python SDK (`sdk/python/authority_nanos/`) for writing agents that run inside the kernel.

### Core APIs

```python
from authority_nanos import AuthorityKernel

ak = AuthorityKernel()

# Typed heap operations
handle = ak.alloc("counter", b'{"value": 0}')
data = ak.read(handle)
ak.write(handle, b'[{"op": "set", "path": "/value", "value": 1}]')
ak.delete(handle)

# Tool execution (WASM sandbox)
result = ak.call_tool("http_get", {"url": "https://example.com"})

# LLM inference
response = ak.inference("claude-3-sonnet", "What is 2+2?")

# Budget and authorization checks
ak.authorize("READ", "/etc/passwd")
status = ak.budget_status("tokens")
```

See `sdk/python/` for the complete SDK.

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

## Building

### Prerequisites

**macOS:**
```bash
brew install nasm go wget qemu
brew tap nanovms/homebrew-qemu
brew install nanovms/homebrew-qemu/qemu
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt-get install nasm build-essential qemu-system-x86-64 wget golang-go
```

### Build

```bash
# Build kernel and libak
make PLATFORM=pc

# For ARM64
make PLATFORM=virt ARCH=aarch64

# For RISC-V
make PLATFORM=riscv-virt ARCH=riscv64
```

### Tests

```bash
make -C test/unit test
```

## Configuration

Runtime policy format (`policy.json`):

```json
{
  "version": "1.0",
  "fs": {
    "read": ["/app/**"],
    "write": ["/tmp/**"]
  },
  "budgets": {
    "tokens": 100000,
    "tool_calls": 50,
    "wall_time_ms": 300000
  }
}
```

Compile-time options in `src/agentic/ak_config.h`.

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

## Project Structure

```
src/agentic/
  ├── ak_agentic.c      # Main kernel entry point
  ├── ak_capability.c   # Capability token system (HMAC-SHA256)
  ├── ak_audit.c        # Hash-chained audit log
  ├── ak_syscall.c      # Syscall dispatch and validation
  ├── ak_policy.c       # Policy parsing and enforcement
  ├── ak_wasm.c         # WASM sandbox for tool execution
  ├── ak_inference.c    # LLM gateway
  └── ak_*.c            # Other kernel subsystems

sdk/python/
  └── authority_nanos/  # Python SDK for userspace agents

test/
  ├── unit/             # Kernel unit tests
  └── integration/      # Integration tests
```

## Syscalls

The kernel implements 14 syscalls (1024-1037) for agent communication:

- **Heap**: `READ`, `ALLOC`, `WRITE`, `DELETE`, `QUERY`, `BATCH`, `COMMIT`
- **Execution**: `CALL` (tool execution), `SPAWN` (child agents)
- **Messaging**: `SEND`, `RECV`, `RESPOND`
- **Control**: `ASSERT`, `INFERENCE`

See `src/agentic/libak.h` for the full C API.

## Documentation

- `docs/` - VitePress documentation site
- `docs/design/` - Architecture and design documents
- `docs/security/` - Security invariants and threat model
- `docs/testing/` - Testing guide (unit, integration, fuzzing)

## License

Apache-2.0

## References

- [Nanos Unikernel](https://github.com/nanovms/nanos)
- [Python SDK](sdk/python/)
