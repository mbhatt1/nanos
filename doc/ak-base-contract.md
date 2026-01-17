# AK Base Contract v1

**Version:** 1.0
**Date:** 2026-01-16
**Status:** ACTIVE

This document defines the fundamental security contract between the Authority Kernel and applications.

---

## 1. Core Principle: Deny-by-Default

The Authority Kernel operates on a **deny-by-default** principle:

> If policy cannot prove an operation is allowed, it is denied.

There are NO implicit permissions. Every effectful operation requires explicit policy authorization.

---

## 2. Boot Capsule Mechanism

### 2.1 Problem Statement

Deny-by-default creates a chicken-and-egg problem:
- Policy must be loaded before user processes start
- But loading policy requires file access
- File access requires policy permission

### 2.2 Solution: Pre-User Policy Load (Option A)

The Authority Kernel uses **Option A: Pre-User Policy Load**:

1. Kernel boots with minimal internal capabilities
2. **Before** any user process starts:
   - Kernel reads policy from initrd `/ak/policy.json`
   - Only kernel-internal reads are allowed
   - No user code executes during this phase
3. Policy is validated and installed
4. User process starts with policy already active
5. No "boot capsule" capability needs to be dropped

### 2.3 Policy Load Order

1. **Embedded Policy** (compile-time): If `CONFIG_AK_EMBEDDED_POLICY` is set, use embedded policy blob
2. **Initrd Policy**: Read `/ak/policy.json` from initrd
3. **Fail Closed**: If no policy found:
   - Deny all operations
   - Print clear console message with expected location
   - Do NOT start user process

### 2.4 Console Message on Missing Policy

```
AK: FATAL - No policy found
AK: Expected policy at: /ak/policy.json (initrd)
AK: Or compile with CONFIG_AK_EMBEDDED_POLICY
AK: Cannot start in deny-by-default mode without policy
AK: Halting.
```

---

## 3. Effect Categories

All effectful operations are categorized:

### 3.1 Filesystem Effects

| Effect | Description | Required Cap |
|--------|-------------|--------------|
| `AK_E_FS_OPEN` | Open file for read/write | `fs.read` or `fs.write` |
| `AK_E_FS_UNLINK` | Delete file | `fs.write` |
| `AK_E_FS_RENAME` | Rename/move file | `fs.write` |
| `AK_E_FS_MKDIR` | Create directory | `fs.write` |

### 3.2 Network Effects

| Effect | Description | Required Cap |
|--------|-------------|--------------|
| `AK_E_NET_CONNECT` | Outbound connection | `net.connect` |
| `AK_E_NET_DNS_RESOLVE` | DNS resolution | `net.dns` |
| `AK_E_NET_BIND` | Bind to port | `net.bind` |
| `AK_E_NET_LISTEN` | Listen for connections | `net.listen` |

### 3.3 Agentic Effects

| Effect | Description | Required Cap |
|--------|-------------|--------------|
| `AK_E_TOOL_CALL` | Execute tool | `tools.call` |
| `AK_E_WASM_INVOKE` | Run WASM module | `wasm.invoke` |
| `AK_E_INFER` | LLM inference | `infer.model` |

### 3.4 Process Effects (P2)

| Effect | Description | Required Cap |
|--------|-------------|--------------|
| `AK_E_PROC_SPAWN` | Create child process | `proc.spawn` |

---

## 4. Capability Model

### 4.1 Capability String Format

Capabilities are expressed as `<category>.<action>`:

- `fs.read` - Read files
- `fs.write` - Write/create/delete files
- `net.connect` - Outbound network connections
- `net.dns` - DNS resolution
- `net.bind` - Bind to ports
- `net.listen` - Accept connections
- `tools.call` - Execute tools
- `wasm.invoke` - Run WASM modules
- `infer.model` - LLM inference

### 4.2 Target Patterns

Each capability is scoped to a **target pattern**:

**Filesystem:**
- `/app/**` - Everything under /app
- `/tmp/*.log` - .log files in /tmp
- `/etc/passwd` - Specific file

**Network:**
- `ip:10.0.0.0/8:*` - Any port on 10.x.x.x
- `ip:*:443` - Port 443 on any host
- `dns:*.example.com:*` - Any subdomain of example.com
- `dns:api.github.com:443` - Specific host and port

**DNS:**
- `*.example.com` - Any subdomain
- `api.github.com` - Specific domain

**Tools:**
- `http_*` - Tools starting with http_
- `file_read` - Specific tool
- `*` - Any tool (dangerous)

---

## 5. Deny Response Contract

When an operation is denied, the Authority Kernel provides:

### 5.1 Immediate Response

- **errno**: Appropriate POSIX error code (`EACCES`, `EPERM`, `ECONNREFUSED`)
- **Rate-limited log**: One-line denial message

### 5.2 Last Deny Information

Available via `AK_SYS_LAST_ERROR`:

```c
struct ak_last_deny {
    ak_effect_op_t op;           // What was attempted
    char target[512];            // Canonical target
    char missing_cap[64];        // What capability was missing
    char suggested_snippet[512]; // Copy-paste policy fix
    u64 trace_id;                // For correlation
    int errno_equiv;             // POSIX errno
    u64 timestamp_ns;            // When denied
};
```

### 5.3 Suggested Snippet Format

For file access denial:
```toml
# Add to ak.toml [fs] section:
read = ["/path/to/denied/file"]
```

For network denial:
```toml
# Add to ak.toml [net] section:
connect = ["dns:example.com:443"]
```

---

## 6. Routing Modes

### 6.1 SOFT Mode (Default)

- POSIX syscalls are routed through AK effects
- Effects are enforced according to policy
- Denied operations fail with errno
- Last deny is populated

### 6.2 HARD Mode (P1)

- Raw effectful POSIX syscalls are denied
- Only AK-routed operations allowed
- Provides stronger isolation guarantees

### 6.3 OFF Mode (Debug Only)

- AK enforcement disabled
- For debugging and legacy compatibility
- NOT for production use
- Limited scope documented

---

## 7. Audit Contract

### 7.1 Control-Plane Events

Synchronous logging for:
- Policy changes
- Tool calls
- WASM invocations
- Inference requests

### 7.2 Data-Plane Events

Bounded ring buffer for:
- File opens
- Network connections
- Rate-limited (no per-event fsync)

### 7.3 Audit Entry Format

```c
struct ak_audit_entry {
    u64 timestamp_ns;
    u64 trace_id;
    ak_effect_op_t op;
    char target[256];
    boolean allowed;
    char reason[64];
};
```

---

## 8. Integration Test Requirements

The following tests MUST pass for the base contract:

### 8.1 Missing Policy Test

```
GIVEN: No policy file in initrd
WHEN: Kernel boots
THEN:
  - Clear error message printed
  - User process does NOT start
  - OR user process starts but all effects denied
```

### 8.2 Deny-by-Default Test

```
GIVEN: Minimal policy (empty fs/net sections)
WHEN: Application attempts file open
THEN:
  - Operation denied with EACCES
  - last_deny populated with:
    - op = AK_E_FS_OPEN
    - target = canonical path
    - missing_cap = "fs.read"
    - suggested_snippet = valid TOML
```

### 8.3 Allow Test

```
GIVEN: Policy with fs.read = ["/allowed/**"]
WHEN: Application opens /allowed/file.txt
THEN:
  - Operation succeeds
  - File descriptor returned
```

### 8.4 Network DNS Test

```
GIVEN: Policy with net.dns = ["example.com"]
WHEN: Application resolves example.com
THEN: Resolution succeeds

WHEN: Application resolves other.com
THEN:
  - Resolution denied
  - last_deny shows net.dns missing
```

---

## 9. Compatibility Notes

### 9.1 Tier 1: Static/musl

Minimal policy requirements:
- `/proc/self/**` for process info (optional)

### 9.2 Tier 2: Dynamic/glibc

Additional requirements:
- `/lib/**`, `/lib64/**` for shared libraries
- `/etc/ld.so.cache` for library cache
- `/etc/nsswitch.conf` for name service
- `/etc/resolv.conf` for DNS config

### 9.3 Tier 3: Full Linux

Out of scope for P0/P1.

---

## 10. Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-01-16 | Initial version |

