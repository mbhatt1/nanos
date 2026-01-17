# Authority Kernel Roadmap

**Version:** 1.0
**Date:** 2026-01-16

This document defines the P0/P1/P2 scope gates and completion criteria for the Authority Kernel migration.

---

## Scope Control Philosophy

- **P0**: Minimal viable deny-by-default. Ship it working.
- **P1**: Hardening and polish. Production-ready.
- **P2**: Advanced features. Future expansion.

Each phase has explicit **completion criteria**. No phase is complete until ALL criteria pass.

---

## P0: Minimal Viable Deny-by-Default

### Goal
A working deny-by-default Authority Kernel with:
- Core effects enforced
- POSIX compatibility layer
- Agentic primitives functional
- Actionable deny UX

### P0 Features

| Feature | Description | Owner |
|---------|-------------|-------|
| Policy Bootstrap | JSON policy from initrd or embedded | Agent B |
| Deny-by-Default | Missing policy = fail closed | Agent B |
| Effects Core | `ak_authorize_and_execute()` working | COORDINATOR |
| Last Deny | Per-thread last denial with suggestion | Agent C |
| FS Routing | open/openat routed through AK | Agent D |
| NET Routing | connect routed through AK | Agent D |
| DNS Effect | `AK_E_NET_DNS_RESOLVE` with policy gate | Agent D |
| TOOL_CALL Effect | Tool execution gated | Agent E |
| WASM_INVOKE Effect | WASM execution gated | Agent E |
| INFER Effect | Inference gated | Agent E |
| SOFT Mode | Default routing mode working | Agent A |
| Smoke Test | `./tools/smoke.sh` passes | Agent F |

### P0 Completion Criteria

- [ ] **Policy Bootstrap**: JSON policy loads from `/ak/policy.json` in initrd
- [ ] **Fail Closed**: Missing policy = deny-all with clear console message
- [ ] **Effects Core**: All P0 effects route through `ak_authorize_and_execute()`
- [ ] **Last Deny**: Denied operations populate last_deny with:
  - Operation type
  - Target
  - Missing capability
  - Suggested snippet
  - Trace ID
- [ ] **FS Routing**: `open()` and `openat()` create `AK_E_FS_OPEN` effect
- [ ] **NET Routing**: `connect()` creates `AK_E_NET_CONNECT` effect
- [ ] **DNS Gate**: DNS resolution creates `AK_E_NET_DNS_RESOLVE` effect
- [ ] **Agentic Effects**:
  - `AK_E_TOOL_CALL` enforced for tool invocations
  - `AK_E_WASM_INVOKE` enforced for WASM execution
  - `AK_E_INFER` enforced for inference requests
- [ ] **Mode**: SOFT mode is default and functional
- [ ] **Unit Tests**: Pattern matching, JSON parsing, canonicalization all pass
- [ ] **Integration Tests**: allow/deny scenarios pass
- [ ] **Smoke Test**: `./tools/smoke.sh` exits 0

### P0 Non-Goals (Explicitly Deferred)

- TOML policy compilation (P1)
- unlink/rename/mkdir routing (P1)
- bind/listen routing (P1)
- PROC_SPAWN effect (P2)
- Handle provenance on FDs (P1)
- HARD mode enforcement (P1)
- Record/Suggest mode (P1)
- Performance tuning (P1)

---

## P1: Hardening and Polish

### Goal
Production-ready Authority Kernel with:
- Complete POSIX routing
- HARD mode
- Performance optimizations
- Handle provenance scaffolding

### P1 Features

| Feature | Description | Owner |
|---------|-------------|-------|
| FS Complete | unlink/rename/mkdir routed | Agent D |
| NET Complete | bind/listen routed | Agent D |
| HARD Mode | Raw syscalls denied | Agent A |
| Handle Provenance | FD/socket metadata for enforcement | Agent A |
| Policy Profiles | Profile expansion working | Agent B |
| TOML Compile | Build-time ak.toml → JSON | Agent B |
| Ring Buffer | Bounded audit ring for data-plane | Agent C |
| Rate Limiting | Deny log rate limiting | Agent C |
| Record Mode | Accumulate denied effects for suggestions | Agent C |
| glibc Tier 2 | Explicit profile for dynamic linking | Agent B |
| Perf Tuning | Ring buffer + rate limit optimization | Agent C |

### P1 Completion Criteria

- [ ] **FS Complete**: unlink, rename, mkdir create appropriate effects
- [ ] **NET Complete**: bind, listen create effects
- [ ] **HARD Mode**: Setting mode=HARD denies raw effectful syscalls
- [ ] **Handle Provenance**: FDs store target + allowed_action for future enforcement
- [ ] **Profiles**: JSON profiles like `"profiles": ["tier1-musl"]` expand correctly
- [ ] **TOML Compile**: `make` automatically compiles ak.toml → embedded policy
- [ ] **Ring Buffer**: Data-plane events use bounded ring, no per-event fsync
- [ ] **Rate Limiting**: Deny messages rate-limited (e.g., 10/sec per effect type)
- [ ] **Record Mode**: `AK_RECORD=1` accumulates suggestions without permitting
- [ ] **Tier 2 Profile**: Working profile for glibc dynamic linking
- [ ] **Performance**: <1μs overhead for cached policy decisions

### P1 Non-Goals

- Full process isolation (P2)
- Exec/fork interception (P2)
- Streaming tool responses (P2)

---

## P2: Advanced Features

### Goal
Full process model and advanced isolation.

### P2 Features

| Feature | Description | Owner |
|---------|-------------|-------|
| PROC_SPAWN | Process creation effect | TBD |
| Exec/Fork | Exec and fork interception | TBD |
| Streaming | Streaming tool/infer responses | TBD |
| Enhanced Sandbox | Stronger WASM isolation | TBD |
| Attestation | Policy attestation for remote verification | TBD |

### P2 Completion Criteria

- [ ] **PROC_SPAWN**: `fork()`, `exec()` create `AK_E_PROC_SPAWN` effect
- [ ] **Exec Story**: Document and partially implement exec capability model
- [ ] **Streaming**: Tool/infer can stream bounded chunks
- [ ] **Enhanced Sandbox**: Additional WASM memory isolation
- [ ] **Attestation**: Policy hash can be remotely attested

---

## Policy Format (P0 JSON)

```json
{
  "version": "1.0",
  "fs": {
    "read": ["/app/**", "/lib/**"],
    "write": ["/tmp/**"]
  },
  "net": {
    "dns": ["*.example.com", "api.github.com"],
    "connect": [
      "dns:api.github.com:443",
      "ip:10.0.0.0/8:5432"
    ]
  },
  "tools": {
    "allow": ["http_get", "file_read"],
    "deny": ["shell_exec"]
  },
  "wasm": {
    "modules": ["trusted_module"],
    "hostcalls": ["fs_read", "net_fetch"]
  },
  "infer": {
    "models": ["gpt-4", "claude-*"],
    "max_tokens": 100000
  },
  "budgets": {
    "tool_calls": 100,
    "tokens": 100000,
    "wall_time_ms": 300000
  },
  "profiles": ["tier1-musl"]
}
```

---

## Policy Format (P1 TOML - Human Facing)

```toml
# ak.toml - Human-readable policy
# Compiled to JSON at build time

[fs]
read = ["/app/**", "/lib/**"]
write = ["/tmp/**"]

[net]
dns = ["*.example.com", "api.github.com"]
connect = [
  "dns:api.github.com:443",
  "ip:10.0.0.0/8:5432"
]

[tools]
allow = ["http_get", "file_read"]
deny = ["shell_exec"]

[wasm]
modules = ["trusted_module"]
hostcalls = ["fs_read", "net_fetch"]

[infer]
models = ["gpt-4", "claude-*"]
max_tokens = 100000

[budgets]
tool_calls = 100
tokens = 100000
wall_time_ms = 300000

[profiles]
include = ["tier1-musl"]
```

---

## Compatibility Tiers

### Tier 1: Static/musl (Recommended)
- Statically linked binaries
- No dynamic library loading
- Simplest policy requirements
- Profile: `tier1-musl`

### Tier 2: Dynamic/glibc
- Dynamically linked binaries
- Requires additional FS permissions for:
  - `/lib/**`, `/lib64/**` (shared libraries)
  - `/etc/ld.so.cache` (library cache)
  - `/etc/nsswitch.conf` (name service switch)
- Profile: `tier2-glibc`

### Tier 3: Full Linux Compat
- **Out of scope** for P0/P1
- Would require extensive syscall coverage
- May be considered for P2+

---

## Built-in Profiles (P0 JSON)

### tier1-musl
```json
{
  "fs": {
    "read": ["/proc/self/**"]
  },
  "net": {
    "dns": []
  }
}
```

### tier2-glibc
```json
{
  "fs": {
    "read": [
      "/lib/**",
      "/lib64/**",
      "/etc/ld.so.cache",
      "/etc/ld.so.preload",
      "/etc/nsswitch.conf",
      "/etc/resolv.conf",
      "/proc/self/**"
    ]
  }
}
```

---

## Boot Capsule Mechanism (P0)

### Chosen Approach: Option A

Policy loads BEFORE starting user processes:

1. Kernel boots with minimal internal capabilities
2. Policy loaded from initrd `/ak/policy.json`
3. If policy missing: fail closed (deny-all + console message)
4. Policy validated and installed
5. User process starts with policy active

### Boot Capsule Test

Integration test verifies:
- No user FS/NET access before policy load
- Policy load completes successfully
- After load, policy is enforced

---

## Threat Model Reference

See `docs/ak-threat-model.md` for:
- Attacker model
- Non-bypass goals
- Security assumptions
- Out-of-scope threats

---

## Timeline Guidance

**Note:** No specific time estimates. Work is ordered by dependency.

### Critical Path
1. Effects API skeleton (blocking for everything)
2. Policy V2 loading (blocking for enforcement)
3. POSIX routing (blocking for smoke test)
4. Smoke test (blocking for P0 completion)

### Parallelizable
- Agentic effects (after Effects API)
- Deny UX (after Effects API)
- Unit tests (any time)
- Documentation (any time)

