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

## 3. Security Invariants

1. **INV-DENY**: Deny-by-default always active after boot
2. **INV-SINGLE**: `ak_authorize_and_execute()` is the ONLY authority gate
3. **INV-CANONICAL**: All targets canonicalized before policy match
4. **INV-BOUNDED**: All buffers have fixed maximum sizes
5. **INV-AUDIT**: Denied effects are logged (rate-limited for data-plane)
6. **INV-NO-BYPASS**: Tools/WASM/Infer cannot bypass AK for FS/NET

---

## 4. Test Requirements

### Unit Tests (run on host)
- Pattern matching logic
- JSON policy parsing
- Canonicalization functions
- Decision engine logic

### Integration Tests (run in unikernel)
- Allow/deny with policy
- Mode switching (OFF/SOFT/HARD)
- Last deny retrieval

### Smoke Test
- `./tools/smoke.sh` must pass
- Boots image, runs test app, verifies deny behavior
