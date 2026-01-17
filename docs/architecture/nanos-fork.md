# Fork Relationship

Authority Nanos is a **fork of [Nanos](https://github.com/nanovms/nanos)** — the original unikernel developed by [NanoVMs](https://nanovms.com).

## What is Nanos?

Nanos is a production-quality unikernel designed to run single applications with minimal overhead:

- **Single-process**: No fork, exec, or multiple users
- **Minimal syscalls**: Only what applications need
- **Fast startup**: Boots in milliseconds
- **Small footprint**: ~20MB base memory
- **Cross-platform**: x86_64 and ARM64

## What Authority Nanos Adds

Authority Nanos extends Nanos with the **Authority Kernel** subsystem:

| Feature | Nanos | Authority Nanos |
|---------|-------|-----------------|
| Unikernel base | Yes | Yes |
| Cross-platform | Yes | Yes |
| Capability-based security | No | Yes |
| Deny-by-default policy | No | Yes |
| Audit logging | No | Yes (hash-chained) |
| Budget enforcement | No | Yes |
| LLM integration | No | Yes (native) |
| Tool sandboxing | No | Yes (WASM) |

## Repository Structure

```
authority-nanos/
├── nanos/                   # Nanos kernel (with AK additions)
│   └── src/
│       └── agentic/        # Authority Kernel implementation
├── docs/                    # Documentation (this site)
├── IMPLEMENTATION_SPEC.md   # AK technical specification
└── SECURITY_INVARIANTS.md   # Security guarantees
```

## Upstream Compatibility

Authority Nanos maintains **full compatibility** with upstream Nanos:

- All existing Nanos applications run unchanged (with `AK_MODE_OFF`)
- Standard ops workflows continue to work
- No breaking changes to the POSIX compatibility layer

## The Authority Kernel Files

The Authority Kernel is implemented in `nanos/src/agentic/`:

```
src/agentic/
├── ak_config.h          # Feature toggles and limits
├── ak_types.h           # Core type definitions
├── ak_syscall.c         # Syscall dispatch (1024-1100)
├── ak_policy.c          # Policy loading and evaluation
├── ak_audit.c           # Hash-chained audit log
├── ak_capability.c      # HMAC token verification
├── ak_effects.c         # Effect authorization
├── ak_context.c         # Per-thread context
├── ak_wasm.c            # WASM sandbox runtime
├── ak_inference.c       # LLM gateway
└── README.md            # Component documentation
```

## Build Configuration

The Authority Kernel is enabled by default:

```makefile
# In kernel.mk
CFLAGS += -DCONFIG_AK_ENABLED=1
CFLAGS += -DCONFIG_AK_EFFECTS=1
CFLAGS += -DAK_DEFAULT_MODE=AK_MODE_SOFT
```

To build without Authority Kernel (pure Nanos):

```bash
make kernel CONFIG_AK_ENABLED=0
```

## Contributing Back to Nanos

Improvements to the core Nanos kernel (not Authority Kernel specific) should be contributed upstream:

1. Identify if the change is AK-specific or general Nanos
2. For general changes, submit PR to [nanovms/nanos](https://github.com/nanovms/nanos)
3. For AK-specific changes, submit PR to Authority Nanos

## Why Fork?

Forking allows Authority Nanos to:

1. **Add security features** that aren't needed for general-purpose unikernels
2. **Maintain AI-first focus** without burdening the main Nanos project
3. **Move fast** on agent-specific features while Nanos maintains stability
4. **Stay compatible** by regularly merging upstream changes

## Syncing with Upstream

Authority Nanos periodically syncs with upstream Nanos:

```bash
# Add upstream remote
git remote add upstream https://github.com/nanovms/nanos.git

# Fetch upstream changes
git fetch upstream

# Merge into authority-nanos
git merge upstream/master
```

Most merges are clean since Authority Kernel code lives in a separate directory (`src/agentic/`).
