# Frequently Asked Questions

## General Questions

### What is Authority Nanos?

Authority Nanos is a **fork of [Nanos](https://github.com/nanovms/nanos)** that adds the Authority Kernel — a capability-based security layer designed specifically for running autonomous AI agents in production.

### How is Authority Nanos different from standard Nanos?

Authority Nanos extends Nanos with:
- Capability-based security with HMAC-SHA256 tokens
- Hash-chained audit logs for complete auditability
- Native LLM inference gateway (local models + external APIs)
- Typed heap with versioned objects and CAS semantics
- Policy engine for declarative security rules
- WASM sandbox for tool execution
- AI-first syscalls optimized for agent workloads

### Why use Authority Nanos for AI agents?

**Security**: Traditional OSes weren't designed for autonomous agents. Authority Nanos provides:
- Zero-trust by default — every operation requires explicit capability
- Complete audit trails for compliance and debugging
- Budget enforcement to prevent runaway costs
- Fail-closed security model

**AI-Native**: Built-in support for:
- Local LLM inference via virtio-serial (Ollama, vLLM)
- External API routing (OpenAI, Anthropic, custom)
- Tool execution in sandboxed WASM environment

**Isolation**: Unikernel architecture eliminates:
- Privilege escalation attacks (no users or privileges)
- Container escape vulnerabilities
- Unnecessary attack surface (minimal syscalls)

## Architecture Questions

### Is 32-bit supported?

No, and there's no intention to add support. Authority Nanos focuses on modern 64-bit architectures (x86_64 and ARM64).

### Do you support multiple processes?

No. Authority Nanos is a **single-process unikernel**. For multiple agents, deploy multiple VMs, each running one agent.

### Do you support multiple threads?

**Yes**. Authority Nanos fully supports multi-threading within the single process.

### What platforms are supported?

**x86_64 (Intel/AMD)**
- Full production support
- KVM acceleration on Linux, HVF on macOS

**ARM64 (aarch64)**
- Full production support
- Raspberry Pi 4, AWS Graviton, Azure Ampere

## AI & LLM Questions

### Does Authority Nanos support local models?

**Yes**. Local model support is a core feature via virtio-serial communication:
- Ollama (recommended)
- vLLM (high performance)
- llama.cpp (lightweight)
- Any inference server speaking JSON over stdio

### Can I use external LLM APIs?

**Yes**. Authority Nanos supports:
- OpenAI (GPT-4, etc.)
- Anthropic (Claude)
- Custom endpoints (any OpenAI-compatible API)

### What is hybrid mode?

Hybrid mode allows intelligent routing between local and external models based on model name, cost optimization, or availability.

## Security Questions

### What are the security invariants?

Authority Nanos enforces four foundational guarantees:

- **INV-1**: Every external effect occurs through a kernel-mediated syscall
- **INV-2**: Every effectful syscall requires a valid capability
- **INV-3**: Resource consumption never exceeds declared budgets
- **INV-4**: All state changes are logged with hash chaining

### How do capabilities work?

Capabilities are **unforgeable HMAC-SHA256 signed tokens** granting specific permissions:
- Type (Net, FS, Tool, Inference)
- Resource pattern
- Allowed methods
- Time-to-live
- Rate limits

### Are audit logs tamper-proof?

**Yes**. The audit log uses cryptographic hash chaining. Any modification breaks the chain and is immediately detectable.

### Can agents escape the sandbox?

**No**. Multiple layers of isolation:
- Unikernel boundary (single-process design)
- Capability enforcement (cryptographic verification)
- WASM sandbox (no direct system access)
- Network isolation (policy-controlled)

## Deployment Questions

### What hypervisors are supported?

- **KVM** (Linux) — recommended
- **HVF** (macOS) — for local development
- **QEMU** (TCG mode) — software emulation
- **Xen** — experimental
- **Hyper-V** (Windows) — experimental

### How do I deploy to cloud providers?

Use [ops](https://ops.city) which supports AWS, GCP, Azure, DigitalOcean, Vultr, and more.

### Can I run on edge devices?

**Yes**, especially ARM devices:
- Raspberry Pi 4
- NVIDIA Jetson
- AWS Graviton edge instances

## Development Questions

### How do I build from source?

```bash
# Clone
git clone https://github.com/nanovms/authority-nanos.git
cd authority-nanos/nanos

# Build
make kernel
```

### How do I debug agent issues?

1. **Audit log analysis**: Query the audit log for the run
2. **Last error syscall**: Call `AK_SYS_LAST_ERROR` for denial details
3. **Record mode**: Run with `AK_RECORD=1` to accumulate suggestions

### Can I contribute?

**Yes!** See [CONTRIBUTING.md](https://github.com/nanovms/authority-nanos/blob/main/nanos/CONTRIBUTING.md).

Priority areas:
- Security (policy language, formal verification)
- AI integration (new providers, streaming)
- Tools (WASM runtime, policy validators)
- Monitoring (metrics, alerting)

## Licensing & Support

### What license is Authority Nanos under?

**Apache License 2.0** (open source)
- Commercial use allowed
- Modification allowed
- Distribution allowed
- Patent grant included

### Where do I get help?

**Community Support** (free):
- [Discussion Forum](https://forums.nanovms.com/)
- [GitHub Issues](https://github.com/nanovms/authority-nanos/issues)

**Commercial Support** (paid):
- 24/7 security incident response
- Priority bug fixes
- Custom policy development
- [Contact NanoVMs](https://nanovms.com/services/subscription)

## More Questions?

- Check the [architecture documentation](/architecture/)
- Read the [security invariants](/security/invariants)
- See the [API reference](/api/)
