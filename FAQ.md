# Authority Nanos - Frequently Asked Questions

## General Questions

### What is Authority Nanos?

Authority Nanos is an AI-first unikernel specifically designed for running autonomous AI agents in production. It combines the proven Nanos kernel with the Authority Kernel — a capability-based security layer that provides cryptographic access control, tamper-evident audit logging, and native LLM integration.

### How is Authority Nanos different from standard Nanos?

Authority Nanos extends Nanos with the **Authority Kernel** subsystem, which adds:
- Capability-based security with HMAC-SHA256 tokens
- Hash-chained audit logs for complete auditability
- Native LLM inference gateway (local models + external APIs)
- Typed heap with versioned objects and CAS semantics
- Policy engine for declarative security rules
- WASM sandbox for tool execution
- AI-first syscalls optimized for agent workloads

While maintaining Nanos's core benefits (single-process, unikernel architecture), Authority Nanos is purpose-built for AI agent deployments.

### Why use Authority Nanos for AI agents?

**Security**: Traditional OSes weren't designed for autonomous agents. Authority Nanos provides:
- Zero-trust by default — every operation requires explicit capability
- Complete audit trails for compliance and debugging
- Budget enforcement to prevent runaway costs
- Fail-closed security model

**AI-Native**: Built-in support for:
- Local LLM inference via virtio-serial (Ollama, vLLM)
- External API routing (OpenAI, Anthropic, custom)
- Hybrid mode with intelligent model routing
- Tool execution in sandboxed WASM environment

**Isolation**: Unikernel architecture eliminates:
- Privilege escalation attacks (no users or privileges)
- Container escape vulnerabilities
- Unnecessary attack surface (minimal syscalls)

---

## Architecture Questions

### Is 32-bit supported?

No, and there's no intention to add support. Authority Nanos focuses on modern 64-bit architectures (x86_64 and ARM64) which represent the vast majority of cloud and edge infrastructure.

### Do you support multiple processes?

No, and there's no intention to add support. Authority Nanos is a **single-process unikernel**.

**Why single-process?**
- Simpler security model (capabilities instead of users/permissions)
- Eliminates privilege escalation attacks
- Faster startup and lower memory overhead
- Matches agent workload patterns (single agent per VM)

**For multiple agents**: Deploy multiple VMs, each running one agent. This provides stronger isolation than processes.

### Do you support multiple threads?

**Yes**. Authority Nanos fully supports multi-threading within the single process. This allows agents to:
- Handle concurrent API requests
- Perform parallel tool execution
- Run background tasks (state sync, log rotation)
- Utilize multi-core CPUs efficiently

### What platforms are supported?

**x86_64 (Intel/AMD)**
- Full production support
- KVM acceleration on Linux, HVF on macOS
- Deployed on AWS, GCP, Azure, and other clouds

**ARM64 (aarch64)**
- Full production support
- Runs on Raspberry Pi 4, AWS Graviton, Azure Ampere
- See [ARM Tutorial](https://nanovms.com/dev/tutorials/nanos-on-64-bit-arm)

**Not supported**: 32-bit architectures, RISC-V (yet)

---

## AI & LLM Questions

### Does Authority Nanos support local models?

**Yes**, extensively. Local model support is a core feature via virtio-serial communication:

**Supported Runtimes:**
- Ollama (recommended)
- vLLM (high performance)
- llama.cpp (lightweight)
- Any inference server speaking JSON over stdio

**Benefits:**
- Zero API costs
- Complete data privacy (inference never leaves your infrastructure)
- Full offline operation
- Lower latency (no external network calls)

**Setup:**
```bash
# Host machine
ollama serve  # Or vLLM, llama.cpp, etc.

# VM config
llm:
  mode: local
  local:
    device_path: /dev/vport0p1
    default_model: llama3.1:70b
```

### Can I use external LLM APIs?

**Yes**. Authority Nanos supports external APIs with built-in providers:
- OpenAI (GPT-4, etc.)
- Anthropic (Claude)
- Custom endpoints (any OpenAI-compatible API)

**Features:**
- Secrets managed via secure host interface
- Automatic request formatting per provider
- Rate limiting and budget tracking
- Complete audit logging (requests/responses hashed, not logged verbatim)

### What is hybrid mode?

**Hybrid mode** allows intelligent routing between local and external models:

```yaml
llm:
  mode: hybrid
  routing:
    - llama3.1:70b    → local   (via Ollama)
    - mixtral:8x7b    → local   (via Ollama)
    - gpt-4           → external (OpenAI API)
    - claude-*        → external (Anthropic API)
```

**Use cases:**
- Privacy-sensitive tasks use local models
- Complex reasoning tasks use frontier models
- Cost optimization (local is free, external is pay-per-token)
- Availability (fallback to external if local is down)

### How do agents call LLMs?

Via the [`ak_sys_inference`](src/agentic/ak_inference.h) syscall:

```c
ak_inference_request_t req = {
    .type = AK_INFERENCE_CHAT,
    .model = "llama3.1:70b",
    .messages = messages,
    .message_count = 3,
    .max_tokens = 1000,
    .temperature = 0.7
};

// Requires AK_CAP_INFERENCE capability
ak_inference_response_t *res = ak_inference_complete(
    agent_ctx, &req, capability
);
```

All inference calls:
- Require a valid capability token (INV-2)
- Are logged to the audit trail (INV-4)
- Count against budget limits (INV-3)
- Include usage tracking (tokens, latency)

---

## Security Questions

### What are the security invariants?

Authority Nanos enforces four foundational security guarantees:

**INV-1: No-Bypass Invariant**
> Every external effect occurs through a kernel-mediated syscall.

The unikernel boundary prevents direct hardware or network access.

**INV-2: Capability Invariant**
> Every effectful syscall must carry a valid, non-revoked capability whose scope subsumes the request.

HMAC-SHA256 signed tokens prevent forgery.

**INV-3: Budget Invariant**
> The sum of in-flight and committed costs never exceeds budget.

Admission control prevents resource exhaustion.

**INV-4: Log Commitment Invariant**
> Each committed transition appends a log entry whose hash chain validates from genesis to head.

Tamper-evident cryptographic logs.

See [SECURITY_INVARIANTS.md](../SECURITY_INVARIANTS.md) for details.

### How do capabilities work?

Capabilities are **unforgeable cryptographic tokens** granting specific permissions:

```c
typedef struct ak_capability {
    ak_cap_type_t type;         // Net, FS, Tool, Inference, etc.
    buffer resource;             // "https://*.github.com/*"
    buffer methods[8];           // ["GET", "POST"]
    timestamp issued_ms;
    u32 ttl_ms;                  // Auto-expires
    u32 rate_limit;              // 100 requests per minute
    buffer run_id;               // Bound to specific run
    u8 kid;                      // Key ID for rotation
    u8 mac[32];                  // HMAC-SHA256 signature
} ak_capability_t;
```

**Properties:**
- **Unforgeable**: HMAC prevents tampering
- **Scoped**: Patterns match resources (`*.github.com`)
- **Time-limited**: Automatic expiration
- **Rate-limited**: Prevent abuse
- **Revocable**: Immediate revocation via revocation list
- **Auditable**: Every use is logged

**Verification** uses constant-time comparison to prevent timing attacks.

### Are audit logs tamper-proof?

**Yes**. The audit log uses cryptographic hash chaining:

```
Entry[N].this_hash = SHA256(Entry[N-1].this_hash || Entry[N])
```

**Properties:**
- **Tamper-evident**: Any modification breaks the chain
- **Append-only**: No deletions or modifications allowed
- **Durable**: fsync() before responses (INV-4)
- **Verifiable**: Full chain validation from genesis
- **Anchored**: Periodic external anchoring for additional assurance

**Use cases:**
- Compliance audits (healthcare, finance)
- Incident investigation
- Debugging agent behavior
- Replay for testing

### Can agents escape the sandbox?

**No**. Multiple layers of isolation:

**Unikernel boundary**: Single-process design eliminates:
- Privilege escalation (no users or privileges)
- Container escape (not a container)
- Process injection (no other processes)

**Capability enforcement**: Every syscall checked:
- Valid capability required (cryptographically verified)
- Resource patterns must match
- Rate limits enforced
- Budget admission control

**WASM sandbox**: Tool execution in WASM:
- No direct system access
- Explicit capability passing only
- Memory limits enforced
- Deterministic execution

**Network isolation**: Agents can only access:
- Domains matching capability patterns
- Via kernel-mediated network stack
- With complete audit logging

---

## Deployment Questions

### Can Authority Nanos run in Kubernetes?

**Yes**, but with caveats.

Kubernetes is designed for containers, not VMs. To run Authority Nanos in K8s:

1. **Nested virtualization** required (KVM in container)
2. **KubeVirt** recommended for VM orchestration
3. **Performance impact** from nested virtualization

See [K8s Guide](https://nanovms.gitbook.io/ops/k8s) for details.

**Recommendation**: Use native VM orchestration (AWS EC2, GCE, Azure VMs) for better performance and simpler configuration.

### What hypervisors are supported?

- **KVM** (Linux) — recommended, best performance
- **HVF** (macOS) — for local development
- **QEMU** (TCG mode) — software emulation, slower
- **Xen** — experimental support
- **Hyper-V** (Windows) — experimental support

### How do I deploy to cloud providers?

Use the `authority` CLI which has native support for:
- AWS (EC2, Fargate)
- Google Cloud (GCE, GKE)
- Azure (VMs, Container Instances)
- DigitalOcean
- Vultr
- And many others

Example:
```bash
authority run -t aws -c agent-config.yaml agent-binary
```

### Can I run Authority Nanos on edge devices?

**Yes**, especially ARM devices:
- Raspberry Pi 4 (ARM64)
- NVIDIA Jetson (ARM64)
- AWS Graviton edge instances

**Benefits for edge:**
- Small footprint (faster startup, less storage)
- Local model inference (privacy, offline)
- Lower latency (no round-trips to cloud)

---

## Development Questions

### How do I build from source?

See the [Building From Source](README.md#building-from-source) section in the main README.

Quick version:
```bash
# Install dependencies (macOS)
brew install nasm go wget ent qemu aarch64-elf-binutils

# Build kernel
make kernel

# Run tests
make test
```

### How do I debug agent issues?

**Audit log analysis:**
```bash
# Query audit log
authority run --trace agent-binary

# Extract specific run
ak_audit_query --run-id="2024-01-15T10:30:00Z"

# Verify log integrity
ak_audit_verify
```

**Replay:**
```bash
# Replay from audit log
ak_replay --log=audit.log --from-seq=0 --to-seq=1000
```

**Enable debug flags:**
```yaml
# agent.yaml
manifest:
  debugsyscalls: t
  futex_trace: t
  ak_debug: t
```

### Can I contribute?

**Yes!** See [CONTRIBUTING.md](CONTRIBUTING.md).

Priority areas:
- 🔐 Security (policy language, formal verification)
- 🤖 AI integration (new providers, streaming)
- 🔧 Tools (WASM runtime, policy validators)
- 📊 Monitoring (metrics, alerting)

For significant changes, open an issue first to discuss.

---

## Comparison Questions

### Authority Nanos vs. Docker containers?

| Feature | Authority Nanos | Docker Containers |
|---------|----------------|-------------------|
| Isolation | Unikernel (VM-level) | cgroups/namespaces |
| Attack Surface | Minimal (~25 syscalls) | Full Linux (~300 syscalls) |
| Security Model | Capabilities | Users/permissions |
| Agent-Native | Yes (built-in) | No (DIY) |
| Audit Logs | Cryptographic hash chain | Optional (DIY) |
| Startup Time | ~10ms | ~100ms-1s |
| Memory Overhead | ~20MB base | ~100MB+ base |

**Use Authority Nanos when**: Security and auditability are critical  
**Use containers when**: Ecosystem/tooling more important than isolation

### Authority Nanos vs. AWS Lambda?

| Feature | Authority Nanos | AWS Lambda |
|---------|----------------|------------|
| Control | Full kernel control | Managed runtime |
| Cold Start | ~10ms | ~100ms-1s |
| Local Models | Yes (virtio-serial) | No |
| Audit Logs | Built-in | CloudWatch (extra cost) |
| Networking | Full control | Limited egress |
| Cost | VM pricing | Per-request |

**Use Authority Nanos when**: Need local models, custom networking, or audit control  
**Use Lambda when**: Simplicity and AWS integration more important

### Authority Nanos vs. gVisor/Firecracker?

**gVisor** provides syscall interception but:
- Higher overhead (syscall translation)
- No built-in agent features
- Linux-based security model

**Firecracker** provides lightweight VMs but:
- No agent-specific features
- DIY security and audit
- No LLM integration

**Authority Nanos** combines:
- VM-level isolation (like Firecracker)
- Agent-native features (capabilities, audit, LLM)
- Minimal overhead (unikernel)

---

## Licensing & Support

### What license is Authority Nanos under?

**Apache License 2.0** (open source)

- ✅ Commercial use allowed
- ✅ Modification allowed
- ✅ Distribution allowed
- ✅ Patent grant included
- ✅ No copyleft (can integrate into proprietary systems)

### Do I need a commercial license?

**Source code**: Always free under Apache-2.0

**Pre-built binaries from NanoVMs**:
- Free for: Individuals, organizations <50 employees, open source projects
- Paid: Organizations with 50+ employees

**Alternative**: Build from source (always free)

### Where do I get help?

**Community Support** (free):
- [Discussion Forum](https://forums.nanovms.com/)
- [GitHub Issues](https://github.com/mbhatt1/nanos/issues)
- [Documentation](https://nanovms.gitbook.io/ops/)

**Commercial Support** (paid):
- 24/7 security incident response
- Priority bug fixes
- Custom policy development
- Integration assistance
- Training and onboarding

[Contact NanoVMs](https://nanovms.com/services/subscription) for enterprise plans.

### Can I get security support?

**Security issues**: Email security@nanovms.com (do not open public issues)

**Commercial customers** get:
- 24/7 security hotline
- Dedicated security response team
- Private vulnerability disclosure
- Expedited patches

---

## Roadmap Questions

### What's coming next?

See [ROADMAP.md](ROADMAP.md) for the full roadmap.

**Upcoming features:**
- Distributed audit log (multi-VM coordination)
- Policy simulation and testing tools
- Enhanced WASM runtime (WASI support)
- Additional LLM providers (Gemini, Mistral)
- Formal verification of critical paths
- Performance monitoring dashboard

### Can I request features?

**Yes!** Open a [GitHub issue](https://github.com/mbhatt1/nanos/issues) with:
- Use case description
- Why existing features don't solve it
- Proposed API or behavior
- Willingness to contribute

Priority is given to:
- Security enhancements
- AI/LLM integration improvements
- Widely requested features

---

## More Questions?

- Check the [main documentation](README.md)
- Visit the [official Nanos FAQ](https://nanos.org/faq)
- Ask on the [discussion forum](https://forums.nanovms.com/)
- Read the [Authority Kernel spec](../IMPLEMENTATION_SPEC.md)

**Built with ❤️ by [NanoVMs](https://nanovms.com) for the age of AI agents**
