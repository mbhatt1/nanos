# Authority Nanos

[![CircleCI](https://circleci.com/gh/nanovms/nanos.svg?style=svg)](https://circleci.com/gh/nanovms/nanos)

<p align="center">
  <img src="https://repository-images.githubusercontent.com/115159616/44eb1980-a6f4-11e9-9e7b-df7adf662967" style="width:200px;"/>
</p>

**The AI-First Unikernel for Autonomous Agents**

Authority Nanos is a security-hardened unikernel designed specifically for running AI agents in production. Built on the proven Nanos kernel architecture, Authority Nanos adds the **Authority Kernel** — a capability-based security layer purpose-built for autonomous agentic systems.

Unlike traditional operating systems designed for human users, Authority Nanos is optimized for AI agents with:
- 🔐 **Capability-based security** - Fine-grained access control for every agent action
- 📝 **Tamper-evident audit logs** - Hash-chained cryptographic logging of all operations
- 🤖 **Native LLM integration** - Local models via virtio-serial and external APIs
- 🚀 **Cross-platform** - x86_64 and ARM64 support for cloud and edge deployment
- ⚡ **Minimal attack surface** - Single-process unikernel with no SSH, no users, no unnecessary syscalls
- 🔄 **Ephemeral by design** - Stateless VMs with external state synchronization

Read more about the [Authority Kernel](src/agentic/README.md) and [Security Invariants](../SECURITY_INVARIANTS.md).

---

## Table of Contents

1. [Why Authority Nanos?](#why-authority-nanos)
2. [Getting Started](#getting-started)
3. [Agentic Runtime Features](#agentic-runtime-features)
4. [Building From Source](#building-from-source)
5. [Configuration](#configuration)
6. [Documentation](#documentation)
7. [Support](#support)

---

## Why Authority Nanos?

### Built for the Age of AI Agents

As AI agents become capable of controlling real-world systems, traditional security models fall short. Authority Nanos provides:

**Zero-Trust Architecture**
- Every operation requires a valid, non-revoked capability token
- No implicit permissions, no ambient authority
- Fail-closed by default — unknown operations are denied

**Complete Auditability**
- Every state change is logged with cryptographic hash chaining
- Replay bundles for compliance and debugging
- Tamper-evident logs prevent undetected modifications

**Resource Control**
- Budget enforcement for tokens, API calls, file I/O, and network usage
- Prevents runaway costs and resource exhaustion
- Admission control before operations execute

**AI-Native Syscalls**
- [`ak_sys_inference`](src/agentic/ak_inference.h) - LLM completions with capability gating
- [`ak_sys_call`](src/agentic/ak_syscall.h) - Tool execution in WASM sandbox
- [`ak_sys_write`](src/agentic/ak_heap.h) - Versioned heap with CAS semantics
- [`ak_sys_batch`](src/agentic/ak_syscall.h) - Atomic multi-operation transactions

### Ideal For

✅ **Autonomous Agent Platforms** - Deploy untrusted agent code safely  
✅ **Computer Use Systems** - Agents that interact with real systems  
✅ **Multi-Tenant SaaS** - Isolate customer agents with strong boundaries  
✅ **Regulated Industries** - Complete audit trails for compliance  
✅ **Edge AI** - Run agents on ARM devices with local models  
✅ **Research & Evaluation** - Reproducible agent execution with replay

---

## Getting Started

### Quick Start with ops

The fastest way to run applications on Authority Nanos is using [ops](https://ops.city):

```bash
# Install ops and Authority Nanos
curl https://ops.city/get.sh -sSfL | sh
```

### Running Your First Agent

Create a simple agent configuration:

```yaml
# agent.yaml
version: "1.0"

llm:
  mode: hybrid  # Use both local and external models
  local:
    device_path: /dev/vport0p1
    default_model: llama3.1:70b
  api:
    provider: anthropic
    model: claude-3-5-sonnet-20241022

budgets:
  tokens: 100000
  calls: 50
  inference_ms: 300000
  file_bytes: 104857600

tools:
  allow:
    - file_read
    - http_get
    - web_search
  deny:
    - shell_exec
```

Deploy your agent:

```bash
ops run -c agent.yaml agent-binary
```

For local model support, start an inference server on the host:

```bash
# Host machine
ollama serve
```

![Demo](doc/demo.gif)

---

## Agentic Runtime Features

### 1. LLM Gateway

Authority Nanos provides unified inference capabilities:

**Local Models** (via virtio-serial)
- Ollama, vLLM, llama.cpp support
- Zero API costs for inference
- Data never leaves your infrastructure
- Full offline operation

**External APIs**
- OpenAI, Anthropic, custom endpoints
- Automatic routing based on model name
- Secrets managed via secure host interface

**Hybrid Mode**
- Route by model: `llama3:70b` → local, `gpt-4` → OpenAI
- Fallback strategies for availability
- Cost optimization through intelligent routing

Example inference call:

```c
ak_inference_request_t req = {
    .type = AK_INFERENCE_CHAT,
    .model = "claude-3-5-sonnet-20241022",
    .messages = messages,
    .message_count = 3,
    .max_tokens = 1000,
    .temperature = 0.7
};

ak_inference_response_t *res = ak_inference_complete(agent_ctx, &req, capability);
```

### 2. Capability System

Fine-grained, cryptographically enforced permissions:

```c
// Capabilities are HMAC-SHA256 signed tokens
typedef struct ak_capability {
    ak_cap_type_t type;         // Net, FS, Tool, Secrets, Inference
    buffer resource;             // Domain pattern, path, tool name
    buffer methods[8];           // Allowed operations
    timestamp issued_ms;
    u32 ttl_ms;                  // Time-to-live
    u32 rate_limit;              // Requests per window
    buffer run_id;               // Bound to specific run
    u8 mac[32];                  // HMAC prevents forgery
} ak_capability_t;
```

**Benefits:**
- **Unforgeable** - HMAC signatures prevent tampering
- **Revocable** - Immediate revocation without restarts
- **Scoped** - Resource patterns like `https://*.github.com/*`
- **Time-limited** - Automatic expiration
- **Rate-limited** - Prevent abuse

### 3. Typed Heap with Versioning

Every agent gets a versioned object store:

```c
// Allocate object
ak_sys_alloc(type, initial_value_json) → ptr, version

// Read (always succeeds)
ak_sys_read(ptr) → {value, version}

// Update with optimistic concurrency
ak_sys_write(ptr, json_patch, expected_version)
  → {new_version} or E_CONFLICT

// Atomic batch
ak_sys_batch([
    {op: "write", ptr: obj1, patch: {...}, version: 5},
    {op: "write", ptr: obj2, patch: {...}, version: 3}
]) → all succeed or all fail
```

**Features:**
- Compare-and-swap (CAS) semantics prevent lost updates
- JSON Patch (RFC 6902) for incremental modifications
- Schema validation on every write
- Immutable version history
- Taint tracking for information flow

### 4. Audit Log

Cryptographic audit trail of all operations:

```
Entry[N] = {
    seq: N,
    pid: "agent-7a3f",
    run_id: "2024-01-15T10:30:00Z",
    op: "WRITE",
    req_hash: SHA256(request),
    res_hash: SHA256(response),
    prev_hash: Entry[N-1].this_hash,
    this_hash: SHA256(prev_hash || canonical(Entry[N]))
}
```

**Properties:**
- **Tamper-evident** - Broken hash chain detected immediately
- **Append-only** - No modifications or deletions
- **Durable** - fsync() before response
- **Queryable** - Search by run_id, time range, operation
- **Replayable** - Reconstruct agent state from genesis

### 5. Policy Engine

Declarative security policies in YAML:

```yaml
version: "1.0"

budgets:
  tokens: 100000          # Total LLM tokens
  calls: 50               # Tool/API calls
  inference_ms: 300000    # 5 minutes of inference time
  file_bytes: 104857600   # 100 MB file I/O
  network_bytes: 104857600

tools:
  allow: [file_read, http_get, web_search]
  deny: [shell_exec, file_write]

domains:
  allow: ["*.github.com", "*.wikipedia.org"]
  deny: ["*.internal", "localhost"]

taint:
  sources: [user_input, external_api]
  sinks: [shell_exec, file_write]
  sanitizers: [html_escape, json_encode]
```

### 6. WASM Sandbox for Tools

Execute untrusted tool code safely:

```c
// Tools run in WASM sandbox with limited capabilities
ak_sys_call(
    tool_name: "web_search",
    args: {query: "latest AI papers"},
    capability: search_cap
) → {results: [...], usage: {...}}
```

**Isolation:**
- WASM sandbox with no system access
- Explicit capability passing only
- Memory limits enforced
- Deterministic execution for replay

---

## Building From Source

### Prerequisites

Authority Nanos requires the same toolchain as standard Nanos, with the agentic components built in.

#### macOS (Intel)

```bash
brew update && brew install nasm go wget ent
brew tap nanovms/homebrew-toolchains
brew install x86_64-elf-binutils
brew tap nanovms/homebrew-qemu
brew install nanovms/homebrew-qemu/qemu
```

#### macOS (Apple Silicon)

```bash
brew update && brew install go wget ent qemu aarch64-elf-binutils
```

#### Linux

```bash
sudo apt-get install qemu-system-x86 nasm golang-go ent ruby
curl https://ops.city/get.sh -sSfL | sh
```

### Build the Kernel

```bash
# Build kernel with Authority Kernel enabled
make kernel

# Or build everything (kernel + klibs)
make
```

The Authority Kernel is enabled by default via [`CONFIG_AK_ENABLED=1`](src/agentic/ak_config.h) in the build configuration.

### Running Examples

```bash
# Run example agent (with hardware acceleration)
make run

# Run specific example
make TARGET=<example> run

# Run without acceleration (VM in VM)
make run-noaccel
```

### Testing

```bash
# Run all tests
make test

# Run Authority Kernel tests specifically
cd src/agentic && make test
```

Authority Kernel tests include:
- Capability verification and forgery attempts
- CAS semantics and concurrent updates
- Audit log integrity and tamper detection
- Policy evaluation and budget enforcement
- Replay protection and sequence validation

---

## Configuration

### Kernel Configuration

Authority Kernel features can be configured via [`src/agentic/ak_config.h`](src/agentic/ak_config.h):

```c
/* Feature Toggles */
#define CONFIG_AK_ENABLED       1       /* Master switch */
#define AK_ENABLE_WASM          1       /* WASM sandboxing */
#define AK_ENABLE_TAINT         1       /* Information flow tracking */
#define AK_ENABLE_STATE_SYNC    1       /* Ephemeral VM state sync */

/* Security Parameters */
#define AK_KEY_ROTATION_INTERVAL_MS     (24 * 60 * 60 * 1000)  /* 24 hours */
#define AK_MAX_CAP_TTL_MS               (7 * 24 * 60 * 60 * 1000)  /* 7 days */
#define AK_ANCHOR_INTERVAL              1000  /* Audit anchor frequency */

/* Resource Limits */
#define AK_MAX_HEAP_OBJECTS             100000
#define AK_MAX_HEAP_BYTES               (1024 * 1024 * 1024)  /* 1 GB */
#define AK_MAX_IPC_MESSAGE              (1024 * 1024)  /* 1 MB */
#define AK_MAX_AGENTS                   64

/* LLM Gateway */
#define AK_LLM_MODE_LOCAL               1       /* Local models */
#define AK_LLM_MODE_EXTERNAL            1       /* External APIs */
```

### Runtime Configuration

Agent policies are loaded at runtime via manifest:

```json
{
  "authority": {
    "policy_path": "/policy.yaml",
    "audit_log_path": "/var/log/authority/audit.log",
    "llm": {
      "mode": "hybrid",
      "local": {
        "device": "/dev/vport0p1",
        "timeout_ms": 30000
      },
      "api": {
        "provider": "anthropic",
        "endpoint": "https://api.anthropic.com/v1",
        "secret_name": "ANTHROPIC_API_KEY"
      }
    }
  }
}
```

---

## Architecture

### Cross-Platform Support

**x86_64 (Intel/AMD)**
- Full hardware support in [`src/x86_64/`](src/x86_64/)
- KVM acceleration on Linux, HVF on macOS
- Deployed on AWS (c5/c6), GCE (n2/c2), Azure (Dv3/Ev3)

**ARM64 (aarch64)**
- Complete implementation in [`src/aarch64/`](src/aarch64/)
- Runs on Raspberry Pi 4, AWS Graviton, Azure Ampere
- See [ARM Tutorial](https://nanovms.com/dev/tutorials/nanos-on-64-bit-arm)

### Single-Process Model

Authority Nanos is a **single-process unikernel**:
- ❌ No multiple processes (no fork, exec)
- ✅ Multi-threaded within single address space
- ❌ No users, groups, or permissions model
- ✅ Capability-based security instead
- ❌ No SSH or remote admin
- ✅ Management via virtio-serial and policy updates

This design:
- Eliminates whole classes of vulnerabilities (privilege escalation, user impersonation)
- Simplifies security model (capabilities instead of ACLs)
- Reduces attack surface (no unnecessary syscalls)
- Enables fast startup and low memory overhead

See [Nanos Charter](CHARTER.md) for the philosophical foundation.

---

## Documentation

### Authority Kernel Documentation

- [Authority Kernel README](src/agentic/README.md) - Component overview
- [Implementation Spec](../IMPLEMENTATION_SPEC.md) - Detailed technical specification
- [Security Invariants](../SECURITY_INVARIANTS.md) - The four foundational guarantees
- [Capability System](src/agentic/ak_capability.h) - Token format and verification
- [LLM Gateway](src/agentic/ak_inference.h) - Inference API and routing
- [Audit Log](src/agentic/ak_audit.h) - Hash chain and replay

### General Nanos Documentation

- [Operations Guide](https://nanovms.gitbook.io/ops/) - Using ops to deploy
- [Architecture](https://github.com/nanovms/nanos/wiki/Architecture) - Kernel internals
- [Debugging Guide](https://github.com/nanovms/nanos/wiki/debugging) - Troubleshooting
- [Networking Setup](https://github.com/nanovms/nanos/wiki/networking-setup) - Manual network config
- [FAQ](FAQ.md) - Frequently asked questions
- [Examples](https://github.com/nanovms/ops-examples) - Sample applications

---

## Benchmarks

Authority Nanos maintains the performance characteristics of standard Nanos:

- **Go on GCloud**: 18k req/sec ([details](https://github.com/nanovms/nanos/wiki/go_gcloud))
- **Rust on GCloud**: 22k req/sec ([details](https://github.com/nanovms/nanos/wiki/rust_gcloud))
- **Node.js on AWS**: 2k req/sec ([details](https://github.com/nanovms/nanos/wiki/nodejs_aws))
- **Node.js on GCloud**: 4k req/sec ([details](https://github.com/nanovms/nanos/wiki/nodejs_gcloud))

The Authority Kernel adds minimal overhead:
- Capability verification: ~5μs (constant-time HMAC)
- Audit log append: ~100μs (includes fsync)
- Heap CAS operation: ~1μs (lock, check, update)
- Policy evaluation: ~2μs (cached policy)

---

## Contributing

### Pull Requests

We welcome contributions that align with Authority Nanos's mission: **security-first AI agent runtime**.

**Before submitting:**
- Ensure changes maintain or improve security guarantees
- Add tests for new functionality
- Update documentation as needed
- Follow the existing code style

For significant changes, please open an issue first to discuss your approach.

### Reporting Bugs

**Security Issues**: Email security@nanovms.com — do not open public issues

**General Bugs**:
1. Search existing issues first
2. Use latest/nightly build to verify
3. Provide minimal reproducible example
4. Attach debug output (`ops run --trace`)
5. Include config.json and policy.yaml

### Areas for Contribution

Priority areas where we welcome contributions:

🔐 **Security**
- Additional taint flow sanitizers
- Policy language enhancements
- Formal verification of critical paths

🤖 **AI Integration**
- New LLM provider adapters
- Streaming inference improvements
- Embedding and vector search

🔧 **Tools & Ecosystem**
- WASM tool runtime optimizations
- Policy validation and testing tools
- Audit log analysis utilities

📊 **Monitoring**
- Metrics and observability
- Policy violation alerting
- Budget tracking dashboards

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

---

## Who is Using Authority Nanos?

Authority Nanos is designed for organizations deploying AI agents in production:

- 🤖 **Autonomous agent platforms** needing strong isolation
- 🏢 **Enterprise IT** running computer-use agents
- 🔬 **AI research labs** requiring reproducible experiments
- 🏥 **Regulated industries** needing audit trails
- ☁️ **Cloud providers** offering agent-as-a-service

If you're using Authority Nanos, please open a PR to add your use case!

---

## Support

### Community Support

- [Discussion Forum](https://forums.nanovms.com/) - General questions and community help
- [GitHub Issues](https://github.com/nanovms/nanos/issues) - Bug reports and feature requests
- [Docs Site](https://nanovms.gitbook.io/ops/) - Comprehensive documentation

### Commercial Support

Authority Nanos is **open source (Apache-2.0)**, but NanoVMs provides commercial support:

- **Security Incident Response** - 24/7 support for security issues
- **Custom Policy Development** - Help designing security policies
- **Integration Assistance** - Integrate with your AI platform
- **Priority Bug Fixes** - Expedited fixes for production issues
- **Training & Onboarding** - Team training on Authority Kernel

[Contact NanoVMs](https://nanovms.com/services/subscription) for enterprise support plans.

**Note**: Organizations with >50 employees using pre-built binaries require a commercial subscription. Alternatively, you may build from source freely under Apache-2.0.

---

## License

Authority Nanos is licensed under **Apache License 2.0**.

The Authority Kernel components ([`src/agentic/`](src/agentic/)) are also Apache-2.0 and can be integrated into other unikernel or OS projects.

See [LICENSE](LICENSE) for full details.

---

## Citation

If you use Authority Nanos in research or publication, please cite:

```bibtex
@software{authority_nanos,
  title = {Authority Nanos: AI-First Unikernel for Autonomous Agents},
  author = {NanoVMs, Inc.},
  year = {2024},
  url = {https://github.com/nanovms/nanos}
}
```

---

**Built with ❤️ by [NanoVMs](https://nanovms.com) for the age of AI agents**

For more information: [nanos.org](https://nanos.org) | [Authority Kernel Spec](../IMPLEMENTATION_SPEC.md)
