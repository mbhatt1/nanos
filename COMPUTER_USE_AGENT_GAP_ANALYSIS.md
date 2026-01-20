# Computer Use Agent Threat Model: Gap Analysis vs Authority Nanos

## Executive Summary

Authority Nanos implements **4 enforced cryptographic invariants** for agentic execution (No-Bypass, Capability, Budget, Log Commitment). However, this is a **unikernel runtime sandbox** focused on constraining agent execution within a process. It does **NOT directly address desktop/UI-level threats** that Computer Use Agents face when controlling full operating systems.

**Critical Finding**: Authority Nanos creates a **capability-based containment box** for agents, but Computer Use Agents also need **visual/semantic understanding guarantees** that a unikernel cannot provide.

---

## Threat Coverage Matrix

### ✅ THREATS WELL-ADDRESSED BY NANOS

#### 1. Resource Exhaustion Attacks
**Threat**: Malicious agent exhausts compute, memory, or tool budget
- LLM token overflow
- Tool call spam
- Memory allocation bomb
- Filesystem quota flooding

**Nanos Defense**: ✅ **INV-3 (Budget Invariant)** with hard limits
```json
"budgets": {
  "tokens": 100000,
  "calls": 50,
  "file_bytes": 10485760,
  "heap_objects": 10000
}
```
- Pre-admission check (reserves before operation)
- Atomic test-and-set (no race conditions)
- Hard rejection (no soft warnings)
- **Status**: FULLY ADDRESSED

**Residual Risk**: Policy configuration error (admin sets too-high budgets)

---

#### 2. Unauthorized Tool/API Access
**Threat**: Agent calls disallowed tools or APIs
- Execution of shell commands without permission
- Network access to internal domains
- Filesystem write to protected locations
- Database manipulation

**Nanos Defense**: ✅ **INV-2 (Capability Invariant)** with scoped capabilities
```c
// Capability structure
type: "tool"
resource: "file_read"
methods: ["GET"]  // Allow list
ttl_ms: 3600000
```
- HMAC-SHA256 signed capability tokens
- Scope matching before execution
- Tool allowlist/denylist enforcement
- Fail-closed default (unknown capability = DENIED)
- **Status**: FULLY ADDRESSED

**Residual Risk**:
- Overly permissive allowlists configured
- Capability token theft (if credentials leaked)

---

#### 3. Capability Escalation/Delegation Abuse
**Threat**: Agent obtains higher privileges than intended
- Parent process privilege escalation
- Token forgery/brute force
- Capability amplification via delegation
- Cross-process capability theft

**Nanos Defense**: ✅ **Multiple layers**
1. HMAC-SHA256 prevents forgery (2^256 brute force space)
2. **Monotonic Attenuation**: Child capabilities ⊆ Parent
   - Child TTL ≤ Parent TTL
   - Child methods ⊆ Parent methods
   - Child resource ⊆ Parent resource
3. Constant-time comparison prevents timing attacks
4. Run-ID binding prevents cross-run token reuse
5. **Status**: FULLY ADDRESSED for within-process escalation

**Residual Risk**: Kernel vulnerability in HMAC/revocation system

---

#### 4. Audit Tampering / Non-Repudiation
**Threat**: Agent or attacker erases evidence of malicious actions
- Log deletion/modification
- Capability revocation log tampering
- Audit chain breakage
- Event sequence forgery

**Nanos Defense**: ✅ **INV-4 (Log Commitment Invariant)** with hash chain
```
Hash[n] = SHA256(Hash[n-1] || Entry[n])
```
- Tamper-evident: any modification breaks chain
- Synchronous fsync before response (crash-safe)
- Immutable chain from genesis to current
- Non-repudiation via request_hash
- Automatic anchoring to prevent rewrites
- **Status**: FULLY ADDRESSED

**Residual Risk**:
- Raw disk access (outside Nanos VM boundary)
- Kernel compromise (could truncate log)
- Admin erasing entire audit volume

---

#### 5. Process Isolation Boundary Violation
**Threat**: Escaping process sandbox to access sibling processes
- Breaking namespace isolation
- Shared memory exploitation
- Interprocess communication bypass
- Process registry manipulation

**Nanos Defense**: ✅ **INV-1 (No-Bypass Invariant)** + Kernel memory model
1. VM isolation: All syscalls through kernel IPC
2. Process namespace: Siblings cannot interact
3. Network namespace: Restricted to loopback
4. Mount namespace: Isolated filesystem views
5. WASM hostcalls: Capability-gated
6. **Status**: FULLY ADDRESSED within unikernel model

**Residual Risk**: VM escape (breaks all invariants)

---

#### 6. Tool Supply Chain Attacks
**Threat**: Compromised tools execute malicious code
- Trojanized dependencies
- Tool runtime exploitation
- Plugin/extension abuse

**Nanos Defense**: ⚠️ **PARTIAL**
- Tool allowlist prevents unauthorized execution ✅
- Filesystem sandbox contains tool output ✅
- Network routing through capability system ✅
- **BUT**: Does NOT verify tool integrity/signature

**Gap**: No cryptographic verification of tool binary/source

---

### ⚠️ THREATS PARTIALLY ADDRESSED

#### 7. Input Injection / Command Injection
**Threat**: Malicious input leads to unintended command execution
- Prompt injection to LLM
- Command string escaping failure
- SQL injection via tool parameters
- Path traversal in file operations

**Nanos Defense**: ⚠️ **PARTIAL**
```c
// Canonicalization prevents path traversal
target_path = canonicalize(request.path);
// Fails-closed on ambiguous cases
```
- Filesystem path canonicalization ✅
- Prevents encoding tricks ✅
- Prevents `.` and `..` traversal ✅
- **BUT**: No prompt injection detection
- **BUT**: No command syntax validation

**Gap**: Does NOT protect against LLM prompt injection at semantic level

**Example**:
```
User: "Read /etc/passwd"
↓
Agent LLM thinks: Execute "cat /etc/passwd"
↓
Agent calls: ak_sys_tool_call("file_read", "/etc/passwd")
↓
Nanos checks: Capability? Budget? ✓
Nanos executes: Permission DENIED if no capability
```
Nanos blocks the tool call, but only AFTER the agent's LLM was confused. For defense, need input sanitization/detection **before** LLM receives it.

---

#### 8. Cross-Agent Data Leakage
**Threat**: Multiple agents sharing same unikernel instance leak data between runs
- Heap memory retention between runs
- Shared cache poisoning
- Timing channel exploitation
- Covert channels via resource contention

**Nanos Defense**: ⚠️ **PARTIAL**
- Process namespace isolation ✅
- Budget reset per run ✅
- Revocation on exit ✅
- **BUT**: Shared kernel memory (between-process)
- **BUT**: No heap wiping on process exit
- **BUT**: No timing-channel protections

**Gap**: Multi-agent scenarios need memory isolation guarantees

---

#### 9. Token/Credential Theft
**Threat**: Agent leaks or steals credentials/API keys
- Printing credentials to logs
- Uploading to external service
- Token reuse across boundaries

**Nanos Defense**: ⚠️ **PARTIAL**
- Filesystem quota limits data exfiltration ✅
- Network bytes budget limits upload ✅
- Domain allowlist prevents arbitrary exfil ✅
- Audit log shows credential access ✅
- **BUT**: Doesn't prevent intentional exfil to allowed domain
- **BUT**: No credential tagging/redaction

**Gap**: Cannot distinguish legitimate API key use from credential theft

---

#### 10. Inference-Time Attacks / Jailbreaks
**Threat**: Adversarial prompts or system message injection
- Role-playing/character jailbreaks
- DAN (Do Anything Now) style attacks
- Few-shot example poisoning
- Context window overflow exploitation

**Nanos Defense**: ❌ **NOT ADDRESSED**
- Nanos enforces execution constraints
- Nanos does NOT constrain LLM prompt/response
- LLM inference happens inside Nanos sandbox but Nanos doesn't validate LLM decisions

**Gap**: Model-level security is outside Nanos scope

---

### ❌ THREATS NOT ADDRESSED BY NANOS

#### 11. Visual Instruction Confusion / UI Hijacking
**Threat** (PRIMARY for Computer Use Agents): Agent cannot verify legitimacy of UI elements
- Fake dialogs misleading agent actions
- Visual prompt injection (adversarial UI)
- Man-in-the-middle on screen content
- Denial of service via confusing UI

**Example Attack**:
```
1. Attacker modifies /etc/passwd display in terminal
2. Agent reads displayed text: "admin:x:0:0"
3. Agent believes user is "admin" when they're not
4. Agent grants elevated permissions
```

**Nanos Defense**: ❌ **ZERO COVERAGE**

**Why**: This is a **desktop/OS-level problem**, not a process-level problem
- Nanos runs IN a process (unikernel model)
- Computer Use Agent controls a FULL desktop OS
- Desktop OS rendering is outside Nanos boundary

**Gap**: Fundamental architectural mismatch
- Nanos: Single-agent-process sandbox
- CUA threat model: Full-OS control with visual deception

---

#### 12. Ransomware / Destructive Actions
**Threat**: Agent deletes/encrypts files permanently
- Filesystem wipe
- Configuration destruction
- Boot sector corruption
- Data encryption for extortion

**Nanos Defense**: ⚠️ **MITIGATION NOT PREVENTION**
- Filesystem bytes budget limits write volume ✅
- Audit log shows what was deleted ✅
- **BUT**: Cannot prevent deletion of intended target
- **BUT**: Cannot prevent agent from using full budget to destroy

**Gap**: Cannot distinguish malicious deletion from legitimate operations

---

#### 13. Supply Chain / Dependency Compromise
**Threat**: Compromised library/tool execute during agent startup
- Backdoored Python packages
- Malicious npm dependencies
- Tool plugin trojans
- Build system compromise

**Nanos Defense**: ❌ **NOT ADDRESSED**

**Why**: Nanos runs AFTER the agent is built
- Tools are pre-loaded into image
- Dependencies already resolved
- No runtime package verification

**Gap**: Need to move into build/packaging layer (outside Nanos)

---

#### 14. Persistent Backdoors / Rootkits
**Threat**: Agent installs persistent malicious code
- Cron job backdoors
- Kernel rootkit installation
- Persistent shell history manipulation
- Systemd service trojans

**Nanos Defense**: ✅ **PARTIAL MITIGATION**
- Ephemeral filesystem (tmpfs in tool scratch areas) ✅
- Read-only system binaries ✅
- **BUT**: If write access to /etc granted, can modify startup scripts
- **BUT**: No verification of binary integrity

**Gap**: Prevention requires immutable filesystem + signature verification

---

#### 15. Multi-Stage Attacks / Staged Payloads
**Threat**: Agent stages multi-step attack over multiple tool calls
- Initial reconnaissance tool call
- Download malware in second call
- Execute in third call

**Nanos Defense**: ⚠️ **DETECTION NOT PREVENTION**
- Audit log captures all calls ✅
- Budget limits reconnaissance scope ✅
- **BUT**: No anomaly detection/behavioral analysis
- **BUT**: No pattern-matching for attack sequences

**Gap**: Requires SIEM/behavioral analysis layer

---

## Detailed Gap Analysis by Dimension

### I. THREAT DIMENSION: UI/Visual Hijacking

| Attack Type | Nanos Coverage | Gap | Why |
|------------|-----------------|-----|-----|
| Fake dialog boxes | ❌ No | Agent can't verify UI authenticity | Nanos is process sandbox, not OS |
| Terminal text manipulation | ❌ No | Agent reads displayed text, not source | No screen capture validation |
| Screenshot spoofing | ❌ No | Visual content not cryptographically bound | No trusted display channel |
| Window manager deception | ❌ No | Agent trusts window system | Requires trusted UI layer |

**Solution**: Needs **trusted display channel** (hardware-backed secure UI rendering)

---

### II. THREAT DIMENSION: Inference/Model Level

| Attack Type | Nanos Coverage | Gap | Why |
|------------|-----------------|-----|-----|
| Prompt injection | ⚠️ Partial | Nanos blocks unauthorized tools, not confused LLM | LLM runs inside Nanos |
| Jailbreak/DAN | ❌ No | LLM reasoning security outside kernel scope | No control over model weights |
| Context poisoning | ❌ No | Previous messages in context not validated | No audit of LLM inputs |
| Few-shot example injection | ❌ No | System prompt not integrity-checked | Model parameters trusted |

**Solution**: Needs **model-level security** (prompt validation, input sanitization before LLM)

---

### III. THREAT DIMENSION: Desktop/OS Control

| Attack Type | Nanos Coverage | Gap | Why |
|------------|-----------------|-----|-----|
| Privilege escalation via application mediation | ⚠️ Partial | Nanos bounds each agent, not application interaction | Can't control app-to-app privs |
| Chained exploits across multiple applications | ❌ No | Each tool call sandboxed, but tool ecosystem not | Agent orchestrates tools |
| OS file descriptor/handle exhaustion | ⚠️ Partial | Process-level limits, not system-wide | Resource limit applies to agent |
| Graphics/rendering subsystem attack | ❌ No | Not applicable to process sandbox | Outside Nanos scope |

**Solution**: Needs **system-wide orchestration layer** (desktop sandboxing + agent mediation)

---

### IV. THREAT DIMENSION: Credential/Secret Management

| Attack Type | Nanos Coverage | Gap | Why |
|------------|-----------------|-----|-----|
| API key theft to attacker domain | ⚠️ Partial | Domain allowlist stops some vectors | Legitimate domain allowed |
| Database connection string leak | ⚠️ Partial | Network bytes budget limits exfil | Doesn't prevent exfil to allowed domain |
| OAuth token re-use cross-run | ⚠️ Partial | Run-ID isolates tokens | But token might live in environment |
| Plaintext secret storage in logs | ⚠️ Partial | Audit log shows what occurred | Secrets visible in audit trail |

**Solution**: Needs **secret management system** (credential redaction, token encryption)

---

### V. THREAT DIMENSION: Supply Chain / Dependencies

| Attack Type | Nanos Coverage | Gap | Why |
|------------|-----------------|-----|-----|
| Trojanized tool binary | ❌ No | Tool is already in image when Nanos starts | Need build-time verification |
| Compromised Python package | ❌ No | Installed before unikernel boots | Need dependency scanning |
| Plugin/extension malware | ❌ No | Extensions pre-loaded or dynamic | No signature verification |
| Compiler backdoor (XcodeGhost) | ❌ No | Outside Nanos entirely | Need build process security |

**Solution**: Needs **supply chain hardening** (SBOMs, signature verification, reproducible builds)

---

### VI. THREAT DIMENSION: Behavioral Anomaly Detection

| Attack Type | Nanos Coverage | Gap | Why |
|------------|-----------------|-----|-----|
| Unusual tool call sequence | ⚠️ Partial | Logged but not analyzed | Audit trail exists but no ML analysis |
| Timing anomalies | ❌ No | No timestamp correlation | Could detect via separate layer |
| Volume anomalies (token spam) | ✅ Yes | Budget enforcement prevents | Hard limits work |
| Geolocation anomalies | ❌ No | No location tracking | Network calls routed through namespace |
| Access pattern anomalies | ⚠️ Partial | Could build on audit log | Requires external SIEM integration |

**Solution**: Needs **behavioral analysis layer** (SIEM/ML pipeline on audit logs)

---

## Architectural Mismatch Analysis

### Authority Nanos Threat Model
```
┌─────────────────────────────────────┐
│  AGENT PROCESS (Single)             │
│  ┌──────────────────────────────┐   │
│  │ LLM Reasoning                │   │
│  ├──────────────────────────────┤   │
│  │ Tool Runtime (WASM/Python)   │   │
│  ├──────────────────────────────┤   │
│  │ AK Syscall Gate              │◄──┼─ INV-1: No-Bypass
│  │ (Capability Verification)    │   │ INV-2: Capability
│  │ (Budget Enforcement)         │   │ INV-3: Budget
│  │ (Audit Logging)              │   │ INV-4: Log Commitment
│  └──────────────────────────────┘   │
└─────────────────────────────────────┘
         ↑
         └─ Kernel boundary
```

**Threat Model Assumption**: Agent is process-isolated and can't escape

**Guarantees**: Effectful operations constrained to declared policy

---

### Computer Use Agent Threat Model
```
┌──────────────────────────────────────────────────┐
│  DESKTOP/LAPTOP OS (Full System)                 │
│  ┌───────────────────────────────────────────┐   │
│  │  Window Manager / UI Framework            │   │
│  │  ┌──────────────────────────────────────┐ │   │
│  │  │ Application 1 (Browser)              │ │   │
│  │  │ ┌────────────────────────────────┐   │ │   │
│  │  │ │ Agent Controls Input/Output    │   │ │   │
│  │  │ │ (Types text, reads screen)     │   │ │   │
│  │  │ └────────────────────────────────┘   │ │   │
│  │  └──────────────────────────────────────┘ │   │
│  │  ┌──────────────────────────────────────┐ │   │
│  │  │ Application 2 (File Manager)         │ │   │
│  │  │ ┌────────────────────────────────┐   │ │   │
│  │  │ │ Agent Controls Input/Output    │   │ │   │
│  │  │ └────────────────────────────────┘   │ │   │
│  │  └──────────────────────────────────────┘ │   │
│  │  ┌──────────────────────────────────────┐ │   │
│  │  │ Application 3 (Terminal)              │ │   │
│  │  │ ┌────────────────────────────────┐   │ │   │
│  │  │ │ Agent Executes Commands        │   │ │   │
│  │  │ └────────────────────────────────┘   │ │   │
│  │  └──────────────────────────────────────┘ │   │
│  └───────────────────────────────────────────┘   │
│  ┌───────────────────────────────────────────┐   │
│  │  File System (Shared)                     │   │
│  │  Kernel (Shared Resources)                │   │
│  │  Hardware (Shared)                        │   │
│  └───────────────────────────────────────────┘   │
└──────────────────────────────────────────────────┘
         ↑
         └─ No boundaries (or weak OS-level DAC)
```

**Threat Model Assumption**: Agent shares full OS with other applications/users

**Attack Surface**: Everything (visual content, inter-application mediation, OS-level privilege escalation)

---

### Mismatch Summary

| Dimension | Nanos Model | CUA Model | Mismatch |
|-----------|------------|----------|----------|
| **Scope** | Single process | Full OS | Nanos can't see OS-level threats |
| **Visual Trust** | N/A | Critical | Nanos has no UI rendering |
| **Privilege Boundary** | VM boundary | OS DAC | OS permissions insufficient |
| **Isolation** | Perfect (VM-backed) | Weak (OS-backed) | OS can be breached |
| **Multi-Agent** | Not designed | Primary | Nanos single-process model |
| **Inference Control** | Not applicable | Critical | Nanos doesn't inspect LLM |

---

## Summary of Critical Gaps

### TIER 1: Architectural Gaps (Cannot Be Fixed in Nanos Kernel)

1. **Visual Instruction Confusion / UI Hijacking** ❌
   - **Why Unfixable**: Nanos runs inside a process; UI rendering is OS-level
   - **Requires**: Trusted display layer (hardware-backed secure rendering)
   - **Impact**: HIGH - Primary attack vector for desktop use cases

2. **Inference-Time Attacks / Prompt Injection** ❌
   - **Why Unfixable**: Model reasoning is outside kernel scope
   - **Requires**: Model-level security (prompt validation, input sanitization)
   - **Impact**: HIGH - Affects all language model-based decisions

3. **Multi-Application Privilege Mediation** ❌
   - **Why Unfixable**: Nanos sandbox is per-process, not system-wide
   - **Requires**: System-level orchestration layer
   - **Impact**: MEDIUM-HIGH - Only for multi-app scenarios

---

### TIER 2: Feature Gaps (Could Be Added to Nanos)

4. **Behavioral Anomaly Detection** ⚠️
   - **Current**: Audit log exists but no analysis
   - **Gap**: No ML/SIEM integration
   - **Solution**: Export audit logs to external behavioral analytics
   - **Impact**: MEDIUM - Helps detect multi-stage attacks

5. **Credential Tagging/Redaction** ⚠️
   - **Current**: Credentials visible in audit trail and network calls
   - **Gap**: No secret management integration
   - **Solution**: Implement credential interception layer
   - **Impact**: MEDIUM - Sensitive for API key scenarios

6. **Tool Supply Chain Verification** ⚠️
   - **Current**: Tool allowlist controls execution
   - **Gap**: No cryptographic verification of tool binaries
   - **Solution**: Require tool signatures, verify at load time
   - **Impact**: MEDIUM - For security-critical tools

---

### TIER 3: Partial Mitigations (Nanos Helps But Isn't Complete)

7. **Input Injection / Command Injection** ⚠️
   - **Current**: Path canonicalization, fail-closed checking
   - **Gap**: Prompt injection not detected, only subsequent tool execution blocked
   - **Nanos Does**: Prevents unauthorized tool calls
   - **Still Needs**: Input sanitization at model level

8. **Ransomware / Destructive Actions** ⚠️
   - **Current**: Filesystem bytes budget + audit trail
   - **Gap**: Can't distinguish malicious from legitimate deletion
   - **Nanos Does**: Limits damage volume and creates evidence
   - **Still Needs**: Sandboxed filesystem with rollback

9. **Cross-Agent Data Leakage** ⚠️
   - **Current**: Process isolation, per-run revocation
   - **Gap**: Shared kernel memory in multi-agent scenario
   - **Nanos Does**: Basic isolation between runs
   - **Still Needs**: Memory wiping, timing-channel protections

---

## Recommended Defense-in-Depth Architecture

### Layer 1: Input Sanitization (Model-Level)
```
User Input
    ↓
[Prompt Injection Detection]  ← Semantic analysis
[Encoding Normalization]     ← Pre-process
[Content Policy Check]       ← Blocklist
    ↓
LLM Inference
```

### Layer 2: Agent Execution (Nanos Kernel)
```
LLM Decision
    ↓
[Canonicalization]          ← Path traversal prevention
[Capability Verification]   ← Token validation (INV-2)
[Budget Check]             ← Admission control (INV-3)
[Fail-Closed Logic]        ← Conservative defaults
    ↓
Tool Execution
    ↓
[Audit Log]                ← Hash-chained evidence (INV-4)
```

### Layer 3: Tool Containment (OS-Level)
```
Tool Call Result
    ↓
[Sandbox Enforcement]       ← Network namespace, mount namespace
[Resource Limits]          ← cgroups, ulimit
[Behavioral Monitoring]    ← SIEM integration
    ↓
Return to Agent
```

### Layer 4: Multi-Agent Orchestration (System-Level)
```
Multiple Agent Processes
    ↓
[Desktop Privilege Model]   ← Cross-app mediation
[Visual Trust Layer]       ← Trusted display rendering
[Incident Response]        ← Suspend/isolate capability
```

### Layer 5: Supply Chain Security (Build-Time)
```
Dependencies
    ↓
[SBOM Generation]          ← Material listing
[Signature Verification]   ← Cryptographic check
[Reproducible Builds]      ← Verifiable compilation
    ↓
Agent Binary
```

---

## Conclusion

### What Authority Nanos Does Exceptionally Well

Authority Nanos provides **mathematically-enforced guarantees** for:
- ✅ **Authorized Access Only** (INV-2: Capability Invariant)
- ✅ **Resource Limits** (INV-3: Budget Invariant)
- ✅ **Tamper-Evident Auditing** (INV-4: Log Commitment Invariant)
- ✅ **Process Escape Prevention** (INV-1: No-Bypass Invariant)

This makes it **excellent for constrained, controlled agent deployments** where:
- Agents perform well-defined tool calls
- Policy is precisely specified
- Audit compliance is critical

---

### What Nanos Cannot Address

Authority Nanos cannot directly protect against:
- ❌ **Visual/UI Deception** (Desktop OS rendering, not kernel)
- ❌ **Model-Level Attacks** (LLM reasoning, not kernel)
- ❌ **Multi-App Privilege Escalation** (System-wide, not per-process)
- ❌ **Supply Chain Compromise** (Build-time, not runtime)

These require **additional layers outside the Nanos kernel**.

---

### Recommended Deployment

**Use Nanos for Computer Use Agents When:**
1. Agent actions are pre-approved tool calls (not freeform OS commands)
2. Audit compliance is mandatory
3. Untrusted environment where agent could be compromised
4. Multi-tenancy with strong isolation needed

**Don't Use Nanos Alone For:**
1. Agents with full desktop control (need trusted UI layer)
2. Scenarios with unvetted LLM models (need prompt security)
3. Supply chain security (need build-time verification)

---

### Path Forward: Integrated Security Stack

```
┌─────────────────────────────────────────────────────┐
│ DEFENSE-IN-DEPTH FOR COMPUTER USE AGENTS           │
├─────────────────────────────────────────────────────┤
│ [Layer 5] Supply Chain Security                     │
│           SBOM, signatures, reproducible builds     │
├─────────────────────────────────────────────────────┤
│ [Layer 4] Visual Trust / UI Rendering               │
│           Hardware-backed secure display            │
├─────────────────────────────────────────────────────┤
│ [Layer 3] Multi-Agent Orchestration                 │
│           Desktop privilege mediation                │
├─────────────────────────────────────────────────────┤
│ [Layer 2] Runtime Sandboxing ← AUTHORITY NANOS      │
│           INV-1, INV-2, INV-3, INV-4                │
├─────────────────────────────────────────────────────┤
│ [Layer 1] Model-Level Security                      │
│           Prompt injection detection                │
├─────────────────────────────────────────────────────┤
│ [Cross-Layer] Behavioral Monitoring / SIEM          │
└─────────────────────────────────────────────────────┘
```

Authority Nanos is **Layer 2** (the kernel/runtime enforcement layer). Computer Use Agent security requires all 5 layers working together.
