---
layout: home

hero:
  name: Authority Nanos
  text: Fork of Nanos with Authority Kernel
  tagline: The AI-First Unikernel for Autonomous Agents
  actions:
    - theme: brand
      text: Get Started
      link: /getting-started/
    - theme: alt
      text: View on GitHub
      link: https://github.com/nanovms/authority-nanos

features:
  - icon: "🔐"
    title: Capability-Based Security
    details: Fine-grained access control with HMAC-SHA256 signed tokens. Every operation requires explicit authorization.
  - icon: "📝"
    title: Tamper-Evident Audit Logs
    details: Hash-chained cryptographic logging of all operations. Complete auditability for compliance and debugging.
  - icon: "🤖"
    title: Native LLM Integration
    details: Local models via virtio-serial (Ollama, vLLM) and external APIs (OpenAI, Anthropic). Hybrid routing support.
  - icon: "🚀"
    title: Minimal Attack Surface
    details: Single-process unikernel with no SSH, no users, no unnecessary syscalls. VM-level isolation by design.
  - icon: "⚡"
    title: Cross-Platform
    details: Full support for x86_64 and ARM64. Deploy to AWS, GCP, Azure, Raspberry Pi, and more.
  - icon: "🔄"
    title: Deny-by-Default
    details: All operations denied unless explicitly allowed by policy. Fail-closed security model throughout.
---

## System Architecture

```mermaid
graph TB
    subgraph "Agent Application"
        APP[AI Agent Code]
        SDK[Authority SDK]
    end

    subgraph "Authority Kernel"
        GATE[Single Authority Gate]

        subgraph "Security Layer"
            CAP[Capability Verifier]
            POL[Policy Engine]
            AUDIT[Audit Logger]
            BUDGET[Budget Controller]
        end

        subgraph "Effect Handlers"
            FS[Filesystem Effects]
            NET[Network Effects]
            TOOL[Tool Effects]
            INFER[Inference Effects]
        end
    end

    subgraph "Nanos Kernel"
        SYSCALL[Syscall Interface]
        MEM[Memory Manager]
        SCHED[Scheduler]
        DRV[Device Drivers]
    end

    subgraph "Hardware / Hypervisor"
        HV[KVM / HVF / QEMU]
    end

    APP --> SDK
    SDK --> GATE
    GATE --> CAP
    CAP --> POL
    POL --> BUDGET
    BUDGET --> AUDIT

    AUDIT --> FS
    AUDIT --> NET
    AUDIT --> TOOL
    AUDIT --> INFER

    FS --> SYSCALL
    NET --> SYSCALL
    TOOL --> SYSCALL
    INFER --> SYSCALL

    SYSCALL --> MEM
    SYSCALL --> SCHED
    SYSCALL --> DRV

    DRV --> HV

    style GATE fill:#e74c3c,color:#fff
    style CAP fill:#3498db,color:#fff
    style POL fill:#3498db,color:#fff
    style AUDIT fill:#2ecc71,color:#fff
    style BUDGET fill:#9b59b6,color:#fff
```

## Request Flow

Every operation in Authority Nanos follows this security pipeline:

```mermaid
sequenceDiagram
    participant Agent as AI Agent
    participant Gate as Authority Gate
    participant Cap as Capability Check
    participant Pol as Policy Engine
    participant Bud as Budget Control
    participant Aud as Audit Log
    participant Exec as Executor
    participant Kern as Nanos Kernel

    Agent->>Gate: Effect Request
    Gate->>Gate: Parse & Validate
    Gate->>Cap: Verify Capability

    alt Invalid Capability
        Cap-->>Agent: E_CAP_INVALID
    end

    Cap->>Pol: Check Policy

    alt Policy Deny
        Pol-->>Agent: E_POLICY_DENY
    end

    Pol->>Bud: Check Budget

    alt Budget Exceeded
        Bud-->>Agent: E_BUDGET_EXCEEDED
    end

    Bud->>Aud: Log Request
    Aud->>Exec: Execute Operation
    Exec->>Kern: Syscall
    Kern-->>Exec: Result
    Exec->>Aud: Log Response
    Aud->>Aud: fsync()
    Aud-->>Agent: Success Response
```

## What is Authority Nanos?

Authority Nanos is a **fork of [Nanos](https://github.com/mbhatt1/nanos)** that adds the **Authority Kernel** — a capability-based security layer purpose-built for running autonomous AI agents in production.

```mermaid
graph LR
    subgraph "Standard Nanos"
        N1[Unikernel Core]
        N2[POSIX Syscalls]
        N3[Network Stack]
        N4[Filesystem]
    end

    subgraph "Authority Nanos Additions"
        A1[Capability System]
        A2[Policy Engine]
        A3[Audit Logging]
        A4[Budget Control]
        A5[LLM Gateway]
        A6[Tool Sandbox]
    end

    N1 --> A1
    N2 --> A2
    N3 --> A5
    N4 --> A3

    style A1 fill:#e74c3c,color:#fff
    style A2 fill:#3498db,color:#fff
    style A3 fill:#2ecc71,color:#fff
    style A4 fill:#9b59b6,color:#fff
    style A5 fill:#f39c12,color:#fff
    style A6 fill:#1abc9c,color:#fff
```

## Security Model

```mermaid
flowchart TB
    subgraph "Four Security Invariants"
        INV1[INV-1: No Bypass<br/>All I/O through kernel]
        INV2[INV-2: Capability Required<br/>HMAC-signed tokens]
        INV3[INV-3: Budget Enforced<br/>Pre-admission control]
        INV4[INV-4: Audit Committed<br/>Hash-chained logs]
    end

    subgraph "Security Guarantees"
        G1[Containment]
        G2[Least Privilege]
        G3[Complete Audit]
        G4[Bounded Cost]
    end

    INV1 --> G1
    INV2 --> G1
    INV2 --> G2
    INV4 --> G3
    INV3 --> G4

    style INV1 fill:#e74c3c,color:#fff
    style INV2 fill:#3498db,color:#fff
    style INV3 fill:#9b59b6,color:#fff
    style INV4 fill:#2ecc71,color:#fff
```

## Quick Example

Create a policy file (`/ak/policy.json`):

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
  "profiles": ["tier1-musl"]
}
```

Build and run:

```bash
authority build myapp -c config.json
authority run myapp
```

## Deployment Options

```mermaid
graph TB
    subgraph "Development"
        DEV[Local Machine]
        QEMU[QEMU/HVF]
    end

    subgraph "Cloud"
        AWS[AWS EC2]
        GCP[Google Cloud]
        AZURE[Azure VMs]
    end

    subgraph "Edge"
        RPI[Raspberry Pi]
        JETSON[NVIDIA Jetson]
    end

    AUTH[Authority Nanos<br/>Image]

    AUTH --> DEV
    AUTH --> AWS
    AUTH --> GCP
    AUTH --> AZURE
    AUTH --> RPI
    AUTH --> JETSON

    DEV --> QEMU

    style AUTH fill:#e74c3c,color:#fff
```

## Project Status

| Component | Status |
|-----------|--------|
| Core Kernel | Stable |
| Authority Kernel | Stable |
| Security Invariants (INV-1 to INV-4) | Enforced |
| Documentation | Active |

See the [roadmap](/architecture/#roadmap) for upcoming features.
