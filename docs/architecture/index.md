# Architecture Overview

Authority Nanos is a **fork of [Nanos](https://github.com/nanovms/nanos)** that adds the Authority Kernel — a capability-based security layer for AI agents.

## System Stack

```mermaid
graph TB
    subgraph "User Space"
        APP[AI Agent Application]
        LIB[Authority SDK / libc]
    end

    subgraph "Authority Kernel Layer"
        GATE["ak_authorize_and_execute()"]

        subgraph "Security Pipeline"
            direction LR
            PARSE[Parse] --> SCHEMA[Schema]
            SCHEMA --> SEQ[Sequence]
            SEQ --> CAP[Capability]
            CAP --> POLICY[Policy]
            POLICY --> BUDGET[Budget]
            BUDGET --> TAINT[Taint]
        end

        subgraph "Effect Handlers"
            FS_EFF[FS Effects]
            NET_EFF[Net Effects]
            TOOL_EFF[Tool Effects]
            INFER_EFF[Inference]
        end

        AUDIT[Audit Logger]
    end

    subgraph "Nanos Kernel"
        VFS[Virtual Filesystem]
        NETSTACK[Network Stack]
        SCHED[Scheduler]
        MEM[Memory Manager]
        VIRTIO[Virtio Drivers]
    end

    subgraph "Hypervisor"
        KVM[KVM/HVF/QEMU]
    end

    APP --> LIB
    LIB --> GATE
    GATE --> PARSE

    TAINT --> FS_EFF
    TAINT --> NET_EFF
    TAINT --> TOOL_EFF
    TAINT --> INFER_EFF

    FS_EFF --> AUDIT
    NET_EFF --> AUDIT
    TOOL_EFF --> AUDIT
    INFER_EFF --> AUDIT

    AUDIT --> VFS
    AUDIT --> NETSTACK
    VFS --> VIRTIO
    NETSTACK --> VIRTIO
    SCHED --> VIRTIO
    MEM --> VIRTIO
    VIRTIO --> KVM

    style GATE fill:#e74c3c,color:#fff
    style AUDIT fill:#2ecc71,color:#fff
```

## Core Principle: Single Authority Gate

All authority-bearing operations MUST flow through ONE enforcement function:

```mermaid
flowchart LR
    subgraph "Entry Points"
        POSIX[POSIX Syscalls]
        AK_API[AK Syscalls]
        TOOL[Tool Calls]
        WASM[WASM Hostcalls]
    end

    GATE[["ak_authorize_and_execute()"]]

    subgraph "Outcomes"
        ALLOW[Execute & Log]
        DENY[Deny & Log]
    end

    POSIX --> GATE
    AK_API --> GATE
    TOOL --> GATE
    WASM --> GATE

    GATE --> ALLOW
    GATE --> DENY

    style GATE fill:#e74c3c,color:#fff
    style DENY fill:#c0392b,color:#fff
    style ALLOW fill:#27ae60,color:#fff
```

- POSIX syscalls are a **compatibility frontend** that translate into AK effects
- Default is **DENY-BY-DEFAULT**: if policy cannot prove allow, deny the effect
- Agentic primitives (tools, WASM, inference) are first-class effects

## Effect Model

Every effectful operation is expressed as an **AK Effect**:

```mermaid
classDiagram
    class ak_effect_req {
        +ak_effect_op_t op
        +u64 trace_id
        +pid_t pid
        +tid_t tid
        +char target[512]
        +u8 params[4096]
        +u32 params_len
        +budget_t budget
    }

    class ak_decision {
        +boolean allow
        +int reason_code
        +int errno_equiv
        +char missing_cap[64]
        +char suggested_snippet[512]
        +u64 trace_id
    }

    class ak_effect_op {
        <<enumeration>>
        AK_E_FS_OPEN
        AK_E_FS_UNLINK
        AK_E_NET_CONNECT
        AK_E_NET_DNS_RESOLVE
        AK_E_TOOL_CALL
        AK_E_INFER
    }

    ak_effect_req --> ak_effect_op
    ak_effect_req ..> ak_decision : produces
```

## Key Components

### Component Relationships

```mermaid
graph TB
    subgraph "Policy System"
        POLICY_FILE[Policy File<br/>JSON/TOML]
        POLICY_LOADER[Policy Loader]
        POLICY_V2[ak_policy_v2_t]
        PATTERN[Pattern Matcher]
    end

    subgraph "Capability System"
        CAP_TOKEN[Capability Token]
        HMAC[HMAC-SHA256]
        KEYRING[Keyring]
        REVOKE[Revocation Map]
    end

    subgraph "Audit System"
        LOG_ENTRY[Log Entry]
        HASH_CHAIN[Hash Chain]
        RING_BUF[Ring Buffer]
        ANCHOR[External Anchor]
    end

    subgraph "Budget System"
        BUDGET_DEF[Budget Definition]
        USAGE[Usage Tracker]
        ADMIT[Admission Control]
    end

    POLICY_FILE --> POLICY_LOADER
    POLICY_LOADER --> POLICY_V2
    POLICY_V2 --> PATTERN

    CAP_TOKEN --> HMAC
    HMAC --> KEYRING
    CAP_TOKEN --> REVOKE

    LOG_ENTRY --> HASH_CHAIN
    HASH_CHAIN --> RING_BUF
    HASH_CHAIN --> ANCHOR

    BUDGET_DEF --> ADMIT
    USAGE --> ADMIT

    style HMAC fill:#e74c3c,color:#fff
    style HASH_CHAIN fill:#2ecc71,color:#fff
    style ADMIT fill:#9b59b6,color:#fff
```

### Capability Token Structure

```mermaid
graph LR
    subgraph "Capability Token"
        TYPE[Type<br/>Net/FS/Tool/Infer]
        RESOURCE[Resource Pattern<br/>*.github.com]
        METHODS[Methods<br/>GET, POST]
        TTL[TTL<br/>3600000ms]
        RATE[Rate Limit<br/>100/min]
        RUN_ID[Run ID]
        MAC[HMAC-SHA256<br/>32 bytes]
    end

    KEY[Signing Key] --> MAC
    TYPE --> MAC
    RESOURCE --> MAC
    METHODS --> MAC
    TTL --> MAC
    RATE --> MAC
    RUN_ID --> MAC

    style MAC fill:#e74c3c,color:#fff
```

### Audit Log Hash Chain

```mermaid
graph LR
    GENESIS[Genesis<br/>0x00...00]

    E1[Entry 1]
    E2[Entry 2]
    E3[Entry 3]
    EN[Entry N]

    GENESIS -->|prev_hash| E1
    E1 -->|prev_hash| E2
    E2 -->|prev_hash| E3
    E3 -->|...| EN

    subgraph "Entry Structure"
        SEQ[seq: N]
        TS[timestamp]
        OP[operation]
        REQ_H[req_hash]
        RES_H[res_hash]
        PREV[prev_hash]
        THIS[this_hash]
    end

    style GENESIS fill:#95a5a6,color:#fff
    style THIS fill:#2ecc71,color:#fff
```

## Request Processing Pipeline

```mermaid
stateDiagram-v2
    [*] --> Receive: Request arrives

    Receive --> Parse: Read frame
    Parse --> Schema: JSON valid

    Schema --> Sequence: Schema valid
    Sequence --> Capability: Not replay

    Capability --> Policy: Cap valid
    Policy --> Budget: Policy allows

    Budget --> Taint: Budget OK
    Taint --> Execute: Taint OK

    Execute --> Log: Operation done
    Log --> Respond: fsync complete
    Respond --> [*]: Response sent

    Parse --> Reject: Invalid JSON
    Schema --> Reject: Bad schema
    Sequence --> Reject: Replay detected
    Capability --> Reject: Invalid/expired cap
    Policy --> Reject: Policy deny
    Budget --> Reject: Exceeded
    Taint --> Reject: Taint violation
    Execute --> Reject: Execution error

    Reject --> LogDeny: Log denial
    LogDeny --> [*]: Error response

    note right of Capability: HMAC verification
    note right of Log: Must fsync before respond
```

## Modes of Operation

```mermaid
graph TB
    subgraph "AK_MODE_OFF"
        OFF_POSIX[POSIX Syscalls] --> OFF_KERN[Kernel]
        OFF_NOTE[No AK enforcement<br/>Legacy mode]
    end

    subgraph "AK_MODE_SOFT"
        SOFT_POSIX[POSIX Syscalls] --> SOFT_AK[Authority Kernel]
        SOFT_AK --> SOFT_KERN[Kernel]
        SOFT_NOTE[POSIX routed through AK<br/>Enforcement active]
    end

    subgraph "AK_MODE_HARD"
        HARD_AK[AK Syscalls Only] --> HARD_KERN[Kernel]
        HARD_POSIX[Raw POSIX] -->|DENIED| HARD_BLOCK[Blocked]
        HARD_NOTE[Must use AK API<br/>Strictest mode]
    end

    style OFF_NOTE fill:#f39c12,color:#fff
    style SOFT_NOTE fill:#3498db,color:#fff
    style HARD_NOTE fill:#e74c3c,color:#fff
```

## Platform Support

```mermaid
graph TB
    AUTH[Authority Nanos]

    subgraph "x86_64"
        X86_KVM[Linux + KVM]
        X86_HVF[macOS + HVF]
        X86_QEMU[QEMU TCG]
    end

    subgraph "ARM64"
        ARM_KVM[Linux + KVM]
        ARM_HVF[macOS + HVF]
        ARM_RPI[Raspberry Pi]
    end

    subgraph "Cloud"
        AWS[AWS EC2/Graviton]
        GCP[Google Cloud]
        AZURE[Azure VMs]
    end

    AUTH --> X86_KVM
    AUTH --> X86_HVF
    AUTH --> X86_QEMU
    AUTH --> ARM_KVM
    AUTH --> ARM_HVF
    AUTH --> ARM_RPI

    X86_KVM --> AWS
    X86_KVM --> GCP
    X86_KVM --> AZURE
    ARM_KVM --> AWS

    style AUTH fill:#e74c3c,color:#fff
```

## Roadmap

```mermaid
gantt
    title Authority Nanos Roadmap
    dateFormat  YYYY-MM
    section Core
    Deny-by-default enforcement    :done, 2024-01, 2024-06
    Security invariants INV-1-4    :done, 2024-03, 2024-06
    POSIX syscall routing          :done, 2024-04, 2024-07

    section Policy
    JSON policy format             :done, 2024-05, 2024-08
    TOML policy format             :active, 2024-09, 2025-01
    Policy simulation tools        :2025-02, 2025-06

    section Security
    Audit logging                  :done, 2024-06, 2024-09
    Budget enforcement             :done, 2024-07, 2024-10
    WASM tool sandbox              :active, 2024-10, 2025-03

    section Future
    Distributed audit log          :2025-03, 2025-09
    Formal verification            :2025-06, 2026-01
```
