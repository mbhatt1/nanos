# Security Invariants

Authority Nanos enforces four foundational security invariants. These are not guidelines — they are properties that the implementation **MUST** preserve at all times.

Any invariant violation is a **P0 security incident**.

## Invariant Overview

```mermaid
graph TB
    subgraph "INV-1: No-Bypass"
        NB1[All I/O through kernel]
        NB2[No direct hardware access]
        NB3[Namespace isolation]
    end

    subgraph "INV-2: Capability Required"
        CAP1[HMAC-SHA256 verification]
        CAP2[Scope matching]
        CAP3[Revocation checking]
    end

    subgraph "INV-3: Budget Enforced"
        BUD1[Pre-admission check]
        BUD2[Atomic decrement]
        BUD3[Hard limits only]
    end

    subgraph "INV-4: Log Commitment"
        LOG1[Hash chain]
        LOG2[fsync before respond]
        LOG3[Tamper detection]
    end

    INV1[INV-1] --> G1[Containment]
    INV2[INV-2] --> G1
    INV2[INV-2] --> G2[Least Privilege]
    INV3[INV-3] --> G3[Bounded Cost]
    INV4[INV-4] --> G4[Complete Audit]

    style INV1 fill:#e74c3c,color:#fff
    style INV2 fill:#3498db,color:#fff
    style INV3 fill:#9b59b6,color:#fff
    style INV4 fill:#2ecc71,color:#fff
    style G1 fill:#f39c12,color:#fff
```

## INV-1: No-Bypass Invariant

> **Statement**: Agents cannot perform external IO except via kernel IPC.

### Preconditions

- Agent process is confined (namespaces + seccomp on Linux; ES framework on macOS)
- Network namespace contains only loopback
- Filesystem is read-only except designated scratch
- Only allowed syscalls are in whitelist

### Formal Definition

```
∀ agent A, ∀ IO operation O:
    O is external ⟹ O goes through kernel IPC channel
```

### Enforcement Points

1. Seccomp-BPF filter blocks: `socket(AF_INET*)`, `execve`, `fork`, `ptrace`
2. Network namespace isolation
3. Mount namespace with pivot_root to isolated root
4. File descriptor inheritance blocked

### Verification

Confinement escape tests MUST pass before any agent execution.

## INV-2: Capability Invariant

> **Statement**: Every effectful syscall must carry a valid, non-revoked capability whose scope subsumes the request.

### Formal Definition

```
∀ syscall S where effect(S) = true:
    ∃ capability C in request R such that:
        valid(C) ∧ ¬revoked(C) ∧ scope(C) ⊇ resource(S)
```

### Implementation Requirements

- **valid(C)**: HMAC-SHA256 verification passes
- **¬revoked(C)**: Token ID not in revocation map R
- **scope(C) ⊇ resource(S)**:
  - C.type matches operation type
  - C.resource pattern matches target resource
  - C.methods includes requested method
  - C.ttl not expired
  - C.rate not exceeded

### Enforcement Points

1. `capability_verify()` called BEFORE any syscall dispatch
2. Revocation map checked synchronously (not eventual consistency)
3. Scope matching is strict (deny if ambiguous)

### Verification

Capability forgery tests MUST fail to forge valid tokens.

## INV-3: Budget Invariant

> **Statement**: Admission control rejects any operation that would exceed declared run budgets.

### Formal Definition

```
∀ operation O with cost(O) = c:
    let current = Σ(costs of completed operations in run)
    let budget = declared_budget(run_id, resource_type)

    PRE: current + c ≤ budget
    POST: current' = current + c

    If PRE fails: reject with E_BUDGET_EXCEEDED (no state change)
```

### Budget Dimensions

| Resource | Unit | Default Limit |
|----------|------|---------------|
| LLM Input Tokens | tokens | 1,000,000 |
| LLM Output Tokens | tokens | 100,000 |
| Tool Calls | count | 100 |
| Wall Time | ms | 300,000 |
| Heap Objects | count | 10,000 |
| Blob Storage | bytes | 100 MB |

### Enforcement Points

1. Budget check BEFORE operation starts
2. Atomic decrement-or-reject (no race conditions)
3. No "soft limits" — hard enforcement only

### Verification

Budget exhaustion tests MUST block at limit.

## INV-4: Log Commitment Invariant

> **Statement**: Each committed transition appends a log entry whose hash chain validates from genesis to head.

### Formal Definition

```
∀ state transition T from Σ to Σ':
    ∃ log entry E such that:
        E.prev_hash = hash(log[n-1])
        E.this_hash = SHA256(E.prev_hash || canonical(E))
        E.req_hash = SHA256(canonical(request))
        E.res_hash = SHA256(canonical(response))

        AND: log' = log ++ [E]
        AND: Response sent to agent only AFTER fsync(log)
```

### Hash Chain Properties

- **Append-only**: No deletions, no modifications
- **Tamper-evident**: Any modification breaks chain
- **Non-repudiation**: Agent cannot deny actions (req_hash proves request)

### Enforcement Points

1. Log write in same transaction as state mutation
2. `fsync()` before response
3. Crash recovery validates chain from genesis

### Verification

Log tamper tests MUST detect any bit flip.

## Security Theorems

```mermaid
flowchart TB
    subgraph "Adversary Classes"
        ADV1[Class I<br/>Prompt Injection]
        ADV2[Class II<br/>Model Poisoning]
        ADV3[Class III<br/>Tool Escape]
    end

    subgraph "Attack Vectors"
        DIRECT[Direct I/O]
        NOCAP[Syscall w/o Cap]
        FORGE[Forged Capability]
    end

    subgraph "Defenses"
        INV1[INV-1: Confinement]
        INV2[INV-2: Cap Check]
        HMAC[HMAC Verification]
    end

    subgraph "Result"
        BLOCK[BLOCKED]
    end

    ADV1 --> DIRECT
    ADV2 --> NOCAP
    ADV3 --> FORGE

    DIRECT --> INV1 --> BLOCK
    NOCAP --> INV2 --> BLOCK
    FORGE --> HMAC --> BLOCK

    style BLOCK fill:#27ae60,color:#fff
    style ADV1 fill:#c0392b,color:#fff
    style ADV2 fill:#c0392b,color:#fff
    style ADV3 fill:#c0392b,color:#fff
```

### Theorem 1: Containment

> Under adversary classes I-III, no side effects occur except through validated syscalls.

**Adversary Classes**:
- Class I: Arbitrary malicious inputs (prompt injection)
- Class II: Compromised agent logic (model poisoning)
- Class III: Tool runtime escape attempts

**Proof Sketch**:
```
Given: INV-1 (no bypass) + INV-2 (capability required)
Assume: Side effect E occurs outside kernel validation

Case 1: E via direct IO
    → Blocked by confinement (INV-1) ⊥

Case 2: E via syscall without capability
    → Rejected by capability check (INV-2) ⊥

Case 3: E via forged capability
    → HMAC verification fails (INV-2) ⊥

∴ No such E exists. QED.
```

### Theorem 2: Audit Completeness

> Every state-changing operation produces a corresponding log entry whose hash commits to all prior entries.

**Proof Sketch**:
```
Given: INV-4 (log commitment)

For any state Σ at time t:
    Let L = [E₀, E₁, ..., Eₙ] be the log

    ∀ i ∈ [1,n]: Eᵢ.prev_hash = hash(Eᵢ₋₁)

    To reconstruct Σ:
        Start from genesis state Σ₀
        Apply each Eᵢ sequentially
        Verify hash chain at each step

    Any tampering at position k:
        Eₖ'.this_hash ≠ Eₖ₊₁.prev_hash
        → Chain breaks → Detected

∴ Audit trail is complete and tamper-evident. QED.
```

### Theorem 3: Budget Enforcement

> Resource consumption is bounded by declared budgets; exceeding operations rejected pre-execution.

**Proof Sketch**:
```
Given: INV-3 (budget invariant)

∀ run R with budget B:
    Let Cᵢ = cost of operation i
    Let Sₙ = Σᵢ₌₁ⁿ Cᵢ (total cost after n operations)

    By INV-3: ∀ n: Sₙ + Cₙ₊₁ > B ⟹ operation n+1 rejected

    ∴ Sₙ ≤ B for all n
    ∴ Total resource consumption ≤ B. QED.
```

## Verification Matrix

| Invariant | Test Category | Pass Criteria |
|-----------|---------------|---------------|
| INV-1 | Confinement | 0 escape paths |
| INV-2 | Capability | 0 forgeries, 0 bypasses |
| INV-3 | Budget | 0 overruns |
| INV-4 | Audit | 0 undetected tampering |

**Continuous Verification**:
- Every commit runs invariant tests
- Every PR requires security review
- Every release requires penetration test
