# API Overview

The Authority Kernel provides a set of syscalls for AI agent operations.

## Syscall Architecture

```mermaid
graph TB
    subgraph "User Space"
        APP[AI Agent Application]
        SDK[Authority SDK]
    end

    subgraph "Authority Kernel Syscalls"
        direction TB
        STATE[State Management<br/>1024-1027]
        TOOLS[Tool Calls<br/>1028-1029]
        AUDIT[Audit<br/>1030-1031]
        CTRL[Control<br/>1032-1036]
        COG[Cognitive<br/>1037]
        UX[Deny UX<br/>1040-1042]
    end

    subgraph "Processing Pipeline"
        GATE[Authority Gate]
        POLICY[Policy Check]
        EXEC[Execute]
        LOG[Audit Log]
    end

    APP --> SDK
    SDK --> STATE
    SDK --> TOOLS
    SDK --> AUDIT
    SDK --> CTRL
    SDK --> COG
    SDK --> UX

    STATE --> GATE
    TOOLS --> GATE
    AUDIT --> GATE
    CTRL --> GATE
    COG --> GATE
    UX --> GATE

    GATE --> POLICY
    POLICY --> EXEC
    EXEC --> LOG

    style GATE fill:#e74c3c,color:#fff
    style STATE fill:#3498db,color:#fff
    style TOOLS fill:#9b59b6,color:#fff
    style AUDIT fill:#2ecc71,color:#fff
    style COG fill:#f39c12,color:#fff
```

## Syscall Categories

### State Management (1024-1027)

| Syscall | Number | Description |
|---------|--------|-------------|
| `AK_SYS_READ` | 1024 | Read heap object |
| `AK_SYS_ALLOC` | 1025 | Allocate new object |
| `AK_SYS_WRITE` | 1026 | Patch object (CAS) |
| `AK_SYS_DELETE` | 1027 | Soft-delete object |

### Tools (1028-1029)

| Syscall | Number | Description |
|---------|--------|-------------|
| `AK_SYS_CALL` | 1028 | Execute tool |
| `AK_SYS_BATCH` | 1029 | Atomic batch operation |

### Audit (1030-1031)

| Syscall | Number | Description |
|---------|--------|-------------|
| `AK_SYS_COMMIT` | 1030 | Force log commit |
| `AK_SYS_QUERY` | 1031 | Query audit log |

### Control (1032-1036)

| Syscall | Number | Description |
|---------|--------|-------------|
| `AK_SYS_SPAWN` | 1032 | Create child agent |
| `AK_SYS_SEND` | 1033 | Send message |
| `AK_SYS_RECV` | 1034 | Receive message |
| `AK_SYS_ASSERT` | 1035 | Assert predicate (halt on fail) |
| `AK_SYS_RESPOND` | 1036 | Send response to external |

### Cognitive (1037)

| Syscall | Number | Description |
|---------|--------|-------------|
| `AK_SYS_INFERENCE` | 1037 | LLM gateway |

### Deny UX (1040-1042)

| Syscall | Number | Description |
|---------|--------|-------------|
| `AK_SYS_LAST_ERROR` | 1040 | Get last denial info |
| `AK_SYS_TRACE_RING_READ` | 1041 | Read trace ring buffer |
| `AK_SYS_POLICY_SUGGEST` | 1042 | Dump policy suggestions |

## Error Codes

```mermaid
graph TB
    subgraph "Error Code Ranges"
        direction TB
        PROTO[-4000 to -4099<br/>Protocol Errors]
        CAP[-4100 to -4199<br/>Capability Errors]
        POL[-4200 to -4299<br/>Policy Errors]
        RES[-4300 to -4399<br/>Resource Errors]
        EXEC[-4400 to -4499<br/>Execution Errors]
    end

    subgraph "Common Error Flows"
        REQ[Request] --> PARSE{Parse OK?}
        PARSE -->|No| PROTO
        PARSE -->|Yes| CAPV{Cap Valid?}
        CAPV -->|No| CAP
        CAPV -->|Yes| POLV{Policy OK?}
        POLV -->|No| POL
        POLV -->|Yes| BUDV{Budget OK?}
        BUDV -->|No| RES
        BUDV -->|Yes| RUN{Execute OK?}
        RUN -->|No| EXEC
        RUN -->|Yes| SUCCESS[Success]
    end

    style PROTO fill:#e74c3c,color:#fff
    style CAP fill:#e74c3c,color:#fff
    style POL fill:#e74c3c,color:#fff
    style RES fill:#e74c3c,color:#fff
    style EXEC fill:#e74c3c,color:#fff
    style SUCCESS fill:#27ae60,color:#fff
```

### Protocol Errors (-4000 to -4099)

| Code | Name | Description |
|------|------|-------------|
| -4001 | `E_FRAME_TOO_LARGE` | Request exceeds max size |
| -4002 | `E_SCHEMA_INVALID` | JSON schema validation failed |
| -4003 | `E_SCHEMA_UNKNOWN` | Unknown schema type |

### Capability Errors (-4100 to -4199)

| Code | Name | Description |
|------|------|-------------|
| -4100 | `E_CAP_MISSING` | No capability provided |
| -4101 | `E_CAP_INVALID` | HMAC verification failed |
| -4102 | `E_CAP_EXPIRED` | Capability TTL exceeded |
| -4103 | `E_CAP_SCOPE` | Capability doesn't cover request |
| -4104 | `E_CAP_REVOKED` | Capability has been revoked |
| -4105 | `E_CAP_RATE` | Rate limit exceeded |

### Policy Errors (-4200 to -4299)

| Code | Name | Description |
|------|------|-------------|
| -4200 | `E_REPLAY` | Duplicate sequence number |
| -4201 | `E_POLICY_DENY` | Policy explicitly denies |
| -4202 | `E_APPROVAL_REQUIRED` | Human approval needed |
| -4203 | `E_TAINT` | Taint level too high |

### Resource Errors (-4300 to -4399)

| Code | Name | Description |
|------|------|-------------|
| -4300 | `E_BUDGET_EXCEEDED` | Would exceed budget |
| -4301 | `E_RATE_LIMIT` | Rate limit exceeded |
| -4302 | `E_DEADLINE` | Operation timed out |

### Execution Errors (-4400 to -4499)

| Code | Name | Description |
|------|------|-------------|
| -4400 | `E_CONFLICT` | CAS version mismatch |
| -4401 | `E_TOOL_FAIL` | Tool execution failed |
| -4402 | `E_DLP_BLOCK` | DLP blocked content |

## Request/Response Flow

```mermaid
sequenceDiagram
    participant Agent as AI Agent
    participant SDK as Authority SDK
    participant Gate as Authority Gate
    participant Exec as Executor
    participant Audit as Audit Log

    Agent->>SDK: Function call
    SDK->>SDK: Build JSON request

    Note over SDK: Request Structure:<br/>pid, run_id, seq,<br/>op, args, cap

    SDK->>Gate: Syscall with JSON
    Gate->>Gate: Parse & Validate
    Gate->>Gate: Verify Capability
    Gate->>Gate: Check Policy
    Gate->>Gate: Check Budget

    alt All Checks Pass
        Gate->>Exec: Execute operation
        Exec-->>Gate: Result
        Gate->>Audit: Log success
        Audit-->>Gate: seq, hash
        Gate-->>SDK: Success response
        SDK-->>Agent: Parsed result
    else Check Failed
        Gate->>Audit: Log denial
        Gate-->>SDK: Error response
        SDK-->>Agent: Error with fix suggestion
    end
```

## Request Format

All AK syscalls use JSON request/response:

```json
{
  "pid": "agent-7a3f",
  "run_id": "2024-01-15T10:30:00Z",
  "seq": 42,
  "op": "WRITE",
  "args": { ... },
  "cap": { ... }
}
```

## Response Format

```json
{
  "ok": true,
  "result": { ... },
  "usage": {
    "tokens": 150,
    "latency_ms": 23
  }
}
```

Or on error:

```json
{
  "ok": false,
  "error": {
    "code": -4201,
    "name": "E_POLICY_DENY",
    "message": "Operation denied by policy",
    "missing_cap": "fs.write",
    "suggested_fix": "write = [\"/path/to/file\"]"
  }
}
```

## Further Reading

- [Syscalls Reference](/api/syscalls) - Detailed syscall documentation
- [Effects Reference](/api/effects) - Effect types and authorization
