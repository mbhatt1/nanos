# Policy Overview

The Authority Kernel uses a **deny-by-default** policy model:

- If no policy is loaded, ALL operations are denied
- If a policy is loaded, only explicitly allowed operations succeed
- Missing rules for a category = deny that category

## Policy Evaluation Flow

```mermaid
flowchart TD
    REQ[Effect Request] --> LOAD{Policy Loaded?}

    LOAD -->|No| DENY1[DENY<br/>No policy found]
    LOAD -->|Yes| MATCH{Pattern Match?}

    MATCH -->|No Match| DENY2[DENY<br/>No rule covers request]
    MATCH -->|Match Found| RULE{Rule Decision?}

    RULE -->|DENY| DENY3[DENY<br/>Explicit deny rule]
    RULE -->|ALLOW| BUDGET{Budget OK?}
    RULE -->|REQUIRE_APPROVAL| APPROVE[Wait for Approval]

    BUDGET -->|Exceeded| DENY4[DENY<br/>Budget exceeded]
    BUDGET -->|OK| ALLOW[ALLOW<br/>Execute operation]

    style DENY1 fill:#c0392b,color:#fff
    style DENY2 fill:#c0392b,color:#fff
    style DENY3 fill:#c0392b,color:#fff
    style DENY4 fill:#c0392b,color:#fff
    style ALLOW fill:#27ae60,color:#fff
    style APPROVE fill:#f39c12,color:#fff
```

## Policy Structure

```mermaid
graph TB
    subgraph "Policy File"
        VER[version: 1.0]

        subgraph FS[Filesystem Rules]
            FS_R[read: patterns]
            FS_W[write: patterns]
        end

        subgraph NET[Network Rules]
            NET_DNS[dns: domains]
            NET_CON[connect: targets]
            NET_BIND[bind: addresses]
            NET_LIST[listen: addresses]
        end

        subgraph TOOLS[Tool Rules]
            T_ALLOW[allow: names]
            T_DENY[deny: names]
        end

        subgraph INFER[Inference Rules]
            I_MODELS[models: patterns]
            I_TOKENS[max_tokens: limit]
        end

        subgraph BUDGETS[Budget Limits]
            B_CALLS[tool_calls]
            B_TOKENS[tokens]
            B_TIME[wall_time_ms]
        end

        PROFILES[profiles: includes]
    end

    style VER fill:#3498db,color:#fff
    style FS fill:#2ecc71,color:#fff
    style NET fill:#9b59b6,color:#fff
    style TOOLS fill:#e74c3c,color:#fff
    style INFER fill:#f39c12,color:#fff
    style BUDGETS fill:#1abc9c,color:#fff
```

## Policy Formats

Authority Nanos supports two policy formats:

- [JSON Format](/policy/json-format) - Primary format for P0
- [TOML Format](/policy/toml-format) - Human-friendly alternative (P1)

## Policy Location

```mermaid
graph LR
    subgraph "Development"
        INITRD[/ak/policy.json<br/>in initrd]
    end

    subgraph "Production"
        EMBED[Embedded in kernel<br/>at compile time]
    end

    subgraph "Runtime"
        LOADER[Policy Loader]
        CACHE[Cached Policy]
    end

    INITRD --> LOADER
    EMBED --> LOADER
    LOADER --> CACHE

    style INITRD fill:#3498db,color:#fff
    style EMBED fill:#e74c3c,color:#fff
    style CACHE fill:#2ecc71,color:#fff
```

### Development (Initrd)

Place your policy at `/ak/policy.json` in the initrd:

```bash
mkdir -p initrd/ak
cp policy.json initrd/ak/policy.json
```

### Production (Embedded)

Compile policy into the kernel image:

```makefile
CFLAGS += -DCONFIG_AK_EMBEDDED_POLICY=1
```

## Pattern Matching

```mermaid
graph TB
    subgraph "Filesystem Pattern Matching"
        PATH[/app/data/file.txt]

        P1["/app/**"] -->|MATCH| PATH
        P2["/app/data/*"] -->|MATCH| PATH
        P3["/app/data/file.txt"] -->|MATCH| PATH
        P4["/tmp/**"] -->|NO MATCH| PATH
    end

    subgraph "Network Pattern Matching"
        TARGET[dns:api.github.com:443]

        N1["dns:api.github.com:443"] -->|MATCH| TARGET
        N2["dns:*.github.com:443"] -->|MATCH| TARGET
        N3["dns:*:443"] -->|MATCH| TARGET
        N4["ip:*:443"] -->|NO MATCH| TARGET
    end

    style PATH fill:#3498db,color:#fff
    style TARGET fill:#9b59b6,color:#fff
```

## Quick Reference

### Filesystem Rules

```json
{
  "fs": {
    "read": ["/app/**", "/lib/**"],
    "write": ["/tmp/**"]
  }
}
```

### Network Rules

```json
{
  "net": {
    "dns": ["api.github.com", "*.googleapis.com"],
    "connect": ["dns:api.github.com:443", "ip:10.0.0.0/8:5432"],
    "bind": ["ip:0.0.0.0:8080"],
    "listen": ["ip:0.0.0.0:8080"]
  }
}
```

### Tool Rules

```json
{
  "tools": {
    "allow": ["http_get", "file_read"],
    "deny": ["shell_exec"]
  }
}
```

### Inference Rules

```json
{
  "infer": {
    "models": ["gpt-4", "claude-*"],
    "max_tokens": 100000
  }
}
```

### Budgets

```json
{
  "budgets": {
    "tool_calls": 100,
    "tokens": 100000,
    "wall_time_ms": 300000
  }
}
```

## Budget Enforcement

```mermaid
sequenceDiagram
    participant Agent
    participant Gate as Authority Gate
    participant Budget as Budget Controller
    participant Op as Operation

    Agent->>Gate: Request (cost=10 tokens)
    Gate->>Budget: Check budget

    Budget->>Budget: current=90, limit=100
    Budget->>Budget: 90 + 10 <= 100?

    alt Within Budget
        Budget-->>Gate: OK
        Gate->>Op: Execute
        Op-->>Gate: Success
        Gate->>Budget: Commit cost
        Budget->>Budget: current = 100
        Gate-->>Agent: Success
    else Exceeds Budget
        Budget-->>Gate: E_BUDGET_EXCEEDED
        Gate-->>Agent: Error (budget exceeded)
    end
```

## Profile Inheritance

```mermaid
graph TB
    subgraph "Built-in Profiles"
        TIER1[tier1-musl<br/>Minimal]
        TIER2[tier2-glibc<br/>Dynamic linking]
    end

    subgraph "User Policy"
        USER[User Rules]
        PROFILES[profiles: tier1-musl]
    end

    subgraph "Effective Policy"
        MERGED[Merged Rules]
    end

    TIER1 --> MERGED
    USER --> MERGED
    PROFILES -.->|includes| TIER1

    style TIER1 fill:#3498db,color:#fff
    style TIER2 fill:#9b59b6,color:#fff
    style MERGED fill:#2ecc71,color:#fff
```

## Denial Debugging

```mermaid
sequenceDiagram
    participant Agent
    participant AK as Authority Kernel
    participant Console
    participant LastError as Last Error Buffer

    Agent->>AK: open("/etc/secret", O_RDONLY)
    AK->>AK: Check policy
    AK->>AK: No match for /etc/secret

    AK->>Console: AK DENY FS_OPEN /etc/secret...
    AK->>LastError: Store denial details

    AK-->>Agent: -EACCES

    Agent->>AK: syscall(AK_SYS_LAST_ERROR)
    AK->>LastError: Read stored denial
    LastError-->>Agent: JSON with details
```

### Console Messages

When an operation is denied:

```
AK DENY FS_OPEN /etc/secret missing fs.read. Fix: read = ["/etc/secret"]
```

### Last Error Syscall

```c
char buf[1024];
syscall(AK_SYS_LAST_ERROR, buf, sizeof(buf));
// buf contains JSON with denial details
```

### Record Mode

Run with `AK_RECORD=1` to accumulate suggestions:

```bash
AK_RECORD=1 ./myapp
```

## Validation

P0 validates:
- Version field present and correct
- All patterns are valid strings
- All numbers are valid integers
- No unknown fields (warning)

### Common Errors

| Error | Cause | Fix |
|-------|-------|-----|
| "Missing version" | No version field | Add `"version": "1.0"` |
| "Invalid JSON" | Syntax error | Check JSON syntax |
| "Pattern too long" | Pattern > 256 chars | Shorten pattern |
| "Invalid CIDR" | Bad CIDR format | Check format |
