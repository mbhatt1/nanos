# JSON Policy Format

The primary policy format for Authority Kernel P0.

## Complete Example

```json
{
  "version": "1.0",

  "fs": {
    "read": [
      "/app/**",
      "/lib/**",
      "/usr/lib/**"
    ],
    "write": [
      "/tmp/**",
      "/app/data/**"
    ]
  },

  "net": {
    "dns": [
      "api.github.com",
      "*.googleapis.com"
    ],
    "connect": [
      "dns:api.github.com:443",
      "dns:*.googleapis.com:443",
      "ip:10.0.0.0/8:5432"
    ],
    "bind": [
      "ip:0.0.0.0:8080"
    ],
    "listen": [
      "ip:0.0.0.0:8080"
    ]
  },

  "tools": {
    "allow": [
      "http_get",
      "http_post",
      "file_read"
    ],
    "deny": [
      "shell_exec",
      "file_write_raw"
    ]
  },

  "wasm": {
    "modules": [
      "trusted_module",
      "crypto_utils"
    ],
    "hostcalls": [
      "fs_read",
      "net_fetch",
      "crypto_sign"
    ]
  },

  "infer": {
    "models": [
      "gpt-4",
      "claude-*"
    ],
    "max_tokens": 100000
  },

  "budgets": {
    "tool_calls": 100,
    "tokens": 100000,
    "wall_time_ms": 300000,
    "cpu_ns": 60000000000,
    "bytes": 104857600
  },

  "profiles": [
    "tier1-musl"
  ]
}
```

## Section Reference

### version (required)

Must be `"1.0"` for P0.

```json
{
  "version": "1.0"
}
```

### fs (Filesystem Rules)

Controls file access.

```json
{
  "fs": {
    "read": ["pattern1", "pattern2"],
    "write": ["pattern3"]
  }
}
```

**Pattern Syntax:**

| Pattern | Description |
|---------|-------------|
| `/path/to/file` | Exact file |
| `/path/to/dir/*` | Files in directory |
| `/path/to/dir/**` | Recursive (all files under directory) |
| `*.txt` | Files ending in .txt |

**Example:**

```json
{
  "fs": {
    "read": [
      "/app/**",
      "/etc/hosts",
      "/lib/**",
      "/proc/self/**"
    ],
    "write": [
      "/tmp/**",
      "/app/logs/**"
    ]
  }
}
```

### net (Network Rules)

Controls network access.

```json
{
  "net": {
    "dns": ["domain patterns"],
    "connect": ["connection patterns"],
    "bind": ["bind patterns"],
    "listen": ["listen patterns"]
  }
}
```

**DNS Patterns:**

| Pattern | Matches |
|---------|---------|
| `example.com` | Exact domain |
| `*.example.com` | Subdomains |
| `*` | Any domain (dangerous!) |

**Connect Patterns:**

| Pattern | Matches |
|---------|---------|
| `dns:example.com:443` | Connect to resolved IP of domain |
| `dns:*.example.com:*` | Any subdomain, any port |
| `ip:10.0.0.0/8:5432` | IP CIDR with port |
| `ip:1.2.3.4:443` | Specific IP and port |

**Bind/Listen Patterns:**

| Pattern | Matches |
|---------|---------|
| `ip:0.0.0.0:8080` | Bind to all interfaces, port 8080 |
| `ip:[::]:8080` | IPv6 all interfaces |
| `ip:127.0.0.1:*` | Localhost, any port |

**Example:**

```json
{
  "net": {
    "dns": [
      "api.github.com",
      "*.googleapis.com"
    ],
    "connect": [
      "dns:api.github.com:443",
      "dns:*.googleapis.com:443",
      "ip:10.0.0.0/8:5432"
    ],
    "bind": ["ip:0.0.0.0:8080"],
    "listen": ["ip:0.0.0.0:8080"]
  }
}
```

### tools (Tool Rules)

Controls tool execution via `AK_SYS_CALL`.

```json
{
  "tools": {
    "allow": ["tool_name", "prefix_*"],
    "deny": ["dangerous_tool"]
  }
}
```

**Matching:**

| Pattern | Matches |
|---------|---------|
| `tool_name` | Exact match |
| `prefix_*` | Prefix match |
| `*` | Any tool (dangerous!) |

**Precedence:** deny rules take precedence over allow.

**Example:**

```json
{
  "tools": {
    "allow": ["http_get", "http_post", "file_*", "json_parse"],
    "deny": ["file_delete", "shell_exec"]
  }
}
```

### wasm (WASM Rules)

Controls WASM module execution and host calls.

```json
{
  "wasm": {
    "modules": ["module_names"],
    "hostcalls": ["allowed_hostcalls"]
  }
}
```

**Example:**

```json
{
  "wasm": {
    "modules": ["crypto_utils", "data_processor", "trusted_*"],
    "hostcalls": ["fs_read", "net_fetch", "crypto_sign", "crypto_verify"]
  }
}
```

### infer (Inference Rules)

Controls LLM inference requests.

```json
{
  "infer": {
    "models": ["model_patterns"],
    "max_tokens": 100000
  }
}
```

**Model Patterns:**

| Pattern | Matches |
|---------|---------|
| `gpt-4` | Exact model |
| `claude-*` | Any Claude model |
| `*` | Any model |

**Example:**

```json
{
  "infer": {
    "models": ["gpt-4", "gpt-3.5-turbo", "claude-3-opus", "claude-*"],
    "max_tokens": 100000
  }
}
```

### budgets

Resource limits for the run.

```json
{
  "budgets": {
    "tool_calls": 100,
    "tokens": 100000,
    "wall_time_ms": 300000,
    "cpu_ns": 60000000000,
    "bytes": 104857600
  }
}
```

| Budget | Description | Example |
|--------|-------------|---------|
| `tool_calls` | Max tool invocations | 100 |
| `tokens` | Max LLM tokens (in+out) | 100000 |
| `wall_time_ms` | Max wall clock time (ms) | 300000 (5 min) |
| `cpu_ns` | Max CPU time (ns) | 60000000000 (60s) |
| `bytes` | Max I/O bytes | 104857600 (100MB) |

### profiles

Include predefined policy fragments.

```json
{
  "profiles": ["tier1-musl", "custom_profile"]
}
```

**Built-in Profiles:**

| Profile | Description |
|---------|-------------|
| `tier1-musl` | Minimal for static/musl binaries |
| `tier2-glibc` | Additional rules for dynamic/glibc |

## Common Patterns

### Web Application

```json
{
  "version": "1.0",
  "fs": {
    "read": ["/app/**", "/etc/ssl/**"],
    "write": ["/app/logs/**", "/tmp/**"]
  },
  "net": {
    "dns": ["*"],
    "connect": ["dns:*:443", "dns:*:80"],
    "bind": ["ip:0.0.0.0:8080"],
    "listen": ["ip:0.0.0.0:8080"]
  },
  "profiles": ["tier1-musl"]
}
```

### Database Client

```json
{
  "version": "1.0",
  "fs": {
    "read": ["/app/**", "/etc/ssl/**"]
  },
  "net": {
    "dns": ["db.internal"],
    "connect": ["dns:db.internal:5432"]
  },
  "profiles": ["tier1-musl"]
}
```

### AI Agent

```json
{
  "version": "1.0",
  "fs": {
    "read": ["/app/**"],
    "write": ["/app/workspace/**"]
  },
  "net": {
    "dns": ["api.openai.com", "api.anthropic.com"],
    "connect": ["dns:api.openai.com:443", "dns:api.anthropic.com:443"]
  },
  "tools": {
    "allow": ["http_get", "file_read", "file_write"],
    "deny": ["shell_exec"]
  },
  "infer": {
    "models": ["gpt-4", "claude-*"],
    "max_tokens": 100000
  },
  "budgets": {
    "tool_calls": 50,
    "tokens": 100000
  },
  "profiles": ["tier1-musl"]
}
```
