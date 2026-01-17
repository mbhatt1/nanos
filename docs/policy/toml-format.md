# TOML Policy Format

::: warning P1 Feature
TOML policy format is planned for P1. Currently, use the [JSON format](/policy/json-format).
:::

## Overview

TOML provides a more human-friendly policy format:

```toml
version = "1.0"

[fs]
read = [
    "/app/**",
    "/lib/**",
    "/etc/ssl/**"
]
write = [
    "/tmp/**",
    "/app/data/**"
]

[net]
dns = ["api.github.com", "*.googleapis.com"]
connect = [
    "dns:api.github.com:443",
    "dns:*.googleapis.com:443"
]
bind = ["ip:0.0.0.0:8080"]
listen = ["ip:0.0.0.0:8080"]

[tools]
allow = ["http_get", "http_post", "file_read"]
deny = ["shell_exec"]

[infer]
models = ["gpt-4", "claude-*"]
max_tokens = 100000

[budgets]
tool_calls = 100
tokens = 100000
wall_time_ms = 300000

profiles = ["tier1-musl"]
```

## Benefits over JSON

| Feature | JSON | TOML |
|---------|------|------|
| Comments | No | Yes (`#`) |
| Trailing commas | No | Yes |
| Multi-line strings | Escaped | Native |
| Readability | Moderate | High |

## Example with Comments

```toml
version = "1.0"

# Filesystem access
[fs]
read = [
    "/app/**",      # Application files
    "/lib/**",      # System libraries
    "/etc/ssl/**",  # SSL certificates
]
write = [
    "/tmp/**",      # Temporary files
    "/app/logs/**", # Application logs
]

# Network access - be specific!
[net]
dns = [
    "api.github.com",
    "api.anthropic.com",
]
connect = [
    "dns:api.github.com:443",
    "dns:api.anthropic.com:443",
]

# Tool permissions
[tools]
allow = [
    "http_get",   # Safe read-only HTTP
    "file_read",  # Read files within policy
]
deny = [
    "shell_exec", # NEVER allow shell execution
]

# LLM inference
[infer]
models = ["claude-*"]  # Any Claude model
max_tokens = 100_000   # Underscore for readability

# Resource budgets
[budgets]
tool_calls = 100
tokens = 100_000
wall_time_ms = 300_000  # 5 minutes

# Include base profile
profiles = ["tier1-musl"]
```

## Compilation

TOML policies are compiled to JSON at build time:

```makefile
policy.json: ak.toml
    $(TOOLS)/ak-compile $< $@

INITRD_FILES += /ak/policy.json:policy.json
```

## Validation

The TOML compiler performs:

1. Syntax validation
2. Schema validation
3. Pattern validation
4. Security warnings (e.g., overly permissive rules)

## Migration from JSON

To convert an existing JSON policy to TOML:

```bash
ak-convert policy.json > policy.toml
```

## Current Status

TOML support is planned for P1. For now, use the JSON format which provides identical functionality.
