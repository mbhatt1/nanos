# Authority Nanos Python SDK

Secure AI agent development with capability-based authorization.

## Installation

```bash
pip install authority-nanos
```

## Quick Start

```python
from authority_nanos import AuthorityKernel

# Simulation mode - works without kernel
with AuthorityKernel(simulate=True) as ak:
    # Allocate a typed object
    handle = ak.alloc("counter", b'{"value": 0}')

    # Read it back
    data = ak.read(handle)
    print(data)  # b'{"value": 0}'

    # Update with JSON Patch
    ak.write(handle, b'[{"op": "replace", "path": "/value", "value": 42}]')

# Real mode - requires running kernel
with AuthorityKernel() as ak:
    # Same API, but operations go through the kernel
    handle = ak.alloc("counter", b'{"value": 0}')
```

## Features

- **Simulation Mode**: Test your agents without running the kernel
- **Typed Heap**: Allocate, read, write, delete typed objects
- **Authorization**: Policy-controlled access to resources
- **Tool Execution**: Run WASM tools in sandbox
- **LLM Inference**: Policy-controlled LLM access
- **Audit Logging**: Tamper-evident audit trail

## Documentation

- [Getting Started](https://authority-systems.github.io/nanos/getting-started/)
- [API Reference](https://authority-systems.github.io/nanos/api/)
- [Security Model](https://authority-systems.github.io/nanos/security/)

## License

Apache 2.0
