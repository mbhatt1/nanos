# Authority Nanos Python SDK Examples

This directory contains example scripts demonstrating the Authority Nanos Python SDK capabilities.

## Examples

### 1. Basic Heap Operations (`01_heap_operations.py`)

Demonstrates typed memory management with allocation, reading, and modification:

- **Allocate**: Create typed objects in the kernel's heap
- **Read**: Retrieve object data
- **Write**: Modify objects using JSON Patch (RFC 6902)
- **Delete**: Clean up allocated objects

Usage:
```bash
python3 examples/01_heap_operations.py
```

### 2. Authorization and Policy (`02_authorization.py`)

Demonstrates capability-based authorization checks:

- **Check authorization** for protected operations
- **File I/O** with policy enforcement
- **HTTP requests** with policy control
- **Error handling** for denied operations

Usage:
```bash
python3 examples/02_authorization.py
```

### 3. WASM Tool Execution (`03_tool_execution.py`)

Demonstrates sandboxed execution of WASM tools:

- **Execute WASM tools** in isolated sandbox
- **Pass arguments** to tools via JSON
- **Receive results** with capability-based access control
- **Error handling** for tool failures

Usage:
```bash
python3 examples/03_tool_execution.py
```

### 4. LLM Inference (`04_inference.py`)

Demonstrates policy-controlled LLM inference:

- **Send inference requests** to configured LLM
- **Policy enforcement** on model access
- **Token budgeting** and rate limiting
- **Response handling** with streaming support

Usage:
```bash
python3 examples/04_inference.py
```

### 5. Audit Logging (`05_audit_logging.py`)

Demonstrates tamper-proof audit logging:

- **Read audit logs** - Append-only, hash-chained entries
- **Query logs** - Filter by event type, actor, timestamp
- **Verify integrity** - Hash chain ensures tampering detection
- **Compliance** - Non-repudiation for security events

Usage:
```bash
python3 examples/05_audit_logging.py
```

## Running Examples

### Prerequisites

1. **Python 3.8+** installed
2. **Authority Nanos SDK** installed:
   ```bash
   pip install -e sdk/python/
   ```
3. **Authority Kernel** running (kernel process or Docker container)

### Setting up the Kernel

The examples require a running Authority Kernel. This can be:

- **Native**: Built locally and run as a process
- **Docker**: Use the provided Dockerfile for containerized kernel
- **Remote**: Connect to a remote kernel instance

### Running Individual Examples

```bash
# Heap operations
python3 examples/01_heap_operations.py

# Authorization checks
python3 examples/02_authorization.py

# Tool execution
python3 examples/03_tool_execution.py

# LLM inference
python3 examples/04_inference.py

# Audit logging
python3 examples/05_audit_logging.py
```

### Expected Output

When the kernel is running, examples will show:
- ✅ Success indicators for completed operations
- ℹ️  Informational messages for expected errors (e.g., unconfigured features)
- ❌ Error indicators for unexpected failures

Example output from `01_heap_operations.py`:
```
✅ Connected to Authority Kernel
✅ Allocated counter with handle: 0x...
✅ Read counter: {'value': 0, 'name': 'counter'}
✅ Updated counter to version: 1
✅ Updated counter: {'value': 42, 'name': 'counter'}
✅ Deleted counter handle
```

## Error Handling

Examples demonstrate proper error handling patterns:

- **AuthorityKernelError**: Base exception for kernel errors
- **OperationDeniedError**: Policy denied the operation
- **CapabilityError**: Invalid or expired capability
- **InvalidArgumentError**: Bad argument to syscall
- **NotFoundError**: Resource not found
- **BufferOverflowError**: Buffer too small
- **TimeoutError**: Operation timed out
- **OutOfMemoryError**: Kernel out of memory
- **LibakError**: Low-level libak error

## Advanced Usage

### Custom Policy Configuration

Create a `policy.toml` file:
```toml
[[capability]]
name = "example_tool"
resource = "*"
methods = ["execute"]
expires_minutes = 60
```

Load in your code:
```python
from authority_nanos import AuthorityKernel

with AuthorityKernel() as ak:
    ak.load_policy("policy.toml")
    # Use policy-controlled operations
```

### Batch Operations

Process multiple operations efficiently:
```python
with AuthorityKernel() as ak:
    handles = []

    # Allocate many objects
    for i in range(100):
        handle = ak.alloc(f"item_{i}", json.dumps({"id": i}).encode())
        handles.append(handle)

    # Process in batches
    for handle in handles:
        data = ak.read(handle)
        # Process...
        ak.delete(handle)
```

### Resource Budgeting

Monitor and enforce resource budgets:
```python
with AuthorityKernel() as ak:
    try:
        # Set memory budget
        ak.set_budget("memory", 10_000_000)  # 10MB

        # Set compute budget
        ak.set_budget("compute", 1_000_000)  # 1M operations

        # Operations are tracked and limited
        for i in range(1000):
            handle = ak.alloc(f"obj_{i}", b"data")

    except BudgetExceededError:
        print("Budget exceeded - operation denied")
```

## Documentation

For more details, see:
- [Python SDK Documentation](../docs/guide/python-sdk.md)
- [API Reference](../docs/api/index.md)
- [Architecture Guide](../docs/architecture/index.md)
- [Security Model](../docs/security/index.md)

## Troubleshooting

### "Kernel connection failed"
- Ensure Authority Kernel is running
- Check kernel logs for errors
- Verify network connectivity (if remote)

### "libak.so not found"
- Install SDK: `pip install -e sdk/python/`
- Build kernel: `make -j$(nproc)`
- Set library path: `export LD_LIBRARY_PATH=output/platform/pc/lib:$LD_LIBRARY_PATH`

### "Authorization denied"
- Check policy configuration
- Verify capabilities are granted
- Review audit logs for denial reasons

### "Buffer overflow"
- Increase buffer size in example code
- Reduce data size being read/written
- Check data format expectations

## Contributing

To add new examples:
1. Create `NN_example_name.py` in this directory
2. Include docstring explaining functionality
3. Add error handling for expected failures
4. Update this README with new example
5. Test with and without kernel running

## License

Examples are provided under the same license as Authority Nanos (Apache 2.0).
