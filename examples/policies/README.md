# Authority Kernel Policy Files

This directory contains policy files for each of the Authority SDK examples.

## Policy Files

| Policy File | Example | Description |
|-------------|---------|-------------|
| `01_heap_policy.json` | `01_heap_operations.py` | Heap operations (alloc, read, write, delete) with budgets |
| `02_authorization_policy.json` | `02_authorization.py` | File read and HTTP authorization |
| `03_tool_policy.json` | `03_tool_execution.py` | Tool execution (add, concat, file_read) |
| `04_inference_policy.json` | `04_inference.py` | LLM inference (gpt-4, claude) |
| `05_audit_policy.json` | `05_audit_logging.py` | Audit log access |

## Policy Loading

The minops tool automatically detects and loads policy files based on the script name.
For example, running `01_heap_operations.py` will auto-load `01_heap_policy.json`.

Manual override:
```bash
minops run examples/01_heap_operations.py -p examples/policies/01_heap_policy.json
```

## Policy JSON Format

```json
{
  "version": "1.0",
  "fs": {
    "read": ["/usr/**", "/lib/**"],
    "write": ["/tmp/**"]
  },
  "net": {
    "dns": ["api.example.com"],
    "connect": ["dns:api.example.com:443"]
  },
  "tools": {
    "allow": ["add", "concat"],
    "deny": ["shell_exec"]
  },
  "infer": {
    "models": ["gpt-4"],
    "max_tokens": 100000
  },
  "budgets": {
    "heap_objects": 1000,
    "heap_bytes": 10485760,
    "tool_calls": 100,
    "tokens": 100000,
    "wall_time_ms": 60000
  }
}
```

## Current Status

**Note:** The Authority SDK examples require a kernel ABI fix to work correctly.
The issue is a mismatch between libak's syscall argument format and the kernel's
expected format in `ak_syscall_handler`.

Basic Python execution works correctly. See `test-simple.py` for a working example.

### Issue Details

- **libak** passes: `arg0=&request, arg1=&response, arg2=0, arg3=0, arg4=0`
- **Kernel expects**: `arg0=agent_id|0, arg1=req_buf, arg2=req_len, arg3=resp_buf, arg4=resp_len`

This causes the kernel to misinterpret the request pointer as an agent ID, failing with -ESRCH.

### Resolution

Fix options:
1. Update libak to use kernel's expected format (serialize requests as JSON buffers)
2. Update kernel to detect and handle libak's structure format
3. Create a compatibility layer

Until fixed, Authority SDK features will not work, but basic Python execution functions correctly.
