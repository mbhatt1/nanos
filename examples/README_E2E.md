# Authority Nanos Examples - Complete End-to-End Guide

This guide covers both **host-side** and **kernel-side** Python execution with Authority Nanos.

## Architecture

Authority Nanos has two execution modes:

### 1. Host-Side Execution (SDK Examples)
Python code runs on **host machine** (macOS/Linux) and makes syscalls to the Authority Kernel:

```
Host Machine (macOS/Linux)
┌─────────────────────────┐
│  Python Example Code    │
│  (examples/01-05.py)    │
│                         │
│  Authority Nanos SDK    │
│  (ctypes bindings)      │
└──────────────┬──────────┘
               │ Syscalls (1024-1100)
               ▼
┌─────────────────────────┐
│ Authority Kernel        │
│ (Nanos Unikernel)       │
│                         │
│ - libak                 │
│ - Policy Engine         │
│ - Capabilities          │
└─────────────────────────┘
```

**Use case**: Control and audit applications running on hosts, enforce policies at kernel level.

### 2. Kernel-Side Execution (Unikernel Examples)
Python code compiled **INTO** the kernel image and executes directly inside the unikernel:

```
Nanos Unikernel (QEMU/KVM)
┌─────────────────────────┐
│  Python Application     │
│  (running inside)       │
│                         │
│  Nanos Kernel           │
│  - Python Runtime       │
│  - File System          │
│  - Network Stack        │
│  - Authority Kernel     │
└─────────────────────────┘
```

**Use case**: Deploy secure, isolated Python applications with minimal overhead.

---

## Part 1: Host-Side Examples (Ready Now)

### Setup

```bash
# Build libak
make -j$(nproc)

# Run examples with helper script
./examples/run_example.sh 1  # Heap operations
./examples/run_example.sh 2  # Authorization
./examples/run_example.sh 3  # Tool execution
./examples/run_example.sh 4  # Inference
./examples/run_example.sh 5  # Audit logging
```

### Available Examples

1. **01_heap_operations.py** - Typed memory management with JSON Patch
2. **02_authorization.py** - Capability-based authorization
3. **03_tool_execution.py** - WASM tool sandboxing
4. **04_inference.py** - LLM inference with policy control
5. **05_audit_logging.py** - Tamper-proof audit logs

### Example: Heap Operations

```python
from authority_nanos import AuthorityKernel
import json

with AuthorityKernel() as ak:
    # Allocate a counter object
    handle = ak.alloc("counter", b'{"value": 0}')

    # Read it back
    data = ak.read(handle)
    counter = json.loads(data.decode('utf-8'))
    print(f"Counter: {counter}")

    # Update with JSON Patch
    patch = b'[{"op": "replace", "path": "/value", "value": 42}]'
    new_version = ak.write(handle, patch)

    # Clean up
    ak.delete(handle)
```

**When this works**: Requires Authority Kernel module loaded on host OS (kernel extension).

---

## Part 2: Kernel-Side Examples (Unikernel)

### Option A: Using `ops` Tool (Recommended)

Install `ops`:
```bash
curl https://ops.city/get.sh -sSfL | sh
```

### Create Kernel-Side Python Application

```bash
mkdir -p kernel-examples/hello-auth
cd kernel-examples/hello-auth
```

Create `main.py`:
```python
#!/usr/bin/env python3
"""
Authority Nanos Python Application
Runs inside the unikernel with direct libak access.
"""

import sys
import json

print("✅ Python running inside Authority Nanos unikernel!")

# Test basic operations
print(f"Python version: {sys.version}")
print(f"Platform: {sys.platform}")

# Test JSON
data = {
    "kernel": "Authority Nanos",
    "language": "Python",
    "execution": "inside-unikernel",
    "status": "✅ working"
}
print(f"Data: {json.dumps(data, indent=2)}")

# Test filesystem (if mounted)
try:
    with open("/proc/cmdline", "r") as f:
        cmdline = f.read()
        print(f"Kernel cmdline: {cmdline}")
except:
    print("Filesystem not available")

print("✅ Unikernel execution complete!")
sys.exit(0)
```

Create `config.json`:
```json
{
  "Args": ["main.py"],
  "ManifestPassthrough": {
    "expected_exit_code": ["0"],
    "debug_exit": "t"
  }
}
```

### Run Inside Kernel

```bash
# Verify kernel image exists
ls -lh ../../../output/platform/pc/bin/kernel.img

# Run Python inside kernel
ops run main.py -c config.json

# You should see:
# ✅ Python running inside Authority Nanos unikernel!
# Python version: 3.x.x
# Platform: nanos
# Data: {...}
# ✅ Unikernel execution complete!
```

### Option B: Using Authority SDK Inside Kernel

Create `auth_app.py`:
```python
#!/usr/bin/env python3
"""
Authority Nanos app with libak syscalls
"""

import sys
sys.path.insert(0, '/lib/python')

# Inside kernel, libak is directly available
try:
    from authority_nanos import AuthorityKernel, AuthorityKernelError

    print("✅ Authority Kernel SDK loaded inside unikernel")

    # Create context (syscalls go directly to kernel)
    with AuthorityKernel() as ak:
        print("✅ Connected to Authority Kernel")

        # Allocate object in kernel heap
        handle = ak.alloc("test", b'{"msg": "hello from inside"}')
        print(f"✅ Allocated handle: {handle}")

        # Read back
        data = ak.read(handle)
        print(f"✅ Read: {data.decode()}")

        # Clean up
        ak.delete(handle)
        print("✅ Deleted handle")

except AuthorityKernelError as e:
    print(f"❌ Kernel error: {e}")
    sys.exit(1)
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("✅ Application complete!")
sys.exit(0)
```

---

## Part 3: End-to-End Test

### Full Test: Host SDK → Kernel → Audit

Create `test_e2e.sh`:
```bash
#!/bin/bash
set -e

echo "🚀 Authority Nanos End-to-End Test"
echo ""

# 1. Build kernel with Python support
echo "1️⃣  Building kernel with Python support..."
make PLATFORM=pc -j$(nproc) kernel > /dev/null
echo "✅ Kernel built"
echo ""

# 2. Run host-side examples
echo "2️⃣  Testing host-side SDK examples..."
for i in 1 2 3 4 5; do
    echo "  • Example $i..."
    ./examples/run_example.sh $i 2>&1 | grep -E "✅|❌" | head -3
done
echo "✅ Host-side examples tested"
echo ""

# 3. Run kernel-side application (requires ops)
if command -v ops &> /dev/null; then
    echo "3️⃣  Testing kernel-side Python application..."
    cd kernel-examples/hello-auth
    ops run main.py -c config.json 2>&1 | grep "✅"
    cd ../..
    echo "✅ Kernel-side application tested"
else
    echo "⚠️  ops tool not found - skipping kernel-side test"
    echo "   Install with: curl https://ops.city/get.sh -sSfL | sh"
fi

echo ""
echo "✅ End-to-End Test Complete!"
```

Run it:
```bash
chmod +x test_e2e.sh
./test_e2e.sh
```

---

## Verification

### Host-Side Verification

```bash
# Check SDK loads
python3 << 'EOF'
import sys
sys.path.insert(0, 'sdk/python')
from authority_nanos import AuthorityKernel
print("✅ SDK imports successfully")
EOF

# Check libak binary
file output/platform/pc/lib/libak.dylib
# Output: Mach-O 64-bit dynamically linked shared library
```

### Kernel-Side Verification

```bash
# Verify kernel image has Python
file output/platform/pc/bin/kernel.img
# Output: ELF 64-bit LSB executable

# Run with QEMU directly
qemu-system-x86_64 \
  -m 2G \
  -kernel output/platform/pc/bin/kernel.img \
  -append "main=hello.py" \
  -display none \
  -serial stdio
```

---

## Troubleshooting

### Host-Side Issues

**Problem**: `Could not load libak.so`
- **Solution**: Ensure libak was built: `make -j$(nproc)`
- **Solution**: Set `LIBAK_PATH`: `export LIBAK_PATH=/path/to/libak.dylib`

**Problem**: `SIGSYS` (Bad system call)
- **Cause**: Authority Kernel module not loaded (expected for host)
- **Info**: This is normal! The examples work when kernel IS running

### Kernel-Side Issues

**Problem**: `ops: command not found`
- **Solution**: Install ops tool: `curl https://ops.city/get.sh -sSfL | sh`

**Problem**: Kernel doesn't boot
- **Solution**: Check kernel log: `qemu-system-x86_64 ... -serial stdio`
- **Solution**: Verify Python support in kernel image

---

## Architecture Summary

| Aspect | Host-Side | Kernel-Side |
|--------|-----------|-------------|
| **Location** | macOS/Linux | Nanos Unikernel |
| **SDK** | Python + ctypes bindings | Python 3.x builtin |
| **Syscalls** | 1024-1100 via IPC | Direct kernel integration |
| **Isolation** | Process isolation | Kernel isolation |
| **Use Case** | Control host apps | Deploy isolated apps |
| **Launch** | `python examples/01.py` | `ops run app.py` |
| **Deployment** | Host package manager | Docker/container registry |

---

## Next Steps

1. **Test Host Examples**: `./examples/run_example.sh 1`
2. **Install ops**: `curl https://ops.city/get.sh -sSfL | sh`
3. **Run Kernel Example**: `cd kernel-examples/hello-auth && ops run main.py -c config.json`
4. **Combine Both**: Use host SDK to manage kernel-side apps
5. **Deploy**: Package kernel images with Authority Kernel for production

---

## References

- [Authority Nanos Documentation](https://authority-systems.github.io/nanos/)
- [ops Tool Documentation](https://ops.city/)
- [Nanos Unikernel Project](https://github.com/nanovms/nanos)
- [Python SDK Guide](../docs/guide/python-sdk.md)
