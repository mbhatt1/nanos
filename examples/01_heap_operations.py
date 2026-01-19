#!/usr/bin/env python3
"""
Example 1: Basic Heap Operations

Demonstrates typed heap allocation, reading, and modification using JSON Patch.
This example shows the core memory management capabilities of Authority Kernel.
"""

import sys
import json
from pathlib import Path

# Add SDK to path
sys.path.insert(0, str(Path(__file__).parent.parent / "sdk/python"))

from authority_nanos import AuthorityKernel, AuthorityKernelError


def main():
    """Basic heap operations example."""
    try:
        # Initialize Authority Kernel context
        # libak.so location is determined by LIBAK_PATH env var or SDK defaults
        with AuthorityKernel() as ak:
            print("✅ Connected to Authority Kernel")

            # Allocate a counter object in typed heap
            counter_data = json.dumps({"value": 0, "name": "counter"}).encode()
            handle = ak.alloc("counter", counter_data)
            print(f"✅ Allocated counter with handle: {handle}")

            # Read the object back
            data = ak.read(handle)
            counter = json.loads(data.decode('utf-8'))
            print(f"✅ Read counter: {counter}")

            # Modify using JSON Patch (RFC 6902)
            # Operation: replace /value with 42
            patch = json.dumps([
                {"op": "replace", "path": "/value", "value": 42}
            ]).encode()
            new_version = ak.write(handle, patch)
            print(f"✅ Updated counter to version: {new_version}")

            # Read updated value
            updated_data = ak.read(handle)
            updated_counter = json.loads(updated_data.decode('utf-8'))
            print(f"✅ Updated counter: {updated_counter}")

            # Clean up
            ak.delete(handle)
            print(f"✅ Deleted counter handle")

    except AuthorityKernelError as e:
        print(f"❌ Kernel error: {e}")
        return 1
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
