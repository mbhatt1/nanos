#!/usr/bin/env python3
"""
Example 0: Hello World - The simplest Authority Kernel example.

This example demonstrates the most basic operation: allocating an object,
reading it back, and printing success.
"""

import json
from authority_nanos import AuthorityKernel

def main():
    print("Connecting to Authority Kernel...")

    # Connect to Authority Kernel
    with AuthorityKernel() as ak:
        # Allocate an object in the typed heap
        data = json.dumps({"message": "Hello, World!"}).encode()
        handle = ak.alloc("greeting", data)

        # Read it back
        result = ak.read(handle)
        obj = json.loads(result.decode())

        # Print success
        print(f"Success! Read: {obj['message']}")
        return 0

if __name__ == "__main__":
    exit(main())
