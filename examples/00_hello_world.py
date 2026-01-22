#!/usr/bin/env python3
"""
Example 0: Hello World - The simplest Authority Kernel example.

This example demonstrates the most basic operation: allocating an object,
reading it back, and printing success. Works in simulation mode by default.
"""

import argparse
import json
from authority_nanos import AuthorityKernel

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Hello World Authority Kernel example")
    parser.add_argument("--real", "--kernel", action="store_true",
                        help="Use real kernel instead of simulation")
    args = parser.parse_args()

    # Determine mode: simulation (default) or real kernel
    simulate = not args.real
    mode = "SIMULATION" if simulate else "REAL KERNEL"
    print(f"Running in {mode} mode")

    # Connect to Authority Kernel
    with AuthorityKernel(simulate=simulate) as ak:
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
