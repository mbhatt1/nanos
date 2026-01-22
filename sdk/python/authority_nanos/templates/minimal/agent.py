#!/usr/bin/env python3
"""
{{PROJECT_NAME}} - Minimal Authority Nanos Agent

A simple agent demonstrating basic heap operations with the Authority Kernel.

Created: {{DATE}}
"""

import json
from authority_nanos import AuthorityKernel, TypedHeap


def main():
    """Main entry point for the agent."""
    print("=" * 50)
    print(f"  {{PROJECT_NAME}} Agent")
    print("  Running with Authority Kernel")
    print("=" * 50)
    print()

    # Initialize the Authority Kernel
    # In simulation mode, this works without the actual kernel
    kernel = AuthorityKernel()
    heap = TypedHeap(kernel)

    # Allocate a simple state object
    print("[1] Allocating state object...")
    state = {"status": "initialized", "counter": 0}
    handle = heap.alloc("state", json.dumps(state).encode())
    print(f"    Allocated handle: {handle}")

    # Read the state
    print("\n[2] Reading state...")
    data = heap.read(handle)
    current_state = json.loads(data.decode())
    print(f"    Current state: {current_state}")

    # Update the state
    print("\n[3] Updating state...")
    patch = json.dumps([
        {"op": "replace", "path": "/status", "value": "running"},
        {"op": "replace", "path": "/counter", "value": 1}
    ]).encode()
    new_version = heap.write(handle, patch)
    print(f"    Updated to version: {new_version}")

    # Read updated state
    print("\n[4] Verifying update...")
    updated_data = heap.read(handle)
    updated_state = json.loads(updated_data.decode())
    print(f"    Updated state: {updated_state}")

    # Clean up
    print("\n[5] Cleaning up...")
    heap.delete(handle)
    print("    State object deleted")

    print("\n" + "=" * 50)
    print("  Agent completed successfully!")
    print("=" * 50)


if __name__ == "__main__":
    main()
