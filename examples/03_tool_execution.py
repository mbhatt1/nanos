#!/usr/bin/env python3
"""
Example 3: WASM Tool Execution

Demonstrates executing WASM-compiled tools in a sandboxed environment
with capability-based access control.

By default, runs in simulation mode (no kernel required).
Use --real or --kernel to run against the actual Authority Kernel.

In simulation mode, basic tools like "add" and "concat" are simulated.
Other tools return a success message indicating simulation.
"""

import argparse
import json
import sys

from authority_nanos import AuthorityKernel, AuthorityKernelError


def main():
    """Tool execution example."""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Tool execution example")
    parser.add_argument("--real", "--kernel", action="store_true",
                        help="Use real kernel instead of simulation")
    args = parser.parse_args()

    # Determine mode
    simulate = not args.real
    mode = "SIMULATION" if simulate else "REAL KERNEL"
    print(f"=== Tool Execution Example ({mode} mode) ===\n")

    try:
        with AuthorityKernel(simulate=simulate) as ak:
            print("[+] Connected to Authority Kernel")

            # Execute an "add" tool (simulated in simulation mode)
            print("\n--- Math Tool: add ---")
            tool_name = "add"
            tool_args = json.dumps({"a": 5, "b": 3}).encode()

            try:
                result = ak.tool_call(tool_name, tool_args)
                result_data = json.loads(result.decode('utf-8'))
                print(f"[+] Tool '{tool_name}' executed")
                print(f"[+] Result: {result_data}")
            except Exception as e:
                print(f"[i] Tool execution: {e}")

            # Execute a string tool
            print("\n--- String Tool: concat ---")
            tool_name = "concat"
            tool_args = json.dumps({
                "str1": "Hello, ",
                "str2": "World!"
            }).encode()

            try:
                result = ak.tool_call(tool_name, tool_args)
                result_data = json.loads(result.decode('utf-8'))
                print(f"[+] Tool '{tool_name}' executed")
                print(f"[+] Result: {result_data}")
            except Exception as e:
                print(f"[i] Tool execution: {e}")

            # Execute a custom tool (will be simulated)
            print("\n--- Custom Tool ---")
            tool_name = "my_custom_tool"
            tool_args = json.dumps({
                "param1": "value1",
                "param2": 42
            }).encode()

            try:
                result = ak.tool_call(tool_name, tool_args)
                result_data = json.loads(result.decode('utf-8'))
                print(f"[+] Tool '{tool_name}' executed")
                print(f"[+] Result: {result_data}")
                if result_data.get("simulated"):
                    print("[i] (This tool was simulated)")
            except Exception as e:
                print(f"[i] Tool execution (expected if tool not deployed): {e}")

            print("\n[+] Tool execution examples completed!")

    except AuthorityKernelError as e:
        print(f"[-] Kernel error: {e}")
        return 1
    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
