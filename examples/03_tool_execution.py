#!/usr/bin/env python3
"""
Example 3: WASM Tool Execution

Demonstrates executing WASM-compiled tools in a sandboxed environment
with capability-based access control.
"""

import json
import sys

from authority_nanos import AuthorityKernel, AuthorityKernelError


def main():
    """Tool execution example."""
    print("=== Tool Execution Example ===\n")

    try:
        with AuthorityKernel() as ak:
            print("[+] Connected to Authority Kernel")

            # Execute an "add" tool
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

            # Execute a custom tool
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
