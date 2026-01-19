#!/usr/bin/env python3
"""
Example 3: WASM Tool Execution

Demonstrates executing WASM-compiled tools in a sandboxed environment
with capability-based access control.
"""

import sys
import json
from pathlib import Path

# Add SDK to path
sys.path.insert(0, str(Path(__file__).parent.parent / "sdk/python"))

from authority_nanos import AuthorityKernel, ToolCall, AuthorityKernelError


def main():
    """Tool execution example."""
    try:
        # libak.so location is determined by LIBAK_PATH env var or SDK defaults
        with AuthorityKernel() as ak:
            print("✅ Connected to Authority Kernel")

            # Execute a WASM tool
            # This example assumes a tool named "add" exists
            tool_name = "add"
            tool_args = json.dumps({"a": 5, "b": 3}).encode()

            try:
                result = ak.tool_call(tool_name, tool_args)
                print(f"✅ Tool '{tool_name}' executed")
                print(f"✅ Result: {result.decode('utf-8')}")
            except Exception as e:
                print(f"ℹ️  Tool execution (expected if tool not deployed): {e}")

            # Execute another tool for string manipulation
            tool_name = "concat"
            tool_args = json.dumps({
                "str1": "Hello, ",
                "str2": "World!"
            }).encode()

            try:
                result = ak.tool_call(tool_name, tool_args)
                print(f"✅ Tool '{tool_name}' executed")
                print(f"✅ Result: {result.decode('utf-8')}")
            except Exception as e:
                print(f"ℹ️  Tool execution (expected if tool not deployed): {e}")

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
