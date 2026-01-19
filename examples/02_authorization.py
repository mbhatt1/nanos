#!/usr/bin/env python3
"""
Example 2: Authorization and Policy Checks

Demonstrates capability-based authorization for protected operations like
file I/O and HTTP requests.
"""

import sys
from pathlib import Path

# Add SDK to path
sys.path.insert(0, str(Path(__file__).parent.parent / "sdk/python"))

from authority_nanos import AuthorityKernel, OperationDeniedError, AuthorityKernelError


def main():
    """Authorization example."""
    try:
        # libak.so location is determined by LIBAK_PATH env var or SDK defaults
        with AuthorityKernel() as ak:
            print("✅ Connected to Authority Kernel")

            # Check if we have authorization to read a protected file
            try:
                if ak.authorize("read", "/etc/config.json"):
                    print("✅ Authorization granted for /etc/config.json")
                    config = ak.file_read("/etc/config.json")
                    print(f"✅ Read {len(config)} bytes from config file")
                else:
                    print("ℹ️  Authorization denied (policy decision)")
            except OperationDeniedError as e:
                print(f"ℹ️  Operation denied: {e}")

            # Check authorization for HTTP request
            try:
                if ak.authorize("http.post", "https://api.example.com"):
                    print("✅ Authorization granted for HTTPS API")
                else:
                    print("ℹ️  Authorization denied for HTTPS API")
            except OperationDeniedError as e:
                print(f"ℹ️  Operation denied: {e}")

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
