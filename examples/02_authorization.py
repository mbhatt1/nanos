#!/usr/bin/env python3
"""
Example 2: Authorization and Policy Checks

Demonstrates capability-based authorization for protected operations like
file I/O and HTTP requests.
"""

import sys

from authority_nanos import AuthorityKernel, OperationDeniedError, AuthorityKernelError


def main():
    """Authorization example."""
    print("=== Authorization Example ===\n")

    try:
        with AuthorityKernel() as ak:
            print("[+] Connected to Authority Kernel")

            # Check if we have authorization to read a protected file
            print("\n--- File Authorization ---")
            try:
                if ak.authorize("read", "/etc/config.json"):
                    print("[+] Authorization granted for /etc/config.json")
                else:
                    print("[i] Authorization denied (policy decision)")
            except OperationDeniedError as e:
                print(f"[i] Operation denied: {e}")

            # Check authorization for HTTP request
            print("\n--- HTTP Authorization ---")
            try:
                if ak.authorize("http.post", "https://api.example.com"):
                    print("[+] Authorization granted for HTTPS API")
                else:
                    print("[i] Authorization denied for HTTPS API")
            except OperationDeniedError as e:
                print(f"[i] Operation denied: {e}")

            print("\n[+] Authorization checks completed!")

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
