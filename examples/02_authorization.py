#!/usr/bin/env python3
"""
Example 2: Authorization and Policy Checks

Demonstrates capability-based authorization for protected operations like
file I/O and HTTP requests.

By default, runs in simulation mode (no kernel required).
Use --real or --kernel to run against the actual Authority Kernel.

In simulation mode, all operations are authorized by default. You can test
denial scenarios by using ak.deny_operation() or ak.deny_target().
"""

import argparse
import sys

from authority_nanos import AuthorityKernel, OperationDeniedError, AuthorityKernelError


def main():
    """Authorization example."""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Authorization example")
    parser.add_argument("--real", "--kernel", action="store_true",
                        help="Use real kernel instead of simulation")
    args = parser.parse_args()

    # Determine mode
    simulate = not args.real
    mode = "SIMULATION" if simulate else "REAL KERNEL"
    print(f"=== Authorization Example ({mode} mode) ===\n")

    try:
        with AuthorityKernel(simulate=simulate) as ak:
            print("[+] Connected to Authority Kernel")

            # Check if we have authorization to read a protected file
            print("\n--- File Authorization ---")
            try:
                if ak.authorize("read", "/etc/config.json"):
                    print("[+] Authorization granted for /etc/config.json")
                    # In simulation, this would try to actually read if file exists
                    # but won't fail if it doesn't - just for demo
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

            # Demonstrate denial in simulation mode
            if simulate:
                print("\n--- Simulating Policy Denial ---")
                # Deny a specific target
                ak.deny_target("/etc/shadow")

                if ak.authorize("read", "/etc/shadow"):
                    print("[+] Authorized for /etc/shadow (unexpected)")
                else:
                    print("[i] Authorization denied for /etc/shadow (expected)")

                # Get denial info
                denial = ak.get_last_denial()
                if denial:
                    print(f"[i] Denial reason: {denial.reason}")

                # Reset to allow all
                ak.allow_all()
                print("[+] Reset to allow all operations")

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
