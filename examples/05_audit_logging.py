#!/usr/bin/env python3
"""
Example 5: Audit Logging

Demonstrates reading audit logs from the Authority Kernel's tamper-proof
append-only log.

By default, runs in simulation mode (no kernel required).
Use --real or --kernel to run against the actual Authority Kernel.

In simulation mode, audit logs are stored in memory and fully functional.
Operations performed in this session will appear in the audit log.
"""

import argparse
import json
import sys

from authority_nanos import AuthorityKernel, AuthorityKernelError


def main():
    """Audit logging example."""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Audit logging example")
    parser.add_argument("--real", "--kernel", action="store_true",
                        help="Use real kernel instead of simulation")
    args = parser.parse_args()

    # Determine mode
    simulate = not args.real
    mode = "SIMULATION" if simulate else "REAL KERNEL"
    print(f"=== Audit Logging Example ({mode} mode) ===\n")

    try:
        with AuthorityKernel(simulate=simulate) as ak:
            print("[+] Connected to Authority Kernel")

            # First, do some operations to generate audit entries
            print("\n--- Generating Audit Events ---")
            counter_data = json.dumps({"value": 100}).encode()
            handle = ak.alloc("audit_test", counter_data)
            print(f"[+] Allocated object (will be logged)")

            _ = ak.read(handle)
            print(f"[+] Read object (will be logged)")

            ak.delete(handle)
            print(f"[+] Deleted object (will be logged)")

            # Log a custom audit event
            ak.audit_log("custom_event", {
                "action": "example_action",
                "user": "demo_user",
                "details": "This is a custom audit entry"
            })
            print("[+] Logged custom audit event")

            # Read audit logs
            print("\n--- Retrieving Audit Logs ---")
            try:
                logs = ak.audit_logs()
                print(f"[+] Retrieved {len(logs)} audit log entries")

                # Display latest entries
                if logs:
                    print("\n  Recent entries:")
                    for i, log_entry in enumerate(logs[-5:]):  # Show last 5 entries
                        try:
                            entry = json.loads(log_entry.decode('utf-8'))
                            print(f"\n  Entry {i+1}:")
                            print(f"    Event: {entry.get('event')}")
                            print(f"    Actor: {entry.get('actor')}")
                            # Show a few other fields if present
                            for key in ['handle_id', 'type', 'action']:
                                if key in entry:
                                    print(f"    {key}: {entry[key]}")
                        except:
                            print(f"  Entry {i+1}: {log_entry}")

            except Exception as e:
                print(f"[i] Audit logs (expected if not configured): {e}")

            # Query audit logs
            print("\n--- Querying Audit Logs ---")
            try:
                # Query for specific events
                query = json.dumps({
                    "event_type": "alloc",
                    "limit": 10
                }).encode()

                results = ak.audit_query(query)
                print(f"[+] Audit query returned {len(results)} results")

                if results:
                    print("  Query results (alloc events):")
                    for r in results[:3]:  # Show first 3
                        try:
                            entry = json.loads(r.decode('utf-8'))
                            print(f"    - {entry.get('event')}: handle_id={entry.get('handle_id')}")
                        except:
                            pass

            except Exception as e:
                print(f"[i] Audit query (expected if not configured): {e}")

            print("\n[+] Audit logging examples completed!")

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
