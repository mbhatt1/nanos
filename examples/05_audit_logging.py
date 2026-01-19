#!/usr/bin/env python3
"""
Example 5: Audit Logging

Demonstrates reading audit logs from the Authority Kernel's tamper-proof
append-only log.
"""

import sys
import json
from pathlib import Path

# Add SDK to path
sys.path.insert(0, str(Path(__file__).parent.parent / "sdk/python"))

from authority_nanos import AuthorityKernel, AuthorityKernelError


def main():
    """Audit logging example."""
    try:
        # libak.so location is determined by LIBAK_PATH env var or SDK defaults
        with AuthorityKernel() as ak:
            print("✅ Connected to Authority Kernel")

            # Read audit logs
            try:
                logs = ak.audit_logs()
                print(f"✅ Retrieved {len(logs)} audit log entries")

                # Display latest entries
                for i, log_entry in enumerate(logs[-5:]):  # Show last 5 entries
                    entry = json.loads(log_entry.decode('utf-8'))
                    print(f"\n  Entry {i+1}:")
                    print(f"    Timestamp: {entry.get('timestamp')}")
                    print(f"    Event: {entry.get('event')}")
                    print(f"    Actor: {entry.get('actor')}")

            except Exception as e:
                print(f"ℹ️  Audit logs (expected if not configured): {e}")

            # Query audit logs
            try:
                # Query for specific events
                query = json.dumps({
                    "event_type": "alloc",
                    "actor": "*",
                    "limit": 10
                }).encode()

                results = ak.audit_query(query)
                print(f"\n✅ Audit query returned {len(results)} results")
            except Exception as e:
                print(f"ℹ️  Audit query (expected if not configured): {e}")

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
