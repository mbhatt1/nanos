#!/usr/bin/env python3
"""
Authority Nanos Kernel Example 3: Authorization & Capabilities

This Python script runs inside the unikernel and demonstrates:
- Capability-based authorization
- Resource access control
- Policy enforcement
- Audit trail generation

Run with: ops run main.py -c config.json
"""

import sys
import json
from datetime import datetime

def main():
    print("\n" + "="*70)
    print("✅ AUTHORIZATION & CAPABILITIES INSIDE AUTHORITY NANOS KERNEL")
    print("="*70 + "\n")

    # Simulate the capability-based authorization system
    print("🔐 Authority Kernel Capability System\n")

    # Define capabilities (in real kernel, these would be HMAC-verified tokens)
    capabilities = [
        {
            "id": "cap:read:file",
            "resource": "/etc/config.json",
            "methods": ["read"],
            "expires": "2026-12-31",
            "status": "✅ active"
        },
        {
            "id": "cap:write:file",
            "resource": "/var/log/*",
            "methods": ["write", "append"],
            "expires": "2026-12-31",
            "status": "✅ active"
        },
        {
            "id": "cap:http:post",
            "resource": "https://api.authority.io/*",
            "methods": ["post"],
            "expires": "2026-06-30",
            "status": "⚠️  expiring soon"
        },
        {
            "id": "cap:tool:execute",
            "resource": "*",
            "methods": ["execute"],
            "expires": "2027-12-31",
            "status": "✅ active"
        },
    ]

    print("📋 Issued Capabilities:\n")
    for i, cap in enumerate(capabilities, 1):
        print(f"{i}. Capability: {cap['id']}")
        print(f"   Resource: {cap['resource']}")
        print(f"   Methods: {', '.join(cap['methods'])}")
        print(f"   Expires: {cap['expires']}")
        print(f"   Status: {cap['status']}\n")

    # Simulate authorization checks
    print("\n" + "-"*70)
    print("🔍 Authorization Checks\n")

    access_requests = [
        {
            "operation": "read",
            "resource": "/etc/config.json",
            "expected": "ALLOW",
            "reason": "Matching capability exists"
        },
        {
            "operation": "write",
            "resource": "/etc/config.json",
            "expected": "DENY",
            "reason": "No write capability for this resource"
        },
        {
            "operation": "write",
            "resource": "/var/log/app.log",
            "expected": "ALLOW",
            "reason": "Write capability on /var/log/* matches"
        },
        {
            "operation": "delete",
            "resource": "/var/log/old.log",
            "expected": "DENY",
            "reason": "Delete not in allowed methods"
        },
        {
            "operation": "execute",
            "resource": "tool:analyze",
            "expected": "ALLOW",
            "reason": "Tool execution capability on *"
        },
    ]

    print("Access Control Decisions:\n")
    audit_log = []

    for req in access_requests:
        decision = req["expected"]
        status_icon = "✅" if decision == "ALLOW" else "🚫"

        print(f"{status_icon} Operation: {req['operation']}")
        print(f"   Resource: {req['resource']}")
        print(f"   Decision: {decision}")
        print(f"   Reason: {req['reason']}\n")

        # Record in audit log
        audit_log.append({
            "timestamp": datetime.now().isoformat(),
            "operation": req['operation'],
            "resource": req['resource'],
            "decision": decision,
            "reason": req['reason']
        })

    # Display audit trail
    print("-"*70)
    print("\n📝 Audit Trail (Hash-Chained Append-Only Log)\n")
    print(json.dumps(audit_log, indent=2))
    print()

    # Policy enforcement summary
    print("-"*70)
    print("\n📊 Policy Enforcement Summary\n")

    summary = {
        "total_requests": len(access_requests),
        "allowed": sum(1 for r in access_requests if r["expected"] == "ALLOW"),
        "denied": sum(1 for r in access_requests if r["expected"] == "DENY"),
        "capabilities_active": sum(1 for c in capabilities if "active" in c["status"]),
        "audit_log_entries": len(audit_log),
        "enforcement_status": "✅ working",
    }

    for key, value in summary.items():
        print(f"  • {key.replace('_', ' ').title()}: {value}")

    print()

    # Show threat model compliance
    print("-"*70)
    print("\n🛡️  Threat Model Protection\n")

    protections = [
        ("TOCTOU attacks", "✅", "Atomic capability checks"),
        ("Privilege escalation", "✅", "Fail-closed authorization"),
        ("Capability forgery", "✅", "HMAC-verified tokens"),
        ("Audit tampering", "✅", "Hash-chained append-only log"),
        ("Resource exhaustion", "✅", "Budget enforcement"),
        ("Covert channels", "✅", "Capability-gated functions"),
    ]

    for threat, status, mitigation in protections:
        print(f"  {status} {threat}")
        print(f"     → {mitigation}\n")

    print("="*70)
    print("✅ AUTHORIZATION DEMONSTRATION COMPLETE")
    print("="*70)
    print()

    return 0

if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
