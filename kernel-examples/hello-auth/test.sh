#!/bin/sh
echo "✅ SHELL SCRIPT RUNNING INSIDE AUTHORITY NANOS UNIKERNEL"
echo ""
echo "System Info:"
echo "  Hostname: $(hostname 2>/dev/null || echo 'unknown')"
echo "  Date: $(date 2>/dev/null || echo 'unknown')"
echo ""
echo "Filesystem:"
ls -la / | head -15
echo ""
echo "✅ TEST PASSED"
