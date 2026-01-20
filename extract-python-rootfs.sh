#!/bin/bash
# Extract Python rootfs from Docker image and prepare for kernel testing

set -e

echo "🔧 Extracting Python rootfs from Docker image..."

# Clean up previous extraction if needed
rm -rf /tmp/nanos-root 2>/dev/null || true
mkdir -p /tmp/nanos-root

# Extract rootfs from Docker image
echo "📦 Running Docker container to extract rootfs..."
docker run --rm -v /tmp/nanos-root:/output nanos-rootfs-python:latest

echo ""
echo "✅ Rootfs extracted successfully!"
echo ""

# Verify structure
echo "📋 Rootfs contents:"
ls -lh /tmp/nanos-root/

echo ""
echo "🐍 Python binary:"
ls -lh /tmp/nanos-root/bin/python3 2>/dev/null || echo "   ❌ Python not found at /tmp/nanos-root/bin/python3"

echo ""
echo "📚 Python library directory:"
ls -lh /tmp/nanos-root/usr/lib/python3.10/ 2>/dev/null | head -10 || echo "   ❌ Python libraries not found"

echo ""
echo "🔗 Runtime loader:"
ls -lh /tmp/nanos-root/lib64/ld-linux-x86-64.so.2 2>/dev/null || echo "   ⚠️  Runtime loader not found"

echo ""
echo "📦 Shared libraries count:"
find /tmp/nanos-root/lib /tmp/nanos-root/usr/lib -name "*.so*" 2>/dev/null | wc -l

echo ""
echo "✅ Rootfs ready at /tmp/nanos-root"
echo ""
echo "Next steps:"
echo "  1. Build kernel: make -j\$(nproc)"
echo "  2. Test Python execution: tools/minops/minops run examples/test-python.py"
