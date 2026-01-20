#!/bin/bash
# Build a Linux rootfs with Python using Docker

set -e

ROOTFS_OUTPUT="${1:-./_rootfs-linux}"

echo "🐳 Building Linux rootfs with Docker..."
echo "   Output: $ROOTFS_OUTPUT"
echo ""

# Create output directory
mkdir -p "$ROOTFS_OUTPUT"

# Build Docker image
echo "📦 Building Docker image..."
docker build -f Dockerfile.rootfs -t nanos-rootfs-builder . || {
    echo "❌ Docker build failed"
    exit 1
}

# Extract rootfs from container
echo "📂 Extracting rootfs from container..."
docker run --rm -v "$ROOTFS_OUTPUT:/output" nanos-rootfs-builder

echo ""
echo "✅ Rootfs built successfully!"
echo "   Size: $(du -sh "$ROOTFS_OUTPUT" | cut -f1)"
echo "   Location: $ROOTFS_OUTPUT"
echo ""
echo "📋 Contents:"
ls -lah "$ROOTFS_OUTPUT/bin/" | grep -E "^-|^l" | head -10
echo ""
ls -lah "$ROOTFS_OUTPUT/usr/bin/" | grep -E "python|pip" | head -10
echo ""
echo "🔗 To use with minops:"
echo "   ln -sf $(cd "$ROOTFS_OUTPUT" && pwd) /tmp/nanos-root"
echo "   cd kernel-examples/hello-auth"
echo "   /path/to/minops run main.py -c config.json -m 512"
