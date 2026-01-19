#!/bin/bash
# Build Authority Nanos inside Docker container

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="authority-nanos-builder"
CONTAINER_NAME="authority-nanos-build-$$"

echo "=========================================="
echo "Building Authority Nanos in Docker"
echo "=========================================="
echo

# Build Docker image
echo "Step 1: Building Docker image..."
docker build -t "$IMAGE_NAME" "$SCRIPT_DIR"
echo "✓ Docker image built: $IMAGE_NAME"
echo

# Run build in container
echo "Step 2: Running build in container..."
docker run \
    --rm \
    --name "$CONTAINER_NAME" \
    -v "$SCRIPT_DIR:/work" \
    -e PLATFORM=pc \
    "$IMAGE_NAME" \
    bash -c "cd /work && make clean && make PLATFORM=pc -j4"

echo
echo "=========================================="
echo "Build completed successfully!"
echo "=========================================="
echo

# Show build artifacts
echo "Build artifacts:"
ls -lh "$SCRIPT_DIR/output/platform/pc/bin/kernel.img" 2>/dev/null || echo "  kernel.img: not found"
ls -lh "$SCRIPT_DIR/output/platform/pc/lib/libak.so" 2>/dev/null || echo "  libak.so: not found"
echo

# Show architectures
echo "Architecture verification:"
file "$SCRIPT_DIR/output/platform/pc/bin/kernel.img" 2>/dev/null || echo "  kernel.img: not found"
file "$SCRIPT_DIR/output/platform/pc/lib/libak.so" 2>/dev/null || echo "  libak.so: not found"
