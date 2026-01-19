#!/bin/bash
# Helper script to run examples with proper library path and Python architecture

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Detect platform and find libak
PLATFORM=$(uname -s)
MACHINE=$(uname -m)
PYTHON_CMD="python3"
ARCH_CMD=""

if [ "$PLATFORM" = "Darwin" ]; then
    # macOS: libak.dylib is ARM64, so run Python in ARM64 mode
    LIBAK_PATH="$PROJECT_ROOT/output/platform/pc/lib/libak.dylib"
    if [ ! -f "$LIBAK_PATH" ]; then
        LIBAK_PATH="$PROJECT_ROOT/output/platform/virt/lib/libak.dylib"
    fi

    # Use system Python with ARM64 architecture
    PYTHON_CMD="/usr/bin/python3"
    ARCH_CMD="arch -arm64"

    if [ ! -f "$PYTHON_CMD" ]; then
        PYTHON_CMD="python3"
        ARCH_CMD=""
    fi
else
    # Linux: use libak.so with regular Python
    LIBAK_PATH="$PROJECT_ROOT/output/platform/pc/lib/libak.so"
    if [ ! -f "$LIBAK_PATH" ]; then
        LIBAK_PATH="$PROJECT_ROOT/output/platform/virt/lib/libak.so"
    fi
fi

if [ ! -f "$LIBAK_PATH" ]; then
    echo "❌ libak binary not found"
    echo "Tried:"
    echo "  $PROJECT_ROOT/output/platform/pc/lib/libak.{dylib,so}"
    echo "  $PROJECT_ROOT/output/platform/virt/lib/libak.{dylib,so}"
    echo ""
    echo "Build with: make -j\$(nproc)"
    exit 1
fi

# Set library paths
export LD_LIBRARY_PATH="$(dirname "$LIBAK_PATH"):$LD_LIBRARY_PATH"
export DYLD_LIBRARY_PATH="$(dirname "$LIBAK_PATH"):$DYLD_LIBRARY_PATH"
export LIBAK_PATH="$LIBAK_PATH"

echo "ℹ️  Using libak: $LIBAK_PATH"
echo "ℹ️  Using Python: $PYTHON_CMD"
[ -n "$ARCH_CMD" ] && echo "ℹ️  Running with: $ARCH_CMD"
echo ""

# Run the example
if [ -z "$1" ]; then
    echo "Usage: $0 <example_number>"
    echo ""
    echo "Available examples:"
    for i in 1 2 3 4 5; do
        EXAMPLE="$SCRIPT_DIR/0${i}_*.py"
        if [ -f $EXAMPLE ]; then
            NAME=$(basename $EXAMPLE | sed 's/0[0-9]_//;s/.py//')
            echo "  $i) $NAME"
        fi
    done
    exit 1
fi

# Find and run the example
EXAMPLE_NUM=$(printf "%02d" "$1")
EXAMPLE_FILE=$(ls "$SCRIPT_DIR"/${EXAMPLE_NUM}_*.py 2>/dev/null | head -1)

if [ ! -f "$EXAMPLE_FILE" ]; then
    echo "❌ Example $1 not found"
    exit 1
fi

echo "🚀 Running: $EXAMPLE_FILE"
echo ""

# Create wrapper script to pass libak_path explicitly
WRAPPER=$(mktemp)
trap "rm -f $WRAPPER" EXIT

cat > "$WRAPPER" << 'WRAPPER_EOF'
#!/usr/bin/env python3
import sys
import os
from pathlib import Path

# Add SDK to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "sdk/python"))

# Get libak_path from environment
libak_path = os.getenv("LIBAK_PATH")

# Import and run the example
example_file = sys.argv[1]
exec_globals = {
    '__name__': '__main__',
    '__file__': example_file,
    'libak_path': libak_path,
}

# Read and execute the example file
with open(example_file, 'r') as f:
    code = f.read()

# Replace AuthorityKernel() with AuthorityKernel(libak_path=libak_path) in the code
code = code.replace(
    'with AuthorityKernel() as ak:',
    'with AuthorityKernel(libak_path=libak_path) as ak:'
)

exec(code, exec_globals)
WRAPPER_EOF

chmod +x "$WRAPPER"

# Run example with explicit libak_path
$ARCH_CMD $PYTHON_CMD "$WRAPPER" "$EXAMPLE_FILE"
