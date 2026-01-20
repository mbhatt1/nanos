#!/bin/bash
# Setup script to create a minimal rootfs with Python, sh, and pip for Nanos unikernel

set -e

ROOTFS_PATH="${1:-./_rootfs}"
PYTHON_BIN="${2:-/usr/bin/python3}"

echo "🔧 Building Nanos rootfs..."
echo "   Rootfs: $ROOTFS_PATH"
echo "   Python: $PYTHON_BIN"

# Create directory structure
mkdir -p "$ROOTFS_PATH/bin"
mkdir -p "$ROOTFS_PATH/lib"
mkdir -p "$ROOTFS_PATH/lib64"
mkdir -p "$ROOTFS_PATH/usr/bin"
mkdir -p "$ROOTFS_PATH/usr/lib"
mkdir -p "$ROOTFS_PATH/usr/local/bin"
mkdir -p "$ROOTFS_PATH/tmp"
mkdir -p "$ROOTFS_PATH/home"
mkdir -p "$ROOTFS_PATH/root"

echo "✅ Created directory structure"

# Copy shell
if [ -f /bin/sh ]; then
    cp /bin/sh "$ROOTFS_PATH/bin/"
    echo "✅ Copied /bin/sh"
else
    echo "⚠️  /bin/sh not found"
fi

# Copy bash if available
if [ -f /bin/bash ]; then
    cp /bin/bash "$ROOTFS_PATH/bin/"
    echo "✅ Copied /bin/bash"
fi

# Copy Python
if [ -f "$PYTHON_BIN" ]; then
    cp "$PYTHON_BIN" "$ROOTFS_PATH/usr/bin/python3"
    echo "✅ Copied Python3"

    # Copy Python library directory
    PYTHON_VERSION=$(basename $(dirname $(dirname "$PYTHON_BIN")))
    PYTHON_LIB="/Library/Frameworks/Python.framework/Versions/3.9/lib"

    if [ -d "$PYTHON_LIB" ]; then
        cp -r "$PYTHON_LIB"/* "$ROOTFS_PATH/usr/lib/" 2>/dev/null || true
        echo "✅ Copied Python libraries"
    fi

    # Create symlink
    ln -sf /usr/bin/python3 "$ROOTFS_PATH/usr/bin/python" || true
else
    echo "⚠️  Python not found at $PYTHON_BIN"
fi

# Copy necessary system libraries
echo "📚 Copying system libraries..."

copy_lib() {
    local lib=$1
    if [ -f "$lib" ]; then
        cp "$lib" "$ROOTFS_PATH/lib/" 2>/dev/null || true
        cp "$lib" "$ROOTFS_PATH/lib64/" 2>/dev/null || true
    fi
}

# Common dylibs on macOS
copy_lib "/usr/lib/libSystem.B.dylib"
copy_lib "/usr/lib/libc++.1.dylib"
copy_lib "/usr/lib/libobjc.A.dylib"

# Try to copy Python runtime files
if [ -d "/Library/Frameworks/Python.framework/Versions/3.9/lib" ]; then
    find "/Library/Frameworks/Python.framework/Versions/3.9/lib" -maxdepth 1 -name "*.dylib" -o -name "*.so" | while read lib; do
        cp "$lib" "$ROOTFS_PATH/usr/lib/" 2>/dev/null || true
    done
    echo "✅ Copied Python runtime libraries"
fi

# Create pip script if possible
if command -v pip3 &> /dev/null; then
    PIP_LOCATION=$(which pip3)
    cp "$PIP_LOCATION" "$ROOTFS_PATH/usr/bin/pip" 2>/dev/null || true
    cp "$PIP_LOCATION" "$ROOTFS_PATH/usr/bin/pip3" 2>/dev/null || true
    echo "✅ Copied pip"
fi

# Create /etc directory with minimal config
mkdir -p "$ROOTFS_PATH/etc"
cat > "$ROOTFS_PATH/etc/passwd" << 'EOF'
root:x:0:0:root:/root:/bin/sh
EOF

cat > "$ROOTFS_PATH/etc/group" << 'EOF'
root:x:0:
wheel:x:1:
EOF

echo "✅ Created /etc/passwd and /etc/group"

# Create a simple test script
cat > "$ROOTFS_PATH/root/test.sh" << 'EOF'
#!/bin/sh
echo "Hello from Nanos unikernel!"
echo "Python version:"
/usr/bin/python3 --version 2>/dev/null || echo "Python not available"
echo "Shell test: $0"
EOF

chmod +x "$ROOTFS_PATH/root/test.sh"
echo "✅ Created test script"

# Show what was created
echo ""
echo "📦 Rootfs contents:"
du -sh "$ROOTFS_PATH"
echo ""
echo "✅ Rootfs setup complete!"
echo ""
echo "To use with minops:"
echo "  ln -sf $ROOTFS_PATH /tmp/nanos-root"
echo "  cd kernel-examples/hello-auth"
echo "  /path/to/minops run main.py -c config.json -m 512"
