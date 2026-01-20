#!/bin/bash
# Verify cross-compilation toolchains for all target architectures
# Usage: ./tools/verify-cross-compile.sh [ARCH]

set -e

UNAME_s=$(uname -s)
HOST_ARCH=$(uname -m)
if [ "$HOST_ARCH" = "arm64" ]; then
  HOST_ARCH="aarch64"
fi

# Get target architecture from argument or detect from PLATFORM
if [ -z "$1" ]; then
  TARGET_ARCH="${ARCH:-$HOST_ARCH}"
else
  TARGET_ARCH="$1"
fi

# Determine toolchain prefix based on OS and target architecture
if [ "$UNAME_s" = "Darwin" ]; then
  case "$TARGET_ARCH" in
    x86_64)  CROSS_COMPILE="x86_64-elf-" ;;
    aarch64) CROSS_COMPILE="aarch64-elf-" ;;
    riscv64) CROSS_COMPILE="riscv64-elf-" ;;
    *)       echo "Unknown architecture: $TARGET_ARCH"; exit 1 ;;
  esac
else  # Linux
  case "$TARGET_ARCH" in
    x86_64)  CROSS_COMPILE="x86_64-linux-gnu-" ;;
    aarch64) CROSS_COMPILE="aarch64-linux-gnu-" ;;
    riscv64) CROSS_COMPILE="riscv64-linux-gnu-" ;;
    *)       echo "Unknown architecture: $TARGET_ARCH"; exit 1 ;;
  esac
fi

# Check if toolchain is available
GCC="${CROSS_COMPILE}gcc"
if ! command -v "$GCC" &> /dev/null; then
  echo "❌ ERROR: Cross-compiler not found: $GCC"
  echo ""
  echo "Target: $TARGET_ARCH"
  echo "Host: $UNAME_s $HOST_ARCH"
  echo ""
  echo "To install on macOS:"
  case "$TARGET_ARCH" in
    x86_64)  echo "  brew install x86_64-elf-gcc" ;;
    aarch64) echo "  brew install aarch64-elf-gcc" ;;
    riscv64) echo "  brew install riscv64-elf-gcc" ;;
  esac
  echo ""
  echo "To install on Ubuntu/Debian:"
  case "$TARGET_ARCH" in
    x86_64)  echo "  sudo apt-get install gcc-x86-64-linux-gnu binutils-x86-64-linux-gnu" ;;
    aarch64) echo "  sudo apt-get install gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu" ;;
    riscv64) echo "  sudo apt-get install gcc-riscv64-linux-gnu binutils-riscv64-linux-gnu" ;;
  esac
  echo ""
  echo "To install on Fedora/RHEL:"
  case "$TARGET_ARCH" in
    x86_64)  echo "  sudo dnf install gcc-x86_64-linux-gnu" ;;
    aarch64) echo "  sudo dnf install gcc-aarch64-linux-gnu" ;;
    riscv64) echo "  sudo dnf install gcc-riscv64-linux-gnu" ;;
  esac
  exit 1
fi

echo "✅ Found cross-compiler: $GCC"
"$GCC" --version | head -1
exit 0
