#!/bin/bash
# Verify cross-compilation support for all targets
#
# This script tests that all supported platforms can be built
# from the current host, checking for required toolchains and
# verifying the output binaries have the correct architecture.

set -e

echo "🔍 Verifying cross-compilation support..."
echo ""

PLATFORMS=("pc:x86_64" "virt:aarch64" "riscv-virt:riscv64")
HOST_ARCH=$(uname -m)
HOST_OS=$(uname -s)
ROOTDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Normalize arm64 to aarch64 for macOS
if [ "$HOST_ARCH" = "arm64" ]; then
    HOST_ARCH="aarch64"
fi

echo "Host: $HOST_OS $HOST_ARCH"
echo "Root: $ROOTDIR"
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Track results
TOTAL=0
PASSED=0
FAILED=0

for platform_arch in "${PLATFORMS[@]}"; do
    IFS=':' read -r platform arch <<< "$platform_arch"

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Testing: PLATFORM=$platform ARCH=$arch"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    ((TOTAL++))

    # Determine expected cross-compiler
    if [ "$arch" != "$HOST_ARCH" ]; then
        if [ "$HOST_OS" = "Darwin" ]; then
            case "$arch" in
                x86_64)
                    CROSS_COMPILER="x86_64-elf-gcc"
                    ;;
                aarch64)
                    CROSS_COMPILER="aarch64-elf-gcc"
                    ;;
                riscv64)
                    CROSS_COMPILER="riscv64-unknown-elf-gcc"
                    ;;
                *)
                    CROSS_COMPILER="${arch}-elf-gcc"
                    ;;
            esac
        else
            CROSS_COMPILER="${arch}-linux-gnu-gcc"
        fi

        if ! command -v "$CROSS_COMPILER" &> /dev/null; then
            echo -e "${YELLOW}⚠️  Cross-compiler not found: $CROSS_COMPILER${NC}"
            if [ "$HOST_OS" = "Darwin" ]; then
                echo "   Install: brew install ${arch}-elf-gcc"
            else
                echo "   Install: apt install gcc-${arch}-linux-gnu"
            fi
            ((FAILED++))
            echo ""
            continue
        fi
        echo "✅ Found cross-compiler: $CROSS_COMPILER"
    else
        echo "✅ Native build (no cross-compiler needed)"
    fi

    # Attempt build
    echo "Building kernel..."
    cd "$ROOTDIR"
    if make clean > /dev/null 2>&1; then
        if make PLATFORM="$platform" ARCH="$arch" kernel -j4 > /dev/null 2>&1; then
            OUTPUT="output/platform/$platform/bin/kernel.img"
            if [ -f "$OUTPUT" ]; then
                ls -lh "$OUTPUT"

                # Check architecture
                ARCH_OUTPUT=$(file "$OUTPUT" 2>/dev/null || echo "unknown")

                case "$arch" in
                    x86_64)
                        if echo "$ARCH_OUTPUT" | grep -qi "x86-64\|x86_64"; then
                            echo -e "${GREEN}✅ Correct architecture (x86-64)${NC}"
                            ((PASSED++))
                        else
                            echo -e "${RED}❌ Wrong architecture detected${NC}"
                            echo "   Got: $ARCH_OUTPUT"
                            ((FAILED++))
                        fi
                        ;;
                    aarch64)
                        if echo "$ARCH_OUTPUT" | grep -qi "aarch64\|ARM"; then
                            echo -e "${GREEN}✅ Correct architecture (ARM aarch64)${NC}"
                            ((PASSED++))
                        else
                            echo -e "${RED}❌ Wrong architecture detected${NC}"
                            echo "   Got: $ARCH_OUTPUT"
                            ((FAILED++))
                        fi
                        ;;
                    riscv64)
                        if echo "$ARCH_OUTPUT" | grep -qi "risc-v\|riscv"; then
                            echo -e "${GREEN}✅ Correct architecture (RISC-V)${NC}"
                            ((PASSED++))
                        else
                            echo -e "${RED}❌ Wrong architecture detected${NC}"
                            echo "   Got: $ARCH_OUTPUT"
                            ((FAILED++))
                        fi
                        ;;
                esac
            else
                echo -e "${RED}❌ Build completed but kernel.img not found${NC}"
                echo "   Expected: $OUTPUT"
                ((FAILED++))
            fi
        else
            echo -e "${RED}❌ Build failed${NC}"
            ((FAILED++))
        fi
    else
        echo -e "${RED}❌ Clean failed${NC}"
        ((FAILED++))
    fi

    echo ""
done

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "VERIFICATION SUMMARY"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Total tests:  $TOTAL"
echo -e "${GREEN}Passed:       $PASSED${NC}"
if [ $FAILED -gt 0 ]; then
    echo -e "${RED}Failed:       $FAILED${NC}"
else
    echo "Failed:       $FAILED"
fi
echo ""

if [ $FAILED -eq 0 ] && [ $PASSED -eq $TOTAL ]; then
    echo -e "${GREEN}✅ All tests passed! Cross-compilation fully supported.${NC}"
    exit 0
else
    echo -e "${RED}❌ Some tests failed. Install missing toolchains and try again.${NC}"
    exit 1
fi
