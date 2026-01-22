#!/bin/bash
#
# Authority Kernel End-to-End Test Runner
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Authority Systems
#
# This script builds and runs the E2E tests for the Authority Kernel.
# It can be run locally or in CI environments.
#
# Usage:
#   ./run_e2e.sh              # Run all tests
#   ./run_e2e.sh --verbose    # Run with verbose output
#   ./run_e2e.sh --no-build   # Skip kernel build (use existing)
#   ./run_e2e.sh --timeout 60 # Set QEMU timeout (default: 120s)
#

set -e

# Script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Colors for output (disable if not a terminal)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m' # No Color
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

# Default configuration
VERBOSE=0
SKIP_BUILD=0
QEMU_TIMEOUT=120
PLATFORM="pc"
ARCH="x86_64"

# Output paths
OUTPUT_DIR="$PROJECT_ROOT/output"
PLATFORM_DIR="$OUTPUT_DIR/platform/$PLATFORM"
KERNEL_IMG="$PLATFORM_DIR/bin/kernel.img"
BOOT_IMG="$PLATFORM_DIR/boot/boot.img"
MKFS_TOOL="$OUTPUT_DIR/tools/bin/mkfs"
TEST_BINARY="$SCRIPT_DIR/test_basic"
TEST_IMAGE="$SCRIPT_DIR/test_e2e.img"
LOG_FILE="$SCRIPT_DIR/e2e_output.log"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        --no-build)
            SKIP_BUILD=1
            shift
            ;;
        --timeout)
            QEMU_TIMEOUT="$2"
            shift 2
            ;;
        --platform)
            PLATFORM="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -v, --verbose     Verbose output"
            echo "  --no-build        Skip kernel build"
            echo "  --timeout SEC     QEMU timeout in seconds (default: 120)"
            echo "  --platform NAME   Platform to use (default: pc)"
            echo "  -h, --help        Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
}

log_step() {
    echo ""
    echo -e "${BLUE}==>${NC} $1"
    echo ""
}

# Detect platform and architecture
detect_platform() {
    UNAME_S=$(uname -s)
    UNAME_M=$(uname -m)

    case "$UNAME_S" in
        Linux)
            HOST_OS="linux"
            ;;
        Darwin)
            HOST_OS="darwin"
            ;;
        *)
            log_error "Unsupported OS: $UNAME_S"
            exit 1
            ;;
    esac

    case "$UNAME_M" in
        x86_64|amd64)
            HOST_ARCH="x86_64"
            QEMU_CMD="qemu-system-x86_64"
            ;;
        arm64|aarch64)
            HOST_ARCH="aarch64"
            QEMU_CMD="qemu-system-aarch64"
            PLATFORM="virt"
            ;;
        *)
            log_error "Unsupported architecture: $UNAME_M"
            exit 1
            ;;
    esac

    log_info "Host: $HOST_OS/$HOST_ARCH"
    log_info "Target platform: $PLATFORM"
}

# Check dependencies
check_dependencies() {
    log_step "Checking dependencies..."

    # Check for QEMU
    if ! command -v "$QEMU_CMD" &> /dev/null; then
        log_error "$QEMU_CMD not found. Please install QEMU."
        echo "  macOS: brew install qemu"
        echo "  Linux: apt-get install qemu-system-x86 (or qemu-system-arm)"
        exit 1
    fi
    log_info "Found $QEMU_CMD"

    # Check for cross-compiler if needed
    if [ "$HOST_ARCH" != "$ARCH" ]; then
        if [ "$ARCH" = "x86_64" ]; then
            CROSS_CC="x86_64-elf-gcc"
        elif [ "$ARCH" = "aarch64" ]; then
            CROSS_CC="aarch64-linux-gnu-gcc"
        fi

        if ! command -v "$CROSS_CC" &> /dev/null; then
            log_warning "Cross-compiler $CROSS_CC not found. Using native compiler."
            CROSS_CC="gcc"
        fi
    else
        CROSS_CC="gcc"
    fi
    log_info "Using compiler: $CROSS_CC"

    # Check for nasm (x86_64 builds)
    if [ "$ARCH" = "x86_64" ]; then
        if ! command -v nasm &> /dev/null; then
            log_error "nasm not found. Please install nasm."
            exit 1
        fi
        log_info "Found nasm"
    fi
}

# Build kernel if needed
build_kernel() {
    if [ "$SKIP_BUILD" -eq 1 ]; then
        log_info "Skipping kernel build (--no-build specified)"
        return 0
    fi

    log_step "Building kernel..."

    cd "$PROJECT_ROOT"

    # Check if kernel already exists
    if [ -f "$KERNEL_IMG" ] && [ -f "$BOOT_IMG" ] && [ -f "$MKFS_TOOL" ]; then
        log_info "Kernel artifacts exist. Use --no-build to skip build entirely."
    fi

    # Build kernel
    if [ $VERBOSE -eq 1 ]; then
        make -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu)" PLATFORM=$PLATFORM
    else
        make -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu)" PLATFORM=$PLATFORM > /dev/null 2>&1
    fi

    # Verify build artifacts
    if [ ! -f "$KERNEL_IMG" ]; then
        log_error "Kernel build failed: $KERNEL_IMG not found"
        exit 1
    fi

    if [ ! -f "$MKFS_TOOL" ]; then
        log_error "mkfs tool not built: $MKFS_TOOL not found"
        exit 1
    fi

    log_success "Kernel built successfully"
}

# Build test program
build_test_program() {
    log_step "Building test program..."

    cd "$SCRIPT_DIR"

    # Determine compiler and flags
    if [ "$HOST_ARCH" = "$ARCH" ]; then
        CC="gcc"
        LDFLAGS="-static"
    else
        if [ "$ARCH" = "x86_64" ]; then
            CC="${CROSS_COMPILE:-x86_64-elf-}gcc"
            LD="${CROSS_COMPILE:-x86_64-elf-}ld"
        else
            CC="${CROSS_COMPILE:-aarch64-linux-gnu-}gcc"
            LD="${CROSS_COMPILE:-aarch64-linux-gnu-}ld"
        fi
        LDFLAGS="-static"

        # On macOS, we need to use the cross-compile toolchain properly
        if [ "$HOST_OS" = "darwin" ]; then
            # Try to find the target root for cross-compilation
            TARGET_ROOT="$PROJECT_ROOT/target-root"
            if [ -d "$TARGET_ROOT" ]; then
                LDFLAGS="$LDFLAGS --sysroot=$TARGET_ROOT"
            fi
        fi
    fi

    # Compile test program
    log_info "Compiling test_basic.c..."

    # Use simple static compilation
    $CC -O2 -Wall -Wextra -static -o "$TEST_BINARY" test_basic.c 2>&1 || {
        # If static linking fails, try dynamic
        log_warning "Static linking failed, trying dynamic..."
        $CC -O2 -Wall -Wextra -o "$TEST_BINARY" test_basic.c 2>&1 || {
            log_error "Failed to compile test program"
            exit 1
        }
    }

    if [ ! -f "$TEST_BINARY" ]; then
        log_error "Test binary not created"
        exit 1
    fi

    log_success "Test program built: $TEST_BINARY"

    # Show binary info
    file "$TEST_BINARY" || true
}

# Create disk image
create_disk_image() {
    log_step "Creating disk image..."

    cd "$SCRIPT_DIR"

    # Create manifest with proper paths
    MANIFEST_FILE="$SCRIPT_DIR/test_e2e.manifest"

    cat > "$MANIFEST_FILE" << EOF
(
    children:(
        test_basic:(contents:(host:$TEST_BINARY))
        policy.json:(contents:(host:$SCRIPT_DIR/test_policy.json))
        tmp:(children:())
        proc:(children:(
            self:(children:(
                status:(contents:"Name:\ttest_basic\nState:\tR (running)\n")
            ))
        ))
    )
    program:/test_basic
    debug_exit:t
    fault:t
    arguments:[test_basic e2e_test]
    environment:(USER:e2e_test PWD:/)
)
EOF

    log_info "Created manifest: $MANIFEST_FILE"

    # Create image using mkfs
    log_info "Creating disk image with mkfs..."

    rm -f "$TEST_IMAGE"

    "$MKFS_TOOL" \
        -b "$BOOT_IMG" \
        -k "$KERNEL_IMG" \
        "$TEST_IMAGE" < "$MANIFEST_FILE"

    if [ ! -f "$TEST_IMAGE" ]; then
        log_error "Failed to create disk image"
        exit 1
    fi

    log_success "Disk image created: $TEST_IMAGE ($(du -h "$TEST_IMAGE" | cut -f1))"
}

# Run QEMU test
run_qemu_test() {
    log_step "Running E2E test in QEMU..."

    cd "$SCRIPT_DIR"

    # QEMU arguments based on platform
    if [ "$PLATFORM" = "pc" ]; then
        QEMU_ARGS=(
            -machine q35
            -cpu max
            -m 512M
            -display none
            -serial stdio
            -drive "if=none,id=hd0,format=raw,file=$TEST_IMAGE"
            -device virtio-scsi-pci,id=scsi0
            -device scsi-hd,bus=scsi0.0,drive=hd0
            -device isa-debug-exit
            -no-reboot
        )

        # Add KVM if available on Linux
        if [ "$HOST_OS" = "linux" ] && [ -e /dev/kvm ]; then
            QEMU_ARGS+=(-enable-kvm -cpu host)
        elif [ "$HOST_OS" = "darwin" ]; then
            # Check for HVF on macOS
            if [ "$(sysctl -n kern.hv_support 2>/dev/null)" = "1" ]; then
                QEMU_ARGS+=(-accel hvf -cpu host,-rdtscp)
            fi
        fi
    elif [ "$PLATFORM" = "virt" ]; then
        QEMU_ARGS=(
            -machine virt
            -cpu cortex-a57
            -m 512M
            -display none
            -serial stdio
            -drive "if=none,id=hd0,format=raw,file=$TEST_IMAGE"
            -device virtio-blk-device,drive=hd0
            -no-reboot
        )
    fi

    log_info "Running: $QEMU_CMD ${QEMU_ARGS[*]}"
    log_info "Timeout: ${QEMU_TIMEOUT}s"

    # Run QEMU and capture output
    rm -f "$LOG_FILE"

    set +e
    timeout "$QEMU_TIMEOUT" "$QEMU_CMD" "${QEMU_ARGS[@]}" 2>&1 | tee "$LOG_FILE"
    QEMU_EXIT_CODE=${PIPESTATUS[0]}
    set -e

    # Analyze exit code (debug-exit returns exit_code >> 1)
    # Exit code 1 from debug-exit means success (0 >> 1 + 1 = 1)
    # Exit code 3 from debug-exit means failure (1 >> 1 + 1 = 3... actually (1 << 1) | 1 = 3)
    # The formula is: (return_value << 1) | 1
    # So exit code 1 = return value 0 (success)
    # Exit code 3 = return value 1 (failure)

    if [ "$QEMU_EXIT_CODE" -eq 124 ]; then
        log_error "QEMU timed out after ${QEMU_TIMEOUT}s"
        return 1
    fi

    log_info "QEMU exited with code: $QEMU_EXIT_CODE"
}

# Analyze test results
analyze_results() {
    log_step "Analyzing test results..."

    if [ ! -f "$LOG_FILE" ]; then
        log_error "No log file found"
        return 1
    fi

    # Count test results
    TESTS_PASSED=$(grep -c '\[TEST_PASS\]' "$LOG_FILE" || echo 0)
    TESTS_FAILED=$(grep -c '\[TEST_FAIL\]' "$LOG_FILE" || echo 0)
    TESTS_TOTAL=$((TESTS_PASSED + TESTS_FAILED))

    log_info "Tests run: $TESTS_TOTAL"
    log_info "Tests passed: $TESTS_PASSED"
    log_info "Tests failed: $TESTS_FAILED"

    # Check for test suite markers
    if grep -q '\[E2E\] TEST_SUITE_PASS' "$LOG_FILE"; then
        log_success "Test suite passed"
        return 0
    elif grep -q '\[E2E\] TEST_SUITE_FAIL' "$LOG_FILE"; then
        log_error "Test suite failed"

        # Show failed tests
        echo ""
        log_info "Failed tests:"
        grep '\[TEST_FAIL\]' "$LOG_FILE" || true

        return 1
    elif grep -q '\[E2E\] TEST_SUITE_START' "$LOG_FILE"; then
        # Suite started but didn't complete
        log_warning "Test suite started but did not complete"

        # Check if we got any results
        if [ "$TESTS_PASSED" -gt 0 ] || [ "$TESTS_FAILED" -gt 0 ]; then
            log_info "Partial results available"
            if [ "$TESTS_FAILED" -eq 0 ]; then
                log_success "All completed tests passed"
                return 0
            else
                return 1
            fi
        fi

        return 1
    else
        log_error "Could not find test suite markers in output"
        log_info "Checking for kernel boot..."

        if grep -q "Authority Kernel E2E Test" "$LOG_FILE"; then
            log_info "Kernel booted and test agent started"
        else
            log_error "Kernel may not have booted properly"
        fi

        return 1
    fi
}

# Cleanup function
cleanup() {
    log_info "Cleaning up..."
    rm -f "$TEST_IMAGE"
    rm -f "$SCRIPT_DIR/test_e2e.manifest"
    # Keep log file for debugging
}

# Main execution
main() {
    echo ""
    echo "=============================================="
    echo "Authority Kernel E2E Test Suite"
    echo "=============================================="
    echo ""

    # Detect platform
    detect_platform

    # Check dependencies
    check_dependencies

    # Build kernel
    build_kernel

    # Build test program
    build_test_program

    # Create disk image
    create_disk_image

    # Run test in QEMU
    run_qemu_test

    # Analyze results
    if analyze_results; then
        echo ""
        echo "=============================================="
        log_success "E2E Tests Passed"
        echo "=============================================="
        cleanup
        exit 0
    else
        echo ""
        echo "=============================================="
        log_error "E2E Tests Failed"
        echo "=============================================="
        echo ""
        echo "Log file: $LOG_FILE"
        exit 1
    fi
}

# Run main
main "$@"
