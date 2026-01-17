#!/bin/bash
#
# run-sanitizers.sh - Run sanitizer tests on the nanos unit tests
#
# This script builds and runs the unit tests with various sanitizers
# to detect memory errors, undefined behavior, and data races.
#
# Sanitizers:
#   - ASan (AddressSanitizer) + UBSan (UndefinedBehaviorSanitizer)
#     Detects: buffer overflows, use-after-free, memory leaks, undefined behavior
#   - TSan (ThreadSanitizer)
#     Detects: data races, deadlocks
#   - MSan (MemorySanitizer) - Linux only
#     Detects: uninitialized memory reads
#
# Usage:
#   ./tools/run-sanitizers.sh [--asan|--tsan|--msan|--all]
#
# Exit codes:
#   0 - All tests passed
#   1 - One or more sanitizer errors detected
#   2 - Build failure
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
UNIT_TEST_DIR="$REPO_ROOT/test/unit"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check for clang
check_clang() {
    if ! command -v clang &> /dev/null; then
        log_error "clang not found. Please install clang to use sanitizers."
        exit 2
    fi
    log_info "Using clang: $(clang --version | head -1)"
}

# Run ASan tests
run_asan() {
    log_info "========================================"
    log_info "Running AddressSanitizer + UBSan tests"
    log_info "========================================"

    cd "$UNIT_TEST_DIR"

    # Set ASan options for more detailed output
    export ASAN_OPTIONS="detect_leaks=1:halt_on_error=0:print_stats=1:check_initialization_order=1"
    export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0"

    if ! make CC=clang asan 2>&1 | tee /tmp/asan_output.log; then
        log_error "ASan tests failed!"
        return 1
    fi

    # Check for ASan errors in output
    if grep -q "ERROR: AddressSanitizer\|ERROR: UndefinedBehaviorSanitizer\|runtime error:" /tmp/asan_output.log; then
        log_error "Sanitizer errors detected in ASan run"
        grep -A 20 "ERROR:\|runtime error:" /tmp/asan_output.log || true
        return 1
    fi

    log_info "ASan tests passed!"
    return 0
}

# Run TSan tests
run_tsan() {
    log_info "========================================"
    log_info "Running ThreadSanitizer tests"
    log_info "========================================"

    cd "$UNIT_TEST_DIR"

    # Set TSan options
    export TSAN_OPTIONS="halt_on_error=0:second_deadlock_stack=1"

    if ! make CC=clang tsan 2>&1 | tee /tmp/tsan_output.log; then
        log_error "TSan tests failed!"
        return 1
    fi

    # Check for TSan errors in output
    if grep -q "WARNING: ThreadSanitizer\|ERROR: ThreadSanitizer" /tmp/tsan_output.log; then
        log_error "Thread sanitizer errors detected"
        grep -A 20 "WARNING: ThreadSanitizer\|ERROR: ThreadSanitizer" /tmp/tsan_output.log || true
        return 1
    fi

    log_info "TSan tests passed!"
    return 0
}

# Run MSan tests (Linux only)
run_msan() {
    log_info "========================================"
    log_info "Running MemorySanitizer tests"
    log_info "========================================"

    if [[ "$(uname)" == "Darwin" ]]; then
        log_warn "MemorySanitizer is not supported on macOS. Skipping."
        return 0
    fi

    cd "$UNIT_TEST_DIR"

    # Set MSan options
    export MSAN_OPTIONS="halt_on_error=0"

    if ! make CC=clang msan 2>&1 | tee /tmp/msan_output.log; then
        log_error "MSan tests failed!"
        return 1
    fi

    # Check for MSan errors in output
    if grep -q "WARNING: MemorySanitizer\|ERROR: MemorySanitizer" /tmp/msan_output.log; then
        log_error "Memory sanitizer errors detected"
        grep -A 20 "WARNING: MemorySanitizer\|ERROR: MemorySanitizer" /tmp/msan_output.log || true
        return 1
    fi

    log_info "MSan tests passed!"
    return 0
}

# Print usage
usage() {
    echo "Usage: $0 [--asan|--tsan|--msan|--all]"
    echo ""
    echo "Options:"
    echo "  --asan    Run AddressSanitizer + UBSan tests"
    echo "  --tsan    Run ThreadSanitizer tests"
    echo "  --msan    Run MemorySanitizer tests (Linux only)"
    echo "  --all     Run all sanitizer tests (default)"
    echo "  --help    Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --asan    # Run only ASan tests"
    echo "  $0 --all     # Run all sanitizer tests"
    echo "  $0           # Same as --all"
}

# Main
main() {
    local run_asan_flag=0
    local run_tsan_flag=0
    local run_msan_flag=0
    local errors=0

    # Parse arguments
    if [[ $# -eq 0 ]]; then
        run_asan_flag=1
        run_tsan_flag=1
        run_msan_flag=1
    else
        while [[ $# -gt 0 ]]; do
            case "$1" in
                --asan)
                    run_asan_flag=1
                    shift
                    ;;
                --tsan)
                    run_tsan_flag=1
                    shift
                    ;;
                --msan)
                    run_msan_flag=1
                    shift
                    ;;
                --all)
                    run_asan_flag=1
                    run_tsan_flag=1
                    run_msan_flag=1
                    shift
                    ;;
                --help|-h)
                    usage
                    exit 0
                    ;;
                *)
                    log_error "Unknown option: $1"
                    usage
                    exit 2
                    ;;
            esac
        done
    fi

    log_info "Starting sanitizer tests..."
    check_clang

    # Run selected sanitizers
    if [[ $run_asan_flag -eq 1 ]]; then
        if ! run_asan; then
            errors=$((errors + 1))
        fi
    fi

    if [[ $run_tsan_flag -eq 1 ]]; then
        if ! run_tsan; then
            errors=$((errors + 1))
        fi
    fi

    if [[ $run_msan_flag -eq 1 ]]; then
        if ! run_msan; then
            errors=$((errors + 1))
        fi
    fi

    # Summary
    echo ""
    log_info "========================================"
    log_info "Sanitizer Test Summary"
    log_info "========================================"

    if [[ $errors -eq 0 ]]; then
        log_info "All sanitizer tests passed!"
        exit 0
    else
        log_error "$errors sanitizer test(s) failed"
        exit 1
    fi
}

main "$@"
