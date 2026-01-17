#!/bin/bash
#
# Authority Kernel - Fuzz Testing Runner
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Authority Systems
#
# This script provides a convenient interface for running fuzz tests
# against the Authority Kernel parser/decoder boundaries.
#
# Usage:
#   ./run-fuzz.sh [options] [target]
#
# Options:
#   -t, --time SECONDS    Maximum fuzzing time (default: 60)
#   -j, --jobs N          Number of parallel jobs (default: 1)
#   -c, --coverage        Enable coverage reporting
#   -m, --minimize        Minimize corpus after fuzzing
#   -v, --verbose         Verbose output
#   -h, --help            Show this help message
#
# Targets:
#   all                   Run all fuzzers (default)
#   json                  Fuzz JSON policy parser
#   pattern               Fuzz pattern matcher
#   path                  Fuzz path canonicalization
#
# Examples:
#   ./run-fuzz.sh                    # Run all fuzzers for 60s each
#   ./run-fuzz.sh -t 300 json        # Fuzz JSON parser for 5 minutes
#   ./run-fuzz.sh -j 4 all           # Run all with 4 parallel jobs
#   ./run-fuzz.sh -c pattern         # Fuzz patterns with coverage
#

set -e

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FUZZ_DIR="${SCRIPT_DIR}/../test/fuzz"

# Default settings
FUZZ_TIME=60
JOBS=1
COVERAGE=0
MINIMIZE=0
VERBOSE=0
TARGET="all"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored message
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Show help
show_help() {
    head -n 30 "$0" | tail -n +3 | sed 's/^# //' | sed 's/^#//'
    exit 0
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--time)
            FUZZ_TIME="$2"
            shift 2
            ;;
        -j|--jobs)
            JOBS="$2"
            shift 2
            ;;
        -c|--coverage)
            COVERAGE=1
            shift
            ;;
        -m|--minimize)
            MINIMIZE=1
            shift
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        -h|--help)
            show_help
            ;;
        all|json|pattern|path)
            TARGET="$1"
            shift
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check for clang
if ! command -v clang &> /dev/null; then
    log_error "clang is required but not installed."
    log_info "Install with: brew install llvm (macOS) or apt install clang (Linux)"
    exit 1
fi

# Check for libFuzzer support
if ! clang -fsanitize=fuzzer -x c -c /dev/null -o /dev/null 2>/dev/null; then
    log_error "clang does not have libFuzzer support."
    log_info "Ensure you have a recent clang version with libFuzzer."
    exit 1
fi

# Change to fuzz directory
cd "$FUZZ_DIR"

# Build targets
log_info "Building fuzz targets..."

if [[ $COVERAGE -eq 1 ]]; then
    make clean
    CFLAGS="-fprofile-instr-generate -fcoverage-mapping" make all
else
    make all
fi

# Generate corpus if needed
if [[ ! -d "corpus/json" ]] || [[ ! -d "corpus/pattern" ]] || [[ ! -d "corpus/path" ]]; then
    log_info "Generating initial corpus..."
    make corpus
fi

# Run fuzzers
run_fuzzer() {
    local name=$1
    local binary=$2
    local corpus=$3

    log_info "Running $name fuzzer (${FUZZ_TIME}s, ${JOBS} job(s))..."

    local fuzzer_args=(
        "-max_total_time=${FUZZ_TIME}"
        "-jobs=${JOBS}"
    )

    if [[ $VERBOSE -eq 1 ]]; then
        fuzzer_args+=("-verbosity=1")
    else
        fuzzer_args+=("-verbosity=0")
    fi

    if [[ $COVERAGE -eq 1 ]]; then
        LLVM_PROFILE_FILE="${name}_%p.profraw" ./"$binary" "${fuzzer_args[@]}" "$corpus"
    else
        ./"$binary" "${fuzzer_args[@]}" "$corpus"
    fi

    local exit_code=$?
    if [[ $exit_code -eq 0 ]]; then
        log_success "$name fuzzer completed successfully"
    else
        log_error "$name fuzzer exited with code $exit_code"
        # Check for crash files
        if ls crash-* 1> /dev/null 2>&1; then
            log_error "Crash files found:"
            ls -la crash-*
        fi
    fi

    return $exit_code
}

# Track overall result
RESULT=0

case $TARGET in
    all)
        log_info "Running all fuzzers..."
        run_fuzzer "JSON parser" "fuzz_json_parser" "corpus/json" || RESULT=1
        run_fuzzer "Pattern matcher" "fuzz_pattern_match" "corpus/pattern" || RESULT=1
        run_fuzzer "Path canonicalization" "fuzz_path_canonicalize" "corpus/path" || RESULT=1
        ;;
    json)
        run_fuzzer "JSON parser" "fuzz_json_parser" "corpus/json" || RESULT=1
        ;;
    pattern)
        run_fuzzer "Pattern matcher" "fuzz_pattern_match" "corpus/pattern" || RESULT=1
        ;;
    path)
        run_fuzzer "Path canonicalization" "fuzz_path_canonicalize" "corpus/path" || RESULT=1
        ;;
esac

# Generate coverage report
if [[ $COVERAGE -eq 1 ]]; then
    log_info "Generating coverage report..."
    llvm-profdata merge -sparse *.profraw -o fuzz.profdata 2>/dev/null || true

    if [[ -f "fuzz.profdata" ]]; then
        for binary in fuzz_json_parser fuzz_pattern_match fuzz_path_canonicalize; do
            if [[ -f "$binary" ]]; then
                llvm-cov show "./$binary" -instr-profile=fuzz.profdata \
                    -output-dir="coverage_${binary}" -format=html 2>/dev/null || true
            fi
        done
        log_success "Coverage reports generated in coverage_*/ directories"
    fi
fi

# Minimize corpus
if [[ $MINIMIZE -eq 1 ]]; then
    log_info "Minimizing corpus..."
    make minimize
fi

# Summary
echo ""
log_info "=========================================="
log_info "Fuzzing Summary"
log_info "=========================================="
log_info "Target:    $TARGET"
log_info "Duration:  ${FUZZ_TIME}s per fuzzer"
log_info "Jobs:      $JOBS"
log_info "Coverage:  $([ $COVERAGE -eq 1 ] && echo 'Yes' || echo 'No')"
log_info "Minimize:  $([ $MINIMIZE -eq 1 ] && echo 'Yes' || echo 'No')"

# Check for crash/leak/timeout files
if ls crash-* 1> /dev/null 2>&1; then
    log_error "CRASHES FOUND:"
    ls -la crash-*
    RESULT=1
fi

if ls leak-* 1> /dev/null 2>&1; then
    log_warn "MEMORY LEAKS FOUND:"
    ls -la leak-*
fi

if ls timeout-* 1> /dev/null 2>&1; then
    log_warn "TIMEOUTS FOUND:"
    ls -la timeout-*
fi

if [[ $RESULT -eq 0 ]]; then
    log_success "All fuzzing completed successfully!"
else
    log_error "Fuzzing completed with errors."
fi

exit $RESULT
