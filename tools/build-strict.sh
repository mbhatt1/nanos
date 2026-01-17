#!/bin/bash
#
# Authority Kernel - Strict Build Verification Script
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Authority Systems
#
# This script runs strict compilation checks on the test suite
# to catch common bugs and ensure code quality.
#
# Exit codes:
#   0 - All tests built and passed
#   1 - Build or test failure
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NANOS_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Track results
UNIT_BUILD_STATUS=0
UNIT_TEST_STATUS=0
INTEGRATION_BUILD_STATUS=0
INTEGRATION_TEST_STATUS=0

echo "=============================================="
echo "  Authority Kernel - Strict Build Check"
echo "=============================================="
echo ""
log_info "Nanos root: $NANOS_ROOT"
echo ""

# Unit Tests
echo "=============================================="
echo "  Building Unit Tests with Strict Warnings"
echo "=============================================="
echo ""

cd "$NANOS_ROOT/test/unit"

log_info "Cleaning unit test build artifacts..."
make clean 2>/dev/null || true

log_info "Building unit tests with strict warning flags..."
if make 2>&1; then
    log_info "Unit tests built successfully"
    UNIT_BUILD_STATUS=0
else
    log_error "Unit test build failed"
    UNIT_BUILD_STATUS=1
fi

if [ $UNIT_BUILD_STATUS -eq 0 ]; then
    echo ""
    log_info "Running unit tests..."
    if make test 2>&1; then
        log_info "Unit tests passed"
        UNIT_TEST_STATUS=0
    else
        log_error "Unit tests failed"
        UNIT_TEST_STATUS=1
    fi
fi

# Integration Tests
echo ""
echo "=============================================="
echo "  Building Integration Tests with Strict Warnings"
echo "=============================================="
echo ""

cd "$NANOS_ROOT/test/integration"

log_info "Cleaning integration test build artifacts..."
make clean 2>/dev/null || true

log_info "Building integration tests with strict warning flags..."
if make 2>&1; then
    log_info "Integration tests built successfully"
    INTEGRATION_BUILD_STATUS=0
else
    log_error "Integration test build failed"
    INTEGRATION_BUILD_STATUS=1
fi

if [ $INTEGRATION_BUILD_STATUS -eq 0 ]; then
    echo ""
    log_info "Running integration tests..."
    if make test 2>&1; then
        log_info "Integration tests passed"
        INTEGRATION_TEST_STATUS=0
    else
        log_error "Integration tests failed"
        INTEGRATION_TEST_STATUS=1
    fi
fi

# Summary
echo ""
echo "=============================================="
echo "  Build Summary"
echo "=============================================="
echo ""

print_status() {
    local name="$1"
    local status="$2"
    if [ "$status" -eq 0 ]; then
        echo -e "  $name: ${GREEN}PASS${NC}"
    else
        echo -e "  $name: ${RED}FAIL${NC}"
    fi
}

print_status "Unit Test Build" $UNIT_BUILD_STATUS
print_status "Unit Test Run" $UNIT_TEST_STATUS
print_status "Integration Test Build" $INTEGRATION_BUILD_STATUS
print_status "Integration Test Run" $INTEGRATION_TEST_STATUS

echo ""

# Determine overall exit code
OVERALL_STATUS=0
if [ $UNIT_BUILD_STATUS -ne 0 ] || [ $UNIT_TEST_STATUS -ne 0 ] || \
   [ $INTEGRATION_BUILD_STATUS -ne 0 ] || [ $INTEGRATION_TEST_STATUS -ne 0 ]; then
    OVERALL_STATUS=1
    log_error "Strict build check FAILED"
else
    log_info "Strict build check PASSED"
fi

echo ""
echo "Strict warning flags used:"
echo "  -Wall -Wextra -Werror -Wshadow -Wconversion -Wsign-conversion"
echo "  -Wformat=2 -Wundef -Wpointer-arith -Wstrict-prototypes -Wvla"
echo ""

exit $OVERALL_STATUS
