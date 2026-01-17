#!/bin/bash
#
# Authority Kernel - Strict Smoke Test
# Runs all gates for bug verification
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NANOS_DIR="$(dirname "$SCRIPT_DIR")"
AUTHORITY_DIR="$(dirname "$NANOS_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; exit 1; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
info() { echo -e "[INFO] $1"; }

echo "=========================================="
echo "  Authority Kernel Strict Smoke Test"
echo "=========================================="
echo ""

# Track results
GATES_PASSED=0
GATES_FAILED=0

###########################################
# GATE 1: Strict Build
###########################################
echo "=== GATE 1: Strict Build ==="

info "Building unit tests..."
cd "$NANOS_DIR/test/unit"

if make clean all 2>&1 | tee /tmp/build.log | tail -20; then
    if grep -q "error:" /tmp/build.log; then
        fail "Build errors found"
        ((GATES_FAILED++))
    else
        pass "Unit tests built"
        ((GATES_PASSED++))
    fi
else
    fail "Build failed"
    ((GATES_FAILED++))
fi

###########################################
# GATE 2: Unit Tests Pass
###########################################
echo ""
echo "=== GATE 2: Unit Tests ==="

info "Running unit tests..."
if make test 2>&1; then
    pass "All unit tests passed"
    ((GATES_PASSED++))
else
    fail "Unit tests failed"
    ((GATES_FAILED++))
fi

###########################################
# GATE 3: Integration Tests Pass
###########################################
echo ""
echo "=== GATE 3: Integration Tests ==="

if [ -d "$NANOS_DIR/test/integration" ]; then
    cd "$NANOS_DIR/test/integration"
    info "Running integration tests..."
    if make test 2>&1; then
        pass "All integration tests passed"
        ((GATES_PASSED++))
    else
        fail "Integration tests failed"
        ((GATES_FAILED++))
    fi
else
    warn "Integration tests directory not found"
fi

###########################################
# GATE 4: Sanitizer Check (if available)
###########################################
echo ""
echo "=== GATE 4: Sanitizer Check ==="

if command -v clang &> /dev/null; then
    cd "$NANOS_DIR/test/unit"
    info "Building with ASan+UBSan..."

    if make clean 2>/dev/null && \
       make CC=clang CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1" all 2>&1 | tail -10; then
        info "Running sanitizer tests..."
        if ./bin/ak_pattern_test 2>&1 && \
           ./bin/ak_policy_test 2>&1 && \
           ./bin/ak_effects_test 2>&1; then
            pass "Sanitizer tests passed"
            ((GATES_PASSED++))
        else
            fail "Sanitizer detected issues"
            ((GATES_FAILED++))
        fi
    else
        warn "ASan build failed (may need clang)"
    fi
else
    warn "clang not found, skipping sanitizer check"
fi

###########################################
# GATE 5: No Unsafe APIs
###########################################
echo ""
echo "=== GATE 5: Unsafe API Check ==="

cd "$NANOS_DIR/src/agentic"
UNSAFE_COUNT=$(grep -r "strcpy\|strcat\|sprintf\|vsprintf\|gets\|alloca" *.c 2>/dev/null | wc -l)

if [ "$UNSAFE_COUNT" -eq 0 ]; then
    pass "No unsafe APIs found"
    ((GATES_PASSED++))
else
    fail "Found $UNSAFE_COUNT unsafe API calls"
    ((GATES_FAILED++))
fi

###########################################
# Summary
###########################################
echo ""
echo "=========================================="
echo "  SUMMARY"
echo "=========================================="
echo ""
echo "Gates Passed: $GATES_PASSED"
echo "Gates Failed: $GATES_FAILED"
echo ""

if [ "$GATES_FAILED" -eq 0 ]; then
    echo -e "${GREEN}ALL GATES PASSED${NC}"
    exit 0
else
    echo -e "${RED}$GATES_FAILED GATE(S) FAILED${NC}"
    exit 1
fi
