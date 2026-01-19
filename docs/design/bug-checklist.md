# Bug Checklist and Known Issues

This document tracks known bugs, security findings, and verification procedures for the Authority Kernel.

---

## Overview

| Severity | Count | Examples |
|----------|-------|----------|
| P0 (Critical) | 2 | User/kernel boundary validation, Integer overflow in policy parsing |
| P1 (High) | 4 | Path traversal, TOCTOU, Input validation |
| P2 (Medium) | 3 | Bounds checks, Escape sequence handling |

---

## Critical Issues (P0)

### Issue #1: User-Space Pointer Validation

**File:** `src/agentic/ak_nanos.c` (Lines 118-139, 186-187)

**Problem:** Syscall handler copies data from user-space pointers without validation that the memory is actually accessible.

**Impact:** Potential kernel memory disclosure and corruption.

**Status:** Requires `validate_user_memory()` wrapper before `copy_from_user()`

---

### Issue #2: Integer Overflow in Policy Parsing

**File:** `src/agentic/ak_policy_v2.c` (Lines 204-211)

**Problem:** `parse_number()` function does not check for integer overflow when parsing JSON numbers.

**Vulnerable Code:**
```c
*out = (*out * 10) + (*p - '0');  // NO OVERFLOW CHECK!
```

**Impact:** Budget limits can wrap around, causing policy bypass.

**Status:** Add overflow check: `if (*out > (ULLONG_MAX - digit) / 10) return error;`

---

## High Priority Issues (P1)

### Issue #3: Integer Overflow in LZ4 Decompression

**File:** `src/agentic/ak_lz4.c` (Lines 297-306, 332-341)

**Problem:** Literal and match length accumulation without overflow checking.

**Impact:** Malicious compressed streams could cause length values to wrap around, bypassing bounds checks.

**Status:** Add overflow guards before accumulating continuation bytes.

---

### Issue #4: Path Traversal Edge Cases

**File:** `src/agentic/ak_posix_route.c`

**Problem:** Canonicalization may not handle all path traversal variants.

**Mitigations Applied:**
- Normalize `.` and `..` segments
- Validate against null bytes
- Lexical canonicalization (no symlink resolution in P0)

**Status:** Covered by test suite; monitor for new variants.

---

### Issue #5: TOCTOU (Time-of-Check to Time-of-Use)

**File:** `src/agentic/ak_effects.c`

**Problem:** Time gap between policy check and actual operation.

**Mitigation:** Canonicalize target immediately on syscall entry; use same canonical target for both check and operation.

**Status:** Mitigated by atomic check-and-act pattern.

---

### Issue #6: Input Validation in Policy Loading

**File:** `src/agentic/ak_policy_v2.c`

**Problem:** Insufficient validation of JSON structure and values.

**Mitigations Applied:**
- Bounded buffers for all pattern strings
- Range checking on all numeric values
- Type validation on capability enums

**Status:** Requires continuous validation during policy parsing.

---

## Medium Priority Issues (P2)

### Issue #7: Missing Bounds Checks

**Status:** Systematically added throughout codebase. Remaining instances identified during code review.

**Example:** Buffer sizes validated against `AK_MAX_*` constants.

---

### Issue #8: Escape Sequence Handling

**Problem:** Policy patterns may contain escape sequences that confuse matching.

**Current Approach:** Single canonical form for all targets before policy matching.

**Status:** Requires comprehensive escape test suite.

---

### Issue #9: Magic Validation Expansion

**Status:** Magic fields added to critical structures.

Magic values defined:
- `AK_CTX_MAGIC` (0x414B4354)
- `AK_CAP_MAGIC` (0x414B4350)
- `AK_REQ_MAGIC` (0x414B5251)
- `AK_POLICY_MAGIC` (0x414B504C)
- `AK_DEAD_MAGIC` (0xDEADBEEF)

---

## Verification Checklist

### Pre-Merge Verification

- [ ] All P0 issues addressed
- [ ] Unit tests pass with assertion level 3
- [ ] Fuzzing tests pass with malformed inputs
- [ ] Integer overflow tests pass
- [ ] Path traversal tests pass
- [ ] TOCTOU tests pass

### Per-Commit Verification

- [ ] `make test` passes
- [ ] `./tools/smoke.sh` passes
- [ ] No new compiler warnings
- [ ] Assertion coverage review

### Pre-Release Verification

- [ ] All P0 and P1 issues resolved
- [ ] Security audit completed
- [ ] Threat model reviewed
- [ ] Invariant coverage verified

---

## Testing Infrastructure

### Unit Tests

Location: `test/unit/ak_*.c`

Run:
```bash
cd test/unit
make
./bin/ak_capability_test
./bin/ak_audit_test
./bin/ak_policy_test
```

### Integration Tests

Location: `test/runtime/`

Run:
```bash
cd test/runtime
make
./ak_integration_test
```

### Fuzzing

Location: `test/fuzz/`

Run:
```bash
cd test/fuzz
make fuzz
# Runs on fuzzing corpus to identify crashes
```

### Smoke Test

```bash
./tools/smoke.sh
```

Verifies:
- Kernel builds successfully
- Boots to user process
- Deny-by-default is enforced
- Last deny information is available

---

## Assertion Levels

The assertion system supports three levels:

| Level | NDEBUG | Description |
|-------|--------|-------------|
| 1 | Yes | Critical only (NULL checks, security invariants) |
| 2 | No | Normal (+ bounds, state validation) |
| 3 | No | Full (+ debug assertions, expensive checks) |

Set via:
```bash
export AK_ASSERT_LEVEL=3
make test
```

---

## Recommendations

1. **Enable assertions in CI** - Run with `AK_ASSERT_LEVEL=3`
2. **Continuous fuzzing** - Integrate fuzzing into CI pipeline
3. **Regular audits** - Schedule security audits every major release
4. **Invariant assertions** - Add `AK_ASSERT_INV*()` calls at enforcement points
5. **Magic validation** - Consider adding to more critical structures

---

## References

- [Security Invariants](./invariants.md)
- [Threat Model](./ak-threat-model.md)
- [Authority Kernel Design](./ak-design.md)
