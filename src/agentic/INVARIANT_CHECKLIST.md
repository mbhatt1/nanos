# Authority Kernel Invariant Checklist

## Agent A12 - API/Contract Auditor Report

### Summary
Added comprehensive assertion infrastructure and documented invariants for the Authority Kernel codebase.

---

## Files Created

### ak_assert.h
New assertion header with:
- **AK_ASSERT()** - Base assertion macro with file/line reporting
- **AK_ASSERT_NOT_NULL()** - Critical NULL pointer checks (always enabled)
- **AK_CHECK_NOT_NULL()** - Soft check returning error value
- **AK_ASSERT_IN_RANGE()** - Bounds checking for values
- **AK_ASSERT_INDEX()** - Array bounds checking
- **AK_ASSERT_MAGIC()** - Structure magic validation
- **AK_PRECONDITION()** / **AK_POSTCONDITION()** - Contract documentation
- **AK_ASSERT_STATE()** - State machine validation
- **AK_ASSERT_INV2_HAS_CAP()** - Capability invariant enforcement
- **AK_ASSERT_INV3_BUDGET()** - Budget invariant enforcement
- **AK_ASSERT_INV4_LOG_CHAIN()** - Audit log chain enforcement

Magic values defined:
- AK_CTX_MAGIC (0x414B4354)
- AK_CAP_MAGIC (0x414B4350)
- AK_REQ_MAGIC (0x414B5251)
- AK_POLICY_MAGIC (0x414B504C)
- AK_DEAD_MAGIC (0xDEADBEEF)

---

## Files Modified

### ak_types.h
- Added compile-time assertions for constant validation
- Documented all four core invariants (INV-1 through INV-4)
- Added static asserts for hash/key sizes

### ak_effects.h
- Added comprehensive function contracts (PRECONDITIONS/POSTCONDITIONS)
- Documented error returns for all public functions
- Added thread safety documentation

### ak_effects.c
- Added precondition checks to ak_effects_init()
- Added precondition checks to ak_ctx_create()
- Added comprehensive validation to ak_authorize_and_execute():
  - NULL pointer checks for ctx, req, decision_out
  - Range validation for effect op codes
  - Bounds checking for params_len

### ak_capability.h
- Added function contracts for ak_capability_create()
- Added function contracts for ak_capability_verify()
- Documented INV-2 enforcement points

### ak_capability.c
- Added precondition checks to ak_capability_create():
  - Heap validation
  - Resource NULL check
  - Type range validation
  - TTL validation
  - Resource length bounds check
- Added INV-2 enforcement documentation to ak_capability_validate()
- Added postcondition checks

### ak_context.c
- Added ak_assert.h include
- (Already has excellent magic validation via AK_CTX_MAGIC)

---

## Invariant Enforcement Summary

### INV-1: No-Bypass (syscall-only effects)
- Enforced by: ak_posix_route.c interception
- Checked by: syscall audit in ak_effects.c
- Status: **ENFORCED**

### INV-2: Capability (valid cap required)
- Enforced by: ak_capability_validate() in syscall path
- Checked by: AK_ASSERT_INV2_HAS_CAP() macro
- Status: **ENFORCED** (assertions added)

### INV-3: Budget (admission control)
- Enforced by: ak_budget_check() before operation
- Checked by: AK_ASSERT_INV3_BUDGET() macro
- Status: **ENFORCED** (assertions added)

### INV-4: Log Commitment (hash-chained audit)
- Enforced by: ak_audit_log() after each operation
- Checked by: AK_ASSERT_INV4_LOG_CHAIN() macro
- Status: **ENFORCED** (assertions added)

---

## Potential Invariant Violations Found

### HIGH PRIORITY

1. **Missing effect op range validation** (FIXED)
   - Location: ak_effects.c:ak_authorize_and_execute()
   - Issue: Effect op codes not validated to be in valid range
   - Fix: Added AK_CHECK_IN_RANGE(req->op, 0x0100, 0x0500, -EINVAL)

2. **Missing params_len bounds check** (FIXED)
   - Location: ak_effects.c:ak_authorize_and_execute()
   - Issue: params_len not validated against AK_MAX_PARAMS
   - Fix: Added AK_CHECK_IN_RANGE(req->params_len, 0, AK_MAX_PARAMS, -EINVAL)

3. **Missing heap validation** (FIXED)
   - Location: ak_effects.c:ak_effects_init(), ak_ctx_create()
   - Issue: No check for INVALID_ADDRESS heap
   - Fix: Added explicit INVALID_ADDRESS check

### MEDIUM PRIORITY

4. **TTL validation in capability creation** (FIXED)
   - Location: ak_capability.c:ak_capability_create()
   - Issue: TTL of 0 would create instantly-expired capability
   - Fix: Added check for ttl_ms > 0

5. **Capability type range validation** (FIXED)
   - Location: ak_capability.c:ak_capability_create()
   - Issue: Type not validated against AK_CAP_* enum range
   - Fix: Added AK_CHECK_IN_RANGE(type, AK_CAP_NONE, AK_CAP_ADMIN, NULL)

### LOW PRIORITY (Already Handled)

6. **Context magic validation**
   - Location: ak_context.c
   - Status: Already enforced via AK_CTX_MAGIC and ctx_validate_magic()

7. **NULL pointer checks at API boundaries**
   - Status: Consistently applied throughout codebase

---

## Assertion Levels

The assertion system supports three levels:

| Level | NDEBUG | Description |
|-------|--------|-------------|
| 1 | Yes | Critical only (NULL checks, security invariants) |
| 2 | No | Normal (+ bounds, state validation) |
| 3 | No | Full (+ debug assertions, expensive checks) |

Production builds should use Level 1 minimum for security.

---

## Recommendations

1. **Enable assertions in CI** - Run tests with AK_ASSERT_LEVEL=3 to catch issues early

2. **Add fuzzing** - Fuzz test API boundaries with invalid inputs to verify assertion coverage

3. **Add magic validation** - Consider adding magic fields to more structures (ak_effect_req_t, etc.)

4. **Periodic assertion review** - Review assertion coverage as new code is added

---

## Compile-Time Assertions Added

```c
AK_STATIC_ASSERT(AK_HASH_SIZE == 32, "AK_HASH_SIZE must be 32 bytes for SHA-256");
AK_STATIC_ASSERT(AK_MAC_SIZE == 32, "AK_MAC_SIZE must be 32 bytes for HMAC-SHA256");
AK_STATIC_ASSERT(AK_KEY_SIZE == 32, "AK_KEY_SIZE must be 32 bytes");
AK_STATIC_ASSERT(AK_TOKEN_ID_SIZE == 16, "AK_TOKEN_ID_SIZE must be 16 bytes");
AK_STATIC_ASSERT(AK_SIG_SIZE == 64, "AK_SIG_SIZE must be 64 bytes for Ed25519");
AK_STATIC_ASSERT(AK_SYS_MIN == 1024, "AK syscalls must start at 1024");
AK_STATIC_ASSERT(AK_RESOURCE_COUNT <= 16, "Too many resource types");
AK_STATIC_ASSERT(AK_MAX_FRAME_SIZE >= AK_MIN_FRAME_SIZE, "Invalid frame size limits");
```

---

*Generated by Agent A12 (API/Contract Auditor)*
*Date: 2026-01-16*
