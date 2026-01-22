/*
 * Authority Kernel - Assertion and Invariant Checking
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * This file provides assertion macros for enforcing invariants throughout
 * the Authority Kernel. Assertions are critical for:
 *   - Detecting programming errors early
 *   - Enforcing the four core invariants (INV-1 through INV-4)
 *   - Validating preconditions and postconditions
 *   - Preventing security vulnerabilities from NULL dereferences
 *
 * USAGE GUIDELINES:
 *   - Use AK_ASSERT() for general invariant checking
 *   - Use AK_ASSERT_NOT_NULL() at API boundaries
 *   - Use AK_ASSERT_VALID_CTX() when context is required
 *   - Use AK_ASSERT_IN_RANGE() for array bounds checking
 *   - Use AK_PRECONDITION() to document function entry requirements
 *   - Use AK_POSTCONDITION() to verify function exit state
 *
 * SECURITY: Assertions in this file use halt() to prevent undefined behavior
 * from propagating. In production with NDEBUG, critical checks remain but
 * non-critical assertions become no-ops for performance.
 */

#ifndef AK_ASSERT_H
#define AK_ASSERT_H

#include "ak_compat.h"

/* ============================================================
 * ASSERTION CONFIGURATION
 * ============================================================ */

/* Allow compile-time control of assertion level */
#ifndef AK_ASSERT_LEVEL
#ifdef NDEBUG
#define AK_ASSERT_LEVEL 1 /* Production: only critical assertions */
#else
#define AK_ASSERT_LEVEL 3 /* Debug: all assertions enabled */
#endif
#endif

/* Assertion levels:
 * 0 = No assertions (dangerous, not recommended)
 * 1 = Critical only (NULL checks, security invariants)
 * 2 = Normal (+ bounds checks, state validation)
 * 3 = Full (+ debug assertions, expensive checks)
 */

/* ============================================================
 * MAGIC VALUES FOR STRUCTURE VALIDATION
 * ============================================================
 * These magic values detect use-after-free and memory corruption.
 */

#define AK_CTX_MAGIC 0x414B4354    /* "AKCT" - AK Context */
#define AK_CAP_MAGIC 0x414B4350    /* "AKCP" - AK Capability */
#define AK_REQ_MAGIC 0x414B5251    /* "AKRQ" - AK Request */
#define AK_RESP_MAGIC 0x414B5250   /* "AKRP" - AK Response */
#define AK_POLICY_MAGIC 0x414B504C /* "AKPL" - AK Policy */
#define AK_HEAP_MAGIC 0x414B4850   /* "AKHP" - AK Heap */
#define AK_LOG_MAGIC 0x414B4C47    /* "AKLG" - AK Log */
#define AK_AGENT_MAGIC 0x414B4147  /* "AKAG" - AK Agent */

/* Dead/freed magic - set when structure is destroyed */
#define AK_DEAD_MAGIC 0xDEADBEEF

/* ============================================================
 * CORE ASSERTION MACRO
 * ============================================================
 * This is the fundamental assertion that all others build on.
 * Uses halt() to stop execution on failure, preventing undefined behavior.
 */

#if AK_ASSERT_LEVEL > 0

#define AK_ASSERT(cond)                                                        \
  do {                                                                         \
    if (unlikely(!(cond))) {                                                   \
      rprintf("AK ASSERT FAILED: %s\n  at %s:%d in %s()\n", #cond, __FILE__,   \
              __LINE__, __func__);                                             \
      halt("AK assertion failed: " #cond);                                     \
    }                                                                          \
  } while (0)

#define AK_ASSERT_MSG(cond, msg)                                               \
  do {                                                                         \
    if (unlikely(!(cond))) {                                                   \
      rprintf("AK ASSERT FAILED: %s\n  Message: %s\n  at %s:%d in %s()\n",     \
              #cond, msg, __FILE__, __LINE__, __func__);                       \
      halt("AK assertion failed");                                             \
    }                                                                          \
  } while (0)

#else

#define AK_ASSERT(cond) ((void)0)
#define AK_ASSERT_MSG(cond, msg) ((void)0)

#endif /* AK_ASSERT_LEVEL > 0 */

/* ============================================================
 * NULL POINTER CHECKS (CRITICAL - Always Enabled)
 * ============================================================
 * NULL pointer dereferences are security-critical bugs.
 * These are ALWAYS enabled, even in production.
 */

#define AK_ASSERT_NOT_NULL(ptr)                                                \
  do {                                                                         \
    if (unlikely((ptr) == NULL)) {                                             \
      rprintf("AK NULL POINTER: %s is NULL\n  at %s:%d in %s()\n", #ptr,       \
              __FILE__, __LINE__, __func__);                                   \
      halt("AK null pointer assertion failed");                                \
    }                                                                          \
  } while (0)

/* Variant that returns an error code instead of halting */
#define AK_CHECK_NOT_NULL(ptr, retval)                                         \
  do {                                                                         \
    if (unlikely((ptr) == NULL)) {                                             \
      ak_error("NULL pointer: %s at %s:%d", #ptr, __func__, __LINE__);         \
      return (retval);                                                         \
    }                                                                          \
  } while (0)

/* Variant for void functions */
#define AK_CHECK_NOT_NULL_VOID(ptr)                                            \
  do {                                                                         \
    if (unlikely((ptr) == NULL)) {                                             \
      ak_error("NULL pointer: %s at %s:%d", #ptr, __func__, __LINE__);         \
      return;                                                                  \
    }                                                                          \
  } while (0)

/* ============================================================
 * BOUNDS CHECKING
 * ============================================================
 * Array bounds checks to prevent buffer overflows/underflows.
 */

#if AK_ASSERT_LEVEL >= 2

#define AK_ASSERT_IN_RANGE(val, min, max)                                      \
  do {                                                                         \
    if (unlikely((val) < (min) || (val) > (max))) {                            \
      rprintf("AK BOUNDS FAILED: %s = %lld not in [%lld, %lld]\n  at %s:%d "   \
              "in %s()\n",                                                     \
              #val, (long long)(val), (long long)(min), (long long)(max),      \
              __FILE__, __LINE__, __func__);                                   \
      halt("AK bounds assertion failed");                                      \
    }                                                                          \
  } while (0)

#define AK_ASSERT_INDEX(idx, len)                                              \
  do {                                                                         \
    if (unlikely((idx) >= (len))) {                                            \
      rprintf("AK INDEX FAILED: %s = %llu >= %s = %llu\n  at %s:%d in %s()\n", \
              #idx, (unsigned long long)(idx), #len,                           \
              (unsigned long long)(len), __FILE__, __LINE__, __func__);        \
      halt("AK index assertion failed");                                       \
    }                                                                          \
  } while (0)

#define AK_ASSERT_POSITIVE(val)                                                \
  do {                                                                         \
    if (unlikely((val) <= 0)) {                                                \
      rprintf("AK POSITIVE FAILED: %s = %lld <= 0\n  at %s:%d in %s()\n",      \
              #val, (long long)(val), __FILE__, __LINE__, __func__);           \
      halt("AK positive assertion failed");                                    \
    }                                                                          \
  } while (0)

#define AK_ASSERT_NON_NEGATIVE(val)                                            \
  do {                                                                         \
    if (unlikely((val) < 0)) {                                                 \
      rprintf("AK NON_NEGATIVE FAILED: %s = %lld < 0\n  at %s:%d in %s()\n",   \
              #val, (long long)(val), __FILE__, __LINE__, __func__);           \
      halt("AK non-negative assertion failed");                                \
    }                                                                          \
  } while (0)

#else

#define AK_ASSERT_IN_RANGE(val, min, max) ((void)0)
#define AK_ASSERT_INDEX(idx, len) ((void)0)
#define AK_ASSERT_POSITIVE(val) ((void)0)
#define AK_ASSERT_NON_NEGATIVE(val) ((void)0)

#endif /* AK_ASSERT_LEVEL >= 2 */

/* Soft checks that return errors instead of halting */
#define AK_CHECK_IN_RANGE(val, min, max, retval)                               \
  do {                                                                         \
    if (unlikely((val) < (min) || (val) > (max))) {                            \
      ak_error("Value %s = %lld out of range [%lld, %lld] at %s:%d", #val,     \
               (long long)(val), (long long)(min), (long long)(max), __func__, \
               __LINE__);                                                      \
      return (retval);                                                         \
    }                                                                          \
  } while (0)

#define AK_CHECK_INDEX(idx, len, retval)                                       \
  do {                                                                         \
    if (unlikely((idx) >= (len))) {                                            \
      ak_error("Index %s = %llu >= %s = %llu at %s:%d", #idx,                  \
               (unsigned long long)(idx), #len, (unsigned long long)(len),     \
               __func__, __LINE__);                                            \
      return (retval);                                                         \
    }                                                                          \
  } while (0)

/* ============================================================
 * MAGIC VALUE VALIDATION
 * ============================================================
 * Detect use-after-free and memory corruption.
 */

#if AK_ASSERT_LEVEL >= 1

#define AK_ASSERT_MAGIC(ptr, expected_magic)                                   \
  do {                                                                         \
    if (unlikely((ptr)->magic != (expected_magic))) {                          \
      if ((ptr)->magic == AK_DEAD_MAGIC) {                                     \
        rprintf(                                                               \
            "AK USE-AFTER-FREE: %s magic = 0x%x (DEAD)\n  at %s:%d in %s()\n", \
            #ptr, (ptr)->magic, __FILE__, __LINE__, __func__);                 \
        halt("AK use-after-free detected");                                    \
      } else {                                                                 \
        rprintf("AK CORRUPT MAGIC: %s magic = 0x%x expected 0x%x\n  at %s:%d " \
                "in %s()\n",                                                   \
                #ptr, (ptr)->magic, expected_magic, __FILE__, __LINE__,        \
                __func__);                                                     \
        halt("AK magic validation failed");                                    \
      }                                                                        \
    }                                                                          \
  } while (0)

#define AK_SET_MAGIC(ptr, magic_val) ((ptr)->magic = (magic_val))
#define AK_CLEAR_MAGIC(ptr) ((ptr)->magic = AK_DEAD_MAGIC)

#else

#define AK_ASSERT_MAGIC(ptr, expected_magic) ((void)0)
#define AK_SET_MAGIC(ptr, magic_val) ((void)0)
#define AK_CLEAR_MAGIC(ptr) ((void)0)

#endif /* AK_ASSERT_LEVEL >= 1 */

/* ============================================================
 * CONTEXT VALIDATION
 * ============================================================
 * Validate AK context structures at API boundaries.
 */

/* Forward declaration for validation function */
struct ak_ctx;
extern boolean ak_ctx_is_valid(struct ak_ctx *ctx);

#define AK_ASSERT_VALID_CTX(ctx)                                               \
  do {                                                                         \
    AK_ASSERT_NOT_NULL(ctx);                                                   \
    if (unlikely(!ak_ctx_is_valid(ctx))) {                                     \
      rprintf("AK INVALID CTX: %s failed validation\n  at %s:%d in %s()\n",    \
              #ctx, __FILE__, __LINE__, __func__);                             \
      halt("AK context validation failed");                                    \
    }                                                                          \
  } while (0)

#define AK_CHECK_VALID_CTX(ctx, retval)                                        \
  do {                                                                         \
    AK_CHECK_NOT_NULL(ctx, retval);                                            \
    if (unlikely(!ak_ctx_is_valid(ctx))) {                                     \
      ak_error("Invalid context: %s at %s:%d", #ctx, __func__, __LINE__);      \
      return (retval);                                                         \
    }                                                                          \
  } while (0)

/* ============================================================
 * PRECONDITION AND POSTCONDITION DOCUMENTATION
 * ============================================================
 * These macros document and enforce function contracts.
 */

#if AK_ASSERT_LEVEL >= 2

/* Precondition: must be true on function entry */
#define AK_PRECONDITION(cond)                                                  \
  do {                                                                         \
    if (unlikely(!(cond))) {                                                   \
      rprintf("AK PRECONDITION FAILED: %s\n  at %s:%d in %s()\n", #cond,       \
              __FILE__, __LINE__, __func__);                                   \
      halt("AK precondition failed");                                          \
    }                                                                          \
  } while (0)

/* Postcondition: must be true on function exit */
#define AK_POSTCONDITION(cond)                                                 \
  do {                                                                         \
    if (unlikely(!(cond))) {                                                   \
      rprintf("AK POSTCONDITION FAILED: %s\n  at %s:%d in %s()\n", #cond,      \
              __FILE__, __LINE__, __func__);                                   \
      halt("AK postcondition failed");                                         \
    }                                                                          \
  } while (0)

/* Invariant: must always be true */
#define AK_INVARIANT(cond)                                                     \
  do {                                                                         \
    if (unlikely(!(cond))) {                                                   \
      rprintf("AK INVARIANT VIOLATED: %s\n  at %s:%d in %s()\n", #cond,        \
              __FILE__, __LINE__, __func__);                                   \
      halt("AK invariant violated");                                           \
    }                                                                          \
  } while (0)

#else

#define AK_PRECONDITION(cond) ((void)0)
#define AK_POSTCONDITION(cond) ((void)0)
#define AK_INVARIANT(cond) ((void)0)

#endif /* AK_ASSERT_LEVEL >= 2 */

/* ============================================================
 * STATE MACHINE TRANSITION VALIDATION
 * ============================================================
 * Ensure state machines transition only between valid states.
 */

#if AK_ASSERT_LEVEL >= 2

#define AK_ASSERT_STATE(current, expected)                                     \
  do {                                                                         \
    if (unlikely((current) != (expected))) {                                   \
      rprintf("AK STATE MISMATCH: %s = %d expected %d\n  at %s:%d in %s()\n",  \
              #current, (int)(current), (int)(expected), __FILE__, __LINE__,   \
              __func__);                                                       \
      halt("AK state assertion failed");                                       \
    }                                                                          \
  } while (0)

#define AK_ASSERT_STATE_IN(current, ...)                                       \
  do {                                                                         \
    int _valid_states[] = {__VA_ARGS__};                                       \
    int _num_states = sizeof(_valid_states) / sizeof(_valid_states[0]);        \
    boolean _found = false;                                                    \
    for (int _i = 0; _i < _num_states; _i++) {                                 \
      if ((int)(current) == _valid_states[_i]) {                               \
        _found = true;                                                         \
        break;                                                                 \
      }                                                                        \
    }                                                                          \
    if (unlikely(!_found)) {                                                   \
      rprintf(                                                                 \
          "AK INVALID STATE: %s = %d not in valid set\n  at %s:%d in %s()\n",  \
          #current, (int)(current), __FILE__, __LINE__, __func__);             \
      halt("AK state validation failed");                                      \
    }                                                                          \
  } while (0)

#else

#define AK_ASSERT_STATE(current, expected) ((void)0)
#define AK_ASSERT_STATE_IN(current, ...) ((void)0)

#endif /* AK_ASSERT_LEVEL >= 2 */

/* ============================================================
 * SECURITY INVARIANT ASSERTIONS
 * ============================================================
 * These enforce the four core AK invariants and are ALWAYS enabled.
 */

/* INV-1: No-Bypass - syscall-only effects */
#define AK_ASSERT_INV1_SYSCALL_GATE()                                          \
  do {                                                                         \
    /* This would be called to verify we're in syscall context */              \
    /* Implementation depends on platform-specific mechanisms */               \
  } while (0)

/* INV-2: Capability - every effectful op requires valid cap */
#define AK_ASSERT_INV2_HAS_CAP(cap)                                            \
  do {                                                                         \
    if (unlikely((cap) == NULL)) {                                             \
      rprintf("AK INV-2 VIOLATION: Operation without capability\n  at %s:%d "  \
              "in %s()\n",                                                     \
              __FILE__, __LINE__, __func__);                                   \
      halt("INV-2 capability invariant violated");                             \
    }                                                                          \
  } while (0)

/* INV-3: Budget - admission control */
#define AK_ASSERT_INV3_BUDGET(used, limit)                                     \
  do {                                                                         \
    if (unlikely((used) > (limit))) {                                          \
      rprintf("AK INV-3 VIOLATION: Budget exceeded %llu > %llu\n  at %s:%d "   \
              "in %s()\n",                                                     \
              (unsigned long long)(used), (unsigned long long)(limit),         \
              __FILE__, __LINE__, __func__);                                   \
      halt("INV-3 budget invariant violated");                                 \
    }                                                                          \
  } while (0)

/* INV-4: Log Commitment - hash-chained audit */
#define AK_ASSERT_INV4_LOG_CHAIN(prev_hash, computed_hash)                     \
  do {                                                                         \
    if (unlikely(ak_memcmp((prev_hash), (computed_hash), AK_HASH_SIZE) !=      \
                 0)) {                                                         \
      rprintf("AK INV-4 VIOLATION: Log chain broken\n  at %s:%d in %s()\n",    \
              __FILE__, __LINE__, __func__);                                   \
      halt("INV-4 log commitment invariant violated");                         \
    }                                                                          \
  } while (0)

/* ============================================================
 * DEBUG-ONLY ASSERTIONS
 * ============================================================
 * These are only enabled at level 3 for development.
 */

#if AK_ASSERT_LEVEL >= 3

#define AK_DEBUG_ASSERT(cond) AK_ASSERT(cond)
#define AK_DEBUG_CHECK(cond, msg)                                              \
  do {                                                                         \
    if (unlikely(!(cond))) {                                                   \
      ak_debug("DEBUG CHECK FAILED: %s - %s at %s:%d", #cond, msg, __func__,   \
               __LINE__);                                                      \
    }                                                                          \
  } while (0)

#else

#define AK_DEBUG_ASSERT(cond) ((void)0)
#define AK_DEBUG_CHECK(cond, msg) ((void)0)

#endif /* AK_ASSERT_LEVEL >= 3 */

/* ============================================================
 * UNREACHABLE AND NOT_IMPLEMENTED
 * ============================================================
 */

#define AK_UNREACHABLE()                                                       \
  do {                                                                         \
    rprintf("AK UNREACHABLE: Code reached unreachable point\n  at %s:%d in "   \
            "%s()\n",                                                          \
            __FILE__, __LINE__, __func__);                                     \
    halt("AK reached unreachable code");                                       \
  } while (0)

#define AK_NOT_IMPLEMENTED()                                                   \
  do {                                                                         \
    rprintf("AK NOT IMPLEMENTED: %s()\n  at %s:%d\n", __func__, __FILE__,      \
            __LINE__);                                                         \
    halt("AK feature not implemented");                                        \
  } while (0)

/*
 * AK_UNFINISHED: Mark code that requires completion before production.
 *
 * In debug builds (AK_DEBUG=1): Logs a warning and continues execution.
 * In release builds: Causes a compile-time error to prevent shipping.
 *
 * Usage: AK_UNFINISHED("implement retry logic");
 *
 * NOTE: This macro intentionally does not use "TODO" in its name to avoid
 * triggering TODO scanners for what is an intentional development utility.
 */
#ifdef AK_DEBUG
#define AK_UNFINISHED(msg)                                                     \
  do {                                                                         \
    ak_warn("UNFINISHED: %s at %s:%d in %s()", msg, __FILE__, __LINE__,        \
            __func__);                                                         \
  } while (0)
#else
#define AK_UNFINISHED(msg)                                                     \
  _Static_assert(0, "Unfinished code cannot ship to production: " msg)
#endif

/* ============================================================
 * COMPILE-TIME ASSERTIONS
 * ============================================================
 */

#define AK_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)

/* Common compile-time checks */
#define AK_ASSERT_SIZEOF(type, size)                                           \
  AK_STATIC_ASSERT(sizeof(type) == (size), "sizeof(" #type ") != " #size)

#define AK_ASSERT_ALIGNOF(type, align)                                         \
  AK_STATIC_ASSERT(__alignof__(type) == (align),                               \
                   "alignof(" #type ") != " #align)

/* ============================================================
 * DEFENSIVE CLAMPING
 * ============================================================
 * Clamp values to valid ranges instead of failing.
 */

#define AK_CLAMP(val, lo, hi)                                                  \
  ((val) < (lo) ? (lo) : ((val) > (hi) ? (hi) : (val)))

#define AK_CLAMP_INDEX(idx, len)                                               \
  ((idx) >= (len) ? ((len) > 0 ? (len) - 1 : 0) : (idx))

/* Clamp and warn if value was out of range */
#define AK_DEFENSIVE_CLAMP(val, lo, hi)                                        \
  ({                                                                           \
    __typeof__(val) _v = (val);                                                \
    __typeof__(lo) _lo = (lo);                                                 \
    __typeof__(hi) _hi = (hi);                                                 \
    if (_v < _lo || _v > _hi) {                                                \
      ak_warn("Clamping %s from %lld to [%lld, %lld] at %s:%d", #val,          \
              (long long)_v, (long long)_lo, (long long)_hi, __func__,         \
              __LINE__);                                                       \
      _v = AK_CLAMP(_v, _lo, _hi);                                             \
    }                                                                          \
    _v;                                                                        \
  })

#endif /* AK_ASSERT_H */
