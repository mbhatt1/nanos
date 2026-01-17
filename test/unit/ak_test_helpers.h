/*
 * Authority Kernel - Test Helper Macros and Utilities
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Comprehensive test helper macros for AK unit and integration tests.
 * These helpers provide consistent assertion patterns, memory testing,
 * and error validation utilities.
 */

#ifndef AK_TEST_HELPERS_H
#define AK_TEST_HELPERS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>

/* ============================================================
 * EXIT CODES
 * ============================================================ */

#ifndef EXIT_SUCCESS
#define EXIT_SUCCESS 0
#endif
#ifndef EXIT_FAILURE
#define EXIT_FAILURE 1
#endif

/* ============================================================
 * BASIC ASSERTION MACROS
 * ============================================================ */

/*
 * Basic assertion with file/line information.
 * Returns false from test function on failure.
 */
#define TEST_ASSERT(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "FAIL: %s at %s:%d\n", #expr, __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

/*
 * Assertion with custom message.
 */
#define TEST_ASSERT_MSG(expr, msg) do { \
    if (!(expr)) { \
        fprintf(stderr, "FAIL: %s - %s at %s:%d\n", msg, #expr, __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

/*
 * Assert two values are equal.
 */
#define TEST_ASSERT_EQ(a, b) do { \
    long _a = (long)(a); \
    long _b = (long)(b); \
    if (_a != _b) { \
        fprintf(stderr, "FAIL: %s != %s (%ld != %ld) at %s:%d\n", \
                #a, #b, _a, _b, __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

/*
 * Assert two values are not equal.
 */
#define TEST_ASSERT_NE(a, b) do { \
    long _a = (long)(a); \
    long _b = (long)(b); \
    if (_a == _b) { \
        fprintf(stderr, "FAIL: %s == %s (both %ld) at %s:%d\n", \
                #a, #b, _a, __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

/*
 * Assert string equality.
 */
#define TEST_ASSERT_STREQ(a, b) do { \
    const char *_a = (a); \
    const char *_b = (b); \
    if (_a == NULL || _b == NULL || strcmp(_a, _b) != 0) { \
        fprintf(stderr, "FAIL: %s != %s (\"%s\" != \"%s\") at %s:%d\n", \
                #a, #b, _a ? _a : "(null)", _b ? _b : "(null)", \
                __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

/*
 * Assert string inequality.
 */
#define TEST_ASSERT_STRNE(a, b) do { \
    const char *_a = (a); \
    const char *_b = (b); \
    if (_a != NULL && _b != NULL && strcmp(_a, _b) == 0) { \
        fprintf(stderr, "FAIL: %s == %s (both \"%s\") at %s:%d\n", \
                #a, #b, _a, __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

/*
 * Assert string contains substring.
 */
#define TEST_ASSERT_STRSTR(haystack, needle) do { \
    const char *_h = (haystack); \
    const char *_n = (needle); \
    if (_h == NULL || _n == NULL || strstr(_h, _n) == NULL) { \
        fprintf(stderr, "FAIL: \"%s\" not in \"%s\" at %s:%d\n", \
                _n ? _n : "(null)", _h ? _h : "(null)", \
                __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

/* ============================================================
 * NULL POINTER ASSERTIONS
 * ============================================================ */

/*
 * Assert pointer is NULL.
 */
#define TEST_EXPECT_NULL(ptr) do { \
    const void *_ptr = (ptr); \
    if (_ptr != NULL) { \
        fprintf(stderr, "FAIL: %s expected NULL but got %p at %s:%d\n", \
                #ptr, _ptr, __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

/*
 * Assert pointer is not NULL.
 */
#define TEST_EXPECT_NOT_NULL(ptr) do { \
    const void *_ptr = (ptr); \
    if (_ptr == NULL) { \
        fprintf(stderr, "FAIL: %s expected non-NULL at %s:%d\n", \
                #ptr, __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

/* ============================================================
 * ERROR CODE ASSERTIONS
 * ============================================================ */

/*
 * Assert expression returns expected error code.
 */
#define TEST_EXPECT_ERROR(expr, expected_err) do { \
    long _result = (long)(expr); \
    long _expected = (long)(expected_err); \
    if (_result != _expected) { \
        fprintf(stderr, "FAIL: %s returned %ld, expected %ld at %s:%d\n", \
                #expr, _result, _expected, __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

/*
 * Assert expression returns success (0 or positive).
 */
#define TEST_EXPECT_SUCCESS(expr) do { \
    long _result = (long)(expr); \
    if (_result < 0) { \
        fprintf(stderr, "FAIL: %s returned error %ld at %s:%d\n", \
                #expr, _result, __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

/*
 * Assert expression returns failure (negative).
 */
#define TEST_EXPECT_FAILURE(expr) do { \
    long _result = (long)(expr); \
    if (_result >= 0) { \
        fprintf(stderr, "FAIL: %s expected failure but got %ld at %s:%d\n", \
                #expr, _result, __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

/*
 * Assert errno is set to expected value.
 */
#define TEST_EXPECT_ERRNO(expected_errno) do { \
    int _expected = (expected_errno); \
    if (errno != _expected) { \
        fprintf(stderr, "FAIL: errno expected %d (%s) but got %d (%s) at %s:%d\n", \
                _expected, strerror(_expected), errno, strerror(errno), \
                __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

/* ============================================================
 * BOUNDARY AND RANGE ASSERTIONS
 * ============================================================ */

/*
 * Assert value is within range [min, max] inclusive.
 */
#define TEST_ASSERT_IN_RANGE(val, min_val, max_val) do { \
    long _v = (long)(val); \
    long _min = (long)(min_val); \
    long _max = (long)(max_val); \
    if (_v < _min || _v > _max) { \
        fprintf(stderr, "FAIL: %s=%ld not in [%ld, %ld] at %s:%d\n", \
                #val, _v, _min, _max, __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

/*
 * Assert value is less than threshold.
 */
#define TEST_ASSERT_LT(val, threshold) do { \
    long _v = (long)(val); \
    long _t = (long)(threshold); \
    if (_v >= _t) { \
        fprintf(stderr, "FAIL: %s=%ld not < %ld at %s:%d\n", \
                #val, _v, _t, __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

/*
 * Assert value is greater than threshold.
 */
#define TEST_ASSERT_GT(val, threshold) do { \
    long _v = (long)(val); \
    long _t = (long)(threshold); \
    if (_v <= _t) { \
        fprintf(stderr, "FAIL: %s=%ld not > %ld at %s:%d\n", \
                #val, _v, _t, __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

/*
 * Assert value is less than or equal to threshold.
 */
#define TEST_ASSERT_LE(val, threshold) do { \
    long _v = (long)(val); \
    long _t = (long)(threshold); \
    if (_v > _t) { \
        fprintf(stderr, "FAIL: %s=%ld not <= %ld at %s:%d\n", \
                #val, _v, _t, __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

/*
 * Assert value is greater than or equal to threshold.
 */
#define TEST_ASSERT_GE(val, threshold) do { \
    long _v = (long)(val); \
    long _t = (long)(threshold); \
    if (_v < _t) { \
        fprintf(stderr, "FAIL: %s=%ld not >= %ld at %s:%d\n", \
                #val, _v, _t, __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

/* ============================================================
 * MEMORY TESTING UTILITIES
 * ============================================================ */

/*
 * Fill buffer with pattern for boundary testing.
 */
static inline void test_fill_buffer(void *buf, size_t size, uint8_t pattern)
{
    memset(buf, pattern, size);
}

/*
 * Check that buffer contains expected pattern.
 */
#define TEST_MEMORY_PATTERN(buf, size, pattern) do { \
    const uint8_t *_buf = (const uint8_t *)(buf); \
    size_t _size = (size); \
    uint8_t _pattern = (pattern); \
    for (size_t _i = 0; _i < _size; _i++) { \
        if (_buf[_i] != _pattern) { \
            fprintf(stderr, "FAIL: memory pattern mismatch at offset %zu: " \
                    "expected 0x%02x, got 0x%02x at %s:%d\n", \
                    _i, _pattern, _buf[_i], __FILE__, __LINE__); \
            return false; \
        } \
    } \
} while (0)

/*
 * Test memory boundary by checking guard bytes.
 * buf should have guard_size bytes before and after the usable area.
 */
#define TEST_MEMORY_BOUNDARY(buf, usable_size, guard_size, guard_pattern) do { \
    const uint8_t *_base = (const uint8_t *)(buf); \
    size_t _usable = (usable_size); \
    size_t _guard = (guard_size); \
    uint8_t _pattern = (guard_pattern); \
    /* Check leading guard */ \
    for (size_t _i = 0; _i < _guard; _i++) { \
        if (_base[_i] != _pattern) { \
            fprintf(stderr, "FAIL: leading guard corrupted at offset %zu at %s:%d\n", \
                    _i, __FILE__, __LINE__); \
            return false; \
        } \
    } \
    /* Check trailing guard */ \
    for (size_t _i = 0; _i < _guard; _i++) { \
        if (_base[_guard + _usable + _i] != _pattern) { \
            fprintf(stderr, "FAIL: trailing guard corrupted at offset %zu at %s:%d\n", \
                    _i, __FILE__, __LINE__); \
            return false; \
        } \
    } \
} while (0)

/*
 * Allocate buffer with guard zones for boundary testing.
 * Returns pointer to usable area (not the base allocation).
 */
static inline void *test_alloc_guarded(size_t size, size_t guard_size, uint8_t guard_pattern)
{
    size_t total = guard_size + size + guard_size;
    uint8_t *base = (uint8_t *)malloc(total);
    if (!base)
        return NULL;
    memset(base, guard_pattern, total);
    return base + guard_size;
}

/*
 * Free guarded buffer (pass the usable pointer, not base).
 */
static inline void test_free_guarded(void *usable_ptr, size_t guard_size)
{
    if (usable_ptr) {
        uint8_t *base = (uint8_t *)usable_ptr - guard_size;
        free(base);
    }
}

/* ============================================================
 * STRING TEST UTILITIES
 * ============================================================ */

/*
 * Create string of specified length filled with character.
 * Caller must free the result.
 */
static inline char *test_make_string(size_t length, char fill)
{
    char *str = (char *)malloc(length + 1);
    if (str) {
        memset(str, fill, length);
        str[length] = '\0';
    }
    return str;
}

/*
 * Create maximum length string for boundary testing.
 */
#define TEST_MAX_STRING_LEN 65536

static inline char *test_make_max_string(void)
{
    return test_make_string(TEST_MAX_STRING_LEN, 'X');
}

/* ============================================================
 * TEST RUNNER UTILITIES
 * ============================================================ */

/*
 * Boolean test function type.
 */
typedef bool (*test_func_t)(void);

/*
 * Test case structure.
 */
typedef struct test_case {
    const char *name;
    test_func_t func;
} test_case_t;

/*
 * Run all tests and report results.
 */
static inline int test_run_all(test_case_t *tests, const char *suite_name)
{
    int passed = 0;
    int failed = 0;

    printf("=== %s ===\n\n", suite_name);

    for (int i = 0; tests[i].name != NULL; i++) {
        printf("Running %s... ", tests[i].name);
        fflush(stdout);

        if (tests[i].func()) {
            printf("PASS\n");
            passed++;
        } else {
            printf("FAIL\n");
            failed++;
        }
    }

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);

    return (failed > 0) ? EXIT_FAILURE : EXIT_SUCCESS;
}

/*
 * Run tests matching a filter pattern.
 */
static inline int test_run_filtered(test_case_t *tests, const char *suite_name, const char *filter)
{
    int passed = 0;
    int failed = 0;
    int skipped = 0;

    printf("=== %s (filter: %s) ===\n\n", suite_name, filter);

    for (int i = 0; tests[i].name != NULL; i++) {
        if (filter && strstr(tests[i].name, filter) == NULL) {
            skipped++;
            continue;
        }

        printf("Running %s... ", tests[i].name);
        fflush(stdout);

        if (tests[i].func()) {
            printf("PASS\n");
            passed++;
        } else {
            printf("FAIL\n");
            failed++;
        }
    }

    printf("\n=== Results: %d passed, %d failed, %d skipped ===\n",
           passed, failed, skipped);

    return (failed > 0) ? EXIT_FAILURE : EXIT_SUCCESS;
}

/* ============================================================
 * TIMING UTILITIES
 * ============================================================ */

#ifdef __APPLE__
#include <mach/mach_time.h>
static inline uint64_t test_get_time_ns(void)
{
    static mach_timebase_info_data_t info = {0, 0};
    if (info.denom == 0) {
        mach_timebase_info(&info);
    }
    return mach_absolute_time() * info.numer / info.denom;
}
#else
#include <time.h>
static inline uint64_t test_get_time_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}
#endif

/*
 * Simple timing wrapper.
 */
#define TEST_TIME_START() uint64_t _test_start_ns = test_get_time_ns()
#define TEST_TIME_END() (test_get_time_ns() - _test_start_ns)

/*
 * Assert operation completes within time limit.
 */
#define TEST_ASSERT_FAST(expr, max_ns) do { \
    TEST_TIME_START(); \
    (void)(expr); \
    uint64_t _elapsed = TEST_TIME_END(); \
    if (_elapsed > (max_ns)) { \
        fprintf(stderr, "FAIL: %s took %llu ns, limit %llu ns at %s:%d\n", \
                #expr, (unsigned long long)_elapsed, \
                (unsigned long long)(max_ns), __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

/* ============================================================
 * DEBUG UTILITIES
 * ============================================================ */

/*
 * Print hex dump of memory for debugging.
 */
static inline void test_hexdump(const void *ptr, size_t size, const char *label)
{
    const uint8_t *buf = (const uint8_t *)ptr;
    fprintf(stderr, "=== %s (%zu bytes) ===\n", label, size);
    for (size_t i = 0; i < size; i++) {
        if (i > 0 && i % 16 == 0)
            fprintf(stderr, "\n");
        fprintf(stderr, "%02x ", buf[i]);
    }
    fprintf(stderr, "\n");
}

/*
 * Skip test with message (for conditional tests).
 */
#define TEST_SKIP(reason) do { \
    fprintf(stderr, "SKIP: %s\n", reason); \
    return true; \
} while (0)

#endif /* AK_TEST_HELPERS_H */
