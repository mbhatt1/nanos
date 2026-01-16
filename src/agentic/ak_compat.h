/*
 * Authority Kernel - Nanos Compatibility Layer
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Provides compatibility wrappers between AK code and Nanos runtime.
 * This header is self-contained and can be included by all ak_*.c files.
 */

#ifndef AK_COMPAT_H
#define AK_COMPAT_H

/* Include ak_types.h for AK-specific types - but guard against circular includes */
#ifndef AK_TYPES_H
/* ak_types.h will include this file, so we need forward declarations here */
#include <runtime.h>
#endif

/* ============================================================
 * TIME COMPATIBILITY
 * ============================================================ */

/* Clock ID for monotonic time - define if not already available */
#ifndef CLOCK_ID_MONOTONIC
#define CLOCK_ID_MONOTONIC      1
#endif

/* Convenience macro for getting current monotonic time in milliseconds */
#ifndef ak_now_ms
#define ak_now_ms()             msec_from_timestamp(now(CLOCK_ID_MONOTONIC))
#endif

/* Get current timestamp (fixed-point format) */
#ifndef ak_now
#define ak_now()                now(CLOCK_ID_MONOTONIC)
#endif

/* ============================================================
 * NUMERIC CONSTANTS
 * ============================================================ */

#ifndef MILLION
#define MILLION                 (1000000ull)
#endif

#ifndef BILLION
#define BILLION                 (1000000000ull)
#endif

#ifndef THOUSAND
#define THOUSAND                (1000ull)
#endif

/* ============================================================
 * ADDRESS VALIDATION
 * ============================================================ */

/* Check for invalid address */
#ifndef ak_is_invalid_address
#define ak_is_invalid_address(p) ((p) == INVALID_ADDRESS || (p) == NULL)
#endif

/* Check for valid address */
#ifndef ak_is_valid_address
#define ak_is_valid_address(p)   ((p) != INVALID_ADDRESS && (p) != NULL)
#endif

/* ============================================================
 * STRING COMPATIBILITY
 * ============================================================
 * AK uses const char * strings, Nanos uses sstring.
 */

static inline u64 runtime_strlen(const char *s)
{
    if (!s) return 0;
    u64 len = 0;
    while (s[len]) len++;
    return len;
}

static inline int runtime_strncmp(const char *s1, const char *s2, u64 n)
{
    if (!s1 || !s2) return s1 ? 1 : (s2 ? -1 : 0);
    for (u64 i = 0; i < n; i++) {
        if (s1[i] != s2[i])
            return (unsigned char)s1[i] - (unsigned char)s2[i];
        if (s1[i] == '\0')
            return 0;
    }
    return 0;
}

/* Override runtime_strcmp to work with const char * */
#undef runtime_strcmp
static inline int runtime_strcmp(const char *s1, const char *s2)
{
    if (!s1 || !s2) return s1 ? 1 : (s2 ? -1 : 0);
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return (unsigned char)*s1 - (unsigned char)*s2;
}

/* String copy with length limit */
static inline char *runtime_strncpy(char *dest, const char *src, u64 n)
{
    if (!dest) return NULL;
    if (!src) {
        if (n > 0) dest[0] = '\0';
        return dest;
    }
    u64 i;
    for (i = 0; i < n && src[i] != '\0'; i++) {
        dest[i] = src[i];
    }
    for (; i < n; i++) {
        dest[i] = '\0';
    }
    return dest;
}

/* ============================================================
 * BUFFER OPERATIONS
 * ============================================================ */

/* buffer_write_cstring is already defined in buffer.h as a macro */
/* #define buffer_write_cstring(b, x)  buffer_write_sstring(b, ss(x)) */

/* byte() macro - already defined in buffer.h */
/* #define byte(__b, __i) *(u8 *)((__b)->contents + (__b)->start + (__i)) */

/* push_u8() - already defined in buffer.h as static inline function */

/* Set buffer end position explicitly */
#ifndef buffer_set_end
static inline void buffer_set_end(buffer b, bytes end)
{
    assert(end <= b->length);
    b->end = end;
}
#endif

/* deallocate_buffer is already defined in buffer.h */

/* ============================================================
 * TABLE (HASH MAP) OPERATIONS
 * ============================================================ */

/* Table allocation - already provided by table.h:
 * table allocate_table(heap h, key (*key_function)(void *x),
 *                      boolean (*equal_function)(void *x, void *y));
 * void table_set(table t, void *c, void *v);
 * void *table_find(table t, void *c);
 * table_foreach macro
 */

/* Key functions for tables - provided by table.h:
 * boolean pointer_equal(void *a, void* b);
 * key identity_key(void *a);
 */

/* Key from pointer - treats pointer address as key */
#ifndef key_from_pointer
static inline key key_from_pointer(void *p)
{
    return (key)u64_from_pointer(p);
}
#endif

/* ============================================================
 * CLOSURE AND CALLBACK OPERATIONS
 * ============================================================ */

/* Closure and apply are defined in closure.h:
 * #define apply(__c, ...) (*(__c))((void *)(__c), ## __VA_ARGS__)
 * closure_type, closure, closure_func, etc.
 */

/* Status handler type - defined in status.h via runtime.h */
/* closure_type(status_handler, void, status s); */

/* Thunk type - simple callback with no args, defined in runtime.h */
/* closure_type(thunk, void); */

/* ============================================================
 * HEAP COMPATIBILITY
 * ============================================================ */

/* Nanos already provides these, but ensure they're available */
#ifndef allocate_zero
static inline void *allocate_zero(heap h, bytes len)
{
    void *p = allocate(h, len);
    if (p && p != INVALID_ADDRESS)
        runtime_memset(p, 0, len);
    return p;
}
#endif

/* Typed allocation helper */
#define ak_alloc(h, type)       ((type *)allocate(h, sizeof(type)))
#define ak_alloc_zero(h, type)  ((type *)allocate_zero(h, sizeof(type)))

/* Array allocation helper */
#define ak_alloc_array(h, type, n)      ((type *)allocate(h, sizeof(type) * (n)))
#define ak_alloc_array_zero(h, type, n) ((type *)allocate_zero(h, sizeof(type) * (n)))

/* ============================================================
 * ERROR CODE COMPATIBILITY
 * ============================================================
 * Standard errno values for kernel use.
 */

#ifndef EINVAL
#define EINVAL      22
#endif

#ifndef ENOENT
#define ENOENT      2
#endif

#ifndef ENOMEM
#define ENOMEM      12
#endif

#ifndef EPERM
#define EPERM       1
#endif

#ifndef EFAULT
#define EFAULT      14
#endif

#ifndef ENOSYS
#define ENOSYS      38
#endif

#ifndef EBUSY
#define EBUSY       16
#endif

#ifndef EAGAIN
#define EAGAIN      11
#endif

#ifndef ETIMEDOUT
#define ETIMEDOUT   110
#endif

#ifndef EEXIST
#define EEXIST      17
#endif

#ifndef ERANGE
#define ERANGE      34
#endif

#ifndef EACCES
#define EACCES      13
#endif

/* ============================================================
 * TYPE COMPATIBILITY
 * ============================================================ */

/* Ensure s64 is available (signed 64-bit) */
#ifndef s64
typedef signed long long s64;
#endif

/* Ensure sysreturn is available */
#ifndef sysreturn
typedef s64 sysreturn;
#endif

/* ============================================================
 * MEMORY OPERATIONS
 * ============================================================
 * These are defined in runtime.h but we re-export for clarity:
 * void runtime_memcpy(void *a, const void *b, bytes len);
 * void runtime_memset(u8 *a, u8 b, bytes len);
 * int runtime_memcmp(const void *a, const void *b, bytes len);
 */

/* Convenience wrappers with void* for memset */
#ifndef ak_memset
static inline void ak_memset(void *dest, u8 val, bytes len)
{
    runtime_memset((u8 *)dest, val, len);
}
#endif

#ifndef ak_memzero
static inline void ak_memzero(void *dest, bytes len)
{
    runtime_memset((u8 *)dest, 0, len);
}
#endif

#ifndef ak_memcpy
#define ak_memcpy(d, s, n)      runtime_memcpy((d), (s), (n))
#endif

#ifndef ak_memcmp
#define ak_memcmp(a, b, n)      runtime_memcmp((a), (b), (n))
#endif

/* ============================================================
 * BUFFER CONVENIENCE MACROS
 * ============================================================ */

/* Create a buffer from a string literal on the stack */
#ifndef ak_buffer_from_literal
#define ak_buffer_from_literal(s) alloca_wrap_cstring(s)
#endif

/* Wrap existing memory as a buffer (read-only) */
#ifndef ak_wrap_buffer
#define ak_wrap_buffer(ptr, len) alloca_wrap_buffer((ptr), (len))
#endif

/* Check if buffer is valid and non-empty */
#ifndef ak_buffer_valid
static inline boolean ak_buffer_valid(buffer b)
{
    return b && b != INVALID_ADDRESS && buffer_length(b) > 0;
}
#endif

/* Safe buffer byte access with bounds checking */
#ifndef ak_buffer_byte
static inline int ak_buffer_byte(buffer b, bytes i)
{
    if (!b || i >= buffer_length(b))
        return -1;
    return byte(b, i);
}
#endif

/* ============================================================
 * DEBUG HELPERS
 * ============================================================ */

#if AK_DEBUG
#define ak_debug(fmt, ...)      rprintf("[AK DEBUG] " fmt "\n", ##__VA_ARGS__)
#define ak_trace(fmt, ...)      rprintf("[AK TRACE %s:%d] " fmt "\n", \
                                        __func__, __LINE__, ##__VA_ARGS__)
#else
#define ak_debug(fmt, ...)      ((void)0)
#define ak_trace(fmt, ...)      ((void)0)
#endif

#define ak_warn(fmt, ...)       rprintf("[AK WARN] " fmt "\n", ##__VA_ARGS__)
#define ak_error(fmt, ...)      rprintf("[AK ERROR] " fmt "\n", ##__VA_ARGS__)

/* ============================================================
 * ASSERTION HELPERS
 * ============================================================ */

/* AK-specific assertion with error code return */
#ifndef ak_assert
#define ak_assert(cond, err_code) do { \
    if (!(cond)) { \
        ak_error("assertion failed: %s at %s:%d", #cond, __func__, __LINE__); \
        return (err_code); \
    } \
} while(0)
#endif

/* AK assertion that returns NULL on failure */
#ifndef ak_assert_null
#define ak_assert_null(cond) do { \
    if (!(cond)) { \
        ak_error("assertion failed: %s at %s:%d", #cond, __func__, __LINE__); \
        return NULL; \
    } \
} while(0)
#endif

/* ============================================================
 * MIN/MAX (already defined in runtime.h but ensure available)
 * ============================================================ */

#ifndef MIN
#define MIN(x, y) __compare((x), (y), <)
#endif

#ifndef MAX
#define MAX(x, y) __compare((x), (y), >)
#endif

#ifndef CLAMP
#define CLAMP(val, lo, hi)      MIN(MAX((val), (lo)), (hi))
#endif

/* ============================================================
 * BIT MANIPULATION
 * ============================================================ */

#ifndef BIT
#define BIT(n)                  (1ULL << (n))
#endif

#ifndef BITS_PER_BYTE
#define BITS_PER_BYTE           8
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr)         (sizeof(arr) / sizeof((arr)[0]))
#endif

/* ============================================================
 * CONTAINER_OF / STRUCT_FROM_FIELD
 * ============================================================
 * Get pointer to containing structure from member pointer.
 * Already defined in runtime.h as struct_from_field.
 */

#ifndef container_of
#define container_of(ptr, type, member) \
    struct_from_field(ptr, type *, member)
#endif

/* ============================================================
 * LIKELY/UNLIKELY BRANCH HINTS
 * ============================================================ */

#ifndef likely
#define likely(x)               __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x)             __builtin_expect(!!(x), 0)
#endif

#endif /* AK_COMPAT_H */
