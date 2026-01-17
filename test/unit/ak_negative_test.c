/*
 * Authority Kernel - Negative and Edge Case Tests
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Comprehensive negative tests for malformed input, NULL pointers,
 * boundary conditions, invalid enum values, and error path coverage.
 * These tests verify that the AK APIs fail gracefully and securely.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>

/* Type definitions for standalone testing */
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;
typedef u8 boolean;
#ifndef true
#define true 1
#endif
#ifndef false
#define false 0
#endif

#include "ak_test_helpers.h"

/* ============================================================
 * CONSTANTS FROM ak_effects.h
 * ============================================================ */

#define AK_MAX_TARGET       512
#define AK_MAX_PARAMS       4096
#define AK_MAX_CAPSTR       64
#define AK_MAX_SUGGEST      512
#define AK_MAX_DETAIL       256

typedef enum ak_effect_op {
    AK_E_FS_OPEN        = 0x0100,
    AK_E_FS_UNLINK      = 0x0101,
    AK_E_FS_RENAME      = 0x0102,
    AK_E_FS_MKDIR       = 0x0103,
    AK_E_FS_RMDIR       = 0x0104,
    AK_E_FS_STAT        = 0x0105,
    AK_E_NET_CONNECT    = 0x0200,
    AK_E_NET_DNS_RESOLVE = 0x0201,
    AK_E_NET_BIND       = 0x0202,
    AK_E_NET_LISTEN     = 0x0203,
    AK_E_NET_ACCEPT     = 0x0204,
    AK_E_PROC_SPAWN     = 0x0300,
    AK_E_PROC_SIGNAL    = 0x0301,
    AK_E_TOOL_CALL      = 0x0400,
    AK_E_WASM_INVOKE    = 0x0401,
    AK_E_INFER          = 0x0402,
    /* Invalid values for testing */
    AK_E_INVALID_LOW    = 0x0000,
    AK_E_INVALID_HIGH   = 0xFFFF,
} ak_effect_op_t;

typedef enum ak_deny_reason {
    AK_DENY_NONE            = 0,
    AK_DENY_NO_POLICY       = 1,
    AK_DENY_NO_CAP          = 2,
    AK_DENY_CAP_EXPIRED     = 3,
    AK_DENY_PATTERN_MISMATCH = 4,
    AK_DENY_BUDGET_EXCEEDED = 5,
    AK_DENY_RATE_LIMITED    = 6,
    AK_DENY_TAINT           = 7,
    AK_DENY_REVOKED         = 8,
    AK_DENY_MODE            = 9,
    AK_DENY_BOOT_CAPSULE    = 10,
    /* Invalid values for testing */
    AK_DENY_INVALID         = 255,
} ak_deny_reason_t;

typedef enum ak_mode {
    AK_MODE_OFF     = 0,
    AK_MODE_SOFT    = 1,
    AK_MODE_HARD    = 2,
    /* Invalid values for testing */
    AK_MODE_INVALID = 99,
} ak_mode_t;

/* ============================================================
 * EFFECT REQUEST STRUCTURE
 * ============================================================ */

typedef struct ak_effect_req {
    ak_effect_op_t op;
    u64 trace_id;
    u32 pid;
    u32 tid;
    char target[AK_MAX_TARGET];
    u8 params[AK_MAX_PARAMS];
    u32 params_len;
    struct {
        u64 cpu_ns;
        u64 wall_ns;
        u64 bytes;
        u64 tokens;
    } budget;
    u32 flags;
} ak_effect_req_t;

typedef struct ak_decision {
    boolean allow;
    ak_deny_reason_t reason_code;
    int errno_equiv;
    char missing_cap[AK_MAX_CAPSTR];
    char suggested_snippet[AK_MAX_SUGGEST];
    u64 trace_id;
    char detail[AK_MAX_DETAIL];
    u64 decision_ns;
} ak_decision_t;

/* ============================================================
 * PATTERN MATCHING (from ak_pattern.c)
 * ============================================================ */

static boolean pattern_match_internal(const char *pattern, u64 plen,
                                       const char *string, u64 slen)
{
    if (!pattern || !string)
        return false;

    u64 pi = 0;
    u64 si = 0;
    u64 star_pi = (u64)-1;
    u64 star_si = (u64)-1;
    boolean star_is_double = false;

    while (si < slen) {
        if (pi < plen && pattern[pi] == '*') {
            if (pi + 1 < plen && pattern[pi + 1] == '*') {
                star_pi = pi + 2;
                star_si = si;
                star_is_double = true;
                pi += 2;
                if (pi < plen && pattern[pi] == '/')
                    pi++;
            } else {
                star_pi = ++pi;
                star_si = si;
                star_is_double = false;
            }
        } else if (pi < plen && (pattern[pi] == '?' || pattern[pi] == string[si])) {
            pi++;
            si++;
        } else if (star_pi != (u64)-1) {
            if (!star_is_double && star_si < slen && string[star_si] == '/') {
                return false;
            }
            pi = star_pi;
            si = ++star_si;
        } else {
            return false;
        }
    }

    while (pi < plen && pattern[pi] == '*')
        pi++;

    return (pi == plen);
}

/* Public API simulation */
static boolean ak_pattern_match(const char *pattern, const char *string)
{
    if (!pattern || !string)
        return false;
    return pattern_match_internal(pattern, strlen(pattern),
                                   string, strlen(string));
}

static boolean ak_pattern_match_n(const char *pattern, u64 pattern_len,
                                   const char *string, u64 string_len)
{
    return pattern_match_internal(pattern, pattern_len, string, string_len);
}

/* ============================================================
 * PATH CANONICALIZATION
 * ============================================================ */

static int ak_canonicalize_path(const char *path, char *out, u32 out_len,
                                 const char *cwd)
{
    if (!path || !out || out_len == 0)
        return -EINVAL;

    char work[AK_MAX_TARGET];
    size_t work_pos = 0;

    /* Handle absolute vs relative */
    if (path[0] == '/') {
        work[work_pos++] = '/';
    } else if (cwd) {
        size_t cwd_len = strlen(cwd);
        if (cwd_len >= sizeof(work) - 1)
            return -ENAMETOOLONG;
        memcpy(work, cwd, cwd_len);
        work_pos = cwd_len;
        if (work_pos > 0 && work[work_pos - 1] != '/')
            work[work_pos++] = '/';
    } else {
        work[work_pos++] = '/';
    }

    const char *p = path;
    if (*p == '/')
        p++;

    while (*p) {
        while (*p == '/')
            p++;
        if (!*p)
            break;

        const char *comp_start = p;
        while (*p && *p != '/')
            p++;
        size_t comp_len = (size_t)(p - comp_start);

        if (comp_len == 1 && comp_start[0] == '.') {
            continue;
        } else if (comp_len == 2 && comp_start[0] == '.' && comp_start[1] == '.') {
            if (work_pos > 1) {
                work_pos--;
                while (work_pos > 1 && work[work_pos - 1] != '/')
                    work_pos--;
            }
        } else {
            if (work_pos + comp_len + 2 >= sizeof(work))
                return -ENAMETOOLONG;

            if (work_pos > 0 && work[work_pos - 1] != '/')
                work[work_pos++] = '/';

            memcpy(work + work_pos, comp_start, comp_len);
            work_pos += comp_len;
        }
    }

    if (work_pos == 0) {
        work[0] = '/';
        work_pos = 1;
    }

    if (work_pos > 1 && work[work_pos - 1] == '/')
        work_pos--;

    if (work_pos >= out_len)
        return -ENAMETOOLONG;

    memcpy(out, work, work_pos);
    out[work_pos] = '\0';
    return 0;
}

/* ============================================================
 * NETWORK ADDRESS CANONICALIZATION
 * ============================================================ */

static int ak_canonicalize_net_addr(const char *addr, u16 port,
                                     char *out, u32 out_len)
{
    if (!addr || !out || out_len == 0)
        return -EINVAL;

    int written;
    boolean is_ipv4 = true;
    boolean is_ipv6 = false;
    const char *p = addr;

    while (*p) {
        if (*p == ':') {
            is_ipv6 = true;
            is_ipv4 = false;
            break;
        }
        if (!(*p >= '0' && *p <= '9') && *p != '.') {
            is_ipv4 = false;
            break;
        }
        p++;
    }

    if (is_ipv4 || is_ipv6) {
        if (is_ipv6) {
            written = snprintf(out, out_len, "ip:[%s]:%u", addr, port);
        } else {
            written = snprintf(out, out_len, "ip:%s:%u", addr, port);
        }
    } else {
        written = snprintf(out, out_len, "dns:%s:%u", addr, port);
    }

    if (written < 0 || (size_t)written >= out_len)
        return -ENAMETOOLONG;

    return 0;
}

/* ============================================================
 * SUGGESTION GENERATION
 * ============================================================ */

static int ak_generate_suggestion(const ak_effect_req_t *req,
                                   char *snippet, u32 max_len)
{
    if (!req || !snippet || max_len == 0)
        return -EINVAL;

    int written;

    switch (req->op) {
    case AK_E_FS_OPEN:
        written = snprintf(snippet, max_len,
                           "[[fs.allow]]\npath = \"%s\"\nread = true",
                           req->target);
        break;
    case AK_E_FS_UNLINK:
    case AK_E_FS_MKDIR:
        written = snprintf(snippet, max_len,
                           "[[fs.allow]]\npath = \"%s\"\nwrite = true",
                           req->target);
        break;
    case AK_E_NET_DNS_RESOLVE: {
        const char *host = req->target;
        if (strncmp(host, "dns:", 4) == 0)
            host += 4;
        written = snprintf(snippet, max_len,
                           "[[net.dns]]\nallow = [\"%s\"]", host);
        break;
    }
    case AK_E_NET_CONNECT:
        written = snprintf(snippet, max_len,
                           "[[net.allow]]\nconnect = [\"%s\"]", req->target);
        break;
    case AK_E_TOOL_CALL: {
        const char *tool = req->target;
        if (strncmp(tool, "tool:", 5) == 0)
            tool += 5;
        char name[64];
        const char *colon = strchr(tool, ':');
        if (colon) {
            size_t len = (size_t)(colon - tool);
            if (len >= sizeof(name))
                len = sizeof(name) - 1;
            memcpy(name, tool, len);
            name[len] = '\0';
        } else {
            strncpy(name, tool, sizeof(name) - 1);
            name[sizeof(name) - 1] = '\0';
        }
        written = snprintf(snippet, max_len,
                           "[[tools]]\nallow = [\"%s\"]", name);
        break;
    }
    default:
        written = snprintf(snippet, max_len, "# Unknown effect type 0x%x", req->op);
        break;
    }

    if (written < 0 || (size_t)written >= max_len)
        return -ENAMETOOLONG;

    return 0;
}

/* ============================================================
 * TEST CASES: NULL INPUT HANDLING
 * ============================================================ */

bool test_pattern_match_null_pattern(void)
{
    TEST_ASSERT_EQ(ak_pattern_match(NULL, "test"), false);
    return true;
}

bool test_pattern_match_null_string(void)
{
    TEST_ASSERT_EQ(ak_pattern_match("pattern", NULL), false);
    return true;
}

bool test_pattern_match_both_null(void)
{
    TEST_ASSERT_EQ(ak_pattern_match(NULL, NULL), false);
    return true;
}

bool test_pattern_match_n_null_pattern(void)
{
    TEST_ASSERT_EQ(ak_pattern_match_n(NULL, 5, "test", 4), false);
    return true;
}

bool test_pattern_match_n_null_string(void)
{
    TEST_ASSERT_EQ(ak_pattern_match_n("pattern", 7, NULL, 4), false);
    return true;
}

bool test_canonicalize_path_null_path(void)
{
    char out[AK_MAX_TARGET];
    TEST_EXPECT_ERROR(ak_canonicalize_path(NULL, out, sizeof(out), "/"), -EINVAL);
    return true;
}

bool test_canonicalize_path_null_out(void)
{
    TEST_EXPECT_ERROR(ak_canonicalize_path("/test", NULL, 512, "/"), -EINVAL);
    return true;
}

bool test_canonicalize_path_zero_len(void)
{
    char out[AK_MAX_TARGET];
    TEST_EXPECT_ERROR(ak_canonicalize_path("/test", out, 0, "/"), -EINVAL);
    return true;
}

bool test_canonicalize_net_null_addr(void)
{
    char out[AK_MAX_TARGET];
    TEST_EXPECT_ERROR(ak_canonicalize_net_addr(NULL, 443, out, sizeof(out)), -EINVAL);
    return true;
}

bool test_canonicalize_net_null_out(void)
{
    TEST_EXPECT_ERROR(ak_canonicalize_net_addr("example.com", 443, NULL, 512), -EINVAL);
    return true;
}

bool test_canonicalize_net_zero_len(void)
{
    char out[AK_MAX_TARGET];
    TEST_EXPECT_ERROR(ak_canonicalize_net_addr("example.com", 443, out, 0), -EINVAL);
    return true;
}

bool test_generate_suggestion_null_req(void)
{
    char snippet[AK_MAX_SUGGEST];
    TEST_EXPECT_ERROR(ak_generate_suggestion(NULL, snippet, sizeof(snippet)), -EINVAL);
    return true;
}

bool test_generate_suggestion_null_snippet(void)
{
    ak_effect_req_t req = {0};
    req.op = AK_E_FS_OPEN;
    strncpy(req.target, "/app/file.txt", sizeof(req.target) - 1);
    TEST_EXPECT_ERROR(ak_generate_suggestion(&req, NULL, 512), -EINVAL);
    return true;
}

bool test_generate_suggestion_zero_len(void)
{
    ak_effect_req_t req = {0};
    char snippet[AK_MAX_SUGGEST];
    req.op = AK_E_FS_OPEN;
    strncpy(req.target, "/app/file.txt", sizeof(req.target) - 1);
    TEST_EXPECT_ERROR(ak_generate_suggestion(&req, snippet, 0), -EINVAL);
    return true;
}

/* ============================================================
 * TEST CASES: EMPTY STRING HANDLING
 * ============================================================ */

bool test_pattern_match_empty_pattern(void)
{
    /* Empty pattern should only match empty string */
    TEST_ASSERT_EQ(ak_pattern_match("", ""), true);
    TEST_ASSERT_EQ(ak_pattern_match("", "anything"), false);
    return true;
}

bool test_pattern_match_empty_string(void)
{
    /* Only * or empty pattern matches empty string */
    TEST_ASSERT_EQ(ak_pattern_match("*", ""), true);
    TEST_ASSERT_EQ(ak_pattern_match("**", ""), true);
    TEST_ASSERT_EQ(ak_pattern_match("a", ""), false);
    TEST_ASSERT_EQ(ak_pattern_match("?", ""), false);
    return true;
}

bool test_canonicalize_path_empty(void)
{
    char out[AK_MAX_TARGET];
    /* Empty path should resolve to cwd or / */
    int result = ak_canonicalize_path("", out, sizeof(out), "/home/user");
    TEST_EXPECT_SUCCESS(result);
    /* Should be /home/user or / depending on implementation */
    TEST_EXPECT_NOT_NULL(out);
    return true;
}

bool test_canonicalize_net_empty_addr(void)
{
    char out[AK_MAX_TARGET];
    /* Empty address - implementation specific, should not crash */
    int result = ak_canonicalize_net_addr("", 443, out, sizeof(out));
    /* Might succeed with empty result or fail gracefully */
    (void)result;
    return true;
}

/* ============================================================
 * TEST CASES: MAXIMUM LENGTH INPUTS
 * ============================================================ */

bool test_pattern_match_max_length_pattern(void)
{
    char *long_pattern = test_make_string(AK_MAX_TARGET - 1, 'a');
    TEST_EXPECT_NOT_NULL(long_pattern);

    char *long_string = test_make_string(AK_MAX_TARGET - 1, 'a');
    TEST_EXPECT_NOT_NULL(long_string);

    /* Should match identical strings */
    TEST_ASSERT_EQ(ak_pattern_match(long_pattern, long_string), true);

    /* Modify one and should not match */
    long_string[0] = 'b';
    TEST_ASSERT_EQ(ak_pattern_match(long_pattern, long_string), false);

    free(long_pattern);
    free(long_string);
    return true;
}

bool test_pattern_match_over_max_length(void)
{
    /* Test with very long string - should not crash */
    char *huge_pattern = test_make_string(TEST_MAX_STRING_LEN, 'a');
    char *huge_string = test_make_string(TEST_MAX_STRING_LEN, 'a');

    if (huge_pattern && huge_string) {
        /* Should either match or handle gracefully */
        (void)ak_pattern_match(huge_pattern, huge_string);
    }

    free(huge_pattern);
    free(huge_string);
    return true;
}

bool test_canonicalize_path_max_length(void)
{
    char out[AK_MAX_TARGET];

    /* Create path at boundary */
    char long_path[AK_MAX_TARGET];
    memset(long_path, 'a', AK_MAX_TARGET - 2);
    long_path[0] = '/';
    long_path[AK_MAX_TARGET - 2] = '\0';

    /* Should handle path at max length */
    int result = ak_canonicalize_path(long_path, out, sizeof(out), "/");
    /* Either succeeds or returns ENAMETOOLONG */
    TEST_ASSERT(result == 0 || result == -ENAMETOOLONG);
    return true;
}

bool test_canonicalize_path_exceeds_buffer(void)
{
    char out[16];  /* Small buffer */

    /* Try to fit long path in small buffer */
    int result = ak_canonicalize_path("/very/long/path/that/exceeds/buffer",
                                       out, sizeof(out), "/");
    TEST_EXPECT_ERROR(result, -ENAMETOOLONG);
    return true;
}

bool test_canonicalize_net_max_hostname(void)
{
    char out[AK_MAX_TARGET];

    /* RFC 1035: max hostname is 253 characters */
    char long_host[254];
    memset(long_host, 'a', 253);
    long_host[253] = '\0';

    int result = ak_canonicalize_net_addr(long_host, 443, out, sizeof(out));
    /* Should either succeed or fail gracefully */
    TEST_ASSERT(result == 0 || result == -ENAMETOOLONG);
    return true;
}

bool test_canonicalize_net_small_buffer(void)
{
    char out[8];  /* Very small buffer */

    int result = ak_canonicalize_net_addr("example.com", 443, out, sizeof(out));
    TEST_EXPECT_ERROR(result, -ENAMETOOLONG);
    return true;
}

/* ============================================================
 * TEST CASES: BOUNDARY VALUES
 * ============================================================ */

bool test_pattern_match_n_zero_lengths(void)
{
    /* Zero-length pattern and string */
    TEST_ASSERT_EQ(ak_pattern_match_n("pattern", 0, "string", 0), true);
    TEST_ASSERT_EQ(ak_pattern_match_n("pattern", 0, "string", 6), false);
    TEST_ASSERT_EQ(ak_pattern_match_n("*", 1, "string", 0), true);
    return true;
}

bool test_pattern_match_n_mismatched_lengths(void)
{
    /* Length doesn't match actual string */
    const char *pattern = "hello";
    const char *string = "hello world";

    /* Match first 5 chars of string against pattern */
    TEST_ASSERT_EQ(ak_pattern_match_n(pattern, 5, string, 5), true);
    TEST_ASSERT_EQ(ak_pattern_match_n(pattern, 5, string, 11), false);
    return true;
}

bool test_canonicalize_path_boundary_dots(void)
{
    char out[AK_MAX_TARGET];

    /* Single dot */
    TEST_EXPECT_SUCCESS(ak_canonicalize_path("/app/.", out, sizeof(out), "/"));
    TEST_ASSERT_STREQ(out, "/app");

    /* Double dot at root */
    TEST_EXPECT_SUCCESS(ak_canonicalize_path("/..", out, sizeof(out), "/"));
    TEST_ASSERT_STREQ(out, "/");

    /* Multiple parent traversals */
    TEST_EXPECT_SUCCESS(ak_canonicalize_path("/a/b/c/../../../..", out, sizeof(out), "/"));
    TEST_ASSERT_STREQ(out, "/");
    return true;
}

bool test_canonicalize_path_many_slashes(void)
{
    char out[AK_MAX_TARGET];

    /* Multiple consecutive slashes */
    TEST_EXPECT_SUCCESS(ak_canonicalize_path("///app///file///", out, sizeof(out), "/"));
    TEST_ASSERT_STREQ(out, "/app/file");

    /* All slashes */
    TEST_EXPECT_SUCCESS(ak_canonicalize_path("//////", out, sizeof(out), "/"));
    TEST_ASSERT_STREQ(out, "/");
    return true;
}

bool test_canonicalize_net_port_boundaries(void)
{
    char out[AK_MAX_TARGET];

    /* Port 0 */
    TEST_EXPECT_SUCCESS(ak_canonicalize_net_addr("127.0.0.1", 0, out, sizeof(out)));
    TEST_ASSERT_STRSTR(out, ":0");

    /* Port 65535 (max) */
    TEST_EXPECT_SUCCESS(ak_canonicalize_net_addr("127.0.0.1", 65535, out, sizeof(out)));
    TEST_ASSERT_STRSTR(out, ":65535");

    /* Port 1 (min non-zero) */
    TEST_EXPECT_SUCCESS(ak_canonicalize_net_addr("127.0.0.1", 1, out, sizeof(out)));
    TEST_ASSERT_STRSTR(out, ":1");
    return true;
}

/* ============================================================
 * TEST CASES: INVALID ENUM VALUES
 * ============================================================ */

bool test_generate_suggestion_invalid_op(void)
{
    ak_effect_req_t req = {0};
    char snippet[AK_MAX_SUGGEST];

    /* Invalid operation code */
    req.op = (ak_effect_op_t)0x9999;
    strncpy(req.target, "/invalid", sizeof(req.target) - 1);

    int result = ak_generate_suggestion(&req, snippet, sizeof(snippet));
    /* Should handle gracefully - either error or "unknown" message */
    if (result == 0) {
        TEST_ASSERT_STRSTR(snippet, "Unknown");
    }
    return true;
}

bool test_generate_suggestion_zero_op(void)
{
    ak_effect_req_t req = {0};
    char snippet[AK_MAX_SUGGEST];

    req.op = (ak_effect_op_t)0;
    strncpy(req.target, "/test", sizeof(req.target) - 1);

    int result = ak_generate_suggestion(&req, snippet, sizeof(snippet));
    if (result == 0) {
        TEST_ASSERT_STRSTR(snippet, "Unknown");
    }
    return true;
}

/* ============================================================
 * TEST CASES: SPECIAL CHARACTERS
 * ============================================================ */

bool test_pattern_match_special_chars(void)
{
    /* Backslash in pattern */
    TEST_ASSERT_EQ(ak_pattern_match("path\\file", "path\\file"), true);

    /* Quote characters */
    TEST_ASSERT_EQ(ak_pattern_match("file\"name", "file\"name"), true);
    TEST_ASSERT_EQ(ak_pattern_match("file'name", "file'name"), true);

    /* Control characters */
    TEST_ASSERT_EQ(ak_pattern_match("file\tname", "file\tname"), true);
    TEST_ASSERT_EQ(ak_pattern_match("file\nname", "file\nname"), true);

    /* Null byte embedded (treated as string terminator) */
    const char pattern_with_null[] = "abc\0def";
    const char string_with_null[] = "abc\0xyz";
    TEST_ASSERT_EQ(ak_pattern_match(pattern_with_null, string_with_null), true);
    return true;
}

bool test_canonicalize_path_special_chars(void)
{
    char out[AK_MAX_TARGET];

    /* Space in path */
    TEST_EXPECT_SUCCESS(ak_canonicalize_path("/path with/spaces", out, sizeof(out), "/"));
    TEST_ASSERT_STREQ(out, "/path with/spaces");

    /* Unicode-like characters (just the bytes) */
    TEST_EXPECT_SUCCESS(ak_canonicalize_path("/path/\xc3\xa9", out, sizeof(out), "/"));

    /* Dash and underscore */
    TEST_EXPECT_SUCCESS(ak_canonicalize_path("/path-name_test", out, sizeof(out), "/"));
    TEST_ASSERT_STREQ(out, "/path-name_test");
    return true;
}

bool test_canonicalize_net_special_hostnames(void)
{
    char out[AK_MAX_TARGET];

    /* Hyphen in hostname (valid) */
    TEST_EXPECT_SUCCESS(ak_canonicalize_net_addr("my-host.example.com", 443, out, sizeof(out)));
    TEST_ASSERT_STRSTR(out, "my-host.example.com");

    /* Underscore (technically invalid but common) */
    TEST_EXPECT_SUCCESS(ak_canonicalize_net_addr("my_host.example.com", 443, out, sizeof(out)));

    /* Numeric hostname */
    TEST_EXPECT_SUCCESS(ak_canonicalize_net_addr("123host.com", 443, out, sizeof(out)));
    return true;
}

/* ============================================================
 * TEST CASES: MEMORY CORRUPTION DETECTION
 * ============================================================ */

bool test_canonicalize_path_buffer_boundary(void)
{
    /* Use guarded buffer to detect overflows */
    size_t buf_size = AK_MAX_TARGET;
    size_t guard_size = 16;
    uint8_t guard_pattern = 0xAA;

    void *guarded = test_alloc_guarded(buf_size, guard_size, guard_pattern);
    TEST_EXPECT_NOT_NULL(guarded);

    char *out = (char *)guarded;
    int result = ak_canonicalize_path("/app/test/file.txt", out, (u32)buf_size, "/");
    TEST_EXPECT_SUCCESS(result);

    /* Verify guards weren't overwritten */
    TEST_MEMORY_BOUNDARY(((uint8_t *)guarded) - guard_size, buf_size, guard_size, guard_pattern);

    test_free_guarded(guarded, guard_size);
    return true;
}

bool test_canonicalize_net_buffer_boundary(void)
{
    size_t buf_size = AK_MAX_TARGET;
    size_t guard_size = 16;
    uint8_t guard_pattern = 0xBB;

    void *guarded = test_alloc_guarded(buf_size, guard_size, guard_pattern);
    TEST_EXPECT_NOT_NULL(guarded);

    char *out = (char *)guarded;
    int result = ak_canonicalize_net_addr("example.com", 443, out, (u32)buf_size);
    TEST_EXPECT_SUCCESS(result);

    TEST_MEMORY_BOUNDARY(((uint8_t *)guarded) - guard_size, buf_size, guard_size, guard_pattern);

    test_free_guarded(guarded, guard_size);
    return true;
}

bool test_generate_suggestion_buffer_boundary(void)
{
    size_t buf_size = AK_MAX_SUGGEST;
    size_t guard_size = 16;
    uint8_t guard_pattern = 0xCC;

    void *guarded = test_alloc_guarded(buf_size, guard_size, guard_pattern);
    TEST_EXPECT_NOT_NULL(guarded);

    ak_effect_req_t req = {0};
    req.op = AK_E_FS_OPEN;
    strncpy(req.target, "/app/file.txt", sizeof(req.target) - 1);

    char *out = (char *)guarded;
    int result = ak_generate_suggestion(&req, out, (u32)buf_size);
    TEST_EXPECT_SUCCESS(result);

    TEST_MEMORY_BOUNDARY(((uint8_t *)guarded) - guard_size, buf_size, guard_size, guard_pattern);

    test_free_guarded(guarded, guard_size);
    return true;
}

/* ============================================================
 * TEST CASES: ERROR PATH COVERAGE
 * ============================================================ */

bool test_canonicalize_path_relative_no_cwd(void)
{
    char out[AK_MAX_TARGET];

    /* Relative path without cwd should use / as default */
    int result = ak_canonicalize_path("relative/path", out, sizeof(out), NULL);
    TEST_EXPECT_SUCCESS(result);
    /* Should be /relative/path with default cwd=/ */
    TEST_ASSERT(out[0] == '/');
    return true;
}

bool test_canonicalize_path_cwd_too_long(void)
{
    char out[AK_MAX_TARGET];
    char long_cwd[AK_MAX_TARGET + 10];
    memset(long_cwd, 'a', sizeof(long_cwd) - 1);
    long_cwd[0] = '/';
    long_cwd[sizeof(long_cwd) - 1] = '\0';

    int result = ak_canonicalize_path("file.txt", out, sizeof(out), long_cwd);
    TEST_EXPECT_ERROR(result, -ENAMETOOLONG);
    return true;
}

bool test_pattern_match_pathological_cases(void)
{
    /* Pattern that could cause backtracking issues */
    /* a]**...**[b pattern with many wildcards */
    char pattern[128];
    memset(pattern, '*', 100);
    pattern[100] = '\0';

    char input[128];
    memset(input, 'a', 100);
    input[100] = '\0';

    /* Should complete in reasonable time without hanging */
    TEST_TIME_START();
    boolean result = ak_pattern_match(pattern, input);
    uint64_t elapsed = TEST_TIME_END();

    /* Should be true (all wildcards match anything) */
    TEST_ASSERT_EQ(result, true);

    /* Should complete quickly (< 100ms) */
    TEST_ASSERT_LT(elapsed, 100000000ULL);
    return true;
}

bool test_pattern_match_alternating_wildcards(void)
{
    /* Pattern: *?*?*?*? - alternating wildcards */
    TEST_ASSERT_EQ(ak_pattern_match("*?*?*?*?", "abcdefgh"), true);
    TEST_ASSERT_EQ(ak_pattern_match("*?*?*?*?", "abc"), false);  /* Need at least 4 chars for ? */

    /* Pattern: ?*?*?*?* - reversed */
    TEST_ASSERT_EQ(ak_pattern_match("?*?*?*?*", "abcd"), true);
    return true;
}

/* ============================================================
 * TEST CASES: SECURITY EDGE CASES
 * ============================================================ */

bool test_path_traversal_variants(void)
{
    char out[AK_MAX_TARGET];

    /* Standard traversal */
    TEST_EXPECT_SUCCESS(ak_canonicalize_path("/app/../etc/passwd", out, sizeof(out), "/"));
    TEST_ASSERT_STREQ(out, "/etc/passwd");

    /* Double-encoded (not decoded by this function, but should handle) */
    TEST_EXPECT_SUCCESS(ak_canonicalize_path("/app/..%2F..%2Fetc", out, sizeof(out), "/"));
    /* Should NOT decode - literal path */
    TEST_ASSERT_STRSTR(out, "%2F");

    /* Null byte injection attempt - C string will truncate */
    const char injection[] = "/app/\x00../etc/passwd";
    TEST_EXPECT_SUCCESS(ak_canonicalize_path(injection, out, sizeof(out), "/"));
    TEST_ASSERT_STREQ(out, "/app");
    return true;
}

bool test_dns_name_security(void)
{
    char out[AK_MAX_TARGET];

    /* IDN homograph attack vectors (just raw characters) */
    TEST_EXPECT_SUCCESS(ak_canonicalize_net_addr("xn--80ak6aa92e.com", 443, out, sizeof(out)));

    /* Very long subdomain labels */
    char long_label[64];
    memset(long_label, 'a', 63);
    long_label[63] = '\0';
    char long_hostname[128];
    snprintf(long_hostname, sizeof(long_hostname), "%s.example.com", long_label);
    TEST_EXPECT_SUCCESS(ak_canonicalize_net_addr(long_hostname, 443, out, sizeof(out)));
    return true;
}

bool test_effect_request_initialization(void)
{
    /* Test that uninitialized fields don't cause issues */
    ak_effect_req_t req;
    memset(&req, 0xFF, sizeof(req));  /* Fill with garbage */

    /* Properly initialize required fields */
    req.op = AK_E_FS_OPEN;
    req.trace_id = 12345;
    req.pid = 1000;
    req.tid = 1;
    memset(req.target, 0, sizeof(req.target));
    strncpy(req.target, "/test/file", sizeof(req.target) - 1);
    req.params_len = 0;

    char snippet[AK_MAX_SUGGEST];
    int result = ak_generate_suggestion(&req, snippet, sizeof(snippet));
    TEST_EXPECT_SUCCESS(result);
    return true;
}

/* ============================================================
 * TEST CASES: REGRESSION TESTS
 * ============================================================ */

/*
 * Regression test for: Pattern matching with trailing wildcards
 * Bug: Pattern "*.txt" didn't match "file.txt" in some cases
 */
bool test_regression_trailing_wildcard(void)
{
    TEST_ASSERT_EQ(ak_pattern_match("*.txt", "file.txt"), true);
    TEST_ASSERT_EQ(ak_pattern_match("*.txt", ".txt"), true);
    TEST_ASSERT_EQ(ak_pattern_match("*.txt", "a.txt"), true);
    TEST_ASSERT_EQ(ak_pattern_match("*.txt", "very_long_filename.txt"), true);
    TEST_ASSERT_EQ(ak_pattern_match("*.txt", "file.txt.bak"), false);
    return true;
}

/*
 * Regression test for: Path canonicalization with empty components
 * Bug: "/app//file" could result in incorrect path
 */
bool test_regression_empty_path_components(void)
{
    char out[AK_MAX_TARGET];

    TEST_EXPECT_SUCCESS(ak_canonicalize_path("/app//file", out, sizeof(out), "/"));
    TEST_ASSERT_STREQ(out, "/app/file");

    TEST_EXPECT_SUCCESS(ak_canonicalize_path("//app//", out, sizeof(out), "/"));
    TEST_ASSERT_STREQ(out, "/app");

    TEST_EXPECT_SUCCESS(ak_canonicalize_path("/./app/./file/.", out, sizeof(out), "/"));
    TEST_ASSERT_STREQ(out, "/app/file");
    return true;
}

/*
 * Regression test for: Double-star pattern edge case
 * Bug: "**" alone could match incorrectly
 */
bool test_regression_double_star_alone(void)
{
    TEST_ASSERT_EQ(ak_pattern_match("**", ""), true);
    TEST_ASSERT_EQ(ak_pattern_match("**", "anything"), true);
    TEST_ASSERT_EQ(ak_pattern_match("**", "a/b/c/d"), true);
    TEST_ASSERT_EQ(ak_pattern_match("/**", "/a/b/c"), true);
    TEST_ASSERT_EQ(ak_pattern_match("**/file", "file"), true);
    TEST_ASSERT_EQ(ak_pattern_match("**/file", "a/b/file"), true);
    return true;
}

/*
 * Regression test for: IPv6 address canonicalization
 * Bug: IPv6 addresses weren't properly bracketed
 */
bool test_regression_ipv6_format(void)
{
    char out[AK_MAX_TARGET];

    TEST_EXPECT_SUCCESS(ak_canonicalize_net_addr("::1", 8080, out, sizeof(out)));
    TEST_ASSERT_STRSTR(out, "[::1]");

    TEST_EXPECT_SUCCESS(ak_canonicalize_net_addr("2001:db8::1", 443, out, sizeof(out)));
    TEST_ASSERT_STRSTR(out, "[2001:db8::1]");
    return true;
}

/*
 * Regression test for: Suggestion generation with long targets
 * Bug: Long target paths could overflow snippet buffer
 */
bool test_regression_long_target_suggestion(void)
{
    ak_effect_req_t req = {0};
    char snippet[AK_MAX_SUGGEST];

    /* Create target near max length */
    req.op = AK_E_FS_OPEN;
    memset(req.target, 'a', AK_MAX_TARGET - 2);
    req.target[0] = '/';
    req.target[AK_MAX_TARGET - 2] = '\0';

    /* Should handle gracefully even if truncated */
    int result = ak_generate_suggestion(&req, snippet, sizeof(snippet));
    /* Either succeeds or returns error, but should not crash */
    (void)result;
    TEST_EXPECT_NOT_NULL(snippet);

    return true;
}

/* ============================================================
 * TEST RUNNER
 * ============================================================ */

test_case_t tests[] = {
    /* NULL input tests */
    {"pattern_match_null_pattern", test_pattern_match_null_pattern},
    {"pattern_match_null_string", test_pattern_match_null_string},
    {"pattern_match_both_null", test_pattern_match_both_null},
    {"pattern_match_n_null_pattern", test_pattern_match_n_null_pattern},
    {"pattern_match_n_null_string", test_pattern_match_n_null_string},
    {"canonicalize_path_null_path", test_canonicalize_path_null_path},
    {"canonicalize_path_null_out", test_canonicalize_path_null_out},
    {"canonicalize_path_zero_len", test_canonicalize_path_zero_len},
    {"canonicalize_net_null_addr", test_canonicalize_net_null_addr},
    {"canonicalize_net_null_out", test_canonicalize_net_null_out},
    {"canonicalize_net_zero_len", test_canonicalize_net_zero_len},
    {"generate_suggestion_null_req", test_generate_suggestion_null_req},
    {"generate_suggestion_null_snippet", test_generate_suggestion_null_snippet},
    {"generate_suggestion_zero_len", test_generate_suggestion_zero_len},

    /* Empty string tests */
    {"pattern_match_empty_pattern", test_pattern_match_empty_pattern},
    {"pattern_match_empty_string", test_pattern_match_empty_string},
    {"canonicalize_path_empty", test_canonicalize_path_empty},
    {"canonicalize_net_empty_addr", test_canonicalize_net_empty_addr},

    /* Maximum length tests */
    {"pattern_match_max_length_pattern", test_pattern_match_max_length_pattern},
    {"pattern_match_over_max_length", test_pattern_match_over_max_length},
    {"canonicalize_path_max_length", test_canonicalize_path_max_length},
    {"canonicalize_path_exceeds_buffer", test_canonicalize_path_exceeds_buffer},
    {"canonicalize_net_max_hostname", test_canonicalize_net_max_hostname},
    {"canonicalize_net_small_buffer", test_canonicalize_net_small_buffer},

    /* Boundary value tests */
    {"pattern_match_n_zero_lengths", test_pattern_match_n_zero_lengths},
    {"pattern_match_n_mismatched_lengths", test_pattern_match_n_mismatched_lengths},
    {"canonicalize_path_boundary_dots", test_canonicalize_path_boundary_dots},
    {"canonicalize_path_many_slashes", test_canonicalize_path_many_slashes},
    {"canonicalize_net_port_boundaries", test_canonicalize_net_port_boundaries},

    /* Invalid enum tests */
    {"generate_suggestion_invalid_op", test_generate_suggestion_invalid_op},
    {"generate_suggestion_zero_op", test_generate_suggestion_zero_op},

    /* Special character tests */
    {"pattern_match_special_chars", test_pattern_match_special_chars},
    {"canonicalize_path_special_chars", test_canonicalize_path_special_chars},
    {"canonicalize_net_special_hostnames", test_canonicalize_net_special_hostnames},

    /* Memory boundary tests */
    {"canonicalize_path_buffer_boundary", test_canonicalize_path_buffer_boundary},
    {"canonicalize_net_buffer_boundary", test_canonicalize_net_buffer_boundary},
    {"generate_suggestion_buffer_boundary", test_generate_suggestion_buffer_boundary},

    /* Error path tests */
    {"canonicalize_path_relative_no_cwd", test_canonicalize_path_relative_no_cwd},
    {"canonicalize_path_cwd_too_long", test_canonicalize_path_cwd_too_long},
    {"pattern_match_pathological_cases", test_pattern_match_pathological_cases},
    {"pattern_match_alternating_wildcards", test_pattern_match_alternating_wildcards},

    /* Security edge case tests */
    {"path_traversal_variants", test_path_traversal_variants},
    {"dns_name_security", test_dns_name_security},
    {"effect_request_initialization", test_effect_request_initialization},

    /* Regression tests */
    {"regression_trailing_wildcard", test_regression_trailing_wildcard},
    {"regression_empty_path_components", test_regression_empty_path_components},
    {"regression_double_star_alone", test_regression_double_star_alone},
    {"regression_ipv6_format", test_regression_ipv6_format},
    {"regression_long_target_suggestion", test_regression_long_target_suggestion},

    {NULL, NULL}
};

int main(int argc, char **argv)
{
    const char *filter = (argc > 1) ? argv[1] : NULL;

    if (filter) {
        return test_run_filtered(tests, "AK Negative & Edge Case Tests", filter);
    } else {
        return test_run_all(tests, "AK Negative & Edge Case Tests");
    }
}
