/*
 * Authority Kernel - Pattern Matching Unit Tests
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Tests for glob pattern matching, CIDR matching, and DNS pattern matching.
 * These tests run on the host without booting the unikernel.
 */

#include <runtime.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

/* Test assertion macro */
#define test_assert(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "FAIL: %s at %s:%d\n", #expr, __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

#define test_assert_msg(expr, msg) do { \
    if (!(expr)) { \
        fprintf(stderr, "FAIL: %s - %s at %s:%d\n", msg, #expr, __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

/* ============================================================
 * GLOB PATTERN MATCHING
 * ============================================================
 * Simplified pattern matching for testing.
 * In production, ak_pattern_match from ak_pattern.c is used.
 */

/* Local implementation for host-side testing */
static boolean pattern_match_internal(const char *pattern, u64 plen,
                                       const char *string, u64 slen)
{
    u64 pi = 0;
    u64 si = 0;
    u64 star_pi = (u64)-1;
    u64 star_si = (u64)-1;
    boolean star_is_double = false;  /* Track if star was ** */

    while (si < slen) {
        if (pi < plen && pattern[pi] == '*') {
            if (pi + 1 < plen && pattern[pi + 1] == '*') {
                /* ** matches across path separators */
                star_pi = pi + 2;
                star_si = si;
                star_is_double = true;
                pi += 2;
                /* Skip trailing slash after ** if present */
                if (pi < plen && pattern[pi] == '/')
                    pi++;
            } else {
                /* * matches anything except / */
                star_pi = ++pi;
                star_si = si;
                star_is_double = false;
            }
        } else if (pi < plen && (pattern[pi] == '?' || pattern[pi] == string[si])) {
            pi++;
            si++;
        } else if (star_pi != (u64)-1) {
            /* For single *, don't cross path separators */
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

static u64 local_strlen(const char *s)
{
    u64 len = 0;
    while (s[len] != '\0')
        len++;
    return len;
}

static boolean glob_match(const char *pattern, const char *string)
{
    if (!pattern || !string)
        return false;
    return pattern_match_internal(pattern, local_strlen(pattern),
                                   string, local_strlen(string));
}

/* ============================================================
 * CIDR MATCHING
 * ============================================================ */

/* Parse IPv4 address into 32-bit value */
static boolean parse_ipv4(const char *str, u32 *out)
{
    u32 octets[4] = {0};
    int i = 0;

    while (*str && i < 4) {
        if (*str >= '0' && *str <= '9') {
            octets[i] = octets[i] * 10 + (u32)(*str - '0');
            if (octets[i] > 255)
                return false;
        } else if (*str == '.') {
            i++;
            if (i >= 4)
                return false;
        } else {
            return false;
        }
        str++;
    }

    if (i != 3)
        return false;

    *out = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
    return true;
}

/* Match IP against CIDR pattern (e.g., "10.0.0.0/8") */
static boolean cidr_match(const char *cidr, const char *ip_str)
{
    char network[32];
    int prefix_len = 32;
    u32 network_addr, ip_addr, mask;

    /* Parse CIDR notation */
    const char *slash = strchr(cidr, '/');
    if (slash) {
        size_t len = (size_t)(slash - cidr);
        if (len >= sizeof(network))
            return false;
        memcpy(network, cidr, len);
        network[len] = '\0';
        prefix_len = atoi(slash + 1);
        if (prefix_len < 0 || prefix_len > 32)
            return false;
    } else {
        if (strlen(cidr) >= sizeof(network))
            return false;
        strcpy(network, cidr);
    }

    if (!parse_ipv4(network, &network_addr))
        return false;
    if (!parse_ipv4(ip_str, &ip_addr))
        return false;

    if (prefix_len == 0)
        return true;  /* /0 matches everything */

    mask = ~((1u << (32 - prefix_len)) - 1);
    return (network_addr & mask) == (ip_addr & mask);
}

/* ============================================================
 * DNS PATTERN MATCHING
 * ============================================================ */

/* Match DNS name against pattern (supports wildcards) */
static boolean dns_match(const char *pattern, const char *hostname)
{
    /* Handle wildcard patterns like "*.example.com" */
    if (pattern[0] == '*' && pattern[1] == '.') {
        /* Skip wildcard and dot */
        const char *pattern_suffix = pattern + 2;

        /* Find first dot in hostname */
        const char *host_suffix = strchr(hostname, '.');
        if (!host_suffix)
            return false;
        host_suffix++;  /* Skip the dot */

        /* Compare suffixes */
        return strcmp(pattern_suffix, host_suffix) == 0;
    }

    /* Exact match */
    return strcmp(pattern, hostname) == 0;
}

/* ============================================================
 * TEST CASES: GLOB PATTERN MATCHING
 * ============================================================ */

boolean test_glob_exact_match(void)
{
    test_assert(glob_match("hello", "hello"));
    test_assert(!glob_match("hello", "world"));
    test_assert(!glob_match("hello", "hell"));
    test_assert(!glob_match("hello", "helloo"));
    return true;
}

boolean test_glob_star_basic(void)
{
    /* Single * matches any characters */
    test_assert(glob_match("*", "anything"));
    test_assert(glob_match("*", ""));
    test_assert(glob_match("*.txt", "file.txt"));
    test_assert(glob_match("*.txt", ".txt"));
    test_assert(!glob_match("*.txt", "file.log"));
    test_assert(glob_match("file.*", "file.txt"));
    test_assert(glob_match("file.*", "file."));
    return true;
}

boolean test_glob_star_middle(void)
{
    test_assert(glob_match("foo*bar", "foobar"));
    test_assert(glob_match("foo*bar", "foo123bar"));
    test_assert(glob_match("foo*bar", "fooXYZbar"));
    test_assert(!glob_match("foo*bar", "foobaz"));
    return true;
}

boolean test_glob_question_mark(void)
{
    test_assert(glob_match("?", "a"));
    test_assert(!glob_match("?", ""));
    test_assert(!glob_match("?", "ab"));
    test_assert(glob_match("???", "abc"));
    test_assert(glob_match("a?c", "abc"));
    test_assert(!glob_match("a?c", "ac"));
    return true;
}

boolean test_glob_path_patterns(void)
{
    /* File path patterns */
    test_assert(glob_match("/app/*", "/app/file.txt"));
    test_assert(glob_match("/app/*.txt", "/app/file.txt"));
    test_assert(!glob_match("/app/*", "/app/subdir/file.txt"));

    /* Double star matches across directories */
    test_assert(glob_match("/app/**", "/app/file.txt"));
    test_assert(glob_match("/app/**", "/app/subdir/file.txt"));
    test_assert(glob_match("/app/**", "/app/a/b/c/file.txt"));
    return true;
}

boolean test_glob_edge_cases(void)
{
    /* Empty strings */
    test_assert(glob_match("", ""));
    test_assert(!glob_match("", "a"));
    test_assert(glob_match("*", ""));

    /* Multiple wildcards */
    test_assert(glob_match("*.*", "file.txt"));
    test_assert(glob_match("*.*.*", "file.tar.gz"));
    test_assert(glob_match("**", "anything"));

    /* Consecutive stars */
    test_assert(glob_match("***", "anything"));
    return true;
}

boolean test_glob_long_strings(void)
{
    char long_pattern[512];
    char long_string[512];

    /* Build a long path */
    memset(long_string, 'a', 500);
    long_string[500] = '\0';

    /* Test with exact match */
    memcpy(long_pattern, long_string, 501);
    test_assert(glob_match(long_pattern, long_string));

    /* Test with wildcard */
    strcpy(long_pattern, "*");
    test_assert(glob_match(long_pattern, long_string));

    return true;
}

/* ============================================================
 * TEST CASES: CIDR MATCHING
 * ============================================================ */

boolean test_cidr_exact_match(void)
{
    test_assert(cidr_match("192.168.1.1/32", "192.168.1.1"));
    test_assert(!cidr_match("192.168.1.1/32", "192.168.1.2"));
    return true;
}

boolean test_cidr_network_match(void)
{
    /* /24 network */
    test_assert(cidr_match("192.168.1.0/24", "192.168.1.0"));
    test_assert(cidr_match("192.168.1.0/24", "192.168.1.1"));
    test_assert(cidr_match("192.168.1.0/24", "192.168.1.255"));
    test_assert(!cidr_match("192.168.1.0/24", "192.168.2.1"));

    /* /16 network */
    test_assert(cidr_match("10.0.0.0/8", "10.0.0.1"));
    test_assert(cidr_match("10.0.0.0/8", "10.255.255.255"));
    test_assert(!cidr_match("10.0.0.0/8", "11.0.0.1"));

    /* /0 matches everything */
    test_assert(cidr_match("0.0.0.0/0", "192.168.1.1"));
    test_assert(cidr_match("0.0.0.0/0", "8.8.8.8"));
    return true;
}

boolean test_cidr_edge_cases(void)
{
    /* Without prefix length (assumes /32) */
    test_assert(cidr_match("192.168.1.1", "192.168.1.1"));
    test_assert(!cidr_match("192.168.1.1", "192.168.1.2"));

    /* Invalid inputs */
    test_assert(!cidr_match("192.168.1.256/24", "192.168.1.1"));
    test_assert(!cidr_match("192.168.1.1/24", "192.168.1.256"));
    test_assert(!cidr_match("invalid", "192.168.1.1"));
    return true;
}

/* ============================================================
 * TEST CASES: DNS PATTERN MATCHING
 * ============================================================ */

boolean test_dns_exact_match(void)
{
    test_assert(dns_match("example.com", "example.com"));
    test_assert(!dns_match("example.com", "other.com"));
    test_assert(!dns_match("example.com", "sub.example.com"));
    return true;
}

boolean test_dns_wildcard_match(void)
{
    test_assert(dns_match("*.example.com", "sub.example.com"));
    test_assert(dns_match("*.example.com", "api.example.com"));
    test_assert(!dns_match("*.example.com", "example.com"));
    test_assert(!dns_match("*.example.com", "sub.other.com"));
    return true;
}

boolean test_dns_edge_cases(void)
{
    /* Empty hostname */
    test_assert(!dns_match("*.example.com", ""));

    /* Single label */
    test_assert(!dns_match("*.example.com", "localhost"));

    /* Deeply nested */
    test_assert(!dns_match("*.example.com", "a.b.example.com"));
    return true;
}

/* ============================================================
 * TEST RUNNER
 * ============================================================ */

typedef boolean (*test_func)(void);

typedef struct {
    const char *name;
    test_func func;
} test_case;

test_case tests[] = {
    /* Glob pattern tests */
    {"glob_exact_match", test_glob_exact_match},
    {"glob_star_basic", test_glob_star_basic},
    {"glob_star_middle", test_glob_star_middle},
    {"glob_question_mark", test_glob_question_mark},
    {"glob_path_patterns", test_glob_path_patterns},
    {"glob_edge_cases", test_glob_edge_cases},
    {"glob_long_strings", test_glob_long_strings},

    /* CIDR matching tests */
    {"cidr_exact_match", test_cidr_exact_match},
    {"cidr_network_match", test_cidr_network_match},
    {"cidr_edge_cases", test_cidr_edge_cases},

    /* DNS pattern tests */
    {"dns_exact_match", test_dns_exact_match},
    {"dns_wildcard_match", test_dns_wildcard_match},
    {"dns_edge_cases", test_dns_edge_cases},

    {NULL, NULL}
};

int main(int argc, char **argv)
{
    (void)argc;  /* unused */
    (void)argv;  /* unused */

    int passed = 0;
    int failed = 0;

    printf("=== AK Pattern Matching Tests ===\n\n");

    for (int i = 0; tests[i].name != NULL; i++) {
        printf("Running %s... ", tests[i].name);
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
