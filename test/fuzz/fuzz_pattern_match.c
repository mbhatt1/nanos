/*
 * Fuzz Target: Glob Pattern Matcher
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * This fuzz target exercises the glob pattern matching logic in ak_pattern.c.
 * It tests for:
 *   - Crashes on malformed patterns
 *   - Exponential backtracking (ReDoS-style attacks)
 *   - Off-by-one errors in boundary conditions
 *   - Incorrect matching of edge cases
 *
 * Build: clang -fsanitize=fuzzer,address,undefined -g fuzz_pattern_match.c -o fuzz_pattern_match
 * Run:   ./fuzz_pattern_match corpus/pattern/ -max_total_time=60
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

/*
 * Minimal type definitions for standalone fuzzing.
 */
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef int boolean;

#define true 1
#define false 0

/*
 * Pattern matching implementation from ak_pattern.c.
 * Uses an iterative approach with backtracking for * wildcards.
 * This avoids recursion to prevent stack overflow on long patterns.
 */
static boolean pattern_match_internal(const char *pattern, u64 plen,
                                       const char *string, u64 slen) {
    u64 pi = 0;  /* pattern index */
    u64 si = 0;  /* string index */

    /* Saved positions for backtracking on * wildcard */
    u64 star_pi = (u64)-1;  /* pattern position after * */
    u64 star_si = (u64)-1;  /* string position to retry from */

    while (si < slen) {
        if (pi < plen && pattern[pi] == '*') {
            /* Found a *, save position for backtracking */
            star_pi = ++pi;  /* Move past the * */
            star_si = si;    /* Remember current string position */
        } else if (pi < plen && (pattern[pi] == '?' || pattern[pi] == string[si])) {
            /* Character match or ? wildcard */
            pi++;
            si++;
        } else if (star_pi != (u64)-1) {
            /* No match, but we have a * to backtrack to */
            pi = star_pi;       /* Go back to position after * */
            si = ++star_si;     /* Try matching one more char with * */
        } else {
            /* No match and no * to backtrack to */
            return false;
        }
    }

    /* Skip trailing * in pattern (they match empty string) */
    while (pi < plen && pattern[pi] == '*')
        pi++;

    /* Match only if we consumed the entire pattern */
    return (pi == plen);
}

/* Local strlen */
static u64 local_strlen(const char *s) {
    u64 len = 0;
    while (s[len] != '\0')
        len++;
    return len;
}

/*
 * Public API: Pattern matching with explicit lengths
 */
boolean ak_pattern_match_n(const char *pattern, u64 pattern_len,
                            const char *string, u64 string_len) {
    /* Null checks */
    if (!pattern || !string)
        return false;

    /* Empty pattern only matches empty string */
    if (pattern_len == 0)
        return (string_len == 0);

    /* Check if pattern is just * (matches anything) */
    if (pattern_len == 1 && pattern[0] == '*')
        return true;

    return pattern_match_internal(pattern, pattern_len, string, string_len);
}

/*
 * Public API: Pattern matching for null-terminated strings
 */
boolean ak_pattern_match(const char *pattern, const char *string) {
    if (!pattern || !string)
        return false;

    return ak_pattern_match_n(pattern, local_strlen(pattern),
                               string, local_strlen(string));
}

/*
 * Extended path matching with ** support (from ak_policy_v2.c)
 *
 * * matches any characters except /
 * ** matches any characters including /
 */
boolean ak_pattern_match_path(const char *pattern, const char *path) {
    if (!pattern || !path)
        return false;

    const char *pp = pattern;
    const char *tp = path;
    const char *star_pp = NULL;
    const char *star_tp = NULL;

    while (*tp) {
        /* Check for ** pattern */
        if (pp[0] == '*' && pp[1] == '*') {
            /* ** matches anything including / */
            star_pp = pp;
            star_tp = tp;
            pp += 2;
            /* Skip trailing / after ** if present */
            if (*pp == '/') pp++;
        } else if (*pp == '*') {
            /* * matches anything except / */
            star_pp = pp;
            star_tp = tp;
            pp++;
        } else if (*pp == *tp) {
            pp++;
            tp++;
        } else if (*pp == '?' && *tp != '/') {
            pp++;
            tp++;
        } else if (star_pp) {
            /* Backtrack to last * or ** */
            if (star_pp[0] == '*' && star_pp[1] == '*') {
                /* ** can consume anything */
                pp = star_pp + 2;
                if (*pp == '/') pp++;
                star_tp++;
                tp = star_tp;
            } else {
                /* * cannot match / */
                if (*star_tp == '/') {
                    return false;
                }
                pp = star_pp + 1;
                star_tp++;
                tp = star_tp;
            }
        } else {
            return false;
        }
    }

    /* Skip trailing wildcards in pattern */
    while (*pp == '*') pp++;
    while (pp[0] == '/' && pp[1] == '*' && pp[2] == '*') {
        pp += 3;
    }

    return (*pp == '\0');
}

/*
 * DNS domain matching with wildcard prefix support.
 * Supports wildcard prefix: *.example.com
 */
boolean ak_pattern_match_dns(const char *pattern, const char *domain) {
    if (!pattern || !domain)
        return false;

    u64 plen = local_strlen(pattern);
    u64 dlen = local_strlen(domain);

    /* Handle wildcard prefix */
    if (plen >= 2 && pattern[0] == '*' && pattern[1] == '.') {
        /* *.example.com matches sub.example.com and example.com */
        const char *suffix = pattern + 1;  /* .example.com */
        u64 suffix_len = plen - 1;

        if (dlen < suffix_len - 1)
            return false;

        /* Check if domain ends with suffix (without leading .) */
        if (dlen >= suffix_len - 1) {
            const char *domain_suffix = domain + dlen - suffix_len + 1;
            if (strcmp(domain_suffix, suffix + 1) == 0)
                return true;
        }

        /* Also match if domain is exactly the suffix without wildcard */
        if (strcmp(domain, suffix + 1) == 0)
            return true;

        return false;
    }

    /* Exact match */
    return (strcmp(pattern, domain) == 0);
}

/*
 * LibFuzzer entry point.
 *
 * The input format is:
 *   [1 byte: separator position]
 *   [pattern bytes...]
 *   [string bytes...]
 *
 * This allows fuzzing both the pattern and the string simultaneously.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Need at least 2 bytes (separator + at least 1 char) */
    if (size < 2) {
        return 0;
    }

    /* Limit input size to prevent timeouts */
    if (size > 65536) {
        return 0;
    }

    /* Use first byte as separator position (scaled to input size) */
    size_t sep = data[0] % (size - 1);
    if (sep == 0) sep = 1;  /* Ensure pattern has at least 1 byte */

    /* Create null-terminated copies */
    char *pattern = malloc(sep + 1);
    char *string = malloc(size - sep);
    if (!pattern || !string) {
        free(pattern);
        free(string);
        return 0;
    }

    memcpy(pattern, data + 1, sep);
    pattern[sep] = '\0';

    memcpy(string, data + 1 + sep, size - 1 - sep);
    string[size - 1 - sep] = '\0';

    /* Test basic pattern matching */
    boolean result1 = ak_pattern_match(pattern, string);

    /* Test with explicit lengths */
    boolean result2 = ak_pattern_match_n(pattern, sep, string, size - 1 - sep);

    /* Test path matching with ** support */
    boolean result3 = ak_pattern_match_path(pattern, string);

    /* Test DNS matching */
    boolean result4 = ak_pattern_match_dns(pattern, string);

    /* Use results to avoid unused variable warnings */
    (void)result3;
    (void)result4;

    /* Results should be consistent (basic match should equal explicit length match) */
    if (result1 != result2) {
        /* This would be a bug - different results for same input */
        __builtin_trap();
    }

    /* Cleanup */
    free(pattern);
    free(string);

    return 0;
}

#ifdef FUZZ_STANDALONE
/*
 * Standalone main for testing without LibFuzzer.
 */
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc != 3) {
        printf("Usage: %s <pattern> <string>\n", argv[0]);
        return 1;
    }

    const char *pattern = argv[1];
    const char *string = argv[2];

    printf("Pattern: '%s'\n", pattern);
    printf("String:  '%s'\n", string);
    printf("Basic match: %s\n", ak_pattern_match(pattern, string) ? "YES" : "NO");
    printf("Path match:  %s\n", ak_pattern_match_path(pattern, string) ? "YES" : "NO");
    printf("DNS match:   %s\n", ak_pattern_match_dns(pattern, string) ? "YES" : "NO");

    return 0;
}
#endif
