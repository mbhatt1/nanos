/*
 * Authority Kernel - Glob-style Pattern Matching
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Implements glob-style pattern matching for capability resource patterns.
 * Supports:
 *   * - matches zero or more characters
 *   ? - matches exactly one character
 */

#include "ak_pattern.h"
#include "ak_compat.h"

/* ============================================================
 * INTERNAL HELPER: Length-based pattern matching
 * ============================================================
 *
 * Uses an iterative approach with backtracking for * wildcards.
 * This avoids recursion to prevent stack overflow on long patterns.
 */
static boolean pattern_match_internal(const char *pattern, u64 plen,
                                       const char *string, u64 slen)
{
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

/* ============================================================
 * PUBLIC API: Pattern matching with explicit lengths
 * ============================================================ */
boolean ak_pattern_match_n(const char *pattern, u64 pattern_len,
                            const char *string, u64 string_len)
{
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

/* ============================================================
 * PUBLIC API: Pattern matching for null-terminated strings
 * ============================================================ */

/* Local strlen to avoid pulling in external dependencies */
static u64 local_strlen(const char *s)
{
    u64 len = 0;
    while (s[len] != '\0')
        len++;
    return len;
}

boolean ak_pattern_match(const char *pattern, const char *string)
{
    if (!pattern || !string)
        return false;

    return ak_pattern_match_n(pattern, local_strlen(pattern),
                               string, local_strlen(string));
}
