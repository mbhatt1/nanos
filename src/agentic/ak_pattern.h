#ifndef AK_PATTERN_H
#define AK_PATTERN_H

#include "ak_types.h"

/*
 * Glob-style pattern matching.
 * Supports: * (any chars), ? (single char)
 * Returns: true if pattern matches string
 */
boolean ak_pattern_match(const char *pattern, const char *string);

/* Match with explicit lengths (for non-null-terminated) */
boolean ak_pattern_match_n(const char *pattern, u64 pattern_len,
                           const char *string, u64 string_len);

#endif
