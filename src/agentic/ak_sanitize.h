/*
 * Authority Kernel - Taint Sanitizers
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Provides sanitization functions for tainted data.
 * Used to safely convert untrusted input for use in specific contexts.
 *
 * SECURITY: These functions prevent common injection attacks:
 *   - XSS (HTML sanitization)
 *   - SQL injection (SQL escaping)
 *   - Command injection (shell escaping)
 *   - Path traversal (path normalization)
 *   - URL manipulation (URL encoding)
 */

#ifndef AK_SANITIZE_H
#define AK_SANITIZE_H

#include "ak_types.h"

/* ============================================================
 * HTML SANITIZATION
 * ============================================================ */

/*
 * Escape HTML special characters.
 *
 * Escapes: < > & " '
 *
 * Use for text content, NOT for attributes with special semantics
 * like href, src, onclick etc.
 *
 * @param h       Heap for allocation
 * @param input   Untrusted input
 * @return        HTML-safe output
 */
buffer ak_sanitize_html(heap h, buffer input);

/* ============================================================
 * SQL SANITIZATION
 * ============================================================ */

/*
 * Escape SQL string literals.
 *
 * Escapes: ' \ NULL newline carriage-return
 *
 * IMPORTANT: This only escapes string content. You must still
 * use proper parameterized queries when possible. This function
 * is for cases where that's not possible.
 *
 * @param h       Heap for allocation
 * @param input   Untrusted input
 * @return        SQL-safe string content
 */
buffer ak_sanitize_sql(heap h, buffer input);

/* ============================================================
 * URL SANITIZATION
 * ============================================================ */

/*
 * Percent-encode special characters for URL components.
 *
 * Preserves: A-Z a-z 0-9 - _ . ~
 * Encodes everything else as %XX
 *
 * @param h       Heap for allocation
 * @param input   Untrusted input
 * @return        URL-safe component
 */
buffer ak_sanitize_url(heap h, buffer input);

/* ============================================================
 * COMMAND SANITIZATION
 * ============================================================ */

/*
 * Escape for shell command arguments.
 *
 * Wraps input in single quotes and escapes internal single quotes.
 * This is the safest way to pass untrusted data to shell commands.
 *
 * SECURITY: Even with escaping, avoid passing untrusted data to
 * shells when possible. Use execve() with argv array instead.
 *
 * @param h       Heap for allocation
 * @param input   Untrusted input
 * @return        Shell-safe argument
 */
buffer ak_sanitize_cmd(heap h, buffer input);

/* ============================================================
 * PATH SANITIZATION
 * ============================================================ */

/*
 * Sanitize filesystem path.
 *
 * Removes:
 *   - Parent directory references (..)
 *   - Leading slashes (absolute paths)
 *   - Null bytes
 *
 * Optionally prefixes with a base path to ensure containment.
 *
 * @param h          Heap for allocation
 * @param input      Untrusted path component
 * @param base_path  Optional base directory (may be NULL)
 * @return           Safe path
 */
buffer ak_sanitize_path(heap h, buffer input, const char *base_path);

/* ============================================================
 * SANITIZER DISPATCH
 * ============================================================ */

/* Sanitizer function type */
typedef buffer (*ak_sanitizer_fn)(heap h, buffer input);

/*
 * Get appropriate sanitizer for a taint transition.
 *
 * Use to find which sanitizer converts from one taint level to another.
 *
 * @param from_taint  Current taint level
 * @param to_taint    Desired taint level
 * @return            Sanitizer function, or NULL if conversion not supported
 */
ak_sanitizer_fn ak_get_sanitizer(ak_taint_t from_taint, ak_taint_t to_taint);

/*
 * Apply sanitization and update taint.
 *
 * Convenience function that sanitizes and returns the new taint level.
 *
 * @param h           Heap for allocation
 * @param input       Untrusted input
 * @param input_taint Current taint level
 * @param to_taint    Desired taint level
 * @param output      Receives sanitized buffer
 * @return            Resulting taint level, or AK_TAINT_UNTRUSTED on failure
 */
ak_taint_t ak_sanitize_apply(heap h, buffer input, ak_taint_t input_taint,
                              ak_taint_t to_taint, buffer *output);

#endif /* AK_SANITIZE_H */
