/*
 * Authority Kernel - Taint Sanitizer Implementation
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Production-quality sanitization for injection prevention.
 */

#include "ak_sanitize.h"
#include "ak_compat.h"

/* ============================================================
 * HTML SANITIZATION
 * ============================================================ */

buffer ak_sanitize_html(heap h, buffer input) {
  if (!input)
    return 0;

  u64 len = buffer_length(input);
  if (len == 0)
    return allocate_buffer(h, 0);

  /* Overflow check: worst case expansion (all & -> &amp;, 6x) */
  if (len > UINT64_MAX / 6)
    return 0;

  /* Allocate with worst case expansion (all & -> &amp;, 5x) */
  buffer out = allocate_buffer(h, len * 6);
  if (out == INVALID_ADDRESS)
    return 0;

  const u8 *src = buffer_ref(input, 0);
  for (u64 i = 0; i < len; i++) {
    u8 c = src[i];
    switch (c) {
    case '<':
      buffer_write_cstring(out, "&lt;");
      break;
    case '>':
      buffer_write_cstring(out, "&gt;");
      break;
    case '&':
      buffer_write_cstring(out, "&amp;");
      break;
    case '"':
      buffer_write_cstring(out, "&quot;");
      break;
    case '\'':
      buffer_write_cstring(out, "&#x27;");
      break;
    default:
      push_u8(out, c);
      break;
    }
  }

  return out;
}

/* ============================================================
 * SQL SANITIZATION
 * ============================================================ */

buffer ak_sanitize_sql(heap h, buffer input) {
  if (!input)
    return 0;

  u64 len = buffer_length(input);
  if (len == 0)
    return allocate_buffer(h, 0);

  /* Overflow check: worst case expansion (all ' -> '', 2x) */
  if (len > UINT64_MAX / 2)
    return 0;

  /* Allocate with worst case expansion (all ' -> '', 2x) */
  buffer out = allocate_buffer(h, len * 2);
  if (out == INVALID_ADDRESS)
    return 0;

  const u8 *src = buffer_ref(input, 0);
  for (u64 i = 0; i < len; i++) {
    u8 c = src[i];
    switch (c) {
    case '\'':
      /* SQL standard: double the quote */
      buffer_write_cstring(out, "''");
      break;
    case '"':
      /* Escape double quote */
      buffer_write_cstring(out, "\\\"");
      break;
    case ';':
      /* Reject semicolon to prevent statement chaining */
      deallocate_buffer(out);
      return 0;
    case '\\':
      /* Escape backslash for MySQL compatibility */
      buffer_write_cstring(out, "\\\\");
      break;
    case '\0':
      /* Escape null byte */
      buffer_write_cstring(out, "\\0");
      break;
    case '\n':
      buffer_write_cstring(out, "\\n");
      break;
    case '\r':
      buffer_write_cstring(out, "\\r");
      break;
    case '\x1a':
      /* Ctrl-Z (DOS EOF) */
      buffer_write_cstring(out, "\\Z");
      break;
    case '-':
      /* Check for SQL comment start (--) */
      if (i + 1 < len && src[i + 1] == '-') {
        /* Reject double-dash to prevent SQL comments */
        deallocate_buffer(out);
        return 0;
      }
      push_u8(out, c);
      break;
    default:
      push_u8(out, c);
      break;
    }
  }

  return out;
}

/* ============================================================
 * URL SANITIZATION
 * ============================================================ */

static const char hex_chars[] = "0123456789ABCDEF";

static boolean is_url_safe(u8 c) {
  /* RFC 3986 unreserved characters */
  if (c >= 'A' && c <= 'Z')
    return true;
  if (c >= 'a' && c <= 'z')
    return true;
  if (c >= '0' && c <= '9')
    return true;
  if (c == '-' || c == '_' || c == '.' || c == '~')
    return true;
  return false;
}

buffer ak_sanitize_url(heap h, buffer input) {
  if (!input)
    return 0;

  u64 len = buffer_length(input);
  if (len == 0)
    return allocate_buffer(h, 0);

  /* Overflow check: worst case expansion (all %XX, 3x) */
  if (len > UINT64_MAX / 3)
    return 0;

  /* Allocate with worst case expansion (all %XX, 3x) */
  buffer out = allocate_buffer(h, len * 3);
  if (out == INVALID_ADDRESS)
    return 0;

  const u8 *src = buffer_ref(input, 0);
  for (u64 i = 0; i < len; i++) {
    u8 c = src[i];
    if (is_url_safe(c)) {
      push_u8(out, c);
    } else {
      push_u8(out, '%');
      push_u8(out, hex_chars[(c >> 4) & 0x0F]);
      push_u8(out, hex_chars[c & 0x0F]);
    }
  }

  return out;
}

/* ============================================================
 * COMMAND SANITIZATION
 * ============================================================ */

buffer ak_sanitize_cmd(heap h, buffer input) {
  if (!input)
    return 0;

  u64 len = buffer_length(input);
  if (len == 0) {
    /* Empty string -> '' */
    buffer out = allocate_buffer(h, 2);
    if (out == INVALID_ADDRESS)
      return 0;
    buffer_write_cstring(out, "''");
    return out;
  }

  /* Count single quotes for sizing */
  u64 quote_count = 0;
  const u8 *src = buffer_ref(input, 0);
  for (u64 i = 0; i < len; i++) {
    if (src[i] == '\'')
      quote_count++;
  }

  /* Overflow checks for allocation size calculation:
   * Each ' becomes '\'' (4 chars), plus 2 for outer quotes
   * Total: len + quote_count * 3 + 2
   */
  if (quote_count > UINT64_MAX / 3)
    return 0;
  u64 extra = quote_count * 3;
  if (len > UINT64_MAX - extra)
    return 0;
  u64 size_needed = len + extra;
  if (size_needed > UINT64_MAX - 2)
    return 0;
  size_needed += 2;

  buffer out = allocate_buffer(h, size_needed);
  if (out == INVALID_ADDRESS)
    return 0;

  push_u8(out, '\'');
  for (u64 i = 0; i < len; i++) {
    u8 c = src[i];
    if (c == '\'') {
      /* End current quote, escape quote, start new quote */
      buffer_write_cstring(out, "'\\''");
    } else {
      push_u8(out, c);
    }
  }
  push_u8(out, '\'');

  return out;
}

/* ============================================================
 * PATH SANITIZATION
 * ============================================================ */

buffer ak_sanitize_path(heap h, buffer input, const char *base_path) {
  if (!input)
    return 0;

  u64 len = buffer_length(input);
  u64 base_len = base_path ? runtime_strlen(base_path) : 0;

  /* Allocate output buffer */
  buffer out = allocate_buffer(h, len + base_len + 2);
  if (out == INVALID_ADDRESS)
    return 0;

  /* Start with base path if provided */
  if (base_path && base_len > 0) {
    buffer_write(out, base_path, base_len);
    /* Add separator if base doesn't end with one */
    if (base_path[base_len - 1] != '/')
      push_u8(out, '/');
  }

  if (len == 0)
    return out;

  const u8 *src = buffer_ref(input, 0);
  u64 i = 0;

  /* Skip leading slashes to prevent absolute paths */
  while (i < len && src[i] == '/')
    i++;

  /* Process path components */
  while (i < len) {
    /* Check for .. at start of component */
    if (i + 1 < len && src[i] == '.' && src[i + 1] == '.') {
      /* Must check i + 2 < len BEFORE accessing src[i + 2] */
      if (i + 2 == len || src[i + 2] == '/') {
        /* Skip ".." and following slash */
        i += 2;
        if (i < len && src[i] == '/')
          i++;
        continue;
      }
    }

    /* Check for single . at start of component */
    if (src[i] == '.' && (i + 1 >= len || src[i + 1] == '/')) {
      /* Skip "." and following slash */
      i++;
      if (i < len && src[i] == '/')
        i++;
      continue;
    }

    /* Skip null bytes */
    if (src[i] == '\0') {
      i++;
      continue;
    }

    /* Copy character */
    push_u8(out, src[i]);
    i++;

    /* Skip consecutive slashes */
    if (i > 0 && src[i - 1] == '/') {
      while (i < len && src[i] == '/')
        i++;
    }
  }

  /* Remove trailing slash (unless that's all we have) */
  u64 out_len = buffer_length(out);
  if (out_len > base_len + 1) {
    u8 *out_ptr = buffer_ref(out, 0);
    if (out_ptr[out_len - 1] == '/') {
      buffer_set_end(out, out_len - 1);
    }
  }

  return out;
}

/* ============================================================
 * SANITIZER DISPATCH
 * ============================================================ */

/*
 * ak_get_sanitizer - Get the appropriate sanitizer function for a taint
 * transition.
 *
 * NOTE: Returns NULL for AK_TAINT_SANITIZED_PATH because ak_sanitize_path()
 * requires an additional base_path parameter and does not match the
 * ak_sanitizer_fn signature. Use ak_sanitize_path() directly or use
 * ak_sanitize_apply() which handles the path sanitizer as a special case.
 *
 * Returns: sanitizer function pointer, or NULL if no direct sanitizer
 * available.
 */
ak_sanitizer_fn ak_get_sanitizer(ak_taint_t from_taint, ak_taint_t to_taint) {
  /* Can only sanitize untrusted data */
  if (from_taint != AK_TAINT_UNTRUSTED)
    return 0;

  switch (to_taint) {
  case AK_TAINT_SANITIZED_HTML:
    return ak_sanitize_html;
  case AK_TAINT_SANITIZED_SQL:
    return ak_sanitize_sql;
  case AK_TAINT_SANITIZED_URL:
    return ak_sanitize_url;
  case AK_TAINT_SANITIZED_CMD:
    return ak_sanitize_cmd;
  case AK_TAINT_SANITIZED_PATH:
    /* Path sanitizer has extra parameter, can't return directly.
     * Use ak_sanitize_path() directly or ak_sanitize_apply() instead. */
    return 0;
  default:
    return 0;
  }
}

ak_taint_t ak_sanitize_apply(heap h, buffer input, ak_taint_t input_taint,
                             ak_taint_t to_taint, buffer *output) {
  if (!output)
    return AK_TAINT_UNTRUSTED;

  *output = 0;

  /* Already at desired taint level or more trusted */
  if (input_taint <= to_taint) {
    *output = input;
    return input_taint;
  }

  /* Get appropriate sanitizer */
  ak_sanitizer_fn sanitizer = ak_get_sanitizer(input_taint, to_taint);
  if (!sanitizer) {
    /* Special case for path sanitizer */
    if (to_taint == AK_TAINT_SANITIZED_PATH) {
      *output = ak_sanitize_path(h, input, 0);
      if (*output)
        return AK_TAINT_SANITIZED_PATH;
    }
    return AK_TAINT_UNTRUSTED;
  }

  *output = sanitizer(h, input);
  if (!*output)
    return AK_TAINT_UNTRUSTED;

  return to_taint;
}

/* ============================================================
 * DLP (DATA LOSS PREVENTION)
 * ============================================================ */

/*
 * Pattern matchers for secret detection.
 * Return true if pattern matches at given position.
 */

/* Check for API key patterns: sk-xxx, Bearer xxx */
static boolean match_api_key(const u8 *data, u64 len, u64 pos) {
  /* OpenAI-style: sk-... */
  if (pos + 3 <= len && data[pos] == 's' && data[pos + 1] == 'k' &&
      data[pos + 2] == '-') {
    return true;
  }

  /* Bearer token */
  if (pos + 7 <= len && runtime_memcmp(&data[pos], "Bearer ", 7) == 0) {
    return true;
  }

  /* Anthropic-style: sk-ant-... */
  if (pos + 7 <= len && runtime_memcmp(&data[pos], "sk-ant-", 7) == 0) {
    return true;
  }

  return false;
}

/* Check for JWT pattern: eyJ... */
static boolean match_jwt(const u8 *data, u64 len, u64 pos) {
  if (pos + 3 <= len && data[pos] == 'e' && data[pos + 1] == 'y' &&
      data[pos + 2] == 'J') {
    return true;
  }
  return false;
}

/* Check for password patterns */
static boolean match_password(const u8 *data, u64 len, u64 pos) {
  /* password=xxx, pwd=xxx, passwd=xxx */
  const char *patterns[] = {"password=", "pwd=", "passwd=", "secret="};
  int pattern_count = 4;

  for (int i = 0; i < pattern_count; i++) {
    u64 plen = runtime_strlen(patterns[i]);
    if (pos + plen <= len &&
        runtime_memcmp(&data[pos], patterns[i], plen) == 0) {
      return true;
    }
  }
  return false;
}

/* Check for private key patterns */
static boolean match_private_key(const u8 *data, u64 len, u64 pos) {
  if (pos + 27 <= len &&
      runtime_memcmp(&data[pos], "-----BEGIN PRIVATE KEY-----", 27) == 0) {
    return true;
  }
  if (pos + 31 <= len &&
      runtime_memcmp(&data[pos], "-----BEGIN RSA PRIVATE KEY-----", 31) == 0) {
    return true;
  }
  return false;
}

/* Find end of secret token (word boundary) */
static u64 find_token_end(const u8 *data, u64 len, u64 start) {
  u64 pos = start;
  while (pos < len) {
    u8 c = data[pos];
    /* Stop at whitespace, quotes, or common delimiters */
    if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '"' ||
        c == '\'' || c == ',' || c == ';' || c == '}' || c == ']' || c == ')' ||
        c == '&') {
      break;
    }
    pos++;
  }
  return pos;
}

u32 ak_dlp_detect_secrets(buffer input, u32 patterns) {
  if (!input || buffer_length(input) == 0)
    return 0;

  u32 detected = 0;
  const u8 *data = buffer_ref(input, 0);
  u64 len = buffer_length(input);

  if (patterns == 0)
    patterns = AK_DLP_PATTERN_ALL;

  for (u64 i = 0; i < len; i++) {
    if ((patterns & AK_DLP_PATTERN_API_KEY) && match_api_key(data, len, i))
      detected |= AK_DLP_PATTERN_API_KEY;

    if ((patterns & AK_DLP_PATTERN_JWT) && match_jwt(data, len, i))
      detected |= AK_DLP_PATTERN_JWT;

    if ((patterns & AK_DLP_PATTERN_PASSWORD) && match_password(data, len, i))
      detected |= AK_DLP_PATTERN_PASSWORD;

    if ((patterns & AK_DLP_PATTERN_PRIVATE_KEY) &&
        match_private_key(data, len, i))
      detected |= AK_DLP_PATTERN_PRIVATE_KEY;
  }

  return detected;
}

buffer ak_dlp_redact_patterns(heap h, buffer input, u32 patterns) {
  if (!input)
    return 0;

  u64 len = buffer_length(input);
  if (len == 0)
    return allocate_buffer(h, 0);

  /* Allocate output (same size, redaction doesn't expand) */
  buffer out = allocate_buffer(h, len + 64);
  if (out == INVALID_ADDRESS)
    return 0;

  const u8 *data = buffer_ref(input, 0);
  u64 i = 0;

  if (patterns == 0)
    patterns = AK_DLP_PATTERN_ALL;

  while (i < len) {
    boolean redacted = false;

    /* Check for API key patterns */
    if ((patterns & AK_DLP_PATTERN_API_KEY) && match_api_key(data, len, i)) {
      u64 end = find_token_end(data, len, i);
      buffer_write_cstring(out, "[REDACTED:API_KEY]");
      i = end;
      redacted = true;
    }

    /* Check for JWT */
    if (!redacted && (patterns & AK_DLP_PATTERN_JWT) &&
        match_jwt(data, len, i)) {
      u64 end = find_token_end(data, len, i);
      buffer_write_cstring(out, "[REDACTED:JWT]");
      i = end;
      redacted = true;
    }

    /* Check for password patterns */
    if (!redacted && (patterns & AK_DLP_PATTERN_PASSWORD) &&
        match_password(data, len, i)) {
      /* Find the '=' and skip the pattern name */
      while (i < len && data[i] != '=')
        push_u8(out, data[i++]);
      if (i < len) {
        push_u8(out, '='); /* Include the '=' */
        i++;
        /* Redact the value */
        u64 end = find_token_end(data, len, i);
        buffer_write_cstring(out, "[REDACTED]");
        i = end;
      }
      redacted = true;
    }

    /* Check for private key */
    if (!redacted && (patterns & AK_DLP_PATTERN_PRIVATE_KEY) &&
        match_private_key(data, len, i)) {
      /* Skip entire key block */
      buffer_write_cstring(out, "[REDACTED:PRIVATE_KEY]");
      /* Find END marker */
      while (i < len) {
        if (i + 23 <= len && runtime_memcmp(&data[i], "-----END ", 9) == 0) {
          /* Skip to end of line */
          while (i < len && data[i] != '\n')
            i++;
          if (i < len)
            i++;
          break;
        }
        i++;
      }
      redacted = true;
    }

    if (!redacted) {
      push_u8(out, data[i]);
      i++;
    }
  }

  return out;
}

buffer ak_dlp_redact_secrets(heap h, buffer input) {
  return ak_dlp_redact_patterns(h, input, AK_DLP_PATTERN_ALL);
}
