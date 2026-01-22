/*
 * Fuzz Target: JSON Policy Parser
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * This fuzz target exercises the JSON policy parser in ak_policy_v2.c.
 * It tests the parser's resilience to malformed, truncated, and malicious
 * JSON inputs that could cause crashes, memory corruption, or infinite loops.
 *
 * Build: clang -fsanitize=fuzzer,address,undefined -g -I../../src -I../../src/agentic -I../../src/runtime fuzz_json_parser.c -o fuzz_json_parser
 * Run:   ./fuzz_json_parser corpus/json/ -max_total_time=60
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

/*
 * Minimal type definitions for standalone fuzzing.
 * These mirror the types in ak_types.h but are self-contained
 * to allow fuzzing without linking the full kernel.
 */

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef signed long long s64;
typedef int boolean;

#define true 1
#define false 0

/* Maximum pattern/path length from ak_policy_v2.h */
#define AK_POLICY_V2_MAX_PATTERN 256
#define AK_MAX_PROFILES 16

/* Minimal heap stub for standalone fuzzing */
typedef void *heap;

__attribute__((unused))
static void *fuzz_alloc(size_t size) {
    return calloc(1, size);
}

__attribute__((unused))
static void fuzz_free(void *p, size_t size) {
    (void)size;
    free(p);
}

/* Stub for runtime_memset */
__attribute__((unused))
static void runtime_memset(u8 *dest, u8 val, u64 len) {
    memset(dest, val, len);
}

/* Stub for runtime_memcpy */
__attribute__((unused))
static void runtime_memcpy(void *dest, const void *src, u64 len) {
    memcpy(dest, src, len);
}

/*
 * Re-implement the JSON parser functions locally for fuzzing.
 * This allows us to fuzz the parsing logic without kernel dependencies.
 */

/* Skip whitespace */
static const u8 *skip_ws(const u8 *p, const u8 *end) {
    if (!p || !end || p >= end)
        return p;
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
        p++;
    return p;
}

/* Local strlen */
__attribute__((unused))
static u64 local_strlen(const char *s) {
    if (!s) return 0;
    u64 len = 0;
    while (s[len]) len++;
    return len;
}

/* Local strncpy */
__attribute__((unused))
static void local_strncpy(char *dest, const char *src, u64 n) {
    if (!dest || !src || n == 0) return;
    u64 i;
    for (i = 0; i < n - 1 && src[i]; i++) {
        dest[i] = src[i];
    }
    dest[i] = '\0';
}

/* Local strncmp */
static int local_strncmp(const char *s1, const char *s2, u64 n) {
    if (!s1 || !s2) return s1 ? 1 : (s2 ? -1 : 0);
    for (u64 i = 0; i < n; i++) {
        if (s1[i] != s2[i])
            return (unsigned char)s1[i] - (unsigned char)s2[i];
        if (s1[i] == '\0')
            return 0;
    }
    return 0;
}

/* Parse a JSON string, return end position */
static const u8 *parse_string(const u8 *p, const u8 *end, char *out, u64 max_len) {
    if (p >= end || *p != '"') return NULL;
    p++;

    u64 i = 0;
    while (p < end && *p != '"') {
        if (*p == '\\' && p + 1 < end) {
            p++;
            if (*p == '"' || *p == '\\') {
                if (i < max_len - 1) out[i++] = *p;
            }
        } else {
            if (i < max_len - 1) out[i++] = *p;
        }
        p++;
    }
    if (p < end && *p == '"') p++;
    out[i] = '\0';
    return p;
}

/* Parse a JSON number (u64 only) */
static const u8 *parse_number(const u8 *p, const u8 *end, u64 *out) {
    *out = 0;
    while (p < end && *p >= '0' && *p <= '9') {
        /* Check for overflow */
        if (*out > 0xFFFFFFFFFFFFFFFFULL / 10) {
            *out = 0xFFFFFFFFFFFFFFFFULL;
            while (p < end && *p >= '0' && *p <= '9') p++;
            return p;
        }
        *out = (*out * 10) + (*p - '0');
        p++;
    }
    return p;
}

/* Skip a JSON value (string, number, object, array, bool, null) */
static const u8 *skip_value(const u8 *p, const u8 *end) {
    p = skip_ws(p, end);
    if (p >= end) return NULL;

    if (*p == '"') {
        p++;
        while (p < end && *p != '"') {
            if (*p == '\\' && p + 1 < end) p++;
            p++;
        }
        return (p < end) ? p + 1 : NULL;
    } else if (*p == '{') {
        int depth = 1;
        p++;
        while (p < end && depth > 0) {
            if (*p == '{') depth++;
            else if (*p == '}') depth--;
            else if (*p == '"') {
                p++;
                while (p < end && *p != '"') {
                    if (*p == '\\' && p + 1 < end) p++;
                    p++;
                }
            }
            p++;
        }
        return p;
    } else if (*p == '[') {
        int depth = 1;
        p++;
        while (p < end && depth > 0) {
            if (*p == '[') depth++;
            else if (*p == ']') depth--;
            else if (*p == '"') {
                p++;
                while (p < end && *p != '"') {
                    if (*p == '\\' && p + 1 < end) p++;
                    p++;
                }
            }
            p++;
        }
        return p;
    } else if (*p >= '0' && *p <= '9') {
        while (p < end && ((*p >= '0' && *p <= '9') || *p == '.'))
            p++;
        return p;
    } else if (local_strncmp((const char *)p, "true", 4) == 0) {
        return p + 4;
    } else if (local_strncmp((const char *)p, "false", 5) == 0) {
        return p + 5;
    } else if (local_strncmp((const char *)p, "null", 4) == 0) {
        return p + 4;
    }
    return NULL;
}

/* Callback type for string array parsing */
typedef void (*string_array_cb)(void *ctx, const char *str);

/* Parse array of strings */
static const u8 *parse_string_array(const u8 *p, const u8 *end,
                                    string_array_cb cb, void *ctx) {
    p = skip_ws(p, end);
    if (p >= end || *p != '[') return NULL;
    p++;

    while (p < end) {
        p = skip_ws(p, end);
        if (p >= end) return NULL;
        if (*p == ']') return p + 1;

        char str[AK_POLICY_V2_MAX_PATTERN];
        p = parse_string(p, end, str, sizeof(str));
        if (!p) return NULL;

        if (cb) cb(ctx, str);

        p = skip_ws(p, end);
        if (p >= end) return NULL;
        if (*p == ',') p++;
        else if (*p != ']') return NULL;
    }
    return NULL;
}

/* Counter for parsed items (used to detect successful parsing) */
static int g_parsed_fs_rules = 0;
static int g_parsed_net_rules = 0;
static int g_parsed_tool_rules = 0;

/* Callbacks for tracking parsed items */
static void count_fs_rule(void *ctx, const char *str) {
    (void)ctx;
    (void)str;
    g_parsed_fs_rules++;
}

static void count_net_rule(void *ctx, const char *str) {
    (void)ctx;
    (void)str;
    g_parsed_net_rules++;
}

static void count_tool_rule(void *ctx, const char *str) {
    (void)ctx;
    (void)str;
    g_parsed_tool_rules++;
}

/*
 * Main JSON policy parser function.
 * This is a simplified version of parse_json_policy from ak_policy_v2.c.
 */
static boolean parse_json_policy(const u8 *json, u64 len) {
    const u8 *p = json;
    const u8 *end = json + len;

    /* Reset counters */
    g_parsed_fs_rules = 0;
    g_parsed_net_rules = 0;
    g_parsed_tool_rules = 0;

    p = skip_ws(p, end);
    if (p >= end || *p != '{') return false;
    p++;

    while (p < end) {
        p = skip_ws(p, end);
        if (p >= end) return false;
        if (*p == '}') break;

        /* Parse key */
        char key[64];
        p = parse_string(p, end, key, sizeof(key));
        if (!p) return false;

        p = skip_ws(p, end);
        if (p >= end || *p != ':') return false;
        p++;
        p = skip_ws(p, end);

        /* Handle known keys */
        if (local_strncmp(key, "version", 7) == 0) {
            char version[32];
            p = parse_string(p, end, version, sizeof(version));
            if (!p) return false;
        }
        else if (local_strncmp(key, "fs", 2) == 0) {
            /* Parse fs object: { "read": [...], "write": [...] } */
            if (*p != '{') { p = skip_value(p, end); goto next; }
            p++;

            while (p < end) {
                p = skip_ws(p, end);
                if (p >= end) return false;
                if (*p == '}') { p++; break; }

                char fs_key[32];
                p = parse_string(p, end, fs_key, sizeof(fs_key));
                if (!p) return false;

                p = skip_ws(p, end);
                if (p >= end || *p != ':') return false;
                p++;

                if (local_strncmp(fs_key, "read", 4) == 0 ||
                    local_strncmp(fs_key, "write", 5) == 0) {
                    p = parse_string_array(p, end, count_fs_rule, NULL);
                } else {
                    p = skip_value(p, end);
                }
                if (!p) return false;

                p = skip_ws(p, end);
                if (p < end && *p == ',') p++;
            }
        }
        else if (local_strncmp(key, "net", 3) == 0) {
            /* Parse net object: { "dns": [...], "connect": [...] } */
            if (*p != '{') { p = skip_value(p, end); goto next; }
            p++;

            while (p < end) {
                p = skip_ws(p, end);
                if (p >= end) return false;
                if (*p == '}') { p++; break; }

                char net_key[32];
                p = parse_string(p, end, net_key, sizeof(net_key));
                if (!p) return false;

                p = skip_ws(p, end);
                if (p >= end || *p != ':') return false;
                p++;

                if (local_strncmp(net_key, "dns", 3) == 0 ||
                    local_strncmp(net_key, "connect", 7) == 0) {
                    p = parse_string_array(p, end, count_net_rule, NULL);
                } else {
                    p = skip_value(p, end);
                }
                if (!p) return false;

                p = skip_ws(p, end);
                if (p < end && *p == ',') p++;
            }
        }
        else if (local_strncmp(key, "tools", 5) == 0) {
            /* Parse tools object: { "allow": [...], "deny": [...] } */
            if (*p != '{') { p = skip_value(p, end); goto next; }
            p++;

            while (p < end) {
                p = skip_ws(p, end);
                if (p >= end) return false;
                if (*p == '}') { p++; break; }

                char tool_key[32];
                p = parse_string(p, end, tool_key, sizeof(tool_key));
                if (!p) return false;

                p = skip_ws(p, end);
                if (p >= end || *p != ':') return false;
                p++;

                if (local_strncmp(tool_key, "allow", 5) == 0 ||
                    local_strncmp(tool_key, "deny", 4) == 0) {
                    p = parse_string_array(p, end, count_tool_rule, NULL);
                } else {
                    p = skip_value(p, end);
                }
                if (!p) return false;

                p = skip_ws(p, end);
                if (p < end && *p == ',') p++;
            }
        }
        else if (local_strncmp(key, "budgets", 7) == 0) {
            /* Parse budgets object */
            if (*p != '{') { p = skip_value(p, end); goto next; }
            p++;

            while (p < end) {
                p = skip_ws(p, end);
                if (*p == '}') { p++; break; }

                char budget_key[32];
                p = parse_string(p, end, budget_key, sizeof(budget_key));
                if (!p) return false;

                p = skip_ws(p, end);
                if (*p != ':') return false;
                p++;
                p = skip_ws(p, end);

                u64 val;
                p = parse_number(p, end, &val);
                if (!p) return false;

                p = skip_ws(p, end);
                if (*p == ',') p++;
            }
        }
        else {
            /* Unknown key, skip value */
            p = skip_value(p, end);
            if (!p) return false;
        }

    next:
        p = skip_ws(p, end);
        if (p < end && *p == ',') p++;
    }

    return true;
}

/*
 * LibFuzzer entry point.
 *
 * This function is called by LibFuzzer with random/mutated input data.
 * We attempt to parse the input as a JSON policy and catch any crashes,
 * hangs, or memory errors.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Limit input size to prevent excessive memory usage */
    if (size > 1024 * 1024) {
        return 0;
    }

    /* Ensure null-termination for safety (make a copy) */
    uint8_t *input = malloc(size + 1);
    if (!input) {
        return 0;
    }
    memcpy(input, data, size);
    input[size] = '\0';

    /* Call the parser */
    boolean result = parse_json_policy(input, size);

    /* Optional: verify result is consistent */
    (void)result;

    free(input);
    return 0;
}

#ifdef FUZZ_STANDALONE
/*
 * Standalone main for testing without LibFuzzer.
 * Reads input from stdin or file argument.
 */
#include <stdio.h>

int main(int argc, char **argv) {
    FILE *f = stdin;
    if (argc > 1) {
        f = fopen(argv[1], "rb");
        if (!f) {
            perror("fopen");
            return 1;
        }
    }

    /* Read input */
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t *data = malloc(size);
    if (!data) {
        perror("malloc");
        return 1;
    }
    fread(data, 1, size, f);

    if (f != stdin) fclose(f);

    /* Run the fuzzer target */
    int result = LLVMFuzzerTestOneInput(data, size);

    printf("Parsed: fs=%d net=%d tools=%d\n",
           g_parsed_fs_rules, g_parsed_net_rules, g_parsed_tool_rules);

    free(data);
    return result;
}
#endif
