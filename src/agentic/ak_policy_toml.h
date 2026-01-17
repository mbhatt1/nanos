/*
 * Authority Kernel - TOML Policy Compiler
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * OWNER: Agent B (Policy + Bootstrap)
 *
 * This file implements a TOML-to-JSON policy compiler for the Authority Kernel.
 * It converts human-readable ak.toml files into JSON format expected by
 * ak_policy_v2_load().
 *
 * TOML Format:
 *   [policy]
 *   version = "2.0"
 *   name = "my-agent-policy"
 *
 *   [[fs.allow]]
 *   path = "/tmp/**"
 *   read = true
 *   write = true
 *
 *   [[net.allow]]
 *   pattern = "*.anthropic.com:443"
 *   connect = true
 *
 *   [[dns.allow]]
 *   pattern = "*.anthropic.com"
 *
 *   [[tools.allow]]
 *   name = "read_file"
 *   version = "*"
 *
 *   [[inference.allow]]
 *   model = "claude-*"
 *   max_tokens = 4096
 *
 * This is a BUILD-TIME TOOL, not runtime code.
 */

#ifndef AK_POLICY_TOML_H
#define AK_POLICY_TOML_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* ============================================================
 * CONSTANTS
 * ============================================================ */

#define AK_TOML_MAX_KEY         64      /* Maximum key length */
#define AK_TOML_MAX_VALUE       512     /* Maximum string value length */
#define AK_TOML_MAX_SECTION     128     /* Maximum section name length */
#define AK_TOML_MAX_RULES       256     /* Maximum rules per category */
#define AK_TOML_MAX_PROFILES    16      /* Maximum profile includes */
#define AK_TOML_MAX_HOSTCALLS   32      /* Maximum WASM hostcalls */
#define AK_TOML_MAX_LINE        1024    /* Maximum line length */

/* ============================================================
 * ERROR CODES
 * ============================================================ */

typedef enum ak_toml_error {
    AK_TOML_OK              = 0,
    AK_TOML_ERR_NULL        = -1,     /* NULL input */
    AK_TOML_ERR_SYNTAX      = -2,     /* TOML syntax error */
    AK_TOML_ERR_OVERFLOW    = -3,     /* Buffer overflow */
    AK_TOML_ERR_UNKNOWN_KEY = -4,     /* Unknown configuration key */
    AK_TOML_ERR_TYPE        = -5,     /* Type mismatch */
    AK_TOML_ERR_ALLOC       = -6,     /* Memory allocation failed */
    AK_TOML_ERR_IO          = -7,     /* I/O error */
    AK_TOML_ERR_TOO_MANY    = -8,     /* Too many rules/items */
} ak_toml_error_t;

/* ============================================================
 * TOML VALUE TYPES
 * ============================================================ */

typedef enum ak_toml_type {
    AK_TOML_TYPE_NONE       = 0,
    AK_TOML_TYPE_STRING     = 1,
    AK_TOML_TYPE_INTEGER    = 2,
    AK_TOML_TYPE_BOOLEAN    = 3,
    AK_TOML_TYPE_ARRAY      = 4,
    AK_TOML_TYPE_TABLE      = 5,
} ak_toml_type_t;

/* ============================================================
 * PARSED RULE STRUCTURES
 * ============================================================
 * Intermediate representation for parsed TOML rules.
 */

/* Filesystem rule */
typedef struct ak_toml_fs_rule {
    char path[AK_TOML_MAX_VALUE];
    bool read;
    bool write;
} ak_toml_fs_rule_t;

/* Network rule */
typedef struct ak_toml_net_rule {
    char pattern[AK_TOML_MAX_VALUE];
    bool connect;
    bool bind;
    bool listen;
} ak_toml_net_rule_t;

/* DNS rule */
typedef struct ak_toml_dns_rule {
    char pattern[AK_TOML_MAX_VALUE];
    bool allow;
} ak_toml_dns_rule_t;

/* Tool rule */
typedef struct ak_toml_tool_rule {
    char name[AK_TOML_MAX_KEY];
    char version[AK_TOML_MAX_KEY];
    bool allow;
} ak_toml_tool_rule_t;

/* WASM rule */
typedef struct ak_toml_wasm_rule {
    char module[AK_TOML_MAX_KEY];
    char hostcalls[AK_TOML_MAX_HOSTCALLS][AK_TOML_MAX_KEY];
    int hostcall_count;
} ak_toml_wasm_rule_t;

/* Inference rule */
typedef struct ak_toml_infer_rule {
    char model[AK_TOML_MAX_KEY];
    uint64_t max_tokens;
} ak_toml_infer_rule_t;

/* Budget configuration */
typedef struct ak_toml_budgets {
    uint64_t cpu_ns;
    uint64_t wall_time_ms;
    uint64_t bytes;
    uint64_t tokens;
    uint64_t tool_calls;
} ak_toml_budgets_t;

/* ============================================================
 * PARSED POLICY STRUCTURE
 * ============================================================
 * Complete intermediate representation of a TOML policy.
 */

typedef struct ak_toml_policy {
    /* Metadata */
    char version[AK_TOML_MAX_KEY];
    char name[AK_TOML_MAX_VALUE];

    /* Filesystem rules */
    ak_toml_fs_rule_t fs_rules[AK_TOML_MAX_RULES];
    int fs_rule_count;

    /* Network rules */
    ak_toml_net_rule_t net_rules[AK_TOML_MAX_RULES];
    int net_rule_count;

    /* DNS rules */
    ak_toml_dns_rule_t dns_rules[AK_TOML_MAX_RULES];
    int dns_rule_count;

    /* Tool rules */
    ak_toml_tool_rule_t tool_allow_rules[AK_TOML_MAX_RULES];
    int tool_allow_count;
    ak_toml_tool_rule_t tool_deny_rules[AK_TOML_MAX_RULES];
    int tool_deny_count;

    /* WASM rules */
    ak_toml_wasm_rule_t wasm_rules[AK_TOML_MAX_RULES];
    int wasm_rule_count;

    /* Inference rules */
    ak_toml_infer_rule_t infer_rules[AK_TOML_MAX_RULES];
    int infer_rule_count;

    /* Budgets */
    ak_toml_budgets_t budgets;
    bool has_budgets;

    /* Profiles */
    char profiles[AK_TOML_MAX_PROFILES][AK_TOML_MAX_KEY];
    int profile_count;

} ak_toml_policy_t;

/* ============================================================
 * PARSER CONTEXT
 * ============================================================ */

typedef struct ak_toml_parser {
    /* Input */
    const char *input;
    size_t input_len;
    size_t pos;

    /* Current position tracking */
    int line;
    int col;

    /* Current section context */
    char section[AK_TOML_MAX_SECTION];
    bool in_array_table;    /* [[section]] vs [section] */

    /* Output policy */
    ak_toml_policy_t *policy;

    /* Error info */
    ak_toml_error_t error;
    char error_msg[256];

} ak_toml_parser_t;

/* ============================================================
 * TOML PARSING API
 * ============================================================ */

/*
 * Initialize a TOML policy structure.
 *
 * @param policy  Policy structure to initialize
 */
void ak_toml_policy_init(ak_toml_policy_t *policy);

/*
 * Parse TOML string into policy structure.
 *
 * @param toml      TOML input string
 * @param toml_len  Length of TOML string
 * @param policy    Output policy structure (must be initialized)
 * @return          AK_TOML_OK on success, error code on failure
 */
ak_toml_error_t ak_toml_parse(
    const char *toml,
    size_t toml_len,
    ak_toml_policy_t *policy
);

/*
 * Parse TOML file into policy structure.
 *
 * @param path      Path to TOML file
 * @param policy    Output policy structure (must be initialized)
 * @return          AK_TOML_OK on success, error code on failure
 */
ak_toml_error_t ak_toml_parse_file(
    const char *path,
    ak_toml_policy_t *policy
);

/*
 * Get error message for last parse error.
 *
 * @param policy    Policy structure after failed parse
 * @return          Error message string (static buffer)
 */
const char *ak_toml_get_error(ak_toml_error_t error);

/* ============================================================
 * JSON EMITTER API
 * ============================================================ */

/*
 * Convert parsed TOML policy to JSON string.
 *
 * The output JSON matches the format expected by ak_policy_v2_load():
 * {
 *   "version": "1.0",
 *   "fs": { "read": [...], "write": [...] },
 *   "net": { "dns": [...], "connect": [...] },
 *   "tools": { "allow": [...], "deny": [...] },
 *   "wasm": { "modules": [...], "hostcalls": [...] },
 *   "infer": { "models": [...], "max_tokens": N },
 *   "budgets": { ... },
 *   "profiles": [...]
 * }
 *
 * @param policy        Parsed TOML policy
 * @param json_out      Output buffer for JSON
 * @param json_max_len  Size of output buffer
 * @param json_len_out  Actual length written (if non-NULL)
 * @return              AK_TOML_OK on success, error code on failure
 */
ak_toml_error_t ak_policy_toml_to_json(
    const ak_toml_policy_t *policy,
    char *json_out,
    size_t json_max_len,
    size_t *json_len_out
);

/*
 * Convert TOML file directly to JSON.
 *
 * Convenience function that combines parsing and conversion.
 *
 * @param toml_path     Path to input TOML file
 * @param json_out      Output buffer for JSON
 * @param json_max_len  Size of output buffer
 * @param json_len_out  Actual length written (if non-NULL)
 * @return              AK_TOML_OK on success, error code on failure
 */
ak_toml_error_t ak_policy_toml_file_to_json(
    const char *toml_path,
    char *json_out,
    size_t json_max_len,
    size_t *json_len_out
);

/* ============================================================
 * UTILITY FUNCTIONS
 * ============================================================ */

/*
 * Validate a parsed policy structure.
 *
 * Checks for:
 *   - Required fields (version)
 *   - Pattern syntax validity
 *   - Budget value sanity
 *
 * @param policy    Policy to validate
 * @return          AK_TOML_OK if valid, error code if invalid
 */
ak_toml_error_t ak_toml_policy_validate(const ak_toml_policy_t *policy);

/*
 * Print policy summary to stdout (for debugging).
 *
 * @param policy    Policy to print
 */
void ak_toml_policy_print(const ak_toml_policy_t *policy);

#endif /* AK_POLICY_TOML_H */
