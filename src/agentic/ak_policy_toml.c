/*
 * Authority Kernel - TOML Policy Compiler Implementation
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * OWNER: Agent B (Policy + Bootstrap)
 *
 * This file implements a simple TOML parser and JSON emitter for
 * converting human-readable ak.toml policy files to JSON format.
 *
 * This is a BUILD-TIME TOOL designed for simplicity over performance.
 * No external dependencies - uses only standard C library.
 */

#include "ak_policy_toml.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* ============================================================
 * INTERNAL HELPER MACROS
 * ============================================================ */

#define TOML_IS_WS(c)       ((c) == ' ' || (c) == '\t')
#define TOML_IS_NEWLINE(c)  ((c) == '\n' || (c) == '\r')
#define TOML_IS_DIGIT(c)    ((c) >= '0' && (c) <= '9')
#define TOML_IS_ALPHA(c)    (((c) >= 'a' && (c) <= 'z') || \
                             ((c) >= 'A' && (c) <= 'Z'))
#define TOML_IS_ALNUM(c)    (TOML_IS_ALPHA(c) || TOML_IS_DIGIT(c))
#define TOML_IS_KEY_CHAR(c) (TOML_IS_ALNUM(c) || (c) == '_' || (c) == '-')

/* ============================================================
 * ERROR MESSAGES
 * ============================================================ */

static const char *ak_toml_error_messages[] = {
    "OK",
    "NULL input",
    "TOML syntax error",
    "Buffer overflow",
    "Unknown configuration key",
    "Type mismatch",
    "Memory allocation failed",
    "I/O error",
    "Too many rules/items",
};

const char *ak_toml_get_error(ak_toml_error_t error)
{
    int idx = -((int)error);
    if (idx < 0 || idx >= (int)(sizeof(ak_toml_error_messages) / sizeof(char *)))
        return "Unknown error";
    return ak_toml_error_messages[idx];
}

/* ============================================================
 * POLICY INITIALIZATION
 * ============================================================ */

void ak_toml_policy_init(ak_toml_policy_t *policy)
{
    if (!policy) return;
    memset(policy, 0, sizeof(ak_toml_policy_t));
    strcpy(policy->version, "1.0");  /* Default version */

    /* Default budgets */
    policy->budgets.wall_time_ms = 300000;   /* 5 minutes */
    policy->budgets.bytes = 100 * 1024 * 1024;  /* 100MB */
    policy->budgets.tokens = 100000;
    policy->budgets.tool_calls = 100;
}

/* ============================================================
 * PARSER HELPERS
 * ============================================================ */

/* Check if at end of input */
static inline bool toml_at_end(ak_toml_parser_t *p)
{
    return p->pos >= p->input_len;
}

/* Peek current character without advancing */
static inline char toml_peek(ak_toml_parser_t *p)
{
    if (toml_at_end(p)) return '\0';
    return p->input[p->pos];
}

/* Peek next character without advancing */
static inline char toml_peek_next(ak_toml_parser_t *p)
{
    if (p->pos + 1 >= p->input_len) return '\0';
    return p->input[p->pos + 1];
}

/* Advance and return current character */
static inline char toml_advance(ak_toml_parser_t *p)
{
    if (toml_at_end(p)) return '\0';
    char c = p->input[p->pos++];
    if (c == '\n') {
        p->line++;
        p->col = 1;
    } else {
        p->col++;
    }
    return c;
}

/* Skip whitespace (not newlines) */
static void toml_skip_ws(ak_toml_parser_t *p)
{
    while (!toml_at_end(p) && TOML_IS_WS(toml_peek(p)))
        toml_advance(p);
}

/* Skip whitespace and newlines */
static void toml_skip_ws_nl(ak_toml_parser_t *p)
{
    while (!toml_at_end(p)) {
        char c = toml_peek(p);
        if (TOML_IS_WS(c) || TOML_IS_NEWLINE(c))
            toml_advance(p);
        else
            break;
    }
}

/* Skip to end of line (for comments) */
static void toml_skip_line(ak_toml_parser_t *p)
{
    while (!toml_at_end(p) && !TOML_IS_NEWLINE(toml_peek(p)))
        toml_advance(p);
    if (!toml_at_end(p))
        toml_advance(p);  /* Consume newline */
}

/* Skip comment if present */
static void toml_skip_comment(ak_toml_parser_t *p)
{
    toml_skip_ws(p);
    if (toml_peek(p) == '#')
        toml_skip_line(p);
}

/* Skip empty lines and comments */
static void toml_skip_empty(ak_toml_parser_t *p)
{
    while (!toml_at_end(p)) {
        toml_skip_ws(p);
        char c = toml_peek(p);
        if (c == '#') {
            toml_skip_line(p);
        } else if (TOML_IS_NEWLINE(c)) {
            toml_advance(p);
        } else {
            break;
        }
    }
}

/* Set parser error */
static void toml_set_error(ak_toml_parser_t *p, ak_toml_error_t err, const char *msg)
{
    p->error = err;
    snprintf(p->error_msg, sizeof(p->error_msg),
             "Line %d, col %d: %s", p->line, p->col, msg);
}

/* ============================================================
 * VALUE PARSING
 * ============================================================ */

/* Parse bare key (unquoted) */
static bool toml_parse_bare_key(ak_toml_parser_t *p, char *out, size_t max_len)
{
    size_t i = 0;
    while (!toml_at_end(p) && TOML_IS_KEY_CHAR(toml_peek(p))) {
        if (i >= max_len - 1) {
            toml_set_error(p, AK_TOML_ERR_OVERFLOW, "Key too long");
            return false;
        }
        out[i++] = toml_advance(p);
    }
    out[i] = '\0';
    return i > 0;
}

/* Parse quoted string */
static bool toml_parse_string(ak_toml_parser_t *p, char *out, size_t max_len)
{
    char quote = toml_advance(p);  /* Consume opening quote */
    if (quote != '"' && quote != '\'') {
        toml_set_error(p, AK_TOML_ERR_SYNTAX, "Expected string");
        return false;
    }

    /* Check for multi-line string (""" or ''') */
    bool multiline = false;
    if (toml_peek(p) == quote && toml_peek_next(p) == quote) {
        toml_advance(p);
        toml_advance(p);
        multiline = true;
        /* Skip immediate newline after opening quotes */
        if (toml_peek(p) == '\n') toml_advance(p);
        else if (toml_peek(p) == '\r') {
            toml_advance(p);
            if (toml_peek(p) == '\n') toml_advance(p);
        }
    }

    size_t i = 0;
    while (!toml_at_end(p)) {
        char c = toml_peek(p);

        /* Check for end of string */
        if (multiline) {
            if (c == quote && toml_peek_next(p) == quote) {
                /* Check for third quote */
                size_t saved_pos = p->pos;
                toml_advance(p);
                toml_advance(p);
                if (toml_peek(p) == quote) {
                    toml_advance(p);
                    break;
                }
                /* Not end, restore and continue */
                p->pos = saved_pos;
            }
        } else {
            if (c == quote) {
                toml_advance(p);
                break;
            }
            if (TOML_IS_NEWLINE(c)) {
                toml_set_error(p, AK_TOML_ERR_SYNTAX, "Unterminated string");
                return false;
            }
        }

        /* Handle escape sequences (double-quoted strings only) */
        if (c == '\\' && quote == '"') {
            toml_advance(p);
            c = toml_advance(p);
            switch (c) {
                case 'n':  c = '\n'; break;
                case 't':  c = '\t'; break;
                case 'r':  c = '\r'; break;
                case '\\': c = '\\'; break;
                case '"':  c = '"';  break;
                case '\'': c = '\''; break;
                case '0':  c = '\0'; break;
                default:
                    toml_set_error(p, AK_TOML_ERR_SYNTAX, "Invalid escape sequence");
                    return false;
            }
        } else {
            toml_advance(p);
        }

        if (i >= max_len - 1) {
            toml_set_error(p, AK_TOML_ERR_OVERFLOW, "String too long");
            return false;
        }
        out[i++] = c;
    }
    out[i] = '\0';
    return true;
}

/* Parse integer */
static bool toml_parse_integer(ak_toml_parser_t *p, int64_t *out)
{
    bool negative = false;
    if (toml_peek(p) == '-') {
        negative = true;
        toml_advance(p);
    } else if (toml_peek(p) == '+') {
        toml_advance(p);
    }

    if (!TOML_IS_DIGIT(toml_peek(p))) {
        toml_set_error(p, AK_TOML_ERR_SYNTAX, "Expected integer");
        return false;
    }

    int64_t val = 0;
    while (!toml_at_end(p) && TOML_IS_DIGIT(toml_peek(p))) {
        val = val * 10 + (toml_advance(p) - '0');
    }

    *out = negative ? -val : val;
    return true;
}

/* Parse boolean */
static bool toml_parse_boolean(ak_toml_parser_t *p, bool *out)
{
    if (strncmp(&p->input[p->pos], "true", 4) == 0 &&
        !TOML_IS_ALNUM(p->input[p->pos + 4])) {
        p->pos += 4;
        p->col += 4;
        *out = true;
        return true;
    }
    if (strncmp(&p->input[p->pos], "false", 5) == 0 &&
        !TOML_IS_ALNUM(p->input[p->pos + 5])) {
        p->pos += 5;
        p->col += 5;
        *out = false;
        return true;
    }
    toml_set_error(p, AK_TOML_ERR_SYNTAX, "Expected boolean");
    return false;
}

/* ============================================================
 * SECTION PARSING
 * ============================================================ */

/* Parse section header: [section] or [[array.section]] */
static bool toml_parse_section(ak_toml_parser_t *p)
{
    if (toml_peek(p) != '[') return false;
    toml_advance(p);

    /* Check for array table [[...]] */
    p->in_array_table = false;
    if (toml_peek(p) == '[') {
        p->in_array_table = true;
        toml_advance(p);
    }

    toml_skip_ws(p);

    /* Parse section name */
    size_t i = 0;
    while (!toml_at_end(p) && toml_peek(p) != ']') {
        char c = toml_advance(p);
        if (i >= AK_TOML_MAX_SECTION - 1) {
            toml_set_error(p, AK_TOML_ERR_OVERFLOW, "Section name too long");
            return false;
        }
        p->section[i++] = c;
    }

    /* Trim trailing whitespace */
    while (i > 0 && TOML_IS_WS(p->section[i - 1])) i--;
    p->section[i] = '\0';

    /* Consume closing bracket(s) */
    if (toml_peek(p) != ']') {
        toml_set_error(p, AK_TOML_ERR_SYNTAX, "Expected ']'");
        return false;
    }
    toml_advance(p);

    if (p->in_array_table) {
        if (toml_peek(p) != ']') {
            toml_set_error(p, AK_TOML_ERR_SYNTAX, "Expected ']]'");
            return false;
        }
        toml_advance(p);
    }

    toml_skip_comment(p);
    return true;
}

/* ============================================================
 * KEY-VALUE PARSING
 * ============================================================ */

/* Parse key and value, add to policy based on current section */
static bool toml_parse_keyval(ak_toml_parser_t *p)
{
    char key[AK_TOML_MAX_KEY];
    char strval[AK_TOML_MAX_VALUE];
    int64_t intval = 0;
    bool boolval = false;

    /* Parse key */
    if (toml_peek(p) == '"' || toml_peek(p) == '\'') {
        if (!toml_parse_string(p, key, sizeof(key))) return false;
    } else {
        if (!toml_parse_bare_key(p, key, sizeof(key))) {
            toml_set_error(p, AK_TOML_ERR_SYNTAX, "Expected key");
            return false;
        }
    }

    toml_skip_ws(p);

    /* Expect '=' */
    if (toml_peek(p) != '=') {
        toml_set_error(p, AK_TOML_ERR_SYNTAX, "Expected '='");
        return false;
    }
    toml_advance(p);

    toml_skip_ws(p);

    /* Determine value type and parse */
    ak_toml_type_t val_type = AK_TOML_TYPE_NONE;
    char c = toml_peek(p);

    if (c == '"' || c == '\'') {
        val_type = AK_TOML_TYPE_STRING;
        if (!toml_parse_string(p, strval, sizeof(strval))) return false;
    } else if (c == '-' || c == '+' || TOML_IS_DIGIT(c)) {
        val_type = AK_TOML_TYPE_INTEGER;
        if (!toml_parse_integer(p, &intval)) return false;
    } else if (c == 't' || c == 'f') {
        val_type = AK_TOML_TYPE_BOOLEAN;
        if (!toml_parse_boolean(p, &boolval)) return false;
    } else if (c == '[') {
        /* Arrays in key-value context are not supported by this policy parser.
         * The policy format uses TOML array tables ([[section]]) for lists
         * of rules, not inline arrays. This keeps the parser simple and
         * encourages clear policy structure. */
        toml_set_error(p, AK_TOML_ERR_SYNTAX, "Arrays not supported in key-value context");
        return false;
    } else {
        toml_set_error(p, AK_TOML_ERR_SYNTAX, "Invalid value");
        return false;
    }

    toml_skip_comment(p);

    /* Store value based on section context */
    ak_toml_policy_t *pol = p->policy;

    /* [policy] section */
    if (strcmp(p->section, "policy") == 0) {
        if (strcmp(key, "version") == 0 && val_type == AK_TOML_TYPE_STRING) {
            strncpy(pol->version, strval, sizeof(pol->version) - 1);
        } else if (strcmp(key, "name") == 0 && val_type == AK_TOML_TYPE_STRING) {
            strncpy(pol->name, strval, sizeof(pol->name) - 1);
        }
        return true;
    }

    /* [[fs.allow]] section */
    if (strcmp(p->section, "fs.allow") == 0) {
        if (pol->fs_rule_count == 0 || !p->in_array_table) {
            if (pol->fs_rule_count >= AK_TOML_MAX_RULES) {
                toml_set_error(p, AK_TOML_ERR_TOO_MANY, "Too many fs rules");
                return false;
            }
        }
        int idx = pol->fs_rule_count > 0 ? pol->fs_rule_count - 1 : 0;
        if (strcmp(key, "path") == 0 && val_type == AK_TOML_TYPE_STRING) {
            /* New rule starts with path */
            if (pol->fs_rules[idx].path[0] != '\0') {
                /* Already have a rule, start new one */
                pol->fs_rule_count++;
                if (pol->fs_rule_count >= AK_TOML_MAX_RULES) {
                    toml_set_error(p, AK_TOML_ERR_TOO_MANY, "Too many fs rules");
                    return false;
                }
                idx = pol->fs_rule_count - 1;
                memset(&pol->fs_rules[idx], 0, sizeof(ak_toml_fs_rule_t));
            }
            strncpy(pol->fs_rules[idx].path, strval, sizeof(pol->fs_rules[idx].path) - 1);
            if (pol->fs_rule_count == 0) pol->fs_rule_count = 1;
        } else if (strcmp(key, "read") == 0 && val_type == AK_TOML_TYPE_BOOLEAN) {
            pol->fs_rules[idx].read = boolval;
        } else if (strcmp(key, "write") == 0 && val_type == AK_TOML_TYPE_BOOLEAN) {
            pol->fs_rules[idx].write = boolval;
        }
        return true;
    }

    /* [[net.allow]] section */
    if (strcmp(p->section, "net.allow") == 0) {
        int idx = pol->net_rule_count > 0 ? pol->net_rule_count - 1 : 0;
        if (strcmp(key, "pattern") == 0 && val_type == AK_TOML_TYPE_STRING) {
            if (pol->net_rules[idx].pattern[0] != '\0') {
                pol->net_rule_count++;
                if (pol->net_rule_count >= AK_TOML_MAX_RULES) {
                    toml_set_error(p, AK_TOML_ERR_TOO_MANY, "Too many net rules");
                    return false;
                }
                idx = pol->net_rule_count - 1;
                memset(&pol->net_rules[idx], 0, sizeof(ak_toml_net_rule_t));
            }
            strncpy(pol->net_rules[idx].pattern, strval, sizeof(pol->net_rules[idx].pattern) - 1);
            if (pol->net_rule_count == 0) pol->net_rule_count = 1;
        } else if (strcmp(key, "connect") == 0 && val_type == AK_TOML_TYPE_BOOLEAN) {
            pol->net_rules[idx].connect = boolval;
        } else if (strcmp(key, "bind") == 0 && val_type == AK_TOML_TYPE_BOOLEAN) {
            pol->net_rules[idx].bind = boolval;
        } else if (strcmp(key, "listen") == 0 && val_type == AK_TOML_TYPE_BOOLEAN) {
            pol->net_rules[idx].listen = boolval;
        }
        return true;
    }

    /* [[dns.allow]] section */
    if (strcmp(p->section, "dns.allow") == 0) {
        int idx = pol->dns_rule_count > 0 ? pol->dns_rule_count - 1 : 0;
        if (strcmp(key, "pattern") == 0 && val_type == AK_TOML_TYPE_STRING) {
            if (pol->dns_rules[idx].pattern[0] != '\0') {
                pol->dns_rule_count++;
                if (pol->dns_rule_count >= AK_TOML_MAX_RULES) {
                    toml_set_error(p, AK_TOML_ERR_TOO_MANY, "Too many dns rules");
                    return false;
                }
                idx = pol->dns_rule_count - 1;
                memset(&pol->dns_rules[idx], 0, sizeof(ak_toml_dns_rule_t));
            }
            strncpy(pol->dns_rules[idx].pattern, strval, sizeof(pol->dns_rules[idx].pattern) - 1);
            pol->dns_rules[idx].allow = true;  /* Default for dns.allow */
            if (pol->dns_rule_count == 0) pol->dns_rule_count = 1;
        }
        return true;
    }

    /* [[tools.allow]] section */
    if (strcmp(p->section, "tools.allow") == 0) {
        int idx = pol->tool_allow_count > 0 ? pol->tool_allow_count - 1 : 0;
        if (strcmp(key, "name") == 0 && val_type == AK_TOML_TYPE_STRING) {
            if (pol->tool_allow_rules[idx].name[0] != '\0') {
                pol->tool_allow_count++;
                if (pol->tool_allow_count >= AK_TOML_MAX_RULES) {
                    toml_set_error(p, AK_TOML_ERR_TOO_MANY, "Too many tool rules");
                    return false;
                }
                idx = pol->tool_allow_count - 1;
                memset(&pol->tool_allow_rules[idx], 0, sizeof(ak_toml_tool_rule_t));
            }
            strncpy(pol->tool_allow_rules[idx].name, strval, sizeof(pol->tool_allow_rules[idx].name) - 1);
            pol->tool_allow_rules[idx].allow = true;
            if (pol->tool_allow_count == 0) pol->tool_allow_count = 1;
        } else if (strcmp(key, "version") == 0 && val_type == AK_TOML_TYPE_STRING) {
            strncpy(pol->tool_allow_rules[idx].version, strval, sizeof(pol->tool_allow_rules[idx].version) - 1);
        }
        return true;
    }

    /* [[tools.deny]] section */
    if (strcmp(p->section, "tools.deny") == 0) {
        int idx = pol->tool_deny_count > 0 ? pol->tool_deny_count - 1 : 0;
        if (strcmp(key, "name") == 0 && val_type == AK_TOML_TYPE_STRING) {
            if (pol->tool_deny_rules[idx].name[0] != '\0') {
                pol->tool_deny_count++;
                if (pol->tool_deny_count >= AK_TOML_MAX_RULES) {
                    toml_set_error(p, AK_TOML_ERR_TOO_MANY, "Too many tool deny rules");
                    return false;
                }
                idx = pol->tool_deny_count - 1;
                memset(&pol->tool_deny_rules[idx], 0, sizeof(ak_toml_tool_rule_t));
            }
            strncpy(pol->tool_deny_rules[idx].name, strval, sizeof(pol->tool_deny_rules[idx].name) - 1);
            pol->tool_deny_rules[idx].allow = false;
            if (pol->tool_deny_count == 0) pol->tool_deny_count = 1;
        }
        return true;
    }

    /* [[wasm.allow]] section */
    if (strcmp(p->section, "wasm.allow") == 0) {
        int idx = pol->wasm_rule_count > 0 ? pol->wasm_rule_count - 1 : 0;
        if (strcmp(key, "module") == 0 && val_type == AK_TOML_TYPE_STRING) {
            if (pol->wasm_rules[idx].module[0] != '\0') {
                pol->wasm_rule_count++;
                if (pol->wasm_rule_count >= AK_TOML_MAX_RULES) {
                    toml_set_error(p, AK_TOML_ERR_TOO_MANY, "Too many wasm rules");
                    return false;
                }
                idx = pol->wasm_rule_count - 1;
                memset(&pol->wasm_rules[idx], 0, sizeof(ak_toml_wasm_rule_t));
            }
            strncpy(pol->wasm_rules[idx].module, strval, sizeof(pol->wasm_rules[idx].module) - 1);
            if (pol->wasm_rule_count == 0) pol->wasm_rule_count = 1;
        }
        return true;
    }

    /* [[inference.allow]] section */
    if (strcmp(p->section, "inference.allow") == 0) {
        int idx = pol->infer_rule_count > 0 ? pol->infer_rule_count - 1 : 0;
        if (strcmp(key, "model") == 0 && val_type == AK_TOML_TYPE_STRING) {
            if (pol->infer_rules[idx].model[0] != '\0') {
                pol->infer_rule_count++;
                if (pol->infer_rule_count >= AK_TOML_MAX_RULES) {
                    toml_set_error(p, AK_TOML_ERR_TOO_MANY, "Too many inference rules");
                    return false;
                }
                idx = pol->infer_rule_count - 1;
                memset(&pol->infer_rules[idx], 0, sizeof(ak_toml_infer_rule_t));
            }
            strncpy(pol->infer_rules[idx].model, strval, sizeof(pol->infer_rules[idx].model) - 1);
            pol->infer_rules[idx].max_tokens = 100000;  /* Default */
            if (pol->infer_rule_count == 0) pol->infer_rule_count = 1;
        } else if (strcmp(key, "max_tokens") == 0 && val_type == AK_TOML_TYPE_INTEGER) {
            pol->infer_rules[idx].max_tokens = (uint64_t)intval;
        }
        return true;
    }

    /* [budgets] section */
    if (strcmp(p->section, "budgets") == 0) {
        pol->has_budgets = true;
        if (strcmp(key, "cpu_ns") == 0 && val_type == AK_TOML_TYPE_INTEGER) {
            pol->budgets.cpu_ns = (uint64_t)intval;
        } else if (strcmp(key, "wall_time_ms") == 0 && val_type == AK_TOML_TYPE_INTEGER) {
            pol->budgets.wall_time_ms = (uint64_t)intval;
        } else if (strcmp(key, "bytes") == 0 && val_type == AK_TOML_TYPE_INTEGER) {
            pol->budgets.bytes = (uint64_t)intval;
        } else if (strcmp(key, "tokens") == 0 && val_type == AK_TOML_TYPE_INTEGER) {
            pol->budgets.tokens = (uint64_t)intval;
        } else if (strcmp(key, "tool_calls") == 0 && val_type == AK_TOML_TYPE_INTEGER) {
            pol->budgets.tool_calls = (uint64_t)intval;
        }
        return true;
    }

    /* Unknown section/key - ignore for forward compatibility */
    return true;
}

/* ============================================================
 * MAIN PARSER
 * ============================================================ */

ak_toml_error_t ak_toml_parse(
    const char *toml,
    size_t toml_len,
    ak_toml_policy_t *policy)
{
    if (!toml || !policy)
        return AK_TOML_ERR_NULL;

    ak_toml_parser_t parser = {
        .input = toml,
        .input_len = toml_len,
        .pos = 0,
        .line = 1,
        .col = 1,
        .section = "",
        .in_array_table = false,
        .policy = policy,
        .error = AK_TOML_OK,
        .error_msg = ""
    };
    ak_toml_parser_t *p = &parser;

    while (!toml_at_end(p)) {
        toml_skip_empty(p);

        if (toml_at_end(p)) break;

        char c = toml_peek(p);

        if (c == '[') {
            /* Section header */
            if (!toml_parse_section(p)) {
                return p->error;
            }
        } else if (TOML_IS_KEY_CHAR(c) || c == '"' || c == '\'') {
            /* Key-value pair */
            if (!toml_parse_keyval(p)) {
                return p->error;
            }
        } else if (c == '#') {
            /* Comment */
            toml_skip_line(p);
        } else if (TOML_IS_NEWLINE(c)) {
            toml_advance(p);
        } else {
            toml_set_error(p, AK_TOML_ERR_SYNTAX, "Unexpected character");
            return p->error;
        }
    }

    return AK_TOML_OK;
}

/* ============================================================
 * FILE PARSING
 * ============================================================ */

ak_toml_error_t ak_toml_parse_file(
    const char *path,
    ak_toml_policy_t *policy)
{
    if (!path || !policy)
        return AK_TOML_ERR_NULL;

    FILE *f = fopen(path, "r");
    if (!f)
        return AK_TOML_ERR_IO;

    /* Get file size */
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size < 0 || size > 1024 * 1024) {  /* Max 1MB */
        fclose(f);
        return AK_TOML_ERR_OVERFLOW;
    }

    /* Read file */
    char *buf = malloc((size_t)size + 1);
    if (!buf) {
        fclose(f);
        return AK_TOML_ERR_ALLOC;
    }

    size_t read_size = fread(buf, 1, (size_t)size, f);
    fclose(f);
    buf[read_size] = '\0';

    /* Parse */
    ak_toml_error_t err = ak_toml_parse(buf, read_size, policy);
    free(buf);

    return err;
}

/* ============================================================
 * JSON EMITTER
 * ============================================================ */

/* Helper to append string to buffer with bounds checking */
static bool json_append(char **out, size_t *remain, const char *str)
{
    size_t len = strlen(str);
    if (len >= *remain)
        return false;
    memcpy(*out, str, len);
    *out += len;
    *remain -= len;
    return true;
}

/* Helper to append quoted JSON string */
static bool json_append_quoted(char **out, size_t *remain, const char *str)
{
    if (*remain < 3) return false;
    *(*out)++ = '"';
    (*remain)--;

    while (*str) {
        char c = *str++;
        if (c == '"' || c == '\\') {
            if (*remain < 3) return false;
            *(*out)++ = '\\';
            (*remain)--;
        }
        if (*remain < 2) return false;
        *(*out)++ = c;
        (*remain)--;
    }

    *(*out)++ = '"';
    (*remain)--;
    return true;
}

/* Helper to append integer */
static bool json_append_int(char **out, size_t *remain, uint64_t val)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "%lu", (unsigned long)val);
    return json_append(out, remain, buf);
}

ak_toml_error_t ak_policy_toml_to_json(
    const ak_toml_policy_t *policy,
    char *json_out,
    size_t json_max_len,
    size_t *json_len_out)
{
    if (!policy || !json_out || json_max_len < 100)
        return AK_TOML_ERR_NULL;

    char *out = json_out;
    size_t remain = json_max_len - 1;  /* Leave room for null */

    /* Start object */
    if (!json_append(&out, &remain, "{\n"))
        return AK_TOML_ERR_OVERFLOW;

    /* Version */
    if (!json_append(&out, &remain, "  \"version\": "))
        return AK_TOML_ERR_OVERFLOW;
    if (!json_append_quoted(&out, &remain, policy->version))
        return AK_TOML_ERR_OVERFLOW;

    /* Filesystem rules */
    if (policy->fs_rule_count > 0) {
        if (!json_append(&out, &remain, ",\n  \"fs\": {\n"))
            return AK_TOML_ERR_OVERFLOW;

        /* Collect read paths */
        bool has_read = false;
        for (int i = 0; i < policy->fs_rule_count; i++) {
            if (policy->fs_rules[i].read) {
                has_read = true;
                break;
            }
        }

        if (has_read) {
            if (!json_append(&out, &remain, "    \"read\": ["))
                return AK_TOML_ERR_OVERFLOW;
            bool first = true;
            for (int i = 0; i < policy->fs_rule_count; i++) {
                if (policy->fs_rules[i].read) {
                    if (!first && !json_append(&out, &remain, ", "))
                        return AK_TOML_ERR_OVERFLOW;
                    if (!json_append_quoted(&out, &remain, policy->fs_rules[i].path))
                        return AK_TOML_ERR_OVERFLOW;
                    first = false;
                }
            }
            if (!json_append(&out, &remain, "]"))
                return AK_TOML_ERR_OVERFLOW;
        }

        /* Collect write paths */
        bool has_write = false;
        for (int i = 0; i < policy->fs_rule_count; i++) {
            if (policy->fs_rules[i].write) {
                has_write = true;
                break;
            }
        }

        if (has_write) {
            if (has_read && !json_append(&out, &remain, ",\n"))
                return AK_TOML_ERR_OVERFLOW;
            if (!json_append(&out, &remain, "    \"write\": ["))
                return AK_TOML_ERR_OVERFLOW;
            bool first = true;
            for (int i = 0; i < policy->fs_rule_count; i++) {
                if (policy->fs_rules[i].write) {
                    if (!first && !json_append(&out, &remain, ", "))
                        return AK_TOML_ERR_OVERFLOW;
                    if (!json_append_quoted(&out, &remain, policy->fs_rules[i].path))
                        return AK_TOML_ERR_OVERFLOW;
                    first = false;
                }
            }
            if (!json_append(&out, &remain, "]"))
                return AK_TOML_ERR_OVERFLOW;
        }

        if (!json_append(&out, &remain, "\n  }"))
            return AK_TOML_ERR_OVERFLOW;
    }

    /* Network rules */
    if (policy->net_rule_count > 0 || policy->dns_rule_count > 0) {
        if (!json_append(&out, &remain, ",\n  \"net\": {\n"))
            return AK_TOML_ERR_OVERFLOW;

        bool has_prev = false;

        /* DNS rules */
        if (policy->dns_rule_count > 0) {
            if (!json_append(&out, &remain, "    \"dns\": ["))
                return AK_TOML_ERR_OVERFLOW;
            for (int i = 0; i < policy->dns_rule_count; i++) {
                if (i > 0 && !json_append(&out, &remain, ", "))
                    return AK_TOML_ERR_OVERFLOW;
                if (!json_append_quoted(&out, &remain, policy->dns_rules[i].pattern))
                    return AK_TOML_ERR_OVERFLOW;
            }
            if (!json_append(&out, &remain, "]"))
                return AK_TOML_ERR_OVERFLOW;
            has_prev = true;
        }

        /* Connect rules */
        bool has_connect = false;
        for (int i = 0; i < policy->net_rule_count; i++) {
            if (policy->net_rules[i].connect) {
                has_connect = true;
                break;
            }
        }
        if (has_connect) {
            if (has_prev && !json_append(&out, &remain, ",\n"))
                return AK_TOML_ERR_OVERFLOW;
            if (!json_append(&out, &remain, "    \"connect\": ["))
                return AK_TOML_ERR_OVERFLOW;
            bool first = true;
            for (int i = 0; i < policy->net_rule_count; i++) {
                if (policy->net_rules[i].connect) {
                    if (!first && !json_append(&out, &remain, ", "))
                        return AK_TOML_ERR_OVERFLOW;
                    /* Format as dns:pattern for compatibility */
                    if (!json_append(&out, &remain, "\"dns:"))
                        return AK_TOML_ERR_OVERFLOW;
                    /* Escape and append pattern */
                    const char *pat = policy->net_rules[i].pattern;
                    while (*pat) {
                        if (*pat == '"' || *pat == '\\') {
                            if (remain < 2) return AK_TOML_ERR_OVERFLOW;
                            *out++ = '\\';
                            remain--;
                        }
                        if (remain < 2) return AK_TOML_ERR_OVERFLOW;
                        *out++ = *pat++;
                        remain--;
                    }
                    if (!json_append(&out, &remain, "\""))
                        return AK_TOML_ERR_OVERFLOW;
                    first = false;
                }
            }
            if (!json_append(&out, &remain, "]"))
                return AK_TOML_ERR_OVERFLOW;
        }

        if (!json_append(&out, &remain, "\n  }"))
            return AK_TOML_ERR_OVERFLOW;
    }

    /* Tool rules */
    if (policy->tool_allow_count > 0 || policy->tool_deny_count > 0) {
        if (!json_append(&out, &remain, ",\n  \"tools\": {\n"))
            return AK_TOML_ERR_OVERFLOW;

        bool has_prev = false;

        if (policy->tool_allow_count > 0) {
            if (!json_append(&out, &remain, "    \"allow\": ["))
                return AK_TOML_ERR_OVERFLOW;
            for (int i = 0; i < policy->tool_allow_count; i++) {
                if (i > 0 && !json_append(&out, &remain, ", "))
                    return AK_TOML_ERR_OVERFLOW;
                if (!json_append_quoted(&out, &remain, policy->tool_allow_rules[i].name))
                    return AK_TOML_ERR_OVERFLOW;
            }
            if (!json_append(&out, &remain, "]"))
                return AK_TOML_ERR_OVERFLOW;
            has_prev = true;
        }

        if (policy->tool_deny_count > 0) {
            if (has_prev && !json_append(&out, &remain, ",\n"))
                return AK_TOML_ERR_OVERFLOW;
            if (!json_append(&out, &remain, "    \"deny\": ["))
                return AK_TOML_ERR_OVERFLOW;
            for (int i = 0; i < policy->tool_deny_count; i++) {
                if (i > 0 && !json_append(&out, &remain, ", "))
                    return AK_TOML_ERR_OVERFLOW;
                if (!json_append_quoted(&out, &remain, policy->tool_deny_rules[i].name))
                    return AK_TOML_ERR_OVERFLOW;
            }
            if (!json_append(&out, &remain, "]"))
                return AK_TOML_ERR_OVERFLOW;
        }

        if (!json_append(&out, &remain, "\n  }"))
            return AK_TOML_ERR_OVERFLOW;
    }

    /* WASM rules */
    if (policy->wasm_rule_count > 0) {
        if (!json_append(&out, &remain, ",\n  \"wasm\": {\n"))
            return AK_TOML_ERR_OVERFLOW;

        if (!json_append(&out, &remain, "    \"modules\": ["))
            return AK_TOML_ERR_OVERFLOW;
        for (int i = 0; i < policy->wasm_rule_count; i++) {
            if (i > 0 && !json_append(&out, &remain, ", "))
                return AK_TOML_ERR_OVERFLOW;
            if (!json_append_quoted(&out, &remain, policy->wasm_rules[i].module))
                return AK_TOML_ERR_OVERFLOW;
        }
        if (!json_append(&out, &remain, "]"))
            return AK_TOML_ERR_OVERFLOW;

        if (!json_append(&out, &remain, "\n  }"))
            return AK_TOML_ERR_OVERFLOW;
    }

    /* Inference rules */
    if (policy->infer_rule_count > 0) {
        if (!json_append(&out, &remain, ",\n  \"infer\": {\n"))
            return AK_TOML_ERR_OVERFLOW;

        if (!json_append(&out, &remain, "    \"models\": ["))
            return AK_TOML_ERR_OVERFLOW;
        for (int i = 0; i < policy->infer_rule_count; i++) {
            if (i > 0 && !json_append(&out, &remain, ", "))
                return AK_TOML_ERR_OVERFLOW;
            if (!json_append_quoted(&out, &remain, policy->infer_rules[i].model))
                return AK_TOML_ERR_OVERFLOW;
        }
        if (!json_append(&out, &remain, "],\n"))
            return AK_TOML_ERR_OVERFLOW;

        /* Use max_tokens from first rule as global default */
        if (!json_append(&out, &remain, "    \"max_tokens\": "))
            return AK_TOML_ERR_OVERFLOW;
        if (!json_append_int(&out, &remain, policy->infer_rules[0].max_tokens))
            return AK_TOML_ERR_OVERFLOW;

        if (!json_append(&out, &remain, "\n  }"))
            return AK_TOML_ERR_OVERFLOW;
    }

    /* Budgets */
    if (policy->has_budgets) {
        if (!json_append(&out, &remain, ",\n  \"budgets\": {\n"))
            return AK_TOML_ERR_OVERFLOW;

        bool has_prev = false;

        if (policy->budgets.tool_calls > 0) {
            if (!json_append(&out, &remain, "    \"tool_calls\": "))
                return AK_TOML_ERR_OVERFLOW;
            if (!json_append_int(&out, &remain, policy->budgets.tool_calls))
                return AK_TOML_ERR_OVERFLOW;
            has_prev = true;
        }

        if (policy->budgets.tokens > 0) {
            if (has_prev && !json_append(&out, &remain, ",\n"))
                return AK_TOML_ERR_OVERFLOW;
            if (!json_append(&out, &remain, "    \"tokens\": "))
                return AK_TOML_ERR_OVERFLOW;
            if (!json_append_int(&out, &remain, policy->budgets.tokens))
                return AK_TOML_ERR_OVERFLOW;
            has_prev = true;
        }

        if (policy->budgets.wall_time_ms > 0) {
            if (has_prev && !json_append(&out, &remain, ",\n"))
                return AK_TOML_ERR_OVERFLOW;
            if (!json_append(&out, &remain, "    \"wall_time_ms\": "))
                return AK_TOML_ERR_OVERFLOW;
            if (!json_append_int(&out, &remain, policy->budgets.wall_time_ms))
                return AK_TOML_ERR_OVERFLOW;
            has_prev = true;
        }

        if (policy->budgets.cpu_ns > 0) {
            if (has_prev && !json_append(&out, &remain, ",\n"))
                return AK_TOML_ERR_OVERFLOW;
            if (!json_append(&out, &remain, "    \"cpu_time_ns\": "))
                return AK_TOML_ERR_OVERFLOW;
            if (!json_append_int(&out, &remain, policy->budgets.cpu_ns))
                return AK_TOML_ERR_OVERFLOW;
            has_prev = true;
        }

        if (policy->budgets.bytes > 0) {
            if (has_prev && !json_append(&out, &remain, ",\n"))
                return AK_TOML_ERR_OVERFLOW;
            if (!json_append(&out, &remain, "    \"bytes\": "))
                return AK_TOML_ERR_OVERFLOW;
            if (!json_append_int(&out, &remain, policy->budgets.bytes))
                return AK_TOML_ERR_OVERFLOW;
        }

        if (!json_append(&out, &remain, "\n  }"))
            return AK_TOML_ERR_OVERFLOW;
    }

    /* Profiles */
    if (policy->profile_count > 0) {
        if (!json_append(&out, &remain, ",\n  \"profiles\": ["))
            return AK_TOML_ERR_OVERFLOW;
        for (int i = 0; i < policy->profile_count; i++) {
            if (i > 0 && !json_append(&out, &remain, ", "))
                return AK_TOML_ERR_OVERFLOW;
            if (!json_append_quoted(&out, &remain, policy->profiles[i]))
                return AK_TOML_ERR_OVERFLOW;
        }
        if (!json_append(&out, &remain, "]"))
            return AK_TOML_ERR_OVERFLOW;
    }

    /* End object */
    if (!json_append(&out, &remain, "\n}\n"))
        return AK_TOML_ERR_OVERFLOW;

    *out = '\0';

    if (json_len_out)
        *json_len_out = (size_t)(out - json_out);

    return AK_TOML_OK;
}

/* ============================================================
 * CONVENIENCE FUNCTIONS
 * ============================================================ */

ak_toml_error_t ak_policy_toml_file_to_json(
    const char *toml_path,
    char *json_out,
    size_t json_max_len,
    size_t *json_len_out)
{
    ak_toml_policy_t policy;
    ak_toml_policy_init(&policy);

    ak_toml_error_t err = ak_toml_parse_file(toml_path, &policy);
    if (err != AK_TOML_OK)
        return err;

    return ak_policy_toml_to_json(&policy, json_out, json_max_len, json_len_out);
}

ak_toml_error_t ak_toml_policy_validate(const ak_toml_policy_t *policy)
{
    if (!policy)
        return AK_TOML_ERR_NULL;

    /* Check version is present */
    if (policy->version[0] == '\0')
        return AK_TOML_ERR_SYNTAX;

    /* Basic sanity checks on budgets */
    if (policy->budgets.tool_calls > 1000000)
        return AK_TOML_ERR_OVERFLOW;

    return AK_TOML_OK;
}

void ak_toml_policy_print(const ak_toml_policy_t *policy)
{
    if (!policy) {
        printf("Policy: NULL\n");
        return;
    }

    printf("Policy:\n");
    printf("  Version: %s\n", policy->version);
    printf("  Name: %s\n", policy->name[0] ? policy->name : "(none)");

    printf("  FS Rules: %d\n", policy->fs_rule_count);
    for (int i = 0; i < policy->fs_rule_count; i++) {
        printf("    [%d] path=%s read=%d write=%d\n",
               i, policy->fs_rules[i].path,
               policy->fs_rules[i].read, policy->fs_rules[i].write);
    }

    printf("  Net Rules: %d\n", policy->net_rule_count);
    for (int i = 0; i < policy->net_rule_count; i++) {
        printf("    [%d] pattern=%s connect=%d bind=%d listen=%d\n",
               i, policy->net_rules[i].pattern,
               policy->net_rules[i].connect,
               policy->net_rules[i].bind,
               policy->net_rules[i].listen);
    }

    printf("  DNS Rules: %d\n", policy->dns_rule_count);
    for (int i = 0; i < policy->dns_rule_count; i++) {
        printf("    [%d] pattern=%s\n", i, policy->dns_rules[i].pattern);
    }

    printf("  Tool Allow: %d\n", policy->tool_allow_count);
    for (int i = 0; i < policy->tool_allow_count; i++) {
        printf("    [%d] name=%s version=%s\n",
               i, policy->tool_allow_rules[i].name,
               policy->tool_allow_rules[i].version);
    }

    printf("  Tool Deny: %d\n", policy->tool_deny_count);

    printf("  WASM Rules: %d\n", policy->wasm_rule_count);
    for (int i = 0; i < policy->wasm_rule_count; i++) {
        printf("    [%d] module=%s\n", i, policy->wasm_rules[i].module);
    }

    printf("  Infer Rules: %d\n", policy->infer_rule_count);
    for (int i = 0; i < policy->infer_rule_count; i++) {
        printf("    [%d] model=%s max_tokens=%lu\n",
               i, policy->infer_rules[i].model,
               (unsigned long)policy->infer_rules[i].max_tokens);
    }

    if (policy->has_budgets) {
        printf("  Budgets:\n");
        printf("    tool_calls: %lu\n", (unsigned long)policy->budgets.tool_calls);
        printf("    tokens: %lu\n", (unsigned long)policy->budgets.tokens);
        printf("    wall_time_ms: %lu\n", (unsigned long)policy->budgets.wall_time_ms);
        printf("    bytes: %lu\n", (unsigned long)policy->budgets.bytes);
    }
}

/* ============================================================
 * COMMAND-LINE TOOL (when compiled as standalone)
 * ============================================================ */

#ifdef AK_TOML_STANDALONE

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <policy.toml> [output.json]\n", argv[0]);
        fprintf(stderr, "\nConverts TOML policy to JSON format for Authority Kernel.\n");
        return 1;
    }

    const char *input_path = argv[1];
    const char *output_path = argc > 2 ? argv[2] : NULL;

    ak_toml_policy_t policy;
    ak_toml_policy_init(&policy);

    ak_toml_error_t err = ak_toml_parse_file(input_path, &policy);
    if (err != AK_TOML_OK) {
        fprintf(stderr, "Error parsing %s: %s\n", input_path, ak_toml_get_error(err));
        return 1;
    }

    err = ak_toml_policy_validate(&policy);
    if (err != AK_TOML_OK) {
        fprintf(stderr, "Policy validation failed: %s\n", ak_toml_get_error(err));
        return 1;
    }

    /* Convert to JSON */
    char json_buf[64 * 1024];  /* 64KB should be enough */
    size_t json_len = 0;

    err = ak_policy_toml_to_json(&policy, json_buf, sizeof(json_buf), &json_len);
    if (err != AK_TOML_OK) {
        fprintf(stderr, "Error converting to JSON: %s\n", ak_toml_get_error(err));
        return 1;
    }

    /* Output */
    if (output_path) {
        FILE *out = fopen(output_path, "w");
        if (!out) {
            fprintf(stderr, "Error opening %s for writing\n", output_path);
            return 1;
        }
        fwrite(json_buf, 1, json_len, out);
        fclose(out);
        fprintf(stderr, "Wrote %zu bytes to %s\n", json_len, output_path);
    } else {
        /* Print to stdout */
        printf("%s", json_buf);
    }

    return 0;
}

#endif /* AK_TOML_STANDALONE */
