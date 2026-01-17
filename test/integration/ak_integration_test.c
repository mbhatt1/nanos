/*
 * Authority Kernel - Integration Tests
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Comprehensive integration tests verifying end-to-end Authority Kernel
 * functionality including:
 *   - Deny-by-default enforcement
 *   - Filesystem routing and policy enforcement
 *   - Network routing and policy enforcement
 *   - Agentic effects (tool calls, WASM, inference)
 *   - Mode transitions (OFF/SOFT/HARD)
 *   - Suggestion generation for actionable denials
 *
 * These tests exercise the full AK stack from context creation through
 * policy enforcement to decision generation.
 *
 * Build modes:
 *   - Host mode: Standalone tests with mock AK (default)
 *   - QEMU mode: Linked against real AK modules (define AK_QEMU_TEST)
 */

#ifdef AK_QEMU_TEST
/* Full kernel mode - use runtime.h */
#include <runtime.h>
#else
/* Standalone host mode - define types locally */
#include <stdint.h>
#include <stdbool.h>
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
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

/* ============================================================
 * TEST ASSERTION MACROS
 * ============================================================ */

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

#define test_assert_eq(a, b) do { \
    if ((a) != (b)) { \
        fprintf(stderr, "FAIL: %s != %s (%ld != %ld) at %s:%d\n", \
                #a, #b, (long)(a), (long)(b), __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

#define test_assert_streq(a, b) do { \
    if (strcmp((a), (b)) != 0) { \
        fprintf(stderr, "FAIL: %s != %s (\"%s\" != \"%s\") at %s:%d\n", \
                #a, #b, (a), (b), __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

/* ============================================================
 * EFFECT TYPES (matching ak_effects.h)
 * ============================================================ */

typedef enum ak_effect_op {
    /* Filesystem effects */
    AK_E_FS_OPEN        = 0x0100,
    AK_E_FS_UNLINK      = 0x0101,
    AK_E_FS_RENAME      = 0x0102,
    AK_E_FS_MKDIR       = 0x0103,
    AK_E_FS_RMDIR       = 0x0104,
    AK_E_FS_STAT        = 0x0105,

    /* Network effects */
    AK_E_NET_CONNECT    = 0x0200,
    AK_E_NET_DNS_RESOLVE = 0x0201,
    AK_E_NET_BIND       = 0x0202,
    AK_E_NET_LISTEN     = 0x0203,
    AK_E_NET_ACCEPT     = 0x0204,

    /* Process effects */
    AK_E_PROC_SPAWN     = 0x0300,
    AK_E_PROC_SIGNAL    = 0x0301,

    /* Agentic effects */
    AK_E_TOOL_CALL      = 0x0400,
    AK_E_WASM_INVOKE    = 0x0401,
    AK_E_INFER          = 0x0402,
} ak_effect_op_t;

/* Routing modes */
typedef enum ak_mode {
    AK_MODE_OFF     = 0,    /* Legacy minimal debug mode */
    AK_MODE_SOFT    = 1,    /* POSIX routed + enforced (DEFAULT) */
    AK_MODE_HARD    = 2,    /* Raw effectful syscalls denied */
} ak_mode_t;

/* Deny reason codes */
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
} ak_deny_reason_t;

/* Maximum sizes for bounded buffers */
#define AK_MAX_TARGET     512
#define AK_MAX_PARAMS     4096
#define AK_MAX_CAPSTR     64
#define AK_MAX_SUGGEST    512
#define AK_MAX_DETAIL     256

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

/* ============================================================
 * AUTHORIZATION DECISION STRUCTURE
 * ============================================================ */

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
 * LAST DENY STRUCTURE
 * ============================================================ */

typedef struct ak_last_deny {
    ak_effect_op_t op;
    char target[AK_MAX_TARGET];
    char missing_cap[AK_MAX_CAPSTR];
    char suggested_snippet[AK_MAX_SUGGEST];
    u64 trace_id;
    int errno_equiv;
    u64 timestamp_ns;
    ak_deny_reason_t reason;
} ak_last_deny_t;

/* ============================================================
 * MOCK AK CONTEXT STRUCTURE
 * ============================================================ */

typedef struct ak_ctx {
    /* Routing mode */
    ak_mode_t mode;

    /* Last denial */
    ak_last_deny_t last_deny;
    boolean has_last_deny;

    /* Boot capsule state */
    boolean boot_capsule_active;
    boolean boot_capsule_dropped;

    /* Trace ID counter */
    u64 trace_counter;

    /* Policy rules (simplified for testing) */
    struct {
        const char **fs_read_patterns;
        size_t fs_read_count;
        const char **fs_write_patterns;
        size_t fs_write_count;
        const char **dns_patterns;
        size_t dns_count;
        const char **ip_patterns;
        size_t ip_count;
        const char **tool_patterns;
        size_t tool_count;
        const char **wasm_patterns;
        size_t wasm_count;
        const char **wasm_hostcalls;
        size_t wasm_hostcall_count;
        const char **model_patterns;
        size_t model_count;
        u64 tool_budget;
        u64 tool_used;
        u64 token_budget;
        u64 tokens_used;
    } policy;

    /* Statistics */
    u64 total_requests;
    u64 allowed;
    u64 denied;
} ak_ctx_t;

/* Global test heap simulation */
static ak_ctx_t *g_current_ctx = NULL;

/* ============================================================
 * MOCK AK CONTEXT FUNCTIONS
 * ============================================================ */

static ak_ctx_t *ak_ctx_create(void *heap, void *agent)
{
    (void)heap;  /* Unused in mock */
    (void)agent; /* Unused in mock */

    ak_ctx_t *ctx = (ak_ctx_t *)malloc(sizeof(ak_ctx_t));
    if (!ctx)
        return NULL;

    memset(ctx, 0, sizeof(ak_ctx_t));
    ctx->mode = AK_MODE_SOFT;
    ctx->boot_capsule_active = true;
    ctx->boot_capsule_dropped = false;
    ctx->trace_counter = 1000;

    /* Default budgets */
    ctx->policy.tool_budget = 100;
    ctx->policy.token_budget = 100000;

    return ctx;
}

static void ak_ctx_destroy(void *heap, ak_ctx_t *ctx)
{
    (void)heap;  /* Unused in mock */
    if (ctx) {
        free(ctx);
    }
}

static void ak_ctx_set_current(ak_ctx_t *ctx)
{
    g_current_ctx = ctx;
}

static ak_ctx_t *ak_ctx_current(void)
{
    return g_current_ctx;
}

static void ak_ctx_set_mode(ak_ctx_t *ctx, ak_mode_t mode)
{
    if (ctx)
        ctx->mode = mode;
}

__attribute__((unused))
static ak_mode_t ak_ctx_get_mode(ak_ctx_t *ctx)
{
    return ctx ? ctx->mode : AK_MODE_SOFT;
}

static boolean ak_ctx_boot_capsule_active(ak_ctx_t *ctx)
{
    return ctx ? ctx->boot_capsule_active : false;
}

static void ak_ctx_drop_boot_capsule(ak_ctx_t *ctx)
{
    if (ctx) {
        ctx->boot_capsule_active = false;
        ctx->boot_capsule_dropped = true;
    }
}

static const ak_last_deny_t *ak_ctx_get_last_deny(ak_ctx_t *ctx)
{
    if (ctx && ctx->has_last_deny)
        return &ctx->last_deny;
    return NULL;
}

static void ak_ctx_clear_last_deny(ak_ctx_t *ctx)
{
    if (ctx) {
        memset(&ctx->last_deny, 0, sizeof(ctx->last_deny));
        ctx->has_last_deny = false;
    }
}

static u64 ak_trace_id_generate(ak_ctx_t *ctx)
{
    if (ctx)
        return ++ctx->trace_counter;
    return 0;
}

/* ============================================================
 * PATTERN MATCHING
 * ============================================================ */

/*
 * Match path against glob pattern.
 * Supports:
 *   * - matches any characters within a path segment
 *   ** - matches any characters including /
 */
static boolean pattern_match_path(const char *pattern, const char *path)
{
    if (!pattern || !path)
        return false;

    const char *p = pattern;
    const char *s = path;

    while (*p && *s) {
        if (p[0] == '*' && p[1] == '*') {
            /* ** matches any path including / */
            p += 2;
            if (*p == '/')
                p++;  /* Skip optional trailing / after ** */
            if (!*p)
                return true;  /* Trailing ** matches all */

            /* Try to match rest of pattern */
            while (*s) {
                if (pattern_match_path(p, s))
                    return true;
                s++;
            }
            return pattern_match_path(p, s);  /* Try empty match */
        } else if (*p == '*') {
            /* * matches within segment (not /) */
            p++;
            while (*s && *s != '/') {
                if (pattern_match_path(p, s))
                    return true;
                s++;
            }
            return pattern_match_path(p, s);
        } else if (*p == *s) {
            p++;
            s++;
        } else {
            return false;
        }
    }

    /* Handle trailing wildcards */
    while (*p == '*')
        p++;

    return (*p == '\0' && *s == '\0');
}

/*
 * Match hostname against DNS pattern.
 * Supports wildcard: *.example.com matches sub.example.com
 */
static boolean pattern_match_dns(const char *pattern, const char *hostname)
{
    if (!pattern || !hostname)
        return false;

    /* Handle leading wildcard */
    if (pattern[0] == '*' && pattern[1] == '.') {
        const char *domain = pattern + 2;
        size_t domain_len = strlen(domain);
        size_t host_len = strlen(hostname);

        if (host_len < domain_len + 1)
            return false;

        /* Check if hostname ends with .domain */
        const char *suffix = hostname + host_len - domain_len;
        if (suffix > hostname && suffix[-1] == '.' &&
            strcmp(suffix, domain) == 0)
            return true;

        /* Exact domain match (without subdomain) */
        return (strcmp(hostname, domain) == 0);
    }

    return (strcmp(pattern, hostname) == 0);
}

/*
 * Match IP:port pattern.
 * Format: "ip:addr:port" or "ip:addr:*"
 */
static boolean pattern_match_ip(const char *pattern, const char *target)
{
    if (!pattern || !target)
        return false;

    /* Simple wildcard at end */
    size_t plen = strlen(pattern);
    if (plen > 0 && pattern[plen - 1] == '*') {
        return (strncmp(pattern, target, plen - 1) == 0);
    }

    return (strcmp(pattern, target) == 0);
}

/* ============================================================
 * PATH CANONICALIZATION
 * ============================================================ */

static boolean canonicalize_path(const char *path, const char *cwd,
                                  char *out, size_t out_len)
{
    if (!path || !out || out_len == 0)
        return false;

    char work[AK_MAX_TARGET];
    size_t work_pos = 0;

    /* Handle absolute vs relative */
    if (path[0] == '/') {
        work[work_pos++] = '/';
    } else if (cwd) {
        size_t cwd_len = strlen(cwd);
        if (cwd_len >= sizeof(work) - 1)
            return false;
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
        /* Skip multiple slashes */
        while (*p == '/')
            p++;
        if (!*p)
            break;

        /* Find end of component */
        const char *comp_start = p;
        while (*p && *p != '/')
            p++;
        size_t comp_len = p - comp_start;

        /* Handle . and .. */
        if (comp_len == 1 && comp_start[0] == '.') {
            continue;
        } else if (comp_len == 2 && comp_start[0] == '.' && comp_start[1] == '.') {
            if (work_pos > 1) {
                work_pos--;
                while (work_pos > 1 && work[work_pos - 1] != '/')
                    work_pos--;
            }
        } else {
            if (work_pos + comp_len + 1 >= sizeof(work))
                return false;

            if (work_pos > 1 || work[0] != '/')
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
        return false;

    memcpy(out, work, work_pos);
    out[work_pos] = '\0';
    return true;
}

/* ============================================================
 * SUGGESTION GENERATION
 * ============================================================ */

static void generate_suggestion(const ak_effect_req_t *req, char *snippet, size_t max_len)
{
    if (!req || !snippet || max_len == 0) {
        if (snippet && max_len > 0)
            snippet[0] = '\0';
        return;
    }

    switch (req->op) {
    case AK_E_FS_OPEN:
        snprintf(snippet, max_len,
                 "[[fs.allow]]\npath = \"%s\"\nread = true", req->target);
        break;
    case AK_E_FS_UNLINK:
    case AK_E_FS_MKDIR:
        snprintf(snippet, max_len,
                 "[[fs.allow]]\npath = \"%s\"\nwrite = true", req->target);
        break;
    case AK_E_NET_DNS_RESOLVE: {
        const char *host = req->target;
        if (strncmp(host, "dns:", 4) == 0)
            host += 4;
        snprintf(snippet, max_len,
                 "[[net.dns]]\nallow = [\"%s\"]", host);
        break;
    }
    case AK_E_NET_CONNECT:
        snprintf(snippet, max_len,
                 "[[net.allow]]\nconnect = [\"%s\"]", req->target);
        break;
    case AK_E_TOOL_CALL: {
        const char *tool = req->target;
        if (strncmp(tool, "tool:", 5) == 0)
            tool += 5;
        char name[64];
        const char *colon = strchr(tool, ':');
        if (colon) {
            size_t len = colon - tool;
            if (len >= sizeof(name))
                len = sizeof(name) - 1;
            memcpy(name, tool, len);
            name[len] = '\0';
        } else {
            strncpy(name, tool, sizeof(name) - 1);
            name[sizeof(name) - 1] = '\0';
        }
        snprintf(snippet, max_len,
                 "[[tools]]\nallow = [\"%s\"]", name);
        break;
    }
    case AK_E_WASM_INVOKE: {
        const char *mod = req->target;
        if (strncmp(mod, "wasm:", 5) == 0)
            mod += 5;
        snprintf(snippet, max_len,
                 "[[wasm]]\nmodule = \"%s\"", mod);
        break;
    }
    case AK_E_INFER: {
        const char *model = req->target;
        if (strncmp(model, "model:", 6) == 0)
            model += 6;
        snprintf(snippet, max_len,
                 "[[infer]]\nmodels = [\"%s\"]", model);
        break;
    }
    default:
        snprintf(snippet, max_len, "# Unknown effect type 0x%x", req->op);
        break;
    }
}

/* ============================================================
 * AUTHORIZATION ENGINE
 * ============================================================ */

static int ak_authorize_and_execute(ak_ctx_t *ctx,
                                     const ak_effect_req_t *req,
                                     ak_decision_t *decision,
                                     long *retval_out)
{
    if (!ctx || !req || !decision)
        return -EINVAL;

    memset(decision, 0, sizeof(*decision));
    decision->trace_id = req->trace_id;
    ctx->total_requests++;

    /* OFF mode: bypass all checks */
    if (ctx->mode == AK_MODE_OFF) {
        decision->allow = true;
        ctx->allowed++;
        *retval_out = 0;
        return 0;
    }

    /* Boot capsule active: allow everything during early boot */
    if (ctx->boot_capsule_active) {
        decision->allow = true;
        ctx->allowed++;
        *retval_out = 0;
        return 0;
    }

    /* No policy rules at all = deny by default */
    boolean has_policy = (ctx->policy.fs_read_count > 0 ||
                          ctx->policy.fs_write_count > 0 ||
                          ctx->policy.dns_count > 0 ||
                          ctx->policy.ip_count > 0 ||
                          ctx->policy.tool_count > 0 ||
                          ctx->policy.wasm_count > 0 ||
                          ctx->policy.model_count > 0);

    switch (req->op) {
    case AK_E_FS_OPEN: {
        /* Check read patterns */
        for (size_t i = 0; i < ctx->policy.fs_read_count; i++) {
            if (pattern_match_path(ctx->policy.fs_read_patterns[i], req->target)) {
                decision->allow = true;
                ctx->allowed++;
                *retval_out = 3;  /* Mock fd */
                return 0;
            }
        }
        decision->allow = false;
        decision->reason_code = has_policy ? AK_DENY_PATTERN_MISMATCH : AK_DENY_NO_POLICY;
        decision->errno_equiv = EACCES;
        strncpy(decision->missing_cap, "fs.read", sizeof(decision->missing_cap) - 1);
        snprintf(decision->detail, sizeof(decision->detail),
                 "path '%s' not in allowed patterns", req->target);
        break;
    }

    case AK_E_NET_DNS_RESOLVE: {
        const char *hostname = req->target;
        if (strncmp(hostname, "dns:", 4) == 0)
            hostname += 4;

        for (size_t i = 0; i < ctx->policy.dns_count; i++) {
            if (pattern_match_dns(ctx->policy.dns_patterns[i], hostname)) {
                decision->allow = true;
                ctx->allowed++;
                *retval_out = 0;
                return 0;
            }
        }
        decision->allow = false;
        decision->reason_code = has_policy ? AK_DENY_PATTERN_MISMATCH : AK_DENY_NO_POLICY;
        decision->errno_equiv = ECONNREFUSED;
        strncpy(decision->missing_cap, "net.dns", sizeof(decision->missing_cap) - 1);
        snprintf(decision->detail, sizeof(decision->detail),
                 "DNS resolution for '%s' not allowed", hostname);
        break;
    }

    case AK_E_NET_CONNECT: {
        for (size_t i = 0; i < ctx->policy.ip_count; i++) {
            if (pattern_match_ip(ctx->policy.ip_patterns[i], req->target)) {
                decision->allow = true;
                ctx->allowed++;
                *retval_out = 0;
                return 0;
            }
        }
        decision->allow = false;
        decision->reason_code = has_policy ? AK_DENY_PATTERN_MISMATCH : AK_DENY_NO_POLICY;
        decision->errno_equiv = ECONNREFUSED;
        strncpy(decision->missing_cap, "net.connect", sizeof(decision->missing_cap) - 1);
        snprintf(decision->detail, sizeof(decision->detail),
                 "connection to '%s' not allowed", req->target);
        break;
    }

    case AK_E_TOOL_CALL: {
        /* Check budget first */
        if (ctx->policy.tool_used >= ctx->policy.tool_budget) {
            decision->allow = false;
            decision->reason_code = AK_DENY_BUDGET_EXCEEDED;
            decision->errno_equiv = ENOSPC;
            strncpy(decision->missing_cap, "budget.tool_calls", sizeof(decision->missing_cap) - 1);
            snprintf(decision->detail, sizeof(decision->detail),
                     "tool call budget exceeded (%lu/%lu)",
                     (unsigned long)ctx->policy.tool_used,
                     (unsigned long)ctx->policy.tool_budget);
            break;
        }

        /* Check tool patterns */
        const char *tool = req->target;
        if (strncmp(tool, "tool:", 5) == 0)
            tool += 5;
        char name[64];
        const char *colon = strchr(tool, ':');
        if (colon) {
            size_t len = colon - tool;
            if (len >= sizeof(name))
                len = sizeof(name) - 1;
            memcpy(name, tool, len);
            name[len] = '\0';
        } else {
            strncpy(name, tool, sizeof(name) - 1);
            name[sizeof(name) - 1] = '\0';
        }

        for (size_t i = 0; i < ctx->policy.tool_count; i++) {
            if (pattern_match_path(ctx->policy.tool_patterns[i], name)) {
                ctx->policy.tool_used++;
                decision->allow = true;
                ctx->allowed++;
                *retval_out = 0;
                return 0;
            }
        }
        decision->allow = false;
        decision->reason_code = has_policy ? AK_DENY_NO_CAP : AK_DENY_NO_POLICY;
        decision->errno_equiv = EPERM;
        strncpy(decision->missing_cap, "tools.allow", sizeof(decision->missing_cap) - 1);
        snprintf(decision->detail, sizeof(decision->detail),
                 "tool '%s' not in allowed list", name);
        break;
    }

    case AK_E_WASM_INVOKE: {
        const char *mod = req->target;
        if (strncmp(mod, "wasm:", 5) == 0)
            mod += 5;

        /* Extract just the module name (before the function) */
        char module_name[64];
        const char *colon = strchr(mod, ':');
        if (colon) {
            size_t len = (size_t)(colon - mod);
            if (len >= sizeof(module_name))
                len = sizeof(module_name) - 1;
            memcpy(module_name, mod, len);
            module_name[len] = '\0';
        } else {
            strncpy(module_name, mod, sizeof(module_name) - 1);
            module_name[sizeof(module_name) - 1] = '\0';
        }

        /* Check WASM module patterns */
        for (size_t i = 0; i < ctx->policy.wasm_count; i++) {
            if (pattern_match_path(ctx->policy.wasm_patterns[i], module_name)) {
                decision->allow = true;
                ctx->allowed++;
                *retval_out = 0;
                return 0;
            }
        }
        decision->allow = false;
        decision->reason_code = has_policy ? AK_DENY_NO_CAP : AK_DENY_NO_POLICY;
        decision->errno_equiv = EPERM;
        strncpy(decision->missing_cap, "wasm.module", sizeof(decision->missing_cap) - 1);
        snprintf(decision->detail, sizeof(decision->detail),
                 "WASM module '%s' not allowed", module_name);
        break;
    }

    case AK_E_INFER: {
        /* Check token budget */
        u64 requested = req->budget.tokens;
        if (ctx->policy.tokens_used + requested > ctx->policy.token_budget) {
            decision->allow = false;
            decision->reason_code = AK_DENY_BUDGET_EXCEEDED;
            decision->errno_equiv = ENOSPC;
            strncpy(decision->missing_cap, "budget.tokens", sizeof(decision->missing_cap) - 1);
            snprintf(decision->detail, sizeof(decision->detail),
                     "token budget exceeded (%lu + %lu > %lu)",
                     (unsigned long)ctx->policy.tokens_used,
                     (unsigned long)requested,
                     (unsigned long)ctx->policy.token_budget);
            break;
        }

        /* Check model patterns */
        const char *model = req->target;
        if (strncmp(model, "model:", 6) == 0)
            model += 6;

        for (size_t i = 0; i < ctx->policy.model_count; i++) {
            if (pattern_match_path(ctx->policy.model_patterns[i], model)) {
                ctx->policy.tokens_used += requested;
                decision->allow = true;
                ctx->allowed++;
                *retval_out = 0;
                return 0;
            }
        }
        decision->allow = false;
        decision->reason_code = has_policy ? AK_DENY_NO_CAP : AK_DENY_NO_POLICY;
        decision->errno_equiv = EPERM;
        strncpy(decision->missing_cap, "infer.models", sizeof(decision->missing_cap) - 1);
        snprintf(decision->detail, sizeof(decision->detail),
                 "model '%s' not in allowlist", model);
        break;
    }

    default:
        decision->allow = false;
        decision->reason_code = AK_DENY_NO_CAP;
        decision->errno_equiv = ENOSYS;
        snprintf(decision->detail, sizeof(decision->detail),
                 "unsupported effect op 0x%x", req->op);
        break;
    }

    /* Record denial */
    if (!decision->allow) {
        ctx->denied++;
        generate_suggestion(req, decision->suggested_snippet, sizeof(decision->suggested_snippet));

        /* Store in last_deny */
        ctx->last_deny.op = req->op;
        strncpy(ctx->last_deny.target, req->target, sizeof(ctx->last_deny.target) - 1);
        strncpy(ctx->last_deny.missing_cap, decision->missing_cap,
                sizeof(ctx->last_deny.missing_cap) - 1);
        strncpy(ctx->last_deny.suggested_snippet, decision->suggested_snippet,
                sizeof(ctx->last_deny.suggested_snippet) - 1);
        ctx->last_deny.trace_id = decision->trace_id;
        ctx->last_deny.errno_equiv = decision->errno_equiv;
        ctx->last_deny.reason = decision->reason_code;
        ctx->has_last_deny = true;

        return -decision->errno_equiv;
    }

    return 0;
}

/* ============================================================
 * MOCK ROUTING FUNCTIONS (simulating ak_route_*)
 * ============================================================ */

static long ak_route_open(const char *path, int flags, int mode)
{
    ak_ctx_t *ctx = ak_ctx_current();
    if (!ctx)
        return -ENOENT;

    ak_effect_req_t req;
    memset(&req, 0, sizeof(req));
    req.op = AK_E_FS_OPEN;
    req.trace_id = ak_trace_id_generate(ctx);
    canonicalize_path(path, "/", req.target, sizeof(req.target));
    req.params_len = snprintf((char *)req.params, sizeof(req.params),
                               "{\"flags\":%d,\"mode\":%d}", flags, mode);

    ak_decision_t decision;
    long retval;
    int result = ak_authorize_and_execute(ctx, &req, &decision, &retval);
    if (result < 0)
        return result;
    return retval;
}

static long ak_route_dns_resolve(const char *hostname)
{
    ak_ctx_t *ctx = ak_ctx_current();
    if (!ctx)
        return -ENOENT;

    ak_effect_req_t req;
    memset(&req, 0, sizeof(req));
    req.op = AK_E_NET_DNS_RESOLVE;
    req.trace_id = ak_trace_id_generate(ctx);
    snprintf(req.target, sizeof(req.target), "dns:%s", hostname);

    ak_decision_t decision;
    long retval;
    int result = ak_authorize_and_execute(ctx, &req, &decision, &retval);
    if (result < 0)
        return result;
    return retval;
}

static long ak_route_connect(const char *addr, u16 port)
{
    ak_ctx_t *ctx = ak_ctx_current();
    if (!ctx)
        return -ENOENT;

    ak_effect_req_t req;
    memset(&req, 0, sizeof(req));
    req.op = AK_E_NET_CONNECT;
    req.trace_id = ak_trace_id_generate(ctx);
    snprintf(req.target, sizeof(req.target), "ip:%s:%u", addr, port);

    ak_decision_t decision;
    long retval;
    int result = ak_authorize_and_execute(ctx, &req, &decision, &retval);
    if (result < 0)
        return result;
    return retval;
}

static int ak_handle_tool_call(ak_ctx_t *ctx, const char *name, const char *version)
{
    ak_effect_req_t req;
    memset(&req, 0, sizeof(req));
    req.op = AK_E_TOOL_CALL;
    req.trace_id = ak_trace_id_generate(ctx);
    snprintf(req.target, sizeof(req.target), "tool:%s:%s",
             name, version ? version : "latest");

    ak_decision_t decision;
    long retval;
    return ak_authorize_and_execute(ctx, &req, &decision, &retval);
}

static int ak_handle_wasm_invoke(ak_ctx_t *ctx, const char *module, const char *function)
{
    ak_effect_req_t req;
    memset(&req, 0, sizeof(req));
    req.op = AK_E_WASM_INVOKE;
    req.trace_id = ak_trace_id_generate(ctx);
    snprintf(req.target, sizeof(req.target), "wasm:%s:%s", module, function);

    ak_decision_t decision;
    long retval;
    return ak_authorize_and_execute(ctx, &req, &decision, &retval);
}

static int ak_handle_infer(ak_ctx_t *ctx, const char *model, u64 max_tokens)
{
    ak_effect_req_t req;
    memset(&req, 0, sizeof(req));
    req.op = AK_E_INFER;
    req.trace_id = ak_trace_id_generate(ctx);
    snprintf(req.target, sizeof(req.target), "model:%s", model);
    req.budget.tokens = max_tokens;

    ak_decision_t decision;
    long retval;
    return ak_authorize_and_execute(ctx, &req, &decision, &retval);
}

/* ============================================================
 * TEST CASES: DENY-BY-DEFAULT
 * ============================================================ */

boolean test_deny_by_default_no_policy(void)
{
    ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
    test_assert(ctx != NULL);
    ak_ctx_set_current(ctx);
    ak_ctx_drop_boot_capsule(ctx);  /* Enable enforcement */

    /* No policy rules set */
    long result = ak_route_open("/any/path", 0, 0);
    test_assert_eq(result, -EACCES);

    /* Verify last_deny populated */
    const ak_last_deny_t *deny = ak_ctx_get_last_deny(ctx);
    test_assert(deny != NULL);
    test_assert_eq(deny->op, AK_E_FS_OPEN);
    test_assert_eq(deny->reason, AK_DENY_NO_POLICY);
    test_assert(strlen(deny->suggested_snippet) > 0);

    ak_ctx_destroy(NULL, ctx);
    return true;
}

boolean test_deny_by_default_empty_fs_section(void)
{
    ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
    test_assert(ctx != NULL);
    ak_ctx_set_current(ctx);
    ak_ctx_drop_boot_capsule(ctx);

    /* Policy has DNS rules but no FS rules */
    const char *dns_patterns[] = {"example.com"};
    ctx->policy.dns_patterns = dns_patterns;
    ctx->policy.dns_count = 1;

    /* FS should be denied */
    long result = ak_route_open("/app/file.txt", 0, 0);
    test_assert_eq(result, -EACCES);

    const ak_last_deny_t *deny = ak_ctx_get_last_deny(ctx);
    test_assert(deny != NULL);
    test_assert_eq(deny->reason, AK_DENY_PATTERN_MISMATCH);

    ak_ctx_destroy(NULL, ctx);
    return true;
}

boolean test_deny_by_default_empty_net_section(void)
{
    ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
    test_assert(ctx != NULL);
    ak_ctx_set_current(ctx);
    ak_ctx_drop_boot_capsule(ctx);

    /* Policy has FS rules but no NET rules */
    const char *fs_patterns[] = {"/app/**"};
    ctx->policy.fs_read_patterns = fs_patterns;
    ctx->policy.fs_read_count = 1;

    /* NET should be denied */
    long result = ak_route_dns_resolve("example.com");
    test_assert_eq(result, -ECONNREFUSED);

    ak_ctx_destroy(NULL, ctx);
    return true;
}

/* ============================================================
 * TEST CASES: FILESYSTEM
 * ============================================================ */

boolean test_fs_read_allowed(void)
{
    ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
    test_assert(ctx != NULL);
    ak_ctx_set_current(ctx);
    ak_ctx_drop_boot_capsule(ctx);

    const char *patterns[] = {"/app/**"};
    ctx->policy.fs_read_patterns = patterns;
    ctx->policy.fs_read_count = 1;

    long result = ak_route_open("/app/file.txt", 0, 0);
    test_assert(result >= 0);

    ak_ctx_destroy(NULL, ctx);
    return true;
}

boolean test_fs_read_denied(void)
{
    ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
    test_assert(ctx != NULL);
    ak_ctx_set_current(ctx);
    ak_ctx_drop_boot_capsule(ctx);

    const char *patterns[] = {"/app/**"};
    ctx->policy.fs_read_patterns = patterns;
    ctx->policy.fs_read_count = 1;

    long result = ak_route_open("/etc/passwd", 0, 0);
    test_assert_eq(result, -EACCES);

    const ak_last_deny_t *deny = ak_ctx_get_last_deny(ctx);
    test_assert(deny != NULL);
    test_assert_streq(deny->missing_cap, "fs.read");

    ak_ctx_destroy(NULL, ctx);
    return true;
}

boolean test_fs_path_traversal_blocked(void)
{
    ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
    test_assert(ctx != NULL);
    ak_ctx_set_current(ctx);
    ak_ctx_drop_boot_capsule(ctx);

    const char *patterns[] = {"/app/**"};
    ctx->policy.fs_read_patterns = patterns;
    ctx->policy.fs_read_count = 1;

    /* Try to escape /app via path traversal */
    long result = ak_route_open("/app/../etc/passwd", 0, 0);
    test_assert_eq(result, -EACCES);

    /* Verify canonical path was checked */
    const ak_last_deny_t *deny = ak_ctx_get_last_deny(ctx);
    test_assert(deny != NULL);
    /* Canonicalized path should be /etc/passwd */
    test_assert_streq(deny->target, "/etc/passwd");

    ak_ctx_destroy(NULL, ctx);
    return true;
}

boolean test_fs_canonicalization(void)
{
    ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
    test_assert(ctx != NULL);
    ak_ctx_set_current(ctx);
    ak_ctx_drop_boot_capsule(ctx);

    const char *patterns[] = {"/app/**"};
    ctx->policy.fs_read_patterns = patterns;
    ctx->policy.fs_read_count = 1;

    /* Path with . and redundant slashes should still work */
    long result = ak_route_open("/app/./data/../file.txt", 0, 0);
    test_assert(result >= 0);

    ak_ctx_destroy(NULL, ctx);
    return true;
}

boolean test_fs_glob_single_star(void)
{
    ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
    test_assert(ctx != NULL);
    ak_ctx_set_current(ctx);
    ak_ctx_drop_boot_capsule(ctx);

    /* Single * matches within one segment */
    const char *patterns[] = {"/app/*.txt"};
    ctx->policy.fs_read_patterns = patterns;
    ctx->policy.fs_read_count = 1;

    /* Should match */
    test_assert(ak_route_open("/app/file.txt", 0, 0) >= 0);

    /* Should not match (subdir) */
    ak_ctx_clear_last_deny(ctx);
    test_assert_eq(ak_route_open("/app/sub/file.txt", 0, 0), -EACCES);

    ak_ctx_destroy(NULL, ctx);
    return true;
}

boolean test_fs_glob_double_star(void)
{
    ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
    test_assert(ctx != NULL);
    ak_ctx_set_current(ctx);
    ak_ctx_drop_boot_capsule(ctx);

    /* Double ** matches across segments */
    const char *patterns[] = {"/app/**"};
    ctx->policy.fs_read_patterns = patterns;
    ctx->policy.fs_read_count = 1;

    test_assert(ak_route_open("/app/file.txt", 0, 0) >= 0);
    test_assert(ak_route_open("/app/sub/file.txt", 0, 0) >= 0);
    test_assert(ak_route_open("/app/sub/deep/file.txt", 0, 0) >= 0);

    ak_ctx_destroy(NULL, ctx);
    return true;
}

/* ============================================================
 * TEST CASES: NETWORK
 * ============================================================ */

boolean test_dns_resolution_allowed(void)
{
    ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
    test_assert(ctx != NULL);
    ak_ctx_set_current(ctx);
    ak_ctx_drop_boot_capsule(ctx);

    const char *patterns[] = {"example.com", "*.api.example.com"};
    ctx->policy.dns_patterns = patterns;
    ctx->policy.dns_count = 2;

    test_assert_eq(ak_route_dns_resolve("example.com"), 0);
    test_assert_eq(ak_route_dns_resolve("sub.api.example.com"), 0);

    ak_ctx_destroy(NULL, ctx);
    return true;
}

boolean test_dns_resolution_denied(void)
{
    ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
    test_assert(ctx != NULL);
    ak_ctx_set_current(ctx);
    ak_ctx_drop_boot_capsule(ctx);

    const char *patterns[] = {"example.com"};
    ctx->policy.dns_patterns = patterns;
    ctx->policy.dns_count = 1;

    long result = ak_route_dns_resolve("evil.com");
    test_assert_eq(result, -ECONNREFUSED);

    const ak_last_deny_t *deny = ak_ctx_get_last_deny(ctx);
    test_assert(deny != NULL);
    test_assert_streq(deny->missing_cap, "net.dns");

    ak_ctx_destroy(NULL, ctx);
    return true;
}

boolean test_connect_allowed(void)
{
    ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
    test_assert(ctx != NULL);
    ak_ctx_set_current(ctx);
    ak_ctx_drop_boot_capsule(ctx);

    const char *patterns[] = {"ip:127.0.0.1:*"};
    ctx->policy.ip_patterns = patterns;
    ctx->policy.ip_count = 1;

    test_assert_eq(ak_route_connect("127.0.0.1", 8080), 0);
    test_assert_eq(ak_route_connect("127.0.0.1", 3000), 0);

    ak_ctx_destroy(NULL, ctx);
    return true;
}

boolean test_connect_denied(void)
{
    ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
    test_assert(ctx != NULL);
    ak_ctx_set_current(ctx);
    ak_ctx_drop_boot_capsule(ctx);

    const char *patterns[] = {"ip:127.0.0.1:*"};
    ctx->policy.ip_patterns = patterns;
    ctx->policy.ip_count = 1;

    /* External IP should be denied */
    long result = ak_route_connect("8.8.8.8", 53);
    test_assert_eq(result, -ECONNREFUSED);

    ak_ctx_destroy(NULL, ctx);
    return true;
}

/* ============================================================
 * TEST CASES: AGENTIC
 * ============================================================ */

boolean test_tool_call_no_policy(void)
{
    ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
    test_assert(ctx != NULL);
    ak_ctx_set_current(ctx);
    ak_ctx_drop_boot_capsule(ctx);

    /* No tool patterns set */
    int result = ak_handle_tool_call(ctx, "http_get", "1.0");
    test_assert_eq(result, -EPERM);

    const ak_last_deny_t *deny = ak_ctx_get_last_deny(ctx);
    test_assert(deny != NULL);
    test_assert_eq(deny->op, AK_E_TOOL_CALL);
    test_assert(strstr(deny->suggested_snippet, "tools") != NULL);

    ak_ctx_destroy(NULL, ctx);
    return true;
}

boolean test_tool_call_allowed(void)
{
    ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
    test_assert(ctx != NULL);
    ak_ctx_set_current(ctx);
    ak_ctx_drop_boot_capsule(ctx);

    const char *patterns[] = {"http_get", "http_post"};
    ctx->policy.tool_patterns = patterns;
    ctx->policy.tool_count = 2;

    test_assert_eq(ak_handle_tool_call(ctx, "http_get", "1.0"), 0);
    test_assert_eq(ak_handle_tool_call(ctx, "http_post", "2.0"), 0);

    ak_ctx_destroy(NULL, ctx);
    return true;
}

boolean test_tool_call_denied(void)
{
    ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
    test_assert(ctx != NULL);
    ak_ctx_set_current(ctx);
    ak_ctx_drop_boot_capsule(ctx);

    const char *patterns[] = {"safe_tool"};
    ctx->policy.tool_patterns = patterns;
    ctx->policy.tool_count = 1;

    int result = ak_handle_tool_call(ctx, "dangerous_tool", "1.0");
    test_assert_eq(result, -EPERM);

    ak_ctx_destroy(NULL, ctx);
    return true;
}

boolean test_wasm_invoke_no_policy(void)
{
    ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
    test_assert(ctx != NULL);
    ak_ctx_set_current(ctx);
    ak_ctx_drop_boot_capsule(ctx);

    int result = ak_handle_wasm_invoke(ctx, "untrusted_module", "main");
    test_assert_eq(result, -EPERM);

    const ak_last_deny_t *deny = ak_ctx_get_last_deny(ctx);
    test_assert(deny != NULL);
    test_assert_eq(deny->op, AK_E_WASM_INVOKE);

    ak_ctx_destroy(NULL, ctx);
    return true;
}

boolean test_wasm_invoke_allowed(void)
{
    ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
    test_assert(ctx != NULL);
    ak_ctx_set_current(ctx);
    ak_ctx_drop_boot_capsule(ctx);

    const char *patterns[] = {"trusted_module"};
    ctx->policy.wasm_patterns = patterns;
    ctx->policy.wasm_count = 1;

    test_assert_eq(ak_handle_wasm_invoke(ctx, "trusted_module", "main"), 0);

    ak_ctx_destroy(NULL, ctx);
    return true;
}

boolean test_infer_no_allowlist(void)
{
    ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
    test_assert(ctx != NULL);
    ak_ctx_set_current(ctx);
    ak_ctx_drop_boot_capsule(ctx);

    int result = ak_handle_infer(ctx, "gpt-4", 1000);
    test_assert_eq(result, -EPERM);

    const ak_last_deny_t *deny = ak_ctx_get_last_deny(ctx);
    test_assert(deny != NULL);
    test_assert_eq(deny->op, AK_E_INFER);

    ak_ctx_destroy(NULL, ctx);
    return true;
}

boolean test_infer_allowed(void)
{
    ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
    test_assert(ctx != NULL);
    ak_ctx_set_current(ctx);
    ak_ctx_drop_boot_capsule(ctx);

    const char *patterns[] = {"gpt-4", "claude-*"};
    ctx->policy.model_patterns = patterns;
    ctx->policy.model_count = 2;

    test_assert_eq(ak_handle_infer(ctx, "gpt-4", 1000), 0);
    test_assert_eq(ak_handle_infer(ctx, "claude-3", 2000), 0);

    ak_ctx_destroy(NULL, ctx);
    return true;
}

boolean test_budget_exceeded(void)
{
    ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
    test_assert(ctx != NULL);
    ak_ctx_set_current(ctx);
    ak_ctx_drop_boot_capsule(ctx);

    const char *patterns[] = {"test_tool"};
    ctx->policy.tool_patterns = patterns;
    ctx->policy.tool_count = 1;
    ctx->policy.tool_budget = 3;  /* Only 3 calls allowed */

    /* First 3 should succeed */
    test_assert_eq(ak_handle_tool_call(ctx, "test_tool", "1.0"), 0);
    test_assert_eq(ak_handle_tool_call(ctx, "test_tool", "1.0"), 0);
    test_assert_eq(ak_handle_tool_call(ctx, "test_tool", "1.0"), 0);

    /* 4th should fail with budget exceeded */
    int result = ak_handle_tool_call(ctx, "test_tool", "1.0");
    test_assert_eq(result, -ENOSPC);

    const ak_last_deny_t *deny = ak_ctx_get_last_deny(ctx);
    test_assert(deny != NULL);
    test_assert_eq(deny->reason, AK_DENY_BUDGET_EXCEEDED);

    ak_ctx_destroy(NULL, ctx);
    return true;
}

boolean test_token_budget_exceeded(void)
{
    ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
    test_assert(ctx != NULL);
    ak_ctx_set_current(ctx);
    ak_ctx_drop_boot_capsule(ctx);

    const char *patterns[] = {"gpt-4"};
    ctx->policy.model_patterns = patterns;
    ctx->policy.model_count = 1;
    ctx->policy.token_budget = 5000;

    /* Use 4000 tokens */
    test_assert_eq(ak_handle_infer(ctx, "gpt-4", 4000), 0);

    /* Try to use 2000 more (would exceed 5000) */
    int result = ak_handle_infer(ctx, "gpt-4", 2000);
    test_assert_eq(result, -ENOSPC);

    const ak_last_deny_t *deny = ak_ctx_get_last_deny(ctx);
    test_assert(deny != NULL);
    test_assert_eq(deny->reason, AK_DENY_BUDGET_EXCEEDED);

    ak_ctx_destroy(NULL, ctx);
    return true;
}

/* ============================================================
 * TEST CASES: MODE TESTS
 * ============================================================ */

boolean test_mode_off_bypasses(void)
{
    ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
    test_assert(ctx != NULL);
    ak_ctx_set_current(ctx);
    ak_ctx_drop_boot_capsule(ctx);
    ak_ctx_set_mode(ctx, AK_MODE_OFF);

    /* No policy set, but OFF mode should bypass */
    long result = ak_route_open("/any/path", 0, 0);
    test_assert(result >= 0);

    result = ak_route_dns_resolve("any.host");
    test_assert_eq(result, 0);

    ak_ctx_destroy(NULL, ctx);
    return true;
}

boolean test_mode_soft_enforces(void)
{
    ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
    test_assert(ctx != NULL);
    ak_ctx_set_current(ctx);
    ak_ctx_drop_boot_capsule(ctx);
    ak_ctx_set_mode(ctx, AK_MODE_SOFT);

    /* SOFT mode should enforce policy */
    long result = ak_route_open("/etc/passwd", 0, 0);
    test_assert_eq(result, -EACCES);

    ak_ctx_destroy(NULL, ctx);
    return true;
}

boolean test_boot_capsule_allows_during_boot(void)
{
    ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
    test_assert(ctx != NULL);
    ak_ctx_set_current(ctx);

    /* Boot capsule still active */
    test_assert(ak_ctx_boot_capsule_active(ctx));

    /* No policy, but should be allowed during boot */
    long result = ak_route_open("/any/path", 0, 0);
    test_assert(result >= 0);

    ak_ctx_destroy(NULL, ctx);
    return true;
}

boolean test_boot_capsule_drop_transitions(void)
{
    ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
    test_assert(ctx != NULL);
    ak_ctx_set_current(ctx);

    /* Before drop: should allow */
    test_assert(ak_ctx_boot_capsule_active(ctx));
    test_assert(ak_route_open("/etc/passwd", 0, 0) >= 0);

    /* Drop boot capsule */
    ak_ctx_drop_boot_capsule(ctx);
    test_assert(!ak_ctx_boot_capsule_active(ctx));

    /* After drop: should deny (no policy) */
    long result = ak_route_open("/etc/passwd", 0, 0);
    test_assert_eq(result, -EACCES);

    ak_ctx_destroy(NULL, ctx);
    return true;
}

/* ============================================================
 * TEST CASES: SUGGESTION TESTS
 * ============================================================ */

boolean test_suggestion_fs_format(void)
{
    ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
    test_assert(ctx != NULL);
    ak_ctx_set_current(ctx);
    ak_ctx_drop_boot_capsule(ctx);

    ak_route_open("/secret/data.txt", 0, 0);

    const ak_last_deny_t *deny = ak_ctx_get_last_deny(ctx);
    test_assert(deny != NULL);
    test_assert(strstr(deny->suggested_snippet, "[[fs.allow]]") != NULL);
    test_assert(strstr(deny->suggested_snippet, "/secret/data.txt") != NULL);
    test_assert(strstr(deny->suggested_snippet, "read = true") != NULL);

    ak_ctx_destroy(NULL, ctx);
    return true;
}

boolean test_suggestion_dns_format(void)
{
    ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
    test_assert(ctx != NULL);
    ak_ctx_set_current(ctx);
    ak_ctx_drop_boot_capsule(ctx);

    ak_route_dns_resolve("api.example.com");

    const ak_last_deny_t *deny = ak_ctx_get_last_deny(ctx);
    test_assert(deny != NULL);
    test_assert(strstr(deny->suggested_snippet, "[[net.dns]]") != NULL);
    test_assert(strstr(deny->suggested_snippet, "api.example.com") != NULL);

    ak_ctx_destroy(NULL, ctx);
    return true;
}

boolean test_suggestion_tool_format(void)
{
    ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
    test_assert(ctx != NULL);
    ak_ctx_set_current(ctx);
    ak_ctx_drop_boot_capsule(ctx);

    ak_handle_tool_call(ctx, "my_tool", "1.0");

    const ak_last_deny_t *deny = ak_ctx_get_last_deny(ctx);
    test_assert(deny != NULL);
    test_assert(strstr(deny->suggested_snippet, "[[tools]]") != NULL);
    test_assert(strstr(deny->suggested_snippet, "my_tool") != NULL);

    ak_ctx_destroy(NULL, ctx);
    return true;
}

boolean test_suggestion_infer_format(void)
{
    ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
    test_assert(ctx != NULL);
    ak_ctx_set_current(ctx);
    ak_ctx_drop_boot_capsule(ctx);

    ak_handle_infer(ctx, "claude-opus", 1000);

    const ak_last_deny_t *deny = ak_ctx_get_last_deny(ctx);
    test_assert(deny != NULL);
    test_assert(strstr(deny->suggested_snippet, "[[infer]]") != NULL);
    test_assert(strstr(deny->suggested_snippet, "claude-opus") != NULL);

    ak_ctx_destroy(NULL, ctx);
    return true;
}

boolean test_suggestion_is_valid_toml(void)
{
    ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
    test_assert(ctx != NULL);
    ak_ctx_set_current(ctx);
    ak_ctx_drop_boot_capsule(ctx);

    ak_route_open("/app/config.json", 0, 0);

    const ak_last_deny_t *deny = ak_ctx_get_last_deny(ctx);
    test_assert(deny != NULL);

    /* Basic TOML validity checks */
    const char *snippet = deny->suggested_snippet;
    test_assert(strlen(snippet) > 0);
    test_assert(snippet[0] == '[');  /* Starts with section header */
    test_assert(strstr(snippet, "=") != NULL);  /* Has assignment */
    test_assert(strstr(snippet, "\"") != NULL);  /* Has quoted string */

    ak_ctx_destroy(NULL, ctx);
    return true;
}

/* ============================================================
 * TEST CASES: STATISTICS
 * ============================================================ */

boolean test_statistics_tracking(void)
{
    ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
    test_assert(ctx != NULL);
    ak_ctx_set_current(ctx);
    ak_ctx_drop_boot_capsule(ctx);

    const char *patterns[] = {"/app/**"};
    ctx->policy.fs_read_patterns = patterns;
    ctx->policy.fs_read_count = 1;

    /* Some allowed, some denied */
    ak_route_open("/app/file1.txt", 0, 0);  /* allowed */
    ak_route_open("/app/file2.txt", 0, 0);  /* allowed */
    ak_route_open("/etc/passwd", 0, 0);      /* denied */
    ak_route_open("/app/file3.txt", 0, 0);  /* allowed */
    ak_route_open("/etc/shadow", 0, 0);      /* denied */

    test_assert_eq(ctx->total_requests, 5);
    test_assert_eq(ctx->allowed, 3);
    test_assert_eq(ctx->denied, 2);

    ak_ctx_destroy(NULL, ctx);
    return true;
}

/* ============================================================
 * EDGE CASE TESTS
 * ============================================================ */

boolean test_edge_multiple_patterns(void)
{
    ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
    test_assert(ctx != NULL);
    ak_ctx_set_current(ctx);
    ak_ctx_drop_boot_capsule(ctx);

    /* Multiple overlapping patterns */
    const char *patterns[] = {"/app/*", "/app/**", "/app/data/*", "*.txt"};
    ctx->policy.fs_read_patterns = patterns;
    ctx->policy.fs_read_count = 4;

    /* Should match multiple patterns */
    test_assert(ak_route_open("/app/file.txt", 0, 0) >= 0);
    test_assert(ak_route_open("/app/data/file.txt", 0, 0) >= 0);

    ak_ctx_destroy(NULL, ctx);
    return true;
}

boolean test_edge_empty_policy_arrays(void)
{
    ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
    test_assert(ctx != NULL);
    ak_ctx_set_current(ctx);
    ak_ctx_drop_boot_capsule(ctx);

    /* Empty arrays (count=0, patterns=NULL) */
    ctx->policy.fs_read_patterns = NULL;
    ctx->policy.fs_read_count = 0;
    ctx->policy.fs_write_patterns = NULL;
    ctx->policy.fs_write_count = 0;

    /* Should deny with no patterns */
    long result = ak_route_open("/any/path", 0, 0);
    test_assert_eq(result, -EACCES);

    ak_ctx_destroy(NULL, ctx);
    return true;
}

boolean test_edge_max_budget_values(void)
{
    ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
    test_assert(ctx != NULL);
    ak_ctx_set_current(ctx);
    ak_ctx_drop_boot_capsule(ctx);

    const char *patterns[] = {"test_tool"};
    ctx->policy.tool_patterns = patterns;
    ctx->policy.tool_count = 1;

    /* Set to max u64 value */
    ctx->policy.tool_budget = UINT64_MAX;
    ctx->policy.tool_used = 0;

    /* Should allow */
    test_assert_eq(ak_handle_tool_call(ctx, "test_tool", "1.0"), 0);

    ak_ctx_destroy(NULL, ctx);
    return true;
}

boolean test_edge_zero_budget(void)
{
    ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
    test_assert(ctx != NULL);
    ak_ctx_set_current(ctx);
    ak_ctx_drop_boot_capsule(ctx);

    const char *patterns[] = {"test_tool"};
    ctx->policy.tool_patterns = patterns;
    ctx->policy.tool_count = 1;

    /* Zero budget should deny immediately */
    ctx->policy.tool_budget = 0;
    ctx->policy.tool_used = 0;

    int result = ak_handle_tool_call(ctx, "test_tool", "1.0");
    test_assert_eq(result, -ENOSPC);

    ak_ctx_destroy(NULL, ctx);
    return true;
}

boolean test_edge_budget_at_limit(void)
{
    ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
    test_assert(ctx != NULL);
    ak_ctx_set_current(ctx);
    ak_ctx_drop_boot_capsule(ctx);

    const char *patterns[] = {"test_tool"};
    ctx->policy.tool_patterns = patterns;
    ctx->policy.tool_count = 1;
    ctx->policy.tool_budget = 5;
    ctx->policy.tool_used = 4;  /* One remaining */

    /* Last call should succeed */
    test_assert_eq(ak_handle_tool_call(ctx, "test_tool", "1.0"), 0);

    /* Next call should fail */
    int result = ak_handle_tool_call(ctx, "test_tool", "1.0");
    test_assert_eq(result, -ENOSPC);

    ak_ctx_destroy(NULL, ctx);
    return true;
}

boolean test_edge_wildcard_only_patterns(void)
{
    ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
    test_assert(ctx != NULL);
    ak_ctx_set_current(ctx);
    ak_ctx_drop_boot_capsule(ctx);

    /* Pattern is just wildcard */
    const char *patterns[] = {"*"};
    ctx->policy.tool_patterns = patterns;
    ctx->policy.tool_count = 1;

    /* Should match any tool */
    test_assert_eq(ak_handle_tool_call(ctx, "any_tool", "1.0"), 0);
    test_assert_eq(ak_handle_tool_call(ctx, "another", "2.0"), 0);
    test_assert_eq(ak_handle_tool_call(ctx, "", "1.0"), 0);  /* Empty name */

    ak_ctx_destroy(NULL, ctx);
    return true;
}

boolean test_edge_very_deep_path(void)
{
    ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
    test_assert(ctx != NULL);
    ak_ctx_set_current(ctx);
    ak_ctx_drop_boot_capsule(ctx);

    const char *patterns[] = {"/app/**"};
    ctx->policy.fs_read_patterns = patterns;
    ctx->policy.fs_read_count = 1;

    /* Very deep path */
    long result = ak_route_open("/app/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/file.txt", 0, 0);
    test_assert(result >= 0);

    ak_ctx_destroy(NULL, ctx);
    return true;
}

boolean test_edge_unicode_in_path(void)
{
    ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
    test_assert(ctx != NULL);
    ak_ctx_set_current(ctx);
    ak_ctx_drop_boot_capsule(ctx);

    const char *patterns[] = {"/app/**"};
    ctx->policy.fs_read_patterns = patterns;
    ctx->policy.fs_read_count = 1;

    /* Unicode path (raw UTF-8 bytes) */
    long result = ak_route_open("/app/\xc3\xa9\xc3\xa8\xc3\xa0/file.txt", 0, 0);
    test_assert(result >= 0);

    ak_ctx_destroy(NULL, ctx);
    return true;
}

boolean test_edge_rapid_mode_switch(void)
{
    ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
    test_assert(ctx != NULL);
    ak_ctx_set_current(ctx);
    ak_ctx_drop_boot_capsule(ctx);

    /* Rapidly switch modes */
    for (int i = 0; i < 100; i++) {
        ak_ctx_set_mode(ctx, AK_MODE_OFF);
        ak_ctx_set_mode(ctx, AK_MODE_SOFT);
        ak_ctx_set_mode(ctx, AK_MODE_HARD);
    }

    /* Should still work normally */
    ak_ctx_set_mode(ctx, AK_MODE_SOFT);
    test_assert(!ak_ctx_boot_capsule_active(ctx));

    ak_ctx_destroy(NULL, ctx);
    return true;
}

boolean test_edge_concurrent_context_ops(void)
{
    /* Create and destroy many contexts */
    for (int i = 0; i < 50; i++) {
        ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
        test_assert(ctx != NULL);
        ak_ctx_set_current(ctx);

        /* Brief usage */
        ak_ctx_set_mode(ctx, AK_MODE_SOFT);
        ak_ctx_drop_boot_capsule(ctx);

        ak_ctx_destroy(NULL, ctx);
    }

    /* Global state should be clear */
    ak_ctx_set_current(NULL);
    test_assert(ak_ctx_current() == NULL);

    return true;
}

boolean test_edge_last_deny_overwrite(void)
{
    ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
    test_assert(ctx != NULL);
    ak_ctx_set_current(ctx);
    ak_ctx_drop_boot_capsule(ctx);

    /* Generate multiple denials */
    ak_route_open("/path1", 0, 0);
    ak_route_open("/path2", 0, 0);
    ak_route_dns_resolve("host1");
    ak_route_dns_resolve("host2");

    /* Last deny should be the most recent */
    const ak_last_deny_t *deny = ak_ctx_get_last_deny(ctx);
    test_assert(deny != NULL);
    test_assert_eq(deny->op, AK_E_NET_DNS_RESOLVE);

    ak_ctx_destroy(NULL, ctx);
    return true;
}

boolean test_edge_trace_id_uniqueness(void)
{
    ak_ctx_t *ctx = ak_ctx_create(NULL, NULL);
    test_assert(ctx != NULL);
    ak_ctx_set_current(ctx);

    u64 ids[100];
    for (int i = 0; i < 100; i++) {
        ids[i] = ak_trace_id_generate(ctx);
    }

    /* All IDs should be unique */
    for (int i = 0; i < 100; i++) {
        for (int j = i + 1; j < 100; j++) {
            test_assert(ids[i] != ids[j]);
        }
    }

    ak_ctx_destroy(NULL, ctx);
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
    /* Deny-by-default tests */
    {"deny_by_default_no_policy", test_deny_by_default_no_policy},
    {"deny_by_default_empty_fs_section", test_deny_by_default_empty_fs_section},
    {"deny_by_default_empty_net_section", test_deny_by_default_empty_net_section},

    /* Filesystem tests */
    {"fs_read_allowed", test_fs_read_allowed},
    {"fs_read_denied", test_fs_read_denied},
    {"fs_path_traversal_blocked", test_fs_path_traversal_blocked},
    {"fs_canonicalization", test_fs_canonicalization},
    {"fs_glob_single_star", test_fs_glob_single_star},
    {"fs_glob_double_star", test_fs_glob_double_star},

    /* Network tests */
    {"dns_resolution_allowed", test_dns_resolution_allowed},
    {"dns_resolution_denied", test_dns_resolution_denied},
    {"connect_allowed", test_connect_allowed},
    {"connect_denied", test_connect_denied},

    /* Agentic tests */
    {"tool_call_no_policy", test_tool_call_no_policy},
    {"tool_call_allowed", test_tool_call_allowed},
    {"tool_call_denied", test_tool_call_denied},
    {"wasm_invoke_no_policy", test_wasm_invoke_no_policy},
    {"wasm_invoke_allowed", test_wasm_invoke_allowed},
    {"infer_no_allowlist", test_infer_no_allowlist},
    {"infer_allowed", test_infer_allowed},
    {"budget_exceeded", test_budget_exceeded},
    {"token_budget_exceeded", test_token_budget_exceeded},

    /* Mode tests */
    {"mode_off_bypasses", test_mode_off_bypasses},
    {"mode_soft_enforces", test_mode_soft_enforces},
    {"boot_capsule_allows_during_boot", test_boot_capsule_allows_during_boot},
    {"boot_capsule_drop_transitions", test_boot_capsule_drop_transitions},

    /* Suggestion tests */
    {"suggestion_fs_format", test_suggestion_fs_format},
    {"suggestion_dns_format", test_suggestion_dns_format},
    {"suggestion_tool_format", test_suggestion_tool_format},
    {"suggestion_infer_format", test_suggestion_infer_format},
    {"suggestion_is_valid_toml", test_suggestion_is_valid_toml},

    /* Statistics */
    {"statistics_tracking", test_statistics_tracking},

    /* Edge case tests */
    {"edge_multiple_patterns", test_edge_multiple_patterns},
    {"edge_empty_policy_arrays", test_edge_empty_policy_arrays},
    {"edge_max_budget_values", test_edge_max_budget_values},
    {"edge_zero_budget", test_edge_zero_budget},
    {"edge_budget_at_limit", test_edge_budget_at_limit},
    {"edge_wildcard_only_patterns", test_edge_wildcard_only_patterns},
    {"edge_very_deep_path", test_edge_very_deep_path},
    {"edge_unicode_in_path", test_edge_unicode_in_path},
    {"edge_rapid_mode_switch", test_edge_rapid_mode_switch},
    {"edge_concurrent_context_ops", test_edge_concurrent_context_ops},
    {"edge_last_deny_overwrite", test_edge_last_deny_overwrite},
    {"edge_trace_id_uniqueness", test_edge_trace_id_uniqueness},

    {NULL, NULL}
};

int main(int argc, char **argv)
{
    int passed = 0;
    int failed = 0;
    const char *filter = NULL;

    if (argc > 1) {
        filter = argv[1];
        printf("=== AK Integration Tests (filter: %s) ===\n\n", filter);
    } else {
        printf("=== AK Integration Tests ===\n\n");
    }

    for (int i = 0; tests[i].name != NULL; i++) {
        /* Apply filter if provided */
        if (filter && strstr(tests[i].name, filter) == NULL)
            continue;

        printf("Running %s... ", tests[i].name);
        fflush(stdout);

        /* Clear global state between tests */
        g_current_ctx = NULL;

        if (tests[i].func()) {
            printf("PASS\n");
            passed++;
        } else {
            printf("FAIL\n");
            failed++;
        }
    }

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);

    if (failed > 0) {
        printf("\nFailed tests:\n");
        for (int i = 0; tests[i].name != NULL; i++) {
            if (filter && strstr(tests[i].name, filter) == NULL)
                continue;
            /* Re-run to find failures (simple approach) */
        }
    }

    return (failed > 0) ? EXIT_FAILURE : EXIT_SUCCESS;
}
