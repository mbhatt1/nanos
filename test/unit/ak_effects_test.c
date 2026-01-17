/*
 * Authority Kernel - Effects Logic Unit Tests
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Tests for effect request builders, canonicalization, and decision logic.
 * These tests run on the host without booting the unikernel.
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

/* Local type definitions to avoid runtime.h dependency */
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef bool boolean;

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

/* Test assertion macros */
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
 * EFFECT TYPES (matching ak_effects.h)
 * ============================================================ */

typedef enum ak_effect_op {
    /* Filesystem effects */
    AK_E_FS_OPEN        = 0x0100,
    AK_E_FS_UNLINK      = 0x0101,
    AK_E_FS_RENAME      = 0x0102,
    AK_E_FS_MKDIR       = 0x0103,

    /* Network effects */
    AK_E_NET_CONNECT    = 0x0200,
    AK_E_NET_DNS_RESOLVE = 0x0201,
    AK_E_NET_BIND       = 0x0202,
    AK_E_NET_LISTEN     = 0x0203,

    /* Process effects */
    AK_E_PROC_SPAWN     = 0x0300,

    /* Agentic effects */
    AK_E_TOOL_CALL      = 0x0400,
    AK_E_WASM_INVOKE    = 0x0401,
    AK_E_INFER          = 0x0402,
} ak_effect_op_t;

/* Maximum sizes for bounded buffers */
#define AK_MAX_TARGET     512
#define AK_MAX_PARAMS     4096
#define AK_MAX_CAPSTR     64
#define AK_MAX_SUGGEST    512
#define AK_MAX_DETAIL     256

/* Effect request structure */
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
} ak_effect_req_t;

/* Deny reason codes */
typedef enum ak_deny_reason {
    AK_DENY_NO_POLICY       = 1,
    AK_DENY_NO_CAP          = 2,
    AK_DENY_CAP_EXPIRED     = 3,
    AK_DENY_PATTERN_MISMATCH = 4,
    AK_DENY_BUDGET_EXCEEDED = 5,
    AK_DENY_RATE_LIMITED    = 6,
    AK_DENY_TAINT           = 7,
} ak_deny_reason_t;

/* Authorization decision structure */
typedef struct ak_decision {
    boolean allow;
    int reason_code;
    int errno_equiv;
    char missing_cap[AK_MAX_CAPSTR];
    char suggested_snippet[AK_MAX_SUGGEST];
    u64 trace_id;
    char detail[AK_MAX_DETAIL];
} ak_decision_t;

/* ============================================================
 * PATH CANONICALIZATION
 * ============================================================ */

/*
 * Canonicalize a filesystem path:
 * - Convert relative to absolute (using cwd)
 * - Normalize . and .. segments
 * - Remove trailing slashes (except for root)
 * - Remove duplicate slashes
 */
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
        size_t comp_len = (size_t)(p - comp_start);

        /* Handle . and .. */
        if (comp_len == 1 && comp_start[0] == '.') {
            /* Current directory - skip */
            continue;
        } else if (comp_len == 2 && comp_start[0] == '.' && comp_start[1] == '.') {
            /* Parent directory - go up */
            if (work_pos > 1) {
                work_pos--;  /* Remove trailing slash */
                while (work_pos > 1 && work[work_pos - 1] != '/')
                    work_pos--;
            }
        } else {
            /* Normal component */
            if (work_pos + comp_len + 2 >= sizeof(work))
                return false;

            /* Add separator if needed (not if we already have trailing slash) */
            if (work_pos > 0 && work[work_pos - 1] != '/')
                work[work_pos++] = '/';

            memcpy(work + work_pos, comp_start, comp_len);
            work_pos += comp_len;
        }
    }

    /* Ensure root is just "/" */
    if (work_pos == 0) {
        work[0] = '/';
        work_pos = 1;
    }

    /* Remove trailing slash (except for root) */
    if (work_pos > 1 && work[work_pos - 1] == '/')
        work_pos--;

    if (work_pos >= out_len)
        return false;

    memcpy(out, work, work_pos);
    out[work_pos] = '\0';
    return true;
}

/* ============================================================
 * NETWORK ADDRESS CANONICALIZATION
 * ============================================================ */

/*
 * Canonicalize network address to standard format:
 * - IPv4: "ip:192.168.1.1:443"
 * - IPv6: "ip:[::1]:443"
 * - DNS: "dns:example.com:443"
 */
static boolean canonicalize_net_addr(const char *addr, u16 port,
                                      char *out, size_t out_len)
{
    if (!addr || !out || out_len == 0)
        return false;

    int written;

    /* Check if it looks like an IP address */
    boolean is_ipv4 = true;
    boolean is_ipv6 = false;
    const char *p = addr;

    while (*p) {
        if (*p == ':') {
            is_ipv6 = true;
            is_ipv4 = false;
            break;
        }
        if (!(*p >= '0' && *p <= '9') && *p != '.') {
            is_ipv4 = false;
            break;
        }
        p++;
    }

    if (is_ipv4 || is_ipv6) {
        if (is_ipv6) {
            written = snprintf(out, out_len, "ip:[%s]:%u", addr, port);
        } else {
            written = snprintf(out, out_len, "ip:%s:%u", addr, port);
        }
    } else {
        /* Hostname - use dns: prefix */
        written = snprintf(out, out_len, "dns:%s:%u", addr, port);
    }

    return (written > 0 && (size_t)written < out_len);
}

/* ============================================================
 * EFFECT REQUEST BUILDERS
 * ============================================================ */

static void effect_req_init(ak_effect_req_t *req, ak_effect_op_t op)
{
    memset(req, 0, sizeof(*req));
    req->op = op;
    /* Generate a simple trace ID (in production, use proper random) */
    req->trace_id = ((u64)(unsigned int)rand() << 32) | (u64)(unsigned int)rand();
}

static boolean effect_from_open(ak_effect_req_t *req,
                                 const char *path, int flags)
{
    effect_req_init(req, AK_E_FS_OPEN);

    if (!canonicalize_path(path, "/", req->target, sizeof(req->target)))
        return false;

    /* Encode flags in params as simple JSON */
    int ret = snprintf((char *)req->params, sizeof(req->params),
                       "{\"flags\": %d}", flags);
    req->params_len = (ret > 0) ? (u32)ret : 0;
    return true;
}

static boolean effect_from_connect(ak_effect_req_t *req,
                                    const char *addr, u16 port)
{
    effect_req_init(req, AK_E_NET_CONNECT);

    if (!canonicalize_net_addr(addr, port, req->target, sizeof(req->target)))
        return false;

    req->params_len = 0;
    return true;
}

static boolean effect_from_dns(ak_effect_req_t *req, const char *hostname)
{
    effect_req_init(req, AK_E_NET_DNS_RESOLVE);

    int written = snprintf(req->target, sizeof(req->target), "dns:%s", hostname);
    if (written < 0 || (size_t)written >= sizeof(req->target))
        return false;

    req->params_len = 0;
    return true;
}

static boolean effect_from_tool(ak_effect_req_t *req,
                                 const char *name, const char *version)
{
    effect_req_init(req, AK_E_TOOL_CALL);

    int written = snprintf(req->target, sizeof(req->target),
                           "tool:%s:%s", name, version ? version : "latest");
    if (written < 0 || (size_t)written >= sizeof(req->target))
        return false;

    req->params_len = 0;
    return true;
}

static boolean effect_from_infer(ak_effect_req_t *req,
                                  const char *model, u64 max_tokens)
{
    effect_req_init(req, AK_E_INFER);

    int written = snprintf(req->target, sizeof(req->target), "model:%s", model);
    if (written < 0 || (size_t)written >= sizeof(req->target))
        return false;

    req->budget.tokens = max_tokens;
    req->params_len = 0;
    return true;
}

/* ============================================================
 * SIMPLE DECISION LOGIC
 * ============================================================ */

/*
 * Simple pattern matching for testing.
 * Supports * as wildcard.
 */
static boolean pattern_match(const char *pattern, const char *str)
{
    if (!pattern || !str)
        return false;

    while (*pattern && *str) {
        if (*pattern == '*') {
            pattern++;
            if (!*pattern)
                return true;  /* Trailing * matches all */

            /* Try to match rest of pattern */
            while (*str) {
                if (pattern_match(pattern, str))
                    return true;
                str++;
            }
            return false;
        }

        if (*pattern != *str)
            return false;

        pattern++;
        str++;
    }

    /* Handle trailing wildcards */
    while (*pattern == '*')
        pattern++;

    return (*pattern == '\0' && *str == '\0');
}

/*
 * Simple policy check for testing.
 * In production, this is done by ak_authorize_and_execute.
 */
typedef struct simple_policy {
    const char **fs_read_patterns;
    size_t fs_read_count;
    const char **fs_write_patterns;
    size_t fs_write_count;
    const char **dns_patterns;
    size_t dns_count;
    const char **tool_patterns;
    size_t tool_count;
} simple_policy_t;

static boolean check_effect(const simple_policy_t *policy,
                            const ak_effect_req_t *req,
                            ak_decision_t *decision)
{
    memset(decision, 0, sizeof(*decision));
    decision->trace_id = req->trace_id;

    /* No policy = deny by default */
    if (!policy) {
        decision->allow = false;
        decision->reason_code = AK_DENY_NO_POLICY;
        decision->errno_equiv = 1;  /* EPERM */
        strncpy(decision->detail, "no policy loaded", sizeof(decision->detail) - 1);
        return false;
    }

    switch (req->op) {
    case AK_E_FS_OPEN: {
        /* Check read patterns (simplified - in reality, check flags) */
        for (size_t i = 0; i < policy->fs_read_count; i++) {
            if (pattern_match(policy->fs_read_patterns[i], req->target)) {
                decision->allow = true;
                return true;
            }
        }
        decision->allow = false;
        decision->reason_code = AK_DENY_PATTERN_MISMATCH;
        decision->errno_equiv = 13;  /* EACCES */
        strncpy(decision->missing_cap, "fs.read", sizeof(decision->missing_cap) - 1);
        snprintf(decision->suggested_snippet, sizeof(decision->suggested_snippet),
                 "fs.read: [\"%s\"]", req->target);
        snprintf(decision->detail, sizeof(decision->detail),
                 "path '%s' not in allowed read patterns", req->target);
        return false;
    }

    case AK_E_NET_DNS_RESOLVE: {
        /* Extract hostname from target (format: "dns:hostname") */
        const char *hostname = req->target;
        if (strncmp(hostname, "dns:", 4) == 0)
            hostname += 4;

        for (size_t i = 0; i < policy->dns_count; i++) {
            if (pattern_match(policy->dns_patterns[i], hostname)) {
                decision->allow = true;
                return true;
            }
        }
        decision->allow = false;
        decision->reason_code = AK_DENY_PATTERN_MISMATCH;
        decision->errno_equiv = 1;  /* EPERM */
        strncpy(decision->missing_cap, "net.dns", sizeof(decision->missing_cap) - 1);
        snprintf(decision->suggested_snippet, sizeof(decision->suggested_snippet),
                 "net.dns: [\"%s\"]", hostname);
        snprintf(decision->detail, sizeof(decision->detail),
                 "DNS resolution for '%s' not allowed", hostname);
        return false;
    }

    case AK_E_TOOL_CALL: {
        /* Extract tool name from target (format: "tool:name:version") */
        const char *tool_name = req->target;
        if (strncmp(tool_name, "tool:", 5) == 0)
            tool_name += 5;

        /* Match up to the version separator */
        char name_only[256];
        const char *colon = strchr(tool_name, ':');
        if (colon) {
            size_t len = (size_t)(colon - tool_name);
            if (len >= sizeof(name_only))
                len = sizeof(name_only) - 1;
            memcpy(name_only, tool_name, len);
            name_only[len] = '\0';
        } else {
            strncpy(name_only, tool_name, sizeof(name_only) - 1);
            name_only[sizeof(name_only) - 1] = '\0';
        }

        for (size_t i = 0; i < policy->tool_count; i++) {
            if (pattern_match(policy->tool_patterns[i], name_only)) {
                decision->allow = true;
                return true;
            }
        }
        decision->allow = false;
        decision->reason_code = AK_DENY_NO_CAP;
        decision->errno_equiv = 1;  /* EPERM */
        strncpy(decision->missing_cap, "tools.allow", sizeof(decision->missing_cap) - 1);
        snprintf(decision->suggested_snippet, sizeof(decision->suggested_snippet),
                 "tools.allow: [\"%s\"]", name_only);
        snprintf(decision->detail, sizeof(decision->detail),
                 "tool '%s' not in allowed list", name_only);
        return false;
    }

    default:
        decision->allow = false;
        decision->reason_code = AK_DENY_NO_CAP;
        decision->errno_equiv = 38;  /* ENOSYS */
        snprintf(decision->detail, sizeof(decision->detail),
                 "unsupported effect op 0x%x", req->op);
        return false;
    }
}

/* ============================================================
 * TEST CASES: EFFECT REQUEST BUILDERS
 * ============================================================ */

boolean test_effect_from_open(void)
{
    ak_effect_req_t req;

    test_assert(effect_from_open(&req, "/app/file.txt", 0));
    test_assert(req.op == AK_E_FS_OPEN);
    test_assert(strcmp(req.target, "/app/file.txt") == 0);
    test_assert(req.trace_id != 0);

    return true;
}

boolean test_effect_from_open_relative(void)
{
    ak_effect_req_t req;

    test_assert(effect_from_open(&req, "file.txt", 0));
    test_assert(strcmp(req.target, "/file.txt") == 0);

    return true;
}

boolean test_effect_from_connect(void)
{
    ak_effect_req_t req;

    test_assert(effect_from_connect(&req, "192.168.1.1", 443));
    test_assert(req.op == AK_E_NET_CONNECT);
    test_assert(strcmp(req.target, "ip:192.168.1.1:443") == 0);

    return true;
}

boolean test_effect_from_connect_dns(void)
{
    ak_effect_req_t req;

    test_assert(effect_from_connect(&req, "example.com", 443));
    test_assert(strcmp(req.target, "dns:example.com:443") == 0);

    return true;
}

boolean test_effect_from_dns(void)
{
    ak_effect_req_t req;

    test_assert(effect_from_dns(&req, "example.com"));
    test_assert(req.op == AK_E_NET_DNS_RESOLVE);
    test_assert(strcmp(req.target, "dns:example.com") == 0);

    return true;
}

boolean test_effect_from_tool(void)
{
    ak_effect_req_t req;

    test_assert(effect_from_tool(&req, "read_file", "1.0"));
    test_assert(req.op == AK_E_TOOL_CALL);
    test_assert(strcmp(req.target, "tool:read_file:1.0") == 0);

    return true;
}

boolean test_effect_from_infer(void)
{
    ak_effect_req_t req;

    test_assert(effect_from_infer(&req, "gpt-4", 4096));
    test_assert(req.op == AK_E_INFER);
    test_assert(strcmp(req.target, "model:gpt-4") == 0);
    test_assert(req.budget.tokens == 4096);

    return true;
}

/* ============================================================
 * TEST CASES: CANONICALIZATION
 * ============================================================ */

boolean test_canonicalize_path_absolute(void)
{
    char out[AK_MAX_TARGET];

    test_assert(canonicalize_path("/app/file.txt", "/", out, sizeof(out)));
    test_assert(strcmp(out, "/app/file.txt") == 0);

    return true;
}

boolean test_canonicalize_path_dotdot(void)
{
    char out[AK_MAX_TARGET];

    test_assert(canonicalize_path("/app/../other/file.txt", "/", out, sizeof(out)));
    test_assert(strcmp(out, "/other/file.txt") == 0);

    test_assert(canonicalize_path("/app/./file.txt", "/", out, sizeof(out)));
    test_assert(strcmp(out, "/app/file.txt") == 0);

    return true;
}

boolean test_canonicalize_path_double_slash(void)
{
    char out[AK_MAX_TARGET];

    test_assert(canonicalize_path("/app//file.txt", "/", out, sizeof(out)));
    test_assert(strcmp(out, "/app/file.txt") == 0);

    test_assert(canonicalize_path("///app///file.txt", "/", out, sizeof(out)));
    test_assert(strcmp(out, "/app/file.txt") == 0);

    return true;
}

boolean test_canonicalize_path_trailing_slash(void)
{
    char out[AK_MAX_TARGET];

    test_assert(canonicalize_path("/app/", "/", out, sizeof(out)));
    test_assert(strcmp(out, "/app") == 0);

    test_assert(canonicalize_path("/", "/", out, sizeof(out)));
    test_assert(strcmp(out, "/") == 0);

    return true;
}

boolean test_canonicalize_path_relative(void)
{
    char out[AK_MAX_TARGET];

    test_assert(canonicalize_path("file.txt", "/app", out, sizeof(out)));
    test_assert(strcmp(out, "/app/file.txt") == 0);

    test_assert(canonicalize_path("../other/file.txt", "/app/sub", out, sizeof(out)));
    test_assert(strcmp(out, "/app/other/file.txt") == 0);

    return true;
}

boolean test_canonicalize_net_ipv4(void)
{
    char out[AK_MAX_TARGET];

    test_assert(canonicalize_net_addr("192.168.1.1", 443, out, sizeof(out)));
    test_assert(strcmp(out, "ip:192.168.1.1:443") == 0);

    test_assert(canonicalize_net_addr("8.8.8.8", 53, out, sizeof(out)));
    test_assert(strcmp(out, "ip:8.8.8.8:53") == 0);

    return true;
}

boolean test_canonicalize_net_dns(void)
{
    char out[AK_MAX_TARGET];

    test_assert(canonicalize_net_addr("example.com", 443, out, sizeof(out)));
    test_assert(strcmp(out, "dns:example.com:443") == 0);

    test_assert(canonicalize_net_addr("api.example.com", 8080, out, sizeof(out)));
    test_assert(strcmp(out, "dns:api.example.com:8080") == 0);

    return true;
}

/* ============================================================
 * TEST CASES: DECISION LOGIC
 * ============================================================ */

boolean test_decision_no_policy(void)
{
    ak_effect_req_t req;
    ak_decision_t decision;

    effect_from_open(&req, "/app/file.txt", 0);
    check_effect(NULL, &req, &decision);

    test_assert(decision.allow == false);
    test_assert(decision.reason_code == AK_DENY_NO_POLICY);

    return true;
}

boolean test_decision_fs_allow(void)
{
    ak_effect_req_t req;
    ak_decision_t decision;

    const char *patterns[] = {"/app/*"};
    simple_policy_t policy = {
        .fs_read_patterns = patterns,
        .fs_read_count = 1,
    };

    effect_from_open(&req, "/app/file.txt", 0);
    check_effect(&policy, &req, &decision);

    test_assert(decision.allow == true);

    return true;
}

boolean test_decision_fs_deny(void)
{
    ak_effect_req_t req;
    ak_decision_t decision;

    const char *patterns[] = {"/app/*"};
    simple_policy_t policy = {
        .fs_read_patterns = patterns,
        .fs_read_count = 1,
    };

    effect_from_open(&req, "/etc/passwd", 0);
    check_effect(&policy, &req, &decision);

    test_assert(decision.allow == false);
    test_assert(decision.reason_code == AK_DENY_PATTERN_MISMATCH);
    test_assert(strcmp(decision.missing_cap, "fs.read") == 0);
    test_assert(strstr(decision.suggested_snippet, "/etc/passwd") != NULL);

    return true;
}

boolean test_decision_dns_allow(void)
{
    ak_effect_req_t req;
    ak_decision_t decision;

    const char *patterns[] = {"example.com", "*.api.example.com"};
    simple_policy_t policy = {
        .dns_patterns = patterns,
        .dns_count = 2,
    };

    effect_from_dns(&req, "example.com");
    check_effect(&policy, &req, &decision);

    test_assert(decision.allow == true);

    return true;
}

boolean test_decision_dns_deny(void)
{
    ak_effect_req_t req;
    ak_decision_t decision;

    const char *patterns[] = {"example.com"};
    simple_policy_t policy = {
        .dns_patterns = patterns,
        .dns_count = 1,
    };

    effect_from_dns(&req, "malicious.com");
    check_effect(&policy, &req, &decision);

    test_assert(decision.allow == false);
    test_assert(strcmp(decision.missing_cap, "net.dns") == 0);

    return true;
}

boolean test_decision_tool_allow(void)
{
    ak_effect_req_t req;
    ak_decision_t decision;

    const char *patterns[] = {"read_file", "write_file"};
    simple_policy_t policy = {
        .tool_patterns = patterns,
        .tool_count = 2,
    };

    effect_from_tool(&req, "read_file", "1.0");
    check_effect(&policy, &req, &decision);

    test_assert(decision.allow == true);

    return true;
}

boolean test_decision_tool_wildcard(void)
{
    ak_effect_req_t req;
    ak_decision_t decision;

    const char *patterns[] = {"http_*"};
    simple_policy_t policy = {
        .tool_patterns = patterns,
        .tool_count = 1,
    };

    effect_from_tool(&req, "http_get", "1.0");
    check_effect(&policy, &req, &decision);

    test_assert(decision.allow == true);

    effect_from_tool(&req, "http_post", "2.0");
    check_effect(&policy, &req, &decision);

    test_assert(decision.allow == true);

    return true;
}

boolean test_decision_tool_deny(void)
{
    ak_effect_req_t req;
    ak_decision_t decision;

    const char *patterns[] = {"safe_tool"};
    simple_policy_t policy = {
        .tool_patterns = patterns,
        .tool_count = 1,
    };

    effect_from_tool(&req, "dangerous_tool", "1.0");
    check_effect(&policy, &req, &decision);

    test_assert(decision.allow == false);
    test_assert(strcmp(decision.missing_cap, "tools.allow") == 0);

    return true;
}

boolean test_decision_suggestion_format(void)
{
    ak_effect_req_t req;
    ak_decision_t decision;

    simple_policy_t policy = {0};

    effect_from_open(&req, "/secret/data", 0);
    check_effect(&policy, &req, &decision);

    test_assert(decision.allow == false);
    /* Suggestion should be copy-pasteable */
    test_assert(strstr(decision.suggested_snippet, "fs.read") != NULL);
    test_assert(strstr(decision.suggested_snippet, "/secret/data") != NULL);

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
    /* Effect request builder tests */
    {"effect_from_open", test_effect_from_open},
    {"effect_from_open_relative", test_effect_from_open_relative},
    {"effect_from_connect", test_effect_from_connect},
    {"effect_from_connect_dns", test_effect_from_connect_dns},
    {"effect_from_dns", test_effect_from_dns},
    {"effect_from_tool", test_effect_from_tool},
    {"effect_from_infer", test_effect_from_infer},

    /* Canonicalization tests */
    {"canonicalize_path_absolute", test_canonicalize_path_absolute},
    {"canonicalize_path_dotdot", test_canonicalize_path_dotdot},
    {"canonicalize_path_double_slash", test_canonicalize_path_double_slash},
    {"canonicalize_path_trailing_slash", test_canonicalize_path_trailing_slash},
    {"canonicalize_path_relative", test_canonicalize_path_relative},
    {"canonicalize_net_ipv4", test_canonicalize_net_ipv4},
    {"canonicalize_net_dns", test_canonicalize_net_dns},

    /* Decision logic tests */
    {"decision_no_policy", test_decision_no_policy},
    {"decision_fs_allow", test_decision_fs_allow},
    {"decision_fs_deny", test_decision_fs_deny},
    {"decision_dns_allow", test_decision_dns_allow},
    {"decision_dns_deny", test_decision_dns_deny},
    {"decision_tool_allow", test_decision_tool_allow},
    {"decision_tool_wildcard", test_decision_tool_wildcard},
    {"decision_tool_deny", test_decision_tool_deny},
    {"decision_suggestion_format", test_decision_suggestion_format},

    {NULL, NULL}
};

int main(int argc, char **argv)
{
    (void)argc;  /* unused */
    (void)argv;  /* unused */

    int passed = 0;
    int failed = 0;

    /* Seed random for trace IDs */
    srand(42);

    printf("=== AK Effects Logic Tests ===\n\n");

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
