/*
 * Authority Kernel - Effects Implementation
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * COORDINATOR-OWNED: This file implements the single authority gate.
 * All effectful operations MUST flow through ak_authorize_and_execute().
 *
 * This is THE critical enforcement point for deny-by-default security.
 */

#include "ak_effects.h"
#include "ak_compat.h"
#include "ak_assert.h"
#include "ak_policy.h"
#include "ak_audit.h"
#include "ak_deny_ux.h"
#include "ak_fd_table.h"
#include "ak_record.h"
#include "ak_process.h"

/* Forward declaration for policy v2 check (implemented by Agent B) */
struct ak_policy_v2;
extern boolean ak_policy_v2_check(struct ak_policy_v2 *p,
                                   const ak_effect_req_t *req,
                                   ak_decision_t *decision_out);

/* Forward declarations for helper functions */
static int ak_format_u8(char *buf, u8 val);
static int ak_format_u16(char *buf, u16 val);
static int ak_format_hex16(char *buf, u16 val);

/* ============================================================
 * MODULE STATE
 * ============================================================ */

/* Global heap for effects subsystem */
static heap effects_heap = NULL;

/* Per-thread context storage */
static __thread ak_ctx_t *current_ctx = NULL;

/* Global statistics */
static ak_effects_stats_t global_stats;

/*
 * CONCURRENCY FIX (BUG-012): Trace ID counter must use atomic operations.
 * Multiple threads can call ak_trace_id_generate() concurrently.
 * Using __sync_fetch_and_add() ensures atomic increment.
 */
static volatile u64 global_trace_counter = 0;

/* Rate limiter state for deny logging */
#define AK_DENY_RATE_LIMIT_WINDOW_NS  (1000000000ULL)  /* 1 second */
#define AK_DENY_RATE_LIMIT_MAX        10               /* 10 per second per effect type */

typedef struct ak_rate_limiter {
    u64 window_start_ns;
    u32 count_per_op[16];  /* One counter per effect category */
} ak_rate_limiter_t;

static __thread ak_rate_limiter_t deny_rate_limiter;

/*
 * HARD MODE SUPPORT: TLS flag to track authorized effect execution.
 *
 * When AK_MODE_HARD is active, raw syscalls are blocked unless they're
 * being made as part of an authorized AK API call. This flag is set to
 * true during ak_authorize_and_execute() when authorization succeeds,
 * allowing the subsequent syscall to proceed.
 *
 * Thread-local to ensure correct behavior in multi-threaded contexts.
 */
static __thread boolean ak_in_authorized_effect = false;

/* Accessor functions for HARD mode flag */
boolean ak_is_in_authorized_effect(void)
{
    return ak_in_authorized_effect;
}

void ak_set_in_authorized_effect(boolean value)
{
    ak_in_authorized_effect = value;
}

/* ============================================================
 * INITIALIZATION / SHUTDOWN
 * ============================================================ */

void ak_effects_init(heap h)
{
    /* PRECONDITION: Heap must be valid */
    AK_CHECK_NOT_NULL_VOID(h);
    if (h == INVALID_ADDRESS) {
        ak_error("ak_effects_init: INVALID_ADDRESS heap");
        return;
    }

    effects_heap = h;

    /* Zero statistics */
    ak_memzero(&global_stats, sizeof(global_stats));

    /* Initialize trace counter with some entropy */
    global_trace_counter = ak_now_ms() ^ 0xABCDEF123456ULL;

    ak_debug("ak_effects: initialized");

    /* POSTCONDITION: effects_heap is set */
    AK_POSTCONDITION(effects_heap != NULL);
}

void ak_effects_shutdown(void)
{
    effects_heap = NULL;
    ak_debug("ak_effects: shutdown");
}

/* ============================================================
 * CONTEXT MANAGEMENT
 * FIX(BUG-017): All context functions marked __attribute__((weak))
 * to resolve ODR violation with ak_context.c which owns the
 * primary implementations. ak_context.c functions take precedence.
 * ============================================================ */

__attribute__((weak))
ak_ctx_t *ak_ctx_current(void)
{
    return current_ctx;
}

__attribute__((weak))
void ak_ctx_set_current(ak_ctx_t *ctx)
{
    current_ctx = ctx;
}

__attribute__((weak))
ak_ctx_t *ak_ctx_create(heap h, ak_agent_context_t *agent)
{
    /* PRECONDITION: Heap must be valid */
    AK_CHECK_NOT_NULL(h, NULL);
    if (h == INVALID_ADDRESS) {
        ak_error("ak_ctx_create: INVALID_ADDRESS heap");
        return NULL;
    }

    ak_ctx_t *ctx = ak_alloc_zero(h, ak_ctx_t);
    if (ak_is_invalid_address(ctx))
        return NULL;

    ctx->agent = agent;
    ctx->mode = AK_MODE_SOFT;  /* Default to soft enforcement */
    ctx->boot_capsule_active = true;
    ctx->boot_capsule_dropped = false;
    ctx->trace_counter = 0;
    ctx->policy = NULL;
    ctx->record = NULL;

    /* Initialize last_deny */
    ak_memzero(&ctx->last_deny, sizeof(ctx->last_deny));

    /* POSTCONDITION: Context is properly initialized */
    AK_POSTCONDITION(ctx != NULL);
    AK_POSTCONDITION(ctx->mode == AK_MODE_SOFT);

    return ctx;
}

__attribute__((weak))
void ak_ctx_destroy(heap h, ak_ctx_t *ctx)
{
    if (!ctx)
        return;

    /* Clear sensitive data */
    ak_memzero(&ctx->last_deny, sizeof(ctx->last_deny));

    deallocate(h, ctx, sizeof(ak_ctx_t));
}

__attribute__((weak))
void ak_ctx_set_mode(ak_ctx_t *ctx, ak_mode_t mode)
{
    if (!ctx)
        return;

    ctx->mode = mode;
    ak_debug("ak_effects: mode set to %d", mode);
}

__attribute__((weak))
ak_mode_t ak_ctx_get_mode(ak_ctx_t *ctx)
{
    if (!ctx)
        return AK_MODE_OFF;
    return ctx->mode;
}

/* ============================================================
 * BOOT CAPSULE
 * FIX(BUG-017): Marked __attribute__((weak)) for ODR resolution
 * ============================================================ */

__attribute__((weak))
boolean ak_ctx_boot_capsule_active(ak_ctx_t *ctx)
{
    if (!ctx)
        return false;
    return ctx->boot_capsule_active && !ctx->boot_capsule_dropped;
}

__attribute__((weak))
void ak_ctx_drop_boot_capsule(ak_ctx_t *ctx)
{
    if (!ctx)
        return;

    ctx->boot_capsule_dropped = true;
    ctx->boot_capsule_active = false;

    ak_debug("ak_effects: boot capsule dropped");
}

/* ============================================================
 * TRACE ID GENERATION
 * FIX(BUG-017): Marked __attribute__((weak)) for ODR resolution
 * ============================================================ */

__attribute__((weak))
u64 ak_trace_id_generate(ak_ctx_t *ctx)
{
    u64 trace_id;

    if (ctx) {
        /*
         * Per-context counter is thread-safe since ctx is typically
         * thread-local. Increment atomically just in case.
         */
        trace_id = __sync_fetch_and_add(&ctx->trace_counter, 1) + 1;
    } else {
        /*
         * CONCURRENCY FIX (BUG-012): Use atomic increment for global counter.
         * Multiple threads may call this without a context.
         */
        trace_id = __sync_fetch_and_add(&global_trace_counter, 1) + 1;
    }

    /* Mix in timestamp for uniqueness */
    trace_id = (trace_id << 20) | (ak_now_ms() & 0xFFFFF);

    return trace_id;
}

/* ============================================================
 * CANONICALIZATION
 * ============================================================ */

int ak_canonicalize_path(const char *path, char *out, u32 out_len,
                         const char *cwd)
{
    if (!path || !out || out_len == 0)
        return -EINVAL;

    u32 pos = 0;
    const char *src = path;

    /* Handle relative paths: prepend cwd */
    if (path[0] != '/') {
        if (!cwd)
            cwd = "/";

        u64 cwd_len = runtime_strlen(cwd);
        if (cwd_len >= out_len)
            return -ERANGE;

        runtime_strncpy(out, cwd, out_len);
        pos = cwd_len;

        /* Ensure separator */
        if (pos > 0 && out[pos - 1] != '/' && pos < out_len - 1) {
            out[pos++] = '/';
        }
    }

    /* Process path components */
    while (*src && pos < out_len - 1) {
        /* Skip leading/consecutive slashes */
        while (*src == '/')
            src++;

        if (*src == '\0')
            break;

        /* Find end of component */
        const char *end = src;
        while (*end && *end != '/')
            end++;

        u64 comp_len = end - src;

        /* Handle "." - skip it */
        if (comp_len == 1 && src[0] == '.') {
            src = end;
            continue;
        }

        /* Handle ".." - go up one level, but never above initial cwd */
        if (comp_len == 2 && src[0] == '.' && src[1] == '.') {
            /* FIX(S1-1): Track minimum position to prevent escape above cwd */
            u64 min_pos = cwd ? runtime_strlen(cwd) : 1;
            if (min_pos == 0) min_pos = 1;  /* At least stay at root */
            if (pos > min_pos) {
                pos--;  /* Move before trailing slash if any */
                while (pos > min_pos && out[pos - 1] != '/')
                    pos--;
            }
            src = end;
            continue;
        }

        /* Handle null bytes - skip (security) */
        boolean has_null = false;
        for (u64 i = 0; i < comp_len; i++) {
            if (src[i] == '\0') {
                has_null = true;
                break;
            }
        }
        if (has_null) {
            src = end;
            continue;
        }

        /* Add separator if needed */
        if (pos == 0 || out[pos - 1] != '/') {
            if (pos < out_len - 1)
                out[pos++] = '/';
        }

        /* Copy component */
        for (u64 i = 0; i < comp_len && pos < out_len - 1; i++) {
            out[pos++] = src[i];
        }

        src = end;
    }

    /* Ensure at least "/" for root */
    if (pos == 0 && out_len > 0) {
        out[pos++] = '/';
    }

    /* Null terminate */
    out[pos] = '\0';

    return 0;
}

int ak_canonicalize_sockaddr(const struct sockaddr *addr, socklen_t len,
                             char *out, u32 out_len)
{
    if (!addr || !out || out_len < 32)
        return -EINVAL;

    /* Handle AF_INET (IPv4) */
    if (addr->sa_family == 2) {  /* AF_INET */
        if (len < 8)  /* sizeof(struct sockaddr_in) minimum */
            return -EINVAL;

        /* Extract IP and port from sockaddr_in layout:
         * struct sockaddr_in {
         *     sa_family_t sin_family;   // offset 0, 2 bytes
         *     in_port_t sin_port;       // offset 2, 2 bytes (network order)
         *     struct in_addr sin_addr;  // offset 4, 4 bytes
         * };
         */
        const u8 *bytes = (const u8 *)addr;
        u16 port = (bytes[2] << 8) | bytes[3];  /* Network to host */
        u8 a = bytes[4], b = bytes[5], c = bytes[6], d = bytes[7];

        /* Normalize loopback: 127.x.x.x -> 127.0.0.1 */
        if (a == 127) {
            b = 0; c = 0; d = 1;
        }

        /* Format: ip:a.b.c.d:port */
        int written = 0;
        out[written++] = 'i';
        out[written++] = 'p';
        out[written++] = ':';

        /* IP address */
        written += ak_format_u8(out + written, a);
        out[written++] = '.';
        written += ak_format_u8(out + written, b);
        out[written++] = '.';
        written += ak_format_u8(out + written, c);
        out[written++] = '.';
        written += ak_format_u8(out + written, d);
        out[written++] = ':';

        /* Port */
        written += ak_format_u16(out + written, port);
        out[written] = '\0';

        return 0;
    }

    /* Handle AF_INET6 (IPv6) */
    if (addr->sa_family == 10) {  /* AF_INET6 */
        if (len < 28)  /* sizeof(struct sockaddr_in6) minimum */
            return -EINVAL;

        const u8 *bytes = (const u8 *)addr;
        u16 port = (bytes[2] << 8) | bytes[3];
        const u8 *ip6 = bytes + 8;  /* sin6_addr offset */

        /* Check for IPv4-mapped IPv6 (::ffff:a.b.c.d) */
        boolean is_v4_mapped = true;
        for (int i = 0; i < 10; i++) {
            if (ip6[i] != 0) {
                is_v4_mapped = false;
                break;
            }
        }
        if (is_v4_mapped && ip6[10] == 0xff && ip6[11] == 0xff) {
            /* Treat as IPv4 */
            u8 a = ip6[12], b = ip6[13], c = ip6[14], d = ip6[15];

            int written = 0;
            out[written++] = 'i';
            out[written++] = 'p';
            out[written++] = ':';
            written += ak_format_u8(out + written, a);
            out[written++] = '.';
            written += ak_format_u8(out + written, b);
            out[written++] = '.';
            written += ak_format_u8(out + written, c);
            out[written++] = '.';
            written += ak_format_u8(out + written, d);
            out[written++] = ':';
            written += ak_format_u16(out + written, port);
            out[written] = '\0';
            return 0;
        }

        /* Check for loopback (::1) */
        boolean is_loopback = true;
        for (int i = 0; i < 15; i++) {
            if (ip6[i] != 0) {
                is_loopback = false;
                break;
            }
        }
        if (is_loopback && ip6[15] == 1) {
            /* Format as IPv6 loopback */
            int written = 0;
            out[written++] = 'i';
            out[written++] = 'p';
            out[written++] = ':';
            out[written++] = '[';
            out[written++] = ':';
            out[written++] = ':';
            out[written++] = '1';
            out[written++] = ']';
            out[written++] = ':';
            written += ak_format_u16(out + written, port);
            out[written] = '\0';
            return 0;
        }

        /* Format general IPv6: ip:[xxxx:xxxx:...]:port */
        /* Simplified - just hex dump each group */
        int written = 0;
        out[written++] = 'i';
        out[written++] = 'p';
        out[written++] = ':';
        out[written++] = '[';

        for (int i = 0; i < 8; i++) {
            if (i > 0) out[written++] = ':';
            u16 group = (ip6[i*2] << 8) | ip6[i*2 + 1];
            written += ak_format_hex16(out + written, group);
        }

        out[written++] = ']';
        out[written++] = ':';
        written += ak_format_u16(out + written, port);
        out[written] = '\0';

        return 0;
    }

    /* Unknown address family */
    return -EAFNOSUPPORT;
}

/* Helper: format u8 as decimal */
static int ak_format_u8(char *buf, u8 val)
{
    int len = 0;
    if (val >= 100) {
        buf[len++] = '0' + (val / 100);
        val %= 100;
        buf[len++] = '0' + (val / 10);
        val %= 10;
    } else if (val >= 10) {
        buf[len++] = '0' + (val / 10);
        val %= 10;
    }
    buf[len++] = '0' + val;
    return len;
}

/* Helper: format u16 as decimal */
static int ak_format_u16(char *buf, u16 val)
{
    char tmp[6];
    int len = 0;

    if (val == 0) {
        buf[0] = '0';
        return 1;
    }

    while (val > 0) {
        tmp[len++] = '0' + (val % 10);
        val /= 10;
    }

    /* Reverse */
    for (int i = 0; i < len; i++) {
        buf[i] = tmp[len - 1 - i];
    }

    return len;
}

/* Helper: format u16 as hex */
static int ak_format_hex16(char *buf, u16 val)
{
    static const char hex[] = "0123456789abcdef";
    buf[0] = hex[(val >> 12) & 0xf];
    buf[1] = hex[(val >> 8) & 0xf];
    buf[2] = hex[(val >> 4) & 0xf];
    buf[3] = hex[val & 0xf];
    return 4;
}

/* ============================================================
 * EFFECT REQUEST BUILDERS
 * ============================================================ */

/* Common initialization for effect requests */
static void ak_effect_req_init(ak_effect_req_t *req, ak_ctx_t *ctx,
                               ak_effect_op_t op)
{
    ak_memzero(req, sizeof(*req));
    req->op = op;
    req->trace_id = ak_trace_id_generate(ctx);

    if (ctx && ctx->agent) {
        /* TODO: Get actual pid/tid from agent context */
        req->pid = 1;
        req->tid = 1;
    }
}

int ak_effect_from_open(ak_effect_req_t *req, ak_ctx_t *ctx,
                        const char *path, int flags, int mode)
{
    if (!req || !path)
        return -EINVAL;

    ak_effect_req_init(req, ctx, AK_E_FS_OPEN);

    /* Canonicalize path */
    int err = ak_canonicalize_path(path, req->target, AK_MAX_TARGET, "/");
    if (err != 0)
        return err;

    /* Encode flags and mode in params as minimal JSON */
    req->params_len = 0;
    char *p = (char *)req->params;
    int len = 0;

    p[len++] = '{';
    p[len++] = '"';
    p[len++] = 'f';  /* flags */
    p[len++] = '"';
    p[len++] = ':';
    len += ak_format_u16(p + len, flags & 0xFFFF);
    p[len++] = ',';
    p[len++] = '"';
    p[len++] = 'm';  /* mode */
    p[len++] = '"';
    p[len++] = ':';
    len += ak_format_u16(p + len, mode & 0xFFFF);
    p[len++] = '}';
    p[len] = '\0';

    req->params_len = len;

    return 0;
}

int ak_effect_from_openat(ak_effect_req_t *req, ak_ctx_t *ctx,
                          int dirfd, const char *path, int flags, int mode)
{
    if (!req || !path)
        return -EINVAL;

    /* Handle absolute paths directly - dirfd is ignored */
    if (path[0] == '/') {
        return ak_effect_from_open(req, ctx, path, flags, mode);
    }

    /* Handle AT_FDCWD - resolve relative to current working directory */
    if (dirfd == AT_FDCWD) {
        char cwd[AK_MAX_TARGET];
        int err = ak_fd_table_get_cwd(cwd, sizeof(cwd));
        if (err < 0) {
            /* Fallback to root if CWD unavailable */
            cwd[0] = '/';
            cwd[1] = '\0';
        }

        char full_path[AK_MAX_TARGET];
        err = ak_canonicalize_path(path, full_path, sizeof(full_path), cwd);
        if (err < 0)
            return err;

        return ak_effect_from_open(req, ctx, full_path, flags, mode);
    }

    /* Resolve relative to dirfd using FD table */
    char resolved_path[AK_MAX_TARGET];
    int err = ak_fd_table_resolve_at(dirfd, path, resolved_path, sizeof(resolved_path));
    if (err < 0) {
        /*
         * FD table lookup failed. This could be:
         *   -EBADF: dirfd not registered (unknown FD)
         *   -ENOTDIR: dirfd is not a directory
         *
         * For policy enforcement, we need to fail securely rather than
         * using a placeholder path that could lead to incorrect decisions.
         */
        ak_debug("ak_effect_from_openat: fd=%d path=%s resolve failed err=%d",
                 dirfd, path, err);
        return err;
    }

    return ak_effect_from_open(req, ctx, resolved_path, flags, mode);
}

int ak_effect_from_unlink(ak_effect_req_t *req, ak_ctx_t *ctx,
                          const char *path)
{
    if (!req || !path)
        return -EINVAL;

    ak_effect_req_init(req, ctx, AK_E_FS_UNLINK);

    int err = ak_canonicalize_path(path, req->target, AK_MAX_TARGET, "/");
    if (err != 0)
        return err;

    req->params_len = 2;
    req->params[0] = '{';
    req->params[1] = '}';

    return 0;
}

int ak_effect_from_rename(ak_effect_req_t *req, ak_ctx_t *ctx,
                          const char *oldpath, const char *newpath)
{
    if (!req || !oldpath || !newpath)
        return -EINVAL;

    ak_effect_req_init(req, ctx, AK_E_FS_RENAME);

    /* Target is the destination path */
    int err = ak_canonicalize_path(newpath, req->target, AK_MAX_TARGET, "/");
    if (err != 0)
        return err;

    /* Encode source in params */
    char canon_old[AK_MAX_TARGET];
    err = ak_canonicalize_path(oldpath, canon_old, AK_MAX_TARGET, "/");
    if (err != 0)
        return err;

    char *p = (char *)req->params;
    int len = 0;
    p[len++] = '{';
    p[len++] = '"';
    p[len++] = 's';  /* source */
    p[len++] = 'r';
    p[len++] = 'c';
    p[len++] = '"';
    p[len++] = ':';
    p[len++] = '"';

    u64 old_len = runtime_strlen(canon_old);
    if (len + old_len + 4 < AK_MAX_PARAMS) {
        runtime_memcpy(p + len, canon_old, old_len);
        len += old_len;
    }

    p[len++] = '"';
    p[len++] = '}';
    p[len] = '\0';

    req->params_len = len;

    return 0;
}

int ak_effect_from_mkdir(ak_effect_req_t *req, ak_ctx_t *ctx,
                         const char *path, int mode)
{
    if (!req || !path)
        return -EINVAL;

    ak_effect_req_init(req, ctx, AK_E_FS_MKDIR);

    int err = ak_canonicalize_path(path, req->target, AK_MAX_TARGET, "/");
    if (err != 0)
        return err;

    char *p = (char *)req->params;
    int len = 0;
    p[len++] = '{';
    p[len++] = '"';
    p[len++] = 'm';
    p[len++] = '"';
    p[len++] = ':';
    len += ak_format_u16(p + len, mode & 0xFFFF);
    p[len++] = '}';
    p[len] = '\0';

    req->params_len = len;

    return 0;
}

int ak_effect_from_connect(ak_effect_req_t *req, ak_ctx_t *ctx,
                           const struct sockaddr *addr, socklen_t addrlen)
{
    if (!req || !addr)
        return -EINVAL;

    ak_effect_req_init(req, ctx, AK_E_NET_CONNECT);

    int err = ak_canonicalize_sockaddr(addr, addrlen,
                                       req->target, AK_MAX_TARGET);
    if (err != 0)
        return err;

    req->params_len = 2;
    req->params[0] = '{';
    req->params[1] = '}';

    return 0;
}

int ak_effect_from_bind(ak_effect_req_t *req, ak_ctx_t *ctx,
                        const struct sockaddr *addr, socklen_t addrlen)
{
    if (!req || !addr)
        return -EINVAL;

    ak_effect_req_init(req, ctx, AK_E_NET_BIND);

    int err = ak_canonicalize_sockaddr(addr, addrlen,
                                       req->target, AK_MAX_TARGET);
    if (err != 0)
        return err;

    req->params_len = 2;
    req->params[0] = '{';
    req->params[1] = '}';

    return 0;
}

int ak_effect_from_listen(ak_effect_req_t *req, ak_ctx_t *ctx,
                          int fd, int backlog)
{
    if (!req)
        return -EINVAL;

    ak_effect_req_init(req, ctx, AK_E_NET_LISTEN);

    /* Target would be socket address - but we need fd resolution */
    /* For now, use placeholder */
    runtime_strncpy(req->target, "ip:0.0.0.0:0", AK_MAX_TARGET);

    char *p = (char *)req->params;
    int len = 0;
    p[len++] = '{';
    p[len++] = '"';
    p[len++] = 'b';  /* backlog */
    p[len++] = '"';
    p[len++] = ':';
    len += ak_format_u16(p + len, backlog & 0xFFFF);
    p[len++] = '}';
    p[len] = '\0';

    req->params_len = len;

    return 0;
}

int ak_effect_from_dns_resolve(ak_effect_req_t *req, ak_ctx_t *ctx,
                               const char *hostname)
{
    if (!req || !hostname)
        return -EINVAL;

    ak_effect_req_init(req, ctx, AK_E_NET_DNS_RESOLVE);

    /* Format: dns:<hostname> */
    int len = 0;
    req->target[len++] = 'd';
    req->target[len++] = 'n';
    req->target[len++] = 's';
    req->target[len++] = ':';

    u64 host_len = runtime_strlen(hostname);
    if (len + host_len >= AK_MAX_TARGET)
        return -ERANGE;

    runtime_memcpy(req->target + len, hostname, host_len);
    len += host_len;
    req->target[len] = '\0';

    req->params_len = 2;
    req->params[0] = '{';
    req->params[1] = '}';

    return 0;
}

int ak_effect_from_tool_call(ak_effect_req_t *req, ak_ctx_t *ctx,
                             const char *tool_name, const char *version,
                             const u8 *args, u32 args_len)
{
    if (!req || !tool_name)
        return -EINVAL;

    ak_effect_req_init(req, ctx, AK_E_TOOL_CALL);

    /* Format: tool:<name>:<version> */
    int len = 0;
    req->target[len++] = 't';
    req->target[len++] = 'o';
    req->target[len++] = 'o';
    req->target[len++] = 'l';
    req->target[len++] = ':';

    u64 name_len = runtime_strlen(tool_name);
    if (len + name_len + 2 >= AK_MAX_TARGET)
        return -ERANGE;

    runtime_memcpy(req->target + len, tool_name, name_len);
    len += name_len;

    req->target[len++] = ':';

    if (version) {
        u64 ver_len = runtime_strlen(version);
        if (len + ver_len >= AK_MAX_TARGET)
            return -ERANGE;
        runtime_memcpy(req->target + len, version, ver_len);
        len += ver_len;
    } else {
        req->target[len++] = '*';
    }
    req->target[len] = '\0';

    /* Copy args if provided */
    if (args && args_len > 0) {
        if (args_len > AK_MAX_PARAMS)
            args_len = AK_MAX_PARAMS;
        runtime_memcpy(req->params, args, args_len);
        req->params_len = args_len;
    } else {
        req->params_len = 2;
        req->params[0] = '{';
        req->params[1] = '}';
    }

    return 0;
}

int ak_effect_from_wasm_invoke(ak_effect_req_t *req, ak_ctx_t *ctx,
                               const char *module, const char *function,
                               const u8 *args, u32 args_len)
{
    if (!req || !module || !function)
        return -EINVAL;

    ak_effect_req_init(req, ctx, AK_E_WASM_INVOKE);

    /* Format: wasm:<module>:<function> */
    int len = 0;
    req->target[len++] = 'w';
    req->target[len++] = 'a';
    req->target[len++] = 's';
    req->target[len++] = 'm';
    req->target[len++] = ':';

    u64 mod_len = runtime_strlen(module);
    if (len + mod_len + 2 >= AK_MAX_TARGET)
        return -ERANGE;

    runtime_memcpy(req->target + len, module, mod_len);
    len += mod_len;
    req->target[len++] = ':';

    u64 func_len = runtime_strlen(function);
    if (len + func_len >= AK_MAX_TARGET)
        return -ERANGE;

    runtime_memcpy(req->target + len, function, func_len);
    len += func_len;
    req->target[len] = '\0';

    if (args && args_len > 0) {
        if (args_len > AK_MAX_PARAMS)
            args_len = AK_MAX_PARAMS;
        runtime_memcpy(req->params, args, args_len);
        req->params_len = args_len;
    } else {
        req->params_len = 2;
        req->params[0] = '{';
        req->params[1] = '}';
    }

    return 0;
}

int ak_effect_from_infer(ak_effect_req_t *req, ak_ctx_t *ctx,
                         const char *model, const char *version,
                         u64 max_tokens)
{
    if (!req || !model)
        return -EINVAL;

    ak_effect_req_init(req, ctx, AK_E_INFER);

    /* Format: model:<name>:<version> */
    int len = 0;
    req->target[len++] = 'm';
    req->target[len++] = 'o';
    req->target[len++] = 'd';
    req->target[len++] = 'e';
    req->target[len++] = 'l';
    req->target[len++] = ':';

    u64 name_len = runtime_strlen(model);
    if (len + name_len + 2 >= AK_MAX_TARGET)
        return -ERANGE;

    runtime_memcpy(req->target + len, model, name_len);
    len += name_len;
    req->target[len++] = ':';

    if (version) {
        u64 ver_len = runtime_strlen(version);
        if (len + ver_len >= AK_MAX_TARGET)
            return -ERANGE;
        runtime_memcpy(req->target + len, version, ver_len);
        len += ver_len;
    } else {
        /* Default version */
        runtime_memcpy(req->target + len, "latest", 6);
        len += 6;
    }
    req->target[len] = '\0';

    /* Set token budget */
    req->budget.tokens = max_tokens;

    req->params_len = 2;
    req->params[0] = '{';
    req->params[1] = '}';

    return 0;
}

/* ============================================================
 * PROCESS EFFECT BUILDERS
 * ============================================================ */

int ak_effect_from_spawn(ak_effect_req_t *req, ak_ctx_t *ctx,
                         const char *program, const char **argv,
                         u32 flags)
{
    if (!req || !program)
        return -EINVAL;

    ak_effect_req_init(req, ctx, AK_E_PROC_SPAWN);

    /* Target format: "spawn:<program>" */
    int len = 0;
    req->target[len++] = 's';
    req->target[len++] = 'p';
    req->target[len++] = 'a';
    req->target[len++] = 'w';
    req->target[len++] = 'n';
    req->target[len++] = ':';

    u64 prog_len = runtime_strlen(program);
    if (len + prog_len >= AK_MAX_TARGET)
        return -ERANGE;

    runtime_memcpy(req->target + len, program, prog_len);
    len += prog_len;
    req->target[len] = '\0';

    /* Encode flags and argv count in params */
    char *p = (char *)req->params;
    int plen = 0;
    p[plen++] = '{';
    p[plen++] = '"';
    p[plen++] = 'f';  /* flags */
    p[plen++] = '"';
    p[plen++] = ':';
    plen += ak_format_u16(p + plen, flags & 0xFFFF);

    /* Count argv if provided */
    if (argv) {
        u32 argc = 0;
        while (argv[argc] && argc < 64)
            argc++;

        p[plen++] = ',';
        p[plen++] = '"';
        p[plen++] = 'a';  /* argc */
        p[plen++] = 'c';
        p[plen++] = '"';
        p[plen++] = ':';
        plen += ak_format_u16(p + plen, argc & 0xFFFF);
    }

    p[plen++] = '}';
    p[plen] = '\0';

    req->params_len = plen;

    return 0;
}

int ak_effect_from_signal(ak_effect_req_t *req, ak_ctx_t *ctx,
                          pid_t target_pid, int signum)
{
    if (!req)
        return -EINVAL;

    ak_effect_req_init(req, ctx, AK_E_PROC_SIGNAL);

    /* Target format: "signal:<pid>:<signum>" */
    int len = 0;
    req->target[len++] = 's';
    req->target[len++] = 'i';
    req->target[len++] = 'g';
    req->target[len++] = 'n';
    req->target[len++] = 'a';
    req->target[len++] = 'l';
    req->target[len++] = ':';

    /* Format PID (treat as u32 for simplicity) */
    u32 pid_val = (target_pid >= 0) ? (u32)target_pid : 0;
    len += ak_format_u16(req->target + len, (u16)(pid_val >> 16));
    len += ak_format_u16(req->target + len, (u16)(pid_val & 0xFFFF));
    req->target[len++] = ':';
    len += ak_format_u16(req->target + len, (u16)(signum & 0xFFFF));
    req->target[len] = '\0';

    /* Encode in params as well for clarity */
    char *p = (char *)req->params;
    int plen = 0;
    p[plen++] = '{';
    p[plen++] = '"';
    p[plen++] = 'p';  /* pid */
    p[plen++] = '"';
    p[plen++] = ':';
    plen += ak_format_u16(p + plen, (u16)(pid_val >> 16));
    plen += ak_format_u16(p + plen, (u16)(pid_val & 0xFFFF));
    p[plen++] = ',';
    p[plen++] = '"';
    p[plen++] = 's';  /* signal */
    p[plen++] = '"';
    p[plen++] = ':';
    plen += ak_format_u16(p + plen, (u16)(signum & 0xFFFF));
    p[plen++] = '}';
    p[plen] = '\0';

    req->params_len = plen;

    return 0;
}

int ak_effect_from_wait(ak_effect_req_t *req, ak_ctx_t *ctx,
                        pid_t target_pid, int options)
{
    if (!req)
        return -EINVAL;

    ak_effect_req_init(req, ctx, AK_E_PROC_WAIT);

    /* Target format: "wait:<pid>" */
    int len = 0;
    req->target[len++] = 'w';
    req->target[len++] = 'a';
    req->target[len++] = 'i';
    req->target[len++] = 't';
    req->target[len++] = ':';

    /* Format PID (-1 means any child) */
    if (target_pid == -1) {
        req->target[len++] = '*';
    } else {
        u32 pid_val = (target_pid >= 0) ? (u32)target_pid : 0;
        len += ak_format_u16(req->target + len, (u16)(pid_val >> 16));
        len += ak_format_u16(req->target + len, (u16)(pid_val & 0xFFFF));
    }
    req->target[len] = '\0';

    /* Encode options in params */
    char *p = (char *)req->params;
    int plen = 0;
    p[plen++] = '{';
    p[plen++] = '"';
    p[plen++] = 'o';  /* options */
    p[plen++] = '"';
    p[plen++] = ':';
    plen += ak_format_u16(p + plen, (u16)(options & 0xFFFF));
    p[plen++] = '}';
    p[plen] = '\0';

    req->params_len = plen;

    return 0;
}

/* ============================================================
 * ERRNO MAPPING
 * ============================================================ */

static int ak_map_deny_to_errno(ak_effect_op_t op, ak_deny_reason_t reason)
{
    /* Base errno depends on effect category */
    u32 category = (op >> 8) & 0xFF;

    switch (category) {
    case 0x01:  /* Filesystem */
        switch (reason) {
        case AK_DENY_NO_CAP:
        case AK_DENY_PATTERN_MISMATCH:
            return EACCES;
        case AK_DENY_NO_POLICY:
        case AK_DENY_REVOKED:
            return EPERM;
        case AK_DENY_BUDGET_EXCEEDED:
            return ENOSPC;
        default:
            return EACCES;
        }

    case 0x02:  /* Network */
        switch (reason) {
        case AK_DENY_NO_CAP:
        case AK_DENY_PATTERN_MISMATCH:
            return ECONNREFUSED;
        case AK_DENY_RATE_LIMITED:
            return EAGAIN;
        default:
            return ENETUNREACH;
        }

    case 0x03:  /* Process */
        return EPERM;

    case 0x04:  /* Agentic (tools, wasm, infer) */
        switch (reason) {
        case AK_DENY_BUDGET_EXCEEDED:
            return ENOSPC;
        case AK_DENY_RATE_LIMITED:
            return EAGAIN;
        default:
            return EPERM;
        }

    default:
        return EPERM;
    }
}

/* ============================================================
 * RATE-LIMITED DENY LOGGING
 * ============================================================ */

static boolean ak_should_log_deny(ak_effect_op_t op)
{
    u64 now_ns = ak_now() * 1000;  /* Approximate ns */
    u32 category = (op >> 8) & 0x0F;

    if (category >= 16)
        category = 15;

    /* Reset window if expired */
    if (now_ns - deny_rate_limiter.window_start_ns > AK_DENY_RATE_LIMIT_WINDOW_NS) {
        deny_rate_limiter.window_start_ns = now_ns;
        ak_memzero(deny_rate_limiter.count_per_op, sizeof(deny_rate_limiter.count_per_op));
    }

    /* Check rate limit */
    if (deny_rate_limiter.count_per_op[category] >= AK_DENY_RATE_LIMIT_MAX) {
        return false;
    }

    deny_rate_limiter.count_per_op[category]++;
    return true;
}

static const char *ak_effect_op_name(ak_effect_op_t op)
{
    switch (op) {
    case AK_E_FS_OPEN:        return "FS_OPEN";
    case AK_E_FS_UNLINK:      return "FS_UNLINK";
    case AK_E_FS_RENAME:      return "FS_RENAME";
    case AK_E_FS_MKDIR:       return "FS_MKDIR";
    case AK_E_FS_RMDIR:       return "FS_RMDIR";
    case AK_E_FS_STAT:        return "FS_STAT";
    case AK_E_NET_CONNECT:    return "NET_CONNECT";
    case AK_E_NET_DNS_RESOLVE: return "NET_DNS";
    case AK_E_NET_BIND:       return "NET_BIND";
    case AK_E_NET_LISTEN:     return "NET_LISTEN";
    case AK_E_NET_ACCEPT:     return "NET_ACCEPT";
    case AK_E_PROC_SPAWN:     return "PROC_SPAWN";
    case AK_E_PROC_SIGNAL:    return "PROC_SIGNAL";
    case AK_E_PROC_WAIT:      return "PROC_WAIT";
    case AK_E_TOOL_CALL:      return "TOOL_CALL";
    case AK_E_WASM_INVOKE:    return "WASM_INVOKE";
    case AK_E_INFER:          return "INFER";
    default:                   return "UNKNOWN";
    }
}

static void ak_log_deny(const ak_effect_req_t *req, const ak_decision_t *decision)
{
    if (!ak_should_log_deny(req->op))
        return;

    /* Format: AK DENY <op> <target> missing <cap>. Fix: <snippet> (trace=<id>) */
    rprintf("AK DENY %s %s missing %s. Fix: %s (trace=%lx)\n",
            ak_effect_op_name(req->op),
            req->target,
            decision->missing_cap,
            decision->suggested_snippet,
            decision->trace_id);
}

/* ============================================================
 * THE SINGLE AUTHORITY GATE
 * ============================================================ */

int ak_authorize_and_execute(
    ak_ctx_t *ctx,
    const ak_effect_req_t *req,
    ak_decision_t *decision_out,
    long *retval_out)
{
    u64 start_ns = ak_now();

    /*
     * PRECONDITIONS: Validate all required inputs at API boundary.
     * This is THE critical security gate - fail-fast on invalid input.
     */
    AK_CHECK_NOT_NULL(ctx, -EINVAL);
    AK_CHECK_NOT_NULL(req, -EINVAL);
    AK_CHECK_NOT_NULL(decision_out, -EINVAL);

    /* Validate effect op is in valid range */
    AK_CHECK_IN_RANGE(req->op, 0x0100, 0x0500, -EINVAL);

    /* Validate params_len is within bounds */
    AK_CHECK_IN_RANGE(req->params_len, 0, AK_MAX_PARAMS, -EINVAL);

    /* Initialize decision */
    ak_memzero(decision_out, sizeof(*decision_out));
    decision_out->trace_id = req->trace_id;

    /*
     * CONCURRENCY FIX (BUG-014): Use atomic operations for statistics counters.
     * Multiple threads may call ak_authorize_and_execute() concurrently.
     */
    __sync_fetch_and_add(&global_stats.total_requests, 1);
    u32 category = (req->op >> 8) & 0x0F;
    if (category < 16)
        __sync_fetch_and_add(&global_stats.by_op[category], 1);

    /* ========================================
     * MODE CHECK
     * ======================================== */

    if (ctx->mode == AK_MODE_OFF) {
        /* Bypass mode - allow everything */
        decision_out->allow = true;
        decision_out->reason_code = AK_DENY_NONE;
        __sync_fetch_and_add(&global_stats.allowed, 1);  /* BUG-014 fix */
        if (retval_out)
            *retval_out = 0;
        return 0;
    }

    /* ========================================
     * RECORD MODE CHECK
     * ========================================
     * In RECORD mode, we check if the effect would be denied by policy,
     * record it for batch suggestions, but allow the operation to proceed.
     * This enables discovering all effects a program needs.
     */
    if (ctx->mode == AK_MODE_RECORD) {
        /* First check if policy would deny this */
        boolean would_allow = false;

        if (ctx->policy) {
            would_allow = ak_policy_v2_check(ctx->policy, req, decision_out);
        }

        if (!would_allow) {
            /* Effect would be denied - record it for suggestion generation */
            if (ctx->record && ak_record_is_enabled(ctx->record)) {
                ak_record_effect(ctx->record, req);
            }

            /* Generate suggestion for logging purposes */
            if (decision_out->suggested_snippet[0] == '\0') {
                ak_generate_suggestion(req, decision_out->suggested_snippet, AK_MAX_SUGGEST);
            }

            /* Log the recorded denial (rate-limited) */
            if (ak_should_log_deny(req->op)) {
                rprintf("AK RECORD %s %s (would deny, recorded for suggestion)\n",
                        ak_effect_op_name(req->op), req->target);
            }
        }

        /* In record mode, always allow the operation to proceed */
        decision_out->allow = true;
        decision_out->reason_code = AK_DENY_NONE;
        decision_out->errno_equiv = 0;
        decision_out->decision_ns = ak_now() - start_ns;

        __sync_fetch_and_add(&global_stats.allowed, 1);
        ak_set_in_authorized_effect(true);

        if (retval_out)
            *retval_out = 0;

        return 0;
    }

    /* ========================================
     * BOOT CAPSULE CHECK
     * ======================================== */

    if (ak_ctx_boot_capsule_active(ctx)) {
        /* During boot, only allow limited operations */
        /* For now, allow FS reads for policy loading */
        if (req->op == AK_E_FS_OPEN) {
            /* Check if it's a read-only open */
            /* Simplified: allow during boot capsule */
            decision_out->allow = true;
            decision_out->reason_code = AK_DENY_NONE;
            __sync_fetch_and_add(&global_stats.allowed, 1);  /* BUG-014 fix */
            if (retval_out)
                *retval_out = 0;
            return 0;
        }

        /* Deny other effects during boot */
        decision_out->allow = false;
        decision_out->reason_code = AK_DENY_BOOT_CAPSULE;
        decision_out->errno_equiv = EPERM;
        runtime_strncpy(decision_out->missing_cap, "boot.complete", AK_MAX_CAPSTR);
        runtime_strncpy(decision_out->suggested_snippet,
                        "# Wait for boot capsule to drop", AK_MAX_SUGGEST);
        runtime_strncpy(decision_out->detail,
                        "Operation denied during boot capsule phase", AK_MAX_DETAIL);

        /* Update last_deny */
        ctx->last_deny.op = req->op;
        runtime_strncpy(ctx->last_deny.target, req->target, AK_MAX_TARGET);
        runtime_strncpy(ctx->last_deny.missing_cap, decision_out->missing_cap, AK_MAX_CAPSTR);
        runtime_strncpy(ctx->last_deny.suggested_snippet,
                        decision_out->suggested_snippet, AK_MAX_SUGGEST);
        ctx->last_deny.trace_id = req->trace_id;
        ctx->last_deny.errno_equiv = decision_out->errno_equiv;
        ctx->last_deny.timestamp_ns = ak_now();
        ctx->last_deny.reason = decision_out->reason_code;

        /* Log (rate-limited) */
        ak_log_deny(req, decision_out);

        __sync_fetch_and_add(&global_stats.denied, 1);  /* BUG-014 fix */
        if (AK_DENY_BOOT_CAPSULE < 16)
            __sync_fetch_and_add(&global_stats.deny_reasons[AK_DENY_BOOT_CAPSULE], 1);

        return -EPERM;
    }

    /* ========================================
     * POLICY CHECK
     * ======================================== */

    if (!ctx->policy) {
        /* No policy loaded - deny by default */
        decision_out->allow = false;
        decision_out->reason_code = AK_DENY_NO_POLICY;
        decision_out->errno_equiv = EPERM;
        runtime_strncpy(decision_out->missing_cap, "policy.loaded", AK_MAX_CAPSTR);
        runtime_strncpy(decision_out->suggested_snippet,
                        "# Load policy: ak_policy_v2_load()", AK_MAX_SUGGEST);
        runtime_strncpy(decision_out->detail,
                        "No policy loaded - deny by default", AK_MAX_DETAIL);

        /* Update last_deny */
        ctx->last_deny.op = req->op;
        runtime_strncpy(ctx->last_deny.target, req->target, AK_MAX_TARGET);
        runtime_strncpy(ctx->last_deny.missing_cap, decision_out->missing_cap, AK_MAX_CAPSTR);
        runtime_strncpy(ctx->last_deny.suggested_snippet,
                        decision_out->suggested_snippet, AK_MAX_SUGGEST);
        ctx->last_deny.trace_id = req->trace_id;
        ctx->last_deny.errno_equiv = decision_out->errno_equiv;
        ctx->last_deny.timestamp_ns = ak_now();
        ctx->last_deny.reason = decision_out->reason_code;

        ak_log_deny(req, decision_out);

        __sync_fetch_and_add(&global_stats.denied, 1);  /* BUG-014 fix */
        if (AK_DENY_NO_POLICY < 16)
            __sync_fetch_and_add(&global_stats.deny_reasons[AK_DENY_NO_POLICY], 1);

        return -EPERM;
    }

    /* Call policy check (Agent B's implementation) */
    boolean allowed = ak_policy_v2_check(ctx->policy, req, decision_out);

    decision_out->decision_ns = ak_now() - start_ns;

    if (allowed) {
        /* ========================================
         * ALLOWED
         * ======================================== */
        decision_out->allow = true;
        decision_out->reason_code = AK_DENY_NONE;
        decision_out->errno_equiv = 0;

        __sync_fetch_and_add(&global_stats.allowed, 1);  /* BUG-014 fix */

        /*
         * HARD MODE SUPPORT: Set the authorized effect flag.
         *
         * This flag indicates that subsequent syscalls (made by the caller
         * after this function returns) are part of an authorized AK API call.
         * The routing layer checks this flag in HARD mode to allow syscalls
         * that are executing on behalf of authorized effects.
         *
         * IMPORTANT: The caller is responsible for clearing this flag after
         * the effect execution completes. For the common case where the
         * routing function calls ak_authorize_and_execute() and then proceeds
         * to the real syscall, this flag allows that syscall to proceed.
         *
         * NOTE: This is a simplification. In a production implementation,
         * this would need more sophisticated tracking (e.g., checking that
         * the syscall matches the authorized effect type and target).
         */
        ak_set_in_authorized_effect(true);

        if (retval_out)
            *retval_out = 0;

        return 0;
    }

    /* ========================================
     * DENIED
     * ======================================== */

    decision_out->allow = false;

    /* Map to errno if not already set */
    if (decision_out->errno_equiv == 0) {
        decision_out->errno_equiv = ak_map_deny_to_errno(req->op,
                                                         decision_out->reason_code);
    }

    /* Generate suggestion if not provided */
    if (decision_out->suggested_snippet[0] == '\0') {
        ak_generate_suggestion(req, decision_out->suggested_snippet, AK_MAX_SUGGEST);
    }

    /* Update last_deny */
    ctx->last_deny.op = req->op;
    runtime_strncpy(ctx->last_deny.target, req->target, AK_MAX_TARGET);
    runtime_strncpy(ctx->last_deny.missing_cap, decision_out->missing_cap, AK_MAX_CAPSTR);
    runtime_strncpy(ctx->last_deny.suggested_snippet,
                    decision_out->suggested_snippet, AK_MAX_SUGGEST);
    ctx->last_deny.trace_id = req->trace_id;
    ctx->last_deny.errno_equiv = decision_out->errno_equiv;
    ctx->last_deny.timestamp_ns = ak_now();
    ctx->last_deny.reason = decision_out->reason_code;

    /* Rate-limited log */
    ak_log_deny(req, decision_out);

    __sync_fetch_and_add(&global_stats.denied, 1);  /* BUG-014 fix */
    if (decision_out->reason_code < 16)
        __sync_fetch_and_add(&global_stats.deny_reasons[decision_out->reason_code], 1);

    return -decision_out->errno_equiv;
}

/* ============================================================
 * LAST DENY ACCESS
 * ============================================================ */

const ak_last_deny_t *ak_get_last_deny(ak_ctx_t *ctx)
{
    if (!ctx)
        return NULL;
    return &ctx->last_deny;
}

void ak_clear_last_deny(ak_ctx_t *ctx)
{
    if (!ctx)
        return;
    ak_memzero(&ctx->last_deny, sizeof(ctx->last_deny));
}

/* ============================================================
 * SUGGESTION GENERATION
 * ============================================================ */

void ak_generate_suggestion(const ak_effect_req_t *req,
                            char *snippet, u32 max_len)
{
    if (!req || !snippet || max_len < 64)
        return;

    snippet[0] = '\0';

    u32 category = (req->op >> 8) & 0xFF;

    switch (category) {
    case 0x01:  /* Filesystem */
        switch (req->op) {
        case AK_E_FS_OPEN:
            runtime_strncpy(snippet,
                "[[fs.allow]]\npath = \"", max_len);
            {
                u64 pos = runtime_strlen(snippet);
                u64 target_len = runtime_strlen(req->target);
                /* FIX(BUG-006): Correct bounds check - need 14 bytes for suffix + 1 for null */
                if (pos + target_len + 15 < max_len) {
                    runtime_memcpy(snippet + pos, req->target, target_len);
                    pos += target_len;
                    runtime_memcpy(snippet + pos, "\"\nread = true", 14);
                    snippet[pos + 13] = '\0';
                }
            }
            break;

        case AK_E_FS_UNLINK:
        case AK_E_FS_RENAME:
        case AK_E_FS_MKDIR:
            runtime_strncpy(snippet,
                "[[fs.allow]]\npath = \"", max_len);
            {
                u64 pos = runtime_strlen(snippet);
                u64 target_len = runtime_strlen(req->target);
                /* FIX(BUG-006): Correct bounds check - need 15 bytes for suffix + 1 for null */
                if (pos + target_len + 16 < max_len) {
                    runtime_memcpy(snippet + pos, req->target, target_len);
                    pos += target_len;
                    runtime_memcpy(snippet + pos, "\"\nwrite = true", 15);
                    snippet[pos + 14] = '\0';
                }
            }
            break;

        default:
            runtime_strncpy(snippet, "# Add fs.allow rule", max_len);
        }
        break;

    case 0x02:  /* Network */
        switch (req->op) {
        case AK_E_NET_CONNECT:
            runtime_strncpy(snippet,
                "[[net.allow]]\npattern = \"", max_len);
            {
                u64 pos = runtime_strlen(snippet);
                u64 target_len = runtime_strlen(req->target);
                /* FIX(BUG-006): Correct bounds check - need 17 bytes for suffix + 1 for null */
                if (pos + target_len + 18 < max_len) {
                    runtime_memcpy(snippet + pos, req->target, target_len);
                    pos += target_len;
                    runtime_memcpy(snippet + pos, "\"\nconnect = true", 17);
                    snippet[pos + 16] = '\0';
                }
            }
            break;

        case AK_E_NET_DNS_RESOLVE:
            runtime_strncpy(snippet,
                "[[dns.allow]]\npattern = \"", max_len);
            {
                u64 pos = runtime_strlen(snippet);
                /* Skip "dns:" prefix */
                const char *host = req->target;
                if (runtime_strncmp(host, "dns:", 4) == 0)
                    host += 4;
                u64 host_len = runtime_strlen(host);
                if (pos + host_len + 2 < max_len) {
                    runtime_memcpy(snippet + pos, host, host_len);
                    pos += host_len;
                    snippet[pos++] = '"';
                    snippet[pos] = '\0';
                }
            }
            break;

        default:
            runtime_strncpy(snippet, "# Add net.allow rule", max_len);
        }
        break;

    case 0x04:  /* Agentic */
        switch (req->op) {
        case AK_E_TOOL_CALL:
            runtime_strncpy(snippet,
                "[[tools.allow]]\nname = \"", max_len);
            {
                u64 pos = runtime_strlen(snippet);
                /* Extract tool name from target: tool:<name>:<version> */
                const char *name = req->target;
                if (runtime_strncmp(name, "tool:", 5) == 0)
                    name += 5;
                /* Find end of name (before :version) */
                u64 name_len = 0;
                while (name[name_len] && name[name_len] != ':')
                    name_len++;
                if (pos + name_len + 2 < max_len) {
                    runtime_memcpy(snippet + pos, name, name_len);
                    pos += name_len;
                    snippet[pos++] = '"';
                    snippet[pos] = '\0';
                }
            }
            break;

        case AK_E_INFER:
            runtime_strncpy(snippet,
                "[[inference.allow]]\nmodel = \"", max_len);
            {
                u64 pos = runtime_strlen(snippet);
                const char *model = req->target;
                if (runtime_strncmp(model, "model:", 6) == 0)
                    model += 6;
                u64 model_len = 0;
                while (model[model_len] && model[model_len] != ':')
                    model_len++;
                if (pos + model_len + 2 < max_len) {
                    runtime_memcpy(snippet + pos, model, model_len);
                    pos += model_len;
                    snippet[pos++] = '"';
                    snippet[pos] = '\0';
                }
            }
            break;

        default:
            runtime_strncpy(snippet, "# Add agentic allow rule", max_len);
        }
        break;

    default:
        runtime_strncpy(snippet, "# Add allow rule for this operation", max_len);
    }
}

/* ============================================================
 * STATISTICS
 * ============================================================ */

void ak_effects_get_stats(ak_effects_stats_t *stats)
{
    if (!stats)
        return;
    runtime_memcpy(stats, &global_stats, sizeof(global_stats));
}

/* ============================================================
 * WEAK STUB FOR POLICY V2 CHECK
 * ============================================================
 * This is a stub that Agent B will override with real implementation.
 * Default behavior: deny everything.
 */

__attribute__((weak))
boolean ak_policy_v2_check(struct ak_policy_v2 *p,
                           const ak_effect_req_t *req,
                           ak_decision_t *decision_out)
{
    (void)p;

    if (!decision_out)
        return false;

    /* Default deny with helpful info */
    decision_out->allow = false;
    decision_out->reason_code = AK_DENY_NO_CAP;
    decision_out->errno_equiv = EPERM;
    runtime_strncpy(decision_out->missing_cap, "policy.stub", AK_MAX_CAPSTR);
    runtime_strncpy(decision_out->detail,
                    "Using stub policy checker - always denies", AK_MAX_DETAIL);

    /* Generate suggestion based on effect type */
    ak_generate_suggestion(req, decision_out->suggested_snippet, AK_MAX_SUGGEST);

    return false;
}
