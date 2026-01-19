/*
 * Authority Kernel - POSIX Syscall Routing Implementation
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * AGENT D OWNED: POSIX syscall routing layer implementation.
 *
 * This module intercepts POSIX syscalls and routes them through the
 * Authority Kernel effects system for policy enforcement.
 *
 * Key implementation patterns:
 *   1. Get current AK context
 *   2. Check routing mode
 *   3. Build effect request with canonicalized target
 *   4. Call ak_authorize_and_execute()
 *   5. If allowed, return 0 (caller proceeds to real syscall)
 *   6. If denied, return negative errno
 */

#include "ak_posix_route.h"
#include "ak_effects.h"
#include "ak_context.h"
#include "ak_compat.h"
#include "ak_fd_table.h"

/* ============================================================
 * MODULE STATE
 * ============================================================ */

/* Heap for routing allocations */
static heap route_heap = NULL;

/* Statistics */
static ak_posix_route_stats_t route_stats;

/* AT_FDCWD constant (Linux value) */
#ifndef AT_FDCWD
#define AT_FDCWD    -100
#endif

/* AT_REMOVEDIR constant */
#ifndef AT_REMOVEDIR
#define AT_REMOVEDIR    0x200
#endif

/* ============================================================
 * INITIALIZATION / SHUTDOWN
 * ============================================================ */

int ak_posix_route_init(heap h)
{
    if (!h)
        return -EINVAL;

    route_heap = h;
    ak_memzero(&route_stats, sizeof(route_stats));

    /* Initialize the FD table subsystem */
    int err = ak_fd_table_init(h);
    if (err < 0) {
        ak_error("ak_posix_route: failed to init FD table: %d", err);
        return err;
    }

    ak_debug("ak_posix_route: initialized");
    return 0;
}

void ak_posix_route_shutdown(void)
{
    /* Shutdown the FD table subsystem */
    ak_fd_table_shutdown();

    route_heap = NULL;
    ak_debug("ak_posix_route: shutdown");
}

/* ============================================================
 * MODE CHECKING
 * ============================================================ */

boolean ak_routing_active(void)
{
    ak_ctx_t *ctx = ak_ctx_current();
    if (!ctx)
        return false;

    ak_mode_t mode = ak_ctx_get_mode(ctx);
    return (mode != AK_MODE_OFF);
}

boolean ak_routing_hard(void)
{
    ak_ctx_t *ctx = ak_ctx_current();
    if (!ctx)
        return false;

    return (ak_ctx_get_mode(ctx) == AK_MODE_HARD);
}

/*
 * HARD MODE ENFORCEMENT: Check if raw syscall should be blocked.
 *
 * In HARD mode, raw effectful syscalls are denied unless they're
 * being executed as part of an authorized AK API call.
 *
 * Returns:
 *   0        - Call is allowed (not HARD mode, or authorized effect)
 *   -EPERM   - Call is blocked (HARD mode, raw syscall)
 */
static sysreturn ak_check_hard_mode_block(void)
{
    ak_ctx_t *ctx = ak_ctx_current();
    if (!ctx)
        return 0;  /* No context = no enforcement */

    /* Only enforce in HARD mode */
    if (ak_ctx_get_mode(ctx) != AK_MODE_HARD)
        return 0;

    /* If we're inside an authorized effect, allow */
    if (ak_is_in_authorized_effect())
        return 0;

    /*
     * HARD MODE BLOCK: Raw syscall not through AK API.
     *
     * In HARD mode, all effectful operations must go through the
     * AK effects API. Direct syscalls are blocked with EPERM.
     */
    route_stats.total_denied++;
    route_stats.hard_mode_blocks++;

    return -EPERM;
}

boolean ak_route_check(ak_effect_op_t op, const char *target)
{
    ak_ctx_t *ctx = ak_ctx_current();
    if (!ctx || !target)
        return false;

    /* Build minimal effect request */
    ak_effect_req_t req;
    ak_memzero(&req, sizeof(req));
    req.op = op;
    req.trace_id = ak_trace_id_generate(ctx);
    runtime_strncpy(req.target, target, AK_MAX_TARGET);
    req.params_len = 2;
    req.params[0] = '{';
    req.params[1] = '}';

    /* Check without executing */
    ak_decision_t decision;
    long retval;
    int result = ak_authorize_and_execute(ctx, &req, &decision, &retval);

    return (result == 0 && decision.allow);
}

/* ============================================================
 * PATH RESOLUTION HELPERS
 * ============================================================ */

int ak_get_cwd(char *out, u32 out_len)
{
    if (!out || out_len == 0)
        return -EINVAL;

    /* Use the FD table's CWD tracking */
    return ak_fd_table_get_cwd(out, out_len);
}

int ak_resolve_path_at(int dirfd, const char *path, char *out, u32 out_len)
{
    if (!path || !out || out_len == 0)
        return -EINVAL;

    /*
     * Use the FD table for path resolution.
     * ak_fd_table_resolve_at handles all cases:
     *   - Absolute paths (returns path directly)
     *   - AT_FDCWD (uses current working directory)
     *   - Registered dirfd (uses directory path from table)
     *   - Unknown dirfd (returns -EBADF)
     */
    return ak_fd_table_resolve_at(dirfd, path, out, out_len);
}

/* ============================================================
 * SOCKET STATE HELPERS
 * ============================================================ */

/*
 * Get the bound address of a socket.
 *
 * This function attempts to retrieve the local address bound to a socket.
 * It is used by listen() routing to determine what address the socket is
 * listening on for policy authorization.
 *
 * Current Implementation:
 *   Returns -ENOENT to indicate the bound address cannot be determined.
 *   Callers should use the wildcard pattern "ip:*:*" for unbound/unknown sockets.
 *
 * Integration Note:
 *   When integrated with Nanos, this should call getsockname() on the
 *   socket to retrieve the actual bound address. The fd-to-socket
 *   resolution would be done via:
 *     struct sock *sock = resolve_socket(current->p, fd);
 *     sock->getsockname(sock, addr, addrlen);
 *
 * Parameters:
 *   fd      - Socket file descriptor
 *   addr    - Output buffer for socket address
 *   addrlen - Input: buffer size, Output: actual address size
 *
 * Returns:
 *   0 on success (address retrieved)
 *   -EINVAL if addr or addrlen is NULL, or buffer too small
 *   -ENOENT if bound address cannot be determined (current stub behavior)
 *   -EBADF if fd is invalid (when full integration available)
 *   -EOPNOTSUPP if socket doesn't support getsockname (when full integration)
 */
int ak_get_socket_bound_addr(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    if (!addr || !addrlen || *addrlen < sizeof(struct sockaddr))
        return -EINVAL;

    /*
     * DESIGN DECISION: Return -ENOENT to signal unknown binding.
     *
     * Socket fd resolution requires kernel socket table access which is
     * architecture-specific. Rather than couple this module to kernel
     * internals, we return -ENOENT and let callers use the wildcard
     * pattern "ip:*:*" for policy matching on unbound/unknown sockets.
     *
     * This maintains module isolation: ak_posix_route handles POSIX
     * syscall routing without kernel socket table dependencies. The
     * kernel integration point (if needed) would be in the syscall
     * layer that calls this function.
     */
    (void)fd;
    (void)addr;
    (void)addrlen;

    return -ENOENT;
}

/* ============================================================
 * COMMON ROUTING PATTERN
 * ============================================================ */

/*
 * Common authorization check pattern.
 *
 * Returns:
 *   0        - Authorized, caller should proceed
 *   negative - Denied or error, caller should return this value
 */
static sysreturn ak_do_authorize(ak_ctx_t *ctx, ak_effect_req_t *req)
{
    ak_decision_t decision;
    long retval = 0;

    int result = ak_authorize_and_execute(ctx, req, &decision, &retval);

    if (result == 0 && decision.allow) {
        route_stats.total_allowed++;
        return 0;  /* Authorized */
    }

    /* Denied - return the appropriate errno */
    route_stats.total_denied++;

    /* Determine denial category for stats */
    u32 category = (req->op >> 8) & 0xFF;
    if (category == 0x01) {
        route_stats.fs_denials++;
    } else if (category == 0x02) {
        route_stats.net_denials++;
    }

    /* Return the errno from decision, or the result */
    if (decision.errno_equiv != 0) {
        return -decision.errno_equiv;
    }
    return result;
}

/* ============================================================
 * FILESYSTEM ROUTING HOOKS
 * ============================================================ */

sysreturn ak_route_open(const char *path, int flags, int mode)
{
    if (!path)
        return -EFAULT;

    /* HARD MODE CHECK: Block raw syscalls not through AK API */
    sysreturn hard_check = ak_check_hard_mode_block();
    if (hard_check < 0)
        return hard_check;

    route_stats.total_routed++;
    route_stats.open_calls++;

    ak_ctx_t *ctx = ak_ctx_current();

    /* MODE_OFF: bypass routing */
    if (!ctx || ak_ctx_get_mode(ctx) == AK_MODE_OFF) {
        route_stats.total_bypassed++;
        return 0;  /* Proceed to real syscall */
    }

    /* Build effect request */
    ak_effect_req_t req;
    int err = ak_effect_from_open(&req, ctx, path, flags, mode);
    if (err < 0)
        return err;

    return ak_do_authorize(ctx, &req);
}

sysreturn ak_route_openat(int dirfd, const char *path, int flags, int mode)
{
    /* HARD MODE CHECK: Block raw syscalls not through AK API */
    sysreturn hard_check = ak_check_hard_mode_block();
    if (hard_check < 0)
        return hard_check;

    route_stats.total_routed++;
    route_stats.openat_calls++;

    ak_ctx_t *ctx = ak_ctx_current();

    /* MODE_OFF: bypass routing */
    if (!ctx || ak_ctx_get_mode(ctx) == AK_MODE_OFF) {
        route_stats.total_bypassed++;
        return 0;  /* Proceed to real syscall */
    }

    /* Build effect request */
    ak_effect_req_t req;
    int err = ak_effect_from_openat(&req, ctx, dirfd, path, flags, mode);
    if (err < 0)
        return err;

    return ak_do_authorize(ctx, &req);
}

sysreturn ak_route_unlink(const char *path)
{
    if (!path)
        return -EFAULT;

    /* HARD MODE CHECK: Block raw syscalls not through AK API */
    sysreturn hard_check = ak_check_hard_mode_block();
    if (hard_check < 0)
        return hard_check;

    route_stats.total_routed++;
    route_stats.unlink_calls++;

    ak_ctx_t *ctx = ak_ctx_current();

    /* MODE_OFF: bypass routing */
    if (!ctx || ak_ctx_get_mode(ctx) == AK_MODE_OFF) {
        route_stats.total_bypassed++;
        return 0;
    }

    /* Build effect request */
    ak_effect_req_t req;
    int err = ak_effect_from_unlink(&req, ctx, path);
    if (err < 0)
        return err;

    return ak_do_authorize(ctx, &req);
}

sysreturn ak_route_unlinkat(int dirfd, const char *path, int flags)
{
    /* HARD MODE CHECK: Block raw syscalls not through AK API */
    sysreturn hard_check = ak_check_hard_mode_block();
    if (hard_check < 0)
        return hard_check;

    route_stats.total_routed++;
    route_stats.unlink_calls++;

    ak_ctx_t *ctx = ak_ctx_current();

    /* MODE_OFF: bypass routing */
    if (!ctx || ak_ctx_get_mode(ctx) == AK_MODE_OFF) {
        route_stats.total_bypassed++;
        return 0;
    }

    /* Resolve path relative to dirfd */
    char resolved[AK_MAX_TARGET];
    int err = ak_resolve_path_at(dirfd, path, resolved, sizeof(resolved));
    if (err < 0)
        return err;

    /* Use RMDIR effect if AT_REMOVEDIR flag set */
    ak_effect_req_t req;
    ak_memzero(&req, sizeof(req));

    if (flags & AT_REMOVEDIR) {
        req.op = AK_E_FS_RMDIR;
    } else {
        req.op = AK_E_FS_UNLINK;
    }

    req.trace_id = ak_trace_id_generate(ctx);
    runtime_strncpy(req.target, resolved, AK_MAX_TARGET);
    req.params_len = 2;
    req.params[0] = '{';
    req.params[1] = '}';

    return ak_do_authorize(ctx, &req);
}

sysreturn ak_route_mkdir(const char *path, int mode)
{
    /* HARD MODE CHECK: Block raw syscalls not through AK API */
    sysreturn hard_check = ak_check_hard_mode_block();
    if (hard_check < 0)
        return hard_check;

    route_stats.total_routed++;
    route_stats.mkdir_calls++;

    ak_ctx_t *ctx = ak_ctx_current();

    /* MODE_OFF: bypass routing */
    if (!ctx || ak_ctx_get_mode(ctx) == AK_MODE_OFF) {
        route_stats.total_bypassed++;
        return 0;
    }

    /* Build effect request */
    ak_effect_req_t req;
    int err = ak_effect_from_mkdir(&req, ctx, path, mode);
    if (err < 0)
        return err;

    return ak_do_authorize(ctx, &req);
}

sysreturn ak_route_mkdirat(int dirfd, const char *path, int mode)
{
    /* HARD MODE CHECK: Block raw syscalls not through AK API */
    sysreturn hard_check = ak_check_hard_mode_block();
    if (hard_check < 0)
        return hard_check;

    route_stats.total_routed++;
    route_stats.mkdir_calls++;

    ak_ctx_t *ctx = ak_ctx_current();

    /* MODE_OFF: bypass routing */
    if (!ctx || ak_ctx_get_mode(ctx) == AK_MODE_OFF) {
        route_stats.total_bypassed++;
        return 0;
    }

    /* Resolve path relative to dirfd */
    char resolved[AK_MAX_TARGET];
    int err = ak_resolve_path_at(dirfd, path, resolved, sizeof(resolved));
    if (err < 0)
        return err;

    /* Build effect request with resolved path */
    ak_effect_req_t req;
    err = ak_effect_from_mkdir(&req, ctx, resolved, mode);
    if (err < 0)
        return err;

    return ak_do_authorize(ctx, &req);
}

sysreturn ak_route_rename(const char *oldpath, const char *newpath)
{
    if (!oldpath || !newpath)
        return -EFAULT;

    /* HARD MODE CHECK: Block raw syscalls not through AK API */
    sysreturn hard_check = ak_check_hard_mode_block();
    if (hard_check < 0)
        return hard_check;

    route_stats.total_routed++;
    route_stats.rename_calls++;

    ak_ctx_t *ctx = ak_ctx_current();

    /* MODE_OFF: bypass routing */
    if (!ctx || ak_ctx_get_mode(ctx) == AK_MODE_OFF) {
        route_stats.total_bypassed++;
        return 0;
    }

    /* Build effect request */
    ak_effect_req_t req;
    int err = ak_effect_from_rename(&req, ctx, oldpath, newpath);
    if (err < 0)
        return err;

    return ak_do_authorize(ctx, &req);
}

sysreturn ak_route_renameat(int olddirfd, const char *oldpath,
                            int newdirfd, const char *newpath)
{
    /* HARD MODE CHECK: Block raw syscalls not through AK API */
    sysreturn hard_check = ak_check_hard_mode_block();
    if (hard_check < 0)
        return hard_check;

    route_stats.total_routed++;
    route_stats.rename_calls++;

    ak_ctx_t *ctx = ak_ctx_current();

    /* MODE_OFF: bypass routing */
    if (!ctx || ak_ctx_get_mode(ctx) == AK_MODE_OFF) {
        route_stats.total_bypassed++;
        return 0;
    }

    /* Resolve both paths */
    char resolved_old[AK_MAX_TARGET];
    char resolved_new[AK_MAX_TARGET];

    int err = ak_resolve_path_at(olddirfd, oldpath,
                                  resolved_old, sizeof(resolved_old));
    if (err < 0)
        return err;

    err = ak_resolve_path_at(newdirfd, newpath,
                              resolved_new, sizeof(resolved_new));
    if (err < 0)
        return err;

    /* Build effect request with resolved paths */
    ak_effect_req_t req;
    err = ak_effect_from_rename(&req, ctx, resolved_old, resolved_new);
    if (err < 0)
        return err;

    return ak_do_authorize(ctx, &req);
}

/* ============================================================
 * NETWORK ROUTING HOOKS
 * ============================================================ */

sysreturn ak_route_connect(int fd, const struct sockaddr *addr,
                           socklen_t addrlen)
{
    if (!addr)
        return -EFAULT;

    /* HARD MODE CHECK: Block raw syscalls not through AK API */
    sysreturn hard_check = ak_check_hard_mode_block();
    if (hard_check < 0)
        return hard_check;

    route_stats.total_routed++;
    route_stats.connect_calls++;

    ak_ctx_t *ctx = ak_ctx_current();

    /* MODE_OFF: bypass routing */
    if (!ctx || ak_ctx_get_mode(ctx) == AK_MODE_OFF) {
        route_stats.total_bypassed++;
        return 0;
    }

    /* Build effect request */
    ak_effect_req_t req;
    int err = ak_effect_from_connect(&req, ctx, addr, addrlen);
    if (err < 0)
        return err;

    return ak_do_authorize(ctx, &req);
}

sysreturn ak_route_bind(int fd, const struct sockaddr *addr,
                        socklen_t addrlen)
{
    if (!addr)
        return -EFAULT;

    /* HARD MODE CHECK: Block raw syscalls not through AK API */
    sysreturn hard_check = ak_check_hard_mode_block();
    if (hard_check < 0)
        return hard_check;

    route_stats.total_routed++;
    route_stats.bind_calls++;

    ak_ctx_t *ctx = ak_ctx_current();

    /* MODE_OFF: bypass routing */
    if (!ctx || ak_ctx_get_mode(ctx) == AK_MODE_OFF) {
        route_stats.total_bypassed++;
        return 0;
    }

    /* Build effect request */
    ak_effect_req_t req;
    int err = ak_effect_from_bind(&req, ctx, addr, addrlen);
    if (err < 0)
        return err;

    return ak_do_authorize(ctx, &req);
}

sysreturn ak_route_listen(int fd, int backlog)
{
    /* HARD MODE CHECK: Block raw syscalls not through AK API */
    sysreturn hard_check = ak_check_hard_mode_block();
    if (hard_check < 0)
        return hard_check;

    route_stats.total_routed++;
    route_stats.listen_calls++;

    ak_ctx_t *ctx = ak_ctx_current();

    /* MODE_OFF: bypass routing */
    if (!ctx || ak_ctx_get_mode(ctx) == AK_MODE_OFF) {
        route_stats.total_bypassed++;
        return 0;
    }

    /*
     * Retrieve the socket's bound address for policy authorization.
     *
     * The bound address determines what the socket will listen on.
     * If ak_get_socket_bound_addr() fails (-ENOENT), we fall back to
     * ak_effect_from_listen() which uses "ip:*:*" as a wildcard target
     * for unbound/unknown sockets.
     *
     * Policies can match wildcard addresses using patterns like:
     *   - "ip:*:8080"     - Any address on port 8080
     *   - "ip:*:*"        - Any network listen operation
     */
    u8 addr_buf[64];
    socklen_t addrlen = sizeof(addr_buf);
    struct sockaddr *addr = (struct sockaddr *)addr_buf;

    int err = ak_get_socket_bound_addr(fd, addr, &addrlen);
    if (err < 0) {
        /*
         * Could not retrieve bound address (invalid fd or internal error).
         * Fall back to using fd-based authorization without address info.
         */
        ak_effect_req_t req;
        err = ak_effect_from_listen(&req, ctx, fd, backlog);
        if (err < 0)
            return err;
        return ak_do_authorize(ctx, &req);
    }

    /* Build effect request with the bound address */
    ak_effect_req_t req;
    ak_memzero(&req, sizeof(req));
    req.op = AK_E_NET_LISTEN;
    req.trace_id = ak_trace_id_generate(ctx);

    /*
     * Canonicalize the bound address to target format.
     * If canonicalization fails, use wildcard "ip:*:*" for unbound/unknown sockets.
     */
    err = ak_canonicalize_sockaddr(addr, addrlen, req.target, AK_MAX_TARGET);
    if (err < 0) {
        /* Use wildcard target for unbound/unknown sockets */
        runtime_strncpy(req.target, "ip:*:*", AK_MAX_TARGET);
    }

    /* Encode backlog in params */
    char *p = (char *)req.params;
    int len = 0;
    p[len++] = '{';
    p[len++] = '"';
    p[len++] = 'b';
    p[len++] = '"';
    p[len++] = ':';

    /* Format backlog as decimal */
    char num[12];
    int numlen = 0;
    int b = backlog;
    if (b <= 0) {
        num[numlen++] = '0';
    } else {
        while (b > 0 && numlen < 11) {
            num[numlen++] = '0' + (b % 10);
            b /= 10;
        }
        /* Reverse */
        for (int i = 0; i < numlen / 2; i++) {
            char t = num[i];
            num[i] = num[numlen - 1 - i];
            num[numlen - 1 - i] = t;
        }
    }
    /* Bounds check to prevent buffer overflow */
    if (len + numlen + 2 > AK_MAX_PARAMS)
        return -EINVAL;
    runtime_memcpy(p + len, num, numlen);
    len += numlen;

    p[len++] = '}';
    p[len] = '\0';
    req.params_len = len;

    return ak_do_authorize(ctx, &req);
}

sysreturn ak_route_dns_resolve(const char *hostname)
{
    /* HARD MODE CHECK: Block raw syscalls not through AK API */
    sysreturn hard_check = ak_check_hard_mode_block();
    if (hard_check < 0)
        return hard_check;

    route_stats.total_routed++;
    route_stats.dns_calls++;

    ak_ctx_t *ctx = ak_ctx_current();

    /* MODE_OFF: bypass routing */
    if (!ctx || ak_ctx_get_mode(ctx) == AK_MODE_OFF) {
        route_stats.total_bypassed++;
        return 0;
    }

    /* Build effect request */
    ak_effect_req_t req;
    int err = ak_effect_from_dns_resolve(&req, ctx, hostname);
    if (err < 0)
        return err;

    return ak_do_authorize(ctx, &req);
}

/* ============================================================
 * FD REGISTRATION / CLOSE HOOKS
 * ============================================================
 *
 * These functions integrate the FD table with syscall routing.
 * They should be called from the Nanos syscall handlers:
 *
 *   - ak_route_register_fd(): Call after successful open/openat
 *   - ak_route_close(): Call before close() to unregister the FD
 *   - ak_route_set_cwd(): Call on chdir/fchdir to update CWD
 */

void ak_route_register_fd(int fd, const char *path, boolean is_directory)
{
    if (fd < 0 || !path)
        return;

    /* Register the FD in the table for later *at() resolution */
    int err = ak_fd_table_register(fd, path, is_directory);
    if (err < 0) {
        ak_debug("ak_route_register_fd: failed to register fd=%d path=%s err=%d",
                 fd, path, err);
    }
}

void ak_route_register_fd_from_openat(int fd, int dirfd, const char *path,
                                       int flags, boolean is_directory)
{
    if (fd < 0 || !path)
        return;

    char resolved_path[AK_MAX_TARGET];
    int err;

    /* Resolve the full path for the FD table */
    if (path[0] == '/') {
        /* Absolute path */
        err = ak_canonicalize_path(path, resolved_path, sizeof(resolved_path), "/");
    } else if (dirfd == AT_FDCWD) {
        /* Relative to CWD */
        char cwd[AK_MAX_TARGET];
        err = ak_fd_table_get_cwd(cwd, sizeof(cwd));
        if (err < 0) {
            cwd[0] = '/';
            cwd[1] = '\0';
        }
        err = ak_canonicalize_path(path, resolved_path, sizeof(resolved_path), cwd);
    } else {
        /* Relative to dirfd */
        err = ak_fd_table_resolve_at(dirfd, path, resolved_path, sizeof(resolved_path));
    }

    if (err < 0) {
        ak_debug("ak_route_register_fd_from_openat: resolve failed fd=%d err=%d", fd, err);
        return;
    }

    /* Register the resolved path */
    err = ak_fd_table_register(fd, resolved_path, is_directory);
    if (err < 0) {
        ak_debug("ak_route_register_fd_from_openat: register failed fd=%d err=%d", fd, err);
    }
}

sysreturn ak_route_close(int fd)
{
    /*
     * Close routing hook.
     *
     * This function should be called before the actual close() syscall.
     * It unregisters the FD from the tracking table.
     *
     * Note: We don't perform policy checks on close() as it's generally
     * a non-effectful cleanup operation. The FD was already authorized
     * when it was opened.
     */

    /* HARD MODE CHECK: Block raw syscalls not through AK API */
    sysreturn hard_check = ak_check_hard_mode_block();
    if (hard_check < 0)
        return hard_check;

    route_stats.total_routed++;

    /* Unregister the FD from our tracking table */
    ak_fd_table_unregister(fd);

    /* Allow close to proceed */
    return 0;
}

int ak_route_set_cwd(const char *path)
{
    /*
     * Update the current working directory used for AT_FDCWD resolution.
     *
     * Should be called after successful chdir() or fchdir().
     */
    if (!path)
        return -EINVAL;

    char canonical[AK_MAX_TARGET];
    int err = ak_canonicalize_path(path, canonical, sizeof(canonical), "/");
    if (err < 0)
        return err;

    return ak_fd_table_set_cwd(canonical);
}

int ak_route_set_cwd_from_fd(int fd)
{
    /*
     * Update CWD from a file descriptor (for fchdir).
     */
    char path[AK_MAX_TARGET];
    int err = ak_fd_table_lookup(fd, path, sizeof(path));
    if (err < 0)
        return err;

    /* Verify it's a directory */
    if (!ak_fd_table_is_directory(fd))
        return -ENOTDIR;

    return ak_fd_table_set_cwd(path);
}

/* ============================================================
 * STATISTICS
 * ============================================================ */

void ak_posix_route_get_stats(ak_posix_route_stats_t *stats)
{
    if (!stats)
        return;
    runtime_memcpy(stats, &route_stats, sizeof(route_stats));
}

/* ============================================================
 * INTEGRATION GUIDANCE
 * ============================================================
 *
 * To integrate these routing hooks into Nanos syscall handlers:
 *
 * 1. FILESYSTEM SYSCALLS (in src/unix/syscall.c):
 *
 *    Modify open():
 *    ```c
 *    sysreturn open(const char *name, int flags, int mode)
 *    {
 *        #ifdef CONFIG_AK_ENABLED
 *        sysreturn ak_rv = ak_route_open(name, flags, mode);
 *        if (ak_rv < 0)
 *            return ak_rv;  // Denied
 *        #endif
 *
 *        // Original implementation...
 *        sstring name_ss;
 *        if (!fault_in_user_string(name, &name_ss))
 *            return -EFAULT;
 *        // ... rest of original code, after getting fd:
 *
 *        #ifdef CONFIG_AK_ENABLED
 *        // Register fd for *at() syscall resolution
 *        boolean is_dir = (flags & O_DIRECTORY) != 0;
 *        ak_route_register_fd(fd, canonical_path, is_dir);
 *        #endif
 *
 *        return fd;
 *    }
 *    ```
 *
 *    Modify openat():
 *    ```c
 *    sysreturn openat(int dirfd, const char *name, int flags, int mode)
 *    {
 *        #ifdef CONFIG_AK_ENABLED
 *        sysreturn ak_rv = ak_route_openat(dirfd, name, flags, mode);
 *        if (ak_rv < 0)
 *            return ak_rv;  // Denied
 *        #endif
 *
 *        // ... original implementation, after getting fd:
 *
 *        #ifdef CONFIG_AK_ENABLED
 *        boolean is_dir = (flags & O_DIRECTORY) != 0;
 *        ak_route_register_fd_from_openat(fd, dirfd, name, flags, is_dir);
 *        #endif
 *
 *        return fd;
 *    }
 *    ```
 *
 *    Modify close():
 *    ```c
 *    sysreturn close(int fd)
 *    {
 *        #ifdef CONFIG_AK_ENABLED
 *        sysreturn ak_rv = ak_route_close(fd);
 *        if (ak_rv < 0)
 *            return ak_rv;
 *        #endif
 *
 *        // Original close implementation...
 *    }
 *    ```
 *
 *    Modify chdir():
 *    ```c
 *    sysreturn chdir(const char *path)
 *    {
 *        // ... original implementation (validate, change dir) ...
 *
 *        #ifdef CONFIG_AK_ENABLED
 *        ak_route_set_cwd(canonical_path);
 *        #endif
 *
 *        return 0;
 *    }
 *    ```
 *
 *    Modify fchdir():
 *    ```c
 *    sysreturn fchdir(int fd)
 *    {
 *        // ... original implementation ...
 *
 *        #ifdef CONFIG_AK_ENABLED
 *        ak_route_set_cwd_from_fd(fd);
 *        #endif
 *
 *        return 0;
 *    }
 *    ```
 *
 *    Similarly for mkdir(), unlink(), rename(), etc.
 *
 * 2. NETWORK SYSCALLS (in src/net/netsyscall.c):
 *
 *    Modify connect():
 *    ```c
 *    sysreturn connect(int sockfd, struct sockaddr *addr, socklen_t addrlen)
 *    {
 *        #ifdef CONFIG_AK_ENABLED
 *        sysreturn ak_rv = ak_route_connect(sockfd, addr, addrlen);
 *        if (ak_rv < 0)
 *            return ak_rv;  // Denied
 *        #endif
 *
 *        // Original implementation...
 *        if (!validate_user_memory(addr, addrlen, false))
 *            return -EFAULT;
 *        // ... rest of original code
 *    }
 *    ```
 *
 *    Similarly for bind(), listen().
 *
 * 3. DNS RESOLUTION (in lwIP or custom resolver):
 *
 *    Before calling dns_gethostbyname() or getaddrinfo():
 *    ```c
 *    #ifdef CONFIG_AK_ENABLED
 *    sysreturn ak_rv = ak_route_dns_resolve(hostname);
 *    if (ak_rv < 0)
 *        return ak_rv;  // DNS resolution denied
 *    #endif
 *    // Proceed with actual resolution
 *    ```
 *
 * 4. ALTERNATIVE: Use the AK_ROUTE_* macros:
 *
 *    ```c
 *    sysreturn open(const char *name, int flags, int mode)
 *    {
 *        AK_ROUTE_FS(open, name, flags, mode);
 *        // Original implementation follows...
 *    }
 *    ```
 *
 * 5. INITIALIZATION:
 *
 *    In kernel init (e.g., ak_init()):
 *    ```c
 *    void ak_init(heap h)
 *    {
 *        ak_effects_init(h);
 *        ak_context_module_init(h);
 *        ak_posix_route_init(h);  // Initializes routing AND FD table
 *        // ... other init
 *    }
 *    ```
 */
