/*
 * Authority Kernel - POSIX Syscall Routing
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * AGENT D OWNED: POSIX syscall routing layer.
 *
 * This module provides the hook layer that intercepts POSIX syscalls
 * and routes them through the Authority Kernel effects system for
 * policy enforcement.
 *
 * Architecture:
 *   User code -> ak_route_XXX() -> ak_authorize_and_execute() -> real_XXX()
 *
 * Routing Modes:
 *   - AK_MODE_OFF:  Bypass AK, call real syscall directly (debug only)
 *   - AK_MODE_SOFT: Route through AK, if allowed execute real syscall
 *   - AK_MODE_HARD: Deny raw effectful syscalls that bypass AK routing
 *
 * Integration with Nanos:
 *   The routing functions are designed to be called at the syscall entry
 *   points. Each route function:
 *     1. Checks the current AK mode
 *     2. Builds an effect request with canonicalized target
 *     3. Calls ak_authorize_and_execute()
 *     4. If allowed, calls the real syscall implementation
 *     5. Returns the result (or denial error)
 */

#ifndef AK_POSIX_ROUTE_H
#define AK_POSIX_ROUTE_H

#include "ak_effects.h"
#include "ak_context.h"
#include "ak_compat.h"

/* Forward declarations for network types */
struct sockaddr;

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

/*
 * Initialize the POSIX routing layer.
 *
 * Must be called after ak_effects_init() and ak_context_module_init().
 * Sets up any routing-specific state.
 *
 * Parameters:
 *   h - Heap for allocations
 *
 * Returns:
 *   0 on success, negative errno on failure
 */
int ak_posix_route_init(heap h);

/*
 * Shutdown the POSIX routing layer.
 *
 * Cleans up routing state. Should be called before ak_effects_shutdown().
 */
void ak_posix_route_shutdown(void);

/* ============================================================
 * FILESYSTEM ROUTING HOOKS
 * ============================================================
 *
 * These functions wrap the corresponding POSIX syscalls and route
 * them through ak_authorize_and_execute() for policy enforcement.
 */

/*
 * Route open() syscall through AK.
 *
 * Builds AK_E_FS_OPEN effect with canonicalized path.
 * If authorized, calls the real open() implementation.
 *
 * Parameters:
 *   path  - File path (may be relative)
 *   flags - Open flags (O_RDONLY, O_WRONLY, O_CREAT, etc.)
 *   mode  - File mode (for O_CREAT)
 *
 * Returns:
 *   File descriptor on success, negative errno on failure/denial
 *
 * Denial errno: -EACCES (permission denied)
 */
sysreturn ak_route_open(const char *path, int flags, int mode);

/*
 * Route openat() syscall through AK.
 *
 * Builds AK_E_FS_OPEN effect. If dirfd is AT_FDCWD or path is absolute,
 * resolves similarly to open(). Otherwise, resolves relative to dirfd.
 *
 * Parameters:
 *   dirfd - Directory file descriptor (or AT_FDCWD)
 *   path  - File path (may be relative)
 *   flags - Open flags
 *   mode  - File mode (for O_CREAT)
 *
 * Returns:
 *   File descriptor on success, negative errno on failure/denial
 */
sysreturn ak_route_openat(int dirfd, const char *path, int flags, int mode);

/*
 * Route unlink() syscall through AK.
 *
 * Builds AK_E_FS_UNLINK effect with canonicalized path.
 * Requires fs.write capability on the file/directory.
 *
 * Parameters:
 *   path - File path to delete
 *
 * Returns:
 *   0 on success, negative errno on failure/denial
 *
 * Denial errno: -EACCES (permission denied)
 */
sysreturn ak_route_unlink(const char *path);

/*
 * Route unlinkat() syscall through AK.
 *
 * Similar to unlink but resolves path relative to dirfd.
 *
 * Parameters:
 *   dirfd - Directory file descriptor
 *   path  - File path to delete
 *   flags - AT_REMOVEDIR to remove directory
 *
 * Returns:
 *   0 on success, negative errno on failure/denial
 */
sysreturn ak_route_unlinkat(int dirfd, const char *path, int flags);

/*
 * Route mkdir() syscall through AK.
 *
 * Builds AK_E_FS_MKDIR effect with canonicalized path.
 * Requires fs.write capability on the parent directory.
 *
 * Parameters:
 *   path - Directory path to create
 *   mode - Directory permissions
 *
 * Returns:
 *   0 on success, negative errno on failure/denial
 */
sysreturn ak_route_mkdir(const char *path, int mode);

/*
 * Route mkdirat() syscall through AK.
 *
 * Similar to mkdir but resolves path relative to dirfd.
 *
 * Parameters:
 *   dirfd - Directory file descriptor
 *   path  - Directory path to create
 *   mode  - Directory permissions
 *
 * Returns:
 *   0 on success, negative errno on failure/denial
 */
sysreturn ak_route_mkdirat(int dirfd, const char *path, int mode);

/*
 * Route rename() syscall through AK.
 *
 * Builds AK_E_FS_RENAME effect with both paths canonicalized.
 * Requires fs.write capability on both source and destination.
 *
 * Parameters:
 *   oldpath - Source path
 *   newpath - Destination path
 *
 * Returns:
 *   0 on success, negative errno on failure/denial
 */
sysreturn ak_route_rename(const char *oldpath, const char *newpath);

/*
 * Route renameat() syscall through AK.
 *
 * Similar to rename but resolves paths relative to directory fds.
 *
 * Parameters:
 *   olddirfd - Source directory fd
 *   oldpath  - Source path
 *   newdirfd - Destination directory fd
 *   newpath  - Destination path
 *
 * Returns:
 *   0 on success, negative errno on failure/denial
 */
sysreturn ak_route_renameat(int olddirfd, const char *oldpath,
                            int newdirfd, const char *newpath);

/* ============================================================
 * NETWORK ROUTING HOOKS
 * ============================================================
 *
 * Network syscall routing with address canonicalization.
 * IPv4-mapped IPv6 addresses are normalized to IPv4 for policy matching.
 */

/*
 * Route connect() syscall through AK.
 *
 * Builds AK_E_NET_CONNECT effect with canonicalized address.
 * Target format: "ip:A.B.C.D:port" or "ip:[ipv6]:port"
 *
 * Parameters:
 *   fd      - Socket file descriptor
 *   addr    - Target address
 *   addrlen - Address length
 *
 * Returns:
 *   0 on success, negative errno on failure/denial
 *
 * Denial errno: -ECONNREFUSED or -ENETUNREACH
 */
sysreturn ak_route_connect(int fd, const struct sockaddr *addr,
                           socklen_t addrlen);

/*
 * Route bind() syscall through AK.
 *
 * Builds AK_E_NET_BIND effect with canonicalized address.
 * Controls which local addresses/ports the process can bind to.
 *
 * Parameters:
 *   fd      - Socket file descriptor
 *   addr    - Local address to bind
 *   addrlen - Address length
 *
 * Returns:
 *   0 on success, negative errno on failure/denial
 */
sysreturn ak_route_bind(int fd, const struct sockaddr *addr,
                        socklen_t addrlen);

/*
 * Route listen() syscall through AK.
 *
 * Builds AK_E_NET_LISTEN effect. Uses the address from a prior bind()
 * or socket state to determine the target.
 *
 * Parameters:
 *   fd      - Socket file descriptor (must be bound)
 *   backlog - Connection queue length
 *
 * Returns:
 *   0 on success, negative errno on failure/denial
 */
sysreturn ak_route_listen(int fd, int backlog);

/*
 * Route DNS resolution through AK.
 *
 * Builds AK_E_NET_DNS_RESOLVE effect.
 * This should be called before getaddrinfo/gethostbyname.
 * Target format: "dns:<hostname>"
 *
 * Parameters:
 *   hostname - Hostname to resolve
 *
 * Returns:
 *   0 if allowed, negative errno if denied
 *
 * Denial errno: -ECONNREFUSED
 *
 * Note: This doesn't perform the actual resolution, just authorizes it.
 *       The caller should call the real resolver after this returns 0.
 */
sysreturn ak_route_dns_resolve(const char *hostname);

/* ============================================================
 * MODE CHECKING HELPERS
 * ============================================================ */

/*
 * Check if routing is active (mode != OFF).
 *
 * Returns:
 *   true if AK routing is active, false if bypassed
 */
boolean ak_routing_active(void);

/*
 * Check if we're in HARD mode (raw syscalls denied).
 *
 * Returns:
 *   true if HARD mode active
 */
boolean ak_routing_hard(void);

/*
 * Check if an effect operation is allowed in current mode without
 * actually executing it. Useful for capability probing.
 *
 * Parameters:
 *   op     - Effect operation to check
 *   target - Canonical target string
 *
 * Returns:
 *   true if would be allowed, false if would be denied
 */
boolean ak_route_check(ak_effect_op_t op, const char *target);

/* ============================================================
 * PATH RESOLUTION HELPERS
 * ============================================================ */

/*
 * Resolve dirfd-relative path to absolute path.
 *
 * Handles AT_FDCWD and absolute paths appropriately.
 *
 * Parameters:
 *   dirfd   - Directory file descriptor (or AT_FDCWD)
 *   path    - Relative or absolute path
 *   out     - Output buffer for resolved path
 *   out_len - Output buffer size
 *
 * Returns:
 *   0 on success, negative errno on failure
 */
int ak_resolve_path_at(int dirfd, const char *path, char *out, u32 out_len);

/*
 * Get current working directory.
 *
 * Parameters:
 *   out     - Output buffer
 *   out_len - Output buffer size
 *
 * Returns:
 *   0 on success, negative errno on failure
 */
int ak_get_cwd(char *out, u32 out_len);

/* ============================================================
 * SOCKET STATE HELPERS
 * ============================================================ */

/*
 * Get bound address for socket fd.
 *
 * Used by listen() routing to determine the target address.
 *
 * Parameters:
 *   fd      - Socket file descriptor
 *   addr    - Output address buffer
 *   addrlen - Input: buffer size, Output: actual size
 *
 * Returns:
 *   0 on success, negative errno on failure
 */
int ak_get_socket_bound_addr(int fd, struct sockaddr *addr, socklen_t *addrlen);

/* ============================================================
 * FD REGISTRATION / CLOSE HOOKS
 * ============================================================
 *
 * These functions integrate with the FD table for proper path
 * resolution in *at() syscalls. They should be called from
 * Nanos syscall handlers.
 */

/*
 * Register a file descriptor with its path.
 *
 * Should be called after a successful open() syscall to record
 * the FD->path mapping for later *at() syscall resolution.
 *
 * Parameters:
 *   fd           - File descriptor (must be >= 0)
 *   path         - Canonical path of the file/directory
 *   is_directory - True if fd refers to a directory
 */
void ak_route_register_fd(int fd, const char *path, boolean is_directory);

/*
 * Register a file descriptor from openat() result.
 *
 * Should be called after a successful openat() syscall. Resolves
 * the relative path to absolute before registering.
 *
 * Parameters:
 *   fd           - File descriptor returned by openat()
 *   dirfd        - Directory fd used in openat() call
 *   path         - Path used in openat() call
 *   flags        - Open flags (used to determine if O_DIRECTORY)
 *   is_directory - True if fd refers to a directory
 */
void ak_route_register_fd_from_openat(int fd, int dirfd, const char *path,
                                       int flags, boolean is_directory);

/*
 * Route close() syscall and unregister the FD.
 *
 * Should be called before close() to unregister the FD from tracking.
 * Does not perform policy checks on close.
 *
 * Parameters:
 *   fd - File descriptor to close
 *
 * Returns:
 *   0 to allow close to proceed
 *   -EPERM if blocked by HARD mode
 */
sysreturn ak_route_close(int fd);

/*
 * Set the current working directory for AT_FDCWD resolution.
 *
 * Should be called after successful chdir() syscall.
 *
 * Parameters:
 *   path - New CWD path
 *
 * Returns:
 *   0 on success, negative errno on failure
 */
int ak_route_set_cwd(const char *path);

/*
 * Set CWD from a file descriptor (for fchdir).
 *
 * Should be called after successful fchdir() syscall.
 *
 * Parameters:
 *   fd - Directory file descriptor
 *
 * Returns:
 *   0 on success
 *   -ENOENT if fd not registered
 *   -ENOTDIR if fd is not a directory
 */
int ak_route_set_cwd_from_fd(int fd);

/* ============================================================
 * STATISTICS
 * ============================================================ */

typedef struct ak_posix_route_stats {
    /* Total calls */
    u64 total_routed;
    u64 total_bypassed;     /* MODE_OFF bypass */
    u64 total_allowed;
    u64 total_denied;

    /* Per-syscall counts */
    u64 open_calls;
    u64 openat_calls;
    u64 unlink_calls;
    u64 mkdir_calls;
    u64 rename_calls;
    u64 connect_calls;
    u64 bind_calls;
    u64 listen_calls;
    u64 dns_calls;

    /* Denial breakdown */
    u64 fs_denials;
    u64 net_denials;

    /* HARD mode enforcement */
    u64 hard_mode_blocks;   /* Raw syscalls blocked in HARD mode */
} ak_posix_route_stats_t;

/*
 * Get routing statistics.
 *
 * Parameters:
 *   stats - Output structure
 */
void ak_posix_route_get_stats(ak_posix_route_stats_t *stats);

/* ============================================================
 * INTEGRATION MACROS
 * ============================================================
 *
 * These macros can be used in Nanos syscall handlers to conditionally
 * route through AK based on compile-time configuration.
 */

#ifdef CONFIG_AK_ENABLED

/*
 * Macro for routing a filesystem syscall.
 * Usage in syscall handler:
 *   AK_ROUTE_FS(open, path, flags, mode);
 */
#define AK_ROUTE_FS(syscall, ...) \
    do { \
        if (ak_routing_active()) { \
            sysreturn rv = ak_route_##syscall(__VA_ARGS__); \
            if (rv < 0) return rv; \
        } \
    } while(0)

/*
 * Macro for routing a network syscall.
 * Usage in syscall handler:
 *   AK_ROUTE_NET(connect, fd, addr, addrlen);
 */
#define AK_ROUTE_NET(syscall, ...) \
    do { \
        if (ak_routing_active()) { \
            sysreturn rv = ak_route_##syscall(__VA_ARGS__); \
            if (rv < 0) return rv; \
        } \
    } while(0)

/*
 * Conditional execution based on AK authorization.
 * Returns denial error if not authorized, otherwise continues.
 */
#define AK_REQUIRE_AUTHORIZED(route_func, ...) \
    do { \
        if (ak_routing_active()) { \
            sysreturn rv = route_func(__VA_ARGS__); \
            if (rv < 0) return rv; \
        } \
    } while(0)

#else /* !CONFIG_AK_ENABLED */

/* No-op when AK is disabled */
#define AK_ROUTE_FS(syscall, ...)           ((void)0)
#define AK_ROUTE_NET(syscall, ...)          ((void)0)
#define AK_REQUIRE_AUTHORIZED(func, ...)    ((void)0)

#endif /* CONFIG_AK_ENABLED */

#endif /* AK_POSIX_ROUTE_H */
