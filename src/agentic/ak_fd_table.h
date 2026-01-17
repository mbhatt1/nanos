/*
 * Authority Kernel - File Descriptor Table
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * This module provides FD-to-path tracking for the Authority Kernel.
 * It enables proper resolution of dirfd arguments in *at() syscalls
 * (openat, unlinkat, mkdirat, renameat, etc.) by maintaining a mapping
 * from file descriptors to their canonical paths.
 *
 * Thread Safety:
 *   All operations on the FD table are protected by a spin lock.
 *   Multiple threads can safely register, unregister, and lookup FDs.
 *
 * Usage:
 *   - Call ak_fd_table_init() during AK initialization
 *   - Call ak_fd_table_register() after successful open/openat
 *   - Call ak_fd_table_unregister() on close()
 *   - Call ak_fd_table_resolve_at() to resolve dirfd-relative paths
 */

#ifndef AK_FD_TABLE_H
#define AK_FD_TABLE_H

#include "ak_types.h"
#include "ak_compat.h"

/* ============================================================
 * CONSTANTS
 * ============================================================ */

/* Maximum number of tracked file descriptors */
#define AK_FD_TABLE_SIZE        1024

/* Special file descriptor values */
#ifndef AT_FDCWD
#define AT_FDCWD                (-100)  /* Use current working directory */
#endif

/* ============================================================
 * DATA STRUCTURES
 * ============================================================ */

/*
 * Entry in the FD table.
 *
 * Tracks the association between a file descriptor and its
 * canonical path at the time of open.
 */
typedef struct ak_fd_entry {
    int fd;                         /* File descriptor number */
    char path[AK_MAX_TARGET];       /* Canonical path */
    boolean is_directory;           /* True if fd refers to a directory */
    boolean valid;                  /* True if this entry is in use */
} ak_fd_entry_t;

/* ============================================================
 * INITIALIZATION / SHUTDOWN
 * ============================================================ */

/*
 * Initialize the FD table subsystem.
 *
 * Must be called during AK initialization, before any FD tracking
 * operations are used. Initializes the table and spin lock.
 *
 * Parameters:
 *   h - Heap for any allocations (currently unused, for future expansion)
 *
 * Returns:
 *   0 on success, negative errno on failure
 */
int ak_fd_table_init(heap h);

/*
 * Shutdown the FD table subsystem.
 *
 * Clears all tracked FDs and releases any resources.
 */
void ak_fd_table_shutdown(void);

/* ============================================================
 * FD REGISTRATION / UNREGISTRATION
 * ============================================================ */

/*
 * Register a file descriptor with its path.
 *
 * Should be called after a successful open/openat syscall to record
 * the mapping from fd to path. The path is stored canonicalized.
 *
 * Parameters:
 *   fd     - File descriptor number (must be >= 0)
 *   path   - Canonical path associated with the fd
 *   is_dir - True if the fd refers to a directory
 *
 * Returns:
 *   0 on success
 *   -EINVAL if fd < 0 or path is NULL
 *   -ENOSPC if FD table is full
 *   -EEXIST if fd is already registered (updates existing entry)
 */
int ak_fd_table_register(int fd, const char *path, boolean is_dir);

/*
 * Unregister a file descriptor.
 *
 * Should be called when a file descriptor is closed. Removes the
 * fd from the tracking table.
 *
 * Parameters:
 *   fd - File descriptor to unregister
 *
 * Returns:
 *   0 on success (or if fd was not registered)
 *   -EINVAL if fd < 0
 */
int ak_fd_table_unregister(int fd);

/* ============================================================
 * FD LOOKUP AND PATH RESOLUTION
 * ============================================================ */

/*
 * Look up the path for a file descriptor.
 *
 * Retrieves the canonical path associated with a registered fd.
 *
 * Parameters:
 *   fd       - File descriptor to look up
 *   path_out - Buffer to receive the path
 *   max_len  - Size of path_out buffer
 *
 * Returns:
 *   0 on success (path copied to path_out)
 *   -EINVAL if fd < 0 or path_out is NULL
 *   -ENOENT if fd is not registered
 *   -ERANGE if path_out buffer is too small
 */
int ak_fd_table_lookup(int fd, char *path_out, u64 max_len);

/*
 * Check if a file descriptor refers to a directory.
 *
 * Parameters:
 *   fd - File descriptor to check
 *
 * Returns:
 *   true if fd is registered and is a directory
 *   false otherwise
 */
boolean ak_fd_table_is_directory(int fd);

/*
 * Resolve a path relative to a directory file descriptor.
 *
 * This is the main function for resolving *at() syscall paths.
 * It handles the following cases:
 *
 *   1. Absolute path (starts with '/'): Returns the path directly,
 *      ignoring dirfd.
 *
 *   2. dirfd == AT_FDCWD (-100): Resolves path relative to the
 *      current working directory (uses "/" as default CWD).
 *
 *   3. Registered dirfd: Resolves path relative to the directory
 *      path associated with dirfd in the FD table.
 *
 *   4. Unknown dirfd: Returns -EBADF (bad file descriptor).
 *
 * Parameters:
 *   dirfd   - Directory file descriptor (or AT_FDCWD)
 *   path    - Relative or absolute path
 *   out     - Buffer to receive resolved canonical path
 *   max_len - Size of out buffer
 *
 * Returns:
 *   0 on success (resolved path in out)
 *   -EINVAL if path or out is NULL
 *   -EBADF if dirfd is not AT_FDCWD and not registered
 *   -ENOTDIR if dirfd is registered but not a directory
 *   -ERANGE if out buffer is too small
 */
int ak_fd_table_resolve_at(int dirfd, const char *path, char *out, u64 max_len);

/* ============================================================
 * CURRENT WORKING DIRECTORY
 * ============================================================ */

/*
 * Set the current working directory for path resolution.
 *
 * This is used when resolving paths with AT_FDCWD. If not set,
 * the default is "/".
 *
 * Parameters:
 *   cwd - Canonical path of current working directory
 *
 * Returns:
 *   0 on success
 *   -EINVAL if cwd is NULL
 */
int ak_fd_table_set_cwd(const char *cwd);

/*
 * Get the current working directory.
 *
 * Parameters:
 *   out     - Buffer to receive CWD
 *   max_len - Size of out buffer
 *
 * Returns:
 *   0 on success
 *   -EINVAL if out is NULL
 *   -ERANGE if out buffer is too small
 */
int ak_fd_table_get_cwd(char *out, u64 max_len);

/* ============================================================
 * STATISTICS
 * ============================================================ */

/*
 * FD table statistics.
 */
typedef struct ak_fd_table_stats {
    u64 registers;          /* Total register calls */
    u64 unregisters;        /* Total unregister calls */
    u64 lookups;            /* Total lookup calls */
    u64 resolves;           /* Total resolve_at calls */
    u64 lookup_hits;        /* Successful lookups */
    u64 lookup_misses;      /* Failed lookups (fd not found) */
    u64 resolve_errors;     /* Resolution errors (bad fd, not dir) */
    u32 current_entries;    /* Currently registered entries */
    u32 peak_entries;       /* Peak number of entries */
} ak_fd_table_stats_t;

/*
 * Get FD table statistics.
 *
 * Parameters:
 *   stats - Output structure for statistics
 */
void ak_fd_table_get_stats(ak_fd_table_stats_t *stats);

/* ============================================================
 * DEBUG / DIAGNOSTIC
 * ============================================================ */

/*
 * Dump the FD table contents for debugging.
 *
 * Prints all registered FDs and their paths to the debug output.
 * Only available when AK_DEBUG is enabled.
 */
void ak_fd_table_dump(void);

#endif /* AK_FD_TABLE_H */
