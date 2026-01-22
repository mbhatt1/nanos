/*
 * Authority Kernel - File Descriptor Table Implementation
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Implements FD-to-path tracking for proper resolution of dirfd
 * arguments in *at() syscalls. This enables the Authority Kernel
 * to correctly canonicalize paths for policy enforcement.
 *
 * Design:
 *   - Simple array-based table with linear search
 *   - Suitable for moderate FD counts (up to 1024)
 *   - Protected by spin lock for thread safety
 *   - Could be extended to hash table for larger FD counts
 *
 * Thread Safety:
 *   All public functions acquire the spin lock before accessing
 *   the table. The lock is held for the minimum necessary duration.
 */

#include "ak_fd_table.h"
#include "ak_effects.h"

/* ============================================================
 * MODULE STATE
 * ============================================================ */

/* The FD table - array of entries */
static ak_fd_entry_t fd_table[AK_FD_TABLE_SIZE];

/* Spin lock for thread-safe access */
static spin_lock fd_table_lock;

/* Current working directory for AT_FDCWD resolution */
static char current_cwd[AK_MAX_TARGET] = "/";

/* Statistics */
static ak_fd_table_stats_t fd_stats;

/* Initialization flag */
static boolean fd_table_initialized = false;

/* ============================================================
 * INTERNAL HELPERS
 * ============================================================ */

/*
 * Find an entry by file descriptor.
 * Caller must hold fd_table_lock.
 *
 * Returns pointer to entry if found, NULL otherwise.
 */
static ak_fd_entry_t *fd_table_find_entry(int fd) {
  for (u32 i = 0; i < AK_FD_TABLE_SIZE; i++) {
    if (fd_table[i].valid && fd_table[i].fd == fd) {
      return &fd_table[i];
    }
  }
  return NULL;
}

/*
 * Find a free slot in the table.
 * Caller must hold fd_table_lock.
 *
 * Returns pointer to free entry, or NULL if table is full.
 */
static ak_fd_entry_t *fd_table_find_free(void) {
  for (u32 i = 0; i < AK_FD_TABLE_SIZE; i++) {
    if (!fd_table[i].valid) {
      return &fd_table[i];
    }
  }
  return NULL;
}

/* ============================================================
 * INITIALIZATION / SHUTDOWN
 * ============================================================ */

int ak_fd_table_init(heap h) {
  (void)h; /* Currently unused, reserved for future expansion */

  if (fd_table_initialized) {
    return 0; /* Already initialized */
  }

  /* Initialize the spin lock */
  spin_lock_init(&fd_table_lock);

  /* Clear the table */
  ak_memzero(fd_table, sizeof(fd_table));

  /* Set default CWD */
  current_cwd[0] = '/';
  current_cwd[1] = '\0';

  /* Clear statistics */
  ak_memzero(&fd_stats, sizeof(fd_stats));

  fd_table_initialized = true;

  ak_debug("ak_fd_table: initialized with %d slots", AK_FD_TABLE_SIZE);
  return 0;
}

void ak_fd_table_shutdown(void) {
  if (!fd_table_initialized) {
    return;
  }

  spin_lock(&fd_table_lock);

  /* Clear all entries */
  ak_memzero(fd_table, sizeof(fd_table));
  fd_stats.current_entries = 0;

  spin_unlock(&fd_table_lock);

  fd_table_initialized = false;

  ak_debug("ak_fd_table: shutdown");
}

/* ============================================================
 * FD REGISTRATION / UNREGISTRATION
 * ============================================================ */

int ak_fd_table_register(int fd, const char *path, boolean is_dir) {
  if (fd < 0) {
    return -EINVAL;
  }
  if (!path) {
    return -EINVAL;
  }
  if (!fd_table_initialized) {
    /* Auto-initialize if needed */
    int err = ak_fd_table_init(NULL);
    if (err < 0)
      return err;
  }

  spin_lock(&fd_table_lock);

  fd_stats.registers++;

  /* Check if fd already exists - update if so */
  ak_fd_entry_t *entry = fd_table_find_entry(fd);
  if (entry) {
    /* Update existing entry */
    runtime_strncpy(entry->path, path, AK_MAX_TARGET);
    entry->path[AK_MAX_TARGET - 1] = '\0'; /* Ensure null termination */
    entry->is_directory = is_dir;
    spin_unlock(&fd_table_lock);
    ak_debug("ak_fd_table: updated fd=%d path=%s dir=%d", fd, entry->path,
             is_dir);
    return 0;
  }

  /* Find a free slot */
  entry = fd_table_find_free();
  if (!entry) {
    spin_unlock(&fd_table_lock);
    ak_warn("ak_fd_table: table full, cannot register fd=%d", fd);
    return -ENOSPC;
  }

  /* Initialize the entry */
  entry->fd = fd;
  runtime_strncpy(entry->path, path, AK_MAX_TARGET);
  entry->path[AK_MAX_TARGET - 1] = '\0'; /* Ensure null termination */
  entry->is_directory = is_dir;
  entry->valid = true;

  fd_stats.current_entries++;
  if (fd_stats.current_entries > fd_stats.peak_entries) {
    fd_stats.peak_entries = fd_stats.current_entries;
  }

  spin_unlock(&fd_table_lock);

  ak_debug("ak_fd_table: registered fd=%d path=%s dir=%d", fd, entry->path,
           is_dir);
  return 0;
}

int ak_fd_table_unregister(int fd) {
  if (fd < 0) {
    return -EINVAL;
  }
  if (!fd_table_initialized) {
    return 0; /* Nothing to unregister */
  }

  spin_lock(&fd_table_lock);

  fd_stats.unregisters++;

  ak_fd_entry_t *entry = fd_table_find_entry(fd);
  if (entry) {
    /* Clear the entry */
    ak_memzero(entry, sizeof(*entry));
    entry->valid = false;
    fd_stats.current_entries--;
    spin_unlock(&fd_table_lock);
    ak_debug("ak_fd_table: unregistered fd=%d", fd);
    return 0;
  }

  spin_unlock(&fd_table_lock);
  /* Not an error if fd wasn't registered */
  return 0;
}

/* ============================================================
 * FD LOOKUP AND PATH RESOLUTION
 * ============================================================ */

int ak_fd_table_lookup(int fd, char *path_out, u64 max_len) {
  if (fd < 0) {
    return -EINVAL;
  }
  if (!path_out || max_len == 0) {
    return -EINVAL;
  }
  if (!fd_table_initialized) {
    return -ENOENT;
  }

  spin_lock(&fd_table_lock);

  fd_stats.lookups++;

  ak_fd_entry_t *entry = fd_table_find_entry(fd);
  if (!entry) {
    fd_stats.lookup_misses++;
    spin_unlock(&fd_table_lock);
    return -ENOENT;
  }

  u64 path_len = runtime_strlen(entry->path);
  if (path_len >= max_len) {
    spin_unlock(&fd_table_lock);
    return -ERANGE;
  }

  runtime_strncpy(path_out, entry->path, max_len);
  path_out[max_len - 1] = '\0';

  fd_stats.lookup_hits++;

  spin_unlock(&fd_table_lock);
  return 0;
}

boolean ak_fd_table_is_directory(int fd) {
  if (fd < 0 || !fd_table_initialized) {
    return false;
  }

  spin_lock(&fd_table_lock);

  ak_fd_entry_t *entry = fd_table_find_entry(fd);
  boolean result = (entry && entry->is_directory);

  spin_unlock(&fd_table_lock);
  return result;
}

int ak_fd_table_resolve_at(int dirfd, const char *path, char *out,
                           u64 max_len) {
  if (!path || !out || max_len == 0) {
    return -EINVAL;
  }

  /* Auto-initialize if needed */
  if (!fd_table_initialized) {
    int err = ak_fd_table_init(NULL);
    if (err < 0)
      return err;
  }

  spin_lock(&fd_table_lock);

  fd_stats.resolves++;

  /* Case 1: Absolute path - ignore dirfd */
  if (path[0] == '/') {
    spin_unlock(&fd_table_lock);
    return ak_canonicalize_path(path, out, max_len, "/");
  }

  /* Case 2: AT_FDCWD - use current working directory */
  if (dirfd == AT_FDCWD) {
    char cwd_copy[AK_MAX_TARGET];
    runtime_strncpy(cwd_copy, current_cwd, sizeof(cwd_copy));
    spin_unlock(&fd_table_lock);
    return ak_canonicalize_path(path, out, max_len, cwd_copy);
  }

  /* Case 3: Lookup the dirfd in our table */
  if (dirfd < 0) {
    fd_stats.resolve_errors++;
    spin_unlock(&fd_table_lock);
    return -EBADF;
  }

  ak_fd_entry_t *entry = fd_table_find_entry(dirfd);
  if (!entry) {
    fd_stats.resolve_errors++;
    spin_unlock(&fd_table_lock);
    ak_debug("ak_fd_table: resolve_at failed - fd=%d not registered", dirfd);
    return -EBADF;
  }

  /* Check if it's actually a directory */
  if (!entry->is_directory) {
    fd_stats.resolve_errors++;
    spin_unlock(&fd_table_lock);
    ak_debug("ak_fd_table: resolve_at failed - fd=%d is not a directory",
             dirfd);
    return -ENOTDIR;
  }

  /* Copy the base path before releasing lock */
  char base_path[AK_MAX_TARGET];
  runtime_strncpy(base_path, entry->path, sizeof(base_path));

  spin_unlock(&fd_table_lock);

  /* Canonicalize the path relative to the directory */
  return ak_canonicalize_path(path, out, max_len, base_path);
}

/* ============================================================
 * CURRENT WORKING DIRECTORY
 * ============================================================ */

int ak_fd_table_set_cwd(const char *cwd) {
  if (!cwd) {
    return -EINVAL;
  }

  /* Auto-initialize if needed */
  if (!fd_table_initialized) {
    int err = ak_fd_table_init(NULL);
    if (err < 0)
      return err;
  }

  spin_lock(&fd_table_lock);

  runtime_strncpy(current_cwd, cwd, sizeof(current_cwd));
  current_cwd[AK_MAX_TARGET - 1] = '\0';

  spin_unlock(&fd_table_lock);

  ak_debug("ak_fd_table: set cwd=%s", current_cwd);
  return 0;
}

int ak_fd_table_get_cwd(char *out, u64 max_len) {
  if (!out || max_len == 0) {
    return -EINVAL;
  }

  if (!fd_table_initialized) {
    /* Return default "/" if not initialized */
    if (max_len < 2) {
      return -ERANGE;
    }
    out[0] = '/';
    out[1] = '\0';
    return 0;
  }

  spin_lock(&fd_table_lock);

  u64 cwd_len = runtime_strlen(current_cwd);
  if (cwd_len >= max_len) {
    spin_unlock(&fd_table_lock);
    return -ERANGE;
  }

  runtime_strncpy(out, current_cwd, max_len);
  out[max_len - 1] = '\0';

  spin_unlock(&fd_table_lock);
  return 0;
}

/* ============================================================
 * STATISTICS
 * ============================================================ */

void ak_fd_table_get_stats(ak_fd_table_stats_t *stats) {
  if (!stats) {
    return;
  }

  if (!fd_table_initialized) {
    ak_memzero(stats, sizeof(*stats));
    return;
  }

  spin_lock(&fd_table_lock);
  runtime_memcpy(stats, &fd_stats, sizeof(fd_stats));
  spin_unlock(&fd_table_lock);
}

/* ============================================================
 * DEBUG / DIAGNOSTIC
 * ============================================================ */

void ak_fd_table_dump(void) {
#if AK_DEBUG
  if (!fd_table_initialized) {
    rprintf("ak_fd_table: not initialized\n");
    return;
  }

  spin_lock(&fd_table_lock);

  rprintf("ak_fd_table: dump (entries=%d, peak=%d)\n", fd_stats.current_entries,
          fd_stats.peak_entries);
  rprintf("  cwd: %s\n", current_cwd);

  for (u32 i = 0; i < AK_FD_TABLE_SIZE; i++) {
    if (fd_table[i].valid) {
      rprintf("  fd=%d dir=%d path=%s\n", fd_table[i].fd,
              fd_table[i].is_directory, fd_table[i].path);
    }
  }

  rprintf("  stats: reg=%lu unreg=%lu lookup=%lu (hit=%lu miss=%lu) "
          "resolve=%lu err=%lu\n",
          fd_stats.registers, fd_stats.unregisters, fd_stats.lookups,
          fd_stats.lookup_hits, fd_stats.lookup_misses, fd_stats.resolves,
          fd_stats.resolve_errors);

  spin_unlock(&fd_table_lock);
#else
  (void)fd_table;
  (void)fd_stats;
  (void)current_cwd;
#endif
}
