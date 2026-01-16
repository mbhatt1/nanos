/*
 * Authority Kernel - External State Synchronization
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Manages state persistence for ephemeral VMs:
 *   - On boot: Hydrate typed heap from external store
 *   - On AK_COMMIT: Sync dirty objects to external store
 *   - On shutdown: Final sync + anchor emission
 *
 * Supports multiple backend storage systems:
 *   - S3-compatible object storage
 *   - Redis/Valkey
 *   - Custom HTTP endpoints
 *
 * SECURITY:
 *   - All state is encrypted at rest
 *   - Integrity verified via merkle proofs
 *   - Anchors provide tamper-evidence
 */

#ifndef AK_STATE_H
#define AK_STATE_H

#include "ak_types.h"
#include "ak_heap.h"

/* ============================================================
 * STORAGE BACKEND CONFIGURATION
 * ============================================================ */

typedef enum ak_storage_backend {
    AK_STORAGE_NONE = 0,        /* In-memory only (ephemeral) */
    AK_STORAGE_S3 = 1,          /* S3-compatible object storage */
    AK_STORAGE_REDIS = 2,       /* Redis/Valkey key-value store */
    AK_STORAGE_HTTP = 3,        /* Custom HTTP API */
    AK_STORAGE_VIRTIO = 4,      /* virtio-serial to host storage */
} ak_storage_backend_t;

/* S3 backend configuration */
typedef struct ak_s3_config {
    char endpoint[256];         /* S3 endpoint URL */
    char bucket[64];            /* Bucket name */
    char prefix[64];            /* Key prefix for namespacing */
    char region[32];            /* AWS region */
    char access_key_secret[64]; /* Secret name for access key */
    char secret_key_secret[64]; /* Secret name for secret key */
    boolean use_path_style;     /* Use path-style URLs */
} ak_s3_config_t;

/* Redis backend configuration */
typedef struct ak_redis_config {
    char host[256];
    u16 port;
    char password_secret[64];   /* Secret name for password */
    u32 db_index;
    char key_prefix[64];
} ak_redis_config_t;

/* HTTP backend configuration */
typedef struct ak_http_config {
    char base_url[256];
    char auth_header_secret[64]; /* Secret name for auth header */
    u32 timeout_ms;
} ak_http_config_t;

/* Virtio backend configuration */
typedef struct ak_virtio_config {
    char device_path[64];
} ak_virtio_config_t;

/* Combined storage configuration */
typedef struct ak_storage_config {
    ak_storage_backend_t backend;

    union {
        ak_s3_config_t s3;
        ak_redis_config_t redis;
        ak_http_config_t http;
        ak_virtio_config_t virtio;
    };

    /* Encryption settings */
    boolean encrypt_at_rest;
    char encryption_key_secret[64];

    /* Sync settings */
    u32 sync_interval_ms;       /* Auto-sync interval (0 = manual) */
    u32 sync_batch_size;        /* Max objects per sync batch */
    u32 sync_timeout_ms;        /* Sync operation timeout */

    /* Compression settings */
    boolean compression_enabled; /* Enable LZ4 compression for sync */

    /* Retry settings */
    u32 max_retries;
    u32 retry_backoff_ms;
} ak_storage_config_t;

/* ============================================================
 * STATE SNAPSHOT
 * ============================================================
 * Represents a consistent state snapshot for sync.
 */

typedef struct ak_state_snapshot {
    /* Identification */
    u8 snapshot_id[AK_TOKEN_ID_SIZE];
    u64 sequence;               /* Monotonic snapshot number */
    u64 timestamp_ms;

    /* Content */
    u8 heap_root_hash[AK_HASH_SIZE];    /* Merkle root of heap */
    u8 log_hash[AK_HASH_SIZE];          /* Latest audit log hash */
    u64 log_sequence;                    /* Latest log entry seq */

    /* Objects included */
    u64 object_count;
    u64 total_bytes;

    /* Dirty tracking */
    u64 *dirty_ptrs;            /* Array of dirty object ptrs */
    u32 dirty_count;
} ak_state_snapshot_t;

/* ============================================================
 * ANCHOR EMISSION
 * ============================================================
 * Anchors provide external proof of state integrity.
 */

typedef struct ak_state_anchor {
    u64 timestamp_ms;
    u64 sequence;
    u8 heap_root[AK_HASH_SIZE];
    u8 log_root[AK_HASH_SIZE];
    u8 prev_anchor[AK_HASH_SIZE];
    u8 signature[64];           /* Ed25519 signature */
} ak_state_anchor_t;

/* ============================================================
 * SYNC STATUS
 * ============================================================ */

typedef enum ak_sync_status {
    AK_SYNC_IDLE = 0,
    AK_SYNC_IN_PROGRESS = 1,
    AK_SYNC_COMPLETED = 2,
    AK_SYNC_FAILED = 3,
    AK_SYNC_PARTIAL = 4,        /* Some objects synced */
} ak_sync_status_t;

typedef struct ak_sync_result {
    ak_sync_status_t status;
    u64 objects_synced;
    u64 bytes_synced;
    u64 duration_ms;
    s64 error_code;
    char error_message[256];
} ak_sync_result_t;

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

/*
 * Initialize state sync subsystem.
 */
void ak_state_init(heap h, ak_storage_config_t *config);

/*
 * Shutdown state sync subsystem.
 * Performs final sync before shutdown.
 */
void ak_state_shutdown(void);

/*
 * Update storage configuration.
 */
s64 ak_state_configure(ak_storage_config_t *config);

/* ============================================================
 * HYDRATION (Boot-time state loading)
 * ============================================================ */

/*
 * Hydrate typed heap from external store.
 *
 * Called during kernel initialization to restore state
 * from previous VM instance.
 *
 * Returns:
 *   0 - Success (state loaded)
 *   AK_E_STATE_NOT_FOUND - No previous state
 *   AK_E_STATE_CORRUPT - State verification failed
 */
s64 ak_state_hydrate(ak_heap_t *heap);

/*
 * Verify hydrated state integrity.
 */
boolean ak_state_verify_integrity(void);

/*
 * Get hydration status.
 */
typedef struct ak_hydration_status {
    boolean hydrated;
    u64 objects_loaded;
    u64 bytes_loaded;
    u64 duration_ms;
    u64 source_sequence;        /* Sequence of source snapshot */
} ak_hydration_status_t;

void ak_state_get_hydration_status(ak_hydration_status_t *status);

/* ============================================================
 * DIRTY TRACKING
 * ============================================================ */

/*
 * Mark object as dirty (needs sync).
 */
void ak_state_mark_dirty(u64 ptr);

/*
 * Mark object as clean (synced).
 */
void ak_state_mark_clean(u64 ptr);

/*
 * Check if object is dirty.
 */
boolean ak_state_is_dirty(u64 ptr);

/*
 * Get count of dirty objects.
 */
u64 ak_state_dirty_count(void);

/*
 * Get list of dirty object ptrs.
 */
u64 *ak_state_get_dirty_list(u32 *count_out);

/* ============================================================
 * SYNC OPERATIONS
 * ============================================================ */

/*
 * Sync all dirty objects to external store.
 *
 * This is the main sync entry point, called by:
 *   - AK_SYS_COMMIT handler
 *   - Periodic sync timer
 *   - Shutdown sequence
 */
ak_sync_result_t ak_state_sync(void);

/*
 * Sync specific objects.
 */
ak_sync_result_t ak_state_sync_objects(u64 *ptrs, u32 count);

/*
 * Force immediate sync (blocking).
 */
ak_sync_result_t ak_state_sync_immediate(void);

/*
 * Check if sync is in progress.
 */
boolean ak_state_sync_in_progress(void);

/*
 * Wait for current sync to complete.
 */
ak_sync_result_t ak_state_sync_wait(u32 timeout_ms);

/* ============================================================
 * ANCHOR EMISSION
 * ============================================================ */

/*
 * Emit state anchor to external store.
 *
 * Called:
 *   - After each successful sync
 *   - At periodic intervals
 *   - On graceful shutdown
 */
s64 ak_state_emit_anchor(void);

/*
 * Get latest anchor.
 */
ak_state_anchor_t *ak_state_get_latest_anchor(void);

/*
 * Verify anchor chain integrity.
 */
boolean ak_state_verify_anchor_chain(void);

/* ============================================================
 * BACKEND OPERATIONS
 * ============================================================
 * Low-level storage operations.
 */

/*
 * Store object to backend.
 */
s64 ak_backend_put(u64 ptr, buffer value, u8 *hash);

/*
 * Retrieve object from backend.
 */
buffer ak_backend_get(u64 ptr);

/*
 * Delete object from backend.
 */
s64 ak_backend_delete(u64 ptr);

/*
 * List all objects (for hydration).
 */
u64 *ak_backend_list(u32 *count_out);

/*
 * Check backend connectivity.
 */
boolean ak_backend_healthy(void);

/* ============================================================
 * SYSCALL HANDLER
 * ============================================================ */

/*
 * Handle state commit (called from ak_handle_commit in ak_syscall.c).
 *
 * Forces sync of dirty state and emits anchor.
 */
ak_response_t *ak_state_handle_commit(ak_agent_context_t *ctx, ak_request_t *req);

/* ============================================================
 * STATISTICS
 * ============================================================ */

typedef struct ak_state_stats {
    u64 syncs_total;
    u64 syncs_successful;
    u64 syncs_failed;
    u64 objects_synced_total;
    u64 bytes_synced_total;
    u64 bytes_compressed;       /* Bytes saved by compression */
    u64 anchors_emitted;
    u64 hydrations_total;
    u64 total_sync_time_ms;
} ak_state_stats_t;

void ak_state_get_stats(ak_state_stats_t *stats);

/* ============================================================
 * ERROR CODES
 * ============================================================ */

#define AK_E_STATE_NOT_FOUND        (-4700)
#define AK_E_STATE_CORRUPT          (-4701)
#define AK_E_STATE_SYNC_FAILED      (-4702)
#define AK_E_STATE_BACKEND_ERROR    (-4703)
#define AK_E_STATE_ENCRYPTION_ERROR (-4704)
#define AK_E_STATE_TIMEOUT          (-4705)

#endif /* AK_STATE_H */
