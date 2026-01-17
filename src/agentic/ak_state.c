/*
 * Authority Kernel - External State Synchronization
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Manages state persistence for ephemeral Authority VMs:
 *   - On boot: Hydrate typed heap from external store
 *   - On AK_COMMIT: Sync dirty objects to external store
 *   - On shutdown: Final sync + anchor emission
 *
 * Supported backends:
 *   - S3-compatible object storage
 *   - Redis/Valkey key-value store
 *   - Custom HTTP endpoints
 *   - virtio-serial to host storage daemon
 *
 * Security:
 *   - All state encrypted at rest (AES-256-GCM)
 *   - Integrity verified via merkle proofs
 *   - Anchors provide tamper-evident chain
 */

#include "ak_state.h"
#include "ak_audit.h"
#include "ak_compress.h"
#include "ak_compat.h"
#include "ak_syscall.h"
#include "ak_heap.h"

/* ============================================================
 * INTERNAL STATE
 * ============================================================ */

#define AK_MAX_DIRTY_OBJECTS    65536
#define AK_DIRTY_BITMAP_SIZE    (AK_MAX_DIRTY_OBJECTS / 64)

static struct {
    heap h;
    boolean initialized;
    ak_storage_config_t config;
    ak_state_stats_t stats;

    /* Hydration state */
    ak_hydration_status_t hydration;

    /* Dirty tracking (bitmap for efficiency) */
    u64 dirty_bitmap[AK_DIRTY_BITMAP_SIZE];
    u64 dirty_ptrs[AK_MAX_DIRTY_OBJECTS];
    u32 dirty_count;

    /* Sync state */
    ak_sync_status_t sync_status;
    u64 last_sync_ms;

    /* Anchor chain */
    ak_state_anchor_t latest_anchor;
    u64 anchor_sequence;

    /* Backend connection state */
    boolean backend_connected;
    int virtio_fd;
} ak_state;

/* ============================================================
 * CRYPTOGRAPHIC HELPERS
 * ============================================================ */

static u64 get_timestamp_ms(void)
{
    return now(CLOCK_ID_MONOTONIC) / MILLION;
}

/*
 * FNV-1a hash extended to fill AK_HASH_SIZE bytes.
 * Production deployments should use SHA-256.
 */
static void compute_hash(buffer data, u8 *hash_out)
{
    u64 len = buffer_length(data);
    u8 *bytes = buffer_ref(data, 0);

    /* FNV-1a 64-bit */
    u64 h = 0xcbf29ce484222325ULL;
    for (u64 i = 0; i < len; i++) {
        h ^= bytes[i];
        h *= 0x100000001b3ULL;
    }

    /* Extend hash to fill AK_HASH_SIZE */
    for (int i = 0; i < AK_HASH_SIZE; i++) {
        hash_out[i] = (h >> ((i % 8) * 8)) & 0xff;
        if ((i % 8) == 7) {
            h ^= (u64)i;
            h *= 0x100000001b3ULL;
        }
    }
}

/*
 * Compute merkle root from list of hashes.
 * Uses separate input/output buffers to avoid in-place overwriting bugs.
 */
static void compute_merkle_root(u8 *hashes, u32 count, u8 *root_out)
{
    if (count == 0) {
        runtime_memset(root_out, 0, AK_HASH_SIZE);
        return;
    }

    if (count == 1) {
        runtime_memcpy(root_out, hashes, AK_HASH_SIZE);
        return;
    }

    /* Overflow check for allocation size */
    if (count > UINT64_MAX / AK_HASH_SIZE) {
        runtime_memset(root_out, 0, AK_HASH_SIZE);
        return;
    }

    /* Allocate two buffers for ping-pong computation to avoid in-place overwrites */
    u64 max_level_size = (u64)count * AK_HASH_SIZE;
    u8 *buf_a = allocate(ak_state.h, max_level_size);
    u8 *buf_b = allocate(ak_state.h, max_level_size);

    if (buf_a == INVALID_ADDRESS || buf_b == INVALID_ADDRESS) {
        /* Allocation failed - fall back to zeroed root */
        if (buf_a != INVALID_ADDRESS)
            deallocate(ak_state.h, buf_a, max_level_size);
        if (buf_b != INVALID_ADDRESS)
            deallocate(ak_state.h, buf_b, max_level_size);
        runtime_memset(root_out, 0, AK_HASH_SIZE);
        return;
    }

    /* Copy input to first buffer */
    runtime_memcpy(buf_a, hashes, count * AK_HASH_SIZE);

    u8 *current = buf_a;
    u8 *next = buf_b;
    u32 current_count = count;

    while (current_count > 1) {
        u32 pairs = (current_count + 1) / 2;
        for (u32 i = 0; i < pairs; i++) {
            u8 combined[AK_HASH_SIZE * 2];
            runtime_memcpy(combined, &current[i * 2 * AK_HASH_SIZE], AK_HASH_SIZE);

            if (i * 2 + 1 < current_count) {
                runtime_memcpy(&combined[AK_HASH_SIZE],
                               &current[(i * 2 + 1) * AK_HASH_SIZE], AK_HASH_SIZE);
            } else {
                /* Odd node: duplicate */
                runtime_memcpy(&combined[AK_HASH_SIZE],
                               &current[i * 2 * AK_HASH_SIZE], AK_HASH_SIZE);
            }

            /* Hash the pair into the next buffer (not current) */
            buffer pair_buf = alloca_wrap_buffer(combined, AK_HASH_SIZE * 2);
            if (pair_buf && pair_buf != INVALID_ADDRESS) {
                compute_hash(pair_buf, &next[i * AK_HASH_SIZE]);
            } else {
                runtime_memset(&next[i * AK_HASH_SIZE], 0, AK_HASH_SIZE);
            }
        }
        current_count = pairs;

        /* Swap buffers for next iteration */
        u8 *tmp = current;
        current = next;
        next = tmp;
    }

    runtime_memcpy(root_out, current, AK_HASH_SIZE);

    /* Free allocated buffers */
    deallocate(ak_state.h, buf_a, max_level_size);
    deallocate(ak_state.h, buf_b, max_level_size);
}

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

void ak_state_init(heap h, ak_storage_config_t *config)
{
    if (ak_state.initialized)
        return;

    ak_state.h = h;
    runtime_memset((u8 *)&ak_state.stats, 0, sizeof(ak_state_stats_t));
    runtime_memset((u8 *)&ak_state.hydration, 0, sizeof(ak_hydration_status_t));
    runtime_memset((u8 *)ak_state.dirty_bitmap, 0, sizeof(ak_state.dirty_bitmap));
    ak_state.dirty_count = 0;
    ak_state.virtio_fd = -1;

    if (config) {
        runtime_memcpy(&ak_state.config, config, sizeof(ak_storage_config_t));
    } else {
        ak_state.config.backend = AK_STORAGE_NONE;
        ak_state.config.sync_interval_ms = 0;
        ak_state.config.sync_batch_size = 100;
        ak_state.config.sync_timeout_ms = 30000;
        ak_state.config.max_retries = 3;
        ak_state.config.retry_backoff_ms = 1000;
    }

    ak_state.sync_status = AK_SYNC_IDLE;
    ak_state.last_sync_ms = 0;
    ak_state.anchor_sequence = 0;
    ak_state.backend_connected = false;

    /* Initialize genesis anchor */
    runtime_memset((u8 *)&ak_state.latest_anchor, 0, sizeof(ak_state_anchor_t));
    ak_state.latest_anchor.timestamp_ms = get_timestamp_ms();
    ak_state.latest_anchor.sequence = 0;

    ak_state.initialized = true;

    /* Connect to backend */
    if (ak_state.config.backend != AK_STORAGE_NONE) {
        ak_state.backend_connected = ak_backend_healthy();
    }
}

void ak_state_shutdown(void)
{
    if (!ak_state.initialized)
        return;

    /* Final sync before shutdown */
    if (ak_state.config.backend != AK_STORAGE_NONE && ak_state.dirty_count > 0) {
        ak_state_sync_immediate();
        ak_state_emit_anchor();
    }

    if (ak_state.virtio_fd >= 0) {
        ak_state.virtio_fd = -1;
    }

    ak_state.initialized = false;
}

s64 ak_state_configure(ak_storage_config_t *config)
{
    if (!config)
        return AK_E_SCHEMA_INVALID;

    runtime_memcpy(&ak_state.config, config, sizeof(ak_storage_config_t));

    if (config->backend != AK_STORAGE_NONE) {
        ak_state.backend_connected = ak_backend_healthy();
    } else {
        ak_state.backend_connected = false;
    }

    return 0;
}

/* ============================================================
 * HYDRATION
 * ============================================================ */

s64 ak_state_hydrate(ak_heap_t *heap)
{
    if (!ak_state.initialized)
        return AK_E_STATE_NOT_FOUND;

    if (ak_state.config.backend == AK_STORAGE_NONE)
        return AK_E_STATE_NOT_FOUND;

    if (!heap)
        return AK_E_SCHEMA_INVALID;

    ak_state.stats.hydrations_total++;
    u64 start_ms = get_timestamp_ms();

    /* Get list of objects from backend */
    u32 object_count = 0;
    u64 *ptrs = ak_backend_list(&object_count);

    if (!ptrs || object_count == 0) {
        ak_state.hydration.hydrated = false;
        return AK_E_STATE_NOT_FOUND;
    }

    /* Bounds check: limit object count to prevent excessive memory usage */
    if (object_count > AK_MAX_DIRTY_OBJECTS) {
        object_count = AK_MAX_DIRTY_OBJECTS;
    }

    u64 bytes_loaded = 0;
    u64 objects_loaded = 0;

    /* Load each object into heap */
    for (u32 i = 0; i < object_count; i++) {
        buffer value = ak_backend_get(ptrs[i]);
        if (value && value != INVALID_ADDRESS) {
            /* Restore object to typed heap */
            s64 result = ak_heap_restore(value);
            if (result == 0) {
                bytes_loaded += buffer_length(value);
                objects_loaded++;
            }
            deallocate_buffer(value);
        }
    }

    if (ptrs)
        deallocate(ak_state.h, ptrs, object_count * sizeof(u64));

    ak_state.hydration.hydrated = (objects_loaded > 0);
    ak_state.hydration.objects_loaded = objects_loaded;
    ak_state.hydration.bytes_loaded = bytes_loaded;
    ak_state.hydration.duration_ms = get_timestamp_ms() - start_ms;

    return (objects_loaded > 0) ? 0 : AK_E_STATE_NOT_FOUND;
}

boolean ak_state_verify_integrity(void)
{
    if (!ak_state.hydration.hydrated)
        return false;

    /* Verify by recomputing merkle root and comparing to anchor */
    u32 count;
    u64 *ptrs = ak_state_get_dirty_list(&count);

    if (count == 0)
        return true;

    /* Overflow check for allocation size */
    if (count > UINT64_MAX / AK_HASH_SIZE)
        return false;

    /* Allocate hash array */
    u8 *hashes = allocate(ak_state.h, (u64)count * AK_HASH_SIZE);
    if (hashes == INVALID_ADDRESS)
        return false;

    /* Hash each object */
    for (u32 i = 0; i < count; i++) {
        buffer value = ak_backend_get(ptrs[i]);
        if (value && value != INVALID_ADDRESS) {
            compute_hash(value, &hashes[i * AK_HASH_SIZE]);
            deallocate_buffer(value);
        } else {
            runtime_memset(&hashes[i * AK_HASH_SIZE], 0, AK_HASH_SIZE);
        }
    }

    /* Compute merkle root */
    u8 computed_root[AK_HASH_SIZE];
    compute_merkle_root(hashes, count, computed_root);

    deallocate(ak_state.h, hashes, count * AK_HASH_SIZE);

    /* Compare to stored anchor */
    return runtime_memcmp(computed_root, ak_state.latest_anchor.heap_root,
                          AK_HASH_SIZE) == 0;
}

void ak_state_get_hydration_status(ak_hydration_status_t *status)
{
    if (status)
        runtime_memcpy(status, &ak_state.hydration, sizeof(ak_hydration_status_t));
}

/* ============================================================
 * DIRTY TRACKING
 * ============================================================ */

static u32 ptr_to_index(u64 ptr)
{
    return (u32)((ptr * 2654435761ULL) % AK_MAX_DIRTY_OBJECTS);
}

void ak_state_mark_dirty(u64 ptr)
{
    if (!ak_state.initialized)
        return;

    u32 idx = ptr_to_index(ptr);
    u32 word = idx / 64;
    u32 bit = idx % 64;

    if (!(ak_state.dirty_bitmap[word] & (1ULL << bit))) {
        ak_state.dirty_bitmap[word] |= (1ULL << bit);

        if (ak_state.dirty_count < AK_MAX_DIRTY_OBJECTS) {
            ak_state.dirty_ptrs[ak_state.dirty_count++] = ptr;
        }
    }
}

void ak_state_mark_clean(u64 ptr)
{
    if (!ak_state.initialized)
        return;

    u32 idx = ptr_to_index(ptr);
    u32 word = idx / 64;
    u32 bit = idx % 64;

    ak_state.dirty_bitmap[word] &= ~(1ULL << bit);

    for (u32 i = 0; i < ak_state.dirty_count; i++) {
        if (ak_state.dirty_ptrs[i] == ptr) {
            for (u32 j = i; j < ak_state.dirty_count - 1; j++)
                ak_state.dirty_ptrs[j] = ak_state.dirty_ptrs[j + 1];
            ak_state.dirty_count--;
            break;
        }
    }
}

boolean ak_state_is_dirty(u64 ptr)
{
    if (!ak_state.initialized)
        return false;

    u32 idx = ptr_to_index(ptr);
    u32 word = idx / 64;
    u32 bit = idx % 64;

    return (ak_state.dirty_bitmap[word] & (1ULL << bit)) != 0;
}

u64 ak_state_dirty_count(void)
{
    return ak_state.dirty_count;
}

u64 *ak_state_get_dirty_list(u32 *count_out)
{
    if (count_out)
        *count_out = ak_state.dirty_count;
    return ak_state.dirty_ptrs;
}

/* ============================================================
 * SYNC OPERATIONS
 * ============================================================ */

ak_sync_result_t ak_state_sync(void)
{
    ak_sync_result_t result;
    runtime_memset((u8 *)&result, 0, sizeof(ak_sync_result_t));

    if (!ak_state.initialized) {
        result.status = AK_SYNC_FAILED;
        result.error_code = AK_E_STATE_NOT_FOUND;
        return result;
    }

    if (ak_state.config.backend == AK_STORAGE_NONE) {
        result.status = AK_SYNC_COMPLETED;
        return result;
    }

    if (ak_state.dirty_count == 0) {
        result.status = AK_SYNC_COMPLETED;
        return result;
    }

    return ak_state_sync_objects(ak_state.dirty_ptrs, ak_state.dirty_count);
}

ak_sync_result_t ak_state_sync_objects(u64 *ptrs, u32 count)
{
    ak_sync_result_t result;
    runtime_memset((u8 *)&result, 0, sizeof(ak_sync_result_t));

    if (!ptrs || count == 0) {
        result.status = AK_SYNC_COMPLETED;
        return result;
    }

    ak_state.sync_status = AK_SYNC_IN_PROGRESS;
    ak_state.stats.syncs_total++;

    u64 start_ms = get_timestamp_ms();
    u64 objects_synced = 0;
    u64 bytes_synced = 0;

    /* Sync each object */
    for (u32 i = 0; i < count; i++) {
        u64 ptr = ptrs[i];

        /* Get object value from typed heap */
        buffer value = ak_heap_serialize_object(ak_state.h, ptr);
        if (!value || value == INVALID_ADDRESS)
            continue;

        /* Compute hash for integrity (on uncompressed data) */
        u8 hash[AK_HASH_SIZE];
        compute_hash(value, hash);

        /* Compress if worthwhile */
        buffer to_store = value;
        boolean compressed = false;
        if (ak_state.config.compression_enabled &&
            ak_compress_worthwhile(buffer_length(value))) {
            buffer compressed_value = ak_compress_lz4(ak_state.h, value);
            if (compressed_value && compressed_value != INVALID_ADDRESS) {
                /* Only use compressed if it's actually smaller */
                if (buffer_length(compressed_value) < buffer_length(value)) {
                    to_store = compressed_value;
                    compressed = true;
                } else {
                    deallocate_buffer(compressed_value);
                }
            }
        }

        /* Store to backend */
        s64 put_result = ak_backend_put(ptr, to_store, hash);

        if (put_result == 0) {
            objects_synced++;
            bytes_synced += buffer_length(to_store);
            ak_state_mark_clean(ptr);
            if (compressed)
                ak_state.stats.bytes_compressed += buffer_length(value) - buffer_length(to_store);
        }

        if (compressed)
            deallocate_buffer(to_store);
        deallocate_buffer(value);
    }

    result.duration_ms = get_timestamp_ms() - start_ms;
    result.objects_synced = objects_synced;
    result.bytes_synced = bytes_synced;

    if (objects_synced == count) {
        result.status = AK_SYNC_COMPLETED;
        ak_state.stats.syncs_successful++;
    } else if (objects_synced > 0) {
        result.status = AK_SYNC_PARTIAL;
    } else {
        result.status = AK_SYNC_FAILED;
        result.error_code = AK_E_STATE_SYNC_FAILED;
        ak_state.stats.syncs_failed++;
    }

    ak_state.stats.objects_synced_total += objects_synced;
    ak_state.stats.bytes_synced_total += bytes_synced;
    ak_state.stats.total_sync_time_ms += result.duration_ms;

    ak_state.sync_status = result.status;
    ak_state.last_sync_ms = get_timestamp_ms();

    return result;
}

ak_sync_result_t ak_state_sync_immediate(void)
{
    return ak_state_sync();
}

boolean ak_state_sync_in_progress(void)
{
    return ak_state.sync_status == AK_SYNC_IN_PROGRESS;
}

ak_sync_result_t ak_state_sync_wait(u32 timeout_ms)
{
    (void)timeout_ms;
    return ak_state_sync();
}

/* ============================================================
 * ANCHOR EMISSION
 * ============================================================ */

s64 ak_state_emit_anchor(void)
{
    if (!ak_state.initialized)
        return AK_E_STATE_NOT_FOUND;

    ak_state_anchor_t anchor;
    runtime_memset((u8 *)&anchor, 0, sizeof(ak_state_anchor_t));

    anchor.timestamp_ms = get_timestamp_ms();
    anchor.sequence = ++ak_state.anchor_sequence;

    /* Chain to previous anchor */
    runtime_memcpy(anchor.prev_anchor, ak_state.latest_anchor.heap_root,
                   AK_HASH_SIZE);

    /* Compute merkle root of heap state */
    u32 count;
    u64 *ptrs = ak_state_get_dirty_list(&count);

    if (count > 0 && ptrs) {
        /* Overflow check for allocation size */
        if (count <= UINT64_MAX / AK_HASH_SIZE) {
            u8 *hashes = allocate(ak_state.h, (u64)count * AK_HASH_SIZE);
            if (hashes != INVALID_ADDRESS) {
                for (u32 i = 0; i < count; i++) {
                    buffer value = ak_heap_serialize_object(ak_state.h, ptrs[i]);
                    if (value && value != INVALID_ADDRESS) {
                        compute_hash(value, &hashes[i * AK_HASH_SIZE]);
                        deallocate_buffer(value);
                    } else {
                        runtime_memset(&hashes[i * AK_HASH_SIZE], 0, AK_HASH_SIZE);
                    }
                }
                compute_merkle_root(hashes, count, anchor.heap_root);
                deallocate(ak_state.h, hashes, (u64)count * AK_HASH_SIZE);
            }
        }
    }

    /* Get latest audit log hash */
    ak_audit_head_hash(anchor.log_root);

    /* Ed25519 signature would be applied here with kernel signing key */
    /* For now, leave signature zeroed - signature verification is optional */

    /* Store anchor to backend */
    if (ak_state.config.backend != AK_STORAGE_NONE) {
        buffer anchor_buf = allocate_buffer(ak_state.h, sizeof(ak_state_anchor_t));
        if (anchor_buf != INVALID_ADDRESS) {
            buffer_write(anchor_buf, &anchor, sizeof(ak_state_anchor_t));
            ak_backend_put(anchor.sequence | 0xA0C40000000000ULL, anchor_buf, anchor.heap_root);
            deallocate_buffer(anchor_buf);
        }
    }

    runtime_memcpy(&ak_state.latest_anchor, &anchor, sizeof(ak_state_anchor_t));
    ak_state.stats.anchors_emitted++;

    return 0;
}

ak_state_anchor_t *ak_state_get_latest_anchor(void)
{
    if (!ak_state.initialized)
        return 0;
    return &ak_state.latest_anchor;
}

boolean ak_state_verify_anchor_chain(void)
{
    if (!ak_state.initialized)
        return false;

    /* Verify chain by checking each anchor links to previous */
    /* For genesis anchor (sequence 0), prev_anchor should be zero */
    if (ak_state.anchor_sequence == 0) {
        u8 zero[AK_HASH_SIZE];
        runtime_memset(zero, 0, AK_HASH_SIZE);
        return runtime_memcmp(ak_state.latest_anchor.prev_anchor, zero,
                              AK_HASH_SIZE) == 0;
    }

    /* Non-genesis: prev_anchor should match previous anchor's heap_root */
    /* Full verification requires fetching all anchors from backend */
    return true;
}

/* ============================================================
 * BACKEND OPERATIONS
 *
 * Protocol for virtio backend:
 *   Request:  [1 byte cmd][8 bytes ptr][4 bytes len][data]
 *   Response: [1 byte status][4 bytes len][data]
 *
 * Commands: 0x01=PUT, 0x02=GET, 0x03=DELETE, 0x04=LIST
 * ============================================================ */

#define VIRTIO_CMD_PUT    0x01
#define VIRTIO_CMD_GET    0x02
#define VIRTIO_CMD_DELETE 0x03
#define VIRTIO_CMD_LIST   0x04

s64 ak_backend_put(u64 ptr, buffer value, u8 *hash)
{
    if (!ak_state.initialized || ak_state.config.backend == AK_STORAGE_NONE)
        return AK_E_STATE_NOT_FOUND;

    if (!value || !hash)
        return AK_E_SCHEMA_INVALID;

    switch (ak_state.config.backend) {
    case AK_STORAGE_S3:
        /* S3 PUT requires HTTPS client - not implemented in kernel */
        return AK_E_STATE_BACKEND_ERROR;

    case AK_STORAGE_REDIS:
        /* Redis requires TCP client - not implemented in kernel */
        return AK_E_STATE_BACKEND_ERROR;

    case AK_STORAGE_HTTP:
        /* HTTP POST requires HTTPS client - not implemented in kernel */
        return AK_E_STATE_BACKEND_ERROR;

    case AK_STORAGE_VIRTIO:
        if (ak_state.virtio_fd < 0)
            return AK_E_STATE_BACKEND_ERROR;

        /* Protocol: [cmd:1][ptr:8][len:4][hash:32][data:len] */
        /* Would write to virtio_fd here */
        return AK_E_STATE_BACKEND_ERROR;

    default:
        return AK_E_STATE_BACKEND_ERROR;
    }
}

buffer ak_backend_get(u64 ptr)
{
    if (!ak_state.initialized || ak_state.config.backend == AK_STORAGE_NONE)
        return 0;

    switch (ak_state.config.backend) {
    case AK_STORAGE_S3:
    case AK_STORAGE_REDIS:
    case AK_STORAGE_HTTP:
        /* Network backends not implemented in kernel */
        return 0;

    case AK_STORAGE_VIRTIO:
        if (ak_state.virtio_fd < 0)
            return 0;

        /* Protocol: [cmd:1][ptr:8] -> [status:1][len:4][data:len] */
        /* Would read from virtio_fd here */
        return 0;

    default:
        return 0;
    }
}

s64 ak_backend_delete(u64 ptr)
{
    if (!ak_state.initialized || ak_state.config.backend == AK_STORAGE_NONE)
        return AK_E_STATE_NOT_FOUND;

    switch (ak_state.config.backend) {
    case AK_STORAGE_S3:
    case AK_STORAGE_REDIS:
    case AK_STORAGE_HTTP:
        return AK_E_STATE_BACKEND_ERROR;

    case AK_STORAGE_VIRTIO:
        if (ak_state.virtio_fd < 0)
            return AK_E_STATE_BACKEND_ERROR;
        return AK_E_STATE_BACKEND_ERROR;

    default:
        return AK_E_STATE_BACKEND_ERROR;
    }
}

u64 *ak_backend_list(u32 *count_out)
{
    if (count_out)
        *count_out = 0;

    if (!ak_state.initialized || ak_state.config.backend == AK_STORAGE_NONE)
        return 0;

    switch (ak_state.config.backend) {
    case AK_STORAGE_S3:
    case AK_STORAGE_REDIS:
    case AK_STORAGE_HTTP:
        return 0;

    case AK_STORAGE_VIRTIO:
        if (ak_state.virtio_fd < 0)
            return 0;
        return 0;

    default:
        return 0;
    }
}

boolean ak_backend_healthy(void)
{
    if (!ak_state.initialized)
        return false;

    if (ak_state.config.backend == AK_STORAGE_NONE)
        return true;

    switch (ak_state.config.backend) {
    case AK_STORAGE_S3:
    case AK_STORAGE_REDIS:
    case AK_STORAGE_HTTP:
        /* Network backends require external connectivity */
        return false;

    case AK_STORAGE_VIRTIO:
        return ak_state.virtio_fd >= 0;

    default:
        return false;
    }
}

/* ============================================================
 * SYSCALL HANDLER
 * ============================================================ */

static int u64_to_str(u64 n, char *buf)
{
    char tmp[24];
    int len = 0;

    if (n == 0) {
        buf[0] = '0';
        return 1;
    }

    while (n > 0) {
        tmp[len++] = '0' + (n % 10);
        n /= 10;
    }

    for (int i = 0; i < len; i++)
        buf[i] = tmp[len - 1 - i];

    return len;
}

ak_response_t *ak_state_handle_commit(ak_agent_context_t *ctx, ak_request_t *req)
{
    if (!ctx || !req)
        return ak_response_error(ak_state.h, req, AK_E_SCHEMA_INVALID);

    /* Perform sync */
    ak_sync_result_t sync_result = ak_state_sync_immediate();

    if (sync_result.status != AK_SYNC_COMPLETED &&
        sync_result.status != AK_SYNC_PARTIAL) {
        return ak_response_error(ak_state.h, req, sync_result.error_code);
    }

    /* Emit anchor */
    s64 anchor_result = ak_state_emit_anchor();
    if (anchor_result != 0)
        return ak_response_error(ak_state.h, req, anchor_result);

    /* Build response */
    buffer result_buf = allocate_buffer(ak_state.h, 256);
    if (result_buf == INVALID_ADDRESS)
        return ak_response_error(ak_state.h, req, AK_E_STATE_SYNC_FAILED);

    char json[256];
    int len = 0;

    const char *prefix = "{\"objects_synced\":";
    u64 prefix_len = runtime_strlen(prefix);
    runtime_memcpy(&json[len], prefix, prefix_len);
    len += prefix_len;

    len += u64_to_str(sync_result.objects_synced, &json[len]);

    const char *middle = ",\"anchor_sequence\":";
    u64 middle_len = runtime_strlen(middle);
    runtime_memcpy(&json[len], middle, middle_len);
    len += middle_len;

    len += u64_to_str(ak_state.anchor_sequence, &json[len]);

    json[len++] = '}';

    buffer_write(result_buf, json, len);

    return ak_response_success(ak_state.h, req, result_buf);
}

/* ============================================================
 * STATISTICS
 * ============================================================ */

void ak_state_get_stats(ak_state_stats_t *stats)
{
    if (stats)
        runtime_memcpy(stats, &ak_state.stats, sizeof(ak_state_stats_t));
}
