/*
 * Authority Kernel - State Management Unit Tests
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Comprehensive tests for the state synchronization subsystem:
 * - Dirty tracking (bitmap operations)
 * - Sync operations (status transitions, statistics)
 * - Anchor emission (chain integrity, merkle roots)
 * - Hydration (boot-time loading)
 * - Backend operations (health checks, PUT/GET/DELETE)
 * - Statistics tracking
 * - Edge cases and error handling
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

/* Test assertion macros */
#define test_assert(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "FAIL: %s at %s:%d\n", #expr, __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

#define test_assert_eq(a, b) do { \
    if ((a) != (b)) { \
        fprintf(stderr, "FAIL: %s != %s (%lld != %lld) at %s:%d\n", \
                #a, #b, (long long)(a), (long long)(b), __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

#define test_assert_neq(a, b) do { \
    if ((a) == (b)) { \
        fprintf(stderr, "FAIL: %s == %s at %s:%d\n", #a, #b, __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

/* ============================================================
 * STATE TYPES (matching ak_state.h)
 * ============================================================ */

#define AK_HASH_SIZE            32
#define AK_TOKEN_ID_SIZE        16
#define AK_MAX_DIRTY_OBJECTS    65536
#define AK_DIRTY_BITMAP_SIZE    (AK_MAX_DIRTY_OBJECTS / 64)

/* Error codes */
#define AK_E_STATE_NOT_FOUND        (-4700)
#define AK_E_STATE_CORRUPT          (-4701)
#define AK_E_STATE_SYNC_FAILED      (-4702)
#define AK_E_STATE_BACKEND_ERROR    (-4703)
#define AK_E_STATE_ENCRYPTION_ERROR (-4704)
#define AK_E_STATE_TIMEOUT          (-4705)
#define AK_E_SCHEMA_INVALID         (-4002)

/* Storage backend types */
typedef enum ak_storage_backend {
    AK_STORAGE_NONE = 0,
    AK_STORAGE_S3 = 1,
    AK_STORAGE_REDIS = 2,
    AK_STORAGE_HTTP = 3,
    AK_STORAGE_VIRTIO = 4,
} ak_storage_backend_t;

/* Sync status types */
typedef enum ak_sync_status {
    AK_SYNC_IDLE = 0,
    AK_SYNC_IN_PROGRESS = 1,
    AK_SYNC_COMPLETED = 2,
    AK_SYNC_FAILED = 3,
    AK_SYNC_PARTIAL = 4,
} ak_sync_status_t;

/* Storage configuration */
typedef struct ak_storage_config {
    ak_storage_backend_t backend;
    bool encrypt_at_rest;
    bool compression_enabled;
    uint32_t sync_interval_ms;
    uint32_t sync_batch_size;
    uint32_t sync_timeout_ms;
    uint32_t max_retries;
    uint32_t retry_backoff_ms;
} ak_storage_config_t;

/* Sync result structure */
typedef struct ak_sync_result {
    ak_sync_status_t status;
    uint64_t objects_synced;
    uint64_t bytes_synced;
    uint64_t duration_ms;
    int64_t error_code;
    char error_message[256];
} ak_sync_result_t;

/* State anchor structure */
typedef struct ak_state_anchor {
    uint64_t timestamp_ms;
    uint64_t sequence;
    uint8_t heap_root[AK_HASH_SIZE];
    uint8_t log_root[AK_HASH_SIZE];
    uint8_t prev_anchor[AK_HASH_SIZE];
    uint8_t signature[64];
} ak_state_anchor_t;

/* Hydration status structure */
typedef struct ak_hydration_status {
    bool hydrated;
    uint64_t objects_loaded;
    uint64_t bytes_loaded;
    uint64_t duration_ms;
    uint64_t source_sequence;
} ak_hydration_status_t;

/* Statistics structure */
typedef struct ak_state_stats {
    uint64_t syncs_total;
    uint64_t syncs_successful;
    uint64_t syncs_failed;
    uint64_t objects_synced_total;
    uint64_t bytes_synced_total;
    uint64_t bytes_compressed;
    uint64_t anchors_emitted;
    uint64_t hydrations_total;
    uint64_t total_sync_time_ms;
} ak_state_stats_t;

/* ============================================================
 * MOCK STATE IMPLEMENTATION
 * ============================================================ */

#define MAX_STORED_OBJECTS 1000

/* Simulated stored object */
typedef struct mock_stored_object {
    uint64_t ptr;
    uint8_t *data;
    uint32_t data_len;
    uint8_t hash[AK_HASH_SIZE];
    bool valid;
} mock_stored_object_t;

static struct {
    bool initialized;
    ak_storage_config_t config;
    ak_state_stats_t stats;
    ak_hydration_status_t hydration;

    /* Dirty tracking */
    uint64_t dirty_bitmap[AK_DIRTY_BITMAP_SIZE];
    uint64_t dirty_ptrs[AK_MAX_DIRTY_OBJECTS];
    uint32_t dirty_count;

    /* Sync state */
    ak_sync_status_t sync_status;
    uint64_t last_sync_ms;

    /* Anchor chain */
    ak_state_anchor_t anchors[100];
    uint32_t anchor_count;
    ak_state_anchor_t latest_anchor;
    uint64_t anchor_sequence;

    /* Backend state */
    bool backend_connected;
    bool backend_healthy;
    int virtio_fd;

    /* Mock storage */
    mock_stored_object_t stored_objects[MAX_STORED_OBJECTS];
    uint32_t stored_count;

    /* Simulated time */
    uint64_t current_time_ms;

    /* Failure injection */
    bool inject_backend_failure;
    int failure_after_count;
    int operation_count;
} mock_state;

/* Simple FNV-1a hash for testing */
static void test_compute_hash(const uint8_t *data, uint32_t len, uint8_t *output)
{
    uint64_t h = 0xcbf29ce484222325ULL;
    for (uint32_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= 0x100000001b3ULL;
    }

    for (int i = 0; i < AK_HASH_SIZE; i++) {
        output[i] = (h >> ((i % 8) * 8)) & 0xff;
        if ((i % 8) == 7) {
            h ^= (uint64_t)i;
            h *= 0x100000001b3ULL;
        }
    }
}

/* Compute merkle root from list of hashes */
static void test_compute_merkle_root(uint8_t *hashes, uint32_t count, uint8_t *root_out)
{
    if (count == 0) {
        memset(root_out, 0, AK_HASH_SIZE);
        return;
    }

    if (count == 1) {
        memcpy(root_out, hashes, AK_HASH_SIZE);
        return;
    }

    /* Allocate working buffers */
    uint8_t *buf_a = malloc((size_t)count * AK_HASH_SIZE);
    uint8_t *buf_b = malloc((size_t)count * AK_HASH_SIZE);

    if (!buf_a || !buf_b) {
        memset(root_out, 0, AK_HASH_SIZE);
        free(buf_a);
        free(buf_b);
        return;
    }

    memcpy(buf_a, hashes, count * AK_HASH_SIZE);

    uint8_t *current = buf_a;
    uint8_t *next = buf_b;
    uint32_t current_count = count;

    while (current_count > 1) {
        uint32_t pairs = (current_count + 1) / 2;
        for (uint32_t i = 0; i < pairs; i++) {
            uint8_t combined[AK_HASH_SIZE * 2];
            memcpy(combined, &current[i * 2 * AK_HASH_SIZE], AK_HASH_SIZE);

            if (i * 2 + 1 < current_count) {
                memcpy(&combined[AK_HASH_SIZE],
                       &current[(i * 2 + 1) * AK_HASH_SIZE], AK_HASH_SIZE);
            } else {
                memcpy(&combined[AK_HASH_SIZE],
                       &current[i * 2 * AK_HASH_SIZE], AK_HASH_SIZE);
            }

            test_compute_hash(combined, AK_HASH_SIZE * 2, &next[i * AK_HASH_SIZE]);
        }
        current_count = pairs;

        uint8_t *tmp = current;
        current = next;
        next = tmp;
    }

    memcpy(root_out, current, AK_HASH_SIZE);

    free(buf_a);
    free(buf_b);
}

/* Pointer to index mapping (matches ak_state.c) */
static uint32_t ptr_to_index(uint64_t ptr)
{
    return (uint32_t)((ptr * 2654435761ULL) % AK_MAX_DIRTY_OBJECTS);
}

/* Initialize mock state */
static void mock_state_init(ak_storage_config_t *config)
{
    memset(&mock_state, 0, sizeof(mock_state));

    if (config) {
        memcpy(&mock_state.config, config, sizeof(ak_storage_config_t));
    } else {
        mock_state.config.backend = AK_STORAGE_NONE;
        mock_state.config.sync_batch_size = 100;
        mock_state.config.sync_timeout_ms = 30000;
        mock_state.config.max_retries = 3;
        mock_state.config.retry_backoff_ms = 1000;
    }

    mock_state.sync_status = AK_SYNC_IDLE;
    mock_state.virtio_fd = -1;
    mock_state.current_time_ms = 1000000;
    mock_state.initialized = true;

    /* Initialize genesis anchor */
    memset(&mock_state.latest_anchor, 0, sizeof(ak_state_anchor_t));
    mock_state.latest_anchor.timestamp_ms = mock_state.current_time_ms;
    mock_state.latest_anchor.sequence = 0;

    /* Set backend connected based on config */
    if (mock_state.config.backend != AK_STORAGE_NONE) {
        mock_state.backend_healthy = true;
        mock_state.backend_connected = true;
    }
}

/* Shutdown mock state */
static void mock_state_shutdown(void)
{
    /* Free any allocated storage */
    for (uint32_t i = 0; i < mock_state.stored_count; i++) {
        if (mock_state.stored_objects[i].data) {
            free(mock_state.stored_objects[i].data);
            mock_state.stored_objects[i].data = NULL;
        }
    }
    mock_state.initialized = false;
}

/* Mark object as dirty */
static void mock_state_mark_dirty(uint64_t ptr)
{
    if (!mock_state.initialized)
        return;

    uint32_t idx = ptr_to_index(ptr);
    uint32_t word = idx / 64;
    uint32_t bit = idx % 64;

    if (!(mock_state.dirty_bitmap[word] & (1ULL << bit))) {
        mock_state.dirty_bitmap[word] |= (1ULL << bit);

        if (mock_state.dirty_count < AK_MAX_DIRTY_OBJECTS) {
            mock_state.dirty_ptrs[mock_state.dirty_count++] = ptr;
        }
    }
}

/* Mark object as clean */
static void mock_state_mark_clean(uint64_t ptr)
{
    if (!mock_state.initialized)
        return;

    uint32_t idx = ptr_to_index(ptr);
    uint32_t word = idx / 64;
    uint32_t bit = idx % 64;

    mock_state.dirty_bitmap[word] &= ~(1ULL << bit);

    for (uint32_t i = 0; i < mock_state.dirty_count; i++) {
        if (mock_state.dirty_ptrs[i] == ptr) {
            for (uint32_t j = i; j < mock_state.dirty_count - 1; j++)
                mock_state.dirty_ptrs[j] = mock_state.dirty_ptrs[j + 1];
            mock_state.dirty_count--;
            break;
        }
    }
}

/* Check if object is dirty */
static bool mock_state_is_dirty(uint64_t ptr)
{
    if (!mock_state.initialized)
        return false;

    uint32_t idx = ptr_to_index(ptr);
    uint32_t word = idx / 64;
    uint32_t bit = idx % 64;

    return (mock_state.dirty_bitmap[word] & (1ULL << bit)) != 0;
}

/* Get dirty count */
static uint64_t mock_state_dirty_count(void)
{
    if (!mock_state.initialized)
        return 0;
    return mock_state.dirty_count;
}

/* Get dirty list */
static uint64_t *mock_state_get_dirty_list(uint32_t *count_out)
{
    if (count_out)
        *count_out = mock_state.dirty_count;
    return mock_state.dirty_ptrs;
}

/* Backend put operation */
static int64_t mock_backend_put(uint64_t ptr, const uint8_t *data, uint32_t len, uint8_t *hash)
{
    if (!mock_state.initialized || mock_state.config.backend == AK_STORAGE_NONE)
        return AK_E_STATE_NOT_FOUND;

    if (!data || !hash)
        return AK_E_SCHEMA_INVALID;

    /* Check for injected failure */
    if (mock_state.inject_backend_failure) {
        mock_state.operation_count++;
        if (mock_state.operation_count > mock_state.failure_after_count) {
            return AK_E_STATE_BACKEND_ERROR;
        }
    }

    if (!mock_state.backend_healthy)
        return AK_E_STATE_BACKEND_ERROR;

    /* Find existing or create new entry */
    int found_idx = -1;
    for (uint32_t i = 0; i < mock_state.stored_count; i++) {
        if (mock_state.stored_objects[i].ptr == ptr && mock_state.stored_objects[i].valid) {
            found_idx = (int)i;
            break;
        }
    }

    if (found_idx < 0) {
        if (mock_state.stored_count >= MAX_STORED_OBJECTS)
            return AK_E_STATE_BACKEND_ERROR;
        found_idx = (int)mock_state.stored_count++;
    } else {
        /* Free old data */
        free(mock_state.stored_objects[found_idx].data);
    }

    /* Store new data */
    mock_state.stored_objects[found_idx].ptr = ptr;
    mock_state.stored_objects[found_idx].data = malloc(len);
    if (!mock_state.stored_objects[found_idx].data)
        return AK_E_STATE_BACKEND_ERROR;

    memcpy(mock_state.stored_objects[found_idx].data, data, len);
    mock_state.stored_objects[found_idx].data_len = len;
    memcpy(mock_state.stored_objects[found_idx].hash, hash, AK_HASH_SIZE);
    mock_state.stored_objects[found_idx].valid = true;

    return 0;
}

/* Backend get operation */
static uint8_t *mock_backend_get(uint64_t ptr, uint32_t *len_out)
{
    if (!mock_state.initialized || mock_state.config.backend == AK_STORAGE_NONE)
        return NULL;

    if (!mock_state.backend_healthy)
        return NULL;

    for (uint32_t i = 0; i < mock_state.stored_count; i++) {
        if (mock_state.stored_objects[i].ptr == ptr && mock_state.stored_objects[i].valid) {
            if (len_out)
                *len_out = mock_state.stored_objects[i].data_len;
            return mock_state.stored_objects[i].data;
        }
    }

    return NULL;
}

/* Backend delete operation */
static int64_t mock_backend_delete(uint64_t ptr)
{
    if (!mock_state.initialized || mock_state.config.backend == AK_STORAGE_NONE)
        return AK_E_STATE_NOT_FOUND;

    if (!mock_state.backend_healthy)
        return AK_E_STATE_BACKEND_ERROR;

    for (uint32_t i = 0; i < mock_state.stored_count; i++) {
        if (mock_state.stored_objects[i].ptr == ptr && mock_state.stored_objects[i].valid) {
            mock_state.stored_objects[i].valid = false;
            free(mock_state.stored_objects[i].data);
            mock_state.stored_objects[i].data = NULL;
            return 0;
        }
    }

    return AK_E_STATE_NOT_FOUND;
}

/* Backend list operation */
static uint64_t *mock_backend_list(uint32_t *count_out)
{
    if (count_out)
        *count_out = 0;

    if (!mock_state.initialized || mock_state.config.backend == AK_STORAGE_NONE)
        return NULL;

    if (!mock_state.backend_healthy)
        return NULL;

    /* Count valid objects */
    uint32_t count = 0;
    for (uint32_t i = 0; i < mock_state.stored_count; i++) {
        if (mock_state.stored_objects[i].valid)
            count++;
    }

    if (count == 0)
        return NULL;

    uint64_t *ptrs = malloc(count * sizeof(uint64_t));
    if (!ptrs)
        return NULL;

    uint32_t idx = 0;
    for (uint32_t i = 0; i < mock_state.stored_count; i++) {
        if (mock_state.stored_objects[i].valid) {
            ptrs[idx++] = mock_state.stored_objects[i].ptr;
        }
    }

    if (count_out)
        *count_out = count;
    return ptrs;
}

/* Backend health check */
static bool mock_backend_healthy(void)
{
    if (!mock_state.initialized)
        return false;

    if (mock_state.config.backend == AK_STORAGE_NONE)
        return true;

    return mock_state.backend_healthy;
}

/* Sync objects */
static ak_sync_result_t mock_state_sync_objects(uint64_t *ptrs, uint32_t count)
{
    ak_sync_result_t result;
    memset(&result, 0, sizeof(ak_sync_result_t));

    if (!ptrs || count == 0) {
        result.status = AK_SYNC_COMPLETED;
        return result;
    }

    /*
     * Copy the ptrs array since mock_state_mark_clean modifies dirty_ptrs
     * by shifting elements, which would cause us to skip elements.
     */
    uint64_t *ptrs_copy = malloc((size_t)count * sizeof(uint64_t));
    if (!ptrs_copy) {
        result.status = AK_SYNC_FAILED;
        result.error_code = AK_E_STATE_SYNC_FAILED;
        return result;
    }
    memcpy(ptrs_copy, ptrs, (size_t)count * sizeof(uint64_t));

    mock_state.sync_status = AK_SYNC_IN_PROGRESS;
    mock_state.stats.syncs_total++;

    uint64_t start_ms = mock_state.current_time_ms;
    uint64_t objects_synced = 0;
    uint64_t bytes_synced = 0;

    for (uint32_t i = 0; i < count; i++) {
        uint64_t ptr = ptrs_copy[i];

        /* Create mock object data */
        uint8_t mock_data[64];
        memset(mock_data, (uint8_t)(ptr & 0xFF), sizeof(mock_data));

        uint8_t hash[AK_HASH_SIZE];
        test_compute_hash(mock_data, sizeof(mock_data), hash);

        int64_t put_result = mock_backend_put(ptr, mock_data, sizeof(mock_data), hash);

        if (put_result == 0) {
            objects_synced++;
            bytes_synced += sizeof(mock_data);
            mock_state_mark_clean(ptr);
        }
    }

    mock_state.current_time_ms += 10;  /* Simulate sync time */
    result.duration_ms = mock_state.current_time_ms - start_ms;
    result.objects_synced = objects_synced;
    result.bytes_synced = bytes_synced;

    if (objects_synced == count) {
        result.status = AK_SYNC_COMPLETED;
        mock_state.stats.syncs_successful++;
    } else if (objects_synced > 0) {
        result.status = AK_SYNC_PARTIAL;
    } else {
        result.status = AK_SYNC_FAILED;
        result.error_code = AK_E_STATE_SYNC_FAILED;
        mock_state.stats.syncs_failed++;
    }

    mock_state.stats.objects_synced_total += objects_synced;
    mock_state.stats.bytes_synced_total += bytes_synced;
    mock_state.stats.total_sync_time_ms += result.duration_ms;

    mock_state.sync_status = result.status;
    mock_state.last_sync_ms = mock_state.current_time_ms;

    free(ptrs_copy);
    return result;
}

/* Sync all dirty objects */
static ak_sync_result_t mock_state_sync(void)
{
    ak_sync_result_t result;
    memset(&result, 0, sizeof(ak_sync_result_t));

    if (!mock_state.initialized) {
        result.status = AK_SYNC_FAILED;
        result.error_code = AK_E_STATE_NOT_FOUND;
        return result;
    }

    if (mock_state.config.backend == AK_STORAGE_NONE) {
        result.status = AK_SYNC_COMPLETED;
        return result;
    }

    if (mock_state.dirty_count == 0) {
        result.status = AK_SYNC_COMPLETED;
        return result;
    }

    return mock_state_sync_objects(mock_state.dirty_ptrs, mock_state.dirty_count);
}

/* Emit state anchor */
static int64_t mock_state_emit_anchor(void)
{
    if (!mock_state.initialized)
        return AK_E_STATE_NOT_FOUND;

    ak_state_anchor_t anchor;
    memset(&anchor, 0, sizeof(ak_state_anchor_t));

    anchor.timestamp_ms = mock_state.current_time_ms;
    anchor.sequence = ++mock_state.anchor_sequence;

    /* Chain to previous anchor */
    memcpy(anchor.prev_anchor, mock_state.latest_anchor.heap_root, AK_HASH_SIZE);

    /* Compute merkle root of current dirty objects */
    uint32_t count;
    uint64_t *ptrs = mock_state_get_dirty_list(&count);

    if (count > 0 && ptrs) {
        uint8_t *hashes = malloc((size_t)count * AK_HASH_SIZE);
        if (hashes) {
            for (uint32_t i = 0; i < count; i++) {
                uint8_t mock_data[64];
                memset(mock_data, (uint8_t)(ptrs[i] & 0xFF), sizeof(mock_data));
                test_compute_hash(mock_data, sizeof(mock_data), &hashes[i * AK_HASH_SIZE]);
            }
            test_compute_merkle_root(hashes, count, anchor.heap_root);
            free(hashes);
        }
    }

    /* Store anchor */
    if (mock_state.anchor_count < 100) {
        memcpy(&mock_state.anchors[mock_state.anchor_count++], &anchor,
               sizeof(ak_state_anchor_t));
    }

    memcpy(&mock_state.latest_anchor, &anchor, sizeof(ak_state_anchor_t));
    mock_state.stats.anchors_emitted++;

    return 0;
}

/* Get latest anchor */
static ak_state_anchor_t *mock_state_get_latest_anchor(void)
{
    if (!mock_state.initialized)
        return NULL;
    return &mock_state.latest_anchor;
}

/* Verify anchor chain */
static bool mock_state_verify_anchor_chain(void)
{
    if (!mock_state.initialized)
        return false;

    /* Genesis anchor (sequence 0) should have zero prev_anchor */
    if (mock_state.anchor_sequence == 0) {
        uint8_t zero[AK_HASH_SIZE];
        memset(zero, 0, AK_HASH_SIZE);
        return memcmp(mock_state.latest_anchor.prev_anchor, zero, AK_HASH_SIZE) == 0;
    }

    /* Verify chain by checking each anchor links to previous */
    for (uint32_t i = 1; i < mock_state.anchor_count; i++) {
        if (memcmp(mock_state.anchors[i].prev_anchor,
                   mock_state.anchors[i-1].heap_root, AK_HASH_SIZE) != 0) {
            return false;
        }
    }

    return true;
}

/* Hydrate state */
static int64_t mock_state_hydrate(void)
{
    if (!mock_state.initialized)
        return AK_E_STATE_NOT_FOUND;

    if (mock_state.config.backend == AK_STORAGE_NONE)
        return AK_E_STATE_NOT_FOUND;

    mock_state.stats.hydrations_total++;
    uint64_t start_ms = mock_state.current_time_ms;

    uint32_t object_count = 0;
    uint64_t *ptrs = mock_backend_list(&object_count);

    if (!ptrs || object_count == 0) {
        mock_state.hydration.hydrated = false;
        return AK_E_STATE_NOT_FOUND;
    }

    uint64_t bytes_loaded = 0;
    uint64_t objects_loaded = 0;

    for (uint32_t i = 0; i < object_count; i++) {
        uint32_t len;
        uint8_t *data = mock_backend_get(ptrs[i], &len);
        if (data) {
            bytes_loaded += len;
            objects_loaded++;
        }
    }

    free(ptrs);

    mock_state.current_time_ms += 5;
    mock_state.hydration.hydrated = (objects_loaded > 0);
    mock_state.hydration.objects_loaded = objects_loaded;
    mock_state.hydration.bytes_loaded = bytes_loaded;
    mock_state.hydration.duration_ms = mock_state.current_time_ms - start_ms;

    return (objects_loaded > 0) ? 0 : AK_E_STATE_NOT_FOUND;
}

/* Get hydration status */
static void mock_state_get_hydration_status(ak_hydration_status_t *status)
{
    if (status)
        memcpy(status, &mock_state.hydration, sizeof(ak_hydration_status_t));
}

/* Get stats */
static void mock_state_get_stats(ak_state_stats_t *stats)
{
    if (stats)
        memcpy(stats, &mock_state.stats, sizeof(ak_state_stats_t));
}

/* Check if sync in progress */
static bool mock_state_sync_in_progress(void)
{
    return mock_state.sync_status == AK_SYNC_IN_PROGRESS;
}

/* ============================================================
 * TEST CASES: INITIALIZATION
 * ============================================================ */

bool test_state_init_default(void)
{
    mock_state_init(NULL);

    test_assert(mock_state.initialized);
    test_assert_eq(mock_state.config.backend, AK_STORAGE_NONE);
    test_assert_eq(mock_state.dirty_count, 0);
    test_assert_eq(mock_state.sync_status, AK_SYNC_IDLE);
    test_assert_eq(mock_state.anchor_sequence, 0);

    mock_state_shutdown();
    return true;
}

bool test_state_init_with_config(void)
{
    ak_storage_config_t config;
    memset(&config, 0, sizeof(config));
    config.backend = AK_STORAGE_S3;
    config.sync_batch_size = 50;
    config.sync_timeout_ms = 60000;
    config.compression_enabled = true;

    mock_state_init(&config);

    test_assert(mock_state.initialized);
    test_assert_eq(mock_state.config.backend, AK_STORAGE_S3);
    test_assert_eq(mock_state.config.sync_batch_size, 50);
    test_assert_eq(mock_state.config.sync_timeout_ms, 60000);
    test_assert(mock_state.config.compression_enabled);

    mock_state_shutdown();
    return true;
}

bool test_state_shutdown(void)
{
    mock_state_init(NULL);
    test_assert(mock_state.initialized);

    mock_state_shutdown();
    test_assert(!mock_state.initialized);

    return true;
}

/* ============================================================
 * TEST CASES: DIRTY TRACKING
 * ============================================================ */

bool test_dirty_mark_single(void)
{
    mock_state_init(NULL);

    uint64_t ptr = 0x12345678;

    test_assert(!mock_state_is_dirty(ptr));
    test_assert_eq(mock_state_dirty_count(), 0);

    mock_state_mark_dirty(ptr);

    test_assert(mock_state_is_dirty(ptr));
    test_assert_eq(mock_state_dirty_count(), 1);

    mock_state_shutdown();
    return true;
}

bool test_dirty_mark_multiple(void)
{
    mock_state_init(NULL);

    for (uint64_t i = 1; i <= 100; i++) {
        mock_state_mark_dirty(i * 1000);
    }

    test_assert_eq(mock_state_dirty_count(), 100);

    for (uint64_t i = 1; i <= 100; i++) {
        test_assert(mock_state_is_dirty(i * 1000));
    }

    mock_state_shutdown();
    return true;
}

bool test_dirty_mark_duplicate(void)
{
    mock_state_init(NULL);

    uint64_t ptr = 0xDEADBEEF;

    mock_state_mark_dirty(ptr);
    mock_state_mark_dirty(ptr);
    mock_state_mark_dirty(ptr);

    test_assert_eq(mock_state_dirty_count(), 1);
    test_assert(mock_state_is_dirty(ptr));

    mock_state_shutdown();
    return true;
}

bool test_dirty_mark_clean(void)
{
    mock_state_init(NULL);

    uint64_t ptr = 0xCAFEBABE;

    mock_state_mark_dirty(ptr);
    test_assert(mock_state_is_dirty(ptr));
    test_assert_eq(mock_state_dirty_count(), 1);

    mock_state_mark_clean(ptr);
    test_assert(!mock_state_is_dirty(ptr));
    test_assert_eq(mock_state_dirty_count(), 0);

    mock_state_shutdown();
    return true;
}

bool test_dirty_mark_clean_middle(void)
{
    mock_state_init(NULL);

    /* Mark 5 objects dirty */
    for (uint64_t i = 1; i <= 5; i++) {
        mock_state_mark_dirty(i * 100);
    }
    test_assert_eq(mock_state_dirty_count(), 5);

    /* Clean the middle one */
    mock_state_mark_clean(300);
    test_assert_eq(mock_state_dirty_count(), 4);
    test_assert(!mock_state_is_dirty(300));
    test_assert(mock_state_is_dirty(100));
    test_assert(mock_state_is_dirty(200));
    test_assert(mock_state_is_dirty(400));
    test_assert(mock_state_is_dirty(500));

    mock_state_shutdown();
    return true;
}

bool test_dirty_get_list(void)
{
    mock_state_init(NULL);

    uint64_t ptrs[] = {100, 200, 300, 400, 500};
    for (int i = 0; i < 5; i++) {
        mock_state_mark_dirty(ptrs[i]);
    }

    uint32_t count;
    uint64_t *list = mock_state_get_dirty_list(&count);

    test_assert_eq(count, 5);
    test_assert(list != NULL);

    /* Verify all expected ptrs are in list */
    for (int i = 0; i < 5; i++) {
        bool found = false;
        for (uint32_t j = 0; j < count; j++) {
            if (list[j] == ptrs[i]) {
                found = true;
                break;
            }
        }
        test_assert(found);
    }

    mock_state_shutdown();
    return true;
}

bool test_dirty_bitmap_operations(void)
{
    mock_state_init(NULL);

    /* Test bit manipulation across different words */
    uint64_t ptrs[] = {0, 64, 128, 1000, 65535};

    for (int i = 0; i < 5; i++) {
        mock_state_mark_dirty(ptrs[i]);
    }

    for (int i = 0; i < 5; i++) {
        test_assert(mock_state_is_dirty(ptrs[i]));
    }

    /* Clean alternating entries */
    mock_state_mark_clean(0);
    mock_state_mark_clean(128);
    mock_state_mark_clean(65535);

    test_assert(!mock_state_is_dirty(0));
    test_assert(mock_state_is_dirty(64));
    test_assert(!mock_state_is_dirty(128));
    test_assert(mock_state_is_dirty(1000));
    test_assert(!mock_state_is_dirty(65535));

    mock_state_shutdown();
    return true;
}

bool test_dirty_max_objects_limit(void)
{
    mock_state_init(NULL);

    /* Try to mark more than AK_MAX_DIRTY_OBJECTS as dirty */
    for (uint64_t i = 0; i < AK_MAX_DIRTY_OBJECTS + 100; i++) {
        mock_state_mark_dirty(i);
    }

    /* Should be capped at max */
    test_assert(mock_state_dirty_count() <= AK_MAX_DIRTY_OBJECTS);

    mock_state_shutdown();
    return true;
}

bool test_dirty_uninitialized(void)
{
    mock_state.initialized = false;

    mock_state_mark_dirty(12345);
    test_assert(!mock_state_is_dirty(12345));
    test_assert_eq(mock_state_dirty_count(), 0);

    return true;
}

/* ============================================================
 * TEST CASES: SYNC OPERATIONS
 * ============================================================ */

bool test_sync_idle_no_dirty(void)
{
    ak_storage_config_t config;
    memset(&config, 0, sizeof(config));
    config.backend = AK_STORAGE_S3;

    mock_state_init(&config);

    /* No dirty objects - sync should complete immediately */
    ak_sync_result_t result = mock_state_sync();

    test_assert_eq(result.status, AK_SYNC_COMPLETED);
    test_assert_eq(result.objects_synced, 0);
    test_assert_eq(result.bytes_synced, 0);

    mock_state_shutdown();
    return true;
}

bool test_sync_no_backend(void)
{
    mock_state_init(NULL);  /* STORAGE_NONE */

    mock_state_mark_dirty(12345);

    ak_sync_result_t result = mock_state_sync();

    test_assert_eq(result.status, AK_SYNC_COMPLETED);

    mock_state_shutdown();
    return true;
}

bool test_sync_single_object(void)
{
    ak_storage_config_t config;
    memset(&config, 0, sizeof(config));
    config.backend = AK_STORAGE_S3;

    mock_state_init(&config);

    mock_state_mark_dirty(0x1000);
    test_assert_eq(mock_state_dirty_count(), 1);

    ak_sync_result_t result = mock_state_sync();

    test_assert_eq(result.status, AK_SYNC_COMPLETED);
    test_assert_eq(result.objects_synced, 1);
    test_assert(result.bytes_synced > 0);
    test_assert_eq(mock_state_dirty_count(), 0);

    mock_state_shutdown();
    return true;
}

bool test_sync_multiple_objects(void)
{
    ak_storage_config_t config;
    memset(&config, 0, sizeof(config));
    config.backend = AK_STORAGE_S3;

    mock_state_init(&config);

    for (uint64_t i = 1; i <= 50; i++) {
        mock_state_mark_dirty(i * 0x100);
    }
    test_assert_eq(mock_state_dirty_count(), 50);

    ak_sync_result_t result = mock_state_sync();

    test_assert_eq(result.status, AK_SYNC_COMPLETED);
    test_assert_eq(result.objects_synced, 50);
    test_assert_eq(mock_state_dirty_count(), 0);

    mock_state_shutdown();
    return true;
}

bool test_sync_status_transitions(void)
{
    ak_storage_config_t config;
    memset(&config, 0, sizeof(config));
    config.backend = AK_STORAGE_S3;

    mock_state_init(&config);

    /* Initial status should be IDLE */
    test_assert_eq(mock_state.sync_status, AK_SYNC_IDLE);

    mock_state_mark_dirty(0x1000);

    /* After sync, status should be COMPLETED */
    ak_sync_result_t result = mock_state_sync();
    test_assert_eq(result.status, AK_SYNC_COMPLETED);
    test_assert_eq(mock_state.sync_status, AK_SYNC_COMPLETED);

    mock_state_shutdown();
    return true;
}

bool test_sync_partial_failure(void)
{
    ak_storage_config_t config;
    memset(&config, 0, sizeof(config));
    config.backend = AK_STORAGE_S3;

    mock_state_init(&config);

    /* Mark multiple objects dirty */
    for (uint64_t i = 1; i <= 10; i++) {
        mock_state_mark_dirty(i * 0x100);
    }

    /* Inject failure after 5 successful operations */
    mock_state.inject_backend_failure = true;
    mock_state.failure_after_count = 5;
    mock_state.operation_count = 0;

    ak_sync_result_t result = mock_state_sync();

    test_assert_eq(result.status, AK_SYNC_PARTIAL);
    test_assert(result.objects_synced > 0);
    test_assert(result.objects_synced < 10);

    mock_state_shutdown();
    return true;
}

bool test_sync_complete_failure(void)
{
    ak_storage_config_t config;
    memset(&config, 0, sizeof(config));
    config.backend = AK_STORAGE_S3;

    mock_state_init(&config);

    mock_state_mark_dirty(0x1000);

    /* Inject immediate failure */
    mock_state.inject_backend_failure = true;
    mock_state.failure_after_count = 0;
    mock_state.operation_count = 0;

    ak_sync_result_t result = mock_state_sync();

    test_assert_eq(result.status, AK_SYNC_FAILED);
    test_assert_eq(result.objects_synced, 0);
    test_assert_eq(result.error_code, AK_E_STATE_SYNC_FAILED);

    mock_state_shutdown();
    return true;
}

bool test_sync_statistics_update(void)
{
    ak_storage_config_t config;
    memset(&config, 0, sizeof(config));
    config.backend = AK_STORAGE_S3;

    mock_state_init(&config);

    /* Perform several syncs */
    for (uint64_t round = 0; round < 3; round++) {
        for (uint64_t i = 1; i <= 10; i++) {
            mock_state_mark_dirty(i * 0x100 + round * 0x10000);
        }
        mock_state_sync();
    }

    ak_state_stats_t stats;
    mock_state_get_stats(&stats);

    test_assert_eq(stats.syncs_total, 3);
    test_assert_eq(stats.syncs_successful, 3);
    test_assert_eq(stats.objects_synced_total, 30);
    test_assert(stats.bytes_synced_total > 0);
    test_assert(stats.total_sync_time_ms > 0);

    mock_state_shutdown();
    return true;
}

bool test_sync_in_progress_check(void)
{
    ak_storage_config_t config;
    memset(&config, 0, sizeof(config));
    config.backend = AK_STORAGE_S3;

    mock_state_init(&config);

    /* Before sync */
    test_assert(!mock_state_sync_in_progress());

    /* During sync would require threading to test properly,
     * but we can verify the flag is set correctly */
    mock_state.sync_status = AK_SYNC_IN_PROGRESS;
    test_assert(mock_state_sync_in_progress());

    mock_state.sync_status = AK_SYNC_COMPLETED;
    test_assert(!mock_state_sync_in_progress());

    mock_state_shutdown();
    return true;
}

/* ============================================================
 * TEST CASES: ANCHOR EMISSION
 * ============================================================ */

bool test_anchor_emit_genesis(void)
{
    mock_state_init(NULL);

    /* Emit first anchor */
    int64_t result = mock_state_emit_anchor();
    test_assert_eq(result, 0);

    ak_state_anchor_t *anchor = mock_state_get_latest_anchor();
    test_assert(anchor != NULL);
    test_assert_eq(anchor->sequence, 1);
    test_assert(anchor->timestamp_ms > 0);

    mock_state_shutdown();
    return true;
}

bool test_anchor_chain_sequence(void)
{
    mock_state_init(NULL);

    for (int i = 1; i <= 10; i++) {
        int64_t result = mock_state_emit_anchor();
        test_assert_eq(result, 0);

        ak_state_anchor_t *anchor = mock_state_get_latest_anchor();
        test_assert_eq(anchor->sequence, (uint64_t)i);
    }

    test_assert_eq(mock_state.anchor_count, 10);

    mock_state_shutdown();
    return true;
}

bool test_anchor_chain_linking(void)
{
    mock_state_init(NULL);

    /* Emit several anchors with dirty objects in between */
    for (uint64_t i = 0; i < 5; i++) {
        mock_state_mark_dirty(i * 0x1000);
        mock_state_emit_anchor();
    }

    /* Verify chain integrity */
    test_assert(mock_state_verify_anchor_chain());

    mock_state_shutdown();
    return true;
}

bool test_anchor_prev_anchor_link(void)
{
    mock_state_init(NULL);

    /* First anchor should have zero prev_anchor initially */
    mock_state_emit_anchor();

    /* Second anchor should link to first */
    mock_state_mark_dirty(0x1000);
    mock_state_emit_anchor();

    /* prev_anchor of second should match heap_root of first */
    test_assert(mock_state.anchor_count >= 2);
    test_assert(memcmp(mock_state.anchors[1].prev_anchor,
                       mock_state.anchors[0].heap_root, AK_HASH_SIZE) == 0);

    mock_state_shutdown();
    return true;
}

bool test_anchor_merkle_root_computation(void)
{
    mock_state_init(NULL);

    /* Mark multiple objects dirty */
    for (uint64_t i = 1; i <= 5; i++) {
        mock_state_mark_dirty(i * 0x100);
    }

    mock_state_emit_anchor();

    ak_state_anchor_t *anchor = mock_state_get_latest_anchor();

    /* Heap root should not be all zeros if we have dirty objects */
    uint8_t zero[AK_HASH_SIZE];
    memset(zero, 0, AK_HASH_SIZE);
    test_assert(memcmp(anchor->heap_root, zero, AK_HASH_SIZE) != 0);

    mock_state_shutdown();
    return true;
}

bool test_anchor_empty_heap_root(void)
{
    mock_state_init(NULL);

    /* No dirty objects */
    mock_state_emit_anchor();

    ak_state_anchor_t *anchor = mock_state_get_latest_anchor();

    /* Heap root should be zero for empty dirty list */
    uint8_t zero[AK_HASH_SIZE];
    memset(zero, 0, AK_HASH_SIZE);
    test_assert(memcmp(anchor->heap_root, zero, AK_HASH_SIZE) == 0);

    mock_state_shutdown();
    return true;
}

bool test_anchor_timestamp_ordering(void)
{
    mock_state_init(NULL);

    mock_state_emit_anchor();
    uint64_t ts1 = mock_state.latest_anchor.timestamp_ms;

    mock_state.current_time_ms += 1000;  /* Advance time */
    mock_state_emit_anchor();
    uint64_t ts2 = mock_state.latest_anchor.timestamp_ms;

    test_assert(ts2 > ts1);

    mock_state_shutdown();
    return true;
}

bool test_anchor_statistics(void)
{
    mock_state_init(NULL);

    for (int i = 0; i < 5; i++) {
        mock_state_emit_anchor();
    }

    ak_state_stats_t stats;
    mock_state_get_stats(&stats);

    test_assert_eq(stats.anchors_emitted, 5);

    mock_state_shutdown();
    return true;
}

bool test_anchor_verify_chain_tampered(void)
{
    mock_state_init(NULL);

    /* Create a valid chain */
    for (uint64_t i = 0; i < 5; i++) {
        mock_state_mark_dirty(i * 0x1000);
        mock_state_emit_anchor();
    }

    /* Tamper with middle anchor */
    mock_state.anchors[2].prev_anchor[0] ^= 0xFF;

    /* Verification should fail */
    test_assert(!mock_state_verify_anchor_chain());

    mock_state_shutdown();
    return true;
}

bool test_anchor_uninitialized(void)
{
    mock_state.initialized = false;

    int64_t result = mock_state_emit_anchor();
    test_assert_eq(result, AK_E_STATE_NOT_FOUND);

    ak_state_anchor_t *anchor = mock_state_get_latest_anchor();
    test_assert(anchor == NULL);

    test_assert(!mock_state_verify_anchor_chain());

    return true;
}

/* ============================================================
 * TEST CASES: HYDRATION
 * ============================================================ */

bool test_hydration_no_backend(void)
{
    mock_state_init(NULL);  /* STORAGE_NONE */

    int64_t result = mock_state_hydrate();
    test_assert_eq(result, AK_E_STATE_NOT_FOUND);

    ak_hydration_status_t status;
    mock_state_get_hydration_status(&status);
    test_assert(!status.hydrated);

    mock_state_shutdown();
    return true;
}

bool test_hydration_empty_store(void)
{
    ak_storage_config_t config;
    memset(&config, 0, sizeof(config));
    config.backend = AK_STORAGE_S3;

    mock_state_init(&config);

    int64_t result = mock_state_hydrate();
    test_assert_eq(result, AK_E_STATE_NOT_FOUND);

    ak_hydration_status_t status;
    mock_state_get_hydration_status(&status);
    test_assert(!status.hydrated);

    mock_state_shutdown();
    return true;
}

bool test_hydration_with_objects(void)
{
    ak_storage_config_t config;
    memset(&config, 0, sizeof(config));
    config.backend = AK_STORAGE_S3;

    mock_state_init(&config);

    /* Pre-populate backend with some objects */
    uint8_t data[64];
    uint8_t hash[AK_HASH_SIZE];

    for (uint64_t i = 1; i <= 10; i++) {
        memset(data, (uint8_t)(i & 0xFF), sizeof(data));
        test_compute_hash(data, sizeof(data), hash);
        mock_backend_put(i * 0x1000, data, sizeof(data), hash);
    }

    /* Now hydrate */
    int64_t result = mock_state_hydrate();
    test_assert_eq(result, 0);

    ak_hydration_status_t status;
    mock_state_get_hydration_status(&status);
    test_assert(status.hydrated);
    test_assert_eq(status.objects_loaded, 10);
    test_assert(status.bytes_loaded > 0);
    test_assert(status.duration_ms > 0);

    mock_state_shutdown();
    return true;
}

bool test_hydration_statistics(void)
{
    ak_storage_config_t config;
    memset(&config, 0, sizeof(config));
    config.backend = AK_STORAGE_S3;

    mock_state_init(&config);

    /* Pre-populate and hydrate multiple times */
    uint8_t data[64];
    uint8_t hash[AK_HASH_SIZE];
    memset(data, 0x42, sizeof(data));
    test_compute_hash(data, sizeof(data), hash);
    mock_backend_put(0x1000, data, sizeof(data), hash);

    mock_state_hydrate();
    mock_state_hydrate();
    mock_state_hydrate();

    ak_state_stats_t stats;
    mock_state_get_stats(&stats);
    test_assert_eq(stats.hydrations_total, 3);

    mock_state_shutdown();
    return true;
}

bool test_hydration_uninitialized(void)
{
    mock_state.initialized = false;

    int64_t result = mock_state_hydrate();
    test_assert_eq(result, AK_E_STATE_NOT_FOUND);

    return true;
}

/* ============================================================
 * TEST CASES: BACKEND OPERATIONS
 * ============================================================ */

bool test_backend_put_get(void)
{
    ak_storage_config_t config;
    memset(&config, 0, sizeof(config));
    config.backend = AK_STORAGE_S3;

    mock_state_init(&config);

    uint8_t data[] = "Hello, Authority!";
    uint8_t hash[AK_HASH_SIZE];
    test_compute_hash(data, sizeof(data), hash);

    int64_t put_result = mock_backend_put(0x1234, data, sizeof(data), hash);
    test_assert_eq(put_result, 0);

    uint32_t len;
    uint8_t *retrieved = mock_backend_get(0x1234, &len);
    test_assert(retrieved != NULL);
    test_assert_eq(len, sizeof(data));
    test_assert(memcmp(retrieved, data, len) == 0);

    mock_state_shutdown();
    return true;
}

bool test_backend_put_overwrite(void)
{
    ak_storage_config_t config;
    memset(&config, 0, sizeof(config));
    config.backend = AK_STORAGE_S3;

    mock_state_init(&config);

    uint8_t data1[] = "First value";
    uint8_t data2[] = "Second value";
    uint8_t hash[AK_HASH_SIZE];

    test_compute_hash(data1, sizeof(data1), hash);
    mock_backend_put(0x1000, data1, sizeof(data1), hash);

    test_compute_hash(data2, sizeof(data2), hash);
    mock_backend_put(0x1000, data2, sizeof(data2), hash);

    uint32_t len;
    uint8_t *retrieved = mock_backend_get(0x1000, &len);
    test_assert(retrieved != NULL);
    test_assert_eq(len, sizeof(data2));
    test_assert(memcmp(retrieved, data2, len) == 0);

    mock_state_shutdown();
    return true;
}

bool test_backend_delete(void)
{
    ak_storage_config_t config;
    memset(&config, 0, sizeof(config));
    config.backend = AK_STORAGE_S3;

    mock_state_init(&config);

    uint8_t data[] = "To be deleted";
    uint8_t hash[AK_HASH_SIZE];
    test_compute_hash(data, sizeof(data), hash);

    mock_backend_put(0x5000, data, sizeof(data), hash);

    /* Verify it exists */
    test_assert(mock_backend_get(0x5000, NULL) != NULL);

    /* Delete it */
    int64_t result = mock_backend_delete(0x5000);
    test_assert_eq(result, 0);

    /* Verify it's gone */
    test_assert(mock_backend_get(0x5000, NULL) == NULL);

    mock_state_shutdown();
    return true;
}

bool test_backend_delete_nonexistent(void)
{
    ak_storage_config_t config;
    memset(&config, 0, sizeof(config));
    config.backend = AK_STORAGE_S3;

    mock_state_init(&config);

    int64_t result = mock_backend_delete(0x9999);
    test_assert_eq(result, AK_E_STATE_NOT_FOUND);

    mock_state_shutdown();
    return true;
}

bool test_backend_list(void)
{
    ak_storage_config_t config;
    memset(&config, 0, sizeof(config));
    config.backend = AK_STORAGE_S3;

    mock_state_init(&config);

    uint8_t data[32];
    uint8_t hash[AK_HASH_SIZE];

    uint64_t expected_ptrs[] = {0x1000, 0x2000, 0x3000, 0x4000, 0x5000};
    for (int i = 0; i < 5; i++) {
        memset(data, (uint8_t)i, sizeof(data));
        test_compute_hash(data, sizeof(data), hash);
        mock_backend_put(expected_ptrs[i], data, sizeof(data), hash);
    }

    uint32_t count;
    uint64_t *ptrs = mock_backend_list(&count);

    test_assert(ptrs != NULL);
    test_assert_eq(count, 5);

    for (int i = 0; i < 5; i++) {
        bool found = false;
        for (uint32_t j = 0; j < count; j++) {
            if (ptrs[j] == expected_ptrs[i]) {
                found = true;
                break;
            }
        }
        test_assert(found);
    }

    free(ptrs);
    mock_state_shutdown();
    return true;
}

bool test_backend_health_no_backend(void)
{
    mock_state_init(NULL);  /* STORAGE_NONE */

    /* No backend should be considered healthy */
    test_assert(mock_backend_healthy());

    mock_state_shutdown();
    return true;
}

bool test_backend_health_connected(void)
{
    ak_storage_config_t config;
    memset(&config, 0, sizeof(config));
    config.backend = AK_STORAGE_S3;

    mock_state_init(&config);

    test_assert(mock_backend_healthy());

    mock_state_shutdown();
    return true;
}

bool test_backend_health_disconnected(void)
{
    ak_storage_config_t config;
    memset(&config, 0, sizeof(config));
    config.backend = AK_STORAGE_S3;

    mock_state_init(&config);
    mock_state.backend_healthy = false;

    test_assert(!mock_backend_healthy());

    mock_state_shutdown();
    return true;
}

bool test_backend_operations_unhealthy(void)
{
    ak_storage_config_t config;
    memset(&config, 0, sizeof(config));
    config.backend = AK_STORAGE_S3;

    mock_state_init(&config);
    mock_state.backend_healthy = false;

    uint8_t data[] = "test";
    uint8_t hash[AK_HASH_SIZE];
    test_compute_hash(data, sizeof(data), hash);

    /* All operations should fail when backend is unhealthy */
    test_assert_eq(mock_backend_put(0x1000, data, sizeof(data), hash),
                   AK_E_STATE_BACKEND_ERROR);
    test_assert(mock_backend_get(0x1000, NULL) == NULL);
    test_assert_eq(mock_backend_delete(0x1000), AK_E_STATE_BACKEND_ERROR);
    test_assert(mock_backend_list(NULL) == NULL);

    mock_state_shutdown();
    return true;
}

bool test_backend_different_types(void)
{
    ak_storage_backend_t backends[] = {
        AK_STORAGE_S3,
        AK_STORAGE_REDIS,
        AK_STORAGE_HTTP,
        AK_STORAGE_VIRTIO
    };

    for (int i = 0; i < 4; i++) {
        ak_storage_config_t config;
        memset(&config, 0, sizeof(config));
        config.backend = backends[i];

        mock_state_init(&config);
        test_assert_eq(mock_state.config.backend, backends[i]);
        mock_state_shutdown();
    }

    return true;
}

/* ============================================================
 * TEST CASES: EDGE CASES
 * ============================================================ */

bool test_overflow_protection_dirty_count(void)
{
    mock_state_init(NULL);

    /* Attempt to overflow dirty count */
    for (uint64_t i = 0; i < AK_MAX_DIRTY_OBJECTS * 2; i++) {
        mock_state_mark_dirty(i);
    }

    /* Should not exceed max */
    test_assert(mock_state.dirty_count <= AK_MAX_DIRTY_OBJECTS);

    mock_state_shutdown();
    return true;
}

bool test_empty_state_sync(void)
{
    ak_storage_config_t config;
    memset(&config, 0, sizeof(config));
    config.backend = AK_STORAGE_S3;

    mock_state_init(&config);

    /* Sync with nothing dirty */
    ak_sync_result_t result = mock_state_sync();
    test_assert_eq(result.status, AK_SYNC_COMPLETED);
    test_assert_eq(result.objects_synced, 0);

    mock_state_shutdown();
    return true;
}

bool test_empty_state_hydration(void)
{
    ak_storage_config_t config;
    memset(&config, 0, sizeof(config));
    config.backend = AK_STORAGE_S3;

    mock_state_init(&config);

    /* Nothing in backend */
    int64_t result = mock_state_hydrate();
    test_assert_eq(result, AK_E_STATE_NOT_FOUND);

    ak_hydration_status_t status;
    mock_state_get_hydration_status(&status);
    test_assert(!status.hydrated);
    test_assert_eq(status.objects_loaded, 0);

    mock_state_shutdown();
    return true;
}

bool test_hash_collision_resilience(void)
{
    mock_state_init(NULL);

    /* Mark objects that might collide in the bitmap */
    uint64_t ptrs[] = {0, AK_MAX_DIRTY_OBJECTS, AK_MAX_DIRTY_OBJECTS * 2};

    for (int i = 0; i < 3; i++) {
        mock_state_mark_dirty(ptrs[i]);
    }

    /* All should be marked dirty */
    for (int i = 0; i < 3; i++) {
        test_assert(mock_state_is_dirty(ptrs[i]));
    }

    mock_state_shutdown();
    return true;
}

bool test_zero_pointer_handling(void)
{
    mock_state_init(NULL);

    /* Zero should be a valid pointer value */
    mock_state_mark_dirty(0);
    test_assert(mock_state_is_dirty(0));
    test_assert_eq(mock_state_dirty_count(), 1);

    mock_state_mark_clean(0);
    test_assert(!mock_state_is_dirty(0));

    mock_state_shutdown();
    return true;
}

bool test_max_pointer_value(void)
{
    mock_state_init(NULL);

    uint64_t max_ptr = UINT64_MAX;
    mock_state_mark_dirty(max_ptr);
    test_assert(mock_state_is_dirty(max_ptr));

    mock_state_mark_clean(max_ptr);
    test_assert(!mock_state_is_dirty(max_ptr));

    mock_state_shutdown();
    return true;
}

bool test_repeated_operations(void)
{
    ak_storage_config_t config;
    memset(&config, 0, sizeof(config));
    config.backend = AK_STORAGE_S3;

    mock_state_init(&config);

    /* Repeat mark/sync cycles */
    for (int cycle = 0; cycle < 10; cycle++) {
        for (uint64_t i = 1; i <= 10; i++) {
            mock_state_mark_dirty(i * 0x100);
        }

        ak_sync_result_t result = mock_state_sync();
        test_assert_eq(result.status, AK_SYNC_COMPLETED);
        test_assert_eq(mock_state_dirty_count(), 0);
    }

    ak_state_stats_t stats;
    mock_state_get_stats(&stats);
    test_assert_eq(stats.syncs_total, 10);
    test_assert_eq(stats.syncs_successful, 10);

    mock_state_shutdown();
    return true;
}

bool test_merkle_root_single_object(void)
{
    uint8_t hash[AK_HASH_SIZE];
    memset(hash, 0x42, AK_HASH_SIZE);

    uint8_t root[AK_HASH_SIZE];
    test_compute_merkle_root(hash, 1, root);

    /* Single object merkle root should equal its hash */
    test_assert(memcmp(root, hash, AK_HASH_SIZE) == 0);

    return true;
}

bool test_merkle_root_empty(void)
{
    uint8_t root[AK_HASH_SIZE];
    test_compute_merkle_root(NULL, 0, root);

    /* Empty merkle root should be all zeros */
    uint8_t zero[AK_HASH_SIZE];
    memset(zero, 0, AK_HASH_SIZE);
    test_assert(memcmp(root, zero, AK_HASH_SIZE) == 0);

    return true;
}

bool test_merkle_root_deterministic(void)
{
    uint8_t hashes[3 * AK_HASH_SIZE];
    memset(&hashes[0 * AK_HASH_SIZE], 0x11, AK_HASH_SIZE);
    memset(&hashes[1 * AK_HASH_SIZE], 0x22, AK_HASH_SIZE);
    memset(&hashes[2 * AK_HASH_SIZE], 0x33, AK_HASH_SIZE);

    uint8_t root1[AK_HASH_SIZE];
    uint8_t root2[AK_HASH_SIZE];

    test_compute_merkle_root(hashes, 3, root1);
    test_compute_merkle_root(hashes, 3, root2);

    /* Same input should produce same output */
    test_assert(memcmp(root1, root2, AK_HASH_SIZE) == 0);

    return true;
}

/* ============================================================
 * TEST CASES: STATISTICS
 * ============================================================ */

bool test_statistics_initial(void)
{
    mock_state_init(NULL);

    ak_state_stats_t stats;
    mock_state_get_stats(&stats);

    test_assert_eq(stats.syncs_total, 0);
    test_assert_eq(stats.syncs_successful, 0);
    test_assert_eq(stats.syncs_failed, 0);
    test_assert_eq(stats.objects_synced_total, 0);
    test_assert_eq(stats.bytes_synced_total, 0);
    test_assert_eq(stats.anchors_emitted, 0);
    test_assert_eq(stats.hydrations_total, 0);

    mock_state_shutdown();
    return true;
}

bool test_statistics_accumulation(void)
{
    ak_storage_config_t config;
    memset(&config, 0, sizeof(config));
    config.backend = AK_STORAGE_S3;

    mock_state_init(&config);

    /* Perform various operations */
    for (uint64_t i = 0; i < 5; i++) {
        mock_state_mark_dirty(i * 0x1000);
    }
    mock_state_sync();
    mock_state_emit_anchor();

    for (uint64_t i = 0; i < 3; i++) {
        mock_state_mark_dirty(i * 0x2000);
    }
    mock_state_sync();
    mock_state_emit_anchor();

    ak_state_stats_t stats;
    mock_state_get_stats(&stats);

    test_assert_eq(stats.syncs_total, 2);
    test_assert_eq(stats.objects_synced_total, 8);
    test_assert_eq(stats.anchors_emitted, 2);

    mock_state_shutdown();
    return true;
}

bool test_statistics_failed_sync_count(void)
{
    ak_storage_config_t config;
    memset(&config, 0, sizeof(config));
    config.backend = AK_STORAGE_S3;

    mock_state_init(&config);

    mock_state_mark_dirty(0x1000);

    /* Force failure */
    mock_state.inject_backend_failure = true;
    mock_state.failure_after_count = 0;
    mock_state.operation_count = 0;

    mock_state_sync();

    ak_state_stats_t stats;
    mock_state_get_stats(&stats);

    test_assert_eq(stats.syncs_total, 1);
    test_assert_eq(stats.syncs_failed, 1);
    test_assert_eq(stats.syncs_successful, 0);

    mock_state_shutdown();
    return true;
}

/* ============================================================
 * TEST RUNNER
 * ============================================================ */

typedef bool (*test_func)(void);

typedef struct {
    const char *name;
    test_func func;
} test_case;

test_case tests[] = {
    /* Initialization */
    {"state_init_default", test_state_init_default},
    {"state_init_with_config", test_state_init_with_config},
    {"state_shutdown", test_state_shutdown},

    /* Dirty tracking */
    {"dirty_mark_single", test_dirty_mark_single},
    {"dirty_mark_multiple", test_dirty_mark_multiple},
    {"dirty_mark_duplicate", test_dirty_mark_duplicate},
    {"dirty_mark_clean", test_dirty_mark_clean},
    {"dirty_mark_clean_middle", test_dirty_mark_clean_middle},
    {"dirty_get_list", test_dirty_get_list},
    {"dirty_bitmap_operations", test_dirty_bitmap_operations},
    {"dirty_max_objects_limit", test_dirty_max_objects_limit},
    {"dirty_uninitialized", test_dirty_uninitialized},

    /* Sync operations */
    {"sync_idle_no_dirty", test_sync_idle_no_dirty},
    {"sync_no_backend", test_sync_no_backend},
    {"sync_single_object", test_sync_single_object},
    {"sync_multiple_objects", test_sync_multiple_objects},
    {"sync_status_transitions", test_sync_status_transitions},
    {"sync_partial_failure", test_sync_partial_failure},
    {"sync_complete_failure", test_sync_complete_failure},
    {"sync_statistics_update", test_sync_statistics_update},
    {"sync_in_progress_check", test_sync_in_progress_check},

    /* Anchor emission */
    {"anchor_emit_genesis", test_anchor_emit_genesis},
    {"anchor_chain_sequence", test_anchor_chain_sequence},
    {"anchor_chain_linking", test_anchor_chain_linking},
    {"anchor_prev_anchor_link", test_anchor_prev_anchor_link},
    {"anchor_merkle_root_computation", test_anchor_merkle_root_computation},
    {"anchor_empty_heap_root", test_anchor_empty_heap_root},
    {"anchor_timestamp_ordering", test_anchor_timestamp_ordering},
    {"anchor_statistics", test_anchor_statistics},
    {"anchor_verify_chain_tampered", test_anchor_verify_chain_tampered},
    {"anchor_uninitialized", test_anchor_uninitialized},

    /* Hydration */
    {"hydration_no_backend", test_hydration_no_backend},
    {"hydration_empty_store", test_hydration_empty_store},
    {"hydration_with_objects", test_hydration_with_objects},
    {"hydration_statistics", test_hydration_statistics},
    {"hydration_uninitialized", test_hydration_uninitialized},

    /* Backend operations */
    {"backend_put_get", test_backend_put_get},
    {"backend_put_overwrite", test_backend_put_overwrite},
    {"backend_delete", test_backend_delete},
    {"backend_delete_nonexistent", test_backend_delete_nonexistent},
    {"backend_list", test_backend_list},
    {"backend_health_no_backend", test_backend_health_no_backend},
    {"backend_health_connected", test_backend_health_connected},
    {"backend_health_disconnected", test_backend_health_disconnected},
    {"backend_operations_unhealthy", test_backend_operations_unhealthy},
    {"backend_different_types", test_backend_different_types},

    /* Edge cases */
    {"overflow_protection_dirty_count", test_overflow_protection_dirty_count},
    {"empty_state_sync", test_empty_state_sync},
    {"empty_state_hydration", test_empty_state_hydration},
    {"hash_collision_resilience", test_hash_collision_resilience},
    {"zero_pointer_handling", test_zero_pointer_handling},
    {"max_pointer_value", test_max_pointer_value},
    {"repeated_operations", test_repeated_operations},
    {"merkle_root_single_object", test_merkle_root_single_object},
    {"merkle_root_empty", test_merkle_root_empty},
    {"merkle_root_deterministic", test_merkle_root_deterministic},

    /* Statistics */
    {"statistics_initial", test_statistics_initial},
    {"statistics_accumulation", test_statistics_accumulation},
    {"statistics_failed_sync_count", test_statistics_failed_sync_count},

    {NULL, NULL}
};

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    int passed = 0;
    int failed = 0;

    printf("=== AK State Management Tests ===\n\n");

    for (int i = 0; tests[i].name != NULL; i++) {
        printf("Running %s... ", tests[i].name);
        fflush(stdout);

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
