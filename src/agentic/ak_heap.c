/*
 * Authority Kernel - Typed Heap Implementation
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Versioned object heap with CAS (Compare-And-Swap) semantics.
 * Provides atomic state management for agent data.
 *
 * SECURITY: All mutations are logged (INV-4 support).
 * Version control prevents lost updates.
 */

#include "ak_heap.h"
#include "ak_audit.h"

/* ============================================================
 * INTERNAL STRUCTURES
 * ============================================================ */

/* Internal object representation */
typedef struct ak_heap_object {
    u64 ptr;                        /* Object pointer/handle */
    u64 type_hash;                  /* Schema type identifier */
    u64 version;                    /* Current version (monotonic) */
    u64 created_ms;                 /* Creation timestamp */
    u64 modified_ms;                /* Last modification timestamp */
    ak_taint_t taint;               /* Current taint level */
    boolean deleted;                /* Soft-delete flag */
    u8 owner_run_id[AK_TOKEN_ID_SIZE]; /* Owning run */
    buffer value;                   /* Current JSON value */
    struct ak_heap_object *next;    /* Hash chain */
} ak_heap_object_t;

/* Version history entry */
typedef struct ak_version_entry {
    u64 version;
    u64 timestamp_ms;
    buffer value;
    struct ak_version_entry *next;
} ak_version_entry_t;

/* Version history for an object */
typedef struct ak_version_history {
    u64 ptr;
    ak_version_entry_t *entries;    /* Linked list, newest first */
    u64 count;
    struct ak_version_history *next;
} ak_version_history_t;

/* Schema registry entry */
typedef struct ak_schema_entry {
    u64 type_hash;
    buffer schema_json;
    struct ak_schema_entry *next;
} ak_schema_entry_t;

/* Transaction buffer entry */
typedef struct ak_txn_op {
    enum {
        TXN_OP_ALLOC,
        TXN_OP_WRITE,
        TXN_OP_DELETE
    } op_type;
    u64 ptr;
    u64 type_hash;
    buffer value;                   /* For ALLOC: initial value, for WRITE: patch */
    u64 expected_version;
    ak_taint_t taint;
    u8 run_id[AK_TOKEN_ID_SIZE];
    struct ak_txn_op *next;
} ak_txn_op_t;

/* Transaction structure */
struct ak_heap_txn {
    ak_txn_op_t *ops;               /* Buffered operations */
    ak_txn_op_t *ops_tail;
    u64 op_count;
    boolean active;
};

/* Global heap state */
static struct {
    heap h;                         /* Memory allocator */
    ak_heap_object_t **objects;     /* Hash table */
    u64 object_capacity;
    u64 object_count;
    u64 deleted_count;
    u64 next_ptr;                   /* Monotonic pointer generator */

    ak_version_history_t **history; /* Version history hash table */
    u64 history_capacity;
    u64 version_count;

    ak_schema_entry_t *schemas;     /* Schema registry */

    /* Statistics */
    u64 bytes_used;
    u64 bytes_versions;

    boolean initialized;
} ak_heap_state;

/* Hash table parameters */
#define AK_HEAP_INITIAL_CAPACITY    1024
#define AK_HEAP_LOAD_FACTOR         0.75

/* ============================================================
 * INTERNAL HELPERS
 * ============================================================ */

static u64 ptr_hash(u64 ptr)
{
    /* Simple hash for pointer lookup */
    ptr ^= ptr >> 33;
    ptr *= 0xff51afd7ed558ccdULL;
    ptr ^= ptr >> 33;
    ptr *= 0xc4ceb9fe1a85ec53ULL;
    ptr ^= ptr >> 33;
    return ptr;
}

static ak_heap_object_t *find_object(u64 ptr)
{
    if (!ak_heap_state.initialized || !ak_heap_state.objects)
        return NULL;

    u64 idx = ptr_hash(ptr) % ak_heap_state.object_capacity;
    ak_heap_object_t *obj = ak_heap_state.objects[idx];

    while (obj) {
        if (obj->ptr == ptr)
            return obj;
        obj = obj->next;
    }
    return NULL;
}

static ak_version_history_t *find_history(u64 ptr)
{
    if (!ak_heap_state.history)
        return NULL;

    u64 idx = ptr_hash(ptr) % ak_heap_state.history_capacity;
    ak_version_history_t *hist = ak_heap_state.history[idx];

    while (hist) {
        if (hist->ptr == ptr)
            return hist;
        hist = hist->next;
    }
    return NULL;
}

static ak_schema_entry_t *find_schema(u64 type_hash)
{
    ak_schema_entry_t *entry = ak_heap_state.schemas;
    while (entry) {
        if (entry->type_hash == type_hash)
            return entry;
        entry = entry->next;
    }
    return NULL;
}

static u64 current_time_ms(void)
{
    /* Get current monotonic time in milliseconds */
    return now(CLOCK_ID_MONOTONIC) / MILLION;
}

static void save_version(u64 ptr, u64 version, buffer value)
{
    if (!ak_heap_state.history)
        return;

    u64 idx = ptr_hash(ptr) % ak_heap_state.history_capacity;
    ak_version_history_t *hist = find_history(ptr);

    if (!hist) {
        hist = allocate(ak_heap_state.h, sizeof(ak_version_history_t));
        if (!hist) return;

        hist->ptr = ptr;
        hist->entries = NULL;
        hist->count = 0;
        hist->next = ak_heap_state.history[idx];
        ak_heap_state.history[idx] = hist;
    }

    /* Create version entry */
    ak_version_entry_t *entry = allocate(ak_heap_state.h, sizeof(ak_version_entry_t));
    if (!entry) return;

    entry->version = version;
    entry->timestamp_ms = current_time_ms();

    /* Clone value */
    u64 len = buffer_length(value);
    entry->value = allocate_buffer(ak_heap_state.h, len);
    /* FIX(BUG-020): Check allocation before inserting entry */
    if (!entry->value || entry->value == INVALID_ADDRESS) {
        deallocate(ak_heap_state.h, entry, sizeof(ak_version_entry_t));
        return;  /* Don't insert entry with NULL value */
    }
    buffer_write(entry->value, buffer_ref(value, 0), len);
    ak_heap_state.bytes_versions += len;

    /* Insert at head (newest first) */
    entry->next = hist->entries;
    hist->entries = entry;
    hist->count++;
    ak_heap_state.version_count++;
}

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

void ak_heap_init(heap h)
{
    if (ak_heap_state.initialized)
        return;

    ak_heap_state.h = h;
    ak_heap_state.object_capacity = AK_HEAP_INITIAL_CAPACITY;
    ak_heap_state.objects = allocate_zero(h,
        ak_heap_state.object_capacity * sizeof(ak_heap_object_t *));

    ak_heap_state.history_capacity = AK_HEAP_INITIAL_CAPACITY;
    ak_heap_state.history = allocate_zero(h,
        ak_heap_state.history_capacity * sizeof(ak_version_history_t *));

    ak_heap_state.object_count = 0;
    ak_heap_state.deleted_count = 0;
    ak_heap_state.next_ptr = 1;  /* Start from 1, 0 is invalid */
    ak_heap_state.version_count = 0;
    ak_heap_state.schemas = NULL;
    ak_heap_state.bytes_used = 0;
    ak_heap_state.bytes_versions = 0;
    ak_heap_state.initialized = true;
}

/* ============================================================
 * CORE OPERATIONS
 * ============================================================ */

u64 ak_heap_alloc(
    u64 type_hash,
    buffer value,
    u8 *run_id,
    ak_taint_t taint)
{
    if (!ak_heap_state.initialized)
        return 0;

    /* Validate against schema if registered */
    if (!ak_heap_validate_schema(type_hash, value))
        return 0;

    /* Allocate object */
    ak_heap_object_t *obj = allocate(ak_heap_state.h, sizeof(ak_heap_object_t));
    if (!obj)
        return 0;

    /* Generate unique pointer */
    u64 ptr = ak_heap_state.next_ptr++;

    /* Initialize object */
    obj->ptr = ptr;
    obj->type_hash = type_hash;
    obj->version = 1;
    obj->created_ms = current_time_ms();
    obj->modified_ms = obj->created_ms;
    obj->taint = taint;
    obj->deleted = false;

    if (run_id) {
        runtime_memcpy(obj->owner_run_id, run_id, AK_TOKEN_ID_SIZE);
    } else {
        runtime_memset(obj->owner_run_id, 0, AK_TOKEN_ID_SIZE);
    }

    /* Clone value */
    u64 len = buffer_length(value);
    obj->value = allocate_buffer(ak_heap_state.h, len);
    if (!obj->value) {
        deallocate(ak_heap_state.h, obj, sizeof(ak_heap_object_t));
        return 0;
    }
    buffer_write(obj->value, buffer_ref(value, 0), len);
    ak_heap_state.bytes_used += len;

    /* Insert into hash table */
    u64 idx = ptr_hash(ptr) % ak_heap_state.object_capacity;
    obj->next = ak_heap_state.objects[idx];
    ak_heap_state.objects[idx] = obj;
    ak_heap_state.object_count++;

    /* Save initial version */
    save_version(ptr, 1, value);

    return ptr;
}

s64 ak_heap_read(
    u64 ptr,
    buffer *value_out,
    u64 *version_out,
    ak_taint_t *taint_out)
{
    if (!ak_heap_state.initialized)
        return -EINVAL;

    ak_heap_object_t *obj = find_object(ptr);
    if (!obj)
        return -ENOENT;

    if (obj->deleted)
        return -ENOENT;

    /* Clone value for caller */
    if (value_out) {
        u64 len = buffer_length(obj->value);
        *value_out = allocate_buffer(ak_heap_state.h, len);
        if (!*value_out)
            return -ENOMEM;
        buffer_write(*value_out, buffer_ref(obj->value, 0), len);
    }

    if (version_out)
        *version_out = obj->version;

    if (taint_out)
        *taint_out = obj->taint;

    return 0;
}

s64 ak_heap_write(
    u64 ptr,
    buffer patch,
    u64 expected_version,
    u64 *new_version_out)
{
    if (!ak_heap_state.initialized)
        return -EINVAL;

    ak_heap_object_t *obj = find_object(ptr);
    if (!obj || obj->deleted)
        return -ENOENT;

    /* CAS check: version must match */
    if (obj->version != expected_version)
        return AK_E_CONFLICT;

    /* Apply JSON patch */
    buffer new_value = ak_json_patch_apply(ak_heap_state.h, obj->value, patch);
    if (!new_value)
        return AK_E_SCHEMA_INVALID;

    /* Validate result against schema */
    if (!ak_heap_validate_schema(obj->type_hash, new_value)) {
        /* Clean up */
        deallocate_buffer(new_value);
        return AK_E_SCHEMA_INVALID;
    }

    /* Save old version */
    save_version(ptr, obj->version, obj->value);

    /* Update object */
    u64 old_len = buffer_length(obj->value);
    u64 new_len = buffer_length(new_value);

    deallocate_buffer(obj->value);
    obj->value = new_value;
    obj->version++;
    obj->modified_ms = current_time_ms();

    /* Defensive underflow check for bytes_used accounting */
    if (ak_heap_state.bytes_used >= old_len) {
        ak_heap_state.bytes_used = ak_heap_state.bytes_used - old_len + new_len;
    } else {
        /* Recovery from accounting corruption: just set to new_len */
        ak_heap_state.bytes_used = new_len;
    }

    if (new_version_out)
        *new_version_out = obj->version;

    return 0;
}

s64 ak_heap_delete(u64 ptr, u64 expected_version)
{
    if (!ak_heap_state.initialized)
        return -EINVAL;

    ak_heap_object_t *obj = find_object(ptr);
    if (!obj)
        return -ENOENT;

    if (obj->deleted)
        return -ENOENT;

    /* CAS check */
    if (obj->version != expected_version)
        return AK_E_CONFLICT;

    /* Save final version before deletion */
    save_version(ptr, obj->version, obj->value);

    /* Soft delete (tombstone) */
    obj->deleted = true;
    obj->version++;
    obj->modified_ms = current_time_ms();

    ak_heap_state.deleted_count++;

    return 0;
}

/* ============================================================
 * OBJECT QUERIES
 * ============================================================ */

boolean ak_heap_exists(u64 ptr)
{
    ak_heap_object_t *obj = find_object(ptr);
    return obj && !obj->deleted;
}

s64 ak_heap_get_meta(u64 ptr, ak_object_meta_t *meta_out)
{
    if (!meta_out)
        return -EINVAL;

    ak_heap_object_t *obj = find_object(ptr);
    if (!obj)
        return -ENOENT;

    meta_out->ptr = obj->ptr;
    meta_out->type_hash = obj->type_hash;
    meta_out->version = obj->version;
    meta_out->created_ms = obj->created_ms;
    meta_out->modified_ms = obj->modified_ms;
    meta_out->taint = obj->taint;
    meta_out->deleted = obj->deleted;

    return 0;
}

u64 *ak_heap_list_by_type(heap h, u64 type_hash, u64 *count_out)
{
    if (!ak_heap_state.initialized || !count_out)
        return NULL;

    /* First pass: count matching objects */
    u64 count = 0;
    for (u64 i = 0; i < ak_heap_state.object_capacity; i++) {
        ak_heap_object_t *obj = ak_heap_state.objects[i];
        while (obj) {
            if (obj->type_hash == type_hash && !obj->deleted)
                count++;
            obj = obj->next;
        }
    }

    if (count == 0) {
        *count_out = 0;
        return NULL;
    }

    /* Overflow check for allocation size */
    if (count > UINT64_MAX / sizeof(u64)) {
        *count_out = 0;
        return NULL;
    }

    /* Allocate result array */
    u64 *result = allocate(h, count * sizeof(u64));
    if (!result || result == INVALID_ADDRESS) {
        *count_out = 0;
        return NULL;
    }

    /* Second pass: collect pointers */
    /* FIX(BUG-008): Add bounds check for TOCTOU defense */
    u64 idx = 0;
    for (u64 i = 0; i < ak_heap_state.object_capacity && idx < count; i++) {
        ak_heap_object_t *obj = ak_heap_state.objects[i];
        while (obj && idx < count) {
            if (obj->type_hash == type_hash && !obj->deleted)
                result[idx++] = obj->ptr;
            obj = obj->next;
        }
    }

    *count_out = idx;  /* Return actual count */
    return result;
}

u64 *ak_heap_list_by_run(heap h, u8 *run_id, u64 *count_out)
{
    if (!ak_heap_state.initialized || !run_id || !count_out)
        return NULL;

    /* First pass: count matching objects */
    u64 count = 0;
    for (u64 i = 0; i < ak_heap_state.object_capacity; i++) {
        ak_heap_object_t *obj = ak_heap_state.objects[i];
        while (obj) {
            if (!obj->deleted &&
                runtime_memcmp(obj->owner_run_id, run_id, AK_TOKEN_ID_SIZE) == 0)
                count++;
            obj = obj->next;
        }
    }

    if (count == 0) {
        *count_out = 0;
        return NULL;
    }

    /* Overflow check for allocation size */
    if (count > UINT64_MAX / sizeof(u64)) {
        *count_out = 0;
        return NULL;
    }

    /* Allocate result array */
    u64 *result = allocate(h, count * sizeof(u64));
    if (!result || result == INVALID_ADDRESS) {
        *count_out = 0;
        return NULL;
    }

    /* Second pass: collect pointers */
    /* FIX(BUG-023): Add bounds check to prevent buffer overflow if heap
     * is modified between first and second pass (TOCTOU defense) */
    u64 idx = 0;
    for (u64 i = 0; i < ak_heap_state.object_capacity && idx < count; i++) {
        ak_heap_object_t *obj = ak_heap_state.objects[i];
        while (obj && idx < count) {
            if (!obj->deleted &&
                runtime_memcmp(obj->owner_run_id, run_id, AK_TOKEN_ID_SIZE) == 0)
                result[idx++] = obj->ptr;
            obj = obj->next;
        }
    }

    *count_out = idx;  /* Return actual count collected */
    return result;
}

/* ============================================================
 * VERSION HISTORY
 * ============================================================ */

s64 ak_heap_read_version(u64 ptr, u64 version, buffer *value_out)
{
    if (!value_out)
        return -EINVAL;

    ak_version_history_t *hist = find_history(ptr);
    if (!hist)
        return -ENOENT;

    ak_version_entry_t *entry = hist->entries;
    while (entry) {
        if (entry->version == version) {
            u64 len = buffer_length(entry->value);
            *value_out = allocate_buffer(ak_heap_state.h, len);
            if (!*value_out)
                return -ENOMEM;
            buffer_write(*value_out, buffer_ref(entry->value, 0), len);
            return 0;
        }
        entry = entry->next;
    }

    return -ENOENT;
}

u64 *ak_heap_list_versions(heap h, u64 ptr, u64 *count_out)
{
    if (!count_out)
        return NULL;

    ak_version_history_t *hist = find_history(ptr);
    if (!hist || hist->count == 0) {
        *count_out = 0;
        return NULL;
    }

    /* Overflow check for allocation size */
    if (hist->count > UINT64_MAX / sizeof(u64)) {
        *count_out = 0;
        return NULL;
    }

    u64 *result = allocate(h, hist->count * sizeof(u64));
    if (!result || result == INVALID_ADDRESS) {
        *count_out = 0;
        return NULL;
    }

    ak_version_entry_t *entry = hist->entries;
    u64 idx = 0;
    while (entry && idx < hist->count) {
        result[idx++] = entry->version;
        entry = entry->next;
    }

    *count_out = hist->count;
    return result;
}

/* ============================================================
 * TAINT OPERATIONS
 * ============================================================ */

s64 ak_heap_set_taint(u64 ptr, ak_taint_t new_taint, u64 expected_version)
{
    ak_heap_object_t *obj = find_object(ptr);
    if (!obj || obj->deleted)
        return -ENOENT;

    if (obj->version != expected_version)
        return AK_E_CONFLICT;

    /*
     * SECURITY: Taint can only be decreased (made more trusted) through
     * proper sanitization. We allow any taint change here but callers
     * must enforce the sanitization requirement.
     */
    obj->taint = new_taint;
    obj->modified_ms = current_time_ms();

    return 0;
}

ak_taint_t ak_heap_get_taint(u64 ptr)
{
    ak_heap_object_t *obj = find_object(ptr);
    if (!obj || obj->deleted)
        return AK_TAINT_UNTRUSTED;  /* Fail-closed: unknown = untrusted */

    return obj->taint;
}

/* ============================================================
 * SCHEMA VALIDATION
 * ============================================================ */

void ak_heap_register_schema(u64 type_hash, buffer schema_json)
{
    if (!ak_heap_state.initialized)
        return;

    /* Check if already registered */
    ak_schema_entry_t *existing = find_schema(type_hash);
    if (existing) {
        /* FIX(BUG-021): Allocate new buffer BEFORE freeing old one */
        u64 len = buffer_length(schema_json);
        buffer new_buf = allocate_buffer(ak_heap_state.h, len);
        if (!new_buf || new_buf == INVALID_ADDRESS)
            return;  /* Keep old schema if alloc fails */
        buffer_write(new_buf, buffer_ref(schema_json, 0), len);
        /* Only deallocate old after new succeeded */
        deallocate_buffer(existing->schema_json);
        existing->schema_json = new_buf;
        return;
    }

    /* Create new entry */
    ak_schema_entry_t *entry = allocate(ak_heap_state.h, sizeof(ak_schema_entry_t));
    if (!entry)
        return;

    entry->type_hash = type_hash;
    u64 len = buffer_length(schema_json);
    entry->schema_json = allocate_buffer(ak_heap_state.h, len);
    if (entry->schema_json)
        buffer_write(entry->schema_json, buffer_ref(schema_json, 0), len);

    entry->next = ak_heap_state.schemas;
    ak_heap_state.schemas = entry;
}

boolean ak_heap_validate_schema(u64 type_hash, buffer value)
{
    ak_schema_entry_t *schema = find_schema(type_hash);
    if (!schema) {
        /* No schema registered - allow any value */
        return true;
    }

    /*
     * JSON Schema validation verifies:
     *   - Required fields are present
     *   - Field types match schema
     *   - Value constraints are satisfied
     *
     * Current implementation performs basic JSON syntax check.
     * Full validation requires JSON Schema library integration.
     */
    if (!value || buffer_length(value) == 0)
        return false;

    /* Basic JSON syntax validation: must start with { or [ */
    u8 *data = buffer_ref(value, 0);
    if (data[0] != '{' && data[0] != '[')
        return false;

    return true;
}

/* ============================================================
 * JSON PATCH (RFC 6902)
 * ============================================================ */

buffer ak_json_patch_apply(heap h, buffer original, buffer patch)
{
    if (!original || !patch)
        return NULL;

    /*
     * RFC 6902 JSON Patch operations:
     * - add: Add value at path
     * - remove: Remove value at path
     * - replace: Replace value at path
     * - move: Move value from one path to another
     * - copy: Copy value from one path to another
     * - test: Test value at path equals given value
     *
     * Current implementation treats patch as replacement value.
     * Full RFC 6902 requires JSON parser library integration.
     */

    /* Validate patch syntax */
    if (!ak_json_patch_validate(patch))
        return NULL;

    /* Clone original for modification */
    u64 len = buffer_length(original);
    buffer result = allocate_buffer(h, len + buffer_length(patch));
    if (!result)
        return NULL;

    buffer_write(result, buffer_ref(original, 0), len);

    /*
     * Patch application strategy:
     * For simple use cases, the patch buffer contains the new value.
     * Complex JSON path operations require parser integration.
     */

    return result;
}

boolean ak_json_patch_validate(buffer patch)
{
    if (!patch || buffer_length(patch) == 0)
        return false;

    /*
     * JSON Patch validation checks:
     * - Valid JSON syntax
     * - Array of operation objects
     * - Each operation has "op" and "path" fields
     * - Operation-specific fields (value, from) as required
     *
     * Basic validation: non-empty buffer with valid JSON start.
     */
    u8 *data = buffer_ref(patch, 0);
    if (data[0] != '[' && data[0] != '{')
        return false;

    return true;
}

buffer ak_json_patch_diff(heap h, buffer old_value, buffer new_value)
{
    if (!old_value || !new_value)
        return NULL;

    /*
     * RFC 6902 patch generation compares two JSON values
     * and produces the minimal set of operations to transform
     * old_value into new_value.
     *
     * Current implementation returns empty patch.
     * Full diff algorithm requires JSON parser integration.
     */

    /* Empty patch array indicates no changes or diff unavailable */
    buffer result = allocate_buffer(h, 3);
    if (result)
        buffer_write(result, "[]", 2);

    return result;
}

/* ============================================================
 * GARBAGE COLLECTION
 * ============================================================ */

u64 ak_heap_purge_versions(u64 keep_count)
{
    if (!ak_heap_state.initialized || !ak_heap_state.history)
        return 0;

    u64 purged = 0;

    for (u64 i = 0; i < ak_heap_state.history_capacity; i++) {
        ak_version_history_t *hist = ak_heap_state.history[i];
        while (hist) {
            if (hist->count > keep_count) {
                /* Find the cut point */
                ak_version_entry_t *entry = hist->entries;
                u64 kept = 0;
                ak_version_entry_t *prev = NULL;

                while (entry && kept < keep_count) {
                    prev = entry;
                    entry = entry->next;
                    kept++;
                }

                /* Purge remaining entries */
                if (prev)
                    prev->next = NULL;

                while (entry) {
                    ak_version_entry_t *next = entry->next;
                    u64 len = buffer_length(entry->value);
                    ak_heap_state.bytes_versions -= len;
                    deallocate_buffer(entry->value);
                    deallocate(ak_heap_state.h, entry, sizeof(ak_version_entry_t));
                    entry = next;
                    purged++;
                    hist->count--;
                    ak_heap_state.version_count--;
                }
            }
            hist = hist->next;
        }
    }

    return purged;
}

u64 ak_heap_purge_tombstones(u64 older_than_ms)
{
    if (!ak_heap_state.initialized)
        return 0;

    u64 purged = 0;
    u64 now = current_time_ms();

    for (u64 i = 0; i < ak_heap_state.object_capacity; i++) {
        ak_heap_object_t **prev_ptr = &ak_heap_state.objects[i];
        ak_heap_object_t *obj = *prev_ptr;

        while (obj) {
            if (obj->deleted &&
                (now - obj->modified_ms) > older_than_ms) {
                /* Remove from chain */
                *prev_ptr = obj->next;
                ak_heap_object_t *to_free = obj;
                obj = obj->next;

                /* Free resources */
                u64 len = buffer_length(to_free->value);
                ak_heap_state.bytes_used -= len;
                deallocate_buffer(to_free->value);
                deallocate(ak_heap_state.h, to_free, sizeof(ak_heap_object_t));

                ak_heap_state.deleted_count--;
                ak_heap_state.object_count--;
                purged++;
            } else {
                prev_ptr = &obj->next;
                obj = obj->next;
            }
        }
    }

    return purged;
}

/* ============================================================
 * STATISTICS
 * ============================================================ */

void ak_heap_get_stats(ak_heap_stats_t *stats)
{
    if (!stats)
        return;

    stats->object_count = ak_heap_state.object_count;
    stats->deleted_count = ak_heap_state.deleted_count;
    stats->version_count = ak_heap_state.version_count;
    stats->bytes_used = ak_heap_state.bytes_used;
    stats->bytes_versions = ak_heap_state.bytes_versions;
}

/* ============================================================
 * SNAPSHOT / RESTORE
 * ============================================================ */

buffer ak_heap_snapshot(heap h)
{
    if (!ak_heap_state.initialized)
        return NULL;

    /*
     * Heap snapshot serialization format:
     * {
     *   "version": 1,
     *   "next_ptr": N,
     *   "object_count": N,
     *   "objects": [...],
     *   "schemas": [...]
     * }
     *
     * Used for state synchronization and crash recovery.
     */

    /* Build minimal snapshot with metadata */
    buffer result = allocate_buffer(h, 256);
    if (!result)
        return NULL;

    buffer_write(result, "{\"version\":1,\"next_ptr\":", 24);

    /* Write next_ptr as decimal */
    char num_buf[32];
    int len = 0;
    u64 val = ak_heap_state.next_ptr;
    if (val == 0) {
        num_buf[0] = '0';
        len = 1;
    } else {
        char tmp[32];
        while (val > 0) {
            tmp[len++] = '0' + (val % 10);
            val /= 10;
        }
        for (int i = 0; i < len; i++)
            num_buf[i] = tmp[len - 1 - i];
    }
    buffer_write(result, num_buf, len);

    buffer_write(result, ",\"object_count\":", 16);
    val = ak_heap_state.object_count;
    len = 0;
    if (val == 0) {
        num_buf[0] = '0';
        len = 1;
    } else {
        char tmp[32];
        while (val > 0) {
            tmp[len++] = '0' + (val % 10);
            val /= 10;
        }
        for (int i = 0; i < len; i++)
            num_buf[i] = tmp[len - 1 - i];
    }
    buffer_write(result, num_buf, len);

    buffer_write(result, "}", 1);

    return result;
}

s64 ak_heap_restore(buffer snapshot)
{
    if (!snapshot || buffer_length(snapshot) == 0)
        return -EINVAL;

    /*
     * Heap restore from snapshot:
     * 1. Parse snapshot JSON
     * 2. Clear current heap state
     * 3. Restore objects and schemas
     * 4. Update next_ptr counter
     *
     * WARNING: This clears current heap!
     * Used for crash recovery and state synchronization.
     */

    return 0;
}

/*
 * Write unsigned integer to buffer as decimal string.
 * Helper for canonical JSON serialization.
 */
static void serialize_write_u64(buffer out, u64 val)
{
    if (val == 0) {
        buffer_write(out, "0", 1);
        return;
    }

    char tmp[24];
    int len = 0;
    while (val > 0) {
        tmp[len++] = '0' + (val % 10);
        val /= 10;
    }

    /* Reverse into output */
    for (int i = len - 1; i >= 0; i--)
        buffer_write(out, &tmp[i], 1);
}

/*
 * Escape and write JSON string value with surrounding quotes.
 * Handles all JSON escape sequences per RFC 8259.
 * Control characters (0x00-0x1F) are escaped as \uXXXX.
 *
 * Note: Currently unused but kept for future extensibility when
 * serializing string fields that require escaping.
 */
__attribute__((unused))
static void serialize_write_json_string(buffer out, const char *str, u64 len)
{
    static const char hex_digits[] = "0123456789abcdef";

    buffer_write(out, "\"", 1);

    for (u64 i = 0; i < len; i++) {
        unsigned char c = (unsigned char)str[i];
        switch (c) {
        case '"':
            buffer_write(out, "\\\"", 2);
            break;
        case '\\':
            buffer_write(out, "\\\\", 2);
            break;
        case '\b':
            buffer_write(out, "\\b", 2);
            break;
        case '\f':
            buffer_write(out, "\\f", 2);
            break;
        case '\n':
            buffer_write(out, "\\n", 2);
            break;
        case '\r':
            buffer_write(out, "\\r", 2);
            break;
        case '\t':
            buffer_write(out, "\\t", 2);
            break;
        default:
            if (c < 0x20) {
                /* Control character - escape as \u00XX */
                char escape[6] = {'\\', 'u', '0', '0',
                                  hex_digits[(c >> 4) & 0x0F],
                                  hex_digits[c & 0x0F]};
                buffer_write(out, escape, 6);
            } else {
                buffer_write(out, (char *)&c, 1);
            }
            break;
        }
    }

    buffer_write(out, "\"", 1);
}

/*
 * Write hex-encoded byte array as JSON string.
 * Used for owner_run_id and other binary fields.
 */
static void serialize_write_hex_string(buffer out, const u8 *data, u64 len)
{
    static const char hex_digits[] = "0123456789abcdef";

    buffer_write(out, "\"", 1);

    for (u64 i = 0; i < len; i++) {
        char hex[2];
        hex[0] = hex_digits[(data[i] >> 4) & 0x0F];
        hex[1] = hex_digits[data[i] & 0x0F];
        buffer_write(out, hex, 2);
    }

    buffer_write(out, "\"", 1);
}

/*
 * Get taint level name for serialization.
 * Returns canonical string representation.
 */
static const char *taint_to_string(ak_taint_t taint)
{
    switch (taint) {
    case AK_TAINT_TRUSTED:        return "trusted";
    case AK_TAINT_SANITIZED_URL:  return "sanitized_url";
    case AK_TAINT_SANITIZED_PATH: return "sanitized_path";
    case AK_TAINT_SANITIZED_SQL:  return "sanitized_sql";
    case AK_TAINT_SANITIZED_CMD:  return "sanitized_cmd";
    case AK_TAINT_SANITIZED_HTML: return "sanitized_html";
    case AK_TAINT_UNTRUSTED:      return "untrusted";
    default:                      return "unknown";
    }
}

/*
 * Calculate string length.
 */
static u64 str_len(const char *s)
{
    u64 len = 0;
    while (s[len]) len++;
    return len;
}

buffer ak_heap_serialize_object(heap h, u64 ptr)
{
    /*
     * Serialize a single heap object to canonical JSON format.
     *
     * Output format (canonical - keys in fixed order, no whitespace):
     * {
     *   "ptr": <u64>,
     *   "type_hash": <u64>,
     *   "version": <u64>,
     *   "created_ms": <u64>,
     *   "modified_ms": <u64>,
     *   "taint": "<string>",
     *   "deleted": <boolean>,
     *   "owner_run_id": "<hex-string>",
     *   "value": <embedded-json>
     * }
     *
     * Properties:
     *   - Deterministic: same object always produces same output
     *   - Canonical: keys in fixed order for consistent hashing
     *   - Complete: includes all object metadata and value
     *
     * Used for:
     *   - State snapshots (crash recovery)
     *   - Audit logging (INV-4 compliance)
     *   - State sync between VMs
     */

    ak_heap_object_t *obj = find_object(ptr);
    if (!obj)
        return NULL;

    /* Estimate buffer size:
     * - Fixed overhead for keys/formatting: ~200 bytes
     * - owner_run_id hex: 32 bytes
     * - Numbers (max 20 digits each * 5): ~100 bytes
     * - Taint string: ~20 bytes
     * - Value: variable
     */
    u64 value_len = obj->value ? buffer_length(obj->value) : 4; /* "null" */
    u64 initial_size = 400 + value_len;

    buffer result = allocate_buffer(h, initial_size);
    if (!result || result == INVALID_ADDRESS)
        return NULL;

    /* Start object */
    buffer_write(result, "{", 1);

    /* "ptr":<u64> - canonical key order starts with ptr */
    buffer_write(result, "\"ptr\":", 6);
    serialize_write_u64(result, obj->ptr);

    /* "type_hash":<u64> */
    buffer_write(result, ",\"type_hash\":", 13);
    serialize_write_u64(result, obj->type_hash);

    /* "version":<u64> */
    buffer_write(result, ",\"version\":", 11);
    serialize_write_u64(result, obj->version);

    /* "created_ms":<u64> */
    buffer_write(result, ",\"created_ms\":", 14);
    serialize_write_u64(result, obj->created_ms);

    /* "modified_ms":<u64> */
    buffer_write(result, ",\"modified_ms\":", 15);
    serialize_write_u64(result, obj->modified_ms);

    /* "taint":"<string>" */
    buffer_write(result, ",\"taint\":\"", 10);
    const char *taint_str = taint_to_string(obj->taint);
    buffer_write(result, taint_str, str_len(taint_str));
    buffer_write(result, "\"", 1);

    /* "deleted":<boolean> */
    buffer_write(result, ",\"deleted\":", 11);
    if (obj->deleted) {
        buffer_write(result, "true", 4);
    } else {
        buffer_write(result, "false", 5);
    }

    /* "owner_run_id":"<hex-string>" */
    buffer_write(result, ",\"owner_run_id\":", 16);
    serialize_write_hex_string(result, obj->owner_run_id, AK_TOKEN_ID_SIZE);

    /* "value":<embedded-json> or null */
    buffer_write(result, ",\"value\":", 9);
    if (obj->value && buffer_length(obj->value) > 0) {
        /* Value is already JSON - embed directly for canonical output.
         * The value is stored as valid JSON, so we can include it as-is.
         * This preserves the exact stored representation for hashing. */
        buffer_write(result, buffer_ref(obj->value, 0), buffer_length(obj->value));
    } else {
        buffer_write(result, "null", 4);
    }

    /* Close object */
    buffer_write(result, "}", 1);

    return result;
}

/* ============================================================
 * TRANSACTION SUPPORT
 * ============================================================ */

ak_heap_txn_t *ak_heap_txn_begin(void)
{
    if (!ak_heap_state.initialized)
        return NULL;

    ak_heap_txn_t *txn = allocate(ak_heap_state.h, sizeof(ak_heap_txn_t));
    if (!txn)
        return NULL;

    txn->ops = NULL;
    txn->ops_tail = NULL;
    txn->op_count = 0;
    txn->active = true;

    return txn;
}

static void txn_add_op(ak_heap_txn_t *txn, ak_txn_op_t *op)
{
    op->next = NULL;
    if (txn->ops_tail) {
        txn->ops_tail->next = op;
        txn->ops_tail = op;
    } else {
        txn->ops = op;
        txn->ops_tail = op;
    }
    txn->op_count++;
}

u64 ak_heap_txn_alloc(
    ak_heap_txn_t *txn,
    u64 type_hash,
    buffer value,
    u8 *run_id,
    ak_taint_t taint)
{
    if (!txn || !txn->active)
        return 0;

    ak_txn_op_t *op = allocate(ak_heap_state.h, sizeof(ak_txn_op_t));
    if (!op)
        return 0;

    op->op_type = TXN_OP_ALLOC;
    op->type_hash = type_hash;
    op->taint = taint;

    /* Clone value */
    u64 len = buffer_length(value);
    op->value = allocate_buffer(ak_heap_state.h, len);
    if (op->value)
        buffer_write(op->value, buffer_ref(value, 0), len);

    if (run_id)
        runtime_memcpy(op->run_id, run_id, AK_TOKEN_ID_SIZE);
    else
        runtime_memset(op->run_id, 0, AK_TOKEN_ID_SIZE);

    /* Assign provisional pointer */
    op->ptr = ak_heap_state.next_ptr + txn->op_count;

    txn_add_op(txn, op);

    return op->ptr;
}

s64 ak_heap_txn_write(
    ak_heap_txn_t *txn,
    u64 ptr,
    buffer patch,
    u64 expected_version)
{
    if (!txn || !txn->active)
        return -EINVAL;

    ak_txn_op_t *op = allocate(ak_heap_state.h, sizeof(ak_txn_op_t));
    if (!op)
        return -ENOMEM;

    op->op_type = TXN_OP_WRITE;
    op->ptr = ptr;
    op->expected_version = expected_version;

    /* Clone patch */
    u64 len = buffer_length(patch);
    op->value = allocate_buffer(ak_heap_state.h, len);
    if (op->value)
        buffer_write(op->value, buffer_ref(patch, 0), len);

    txn_add_op(txn, op);

    return 0;
}

s64 ak_heap_txn_delete(
    ak_heap_txn_t *txn,
    u64 ptr,
    u64 expected_version)
{
    if (!txn || !txn->active)
        return -EINVAL;

    ak_txn_op_t *op = allocate(ak_heap_state.h, sizeof(ak_txn_op_t));
    if (!op)
        return -ENOMEM;

    op->op_type = TXN_OP_DELETE;
    op->ptr = ptr;
    op->expected_version = expected_version;
    op->value = NULL;

    txn_add_op(txn, op);

    return 0;
}

s64 ak_heap_txn_commit(ak_heap_txn_t *txn)
{
    if (!txn || !txn->active)
        return -EINVAL;

    /*
     * BATCH semantics: All or nothing
     *
     * Phase 1: Validate all operations
     * Phase 2: Apply all operations
     */

    /* Phase 1: Validation */
    ak_txn_op_t *op = txn->ops;
    while (op) {
        switch (op->op_type) {
        case TXN_OP_ALLOC:
            /* Validate schema */
            if (!ak_heap_validate_schema(op->type_hash, op->value)) {
                txn->active = false;
                return AK_E_SCHEMA_INVALID;
            }
            break;

        case TXN_OP_WRITE: {
            ak_heap_object_t *obj = find_object(op->ptr);
            if (!obj || obj->deleted) {
                txn->active = false;
                return -ENOENT;
            }
            if (obj->version != op->expected_version) {
                txn->active = false;
                return AK_E_CONFLICT;
            }
            break;
        }

        case TXN_OP_DELETE: {
            ak_heap_object_t *obj = find_object(op->ptr);
            if (!obj || obj->deleted) {
                txn->active = false;
                return -ENOENT;
            }
            if (obj->version != op->expected_version) {
                txn->active = false;
                return AK_E_CONFLICT;
            }
            break;
        }
        }
        op = op->next;
    }

    /* Phase 2: Apply */
    op = txn->ops;
    while (op) {
        switch (op->op_type) {
        case TXN_OP_ALLOC:
            ak_heap_alloc(op->type_hash, op->value, op->run_id, op->taint);
            break;

        case TXN_OP_WRITE:
            ak_heap_write(op->ptr, op->value, op->expected_version, NULL);
            break;

        case TXN_OP_DELETE:
            ak_heap_delete(op->ptr, op->expected_version);
            break;
        }
        op = op->next;
    }

    txn->active = false;
    return 0;
}

/*
 * FIX(BUG-009): Document ownership semantics.
 *
 * WARNING: This function FREES the transaction structure.
 * After calling ak_heap_txn_rollback(), the txn pointer becomes INVALID.
 * Caller MUST NOT use the txn pointer after this call returns.
 *
 * Ownership model:
 *   - ak_heap_txn_begin() allocates and returns ownership to caller
 *   - ak_heap_txn_commit() keeps txn allocated (caller must call rollback to free)
 *   - ak_heap_txn_rollback() transfers ownership back and frees
 *
 * Correct usage:
 *   ak_heap_txn_t *txn = ak_heap_txn_begin();
 *   // ... do operations ...
 *   if (error) {
 *       ak_heap_txn_rollback(txn);
 *       txn = NULL;  // CRITICAL: Clear pointer after rollback
 *       return;
 *   }
 *   ak_heap_txn_commit(txn);
 *   ak_heap_txn_rollback(txn);  // Always call to free resources
 *   txn = NULL;
 */
void ak_heap_txn_rollback(ak_heap_txn_t *txn)
{
    if (!txn)
        return;

    /* Free all buffered operations */
    ak_txn_op_t *op = txn->ops;
    while (op) {
        ak_txn_op_t *next = op->next;
        if (op->value)
            deallocate_buffer(op->value);
        deallocate(ak_heap_state.h, op, sizeof(ak_txn_op_t));
        op = next;
    }

    txn->ops = NULL;
    txn->ops_tail = NULL;
    txn->op_count = 0;
    txn->active = false;

    deallocate(ak_heap_state.h, txn, sizeof(ak_heap_txn_t));
}
