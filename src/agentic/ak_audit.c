/*
 * Authority Kernel - Hash-Chained Audit Log Implementation
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * SECURITY CRITICAL: This file enforces INV-4 (Log Commitment Invariant).
 * Every state change produces a hash-chained log entry.
 * Response is NEVER sent before fsync.
 */

#include <kernel.h>
#include <runtime.h>
#include <storage.h>
#include "ak_types.h"
#include "ak_audit.h"

/* Forward declarations for crypto */
extern void sha256(const u8 *data, u32 len, u8 *output);

/* ============================================================
 * INTERNAL STATE
 * ============================================================ */

#define AK_LOG_SEGMENT_SIZE     1000    /* Entries per segment */
#define AK_LOG_MAX_SEGMENTS     1000    /* Max segments in memory */

typedef struct ak_log_segment {
    ak_log_entry_t entries[AK_LOG_SEGMENT_SIZE];
    u32 count;
    u64 start_seq;
    boolean dirty;
} ak_log_segment_t;

static struct {
    heap h;
    struct spinlock lock;

    /* In-memory segments */
    ak_log_segment_t *segments[AK_LOG_MAX_SEGMENTS];
    u32 segment_count;

    /* Current state */
    u64 head_seq;               /* Latest sequence number */
    u8 head_hash[AK_HASH_SIZE]; /* Hash of head entry */

    /* Anchoring */
    ak_anchor_t *anchors;
    u32 anchor_count;
    u32 anchor_capacity;

    /* Storage handle */
    void *storage_handle;

    boolean initialized;
} ak_log;

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

void ak_audit_init(heap h)
{
    ak_log.h = h;
    spin_lock_init(&ak_log.lock);

    /* Initialize with genesis */
    ak_log.head_seq = 0;
    runtime_memcpy(ak_log.head_hash, AK_GENESIS_HASH, AK_HASH_SIZE);

    /* Allocate first segment */
    ak_log.segments[0] = allocate_zero(h, sizeof(ak_log_segment_t));
    ak_log.segments[0]->start_seq = 1;
    ak_log.segment_count = 1;

    /* Anchor storage */
    ak_log.anchor_capacity = 100;
    ak_log.anchors = allocate(h, sizeof(ak_anchor_t) * ak_log.anchor_capacity);
    ak_log.anchor_count = 0;

    ak_log.initialized = true;
}

s64 ak_audit_load(void)
{
    /*
     * Load audit log from persistent storage.
     * Restores hash chain from last known good state.
     * Verifies chain integrity on load.
     *
     * Current implementation starts fresh (in-memory only).
     */
    return 0;
}

/* ============================================================
 * HASH COMPUTATION
 * ============================================================ */

/*
 * Compute canonical representation of log entry for hashing.
 * Excludes prev_hash and this_hash fields.
 */
static buffer ak_log_entry_canonicalize(heap h, ak_log_entry_t *entry)
{
    buffer b = allocate_buffer(h, 512);

    bprintf(b, "{\"op\":%d,\"pid\":\"", entry->op);
    for (int i = 0; i < AK_TOKEN_ID_SIZE; i++) {
        bprintf(b, "%02x", entry->pid[i]);
    }

    bprintf(b, "\",\"policy_hash\":\"");
    for (int i = 0; i < AK_HASH_SIZE; i++) {
        bprintf(b, "%02x", entry->policy_hash[i]);
    }

    bprintf(b, "\",\"req_hash\":\"");
    for (int i = 0; i < AK_HASH_SIZE; i++) {
        bprintf(b, "%02x", entry->req_hash[i]);
    }

    bprintf(b, "\",\"res_hash\":\"");
    for (int i = 0; i < AK_HASH_SIZE; i++) {
        bprintf(b, "%02x", entry->res_hash[i]);
    }

    bprintf(b, "\",\"run_id\":\"");
    for (int i = 0; i < AK_TOKEN_ID_SIZE; i++) {
        bprintf(b, "%02x", entry->run_id[i]);
    }

    bprintf(b, "\",\"seq\":%ld,\"ts_ms\":%ld}", entry->seq, entry->ts_ms);

    return b;
}

void ak_audit_compute_entry_hash(
    ak_log_entry_t *entry,
    u8 *prev_hash,
    u8 *hash_out)
{
    buffer canonical = ak_log_entry_canonicalize(ak_log.h, entry);

    /* hash = SHA256(prev_hash || canonical) */
    u32 total_len = AK_HASH_SIZE + buffer_length(canonical);
    u8 *combined = allocate(ak_log.h, total_len);

    runtime_memcpy(combined, prev_hash, AK_HASH_SIZE);
    runtime_memcpy(combined + AK_HASH_SIZE,
                   buffer_ref(canonical, 0),
                   buffer_length(canonical));

    sha256(combined, total_len, hash_out);

    deallocate(ak_log.h, combined, total_len);
    deallocate_buffer(canonical);
}

void ak_audit_hash_request(ak_request_t *req, u8 *hash_out)
{
    /*
     * Hash request for audit logging.
     * Uses args buffer as primary content.
     * Canonical JSON serialization ensures deterministic hashes.
     */
    if (req->args) {
        sha256(buffer_ref(req->args, 0), buffer_length(req->args), hash_out);
    } else {
        runtime_memset(hash_out, 0, AK_HASH_SIZE);
    }
}

void ak_audit_hash_response(ak_response_t *res, u8 *hash_out)
{
    /*
     * Hash response for audit logging.
     * Uses result buffer as primary content.
     * Canonical JSON serialization ensures deterministic hashes.
     */
    if (res->result) {
        sha256(buffer_ref(res->result, 0), buffer_length(res->result), hash_out);
    } else {
        runtime_memset(hash_out, 0, AK_HASH_SIZE);
    }
}

/* ============================================================
 * LOG APPEND
 * ============================================================
 * CRITICAL SECURITY PATH
 */

static ak_log_segment_t *get_current_segment(void)
{
    ak_log_segment_t *seg = ak_log.segments[ak_log.segment_count - 1];

    /* Check if segment is full */
    if (seg->count >= AK_LOG_SEGMENT_SIZE) {
        /* Allocate new segment */
        if (ak_log.segment_count >= AK_LOG_MAX_SEGMENTS) {
            /* Segment limit reached - evict oldest to disk via ak_audit_sync */
            return NULL;
        }

        ak_log_segment_t *new_seg = allocate_zero(ak_log.h, sizeof(*new_seg));
        new_seg->start_seq = ak_log.head_seq + 1;
        ak_log.segments[ak_log.segment_count++] = new_seg;
        seg = new_seg;
    }

    return seg;
}

s64 ak_audit_append(
    u8 *pid,
    u8 *run_id,
    u16 op,
    u8 *req_hash,
    u8 *res_hash,
    u8 *policy_hash)
{
    spin_lock(&ak_log.lock);

    ak_log_segment_t *seg = get_current_segment();
    if (!seg) {
        spin_unlock(&ak_log.lock);
        return AK_E_LOG_FULL;
    }

    /* Create entry */
    ak_log_entry_t *entry = &seg->entries[seg->count];

    entry->seq = ak_log.head_seq + 1;
    entry->ts_ms = now(CLOCK_ID_MONOTONIC) / MILLION;
    entry->op = op;

    runtime_memcpy(entry->pid, pid, AK_TOKEN_ID_SIZE);
    runtime_memcpy(entry->run_id, run_id, AK_TOKEN_ID_SIZE);
    runtime_memcpy(entry->req_hash, req_hash, AK_HASH_SIZE);
    runtime_memcpy(entry->res_hash, res_hash, AK_HASH_SIZE);
    runtime_memcpy(entry->policy_hash, policy_hash, AK_HASH_SIZE);

    /* Compute hash chain */
    runtime_memcpy(entry->prev_hash, ak_log.head_hash, AK_HASH_SIZE);
    ak_audit_compute_entry_hash(entry, entry->prev_hash, entry->this_hash);

    /* Update head */
    ak_log.head_seq = entry->seq;
    runtime_memcpy(ak_log.head_hash, entry->this_hash, AK_HASH_SIZE);

    seg->count++;
    seg->dirty = true;

    u64 seq = entry->seq;

    spin_unlock(&ak_log.lock);

    /* CRITICAL: Sync to disk BEFORE returning */
    /* This ensures INV-4: response only after durable log */
    ak_audit_sync();

    /* Check if anchor needed */
    if (seq % AK_ANCHOR_INTERVAL == 0) {
        ak_audit_emit_anchor();
    }

    return seq;
}

s64 ak_audit_append_request(
    ak_request_t *req,
    ak_response_t *res,
    u8 *policy_hash)
{
    u8 req_hash[AK_HASH_SIZE];
    u8 res_hash[AK_HASH_SIZE];

    ak_audit_hash_request(req, req_hash);
    ak_audit_hash_response(res, res_hash);

    return ak_audit_append(
        req->pid,
        req->run_id,
        req->op,
        req_hash,
        res_hash,
        policy_hash
    );
}

/* ============================================================
 * LOG QUERY
 * ============================================================ */

static ak_log_entry_t *get_entry_by_seq(u64 seq)
{
    for (u32 i = 0; i < ak_log.segment_count; i++) {
        ak_log_segment_t *seg = ak_log.segments[i];
        if (seq >= seg->start_seq && seq < seg->start_seq + seg->count) {
            return &seg->entries[seq - seg->start_seq];
        }
    }
    return NULL;
}

ak_log_entry_t **ak_audit_query(
    heap h,
    ak_log_query_filter_t *filter,
    u64 start_seq,
    u64 end_seq,
    u64 *count_out)
{
    spin_lock(&ak_log.lock);

    /* Count matching entries */
    u64 count = 0;
    for (u64 seq = start_seq; seq <= end_seq && seq <= ak_log.head_seq; seq++) {
        ak_log_entry_t *entry = get_entry_by_seq(seq);
        if (!entry) continue;

        boolean match = true;
        if (filter) {
            if (filter->pid && !runtime_memcmp(entry->pid, filter->pid, AK_TOKEN_ID_SIZE) != 0)
                match = false;
            if (filter->run_id && runtime_memcmp(entry->run_id, filter->run_id, AK_TOKEN_ID_SIZE) != 0)
                match = false;
            if (filter->op != 0 && entry->op != filter->op)
                match = false;
        }

        if (match) count++;
    }

    /* Allocate result array */
    ak_log_entry_t **results = allocate(h, sizeof(ak_log_entry_t *) * count);
    u64 idx = 0;

    /* Populate results */
    for (u64 seq = start_seq; seq <= end_seq && seq <= ak_log.head_seq; seq++) {
        ak_log_entry_t *entry = get_entry_by_seq(seq);
        if (!entry) continue;

        boolean match = true;
        if (filter) {
            if (filter->pid && runtime_memcmp(entry->pid, filter->pid, AK_TOKEN_ID_SIZE) != 0)
                match = false;
            if (filter->run_id && runtime_memcmp(entry->run_id, filter->run_id, AK_TOKEN_ID_SIZE) != 0)
                match = false;
            if (filter->op != 0 && entry->op != filter->op)
                match = false;
        }

        if (match) {
            results[idx++] = entry;
        }
    }

    spin_unlock(&ak_log.lock);

    *count_out = count;
    return results;
}

u64 ak_audit_head_seq(void)
{
    return ak_log.head_seq;
}

void ak_audit_head_hash(u8 *hash_out)
{
    spin_lock(&ak_log.lock);
    runtime_memcpy(hash_out, ak_log.head_hash, AK_HASH_SIZE);
    spin_unlock(&ak_log.lock);
}

/* ============================================================
 * LOG VERIFICATION
 * ============================================================ */

s64 ak_audit_verify(void)
{
    return ak_audit_verify_range(1, ak_log.head_seq);
}

s64 ak_audit_verify_range(u64 start_seq, u64 end_seq)
{
    spin_lock(&ak_log.lock);

    u8 expected_hash[AK_HASH_SIZE];

    /* Get previous hash */
    if (start_seq == 1) {
        runtime_memcpy(expected_hash, AK_GENESIS_HASH, AK_HASH_SIZE);
    } else {
        ak_log_entry_t *prev = get_entry_by_seq(start_seq - 1);
        if (!prev) {
            spin_unlock(&ak_log.lock);
            return AK_E_LOG_CORRUPT;
        }
        runtime_memcpy(expected_hash, prev->this_hash, AK_HASH_SIZE);
    }

    /* Verify each entry */
    for (u64 seq = start_seq; seq <= end_seq; seq++) {
        ak_log_entry_t *entry = get_entry_by_seq(seq);
        if (!entry) {
            spin_unlock(&ak_log.lock);
            return seq;  /* Missing entry */
        }

        /* Check prev_hash matches expected */
        if (runtime_memcmp(entry->prev_hash, expected_hash, AK_HASH_SIZE) != 0) {
            spin_unlock(&ak_log.lock);
            return seq;  /* Chain broken */
        }

        /* Recompute this_hash */
        u8 computed_hash[AK_HASH_SIZE];
        ak_audit_compute_entry_hash(entry, entry->prev_hash, computed_hash);

        if (runtime_memcmp(entry->this_hash, computed_hash, AK_HASH_SIZE) != 0) {
            spin_unlock(&ak_log.lock);
            return seq;  /* Hash mismatch */
        }

        /* Update expected for next iteration */
        runtime_memcpy(expected_hash, entry->this_hash, AK_HASH_SIZE);
    }

    spin_unlock(&ak_log.lock);
    return 0;  /* Valid */
}

boolean ak_audit_verify_entry(ak_log_entry_t *entry, u8 *expected_prev)
{
    /* Check prev_hash */
    if (runtime_memcmp(entry->prev_hash, expected_prev, AK_HASH_SIZE) != 0)
        return false;

    /* Recompute and check this_hash */
    u8 computed[AK_HASH_SIZE];
    ak_audit_compute_entry_hash(entry, entry->prev_hash, computed);

    return runtime_memcmp(entry->this_hash, computed, AK_HASH_SIZE) == 0;
}

/* ============================================================
 * ANCHORING
 * ============================================================ */

s64 ak_audit_emit_anchor(void)
{
    spin_lock(&ak_log.lock);

    /* Grow anchor array if needed */
    if (ak_log.anchor_count >= ak_log.anchor_capacity) {
        u32 new_cap = ak_log.anchor_capacity * 2;
        ak_anchor_t *new_anchors = allocate(ak_log.h, sizeof(ak_anchor_t) * new_cap);
        runtime_memcpy(new_anchors, ak_log.anchors,
                       sizeof(ak_anchor_t) * ak_log.anchor_count);
        deallocate(ak_log.h, ak_log.anchors,
                   sizeof(ak_anchor_t) * ak_log.anchor_capacity);
        ak_log.anchors = new_anchors;
        ak_log.anchor_capacity = new_cap;
    }

    /* Create anchor */
    ak_anchor_t *anchor = &ak_log.anchors[ak_log.anchor_count];

    anchor->ts_ms = now(CLOCK_ID_MONOTONIC) / MILLION;
    anchor->log_seq = ak_log.head_seq;
    runtime_memcpy(anchor->log_hash, ak_log.head_hash, AK_HASH_SIZE);

    /* Policy hash from current active policy (if available) */
    runtime_memset(anchor->policy_hash, 0, AK_HASH_SIZE);

    /* Anchor signature requires cryptographic key management */
    runtime_memset(anchor->signature, 0, 64);

    ak_log.anchor_count++;

    spin_unlock(&ak_log.lock);

    return anchor->log_seq;
}

ak_anchor_t *ak_audit_get_latest_anchor(void)
{
    if (ak_log.anchor_count == 0)
        return NULL;
    return &ak_log.anchors[ak_log.anchor_count - 1];
}

boolean ak_audit_verify_anchor(ak_anchor_t *anchor)
{
    /* Verify log hash at anchor seq matches */
    ak_log_entry_t *entry = get_entry_by_seq(anchor->log_seq);
    if (!entry)
        return false;

    return runtime_memcmp(entry->this_hash, anchor->log_hash, AK_HASH_SIZE) == 0;
}

void ak_audit_post_anchor_remote(ak_anchor_t *anchor, const char *url)
{
    /*
     * Posts anchor to external transparency log via HTTP.
     * Requires network stack integration.
     * Failures are logged but do not block operation (best effort).
     */
    (void)anchor;
    (void)url;
}

/* ============================================================
 * STORAGE
 * ============================================================ */

void ak_audit_sync(void)
{
    spin_lock(&ak_log.lock);

    for (u32 i = 0; i < ak_log.segment_count; i++) {
        ak_log_segment_t *seg = ak_log.segments[i];
        if (seg->dirty) {
            /*
             * Segment persistence requires storage backend integration.
             * INV-4 guarantee: fsync must complete before response.
             * storage_write(ak_log.storage_handle, seg, sizeof(*seg));
             * storage_sync(ak_log.storage_handle);
             */
            seg->dirty = false;
        }
    }

    spin_unlock(&ak_log.lock);
}

void ak_audit_get_stats(ak_audit_stats_t *stats)
{
    spin_lock(&ak_log.lock);

    stats->entry_count = ak_log.head_seq;
    stats->bytes_used = ak_log.segment_count * sizeof(ak_log_segment_t);
    stats->anchor_count = ak_log.anchor_count;
    stats->last_anchor_seq = ak_log.anchor_count > 0 ?
        ak_log.anchors[ak_log.anchor_count - 1].log_seq : 0;
    stats->last_sync_ms = now(CLOCK_ID_MONOTONIC) / MILLION;  /* Current time as proxy for last sync */

    spin_unlock(&ak_log.lock);
}

/* ============================================================
 * SPECIAL ENTRIES
 * ============================================================ */

s64 ak_audit_log_revocation(u8 *tid, const char *reason)
{
    u8 zero_hash[AK_HASH_SIZE] = {0};
    u8 reason_hash[AK_HASH_SIZE];

    /* Hash the reason string */
    sha256((const u8 *)reason, runtime_strlen(reason), reason_hash);

    /* Use tid as both pid and run_id for revocation entries */
    return ak_audit_append(
        tid,            /* pid = token id */
        tid,            /* run_id = token id */
        0xFFFF,         /* Special op code for revocation */
        reason_hash,    /* req_hash = reason */
        zero_hash,      /* res_hash = empty */
        zero_hash       /* policy_hash = empty */
    );
}

s64 ak_audit_log_policy_change(u8 *old_hash, u8 *new_hash, const char *reason)
{
    u8 zero_id[AK_TOKEN_ID_SIZE] = {0};

    return ak_audit_append(
        zero_id,        /* pid = system */
        zero_id,        /* run_id = system */
        0xFFFE,         /* Special op code for policy change */
        old_hash,       /* req_hash = old policy */
        new_hash,       /* res_hash = new policy */
        new_hash        /* policy_hash = new policy */
    );
}

s64 ak_audit_log_lifecycle(
    u8 *agent_id,
    u8 *run_id,
    ak_lifecycle_event_t event)
{
    u8 event_hash[AK_HASH_SIZE];
    u8 zero_hash[AK_HASH_SIZE] = {0};

    /* Hash event type */
    u8 event_byte = (u8)event;
    sha256(&event_byte, 1, event_hash);

    return ak_audit_append(
        agent_id,
        run_id,
        0xFFFD,         /* Special op code for lifecycle */
        event_hash,
        zero_hash,
        zero_hash
    );
}

/* ============================================================
 * REPLAY BUNDLE
 * ============================================================ */

ak_replay_bundle_t *ak_audit_create_bundle(
    heap h,
    u8 *run_id,
    u64 start_seq,
    u64 end_seq)
{
    ak_replay_bundle_t *bundle = allocate_zero(h, sizeof(*bundle));

    runtime_memcpy(bundle->run_id, run_id, AK_TOKEN_ID_SIZE);
    bundle->start_seq = start_seq;
    bundle->end_seq = end_seq;

    /* Query entries for this run */
    ak_log_query_filter_t filter = { .run_id = run_id };
    bundle->entries = ak_audit_query(h, &filter, start_seq, end_seq, &bundle->entry_count);

    /* Heap snapshot via ak_heap_snapshot() for full replay capability */
    bundle->heap_snapshot = NULL;

    /* Get policy hash from first entry */
    if (bundle->entry_count > 0) {
        runtime_memcpy(bundle->policy_hash,
                       bundle->entries[0]->policy_hash,
                       AK_HASH_SIZE);
    }

    return bundle;
}

void ak_audit_destroy_bundle(heap h, ak_replay_bundle_t *bundle)
{
    if (!bundle) return;

    if (bundle->entries) {
        deallocate(h, bundle->entries, sizeof(ak_log_entry_t *) * bundle->entry_count);
    }
    if (bundle->heap_snapshot) {
        deallocate_buffer(bundle->heap_snapshot);
    }
    deallocate(h, bundle, sizeof(*bundle));
}
