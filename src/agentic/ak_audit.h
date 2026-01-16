/*
 * Authority Kernel - Hash-Chained Audit Log
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Implements INV-4: Log Commitment Invariant
 * "Each committed transition appends a log entry whose hash chain
 *  validates from genesis to head."
 *
 * SECURITY CRITICAL: All state changes MUST be logged before response.
 * The hash chain provides tamper evidence.
 */

#ifndef AK_AUDIT_H
#define AK_AUDIT_H

#include "ak_types.h"

/* ============================================================
 * LOG INITIALIZATION
 * ============================================================ */

/*
 * Initialize audit log subsystem.
 *
 * Creates genesis entry with all-zero prev_hash.
 */
void ak_audit_init(heap h);

/*
 * Load log from persistent storage (crash recovery).
 *
 * Verifies entire hash chain before accepting.
 * Returns: 0 on success, negative on corruption/error.
 */
s64 ak_audit_load(void);

/* ============================================================
 * LOG OPERATIONS
 * ============================================================ */

/*
 * Append entry to audit log.
 *
 * SECURITY: This is SYNCHRONOUS. Returns only after fsync().
 * Response to agent MUST NOT be sent until this returns.
 *
 * The entry's prev_hash and this_hash are computed internally.
 *
 * Returns: log sequence number on success, negative on error.
 */
s64 ak_audit_append(
    u8 *pid,
    u8 *run_id,
    u16 op,
    u8 *req_hash,
    u8 *res_hash,
    u8 *policy_hash
);

/*
 * Convenience: append from request/response structures.
 */
s64 ak_audit_append_request(
    ak_request_t *req,
    ak_response_t *res,
    u8 *policy_hash
);

/*
 * Query log entries.
 *
 * Returns entries matching filter in [start_seq, end_seq].
 * Caller must free returned array.
 */
typedef struct ak_log_query_filter {
    u8 *pid;                    /* NULL = any */
    u8 *run_id;                 /* NULL = any */
    u16 op;                     /* 0 = any */
} ak_log_query_filter_t;

ak_log_entry_t **ak_audit_query(
    heap h,
    ak_log_query_filter_t *filter,
    u64 start_seq,
    u64 end_seq,
    u64 *count_out
);

/*
 * Get current log head sequence number.
 */
u64 ak_audit_head_seq(void);

/*
 * Get current log head hash.
 */
void ak_audit_head_hash(u8 *hash_out);

/* ============================================================
 * LOG VERIFICATION
 * ============================================================
 * CRITICAL for detecting tampering.
 */

/*
 * Verify entire log hash chain.
 *
 * Returns:
 *   0                  - Valid
 *   AK_E_LOG_CORRUPT   - Hash chain broken
 *   Positive value     - Sequence number where corruption detected
 */
s64 ak_audit_verify(void);

/*
 * Verify log segment [start, end].
 *
 * Useful for incremental verification.
 */
s64 ak_audit_verify_range(u64 start_seq, u64 end_seq);

/*
 * Verify single entry against expected previous hash.
 */
boolean ak_audit_verify_entry(ak_log_entry_t *entry, u8 *expected_prev);

/* ============================================================
 * ANCHORING (External Commitments)
 * ============================================================
 * Anchors prevent undetected log rewrite.
 */

/*
 * Emit anchor at current log head.
 *
 * Called automatically every AK_ANCHOR_INTERVAL entries.
 * Also callable manually for important checkpoints.
 */
s64 ak_audit_emit_anchor(void);

/*
 * Get latest anchor.
 */
ak_anchor_t *ak_audit_get_latest_anchor(void);

/*
 * Verify anchor against log.
 */
boolean ak_audit_verify_anchor(ak_anchor_t *anchor);

/*
 * Post anchor to remote service (optional).
 *
 * Failures are logged but don't block execution.
 */
void ak_audit_post_anchor_remote(ak_anchor_t *anchor, const char *url);

/* ============================================================
 * STORAGE
 * ============================================================ */

/*
 * Flush all pending writes to disk.
 *
 * Called automatically on append(), but can be called
 * explicitly for checkpointing.
 */
void ak_audit_sync(void);

/*
 * Get storage statistics.
 */
typedef struct ak_audit_stats {
    u64 entry_count;
    u64 bytes_used;
    u64 anchor_count;
    u64 last_anchor_seq;
    u64 last_sync_ms;
} ak_audit_stats_t;

void ak_audit_get_stats(ak_audit_stats_t *stats);

/* ============================================================
 * HASH COMPUTATION
 * ============================================================ */

/*
 * Compute hash for log entry.
 *
 * hash = SHA256(prev_hash || canonical(entry_without_hashes))
 */
void ak_audit_compute_entry_hash(
    ak_log_entry_t *entry,
    u8 *prev_hash,
    u8 *hash_out
);

/*
 * Compute hash of request/response for logging.
 */
void ak_audit_hash_request(ak_request_t *req, u8 *hash_out);
void ak_audit_hash_response(ak_response_t *res, u8 *hash_out);

/* ============================================================
 * REPLAY SUPPORT
 * ============================================================ */

/*
 * Create replay bundle from log segment.
 *
 * Bundle contains everything needed to replay a run.
 */
typedef struct ak_replay_bundle {
    u8 run_id[AK_TOKEN_ID_SIZE];
    u64 start_seq;
    u64 end_seq;
    ak_log_entry_t **entries;
    u64 entry_count;
    buffer heap_snapshot;       /* Initial heap state */
    u8 policy_hash[AK_HASH_SIZE];
} ak_replay_bundle_t;

ak_replay_bundle_t *ak_audit_create_bundle(
    heap h,
    u8 *run_id,
    u64 start_seq,
    u64 end_seq
);

void ak_audit_destroy_bundle(heap h, ak_replay_bundle_t *bundle);

/* ============================================================
 * SPECIAL ENTRIES
 * ============================================================ */

/*
 * Log capability revocation.
 */
s64 ak_audit_log_revocation(u8 *tid, const char *reason);

/*
 * Log policy change.
 */
s64 ak_audit_log_policy_change(u8 *old_hash, u8 *new_hash, const char *reason);

/*
 * Log agent lifecycle event.
 */
typedef enum ak_lifecycle_event {
    AK_LIFECYCLE_SPAWN,
    AK_LIFECYCLE_EXIT,
    AK_LIFECYCLE_CRASH,
    AK_LIFECYCLE_TIMEOUT,
} ak_lifecycle_event_t;

s64 ak_audit_log_lifecycle(
    u8 *agent_id,
    u8 *run_id,
    ak_lifecycle_event_t event
);

#endif /* AK_AUDIT_H */
