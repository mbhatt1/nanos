/*
 * Authority Kernel - Audit Log Unit Tests
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Comprehensive tests for INV-4 (Log Commitment Invariant) enforcement:
 * - Hash chain integrity
 * - Append-only semantics
 * - Tamper detection
 * - Log verification
 * - Anchor system
 * - Query functionality
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
 * AUDIT TYPES (matching ak_audit.h)
 * ============================================================ */

#define AK_HASH_SIZE        32
#define AK_TOKEN_ID_SIZE    16

/* Error codes */
#define AK_E_LOG_FULL       -4500
#define AK_E_LOG_CORRUPT    -4501
#define AK_E_LOG_NOT_FOUND  -4502

/* Genesis hash - all zeros */
static const uint8_t AK_GENESIS_HASH[AK_HASH_SIZE] = {0};

typedef struct ak_log_entry {
    uint64_t seq;
    uint64_t ts_ms;
    uint16_t op;
    uint8_t pid[AK_TOKEN_ID_SIZE];
    uint8_t run_id[AK_TOKEN_ID_SIZE];
    uint8_t req_hash[AK_HASH_SIZE];
    uint8_t res_hash[AK_HASH_SIZE];
    uint8_t policy_hash[AK_HASH_SIZE];
    uint8_t prev_hash[AK_HASH_SIZE];
    uint8_t this_hash[AK_HASH_SIZE];
} ak_log_entry_t;

typedef struct ak_anchor {
    uint64_t ts_ms;
    uint64_t log_seq;
    uint8_t log_hash[AK_HASH_SIZE];
    uint8_t policy_hash[AK_HASH_SIZE];
    uint8_t signature[64];
} ak_anchor_t;

/* ============================================================
 * MOCK AUDIT LOG IMPLEMENTATION
 * ============================================================ */

#define MAX_LOG_ENTRIES 1000
#define MAX_ANCHORS 100

static struct {
    ak_log_entry_t entries[MAX_LOG_ENTRIES];
    uint64_t entry_count;
    uint8_t head_hash[AK_HASH_SIZE];

    ak_anchor_t anchors[MAX_ANCHORS];
    uint32_t anchor_count;

    uint64_t current_time_ms;
    bool initialized;
} mock_log;

/* Simple hash function for testing */
static void test_sha256(const uint8_t *data, uint32_t len, uint8_t *output)
{
    uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

    for (uint32_t i = 0; i < len; i++) {
        h[i % 8] ^= ((uint32_t)data[i] << ((i % 4) * 8));
        h[(i + 1) % 8] += h[i % 8];
        h[(i + 2) % 8] ^= h[(i + 3) % 8] >> 13;
    }

    for (int i = 0; i < 8; i++) {
        output[i*4] = (h[i] >> 24) & 0xFF;
        output[i*4+1] = (h[i] >> 16) & 0xFF;
        output[i*4+2] = (h[i] >> 8) & 0xFF;
        output[i*4+3] = h[i] & 0xFF;
    }
}

static void mock_log_init(void)
{
    memset(&mock_log, 0, sizeof(mock_log));
    memcpy(mock_log.head_hash, AK_GENESIS_HASH, AK_HASH_SIZE);
    mock_log.current_time_ms = 1000000;
    mock_log.initialized = true;
}

/* Compute canonical entry representation */
static int canonicalize_entry(ak_log_entry_t *entry, uint8_t *buf, size_t buf_len)
{
    int pos = 0;
    pos += snprintf((char *)buf + pos, buf_len - pos, "{\"seq\":%llu,\"ts_ms\":%llu,\"op\":%u,",
                    (unsigned long long)entry->seq, (unsigned long long)entry->ts_ms, entry->op);

    pos += snprintf((char *)buf + pos, buf_len - pos, "\"pid\":\"");
    for (int i = 0; i < AK_TOKEN_ID_SIZE && pos < (int)buf_len - 3; i++) {
        pos += snprintf((char *)buf + pos, buf_len - pos, "%02x", entry->pid[i]);
    }
    pos += snprintf((char *)buf + pos, buf_len - pos, "\",");

    pos += snprintf((char *)buf + pos, buf_len - pos, "\"req_hash\":\"");
    for (int i = 0; i < AK_HASH_SIZE && pos < (int)buf_len - 3; i++) {
        pos += snprintf((char *)buf + pos, buf_len - pos, "%02x", entry->req_hash[i]);
    }
    pos += snprintf((char *)buf + pos, buf_len - pos, "\"}");

    return pos;
}

/* Compute entry hash: SHA256(prev_hash || canonical(entry)) */
static void compute_entry_hash(ak_log_entry_t *entry, uint8_t *prev_hash, uint8_t *hash_out)
{
    uint8_t canonical[1024];
    int len = canonicalize_entry(entry, canonical, sizeof(canonical));

    uint8_t combined[AK_HASH_SIZE + 1024];
    memcpy(combined, prev_hash, AK_HASH_SIZE);
    memcpy(combined + AK_HASH_SIZE, canonical, len);

    test_sha256(combined, AK_HASH_SIZE + len, hash_out);
}

/* Append entry to log */
static int64_t mock_log_append(uint8_t *pid, uint8_t *run_id, uint16_t op,
                                uint8_t *req_hash, uint8_t *res_hash, uint8_t *policy_hash)
{
    if (!mock_log.initialized) return -1;
    if (mock_log.entry_count >= MAX_LOG_ENTRIES) return AK_E_LOG_FULL;

    ak_log_entry_t *entry = &mock_log.entries[mock_log.entry_count];

    entry->seq = mock_log.entry_count + 1;
    entry->ts_ms = mock_log.current_time_ms++;
    entry->op = op;

    memcpy(entry->pid, pid, AK_TOKEN_ID_SIZE);
    memcpy(entry->run_id, run_id, AK_TOKEN_ID_SIZE);
    memcpy(entry->req_hash, req_hash, AK_HASH_SIZE);
    memcpy(entry->res_hash, res_hash, AK_HASH_SIZE);
    memcpy(entry->policy_hash, policy_hash, AK_HASH_SIZE);

    /* Chain from previous */
    memcpy(entry->prev_hash, mock_log.head_hash, AK_HASH_SIZE);
    compute_entry_hash(entry, entry->prev_hash, entry->this_hash);

    /* Update head */
    memcpy(mock_log.head_hash, entry->this_hash, AK_HASH_SIZE);
    mock_log.entry_count++;

    return entry->seq;
}

/* Verify hash chain */
static int64_t mock_log_verify(uint64_t start_seq, uint64_t end_seq)
{
    if (start_seq == 0 || end_seq < start_seq) return -1;
    if (end_seq > mock_log.entry_count) end_seq = mock_log.entry_count;

    uint8_t expected_hash[AK_HASH_SIZE];

    /* Get starting hash */
    if (start_seq == 1) {
        memcpy(expected_hash, AK_GENESIS_HASH, AK_HASH_SIZE);
    } else {
        memcpy(expected_hash, mock_log.entries[start_seq - 2].this_hash, AK_HASH_SIZE);
    }

    /* Verify each entry */
    for (uint64_t i = start_seq - 1; i < end_seq; i++) {
        ak_log_entry_t *entry = &mock_log.entries[i];

        /* Check prev_hash matches expected */
        if (memcmp(entry->prev_hash, expected_hash, AK_HASH_SIZE) != 0) {
            return i + 1;  /* Return sequence number of bad entry */
        }

        /* Recompute this_hash */
        uint8_t computed_hash[AK_HASH_SIZE];
        compute_entry_hash(entry, entry->prev_hash, computed_hash);

        if (memcmp(entry->this_hash, computed_hash, AK_HASH_SIZE) != 0) {
            return i + 1;
        }

        memcpy(expected_hash, entry->this_hash, AK_HASH_SIZE);
    }

    return 0;  /* Valid */
}

/* Get entry by sequence number */
static ak_log_entry_t *mock_log_get(uint64_t seq)
{
    if (seq == 0 || seq > mock_log.entry_count) return NULL;
    return &mock_log.entries[seq - 1];
}

/* Create anchor */
static int64_t mock_log_anchor(void)
{
    if (mock_log.anchor_count >= MAX_ANCHORS) return AK_E_LOG_FULL;

    ak_anchor_t *anchor = &mock_log.anchors[mock_log.anchor_count];
    anchor->ts_ms = mock_log.current_time_ms;
    anchor->log_seq = mock_log.entry_count;
    memcpy(anchor->log_hash, mock_log.head_hash, AK_HASH_SIZE);

    mock_log.anchor_count++;
    return anchor->log_seq;
}

/* Verify anchor */
static bool mock_log_verify_anchor(ak_anchor_t *anchor)
{
    if (!anchor) return false;
    if (anchor->log_seq == 0 || anchor->log_seq > mock_log.entry_count) return false;

    ak_log_entry_t *entry = &mock_log.entries[anchor->log_seq - 1];
    return memcmp(entry->this_hash, anchor->log_hash, AK_HASH_SIZE) == 0;
}

/* ============================================================
 * TEST CASES: BASIC LOG OPERATIONS
 * ============================================================ */

bool test_audit_init(void)
{
    mock_log_init();

    test_assert(mock_log.initialized);
    test_assert_eq(mock_log.entry_count, 0);
    test_assert(memcmp(mock_log.head_hash, AK_GENESIS_HASH, AK_HASH_SIZE) == 0);

    return true;
}

bool test_audit_append_single(void)
{
    mock_log_init();

    uint8_t pid[AK_TOKEN_ID_SIZE] = {1};
    uint8_t run_id[AK_TOKEN_ID_SIZE] = {2};
    uint8_t req_hash[AK_HASH_SIZE] = {3};
    uint8_t res_hash[AK_HASH_SIZE] = {4};
    uint8_t policy_hash[AK_HASH_SIZE] = {5};

    int64_t seq = mock_log_append(pid, run_id, 0x0100, req_hash, res_hash, policy_hash);

    test_assert_eq(seq, 1);
    test_assert_eq(mock_log.entry_count, 1);

    ak_log_entry_t *entry = mock_log_get(1);
    test_assert(entry != NULL);
    test_assert_eq(entry->seq, 1);
    test_assert_eq(entry->op, 0x0100);
    test_assert(memcmp(entry->pid, pid, AK_TOKEN_ID_SIZE) == 0);

    return true;
}

bool test_audit_append_multiple(void)
{
    mock_log_init();

    uint8_t pid[AK_TOKEN_ID_SIZE] = {1};
    uint8_t run_id[AK_TOKEN_ID_SIZE] = {2};
    uint8_t hash[AK_HASH_SIZE] = {0};

    for (int i = 0; i < 100; i++) {
        hash[0] = i;
        int64_t seq = mock_log_append(pid, run_id, i, hash, hash, hash);
        test_assert_eq(seq, i + 1);
    }

    test_assert_eq(mock_log.entry_count, 100);

    return true;
}

bool test_audit_sequence_numbers(void)
{
    mock_log_init();

    uint8_t dummy[AK_HASH_SIZE] = {0};

    for (int i = 0; i < 50; i++) {
        int64_t seq = mock_log_append(dummy, dummy, i, dummy, dummy, dummy);
        test_assert_eq(seq, i + 1);

        ak_log_entry_t *entry = mock_log_get(seq);
        test_assert(entry != NULL);
        test_assert_eq(entry->seq, (uint64_t)(i + 1));
    }

    return true;
}

/* ============================================================
 * TEST CASES: HASH CHAIN INTEGRITY
 * ============================================================ */

bool test_audit_hash_chain_genesis(void)
{
    mock_log_init();

    uint8_t dummy[AK_HASH_SIZE] = {0};
    mock_log_append(dummy, dummy, 0, dummy, dummy, dummy);

    ak_log_entry_t *entry = mock_log_get(1);
    test_assert(entry != NULL);

    /* First entry's prev_hash should be genesis */
    test_assert(memcmp(entry->prev_hash, AK_GENESIS_HASH, AK_HASH_SIZE) == 0);

    return true;
}

bool test_audit_hash_chain_links(void)
{
    mock_log_init();

    uint8_t dummy[AK_HASH_SIZE] = {0};

    for (int i = 0; i < 10; i++) {
        mock_log_append(dummy, dummy, i, dummy, dummy, dummy);
    }

    /* Verify each entry links to previous */
    for (uint64_t i = 2; i <= mock_log.entry_count; i++) {
        ak_log_entry_t *curr = mock_log_get(i);
        ak_log_entry_t *prev = mock_log_get(i - 1);

        test_assert(curr != NULL);
        test_assert(prev != NULL);
        test_assert(memcmp(curr->prev_hash, prev->this_hash, AK_HASH_SIZE) == 0);
    }

    return true;
}

bool test_audit_hash_chain_verify_valid(void)
{
    mock_log_init();

    uint8_t dummy[AK_HASH_SIZE] = {0};

    for (int i = 0; i < 50; i++) {
        mock_log_append(dummy, dummy, i, dummy, dummy, dummy);
    }

    int64_t result = mock_log_verify(1, 50);
    test_assert_eq(result, 0);

    return true;
}

bool test_audit_hash_chain_verify_partial(void)
{
    mock_log_init();

    uint8_t dummy[AK_HASH_SIZE] = {0};

    for (int i = 0; i < 100; i++) {
        mock_log_append(dummy, dummy, i, dummy, dummy, dummy);
    }

    /* Verify middle range */
    int64_t result = mock_log_verify(25, 75);
    test_assert_eq(result, 0);

    return true;
}

/* ============================================================
 * TEST CASES: TAMPER DETECTION
 * ============================================================ */

bool test_audit_tamper_detect_single_bit(void)
{
    mock_log_init();

    uint8_t dummy[AK_HASH_SIZE] = {0};

    for (int i = 0; i < 10; i++) {
        mock_log_append(dummy, dummy, i, dummy, dummy, dummy);
    }

    /* Tamper with entry 5 - flip single bit in this_hash */
    mock_log.entries[4].this_hash[0] ^= 0x01;

    /* Verification should fail at entry 5 or 6 */
    int64_t result = mock_log_verify(1, 10);
    test_assert(result == 5 || result == 6);

    return true;
}

bool test_audit_tamper_detect_modified_data(void)
{
    mock_log_init();

    uint8_t dummy[AK_HASH_SIZE] = {0};

    for (int i = 0; i < 10; i++) {
        mock_log_append(dummy, dummy, i, dummy, dummy, dummy);
    }

    /* Tamper with entry 3 - modify op code */
    mock_log.entries[2].op = 0xFFFF;

    /* Verification should fail at entry 3 (hash won't match) */
    int64_t result = mock_log_verify(1, 10);
    test_assert_eq(result, 3);

    return true;
}

bool test_audit_tamper_detect_chain_break(void)
{
    mock_log_init();

    uint8_t dummy[AK_HASH_SIZE] = {0};

    for (int i = 0; i < 10; i++) {
        mock_log_append(dummy, dummy, i, dummy, dummy, dummy);
    }

    /* Break the chain - modify prev_hash of entry 7 */
    mock_log.entries[6].prev_hash[0] ^= 0xFF;

    /* Verification should fail at entry 7 */
    int64_t result = mock_log_verify(1, 10);
    test_assert_eq(result, 7);

    return true;
}

bool test_audit_tamper_detect_swap_entries(void)
{
    mock_log_init();

    uint8_t dummy[AK_HASH_SIZE] = {0};

    for (int i = 0; i < 10; i++) {
        dummy[0] = i;  /* Different data per entry */
        mock_log_append(dummy, dummy, i, dummy, dummy, dummy);
    }

    /* Swap entries 4 and 5 */
    ak_log_entry_t temp = mock_log.entries[3];
    mock_log.entries[3] = mock_log.entries[4];
    mock_log.entries[4] = temp;

    /* Verification should fail */
    int64_t result = mock_log_verify(1, 10);
    test_assert(result > 0);

    return true;
}

bool test_audit_tamper_detect_deletion(void)
{
    mock_log_init();

    uint8_t dummy[AK_HASH_SIZE] = {0};

    for (int i = 0; i < 10; i++) {
        mock_log_append(dummy, dummy, i, dummy, dummy, dummy);
    }

    /* "Delete" entry 5 by shifting entries */
    for (int i = 4; i < 9; i++) {
        mock_log.entries[i] = mock_log.entries[i + 1];
    }
    mock_log.entry_count--;

    /* Verification should fail */
    int64_t result = mock_log_verify(1, mock_log.entry_count);
    test_assert(result > 0);

    return true;
}

bool test_audit_tamper_detect_insertion(void)
{
    mock_log_init();

    uint8_t dummy[AK_HASH_SIZE] = {0};

    for (int i = 0; i < 10; i++) {
        mock_log_append(dummy, dummy, i, dummy, dummy, dummy);
    }

    /* "Insert" entry by shifting and creating fake entry */
    mock_log.entry_count++;
    for (int i = mock_log.entry_count - 1; i > 5; i--) {
        mock_log.entries[i] = mock_log.entries[i - 1];
    }

    /* Create fake entry at position 5 */
    memset(&mock_log.entries[5], 0x42, sizeof(ak_log_entry_t));

    /* Verification should fail */
    int64_t result = mock_log_verify(1, mock_log.entry_count);
    test_assert(result > 0);

    return true;
}

/* ============================================================
 * TEST CASES: ANCHORING
 * ============================================================ */

bool test_audit_anchor_create(void)
{
    mock_log_init();

    uint8_t dummy[AK_HASH_SIZE] = {0};

    for (int i = 0; i < 100; i++) {
        mock_log_append(dummy, dummy, i, dummy, dummy, dummy);
    }

    int64_t anchor_seq = mock_log_anchor();
    test_assert_eq(anchor_seq, 100);
    test_assert_eq(mock_log.anchor_count, 1);

    return true;
}

bool test_audit_anchor_verify_valid(void)
{
    mock_log_init();

    uint8_t dummy[AK_HASH_SIZE] = {0};

    for (int i = 0; i < 100; i++) {
        mock_log_append(dummy, dummy, i, dummy, dummy, dummy);
    }

    mock_log_anchor();

    /* Anchor should be valid */
    test_assert(mock_log_verify_anchor(&mock_log.anchors[0]));

    return true;
}

bool test_audit_anchor_verify_after_more_entries(void)
{
    mock_log_init();

    uint8_t dummy[AK_HASH_SIZE] = {0};

    for (int i = 0; i < 100; i++) {
        mock_log_append(dummy, dummy, i, dummy, dummy, dummy);
    }

    mock_log_anchor();

    /* Add more entries */
    for (int i = 0; i < 50; i++) {
        mock_log_append(dummy, dummy, i, dummy, dummy, dummy);
    }

    /* Anchor should still be valid (points to entry 100) */
    test_assert(mock_log_verify_anchor(&mock_log.anchors[0]));

    return true;
}

bool test_audit_anchor_verify_tampered(void)
{
    mock_log_init();

    uint8_t dummy[AK_HASH_SIZE] = {0};

    for (int i = 0; i < 100; i++) {
        mock_log_append(dummy, dummy, i, dummy, dummy, dummy);
    }

    mock_log_anchor();

    /* Tamper with anchor's log_hash */
    mock_log.anchors[0].log_hash[0] ^= 0xFF;

    /* Anchor should no longer be valid */
    test_assert(!mock_log_verify_anchor(&mock_log.anchors[0]));

    return true;
}

bool test_audit_multiple_anchors(void)
{
    mock_log_init();

    uint8_t dummy[AK_HASH_SIZE] = {0};

    for (int i = 0; i < 50; i++) {
        mock_log_append(dummy, dummy, i, dummy, dummy, dummy);
    }
    mock_log_anchor();

    for (int i = 0; i < 50; i++) {
        mock_log_append(dummy, dummy, i, dummy, dummy, dummy);
    }
    mock_log_anchor();

    for (int i = 0; i < 50; i++) {
        mock_log_append(dummy, dummy, i, dummy, dummy, dummy);
    }
    mock_log_anchor();

    test_assert_eq(mock_log.anchor_count, 3);
    test_assert_eq(mock_log.anchors[0].log_seq, 50);
    test_assert_eq(mock_log.anchors[1].log_seq, 100);
    test_assert_eq(mock_log.anchors[2].log_seq, 150);

    /* All anchors should be valid */
    for (int i = 0; i < 3; i++) {
        test_assert(mock_log_verify_anchor(&mock_log.anchors[i]));
    }

    return true;
}

/* ============================================================
 * TEST CASES: QUERY FUNCTIONALITY
 * ============================================================ */

bool test_audit_query_by_seq(void)
{
    mock_log_init();

    uint8_t dummy[AK_HASH_SIZE] = {0};

    for (int i = 0; i < 100; i++) {
        mock_log_append(dummy, dummy, i, dummy, dummy, dummy);
    }

    /* Query specific entries */
    for (int i = 1; i <= 100; i++) {
        ak_log_entry_t *entry = mock_log_get(i);
        test_assert(entry != NULL);
        test_assert_eq(entry->seq, (uint64_t)i);
    }

    return true;
}

bool test_audit_query_invalid_seq(void)
{
    mock_log_init();

    uint8_t dummy[AK_HASH_SIZE] = {0};

    for (int i = 0; i < 10; i++) {
        mock_log_append(dummy, dummy, i, dummy, dummy, dummy);
    }

    /* Query out of range */
    test_assert(mock_log_get(0) == NULL);
    test_assert(mock_log_get(11) == NULL);
    test_assert(mock_log_get(1000) == NULL);

    return true;
}

/* ============================================================
 * TEST CASES: EDGE CASES
 * ============================================================ */

bool test_audit_empty_log_verify(void)
{
    mock_log_init();

    /* Verify empty log - should succeed (no entries to verify) */
    int64_t result = mock_log_verify(1, 0);
    test_assert_eq(result, -1);  /* Invalid range */

    return true;
}

bool test_audit_log_full(void)
{
    mock_log_init();

    uint8_t dummy[AK_HASH_SIZE] = {0};

    /* Fill the log */
    for (int i = 0; i < MAX_LOG_ENTRIES; i++) {
        int64_t seq = mock_log_append(dummy, dummy, i, dummy, dummy, dummy);
        test_assert(seq > 0);
    }

    /* Next append should fail */
    int64_t seq = mock_log_append(dummy, dummy, 0, dummy, dummy, dummy);
    test_assert_eq(seq, AK_E_LOG_FULL);

    return true;
}

bool test_audit_large_entries(void)
{
    mock_log_init();

    uint8_t large_data[AK_HASH_SIZE];
    for (int i = 0; i < AK_HASH_SIZE; i++) {
        large_data[i] = (uint8_t)(i * 17 + 13);
    }

    /* Append entries with varied data */
    for (int i = 0; i < 100; i++) {
        large_data[0] = i;
        int64_t seq = mock_log_append(large_data, large_data, i, large_data, large_data, large_data);
        test_assert_eq(seq, i + 1);
    }

    /* Verify chain */
    int64_t result = mock_log_verify(1, 100);
    test_assert_eq(result, 0);

    return true;
}

bool test_audit_all_operations_logged(void)
{
    mock_log_init();

    uint8_t dummy[AK_HASH_SIZE] = {0};

    /* Log various operation types */
    uint16_t ops[] = {0x0100, 0x0101, 0x0200, 0x0201, 0x0300, 0x0400, 0x0401, 0x0402};

    for (int i = 0; i < 8; i++) {
        mock_log_append(dummy, dummy, ops[i], dummy, dummy, dummy);
    }

    /* Verify all were logged correctly */
    for (int i = 0; i < 8; i++) {
        ak_log_entry_t *entry = mock_log_get(i + 1);
        test_assert(entry != NULL);
        test_assert_eq(entry->op, ops[i]);
    }

    return true;
}

/* ============================================================
 * TEST CASES: CONCURRENCY SIMULATION
 * ============================================================ */

bool test_audit_sequential_consistency(void)
{
    mock_log_init();

    uint8_t dummy[AK_HASH_SIZE] = {0};

    /* Simulate concurrent appends (in reality sequential, but tests logic) */
    for (int thread = 0; thread < 10; thread++) {
        for (int i = 0; i < 10; i++) {
            dummy[0] = thread;
            dummy[1] = i;
            int64_t seq = mock_log_append(dummy, dummy, thread * 10 + i, dummy, dummy, dummy);
            test_assert(seq > 0);
        }
    }

    /* All entries should form valid chain */
    int64_t result = mock_log_verify(1, 100);
    test_assert_eq(result, 0);

    /* Sequence numbers should be unique and increasing */
    for (uint64_t i = 1; i <= 100; i++) {
        ak_log_entry_t *entry = mock_log_get(i);
        test_assert(entry != NULL);
        test_assert_eq(entry->seq, i);
    }

    return true;
}

/* ============================================================
 * TEST CASES: HASH UNIQUENESS
 * ============================================================ */

bool test_audit_hash_uniqueness(void)
{
    mock_log_init();

    uint8_t dummy[AK_HASH_SIZE] = {0};

    for (int i = 0; i < 100; i++) {
        dummy[0] = i;
        mock_log_append(dummy, dummy, i, dummy, dummy, dummy);
    }

    /* All this_hash values should be unique */
    for (int i = 0; i < 100; i++) {
        for (int j = i + 1; j < 100; j++) {
            test_assert(memcmp(mock_log.entries[i].this_hash,
                               mock_log.entries[j].this_hash,
                               AK_HASH_SIZE) != 0);
        }
    }

    return true;
}

bool test_audit_same_content_different_position(void)
{
    mock_log_init();

    uint8_t same_data[AK_HASH_SIZE] = {42};

    /* Append same data twice */
    mock_log_append(same_data, same_data, 0, same_data, same_data, same_data);
    mock_log_append(same_data, same_data, 0, same_data, same_data, same_data);

    /* Hashes should be different due to position in chain */
    test_assert(memcmp(mock_log.entries[0].this_hash,
                       mock_log.entries[1].this_hash,
                       AK_HASH_SIZE) != 0);

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
    /* Basic operations */
    {"audit_init", test_audit_init},
    {"audit_append_single", test_audit_append_single},
    {"audit_append_multiple", test_audit_append_multiple},
    {"audit_sequence_numbers", test_audit_sequence_numbers},

    /* Hash chain integrity */
    {"audit_hash_chain_genesis", test_audit_hash_chain_genesis},
    {"audit_hash_chain_links", test_audit_hash_chain_links},
    {"audit_hash_chain_verify_valid", test_audit_hash_chain_verify_valid},
    {"audit_hash_chain_verify_partial", test_audit_hash_chain_verify_partial},

    /* Tamper detection */
    {"audit_tamper_detect_single_bit", test_audit_tamper_detect_single_bit},
    {"audit_tamper_detect_modified_data", test_audit_tamper_detect_modified_data},
    {"audit_tamper_detect_chain_break", test_audit_tamper_detect_chain_break},
    {"audit_tamper_detect_swap_entries", test_audit_tamper_detect_swap_entries},
    {"audit_tamper_detect_deletion", test_audit_tamper_detect_deletion},
    {"audit_tamper_detect_insertion", test_audit_tamper_detect_insertion},

    /* Anchoring */
    {"audit_anchor_create", test_audit_anchor_create},
    {"audit_anchor_verify_valid", test_audit_anchor_verify_valid},
    {"audit_anchor_verify_after_more_entries", test_audit_anchor_verify_after_more_entries},
    {"audit_anchor_verify_tampered", test_audit_anchor_verify_tampered},
    {"audit_multiple_anchors", test_audit_multiple_anchors},

    /* Query functionality */
    {"audit_query_by_seq", test_audit_query_by_seq},
    {"audit_query_invalid_seq", test_audit_query_invalid_seq},

    /* Edge cases */
    {"audit_empty_log_verify", test_audit_empty_log_verify},
    {"audit_log_full", test_audit_log_full},
    {"audit_large_entries", test_audit_large_entries},
    {"audit_all_operations_logged", test_audit_all_operations_logged},

    /* Concurrency simulation */
    {"audit_sequential_consistency", test_audit_sequential_consistency},

    /* Hash uniqueness */
    {"audit_hash_uniqueness", test_audit_hash_uniqueness},
    {"audit_same_content_different_position", test_audit_same_content_different_position},

    {NULL, NULL}
};

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    int passed = 0;
    int failed = 0;

    printf("=== AK Audit Log Tests ===\n\n");

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
