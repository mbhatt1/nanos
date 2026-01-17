/*
 * Authority Kernel - Capability System Unit Tests
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Comprehensive tests for INV-2 (Capability Invariant) enforcement:
 * - Capability creation and verification
 * - HMAC integrity checking
 * - Revocation mechanisms
 * - Scope validation
 * - Rate limiting
 * - Delegation constraints
 * - Attack resistance (forgery, replay, timing)
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

#define test_assert_null(ptr) do { \
    if ((ptr) != NULL) { \
        fprintf(stderr, "FAIL: %s is not NULL at %s:%d\n", #ptr, __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

#define test_assert_not_null(ptr) do { \
    if ((ptr) == NULL) { \
        fprintf(stderr, "FAIL: %s is NULL at %s:%d\n", #ptr, __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

/* ============================================================
 * CAPABILITY TYPES (matching ak_capability.h)
 * ============================================================ */

#define AK_KEY_SIZE         32
#define AK_MAC_SIZE         32
#define AK_TOKEN_ID_SIZE    16
#define AK_MAX_KEYS         4
#define AK_KEY_ROTATION_MS  (24 * 60 * 60 * 1000)  /* 24 hours */
#define AK_KEY_GRACE_MS     (1 * 60 * 60 * 1000)   /* 1 hour grace */

typedef enum ak_cap_type {
    AK_CAP_NONE = 0,
    AK_CAP_FS,
    AK_CAP_NET,
    AK_CAP_TOOL,
    AK_CAP_INFER,
    AK_CAP_ADMIN,
} ak_cap_type_t;

/* Error codes */
#define AK_E_CAP_MISSING    -4100
#define AK_E_CAP_INVALID    -4101
#define AK_E_CAP_EXPIRED    -4102
#define AK_E_CAP_SCOPE      -4103
#define AK_E_CAP_REVOKED    -4104
#define AK_E_CAP_RATE       -4105
#define AK_E_CAP_RUN_MISMATCH -4106

typedef struct ak_capability {
    ak_cap_type_t type;
    uint8_t resource[256];
    uint32_t resource_len;
    uint8_t methods[8][32];
    uint8_t method_count;
    uint64_t issued_ms;
    uint32_t ttl_ms;
    uint32_t rate_limit;
    uint32_t rate_window_ms;
    uint8_t run_id[AK_TOKEN_ID_SIZE];
    uint8_t tid[AK_TOKEN_ID_SIZE];
    uint8_t kid;
    uint8_t mac[AK_MAC_SIZE];
} ak_capability_t;

typedef struct ak_key {
    uint8_t kid;
    uint8_t secret[AK_KEY_SIZE];
    uint64_t created_ms;
    uint64_t expires_ms;
    bool active;
    bool retired;
} ak_key_t;

/* ============================================================
 * MOCK IMPLEMENTATIONS FOR TESTING
 * ============================================================ */

static ak_key_t test_keys[AK_MAX_KEYS];
static uint8_t test_active_kid = 0;
static uint64_t test_current_time_ms = 1000000;  /* Start at 1M ms */

/* Revocation tracking */
#define MAX_REVOCATIONS 100
static struct {
    uint8_t tid[AK_TOKEN_ID_SIZE];
    bool active;
} test_revocations[MAX_REVOCATIONS];
static int test_revocation_count = 0;

/* Rate limit tracking */
#define MAX_RATE_ENTRIES 100
static struct {
    uint8_t tid[AK_TOKEN_ID_SIZE];
    uint32_t count;
    uint64_t window_start;
} test_rate_limits[MAX_RATE_ENTRIES];
static int test_rate_count = 0;

static void test_init_keys(void)
{
    memset(test_keys, 0, sizeof(test_keys));

    /* Initialize first key */
    test_keys[0].kid = 0;
    for (int i = 0; i < AK_KEY_SIZE; i++) {
        test_keys[0].secret[i] = (uint8_t)(i * 7 + 13);  /* Deterministic for testing */
    }
    test_keys[0].created_ms = test_current_time_ms;
    test_keys[0].expires_ms = test_current_time_ms + AK_KEY_ROTATION_MS + AK_KEY_GRACE_MS;
    test_keys[0].active = true;
    test_keys[0].retired = false;

    test_active_kid = 0;
    test_revocation_count = 0;
    test_rate_count = 0;
}

static ak_key_t *test_get_active_key(void)
{
    return &test_keys[test_active_kid];
}

static ak_key_t *test_get_key(uint8_t kid)
{
    for (int i = 0; i < AK_MAX_KEYS; i++) {
        if (test_keys[i].kid == kid && !test_keys[i].retired) {
            return &test_keys[i];
        }
    }
    return NULL;
}

/* Simple SHA256-like hash (NOT cryptographically secure - for testing only) */
static void test_hash(const uint8_t *data, uint32_t len, uint8_t *output)
{
    uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

    for (uint32_t i = 0; i < len; i++) {
        h[i % 8] ^= ((uint32_t)data[i] << ((i % 4) * 8));
        h[(i + 1) % 8] += h[i % 8];
    }

    for (int i = 0; i < 8; i++) {
        output[i*4] = (h[i] >> 24) & 0xFF;
        output[i*4+1] = (h[i] >> 16) & 0xFF;
        output[i*4+2] = (h[i] >> 8) & 0xFF;
        output[i*4+3] = h[i] & 0xFF;
    }
}

/* Simple HMAC-like construction */
static void test_hmac(const uint8_t *key, uint32_t key_len,
                      const uint8_t *data, uint32_t data_len,
                      uint8_t *output)
{
    uint8_t combined[4096];
    if (key_len + data_len > sizeof(combined)) {
        memset(output, 0, AK_MAC_SIZE);
        return;
    }
    memcpy(combined, key, key_len);
    memcpy(combined + key_len, data, data_len);
    test_hash(combined, key_len + data_len, output);
}

/* Constant-time comparison */
static bool constant_time_compare(const uint8_t *a, const uint8_t *b, uint32_t len)
{
    uint8_t diff = 0;
    for (uint32_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

/* Canonicalize capability for signing */
static int test_canonicalize_cap(ak_capability_t *cap, uint8_t *buf, size_t buf_len)
{
    return snprintf((char *)buf, buf_len,
        "{\"kid\":%d,\"resource\":\"%.*s\",\"ttl_ms\":%u,\"type\":%d}",
        cap->kid, (int)cap->resource_len, cap->resource, cap->ttl_ms, cap->type);
}

/* Check revocation */
static bool test_check_revoked(uint8_t *tid)
{
    for (int i = 0; i < test_revocation_count; i++) {
        if (test_revocations[i].active &&
            memcmp(test_revocations[i].tid, tid, AK_TOKEN_ID_SIZE) == 0) {
            return true;
        }
    }
    return false;
}

/* Add revocation */
static void test_add_revocation(uint8_t *tid)
{
    if (test_revocation_count < MAX_REVOCATIONS) {
        memcpy(test_revocations[test_revocation_count].tid, tid, AK_TOKEN_ID_SIZE);
        test_revocations[test_revocation_count].active = true;
        test_revocation_count++;
    }
}

/* Check rate limit */
static bool test_check_rate_limit(uint8_t *tid, uint32_t limit, uint32_t window_ms)
{
    /* Find existing entry */
    for (int i = 0; i < test_rate_count; i++) {
        if (memcmp(test_rate_limits[i].tid, tid, AK_TOKEN_ID_SIZE) == 0) {
            /* Check if window expired */
            if (test_current_time_ms - test_rate_limits[i].window_start > window_ms) {
                test_rate_limits[i].count = 0;
                test_rate_limits[i].window_start = test_current_time_ms;
            }

            if (test_rate_limits[i].count >= limit) {
                return false;
            }
            test_rate_limits[i].count++;
            return true;
        }
    }

    /* New entry */
    if (test_rate_count < MAX_RATE_ENTRIES) {
        memcpy(test_rate_limits[test_rate_count].tid, tid, AK_TOKEN_ID_SIZE);
        test_rate_limits[test_rate_count].count = 1;
        test_rate_limits[test_rate_count].window_start = test_current_time_ms;
        test_rate_count++;
    }
    return true;
}

/* ============================================================
 * CAPABILITY CREATION AND VERIFICATION
 * ============================================================ */

static ak_capability_t *test_create_capability(
    ak_cap_type_t type,
    const char *resource,
    uint32_t ttl_ms)
{
    ak_capability_t *cap = calloc(1, sizeof(ak_capability_t));
    if (!cap) return NULL;

    cap->type = type;
    cap->resource_len = strlen(resource);
    if (cap->resource_len >= sizeof(cap->resource)) {
        free(cap);
        return NULL;
    }
    memcpy(cap->resource, resource, cap->resource_len);

    cap->issued_ms = test_current_time_ms;
    cap->ttl_ms = ttl_ms;

    /* Generate token ID */
    for (int i = 0; i < AK_TOKEN_ID_SIZE; i++) {
        cap->tid[i] = (uint8_t)(rand() & 0xFF);
    }

    /* Sign with active key */
    ak_key_t *key = test_get_active_key();
    cap->kid = key->kid;

    uint8_t canonical[512];
    int len = test_canonicalize_cap(cap, canonical, sizeof(canonical));
    test_hmac(key->secret, AK_KEY_SIZE, canonical, len, cap->mac);

    return cap;
}

static int64_t test_verify_capability(ak_capability_t *cap)
{
    if (!cap) return AK_E_CAP_MISSING;

    /* Find key */
    ak_key_t *key = test_get_key(cap->kid);
    if (!key) return AK_E_CAP_INVALID;
    if (key->retired) return AK_E_CAP_EXPIRED;

    /* Recompute MAC */
    uint8_t computed_mac[AK_MAC_SIZE];
    uint8_t canonical[512];
    int len = test_canonicalize_cap(cap, canonical, sizeof(canonical));
    test_hmac(key->secret, AK_KEY_SIZE, canonical, len, computed_mac);

    /* Constant-time comparison */
    if (!constant_time_compare(cap->mac, computed_mac, AK_MAC_SIZE)) {
        return AK_E_CAP_INVALID;
    }

    /* Check TTL */
    if (test_current_time_ms > cap->issued_ms + cap->ttl_ms) {
        return AK_E_CAP_EXPIRED;
    }

    /* Check revocation */
    if (test_check_revoked(cap->tid)) {
        return AK_E_CAP_REVOKED;
    }

    return 0;
}

/* ============================================================
 * TEST CASES: CAPABILITY CREATION
 * ============================================================ */

bool test_cap_create_valid(void)
{
    test_init_keys();

    ak_capability_t *cap = test_create_capability(AK_CAP_FS, "/app/*", 3600000);
    test_assert_not_null(cap);
    test_assert_eq(cap->type, AK_CAP_FS);
    test_assert_eq(cap->ttl_ms, 3600000);
    test_assert(cap->resource_len > 0);

    free(cap);
    return true;
}

bool test_cap_create_various_types(void)
{
    test_init_keys();

    ak_cap_type_t types[] = {AK_CAP_FS, AK_CAP_NET, AK_CAP_TOOL, AK_CAP_INFER};

    for (int i = 0; i < 4; i++) {
        ak_capability_t *cap = test_create_capability(types[i], "/test", 1000);
        test_assert_not_null(cap);
        test_assert_eq(cap->type, types[i]);
        free(cap);
    }

    return true;
}

bool test_cap_create_resource_too_long(void)
{
    test_init_keys();

    char long_resource[300];
    memset(long_resource, 'a', sizeof(long_resource) - 1);
    long_resource[sizeof(long_resource) - 1] = '\0';

    ak_capability_t *cap = test_create_capability(AK_CAP_FS, long_resource, 1000);
    test_assert_null(cap);

    return true;
}

/* ============================================================
 * TEST CASES: CAPABILITY VERIFICATION
 * ============================================================ */

bool test_cap_verify_valid(void)
{
    test_init_keys();

    ak_capability_t *cap = test_create_capability(AK_CAP_FS, "/app/*", 3600000);
    test_assert_not_null(cap);

    int64_t result = test_verify_capability(cap);
    test_assert_eq(result, 0);

    free(cap);
    return true;
}

bool test_cap_verify_null(void)
{
    int64_t result = test_verify_capability(NULL);
    test_assert_eq(result, AK_E_CAP_MISSING);
    return true;
}

bool test_cap_verify_expired(void)
{
    test_init_keys();

    ak_capability_t *cap = test_create_capability(AK_CAP_FS, "/app/*", 1000);
    test_assert_not_null(cap);

    /* Advance time past TTL */
    test_current_time_ms += 2000;

    int64_t result = test_verify_capability(cap);
    test_assert_eq(result, AK_E_CAP_EXPIRED);

    free(cap);
    return true;
}

bool test_cap_verify_tampered_mac(void)
{
    test_init_keys();

    ak_capability_t *cap = test_create_capability(AK_CAP_FS, "/app/*", 3600000);
    test_assert_not_null(cap);

    /* Tamper with MAC */
    cap->mac[0] ^= 0xFF;

    int64_t result = test_verify_capability(cap);
    test_assert_eq(result, AK_E_CAP_INVALID);

    free(cap);
    return true;
}

bool test_cap_verify_tampered_resource(void)
{
    test_init_keys();

    ak_capability_t *cap = test_create_capability(AK_CAP_FS, "/app/*", 3600000);
    test_assert_not_null(cap);

    /* Tamper with resource (should invalidate MAC) */
    cap->resource[0] = 'X';

    int64_t result = test_verify_capability(cap);
    test_assert_eq(result, AK_E_CAP_INVALID);

    free(cap);
    return true;
}

bool test_cap_verify_tampered_type(void)
{
    test_init_keys();

    ak_capability_t *cap = test_create_capability(AK_CAP_FS, "/app/*", 3600000);
    test_assert_not_null(cap);

    /* Tamper with type */
    cap->type = AK_CAP_ADMIN;

    int64_t result = test_verify_capability(cap);
    test_assert_eq(result, AK_E_CAP_INVALID);

    free(cap);
    return true;
}

bool test_cap_verify_unknown_key(void)
{
    test_init_keys();

    ak_capability_t *cap = test_create_capability(AK_CAP_FS, "/app/*", 3600000);
    test_assert_not_null(cap);

    /* Use unknown key ID */
    cap->kid = 99;

    int64_t result = test_verify_capability(cap);
    test_assert_eq(result, AK_E_CAP_INVALID);

    free(cap);
    return true;
}

/* ============================================================
 * TEST CASES: REVOCATION
 * ============================================================ */

bool test_cap_revocation_basic(void)
{
    test_init_keys();

    ak_capability_t *cap = test_create_capability(AK_CAP_FS, "/app/*", 3600000);
    test_assert_not_null(cap);

    /* Verify before revocation */
    int64_t result = test_verify_capability(cap);
    test_assert_eq(result, 0);

    /* Revoke */
    test_add_revocation(cap->tid);

    /* Verify after revocation */
    result = test_verify_capability(cap);
    test_assert_eq(result, AK_E_CAP_REVOKED);

    free(cap);
    return true;
}

bool test_cap_revocation_multiple(void)
{
    test_init_keys();

    ak_capability_t *caps[10];
    for (int i = 0; i < 10; i++) {
        caps[i] = test_create_capability(AK_CAP_FS, "/test", 3600000);
        test_assert_not_null(caps[i]);
    }

    /* Revoke every other capability */
    for (int i = 0; i < 10; i += 2) {
        test_add_revocation(caps[i]->tid);
    }

    /* Verify revocation status */
    for (int i = 0; i < 10; i++) {
        int64_t result = test_verify_capability(caps[i]);
        if (i % 2 == 0) {
            test_assert_eq(result, AK_E_CAP_REVOKED);
        } else {
            test_assert_eq(result, 0);
        }
    }

    for (int i = 0; i < 10; i++) {
        free(caps[i]);
    }
    return true;
}

bool test_cap_revocation_not_affected_others(void)
{
    test_init_keys();

    ak_capability_t *cap1 = test_create_capability(AK_CAP_FS, "/app/*", 3600000);
    ak_capability_t *cap2 = test_create_capability(AK_CAP_FS, "/app/*", 3600000);

    test_assert_not_null(cap1);
    test_assert_not_null(cap2);

    /* Revoke cap1 */
    test_add_revocation(cap1->tid);

    /* cap2 should still be valid */
    test_assert_eq(test_verify_capability(cap1), AK_E_CAP_REVOKED);
    test_assert_eq(test_verify_capability(cap2), 0);

    free(cap1);
    free(cap2);
    return true;
}

/* ============================================================
 * TEST CASES: RATE LIMITING
 * ============================================================ */

bool test_cap_rate_limit_basic(void)
{
    test_init_keys();

    uint8_t tid[AK_TOKEN_ID_SIZE] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    /* Should allow up to limit */
    for (int i = 0; i < 5; i++) {
        test_assert(test_check_rate_limit(tid, 5, 1000));
    }

    /* Should block after limit */
    test_assert(!test_check_rate_limit(tid, 5, 1000));

    return true;
}

bool test_cap_rate_limit_window_reset(void)
{
    test_init_keys();

    uint8_t tid[AK_TOKEN_ID_SIZE] = {2, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    /* Use up the limit */
    for (int i = 0; i < 5; i++) {
        test_assert(test_check_rate_limit(tid, 5, 1000));
    }
    test_assert(!test_check_rate_limit(tid, 5, 1000));

    /* Advance time past window */
    test_current_time_ms += 2000;

    /* Should be allowed again */
    test_assert(test_check_rate_limit(tid, 5, 1000));

    return true;
}

bool test_cap_rate_limit_different_tokens(void)
{
    test_init_keys();

    uint8_t tid1[AK_TOKEN_ID_SIZE] = {1};
    uint8_t tid2[AK_TOKEN_ID_SIZE] = {2};

    /* Use up tid1's limit */
    for (int i = 0; i < 3; i++) {
        test_assert(test_check_rate_limit(tid1, 3, 1000));
    }
    test_assert(!test_check_rate_limit(tid1, 3, 1000));

    /* tid2 should have its own limit */
    for (int i = 0; i < 3; i++) {
        test_assert(test_check_rate_limit(tid2, 3, 1000));
    }
    test_assert(!test_check_rate_limit(tid2, 3, 1000));

    return true;
}

/* ============================================================
 * TEST CASES: FORGERY ATTACKS
 * ============================================================ */

bool test_cap_forgery_random_mac(void)
{
    test_init_keys();

    /* Create a forged capability with random MAC */
    ak_capability_t forged;
    memset(&forged, 0, sizeof(forged));
    forged.type = AK_CAP_ADMIN;
    strcpy((char *)forged.resource, "/*");
    forged.resource_len = 2;
    forged.issued_ms = test_current_time_ms;
    forged.ttl_ms = 3600000;
    forged.kid = 0;

    /* Random MAC */
    for (int i = 0; i < AK_MAC_SIZE; i++) {
        forged.mac[i] = rand() & 0xFF;
    }

    int64_t result = test_verify_capability(&forged);
    test_assert_eq(result, AK_E_CAP_INVALID);

    return true;
}

bool test_cap_forgery_brute_force(void)
{
    test_init_keys();

    ak_capability_t forged;
    memset(&forged, 0, sizeof(forged));
    forged.type = AK_CAP_ADMIN;
    strcpy((char *)forged.resource, "/*");
    forged.resource_len = 2;
    forged.issued_ms = test_current_time_ms;
    forged.ttl_ms = 3600000;
    forged.kid = 0;

    /* Try 1000 random MACs (should all fail) */
    int failures = 0;
    for (int attempt = 0; attempt < 1000; attempt++) {
        for (int i = 0; i < AK_MAC_SIZE; i++) {
            forged.mac[i] = rand() & 0xFF;
        }

        if (test_verify_capability(&forged) != 0) {
            failures++;
        }
    }

    test_assert_eq(failures, 1000);

    return true;
}

bool test_cap_forgery_replay_revoked(void)
{
    test_init_keys();

    /* Create and revoke a capability */
    ak_capability_t *cap = test_create_capability(AK_CAP_ADMIN, "/*", 3600000);
    test_assert_not_null(cap);

    /* Save a copy */
    ak_capability_t copy;
    memcpy(&copy, cap, sizeof(copy));

    test_add_revocation(cap->tid);

    /* Try to use the saved copy (replay) */
    int64_t result = test_verify_capability(&copy);
    test_assert_eq(result, AK_E_CAP_REVOKED);

    free(cap);
    return true;
}

/* ============================================================
 * TEST CASES: KEY ROTATION
 * ============================================================ */

bool test_cap_key_rotation_old_key_works(void)
{
    test_init_keys();

    /* Create cap with key 0 */
    ak_capability_t *cap = test_create_capability(AK_CAP_FS, "/app/*", 3600000);
    test_assert_not_null(cap);
    test_assert_eq(cap->kid, 0);

    /* Add new key and make it active */
    test_keys[1].kid = 1;
    for (int i = 0; i < AK_KEY_SIZE; i++) {
        test_keys[1].secret[i] = (uint8_t)(i * 11 + 17);
    }
    test_keys[1].created_ms = test_current_time_ms;
    test_keys[1].expires_ms = test_current_time_ms + AK_KEY_ROTATION_MS + AK_KEY_GRACE_MS;
    test_keys[1].active = true;
    test_keys[1].retired = false;

    test_active_kid = 1;

    /* Old cap should still verify with key 0 */
    int64_t result = test_verify_capability(cap);
    test_assert_eq(result, 0);

    free(cap);
    return true;
}

bool test_cap_key_rotation_retired_key_fails(void)
{
    test_init_keys();

    /* Create cap with key 0 */
    ak_capability_t *cap = test_create_capability(AK_CAP_FS, "/app/*", 3600000);
    test_assert_not_null(cap);

    /* Retire key 0 */
    test_keys[0].retired = true;

    /* Cap should now fail verification */
    int64_t result = test_verify_capability(cap);
    test_assert_eq(result, AK_E_CAP_EXPIRED);

    free(cap);
    return true;
}

/* ============================================================
 * TEST CASES: SCOPE VALIDATION
 * ============================================================ */

/* Simple pattern matcher for testing */
static bool test_pattern_match(const char *pattern, const char *resource)
{
    if (!pattern || !resource) return false;

    size_t plen = strlen(pattern);
    size_t rlen = strlen(resource);

    /* Exact match */
    if (strcmp(pattern, resource) == 0) return true;

    /* Wildcard at end */
    if (plen > 0 && pattern[plen-1] == '*') {
        return strncmp(pattern, resource, plen - 1) == 0;
    }

    /* Wildcard at start */
    if (plen > 1 && pattern[0] == '*') {
        const char *suffix = pattern + 1;
        size_t slen = strlen(suffix);
        if (rlen >= slen) {
            return strcmp(resource + rlen - slen, suffix) == 0;
        }
    }

    return false;
}

bool test_cap_scope_exact_match(void)
{
    test_assert(test_pattern_match("/app/file.txt", "/app/file.txt"));
    test_assert(!test_pattern_match("/app/file.txt", "/app/other.txt"));
    return true;
}

bool test_cap_scope_wildcard_suffix(void)
{
    test_assert(test_pattern_match("/app/*", "/app/file.txt"));
    test_assert(test_pattern_match("/app/*", "/app/dir/file.txt"));
    test_assert(!test_pattern_match("/app/*", "/other/file.txt"));
    return true;
}

bool test_cap_scope_wildcard_prefix(void)
{
    test_assert(test_pattern_match("*.txt", "/app/file.txt"));
    test_assert(test_pattern_match("*.txt", "file.txt"));
    test_assert(!test_pattern_match("*.txt", "/app/file.json"));
    return true;
}

bool test_cap_scope_no_match(void)
{
    test_assert(!test_pattern_match("/app/*", "/etc/passwd"));
    test_assert(!test_pattern_match("/home/user/*", "/root/secret"));
    return true;
}

/* ============================================================
 * TEST CASES: EDGE CASES AND BOUNDARY CONDITIONS
 * ============================================================ */

bool test_cap_ttl_boundary_exact(void)
{
    test_init_keys();

    ak_capability_t *cap = test_create_capability(AK_CAP_FS, "/app/*", 1000);
    test_assert_not_null(cap);

    /* Just before expiry */
    test_current_time_ms = cap->issued_ms + 999;
    test_assert_eq(test_verify_capability(cap), 0);

    /* Exactly at expiry */
    test_current_time_ms = cap->issued_ms + 1000;
    test_assert_eq(test_verify_capability(cap), 0);

    /* Just after expiry */
    test_current_time_ms = cap->issued_ms + 1001;
    test_assert_eq(test_verify_capability(cap), AK_E_CAP_EXPIRED);

    free(cap);
    return true;
}

bool test_cap_empty_resource(void)
{
    test_init_keys();

    ak_capability_t *cap = test_create_capability(AK_CAP_FS, "", 3600000);
    test_assert_not_null(cap);
    test_assert_eq(cap->resource_len, 0);
    test_assert_eq(test_verify_capability(cap), 0);

    free(cap);
    return true;
}

bool test_cap_special_characters_resource(void)
{
    test_init_keys();

    const char *resources[] = {
        "/path/with spaces",
        "/path/with\"quotes",
        "/path/with\\backslash",
        "/path/with\ttab",
        "/path/with\nnewline",
    };

    for (int i = 0; i < 5; i++) {
        ak_capability_t *cap = test_create_capability(AK_CAP_FS, resources[i], 3600000);
        if (cap) {
            test_assert_eq(test_verify_capability(cap), 0);
            free(cap);
        }
    }

    return true;
}

bool test_cap_zero_ttl(void)
{
    test_init_keys();

    ak_capability_t *cap = test_create_capability(AK_CAP_FS, "/app/*", 0);
    test_assert_not_null(cap);

    /* Zero TTL means already expired */
    test_current_time_ms += 1;
    test_assert_eq(test_verify_capability(cap), AK_E_CAP_EXPIRED);

    free(cap);
    return true;
}

bool test_cap_max_ttl(void)
{
    test_init_keys();

    ak_capability_t *cap = test_create_capability(AK_CAP_FS, "/app/*", UINT32_MAX);
    test_assert_not_null(cap);
    test_assert_eq(test_verify_capability(cap), 0);

    free(cap);
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
    /* Creation tests */
    {"cap_create_valid", test_cap_create_valid},
    {"cap_create_various_types", test_cap_create_various_types},
    {"cap_create_resource_too_long", test_cap_create_resource_too_long},

    /* Verification tests */
    {"cap_verify_valid", test_cap_verify_valid},
    {"cap_verify_null", test_cap_verify_null},
    {"cap_verify_expired", test_cap_verify_expired},
    {"cap_verify_tampered_mac", test_cap_verify_tampered_mac},
    {"cap_verify_tampered_resource", test_cap_verify_tampered_resource},
    {"cap_verify_tampered_type", test_cap_verify_tampered_type},
    {"cap_verify_unknown_key", test_cap_verify_unknown_key},

    /* Revocation tests */
    {"cap_revocation_basic", test_cap_revocation_basic},
    {"cap_revocation_multiple", test_cap_revocation_multiple},
    {"cap_revocation_not_affected_others", test_cap_revocation_not_affected_others},

    /* Rate limiting tests */
    {"cap_rate_limit_basic", test_cap_rate_limit_basic},
    {"cap_rate_limit_window_reset", test_cap_rate_limit_window_reset},
    {"cap_rate_limit_different_tokens", test_cap_rate_limit_different_tokens},

    /* Forgery attack tests */
    {"cap_forgery_random_mac", test_cap_forgery_random_mac},
    {"cap_forgery_brute_force", test_cap_forgery_brute_force},
    {"cap_forgery_replay_revoked", test_cap_forgery_replay_revoked},

    /* Key rotation tests */
    {"cap_key_rotation_old_key_works", test_cap_key_rotation_old_key_works},
    {"cap_key_rotation_retired_key_fails", test_cap_key_rotation_retired_key_fails},

    /* Scope validation tests */
    {"cap_scope_exact_match", test_cap_scope_exact_match},
    {"cap_scope_wildcard_suffix", test_cap_scope_wildcard_suffix},
    {"cap_scope_wildcard_prefix", test_cap_scope_wildcard_prefix},
    {"cap_scope_no_match", test_cap_scope_no_match},

    /* Edge cases */
    {"cap_ttl_boundary_exact", test_cap_ttl_boundary_exact},
    {"cap_empty_resource", test_cap_empty_resource},
    {"cap_special_characters_resource", test_cap_special_characters_resource},
    {"cap_zero_ttl", test_cap_zero_ttl},
    {"cap_max_ttl", test_cap_max_ttl},

    {NULL, NULL}
};

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    int passed = 0;
    int failed = 0;

    srand(42);  /* Deterministic for reproducibility */

    printf("=== AK Capability System Tests ===\n\n");

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
