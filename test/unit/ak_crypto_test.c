/*
 * Authority Kernel - Cryptographic Primitives Unit Tests
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Comprehensive tests for cryptographic primitives used by Authority Kernel:
 * - HMAC-SHA256 for capability token verification
 * - Ed25519 signatures for module verification and anchors
 * - SHA-256 for hashing
 * - Hash chain verification for audit logs
 *
 * These tests use mock implementations that mirror the real crypto APIs
 * but with simplified implementations suitable for unit testing.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

/* ============================================================
 * TEST ASSERTION MACROS
 * ============================================================ */

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

#define test_assert_mem_eq(a, b, len) do { \
    if (memcmp((a), (b), (len)) != 0) { \
        fprintf(stderr, "FAIL: memory comparison failed at %s:%d\n", __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

#define test_assert_mem_neq(a, b, len) do { \
    if (memcmp((a), (b), (len)) == 0) { \
        fprintf(stderr, "FAIL: memory should differ at %s:%d\n", __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

/* ============================================================
 * CRYPTOGRAPHIC CONSTANTS (matching ak_types.h)
 * ============================================================ */

#define AK_HASH_SIZE            32      /* SHA-256 */
#define AK_MAC_SIZE             32      /* HMAC-SHA256 */
#define AK_KEY_SIZE             32      /* 256-bit keys */
#define AK_TOKEN_ID_SIZE        16      /* 128-bit token IDs */
#define AK_ED25519_PUBLIC_KEY_SIZE  32
#define AK_ED25519_SIGNATURE_SIZE   64
#define AK_ED25519_MAX_TRUSTED_KEYS 16

/* Error codes */
#define AK_E_CAP_MISSING        (-4100)
#define AK_E_CAP_INVALID        (-4101)
#define AK_E_CAP_EXPIRED        (-4102)
#define AK_E_LOG_CORRUPT        (-4405)

/* ============================================================
 * MOCK SHA-256 IMPLEMENTATION
 * ============================================================
 * This is a simplified hash function for testing. It produces
 * deterministic output but is NOT cryptographically secure.
 * Real implementation uses mbedtls or similar.
 */

static void mock_sha256(const uint8_t *data, size_t len, uint8_t *output)
{
    /* Initial hash values (first 32 bits of fractional parts of square roots) */
    uint32_t h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    /* Simple mixing function - NOT secure, just for testing */
    for (size_t i = 0; i < len; i++) {
        uint32_t byte_val = data[i];
        h[i % 8] ^= (byte_val << ((i % 4) * 8));
        h[(i + 1) % 8] += h[i % 8];
        h[(i + 2) % 8] ^= (h[(i + 3) % 8] >> 13);
        h[(i + 4) % 8] += byte_val;
        h[(i + 5) % 8] ^= (h[(i + 6) % 8] << 7);
    }

    /* Additional mixing rounds */
    for (int round = 0; round < 4; round++) {
        for (int i = 0; i < 8; i++) {
            h[i] += h[(i + 1) % 8] ^ (h[(i + 7) % 8] >> 11);
        }
    }

    /* Output as big-endian bytes */
    for (int i = 0; i < 8; i++) {
        output[i*4]     = (uint8_t)((h[i] >> 24) & 0xFF);
        output[i*4 + 1] = (uint8_t)((h[i] >> 16) & 0xFF);
        output[i*4 + 2] = (uint8_t)((h[i] >> 8)  & 0xFF);
        output[i*4 + 3] = (uint8_t)(h[i] & 0xFF);
    }
}

/* ============================================================
 * MOCK HMAC-SHA256 IMPLEMENTATION
 * ============================================================
 */

static void mock_hmac_sha256(
    const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_len,
    uint8_t *output)
{
    uint8_t k_ipad[64];
    uint8_t k_opad[64];
    uint8_t inner_hash[AK_HASH_SIZE];

    /* Prepare key (pad or hash if needed) */
    uint8_t key_block[64];
    memset(key_block, 0, 64);

    if (key_len > 64) {
        mock_sha256(key, key_len, key_block);
        key_len = AK_HASH_SIZE;
    } else {
        memcpy(key_block, key, key_len);
    }

    /* XOR key with ipad and opad */
    for (int i = 0; i < 64; i++) {
        k_ipad[i] = key_block[i] ^ 0x36;
        k_opad[i] = key_block[i] ^ 0x5c;
    }

    /* Inner hash: H(K XOR ipad || data) */
    uint8_t *inner_buf = malloc(64 + data_len);
    if (!inner_buf) {
        memset(output, 0, AK_MAC_SIZE);
        return;
    }
    memcpy(inner_buf, k_ipad, 64);
    if (data && data_len > 0)
        memcpy(inner_buf + 64, data, data_len);
    mock_sha256(inner_buf, 64 + data_len, inner_hash);
    free(inner_buf);

    /* Outer hash: H(K XOR opad || inner_hash) */
    uint8_t outer_buf[64 + AK_HASH_SIZE];
    memcpy(outer_buf, k_opad, 64);
    memcpy(outer_buf + 64, inner_hash, AK_HASH_SIZE);
    mock_sha256(outer_buf, 64 + AK_HASH_SIZE, output);
}

/* Constant-time comparison to prevent timing attacks */
static bool constant_time_compare(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

/* HMAC verification */
static bool mock_hmac_verify(
    const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_len,
    const uint8_t *expected_mac)
{
    uint8_t computed_mac[AK_MAC_SIZE];
    mock_hmac_sha256(key, key_len, data, data_len, computed_mac);
    return constant_time_compare(computed_mac, expected_mac, AK_MAC_SIZE);
}

/* ============================================================
 * MOCK ED25519 IMPLEMENTATION
 * ============================================================
 * Simplified mock for testing. Real implementation uses TweetNaCl.
 */

typedef struct {
    uint8_t public_key[AK_ED25519_PUBLIC_KEY_SIZE];
    uint8_t private_key[64];  /* Ed25519 private key is 64 bytes */
} mock_ed25519_keypair_t;

/* Trusted key store */
static struct {
    uint8_t keys[AK_ED25519_MAX_TRUSTED_KEYS][AK_ED25519_PUBLIC_KEY_SIZE];
    char names[AK_ED25519_MAX_TRUSTED_KEYS][64];
    uint32_t count;
    bool initialized;
} mock_trusted_keys;

static void mock_ed25519_init(void)
{
    memset(&mock_trusted_keys, 0, sizeof(mock_trusted_keys));
    mock_trusted_keys.initialized = true;
}

/* Generate deterministic keypair for testing */
static void mock_ed25519_generate_keypair(
    uint8_t *public_key,
    uint8_t *private_key,
    const uint8_t *seed)
{
    /* Generate private key from seed */
    mock_sha256(seed, 32, private_key);
    mock_sha256(private_key, 32, private_key + 32);

    /* Derive public key (simplified - just hash of private key) */
    mock_sha256(private_key, 64, public_key);
}

/* Sign message (mock implementation) */
static void mock_ed25519_sign(
    const uint8_t *message, size_t message_len,
    const uint8_t *private_key,
    const uint8_t *public_key,
    uint8_t *signature)
{
    /*
     * Mock signature construction:
     * - First 32 bytes = H(private_key || message)
     * - Second 32 bytes = H(public_key || message || first_half)
     *
     * This ensures tampering with ANY part of the signature causes
     * verification to fail, since the second half depends on the first.
     */
    uint8_t *buf = malloc(64 + message_len + 32);
    if (!buf) {
        memset(signature, 0, AK_ED25519_SIGNATURE_SIZE);
        return;
    }

    /* First 32 bytes of signature - derived from private key */
    memcpy(buf, private_key, 64);
    if (message_len > 0) {
        memcpy(buf + 64, message, message_len);
    }
    mock_sha256(buf, 64 + message_len, signature);

    /* Second 32 bytes - includes first half to bind them together */
    memcpy(buf, public_key, 32);
    if (message_len > 0) {
        memcpy(buf + 32, message, message_len);
    }
    memcpy(buf + 32 + message_len, signature, 32);  /* Include first half */
    mock_sha256(buf, 32 + message_len + 32, signature + 32);

    free(buf);
}

/* Verify signature (mock implementation) */
static bool mock_ed25519_verify(
    const uint8_t *message, size_t message_len,
    const uint8_t *signature,
    const uint8_t *public_key)
{
    /*
     * Verify by recomputing expected second half.
     * Since second half = H(public_key || message || first_half),
     * tampering with ANY part of the signature causes verification to fail.
     */
    uint8_t *buf = malloc(32 + message_len + 32);
    if (!buf) return false;

    memcpy(buf, public_key, 32);
    if (message_len > 0) {
        memcpy(buf + 32, message, message_len);
    }
    memcpy(buf + 32 + message_len, signature, 32);  /* Include first half */

    uint8_t expected[32];
    mock_sha256(buf, 32 + message_len + 32, expected);
    free(buf);

    /* Compare second half of signature */
    return constant_time_compare(signature + 32, expected, 32);
}

/* Add trusted key */
static bool mock_ed25519_add_trusted_key(const uint8_t *public_key, const char *name)
{
    if (!mock_trusted_keys.initialized) return false;
    if (mock_trusted_keys.count >= AK_ED25519_MAX_TRUSTED_KEYS) return false;

    memcpy(mock_trusted_keys.keys[mock_trusted_keys.count], public_key, AK_ED25519_PUBLIC_KEY_SIZE);
    strncpy(mock_trusted_keys.names[mock_trusted_keys.count], name, 63);
    mock_trusted_keys.names[mock_trusted_keys.count][63] = '\0';
    mock_trusted_keys.count++;
    return true;
}

/* Check if key is trusted */
static bool mock_ed25519_is_trusted(const uint8_t *public_key)
{
    if (!mock_trusted_keys.initialized) return false;

    for (uint32_t i = 0; i < mock_trusted_keys.count; i++) {
        if (constant_time_compare(mock_trusted_keys.keys[i], public_key, AK_ED25519_PUBLIC_KEY_SIZE)) {
            return true;
        }
    }
    return false;
}

/* Remove trusted key */
static bool mock_ed25519_remove_trusted_key(const uint8_t *public_key)
{
    if (!mock_trusted_keys.initialized) return false;

    for (uint32_t i = 0; i < mock_trusted_keys.count; i++) {
        if (constant_time_compare(mock_trusted_keys.keys[i], public_key, AK_ED25519_PUBLIC_KEY_SIZE)) {
            /* Shift remaining keys */
            for (uint32_t j = i; j < mock_trusted_keys.count - 1; j++) {
                memcpy(mock_trusted_keys.keys[j], mock_trusted_keys.keys[j + 1], AK_ED25519_PUBLIC_KEY_SIZE);
                strcpy(mock_trusted_keys.names[j], mock_trusted_keys.names[j + 1]);
            }
            mock_trusted_keys.count--;
            return true;
        }
    }
    return false;
}

/* Get trusted key count */
static uint32_t mock_ed25519_trusted_key_count(void)
{
    return mock_trusted_keys.count;
}

/* ============================================================
 * MOCK HASH CHAIN IMPLEMENTATION
 * ============================================================ */

#define MAX_CHAIN_ENTRIES 100

typedef struct hash_chain_entry {
    uint64_t seq;
    uint8_t data[64];
    size_t data_len;
    uint8_t prev_hash[AK_HASH_SIZE];
    uint8_t this_hash[AK_HASH_SIZE];
} hash_chain_entry_t;

static struct {
    hash_chain_entry_t entries[MAX_CHAIN_ENTRIES];
    uint64_t count;
    uint8_t head_hash[AK_HASH_SIZE];
    bool initialized;
} mock_chain;

static const uint8_t GENESIS_HASH[AK_HASH_SIZE] = {0};

static void mock_chain_init(void)
{
    memset(&mock_chain, 0, sizeof(mock_chain));
    memcpy(mock_chain.head_hash, GENESIS_HASH, AK_HASH_SIZE);
    mock_chain.initialized = true;
}

static void compute_chain_hash(
    const uint8_t *prev_hash,
    const uint8_t *data, size_t data_len,
    uint8_t *hash_out)
{
    uint8_t *combined = malloc(AK_HASH_SIZE + data_len);
    if (!combined) {
        memset(hash_out, 0, AK_HASH_SIZE);
        return;
    }

    memcpy(combined, prev_hash, AK_HASH_SIZE);
    memcpy(combined + AK_HASH_SIZE, data, data_len);
    mock_sha256(combined, AK_HASH_SIZE + data_len, hash_out);
    free(combined);
}

static int64_t mock_chain_append(const uint8_t *data, size_t data_len)
{
    if (!mock_chain.initialized) return -1;
    if (mock_chain.count >= MAX_CHAIN_ENTRIES) return -1;
    if (data_len > 64) return -1;

    hash_chain_entry_t *entry = &mock_chain.entries[mock_chain.count];
    entry->seq = mock_chain.count + 1;
    memcpy(entry->data, data, data_len);
    entry->data_len = data_len;
    memcpy(entry->prev_hash, mock_chain.head_hash, AK_HASH_SIZE);

    compute_chain_hash(entry->prev_hash, entry->data, entry->data_len, entry->this_hash);
    memcpy(mock_chain.head_hash, entry->this_hash, AK_HASH_SIZE);
    mock_chain.count++;

    return (int64_t)entry->seq;
}

static int64_t mock_chain_verify(uint64_t start_seq, uint64_t end_seq)
{
    if (start_seq == 0 || end_seq < start_seq) return -1;
    if (end_seq > mock_chain.count) end_seq = mock_chain.count;

    uint8_t expected_prev[AK_HASH_SIZE];

    if (start_seq == 1) {
        memcpy(expected_prev, GENESIS_HASH, AK_HASH_SIZE);
    } else {
        memcpy(expected_prev, mock_chain.entries[start_seq - 2].this_hash, AK_HASH_SIZE);
    }

    for (uint64_t i = start_seq - 1; i < end_seq; i++) {
        hash_chain_entry_t *entry = &mock_chain.entries[i];

        /* Verify prev_hash linkage */
        if (memcmp(entry->prev_hash, expected_prev, AK_HASH_SIZE) != 0) {
            return (int64_t)(i + 1);  /* Return sequence number of bad entry */
        }

        /* Recompute and verify this_hash */
        uint8_t computed[AK_HASH_SIZE];
        compute_chain_hash(entry->prev_hash, entry->data, entry->data_len, computed);

        if (memcmp(entry->this_hash, computed, AK_HASH_SIZE) != 0) {
            return (int64_t)(i + 1);
        }

        memcpy(expected_prev, entry->this_hash, AK_HASH_SIZE);
    }

    return 0;  /* Valid */
}

/* ============================================================
 * MOCK CAPABILITY TOKEN CRYPTOGRAPHY
 * ============================================================ */

typedef struct mock_capability {
    uint8_t tid[AK_TOKEN_ID_SIZE];
    uint8_t kid;
    uint8_t resource[64];
    size_t resource_len;
    uint64_t issued_ms;
    uint32_t ttl_ms;
    uint8_t mac[AK_MAC_SIZE];
} mock_capability_t;

/* Key management */
static struct {
    uint8_t keys[4][AK_KEY_SIZE];
    uint8_t active_kid;
    bool retired[4];
} mock_key_store;

static uint64_t mock_current_time_ms = 1000000;

static void mock_cap_crypto_init(void)
{
    memset(&mock_key_store, 0, sizeof(mock_key_store));

    /* Initialize with deterministic test keys */
    for (int k = 0; k < 4; k++) {
        for (int i = 0; i < AK_KEY_SIZE; i++) {
            mock_key_store.keys[k][i] = (uint8_t)((k + 1) * 17 + i * 7);
        }
    }
    mock_key_store.active_kid = 0;
}

static void mock_generate_token_id(uint8_t *tid)
{
    static uint32_t counter = 0;
    counter++;

    for (int i = 0; i < AK_TOKEN_ID_SIZE; i++) {
        tid[i] = (uint8_t)((counter >> (i * 2)) ^ (unsigned)(i * 13));
    }
}

static int canonicalize_cap(mock_capability_t *cap, uint8_t *buf, size_t buf_len)
{
    return snprintf((char *)buf, buf_len,
        "{\"kid\":%d,\"resource\":\"%.*s\",\"ttl_ms\":%u,\"issued_ms\":%llu}",
        cap->kid, (int)cap->resource_len, cap->resource,
        cap->ttl_ms, (unsigned long long)cap->issued_ms);
}

static mock_capability_t *mock_cap_create(const char *resource, uint32_t ttl_ms)
{
    mock_capability_t *cap = calloc(1, sizeof(mock_capability_t));
    if (!cap) return NULL;

    cap->resource_len = strlen(resource);
    if (cap->resource_len >= sizeof(cap->resource)) {
        free(cap);
        return NULL;
    }
    memcpy(cap->resource, resource, cap->resource_len);

    mock_generate_token_id(cap->tid);
    cap->kid = mock_key_store.active_kid;
    cap->issued_ms = mock_current_time_ms;
    cap->ttl_ms = ttl_ms;

    /* Compute MAC */
    uint8_t canonical[256];
    int len = canonicalize_cap(cap, canonical, sizeof(canonical));
    mock_hmac_sha256(mock_key_store.keys[cap->kid], AK_KEY_SIZE,
                     canonical, (size_t)len, cap->mac);

    return cap;
}

static int64_t mock_cap_verify(mock_capability_t *cap)
{
    if (!cap) return AK_E_CAP_MISSING;
    if (cap->kid >= 4) return AK_E_CAP_INVALID;
    if (mock_key_store.retired[cap->kid]) return AK_E_CAP_EXPIRED;

    /* Recompute MAC */
    uint8_t canonical[256];
    int len = canonicalize_cap(cap, canonical, sizeof(canonical));

    uint8_t computed_mac[AK_MAC_SIZE];
    mock_hmac_sha256(mock_key_store.keys[cap->kid], AK_KEY_SIZE,
                     canonical, (size_t)len, computed_mac);

    if (!constant_time_compare(cap->mac, computed_mac, AK_MAC_SIZE)) {
        return AK_E_CAP_INVALID;
    }

    /* Check expiration */
    if (mock_current_time_ms > cap->issued_ms + cap->ttl_ms) {
        return AK_E_CAP_EXPIRED;
    }

    return 0;
}

/* ============================================================
 * TEST CASES: SHA-256 HASHING
 * ============================================================ */

bool test_sha256_basic(void)
{
    uint8_t data[] = "Hello, World!";
    uint8_t hash[AK_HASH_SIZE];

    mock_sha256(data, strlen((char *)data), hash);

    /* Hash should be non-zero */
    bool all_zero = true;
    for (int i = 0; i < AK_HASH_SIZE; i++) {
        if (hash[i] != 0) {
            all_zero = false;
            break;
        }
    }
    test_assert(!all_zero);

    return true;
}

bool test_sha256_deterministic(void)
{
    uint8_t data[] = "Test message for hashing";
    uint8_t hash1[AK_HASH_SIZE];
    uint8_t hash2[AK_HASH_SIZE];

    mock_sha256(data, strlen((char *)data), hash1);
    mock_sha256(data, strlen((char *)data), hash2);

    test_assert_mem_eq(hash1, hash2, AK_HASH_SIZE);

    return true;
}

bool test_sha256_empty_input(void)
{
    uint8_t hash[AK_HASH_SIZE];

    /* Hash of empty input should still produce valid output */
    mock_sha256(NULL, 0, hash);

    /* Should produce deterministic output */
    uint8_t hash2[AK_HASH_SIZE];
    mock_sha256(NULL, 0, hash2);

    test_assert_mem_eq(hash, hash2, AK_HASH_SIZE);

    return true;
}

bool test_sha256_collision_resistance(void)
{
    uint8_t data1[] = "Message one";
    uint8_t data2[] = "Message two";
    uint8_t hash1[AK_HASH_SIZE];
    uint8_t hash2[AK_HASH_SIZE];

    mock_sha256(data1, strlen((char *)data1), hash1);
    mock_sha256(data2, strlen((char *)data2), hash2);

    /* Different inputs should produce different hashes */
    test_assert_mem_neq(hash1, hash2, AK_HASH_SIZE);

    return true;
}

bool test_sha256_single_bit_change(void)
{
    uint8_t data1[] = "Test message";
    uint8_t data2[] = "Test mesgage";  /* 's' -> 'g' */
    uint8_t hash1[AK_HASH_SIZE];
    uint8_t hash2[AK_HASH_SIZE];

    mock_sha256(data1, strlen((char *)data1), hash1);
    mock_sha256(data2, strlen((char *)data2), hash2);

    /* Single character change should produce completely different hash */
    test_assert_mem_neq(hash1, hash2, AK_HASH_SIZE);

    /* Count differing bytes - should be significant */
    int diff_count = 0;
    for (int i = 0; i < AK_HASH_SIZE; i++) {
        if (hash1[i] != hash2[i]) diff_count++;
    }
    test_assert(diff_count > 8);  /* Avalanche effect */

    return true;
}

bool test_sha256_large_input(void)
{
    /* 1MB input */
    size_t len = 1024 * 1024;
    uint8_t *large_data = malloc(len);
    test_assert_not_null(large_data);

    for (size_t i = 0; i < len; i++) {
        large_data[i] = (uint8_t)(i * 17 + 13);
    }

    uint8_t hash[AK_HASH_SIZE];
    mock_sha256(large_data, len, hash);

    /* Should complete and produce valid hash */
    bool all_zero = true;
    for (int i = 0; i < AK_HASH_SIZE; i++) {
        if (hash[i] != 0) {
            all_zero = false;
            break;
        }
    }
    test_assert(!all_zero);

    free(large_data);
    return true;
}

bool test_sha256_known_vector(void)
{
    /* Test with known input - empty string */
    /* Note: Mock doesn't produce real SHA-256, but should be deterministic */
    uint8_t hash1[AK_HASH_SIZE];
    uint8_t hash2[AK_HASH_SIZE];

    mock_sha256((uint8_t *)"", 0, hash1);
    mock_sha256((uint8_t *)"", 0, hash2);

    test_assert_mem_eq(hash1, hash2, AK_HASH_SIZE);

    return true;
}

/* ============================================================
 * TEST CASES: HMAC-SHA256
 * ============================================================ */

bool test_hmac_basic(void)
{
    uint8_t key[AK_KEY_SIZE] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                                 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
    uint8_t data[] = "Test message for HMAC";
    uint8_t mac[AK_MAC_SIZE];

    mock_hmac_sha256(key, AK_KEY_SIZE, data, strlen((char *)data), mac);

    /* MAC should be non-zero */
    bool all_zero = true;
    for (int i = 0; i < AK_MAC_SIZE; i++) {
        if (mac[i] != 0) {
            all_zero = false;
            break;
        }
    }
    test_assert(!all_zero);

    return true;
}

bool test_hmac_deterministic(void)
{
    uint8_t key[AK_KEY_SIZE];
    for (int i = 0; i < AK_KEY_SIZE; i++) key[i] = (uint8_t)(i + 1);

    uint8_t data[] = "Repeated message";
    uint8_t mac1[AK_MAC_SIZE];
    uint8_t mac2[AK_MAC_SIZE];

    mock_hmac_sha256(key, AK_KEY_SIZE, data, strlen((char *)data), mac1);
    mock_hmac_sha256(key, AK_KEY_SIZE, data, strlen((char *)data), mac2);

    test_assert_mem_eq(mac1, mac2, AK_MAC_SIZE);

    return true;
}

bool test_hmac_verification(void)
{
    uint8_t key[AK_KEY_SIZE];
    for (int i = 0; i < AK_KEY_SIZE; i++) key[i] = (uint8_t)(i * 7 + 3);

    uint8_t data[] = "Message to verify";
    uint8_t mac[AK_MAC_SIZE];

    mock_hmac_sha256(key, AK_KEY_SIZE, data, strlen((char *)data), mac);

    /* Verification should succeed */
    test_assert(mock_hmac_verify(key, AK_KEY_SIZE, data, strlen((char *)data), mac));

    return true;
}

bool test_hmac_tampered_mac_detection(void)
{
    uint8_t key[AK_KEY_SIZE];
    for (int i = 0; i < AK_KEY_SIZE; i++) key[i] = (uint8_t)(i + 10);

    uint8_t data[] = "Protected data";
    uint8_t mac[AK_MAC_SIZE];

    mock_hmac_sha256(key, AK_KEY_SIZE, data, strlen((char *)data), mac);

    /* Tamper with MAC */
    mac[0] ^= 0x01;

    /* Verification should fail */
    test_assert(!mock_hmac_verify(key, AK_KEY_SIZE, data, strlen((char *)data), mac));

    return true;
}

bool test_hmac_wrong_key_detection(void)
{
    uint8_t key1[AK_KEY_SIZE];
    uint8_t key2[AK_KEY_SIZE];
    for (int i = 0; i < AK_KEY_SIZE; i++) {
        key1[i] = (uint8_t)(i + 1);
        key2[i] = (uint8_t)(i + 100);  /* Different key */
    }

    uint8_t data[] = "Test data";
    uint8_t mac[AK_MAC_SIZE];

    /* Create MAC with key1 */
    mock_hmac_sha256(key1, AK_KEY_SIZE, data, strlen((char *)data), mac);

    /* Verify with key2 should fail */
    test_assert(!mock_hmac_verify(key2, AK_KEY_SIZE, data, strlen((char *)data), mac));

    return true;
}

bool test_hmac_empty_input(void)
{
    uint8_t key[AK_KEY_SIZE];
    for (int i = 0; i < AK_KEY_SIZE; i++) key[i] = (uint8_t)(i + 1);

    uint8_t mac[AK_MAC_SIZE];

    /* HMAC of empty input should work */
    mock_hmac_sha256(key, AK_KEY_SIZE, (uint8_t *)"", 0, mac);

    /* Should be deterministic */
    uint8_t mac2[AK_MAC_SIZE];
    mock_hmac_sha256(key, AK_KEY_SIZE, (uint8_t *)"", 0, mac2);

    test_assert_mem_eq(mac, mac2, AK_MAC_SIZE);

    return true;
}

bool test_hmac_large_input(void)
{
    uint8_t key[AK_KEY_SIZE];
    for (int i = 0; i < AK_KEY_SIZE; i++) key[i] = (uint8_t)(i + 1);

    /* 64KB input */
    size_t len = 64 * 1024;
    uint8_t *large_data = malloc(len);
    test_assert_not_null(large_data);

    for (size_t i = 0; i < len; i++) {
        large_data[i] = (uint8_t)(i % 256);
    }

    uint8_t mac[AK_MAC_SIZE];
    mock_hmac_sha256(key, AK_KEY_SIZE, large_data, len, mac);

    /* Verify it */
    test_assert(mock_hmac_verify(key, AK_KEY_SIZE, large_data, len, mac));

    free(large_data);
    return true;
}

bool test_hmac_key_rotation(void)
{
    uint8_t key1[AK_KEY_SIZE];
    uint8_t key2[AK_KEY_SIZE];
    for (int i = 0; i < AK_KEY_SIZE; i++) {
        key1[i] = (uint8_t)i;
        key2[i] = (uint8_t)(255 - i);
    }

    uint8_t data[] = "Rotation test";
    uint8_t mac1[AK_MAC_SIZE];
    uint8_t mac2[AK_MAC_SIZE];

    mock_hmac_sha256(key1, AK_KEY_SIZE, data, strlen((char *)data), mac1);
    mock_hmac_sha256(key2, AK_KEY_SIZE, data, strlen((char *)data), mac2);

    /* Different keys should produce different MACs */
    test_assert_mem_neq(mac1, mac2, AK_MAC_SIZE);

    /* Each should verify with its own key */
    test_assert(mock_hmac_verify(key1, AK_KEY_SIZE, data, strlen((char *)data), mac1));
    test_assert(mock_hmac_verify(key2, AK_KEY_SIZE, data, strlen((char *)data), mac2));

    /* Cross-verification should fail */
    test_assert(!mock_hmac_verify(key1, AK_KEY_SIZE, data, strlen((char *)data), mac2));
    test_assert(!mock_hmac_verify(key2, AK_KEY_SIZE, data, strlen((char *)data), mac1));

    return true;
}

bool test_hmac_long_key(void)
{
    /* Key longer than block size (64 bytes) should be hashed first */
    uint8_t long_key[128];
    for (int i = 0; i < 128; i++) long_key[i] = (uint8_t)(i + 1);

    uint8_t data[] = "Test with long key";
    uint8_t mac[AK_MAC_SIZE];

    mock_hmac_sha256(long_key, 128, data, strlen((char *)data), mac);

    /* Should be deterministic */
    uint8_t mac2[AK_MAC_SIZE];
    mock_hmac_sha256(long_key, 128, data, strlen((char *)data), mac2);

    test_assert_mem_eq(mac, mac2, AK_MAC_SIZE);

    return true;
}

/* ============================================================
 * TEST CASES: ED25519 SIGNATURES
 * ============================================================ */

bool test_ed25519_keypair_generation(void)
{
    uint8_t seed[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
    uint8_t public_key[AK_ED25519_PUBLIC_KEY_SIZE];
    uint8_t private_key[64];

    mock_ed25519_generate_keypair(public_key, private_key, seed);

    /* Public key should be non-zero */
    bool all_zero = true;
    for (int i = 0; i < AK_ED25519_PUBLIC_KEY_SIZE; i++) {
        if (public_key[i] != 0) {
            all_zero = false;
            break;
        }
    }
    test_assert(!all_zero);

    return true;
}

bool test_ed25519_keypair_deterministic(void)
{
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) seed[i] = (uint8_t)(i + 100);

    uint8_t public_key1[AK_ED25519_PUBLIC_KEY_SIZE];
    uint8_t private_key1[64];
    uint8_t public_key2[AK_ED25519_PUBLIC_KEY_SIZE];
    uint8_t private_key2[64];

    mock_ed25519_generate_keypair(public_key1, private_key1, seed);
    mock_ed25519_generate_keypair(public_key2, private_key2, seed);

    test_assert_mem_eq(public_key1, public_key2, AK_ED25519_PUBLIC_KEY_SIZE);
    test_assert_mem_eq(private_key1, private_key2, 64);

    return true;
}

bool test_ed25519_sign_verify(void)
{
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) seed[i] = (uint8_t)(i * 3);

    uint8_t public_key[AK_ED25519_PUBLIC_KEY_SIZE];
    uint8_t private_key[64];
    mock_ed25519_generate_keypair(public_key, private_key, seed);

    uint8_t message[] = "Message to sign";
    uint8_t signature[AK_ED25519_SIGNATURE_SIZE];

    mock_ed25519_sign(message, strlen((char *)message), private_key, public_key, signature);

    /* Verification should succeed */
    test_assert(mock_ed25519_verify(message, strlen((char *)message), signature, public_key));

    return true;
}

bool test_ed25519_invalid_signature_rejection(void)
{
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) seed[i] = (uint8_t)(i + 50);

    uint8_t public_key[AK_ED25519_PUBLIC_KEY_SIZE];
    uint8_t private_key[64];
    mock_ed25519_generate_keypair(public_key, private_key, seed);

    uint8_t message[] = "Original message";
    uint8_t signature[AK_ED25519_SIGNATURE_SIZE];

    mock_ed25519_sign(message, strlen((char *)message), private_key, public_key, signature);

    /* Tamper with signature */
    signature[0] ^= 0xFF;

    /* Verification should fail */
    test_assert(!mock_ed25519_verify(message, strlen((char *)message), signature, public_key));

    return true;
}

bool test_ed25519_wrong_key_rejection(void)
{
    uint8_t seed1[32], seed2[32];
    for (int i = 0; i < 32; i++) {
        seed1[i] = (uint8_t)i;
        seed2[i] = (uint8_t)(255 - i);
    }

    uint8_t public_key1[AK_ED25519_PUBLIC_KEY_SIZE], private_key1[64];
    uint8_t public_key2[AK_ED25519_PUBLIC_KEY_SIZE], private_key2[64];

    mock_ed25519_generate_keypair(public_key1, private_key1, seed1);
    mock_ed25519_generate_keypair(public_key2, private_key2, seed2);

    uint8_t message[] = "Test message";
    uint8_t signature[AK_ED25519_SIGNATURE_SIZE];

    /* Sign with key1 */
    mock_ed25519_sign(message, strlen((char *)message), private_key1, public_key1, signature);

    /* Verify with key2 should fail */
    test_assert(!mock_ed25519_verify(message, strlen((char *)message), signature, public_key2));

    return true;
}

bool test_ed25519_signature_size(void)
{
    test_assert_eq(AK_ED25519_SIGNATURE_SIZE, 64);
    return true;
}

bool test_ed25519_public_key_size(void)
{
    test_assert_eq(AK_ED25519_PUBLIC_KEY_SIZE, 32);
    return true;
}

bool test_ed25519_trusted_key_add(void)
{
    mock_ed25519_init();

    uint8_t public_key[AK_ED25519_PUBLIC_KEY_SIZE];
    for (int i = 0; i < AK_ED25519_PUBLIC_KEY_SIZE; i++) public_key[i] = (uint8_t)(i + 1);

    test_assert(mock_ed25519_add_trusted_key(public_key, "test-key"));
    test_assert_eq(mock_ed25519_trusted_key_count(), 1);

    return true;
}

bool test_ed25519_trusted_key_check(void)
{
    mock_ed25519_init();

    uint8_t trusted_key[AK_ED25519_PUBLIC_KEY_SIZE];
    uint8_t untrusted_key[AK_ED25519_PUBLIC_KEY_SIZE];

    for (int i = 0; i < AK_ED25519_PUBLIC_KEY_SIZE; i++) {
        trusted_key[i] = (uint8_t)(i + 1);
        untrusted_key[i] = (uint8_t)(255 - i);
    }

    test_assert(mock_ed25519_add_trusted_key(trusted_key, "trusted"));

    test_assert(mock_ed25519_is_trusted(trusted_key));
    test_assert(!mock_ed25519_is_trusted(untrusted_key));

    return true;
}

bool test_ed25519_trusted_key_remove(void)
{
    mock_ed25519_init();

    uint8_t public_key[AK_ED25519_PUBLIC_KEY_SIZE];
    for (int i = 0; i < AK_ED25519_PUBLIC_KEY_SIZE; i++) public_key[i] = (uint8_t)(i + 1);

    test_assert(mock_ed25519_add_trusted_key(public_key, "removable"));
    test_assert(mock_ed25519_is_trusted(public_key));

    test_assert(mock_ed25519_remove_trusted_key(public_key));
    test_assert(!mock_ed25519_is_trusted(public_key));
    test_assert_eq(mock_ed25519_trusted_key_count(), 0);

    return true;
}

bool test_ed25519_trusted_key_max(void)
{
    mock_ed25519_init();

    /* Add maximum number of keys */
    for (int k = 0; k < AK_ED25519_MAX_TRUSTED_KEYS; k++) {
        uint8_t key[AK_ED25519_PUBLIC_KEY_SIZE];
        for (int i = 0; i < AK_ED25519_PUBLIC_KEY_SIZE; i++) {
            key[i] = (uint8_t)((k + 1) * (i + 1));
        }
        test_assert(mock_ed25519_add_trusted_key(key, "key"));
    }

    test_assert_eq(mock_ed25519_trusted_key_count(), AK_ED25519_MAX_TRUSTED_KEYS);

    /* Adding one more should fail */
    uint8_t extra_key[AK_ED25519_PUBLIC_KEY_SIZE] = {0xFF};
    test_assert(!mock_ed25519_add_trusted_key(extra_key, "extra"));

    return true;
}

bool test_ed25519_empty_message(void)
{
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) seed[i] = (uint8_t)i;

    uint8_t public_key[AK_ED25519_PUBLIC_KEY_SIZE];
    uint8_t private_key[64];
    mock_ed25519_generate_keypair(public_key, private_key, seed);

    uint8_t signature[AK_ED25519_SIGNATURE_SIZE];
    mock_ed25519_sign((uint8_t *)"", 0, private_key, public_key, signature);

    test_assert(mock_ed25519_verify((uint8_t *)"", 0, signature, public_key));

    return true;
}

/* ============================================================
 * TEST CASES: HASH CHAIN
 * ============================================================ */

bool test_hash_chain_init(void)
{
    mock_chain_init();

    test_assert(mock_chain.initialized);
    test_assert_eq(mock_chain.count, 0);
    test_assert_mem_eq(mock_chain.head_hash, GENESIS_HASH, AK_HASH_SIZE);

    return true;
}

bool test_hash_chain_append(void)
{
    mock_chain_init();

    uint8_t data[] = "First entry";
    int64_t seq = mock_chain_append(data, strlen((char *)data));

    test_assert_eq(seq, 1);
    test_assert_eq(mock_chain.count, 1);

    /* Head hash should have changed */
    test_assert_mem_neq(mock_chain.head_hash, GENESIS_HASH, AK_HASH_SIZE);

    return true;
}

bool test_hash_chain_links(void)
{
    mock_chain_init();

    uint8_t data1[] = "Entry one";
    uint8_t data2[] = "Entry two";
    uint8_t data3[] = "Entry three";

    mock_chain_append(data1, strlen((char *)data1));
    mock_chain_append(data2, strlen((char *)data2));
    mock_chain_append(data3, strlen((char *)data3));

    /* Verify chain linkage */
    test_assert_mem_eq(mock_chain.entries[0].prev_hash, GENESIS_HASH, AK_HASH_SIZE);
    test_assert_mem_eq(mock_chain.entries[1].prev_hash, mock_chain.entries[0].this_hash, AK_HASH_SIZE);
    test_assert_mem_eq(mock_chain.entries[2].prev_hash, mock_chain.entries[1].this_hash, AK_HASH_SIZE);

    return true;
}

bool test_hash_chain_verify_valid(void)
{
    mock_chain_init();

    for (int i = 0; i < 50; i++) {
        uint8_t data[16];
        snprintf((char *)data, sizeof(data), "Entry %d", i);
        mock_chain_append(data, strlen((char *)data));
    }

    int64_t result = mock_chain_verify(1, 50);
    test_assert_eq(result, 0);

    return true;
}

bool test_hash_chain_tamper_single_bit(void)
{
    mock_chain_init();

    for (int i = 0; i < 10; i++) {
        uint8_t data[16];
        snprintf((char *)data, sizeof(data), "Entry %d", i);
        mock_chain_append(data, strlen((char *)data));
    }

    /* Tamper with entry 5's hash */
    mock_chain.entries[4].this_hash[0] ^= 0x01;

    /* Verification should detect the tamper */
    int64_t result = mock_chain_verify(1, 10);
    test_assert(result > 0);  /* Should return failing sequence number */

    return true;
}

bool test_hash_chain_tamper_data(void)
{
    mock_chain_init();

    for (int i = 0; i < 10; i++) {
        uint8_t data[16];
        snprintf((char *)data, sizeof(data), "Entry %d", i);
        mock_chain_append(data, strlen((char *)data));
    }

    /* Tamper with entry 3's data */
    mock_chain.entries[2].data[0] = 'X';

    /* Verification should detect the tamper */
    int64_t result = mock_chain_verify(1, 10);
    test_assert_eq(result, 3);

    return true;
}

bool test_hash_chain_tamper_prev_hash(void)
{
    mock_chain_init();

    for (int i = 0; i < 10; i++) {
        uint8_t data[16];
        snprintf((char *)data, sizeof(data), "Entry %d", i);
        mock_chain_append(data, strlen((char *)data));
    }

    /* Break the chain at entry 7 */
    mock_chain.entries[6].prev_hash[0] ^= 0xFF;

    int64_t result = mock_chain_verify(1, 10);
    test_assert_eq(result, 7);

    return true;
}

bool test_hash_chain_partial_verify(void)
{
    mock_chain_init();

    for (int i = 0; i < 100; i++) {
        uint8_t data[16];
        snprintf((char *)data, sizeof(data), "Entry %d", i);
        mock_chain_append(data, strlen((char *)data));
    }

    /* Verify middle range */
    int64_t result = mock_chain_verify(25, 75);
    test_assert_eq(result, 0);

    return true;
}

bool test_hash_chain_uniqueness(void)
{
    mock_chain_init();

    for (int i = 0; i < 50; i++) {
        uint8_t data[16];
        snprintf((char *)data, sizeof(data), "Entry %d", i);
        mock_chain_append(data, strlen((char *)data));
    }

    /* All hashes should be unique */
    for (int i = 0; i < 50; i++) {
        for (int j = i + 1; j < 50; j++) {
            test_assert_mem_neq(mock_chain.entries[i].this_hash,
                               mock_chain.entries[j].this_hash, AK_HASH_SIZE);
        }
    }

    return true;
}

/* ============================================================
 * TEST CASES: CAPABILITY TOKEN CRYPTOGRAPHY
 * ============================================================ */

bool test_cap_token_create(void)
{
    mock_cap_crypto_init();

    mock_capability_t *cap = mock_cap_create("/app/*", 3600000);
    test_assert_not_null(cap);
    test_assert(cap->resource_len > 0);
    test_assert(cap->ttl_ms == 3600000);

    free(cap);
    return true;
}

bool test_cap_token_verify_valid(void)
{
    mock_cap_crypto_init();

    mock_capability_t *cap = mock_cap_create("/test/path", 3600000);
    test_assert_not_null(cap);

    int64_t result = mock_cap_verify(cap);
    test_assert_eq(result, 0);

    free(cap);
    return true;
}

bool test_cap_token_forgery_detection(void)
{
    mock_cap_crypto_init();

    mock_capability_t *cap = mock_cap_create("/admin/*", 3600000);
    test_assert_not_null(cap);

    /* Tamper with MAC */
    cap->mac[0] ^= 0xFF;

    int64_t result = mock_cap_verify(cap);
    test_assert_eq(result, AK_E_CAP_INVALID);

    free(cap);
    return true;
}

bool test_cap_token_resource_tampering(void)
{
    mock_cap_crypto_init();

    mock_capability_t *cap = mock_cap_create("/limited/*", 3600000);
    test_assert_not_null(cap);

    /* Try to escalate resource to admin */
    memcpy(cap->resource, "/admin/*", 8);
    cap->resource_len = 8;

    int64_t result = mock_cap_verify(cap);
    test_assert_eq(result, AK_E_CAP_INVALID);

    free(cap);
    return true;
}

bool test_cap_token_expiration(void)
{
    mock_cap_crypto_init();

    mock_capability_t *cap = mock_cap_create("/test", 1000);  /* 1 second TTL */
    test_assert_not_null(cap);

    /* Advance time past TTL */
    mock_current_time_ms += 2000;

    int64_t result = mock_cap_verify(cap);
    test_assert_eq(result, AK_E_CAP_EXPIRED);

    free(cap);
    return true;
}

bool test_cap_token_null_check(void)
{
    int64_t result = mock_cap_verify(NULL);
    test_assert_eq(result, AK_E_CAP_MISSING);
    return true;
}

bool test_cap_token_invalid_kid(void)
{
    mock_cap_crypto_init();

    mock_capability_t *cap = mock_cap_create("/test", 3600000);
    test_assert_not_null(cap);

    /* Set invalid key ID */
    cap->kid = 99;

    int64_t result = mock_cap_verify(cap);
    test_assert_eq(result, AK_E_CAP_INVALID);

    free(cap);
    return true;
}

bool test_cap_token_retired_key(void)
{
    mock_cap_crypto_init();

    mock_capability_t *cap = mock_cap_create("/test", 3600000);
    test_assert_not_null(cap);

    /* Retire the key */
    mock_key_store.retired[cap->kid] = true;

    int64_t result = mock_cap_verify(cap);
    test_assert_eq(result, AK_E_CAP_EXPIRED);

    free(cap);
    return true;
}

bool test_cap_token_brute_force_resistance(void)
{
    mock_cap_crypto_init();

    mock_capability_t forged;
    memset(&forged, 0, sizeof(forged));
    strcpy((char *)forged.resource, "/admin/*");
    forged.resource_len = 8;
    forged.kid = 0;
    forged.issued_ms = mock_current_time_ms;
    forged.ttl_ms = 3600000;

    /* Try 1000 random MACs */
    int failures = 0;
    for (int attempt = 0; attempt < 1000; attempt++) {
        for (int i = 0; i < AK_MAC_SIZE; i++) {
            forged.mac[i] = (uint8_t)(rand() & 0xFF);
        }

        if (mock_cap_verify(&forged) != 0) {
            failures++;
        }
    }

    test_assert_eq(failures, 1000);  /* All should fail */

    return true;
}

bool test_cap_token_unique_ids(void)
{
    mock_cap_crypto_init();

    uint8_t tids[100][AK_TOKEN_ID_SIZE];

    for (int i = 0; i < 100; i++) {
        mock_capability_t *cap = mock_cap_create("/test", 3600000);
        test_assert_not_null(cap);
        memcpy(tids[i], cap->tid, AK_TOKEN_ID_SIZE);
        free(cap);
    }

    /* All token IDs should be unique */
    for (int i = 0; i < 100; i++) {
        for (int j = i + 1; j < 100; j++) {
            test_assert_mem_neq(tids[i], tids[j], AK_TOKEN_ID_SIZE);
        }
    }

    return true;
}

/* ============================================================
 * TEST CASES: AUDIT LOG CRYPTOGRAPHY
 * ============================================================ */

bool test_audit_entry_hash(void)
{
    uint8_t prev_hash[AK_HASH_SIZE] = {1, 2, 3, 4};
    uint8_t data[] = "Audit entry data";
    uint8_t hash[AK_HASH_SIZE];

    compute_chain_hash(prev_hash, data, strlen((char *)data), hash);

    /* Hash should be non-zero */
    bool all_zero = true;
    for (int i = 0; i < AK_HASH_SIZE; i++) {
        if (hash[i] != 0) {
            all_zero = false;
            break;
        }
    }
    test_assert(!all_zero);

    return true;
}

bool test_audit_chain_integrity(void)
{
    mock_chain_init();

    /* Simulate audit log entries */
    for (int i = 0; i < 100; i++) {
        uint8_t entry[32];
        snprintf((char *)entry, sizeof(entry), "op:%d seq:%d", i % 10, i);
        mock_chain_append(entry, strlen((char *)entry));
    }

    /* Full chain should verify */
    test_assert_eq(mock_chain_verify(1, 100), 0);

    return true;
}

bool test_audit_anchor_verification(void)
{
    mock_chain_init();

    /* Build chain */
    for (int i = 0; i < 50; i++) {
        uint8_t data[16];
        snprintf((char *)data, sizeof(data), "entry-%d", i);
        mock_chain_append(data, strlen((char *)data));
    }

    /* Save anchor point */
    uint8_t anchor_hash[AK_HASH_SIZE];
    memcpy(anchor_hash, mock_chain.entries[49].this_hash, AK_HASH_SIZE);

    /* Add more entries */
    for (int i = 50; i < 100; i++) {
        uint8_t data[16];
        snprintf((char *)data, sizeof(data), "entry-%d", i);
        mock_chain_append(data, strlen((char *)data));
    }

    /* Anchor should still match entry 50 */
    test_assert_mem_eq(anchor_hash, mock_chain.entries[49].this_hash, AK_HASH_SIZE);

    return true;
}

/* ============================================================
 * TEST CASES: EDGE CASES AND BOUNDARY CONDITIONS
 * ============================================================ */

bool test_constant_time_compare_equal(void)
{
    uint8_t a[32], b[32];
    for (int i = 0; i < 32; i++) {
        a[i] = (uint8_t)i;
        b[i] = (uint8_t)i;
    }

    test_assert(constant_time_compare(a, b, 32));

    return true;
}

bool test_constant_time_compare_different(void)
{
    uint8_t a[32], b[32];
    for (int i = 0; i < 32; i++) {
        a[i] = (uint8_t)i;
        b[i] = (uint8_t)(31 - i);
    }

    test_assert(!constant_time_compare(a, b, 32));

    return true;
}

bool test_constant_time_compare_single_bit(void)
{
    uint8_t a[32], b[32];
    for (int i = 0; i < 32; i++) {
        a[i] = (uint8_t)i;
        b[i] = (uint8_t)i;
    }

    /* Single bit difference */
    b[15] ^= 0x01;

    test_assert(!constant_time_compare(a, b, 32));

    return true;
}

bool test_null_input_hmac(void)
{
    uint8_t key[AK_KEY_SIZE] = {0};
    uint8_t mac[AK_MAC_SIZE];

    /* Should handle NULL data gracefully */
    mock_hmac_sha256(key, AK_KEY_SIZE, NULL, 0, mac);

    /* Result should be deterministic */
    uint8_t mac2[AK_MAC_SIZE];
    mock_hmac_sha256(key, AK_KEY_SIZE, NULL, 0, mac2);

    test_assert_mem_eq(mac, mac2, AK_MAC_SIZE);

    return true;
}

bool test_zero_length_operations(void)
{
    /* SHA-256 with zero length */
    uint8_t hash[AK_HASH_SIZE];
    mock_sha256((uint8_t *)"", 0, hash);

    /* HMAC with zero length message */
    uint8_t key[AK_KEY_SIZE] = {1};
    uint8_t mac[AK_MAC_SIZE];
    mock_hmac_sha256(key, AK_KEY_SIZE, (uint8_t *)"", 0, mac);

    /* Chain append with minimal data */
    mock_chain_init();
    int64_t seq = mock_chain_append((uint8_t *)"", 0);
    test_assert(seq > 0);

    return true;
}

bool test_max_chain_entries(void)
{
    mock_chain_init();

    /* Fill to maximum */
    for (int i = 0; i < MAX_CHAIN_ENTRIES; i++) {
        uint8_t data[8] = {(uint8_t)i};
        int64_t seq = mock_chain_append(data, 1);
        test_assert(seq > 0);
    }

    /* Next append should fail */
    uint8_t data[8] = {0xFF};
    int64_t seq = mock_chain_append(data, 1);
    test_assert_eq(seq, -1);

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
    /* SHA-256 tests */
    {"sha256_basic", test_sha256_basic},
    {"sha256_deterministic", test_sha256_deterministic},
    {"sha256_empty_input", test_sha256_empty_input},
    {"sha256_collision_resistance", test_sha256_collision_resistance},
    {"sha256_single_bit_change", test_sha256_single_bit_change},
    {"sha256_large_input", test_sha256_large_input},
    {"sha256_known_vector", test_sha256_known_vector},

    /* HMAC-SHA256 tests */
    {"hmac_basic", test_hmac_basic},
    {"hmac_deterministic", test_hmac_deterministic},
    {"hmac_verification", test_hmac_verification},
    {"hmac_tampered_mac_detection", test_hmac_tampered_mac_detection},
    {"hmac_wrong_key_detection", test_hmac_wrong_key_detection},
    {"hmac_empty_input", test_hmac_empty_input},
    {"hmac_large_input", test_hmac_large_input},
    {"hmac_key_rotation", test_hmac_key_rotation},
    {"hmac_long_key", test_hmac_long_key},

    /* Ed25519 tests */
    {"ed25519_keypair_generation", test_ed25519_keypair_generation},
    {"ed25519_keypair_deterministic", test_ed25519_keypair_deterministic},
    {"ed25519_sign_verify", test_ed25519_sign_verify},
    {"ed25519_invalid_signature_rejection", test_ed25519_invalid_signature_rejection},
    {"ed25519_wrong_key_rejection", test_ed25519_wrong_key_rejection},
    {"ed25519_signature_size", test_ed25519_signature_size},
    {"ed25519_public_key_size", test_ed25519_public_key_size},
    {"ed25519_trusted_key_add", test_ed25519_trusted_key_add},
    {"ed25519_trusted_key_check", test_ed25519_trusted_key_check},
    {"ed25519_trusted_key_remove", test_ed25519_trusted_key_remove},
    {"ed25519_trusted_key_max", test_ed25519_trusted_key_max},
    {"ed25519_empty_message", test_ed25519_empty_message},

    /* Hash chain tests */
    {"hash_chain_init", test_hash_chain_init},
    {"hash_chain_append", test_hash_chain_append},
    {"hash_chain_links", test_hash_chain_links},
    {"hash_chain_verify_valid", test_hash_chain_verify_valid},
    {"hash_chain_tamper_single_bit", test_hash_chain_tamper_single_bit},
    {"hash_chain_tamper_data", test_hash_chain_tamper_data},
    {"hash_chain_tamper_prev_hash", test_hash_chain_tamper_prev_hash},
    {"hash_chain_partial_verify", test_hash_chain_partial_verify},
    {"hash_chain_uniqueness", test_hash_chain_uniqueness},

    /* Capability token cryptography tests */
    {"cap_token_create", test_cap_token_create},
    {"cap_token_verify_valid", test_cap_token_verify_valid},
    {"cap_token_forgery_detection", test_cap_token_forgery_detection},
    {"cap_token_resource_tampering", test_cap_token_resource_tampering},
    {"cap_token_expiration", test_cap_token_expiration},
    {"cap_token_null_check", test_cap_token_null_check},
    {"cap_token_invalid_kid", test_cap_token_invalid_kid},
    {"cap_token_retired_key", test_cap_token_retired_key},
    {"cap_token_brute_force_resistance", test_cap_token_brute_force_resistance},
    {"cap_token_unique_ids", test_cap_token_unique_ids},

    /* Audit log cryptography tests */
    {"audit_entry_hash", test_audit_entry_hash},
    {"audit_chain_integrity", test_audit_chain_integrity},
    {"audit_anchor_verification", test_audit_anchor_verification},

    /* Edge cases and boundary conditions */
    {"constant_time_compare_equal", test_constant_time_compare_equal},
    {"constant_time_compare_different", test_constant_time_compare_different},
    {"constant_time_compare_single_bit", test_constant_time_compare_single_bit},
    {"null_input_hmac", test_null_input_hmac},
    {"zero_length_operations", test_zero_length_operations},
    {"max_chain_entries", test_max_chain_entries},

    {NULL, NULL}
};

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    int passed = 0;
    int failed = 0;

    srand(42);  /* Deterministic for reproducibility */

    printf("=== AK Cryptographic Primitives Tests ===\n\n");

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
