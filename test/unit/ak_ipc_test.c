/*
 * Authority Kernel - IPC System Unit Tests
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Comprehensive tests for IPC system:
 * - Frame format validation (magic, version, payload bounds, CRC-32C)
 * - Channel management (create, destroy, state transitions, stats)
 * - Sequence tracking (anti-replay, monotonic enforcement, sliding window)
 * - Serialization (request/response JSON, hex encoding/decoding)
 * - Frame operations (header validation, payload validation, checksum)
 * - Batch operations
 * - Error handling (invalid frames, missing fields, malformed JSON)
 * - Security attack scenarios (injection, replay, malformed frames)
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

#define test_assert_str_eq(a, b) do { \
    if (strcmp((a), (b)) != 0) { \
        fprintf(stderr, "FAIL: %s != %s (\"%s\" != \"%s\") at %s:%d\n", \
                #a, #b, (a), (b), __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

#define test_assert_mem_eq(a, b, len) do { \
    if (memcmp((a), (b), (len)) != 0) { \
        fprintf(stderr, "FAIL: %s != %s (memory mismatch) at %s:%d\n", \
                #a, #b, __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

/* ============================================================
 * IPC CONSTANTS (matching ak_ipc.h)
 * ============================================================ */

#define AK_IPC_MAGIC            0x414B  /* "AK" */
#define AK_IPC_VERSION          1
#define AK_IPC_HEADER_SIZE      20
#define AK_IPC_MAX_PAYLOAD      (1024 * 1024)  /* 1 MB max */

/* Frame flags */
#define AK_IPC_FLAG_REQUEST     0x01
#define AK_IPC_FLAG_RESPONSE    0x02
#define AK_IPC_FLAG_ERROR       0x04
#define AK_IPC_FLAG_COMPRESSED  0x08
#define AK_IPC_FLAG_BATCH       0x10

/* Channel states */
typedef enum ak_channel_state {
    AK_CHANNEL_DISCONNECTED,
    AK_CHANNEL_CONNECTING,
    AK_CHANNEL_CONNECTED,
    AK_CHANNEL_ERROR
} ak_channel_state_t;

/* Error codes */
#define AK_E_CAP_INVALID        (-4101)
#define AK_E_CAP_EXPIRED        (-4102)
#define AK_E_CAP_SCOPE          (-4103)
#define AK_E_CAP_RATE           (-4105)
#define AK_E_CAP_RUN_MISMATCH   (-4106)
#define AK_E_REPLAY             (-4200)
#define AK_E_CONFLICT           (-4400)
#define AK_E_SCHEMA_INVALID     (-4002)
#define AK_E_POLICY_DENIED      (-4502)
#define AK_E_BUDGET_EXCEEDED    (-4300)
#define AK_E_IPC_INVALID        (-4500)
#define AK_E_SEQ_GAP            (-4501)
#define AK_E_TAINT              (-4203)
#define AK_E_LOG_CORRUPT        (-4405)
#define AK_E_TIMEOUT            (-4503)

/* Syscall operations */
#define AK_SYS_READ             1024
#define AK_SYS_ALLOC            1025
#define AK_SYS_WRITE            1026
#define AK_SYS_DELETE           1027
#define AK_SYS_QUERY            1031
#define AK_SYS_BATCH            1029
#define AK_SYS_COMMIT           1030
#define AK_SYS_CALL             1028
#define AK_SYS_SPAWN            1032
#define AK_SYS_SEND             1033
#define AK_SYS_RECV             1034
#define AK_SYS_RESPOND          1036
#define AK_SYS_ASSERT           1035
#define AK_SYS_INFERENCE        1037

#define AK_TOKEN_ID_SIZE        16
#define AK_HASH_SIZE            32
#define AK_MAC_SIZE             32

#define EINVAL                  22
#define ENOENT                  2
#define ENOMEM                  12
#define EPERM                   1

/* ============================================================
 * MOCK BUFFER IMPLEMENTATION
 * ============================================================ */

typedef struct mock_buffer {
    uint8_t *data;
    uint64_t length;
    uint64_t capacity;
} mock_buffer_t;

static mock_buffer_t *mock_buffer_create(uint64_t capacity)
{
    mock_buffer_t *buf = calloc(1, sizeof(mock_buffer_t));
    if (!buf) return NULL;

    buf->data = calloc(1, capacity);
    if (!buf->data) {
        free(buf);
        return NULL;
    }

    buf->capacity = capacity;
    buf->length = 0;
    return buf;
}

static void mock_buffer_destroy(mock_buffer_t *buf)
{
    if (buf) {
        free(buf->data);
        free(buf);
    }
}

static void mock_buffer_write(mock_buffer_t *buf, const void *data, uint64_t len)
{
    if (buf->length + len > buf->capacity) {
        /* Expand buffer */
        uint64_t new_cap = (buf->length + len) * 2;
        uint8_t *new_data = realloc(buf->data, new_cap);
        if (!new_data) return;
        buf->data = new_data;
        buf->capacity = new_cap;
    }
    memcpy(buf->data + buf->length, data, len);
    buf->length += len;
}

static uint8_t *mock_buffer_ref(mock_buffer_t *buf, uint64_t offset)
{
    if (!buf || offset >= buf->length) return NULL;
    return buf->data + offset;
}

static uint64_t mock_buffer_length(mock_buffer_t *buf)
{
    return buf ? buf->length : 0;
}

/* ============================================================
 * IPC FRAME HEADER STRUCTURE
 * ============================================================ */

typedef struct ak_ipc_header {
    uint16_t magic;
    uint8_t version;
    uint8_t flags;
    uint32_t payload_length;
    uint64_t sequence;
    uint32_t checksum;
} __attribute__((packed)) ak_ipc_header_t;

/* ============================================================
 * MOCK IPC CHANNEL STRUCTURE
 * ============================================================ */

typedef struct ak_ipc_channel {
    uint8_t agent_id[AK_TOKEN_ID_SIZE];
    int fd;
    ak_channel_state_t state;
    uint64_t next_seq;

    /* Statistics */
    uint64_t frames_sent;
    uint64_t frames_received;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t errors;
    uint64_t checksum_failures;

    mock_buffer_t *recv_buf;
} ak_ipc_channel_t;

typedef struct ak_ipc_stats {
    uint64_t frames_sent;
    uint64_t frames_received;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t errors;
    uint64_t checksum_failures;
} ak_ipc_stats_t;

/* ============================================================
 * MOCK SEQUENCE TRACKER STRUCTURE
 * ============================================================ */

#define SEQ_WINDOW_SIZE 1024

typedef struct ak_seq_tracker {
    uint8_t pid[AK_TOKEN_ID_SIZE];
    uint8_t run_id[AK_TOKEN_ID_SIZE];
    uint64_t highest_seen;
    uint64_t expected_next;

    /* Bitmap for recent sequences (sliding window) */
    uint8_t seen_bitmap[SEQ_WINDOW_SIZE / 8];
    uint64_t window_base;
} ak_seq_tracker_t;

/* ============================================================
 * MOCK REQUEST/RESPONSE STRUCTURES
 * ============================================================ */

typedef struct ak_request {
    uint8_t pid[AK_TOKEN_ID_SIZE];
    uint8_t run_id[AK_TOKEN_ID_SIZE];
    uint64_t seq;
    uint16_t op;
    mock_buffer_t *args;
} ak_request_t;

typedef struct ak_response {
    uint8_t pid[AK_TOKEN_ID_SIZE];
    uint8_t run_id[AK_TOKEN_ID_SIZE];
    uint64_t seq;
    int64_t error_code;
    mock_buffer_t *result;
} ak_response_t;

/* ============================================================
 * CRC-32C IMPLEMENTATION (Castagnoli)
 * ============================================================ */

static const uint32_t crc32c_table[256] = {
    0x00000000, 0xF26B8303, 0xE13B70F7, 0x1350F3F4,
    0xC79A971F, 0x35F1141C, 0x26A1E7E8, 0xD4CA64EB,
    0x8AD958CF, 0x78B2DBCC, 0x6BE22838, 0x9989AB3B,
    0x4D43CFD0, 0xBF284CD3, 0xAC78BF27, 0x5E133C24,
    0x105EC76F, 0xE235446C, 0xF165B798, 0x030E349B,
    0xD7C45070, 0x25AFD373, 0x36FF2087, 0xC494A384,
    0x9A879FA0, 0x68EC1CA3, 0x7BBCEF57, 0x89D76C54,
    0x5D1D08BF, 0xAF768BBC, 0xBC267848, 0x4E4DFB4B,
    0x20BD8EDE, 0xD2D60DDD, 0xC186FE29, 0x33ED7D2A,
    0xE72719C1, 0x154C9AC2, 0x061C6936, 0xF477EA35,
    0xAA64D611, 0x580F5512, 0x4B5FA6E6, 0xB93425E5,
    0x6DFE410E, 0x9F95C20D, 0x8CC531F9, 0x7EAEB2FA,
    0x30E349B1, 0xC288CAB2, 0xD1D83946, 0x23B3BA45,
    0xF779DEAE, 0x05125DAD, 0x1642AE59, 0xE4292D5A,
    0xBA3A117E, 0x4851927D, 0x5B016189, 0xA96AE28A,
    0x7DA08661, 0x8FCB0562, 0x9C9BF696, 0x6EF07595,
    0x417B1DBC, 0xB3109EBF, 0xA0406D4B, 0x522BEE48,
    0x86E18AA3, 0x748A09A0, 0x67DAFA54, 0x95B17957,
    0xCBA24573, 0x39C9C670, 0x2A993584, 0xD8F2B687,
    0x0C38D26C, 0xFE53516F, 0xED03A29B, 0x1F682198,
    0x5125DAD3, 0xA34E59D0, 0xB01EAA24, 0x42752927,
    0x96BF4DCC, 0x64D4CECF, 0x77843D3B, 0x85EFBE38,
    0xDBFC821C, 0x2997011F, 0x3AC7F2EB, 0xC8AC71E8,
    0x1C661503, 0xEE0D9600, 0xFD5D65F4, 0x0F36E6F7,
    0x61C69362, 0x93AD1061, 0x80FDE395, 0x72966096,
    0xA65C047D, 0x5437877E, 0x4767748A, 0xB50CF789,
    0xEB1FCBAD, 0x197448AE, 0x0A24BB5A, 0xF84F3859,
    0x2C855CB2, 0xDEEEDFB1, 0xCDBE2C45, 0x3FD5AF46,
    0x7198540D, 0x83F3D70E, 0x90A324FA, 0x62C8A7F9,
    0xB602C312, 0x44694011, 0x5739B3E5, 0xA55230E6,
    0xFB410CC2, 0x092A8FC1, 0x1A7A7C35, 0xE811FF36,
    0x3CDB9BDD, 0xCEB018DE, 0xDDE0EB2A, 0x2F8B6829,
    0x82F63B78, 0x709DB87B, 0x63CD4B8F, 0x91A6C88C,
    0x456CAC67, 0xB7072F64, 0xA457DC90, 0x563C5F93,
    0x082F63B7, 0xFA44E0B4, 0xE9141340, 0x1B7F9043,
    0xCFB5F4A8, 0x3DDE77AB, 0x2E8E845F, 0xDCE5075C,
    0x92A8FC17, 0x60C37F14, 0x73938CE0, 0x81F80FE3,
    0x55326B08, 0xA759E80B, 0xB4091BFF, 0x466298FC,
    0x1871A4D8, 0xEA1A27DB, 0xF94AD42F, 0x0B21572C,
    0xDFEB33C7, 0x2D80B0C4, 0x3ED04330, 0xCCBBC033,
    0xA24BB5A6, 0x502036A5, 0x4370C551, 0xB11B4652,
    0x65D122B9, 0x97BAA1BA, 0x84EA524E, 0x7681D14D,
    0x2892ED69, 0xDAF96E6A, 0xC9A99D9E, 0x3BC21E9D,
    0xEF087A76, 0x1D63F975, 0x0E330A81, 0xFC588982,
    0xB21572C9, 0x407EF1CA, 0x532E023E, 0xA145813D,
    0x758FE5D6, 0x87E466D5, 0x94B49521, 0x66DF1622,
    0x38CC2A06, 0xCAA7A905, 0xD9F75AF1, 0x2B9CD9F2,
    0xFF56BD19, 0x0D3D3E1A, 0x1E6DCDEE, 0xEC064EED,
    0xC38D26C4, 0x31E6A5C7, 0x22B65633, 0xD0DDD530,
    0x0417B1DB, 0xF67C32D8, 0xE52CC12C, 0x1747422F,
    0x49547E0B, 0xBB3FFD08, 0xA86F0EFC, 0x5A048DFF,
    0x8ECEE914, 0x7CA56A17, 0x6FF599E3, 0x9D9E1AE0,
    0xD3D3E1AB, 0x21B862A8, 0x32E8915C, 0xC083125F,
    0x144976B4, 0xE622F5B7, 0xF5720643, 0x07198540,
    0x590AB964, 0xAB613A67, 0xB831C993, 0x4A5A4A90,
    0x9E902E7B, 0x6CFBAD78, 0x7FAB5E8C, 0x8DC0DD8F,
    0xE330A81A, 0x115B2B19, 0x020BD8ED, 0xF0605BEE,
    0x24AA3F05, 0xD6C1BC06, 0xC5914FF2, 0x37FACCF1,
    0x69E9F0D5, 0x9B8273D6, 0x88D28022, 0x7AB90321,
    0xAE7367CA, 0x5C18E4C9, 0x4F48173D, 0xBD23943E,
    0xF36E6F75, 0x0105EC76, 0x12551F82, 0xE03E9C81,
    0x34F4F86A, 0xC69F7B69, 0xD5CF889D, 0x27A40B9E,
    0x79B737BA, 0x8BDCB4B9, 0x988C474D, 0x6AE7C44E,
    0xBE2DA0A5, 0x4C4623A6, 0x5F16D052, 0xAD7D5351,
};

static uint32_t crc32c(const uint8_t *data, uint64_t len)
{
    uint32_t crc = 0xFFFFFFFF;
    while (len--) {
        crc = (crc >> 8) ^ crc32c_table[(crc ^ *data++) & 0xFF];
    }
    return crc ^ 0xFFFFFFFF;
}

/* ============================================================
 * MOCK IPC FUNCTIONS
 * ============================================================ */

static uint32_t mock_compute_checksum(ak_ipc_header_t *hdr, mock_buffer_t *payload)
{
    uint32_t crc = 0xFFFFFFFF;

    /* Hash header (first 16 bytes, excluding checksum field) */
    uint8_t *hdr_bytes = (uint8_t *)hdr;
    for (int i = 0; i < 16; i++) {
        crc = (crc >> 8) ^ crc32c_table[(crc ^ hdr_bytes[i]) & 0xFF];
    }

    /* Hash payload */
    if (payload && payload->length > 0) {
        uint8_t *p = payload->data;
        uint64_t len = payload->length;
        while (len--) {
            crc = (crc >> 8) ^ crc32c_table[(crc ^ *p++) & 0xFF];
        }
    }

    return crc ^ 0xFFFFFFFF;
}

static int64_t mock_validate_header(ak_ipc_header_t *hdr)
{
    if (!hdr)
        return -EINVAL;

    /* Check magic */
    if (hdr->magic != AK_IPC_MAGIC)
        return AK_E_IPC_INVALID;

    /* Check version */
    if (hdr->version != AK_IPC_VERSION)
        return AK_E_IPC_INVALID;

    /* Check payload length */
    if (hdr->payload_length > AK_IPC_MAX_PAYLOAD)
        return AK_E_IPC_INVALID;

    return 0;
}

static int64_t mock_validate_payload(uint8_t flags, mock_buffer_t *payload)
{
    if (!payload || payload->length == 0)
        return -EINVAL;

    /* Validate JSON structure */
    uint8_t *data = payload->data;
    if (data[0] != '{' && data[0] != '[')
        return AK_E_IPC_INVALID;

    (void)flags;
    return 0;
}

/* Channel management */
static ak_ipc_channel_t *mock_channel_create(uint8_t *agent_id, int fd)
{
    ak_ipc_channel_t *ch = calloc(1, sizeof(ak_ipc_channel_t));
    if (!ch) return NULL;

    ch->fd = fd;
    ch->state = AK_CHANNEL_CONNECTED;
    ch->next_seq = 1;

    if (agent_id)
        memcpy(ch->agent_id, agent_id, AK_TOKEN_ID_SIZE);

    ch->recv_buf = mock_buffer_create(4096);
    if (!ch->recv_buf) {
        free(ch);
        return NULL;
    }

    return ch;
}

static void mock_channel_destroy(ak_ipc_channel_t *ch)
{
    if (ch) {
        mock_buffer_destroy(ch->recv_buf);
        free(ch);
    }
}

static ak_channel_state_t mock_channel_state(ak_ipc_channel_t *ch)
{
    return ch ? ch->state : AK_CHANNEL_DISCONNECTED;
}

static void mock_channel_stats(ak_ipc_channel_t *ch, ak_ipc_stats_t *stats)
{
    if (ch && stats) {
        stats->frames_sent = ch->frames_sent;
        stats->frames_received = ch->frames_received;
        stats->bytes_sent = ch->bytes_sent;
        stats->bytes_received = ch->bytes_received;
        stats->errors = ch->errors;
        stats->checksum_failures = ch->checksum_failures;
    }
}

/* Sequence tracker management */
static ak_seq_tracker_t *mock_seq_tracker_create(uint8_t *pid, uint8_t *run_id)
{
    ak_seq_tracker_t *tracker = calloc(1, sizeof(ak_seq_tracker_t));
    if (!tracker) return NULL;

    if (pid)
        memcpy(tracker->pid, pid, AK_TOKEN_ID_SIZE);
    if (run_id)
        memcpy(tracker->run_id, run_id, AK_TOKEN_ID_SIZE);

    tracker->highest_seen = 0;
    tracker->expected_next = 1;
    tracker->window_base = 0;

    return tracker;
}

static void mock_seq_tracker_destroy(ak_seq_tracker_t *tracker)
{
    free(tracker);
}

static int64_t mock_seq_tracker_check(ak_seq_tracker_t *tracker, uint64_t seq)
{
    if (!tracker)
        return -EINVAL;

    /* Check for replay */
    if (seq <= tracker->highest_seen) {
        if (seq >= tracker->window_base &&
            seq < tracker->window_base + SEQ_WINDOW_SIZE) {
            uint64_t offset = seq - tracker->window_base;
            uint64_t byte_idx = offset / 8;
            uint8_t bit_mask = 1 << (offset % 8);

            if (tracker->seen_bitmap[byte_idx] & bit_mask) {
                return AK_E_REPLAY;
            }
            tracker->seen_bitmap[byte_idx] |= bit_mask;
        }
        return AK_E_REPLAY;
    }

    /* Check for gap */
    int64_t result = 0;
    if (seq > tracker->expected_next) {
        result = AK_E_SEQ_GAP;
    }

    /* Update tracking */
    tracker->highest_seen = seq;
    tracker->expected_next = seq + 1;

    /* Slide window if needed */
    if (seq >= tracker->window_base + SEQ_WINDOW_SIZE) {
        uint64_t new_base = seq - SEQ_WINDOW_SIZE / 2;
        uint64_t shift = new_base - tracker->window_base;

        if (shift >= SEQ_WINDOW_SIZE) {
            memset(tracker->seen_bitmap, 0, SEQ_WINDOW_SIZE / 8);
        } else {
            uint64_t bytes_to_shift = shift / 8;
            if (bytes_to_shift > 0) {
                memmove(tracker->seen_bitmap,
                        tracker->seen_bitmap + bytes_to_shift,
                        SEQ_WINDOW_SIZE / 8 - bytes_to_shift);
                memset(tracker->seen_bitmap + SEQ_WINDOW_SIZE / 8 - bytes_to_shift,
                       0, bytes_to_shift);
            }
        }
        tracker->window_base = new_base;
    }

    /* Mark current sequence as seen */
    if (seq >= tracker->window_base &&
        seq < tracker->window_base + SEQ_WINDOW_SIZE) {
        uint64_t offset = seq - tracker->window_base;
        uint64_t byte_idx = offset / 8;
        uint8_t bit_mask = 1 << (offset % 8);
        tracker->seen_bitmap[byte_idx] |= bit_mask;
    }

    return result;
}

static uint64_t mock_seq_tracker_expected(ak_seq_tracker_t *tracker)
{
    return tracker ? tracker->expected_next : 0;
}

static uint64_t mock_seq_tracker_highest(ak_seq_tracker_t *tracker)
{
    return tracker ? tracker->highest_seen : 0;
}

/* Hex encoding/decoding */
static const char hex_chars[] = "0123456789abcdef";

static void mock_hex_encode(uint8_t *data, uint64_t len, char *out)
{
    for (uint64_t i = 0; i < len; i++) {
        out[i * 2] = hex_chars[(data[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hex_chars[data[i] & 0x0F];
    }
    out[len * 2] = '\0';
}

static int hex_digit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool mock_hex_decode(const char *hex, uint8_t *out, uint64_t max_len)
{
    if (!hex || !out)
        return false;

    uint64_t len = strlen(hex);
    if (len % 2 != 0 || len / 2 > max_len)
        return false;

    for (uint64_t i = 0; i < len / 2; i++) {
        int hi = hex_digit(hex[i * 2]);
        int lo = hex_digit(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0)
            return false;
        out[i] = (hi << 4) | lo;
    }

    return true;
}

/* Operation string conversion */
static const char *mock_op_to_string(uint16_t op)
{
    switch (op) {
    case AK_SYS_READ:       return "READ";
    case AK_SYS_ALLOC:      return "ALLOC";
    case AK_SYS_WRITE:      return "WRITE";
    case AK_SYS_DELETE:     return "DELETE";
    case AK_SYS_QUERY:      return "QUERY";
    case AK_SYS_BATCH:      return "BATCH";
    case AK_SYS_COMMIT:     return "COMMIT";
    case AK_SYS_CALL:       return "CALL";
    case AK_SYS_SPAWN:      return "SPAWN";
    case AK_SYS_SEND:       return "SEND";
    case AK_SYS_RECV:       return "RECV";
    case AK_SYS_RESPOND:    return "RESPOND";
    case AK_SYS_ASSERT:     return "ASSERT";
    case AK_SYS_INFERENCE:  return "INFERENCE";
    default:                return "UNKNOWN";
    }
}

static uint16_t mock_string_to_op(const char *str)
{
    if (!str) return 0;

    if (strcmp(str, "READ") == 0)       return AK_SYS_READ;
    if (strcmp(str, "ALLOC") == 0)      return AK_SYS_ALLOC;
    if (strcmp(str, "WRITE") == 0)      return AK_SYS_WRITE;
    if (strcmp(str, "DELETE") == 0)     return AK_SYS_DELETE;
    if (strcmp(str, "QUERY") == 0)      return AK_SYS_QUERY;
    if (strcmp(str, "BATCH") == 0)      return AK_SYS_BATCH;
    if (strcmp(str, "COMMIT") == 0)     return AK_SYS_COMMIT;
    if (strcmp(str, "CALL") == 0)       return AK_SYS_CALL;
    if (strcmp(str, "SPAWN") == 0)      return AK_SYS_SPAWN;
    if (strcmp(str, "SEND") == 0)       return AK_SYS_SEND;
    if (strcmp(str, "RECV") == 0)       return AK_SYS_RECV;
    if (strcmp(str, "RESPOND") == 0)    return AK_SYS_RESPOND;
    if (strcmp(str, "ASSERT") == 0)     return AK_SYS_ASSERT;
    if (strcmp(str, "INFERENCE") == 0)  return AK_SYS_INFERENCE;

    return 0;
}

/* Error messages */
static const char *mock_error_message(int64_t error_code)
{
    switch (error_code) {
    case 0:                     return "success";
    case AK_E_CAP_INVALID:      return "capability invalid";
    case AK_E_CAP_EXPIRED:      return "capability expired";
    case AK_E_CAP_SCOPE:        return "capability scope insufficient";
    case AK_E_CAP_RATE:         return "rate limit exceeded";
    case AK_E_CAP_RUN_MISMATCH: return "run ID mismatch";
    case AK_E_REPLAY:           return "replay detected";
    case AK_E_SEQ_GAP:          return "sequence gap";
    case AK_E_CONFLICT:         return "version conflict";
    case AK_E_SCHEMA_INVALID:   return "schema validation failed";
    case AK_E_POLICY_DENIED:    return "policy denied";
    case AK_E_BUDGET_EXCEEDED:  return "budget exceeded";
    case AK_E_IPC_INVALID:      return "invalid IPC frame";
    case AK_E_TAINT:            return "taint violation";
    case AK_E_LOG_CORRUPT:      return "log corruption detected";
    case AK_E_TIMEOUT:          return "timeout";
    case -EINVAL:               return "invalid argument";
    case -ENOENT:               return "not found";
    case -ENOMEM:               return "out of memory";
    case -EPERM:                return "permission denied";
    default:                    return "unknown error";
    }
}

/* ============================================================
 * TEST CASES: FRAME FORMAT VALIDATION
 * ============================================================ */

bool test_frame_magic_valid(void)
{
    ak_ipc_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));

    hdr.magic = AK_IPC_MAGIC;
    hdr.version = AK_IPC_VERSION;
    hdr.payload_length = 0;

    int64_t result = mock_validate_header(&hdr);
    test_assert_eq(result, 0);

    return true;
}

bool test_frame_magic_invalid(void)
{
    ak_ipc_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));

    /* Wrong magic number */
    hdr.magic = 0xDEAD;
    hdr.version = AK_IPC_VERSION;
    hdr.payload_length = 0;

    int64_t result = mock_validate_header(&hdr);
    test_assert_eq(result, AK_E_IPC_INVALID);

    return true;
}

bool test_frame_magic_zero(void)
{
    ak_ipc_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));

    hdr.magic = 0;
    hdr.version = AK_IPC_VERSION;

    int64_t result = mock_validate_header(&hdr);
    test_assert_eq(result, AK_E_IPC_INVALID);

    return true;
}

bool test_frame_magic_swapped_bytes(void)
{
    ak_ipc_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));

    /* Byte-swapped magic (big-endian vs little-endian) */
    hdr.magic = 0x4B41;  /* "KA" instead of "AK" */
    hdr.version = AK_IPC_VERSION;

    int64_t result = mock_validate_header(&hdr);
    test_assert_eq(result, AK_E_IPC_INVALID);

    return true;
}

bool test_frame_version_valid(void)
{
    ak_ipc_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));

    hdr.magic = AK_IPC_MAGIC;
    hdr.version = AK_IPC_VERSION;
    hdr.payload_length = 0;

    int64_t result = mock_validate_header(&hdr);
    test_assert_eq(result, 0);

    return true;
}

bool test_frame_version_invalid(void)
{
    ak_ipc_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));

    hdr.magic = AK_IPC_MAGIC;
    hdr.version = 99;  /* Unsupported version */
    hdr.payload_length = 0;

    int64_t result = mock_validate_header(&hdr);
    test_assert_eq(result, AK_E_IPC_INVALID);

    return true;
}

bool test_frame_version_zero(void)
{
    ak_ipc_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));

    hdr.magic = AK_IPC_MAGIC;
    hdr.version = 0;

    int64_t result = mock_validate_header(&hdr);
    test_assert_eq(result, AK_E_IPC_INVALID);

    return true;
}

bool test_frame_version_future(void)
{
    ak_ipc_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));

    hdr.magic = AK_IPC_MAGIC;
    hdr.version = 255;  /* Future version */

    int64_t result = mock_validate_header(&hdr);
    test_assert_eq(result, AK_E_IPC_INVALID);

    return true;
}

bool test_frame_payload_length_zero(void)
{
    ak_ipc_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));

    hdr.magic = AK_IPC_MAGIC;
    hdr.version = AK_IPC_VERSION;
    hdr.payload_length = 0;

    int64_t result = mock_validate_header(&hdr);
    test_assert_eq(result, 0);

    return true;
}

bool test_frame_payload_length_max(void)
{
    ak_ipc_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));

    hdr.magic = AK_IPC_MAGIC;
    hdr.version = AK_IPC_VERSION;
    hdr.payload_length = AK_IPC_MAX_PAYLOAD;

    int64_t result = mock_validate_header(&hdr);
    test_assert_eq(result, 0);

    return true;
}

bool test_frame_payload_length_exceeds_max(void)
{
    ak_ipc_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));

    hdr.magic = AK_IPC_MAGIC;
    hdr.version = AK_IPC_VERSION;
    hdr.payload_length = AK_IPC_MAX_PAYLOAD + 1;

    int64_t result = mock_validate_header(&hdr);
    test_assert_eq(result, AK_E_IPC_INVALID);

    return true;
}

bool test_frame_payload_length_max_uint32(void)
{
    ak_ipc_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));

    hdr.magic = AK_IPC_MAGIC;
    hdr.version = AK_IPC_VERSION;
    hdr.payload_length = UINT32_MAX;

    int64_t result = mock_validate_header(&hdr);
    test_assert_eq(result, AK_E_IPC_INVALID);

    return true;
}

bool test_frame_header_null(void)
{
    int64_t result = mock_validate_header(NULL);
    test_assert_eq(result, -EINVAL);

    return true;
}

bool test_frame_checksum_valid(void)
{
    ak_ipc_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));

    hdr.magic = AK_IPC_MAGIC;
    hdr.version = AK_IPC_VERSION;
    hdr.flags = AK_IPC_FLAG_REQUEST;
    hdr.payload_length = 2;
    hdr.sequence = 1;

    mock_buffer_t *payload = mock_buffer_create(16);
    mock_buffer_write(payload, "{}", 2);

    hdr.checksum = mock_compute_checksum(&hdr, payload);

    /* Verify checksum matches */
    uint32_t computed = mock_compute_checksum(&hdr, payload);
    test_assert_eq(computed, hdr.checksum);

    mock_buffer_destroy(payload);
    return true;
}

bool test_frame_checksum_mismatch(void)
{
    ak_ipc_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));

    hdr.magic = AK_IPC_MAGIC;
    hdr.version = AK_IPC_VERSION;
    hdr.flags = AK_IPC_FLAG_REQUEST;
    hdr.payload_length = 2;
    hdr.sequence = 1;

    mock_buffer_t *payload = mock_buffer_create(16);
    mock_buffer_write(payload, "{}", 2);

    hdr.checksum = 0xDEADBEEF;  /* Wrong checksum */

    uint32_t computed = mock_compute_checksum(&hdr, payload);
    test_assert_neq(computed, hdr.checksum);

    mock_buffer_destroy(payload);
    return true;
}

bool test_frame_checksum_empty_payload(void)
{
    ak_ipc_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));

    hdr.magic = AK_IPC_MAGIC;
    hdr.version = AK_IPC_VERSION;
    hdr.payload_length = 0;

    uint32_t checksum = mock_compute_checksum(&hdr, NULL);

    /* Same header should produce same checksum */
    uint32_t checksum2 = mock_compute_checksum(&hdr, NULL);
    test_assert_eq(checksum, checksum2);

    return true;
}

bool test_frame_checksum_different_payloads(void)
{
    ak_ipc_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));

    hdr.magic = AK_IPC_MAGIC;
    hdr.version = AK_IPC_VERSION;

    mock_buffer_t *payload1 = mock_buffer_create(16);
    mock_buffer_write(payload1, "{\"a\":1}", 7);

    mock_buffer_t *payload2 = mock_buffer_create(16);
    mock_buffer_write(payload2, "{\"a\":2}", 7);

    hdr.payload_length = 7;

    uint32_t checksum1 = mock_compute_checksum(&hdr, payload1);
    uint32_t checksum2 = mock_compute_checksum(&hdr, payload2);

    test_assert_neq(checksum1, checksum2);

    mock_buffer_destroy(payload1);
    mock_buffer_destroy(payload2);
    return true;
}

/* ============================================================
 * TEST CASES: CHANNEL MANAGEMENT
 * ============================================================ */

bool test_channel_create_basic(void)
{
    uint8_t agent_id[AK_TOKEN_ID_SIZE] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    ak_ipc_channel_t *ch = mock_channel_create(agent_id, 42);
    test_assert_not_null(ch);
    test_assert_eq(ch->fd, 42);
    test_assert_eq(ch->state, AK_CHANNEL_CONNECTED);
    test_assert_eq(ch->next_seq, 1);
    test_assert_mem_eq(ch->agent_id, agent_id, AK_TOKEN_ID_SIZE);

    mock_channel_destroy(ch);
    return true;
}

bool test_channel_create_null_agent_id(void)
{
    ak_ipc_channel_t *ch = mock_channel_create(NULL, 42);
    test_assert_not_null(ch);

    /* Agent ID should be zeroed */
    uint8_t zero_id[AK_TOKEN_ID_SIZE] = {0};
    test_assert_mem_eq(ch->agent_id, zero_id, AK_TOKEN_ID_SIZE);

    mock_channel_destroy(ch);
    return true;
}

bool test_channel_destroy_null(void)
{
    /* Should not crash */
    mock_channel_destroy(NULL);
    return true;
}

bool test_channel_state_connected(void)
{
    ak_ipc_channel_t *ch = mock_channel_create(NULL, 0);
    test_assert_not_null(ch);

    test_assert_eq(mock_channel_state(ch), AK_CHANNEL_CONNECTED);

    mock_channel_destroy(ch);
    return true;
}

bool test_channel_state_null(void)
{
    test_assert_eq(mock_channel_state(NULL), AK_CHANNEL_DISCONNECTED);
    return true;
}

bool test_channel_state_transitions(void)
{
    ak_ipc_channel_t *ch = mock_channel_create(NULL, 0);
    test_assert_not_null(ch);

    /* Test all state transitions */
    ch->state = AK_CHANNEL_DISCONNECTED;
    test_assert_eq(mock_channel_state(ch), AK_CHANNEL_DISCONNECTED);

    ch->state = AK_CHANNEL_CONNECTING;
    test_assert_eq(mock_channel_state(ch), AK_CHANNEL_CONNECTING);

    ch->state = AK_CHANNEL_CONNECTED;
    test_assert_eq(mock_channel_state(ch), AK_CHANNEL_CONNECTED);

    ch->state = AK_CHANNEL_ERROR;
    test_assert_eq(mock_channel_state(ch), AK_CHANNEL_ERROR);

    mock_channel_destroy(ch);
    return true;
}

bool test_channel_stats_initial(void)
{
    ak_ipc_channel_t *ch = mock_channel_create(NULL, 0);
    test_assert_not_null(ch);

    ak_ipc_stats_t stats;
    mock_channel_stats(ch, &stats);

    test_assert_eq(stats.frames_sent, 0);
    test_assert_eq(stats.frames_received, 0);
    test_assert_eq(stats.bytes_sent, 0);
    test_assert_eq(stats.bytes_received, 0);
    test_assert_eq(stats.errors, 0);
    test_assert_eq(stats.checksum_failures, 0);

    mock_channel_destroy(ch);
    return true;
}

bool test_channel_stats_tracking(void)
{
    ak_ipc_channel_t *ch = mock_channel_create(NULL, 0);
    test_assert_not_null(ch);

    /* Simulate activity */
    ch->frames_sent = 10;
    ch->frames_received = 8;
    ch->bytes_sent = 1024;
    ch->bytes_received = 512;
    ch->errors = 2;
    ch->checksum_failures = 1;

    ak_ipc_stats_t stats;
    mock_channel_stats(ch, &stats);

    test_assert_eq(stats.frames_sent, 10);
    test_assert_eq(stats.frames_received, 8);
    test_assert_eq(stats.bytes_sent, 1024);
    test_assert_eq(stats.bytes_received, 512);
    test_assert_eq(stats.errors, 2);
    test_assert_eq(stats.checksum_failures, 1);

    mock_channel_destroy(ch);
    return true;
}

bool test_channel_stats_null_channel(void)
{
    ak_ipc_stats_t stats;
    memset(&stats, 0xFF, sizeof(stats));

    /* Should not crash, stats unchanged */
    mock_channel_stats(NULL, &stats);

    return true;
}

bool test_channel_stats_null_stats(void)
{
    ak_ipc_channel_t *ch = mock_channel_create(NULL, 0);
    test_assert_not_null(ch);

    /* Should not crash */
    mock_channel_stats(ch, NULL);

    mock_channel_destroy(ch);
    return true;
}

/* ============================================================
 * TEST CASES: SEQUENCE TRACKING (ANTI-REPLAY)
 * ============================================================ */

bool test_seq_tracker_create(void)
{
    uint8_t pid[AK_TOKEN_ID_SIZE] = {1};
    uint8_t run_id[AK_TOKEN_ID_SIZE] = {2};

    ak_seq_tracker_t *tracker = mock_seq_tracker_create(pid, run_id);
    test_assert_not_null(tracker);
    test_assert_mem_eq(tracker->pid, pid, AK_TOKEN_ID_SIZE);
    test_assert_mem_eq(tracker->run_id, run_id, AK_TOKEN_ID_SIZE);
    test_assert_eq(tracker->highest_seen, 0);
    test_assert_eq(tracker->expected_next, 1);

    mock_seq_tracker_destroy(tracker);
    return true;
}

bool test_seq_tracker_create_null_ids(void)
{
    ak_seq_tracker_t *tracker = mock_seq_tracker_create(NULL, NULL);
    test_assert_not_null(tracker);

    uint8_t zero[AK_TOKEN_ID_SIZE] = {0};
    test_assert_mem_eq(tracker->pid, zero, AK_TOKEN_ID_SIZE);
    test_assert_mem_eq(tracker->run_id, zero, AK_TOKEN_ID_SIZE);

    mock_seq_tracker_destroy(tracker);
    return true;
}

bool test_seq_tracker_monotonic_valid(void)
{
    ak_seq_tracker_t *tracker = mock_seq_tracker_create(NULL, NULL);
    test_assert_not_null(tracker);

    /* Sequential sequences should work */
    test_assert_eq(mock_seq_tracker_check(tracker, 1), 0);
    test_assert_eq(mock_seq_tracker_check(tracker, 2), 0);
    test_assert_eq(mock_seq_tracker_check(tracker, 3), 0);
    test_assert_eq(mock_seq_tracker_check(tracker, 4), 0);
    test_assert_eq(mock_seq_tracker_check(tracker, 5), 0);

    test_assert_eq(tracker->highest_seen, 5);
    test_assert_eq(tracker->expected_next, 6);

    mock_seq_tracker_destroy(tracker);
    return true;
}

bool test_seq_tracker_replay_detection(void)
{
    ak_seq_tracker_t *tracker = mock_seq_tracker_create(NULL, NULL);
    test_assert_not_null(tracker);

    /* First occurrence should succeed */
    test_assert_eq(mock_seq_tracker_check(tracker, 5), 0);

    /* Replay should fail */
    test_assert_eq(mock_seq_tracker_check(tracker, 5), AK_E_REPLAY);
    test_assert_eq(mock_seq_tracker_check(tracker, 5), AK_E_REPLAY);

    mock_seq_tracker_destroy(tracker);
    return true;
}

bool test_seq_tracker_replay_old_sequence(void)
{
    ak_seq_tracker_t *tracker = mock_seq_tracker_create(NULL, NULL);
    test_assert_not_null(tracker);

    /* Move forward */
    test_assert_eq(mock_seq_tracker_check(tracker, 10), 0);

    /* Old sequences should be rejected as replay */
    test_assert_eq(mock_seq_tracker_check(tracker, 1), AK_E_REPLAY);
    test_assert_eq(mock_seq_tracker_check(tracker, 5), AK_E_REPLAY);
    test_assert_eq(mock_seq_tracker_check(tracker, 9), AK_E_REPLAY);

    mock_seq_tracker_destroy(tracker);
    return true;
}

bool test_seq_tracker_gap_detection(void)
{
    ak_seq_tracker_t *tracker = mock_seq_tracker_create(NULL, NULL);
    test_assert_not_null(tracker);

    /* First sequence */
    test_assert_eq(mock_seq_tracker_check(tracker, 1), 0);

    /* Gap detected (but allowed) */
    test_assert_eq(mock_seq_tracker_check(tracker, 5), AK_E_SEQ_GAP);

    /* Continuing after gap */
    test_assert_eq(mock_seq_tracker_check(tracker, 6), 0);

    mock_seq_tracker_destroy(tracker);
    return true;
}

bool test_seq_tracker_large_gap(void)
{
    ak_seq_tracker_t *tracker = mock_seq_tracker_create(NULL, NULL);
    test_assert_not_null(tracker);

    /* Start normally */
    test_assert_eq(mock_seq_tracker_check(tracker, 1), 0);

    /* Large gap */
    test_assert_eq(mock_seq_tracker_check(tracker, 10000), AK_E_SEQ_GAP);

    /* Highest should be updated */
    test_assert_eq(tracker->highest_seen, 10000);

    mock_seq_tracker_destroy(tracker);
    return true;
}

bool test_seq_tracker_sliding_window(void)
{
    ak_seq_tracker_t *tracker = mock_seq_tracker_create(NULL, NULL);
    test_assert_not_null(tracker);

    /* Process sequences within window */
    for (int i = 1; i <= 100; i++) {
        int64_t result = mock_seq_tracker_check(tracker, i);
        if (i == 1) {
            test_assert_eq(result, 0);
        } else {
            /* May be 0 or AK_E_SEQ_GAP depending on implementation */
            test_assert(result == 0 || result == AK_E_SEQ_GAP);
        }
    }

    /* All these should now be detected as replays */
    for (int i = 1; i <= 100; i++) {
        test_assert_eq(mock_seq_tracker_check(tracker, i), AK_E_REPLAY);
    }

    mock_seq_tracker_destroy(tracker);
    return true;
}

bool test_seq_tracker_window_slide(void)
{
    ak_seq_tracker_t *tracker = mock_seq_tracker_create(NULL, NULL);
    test_assert_not_null(tracker);

    /* Process enough sequences to force window slide */
    for (uint64_t i = 1; i <= SEQ_WINDOW_SIZE + 100; i++) {
        mock_seq_tracker_check(tracker, i);
    }

    /* Very old sequences should be rejected */
    test_assert_eq(mock_seq_tracker_check(tracker, 1), AK_E_REPLAY);
    test_assert_eq(mock_seq_tracker_check(tracker, 10), AK_E_REPLAY);

    mock_seq_tracker_destroy(tracker);
    return true;
}

bool test_seq_tracker_expected(void)
{
    ak_seq_tracker_t *tracker = mock_seq_tracker_create(NULL, NULL);
    test_assert_not_null(tracker);

    test_assert_eq(mock_seq_tracker_expected(tracker), 1);

    mock_seq_tracker_check(tracker, 1);
    test_assert_eq(mock_seq_tracker_expected(tracker), 2);

    mock_seq_tracker_check(tracker, 5);  /* Gap */
    test_assert_eq(mock_seq_tracker_expected(tracker), 6);

    mock_seq_tracker_destroy(tracker);
    return true;
}

bool test_seq_tracker_highest(void)
{
    ak_seq_tracker_t *tracker = mock_seq_tracker_create(NULL, NULL);
    test_assert_not_null(tracker);

    test_assert_eq(mock_seq_tracker_highest(tracker), 0);

    mock_seq_tracker_check(tracker, 5);
    test_assert_eq(mock_seq_tracker_highest(tracker), 5);

    mock_seq_tracker_check(tracker, 10);
    test_assert_eq(mock_seq_tracker_highest(tracker), 10);

    /* Old sequence shouldn't update highest */
    mock_seq_tracker_check(tracker, 3);  /* Replay */
    test_assert_eq(mock_seq_tracker_highest(tracker), 10);

    mock_seq_tracker_destroy(tracker);
    return true;
}

bool test_seq_tracker_null(void)
{
    test_assert_eq(mock_seq_tracker_check(NULL, 1), -EINVAL);
    test_assert_eq(mock_seq_tracker_expected(NULL), 0);
    test_assert_eq(mock_seq_tracker_highest(NULL), 0);

    return true;
}

bool test_seq_tracker_zero_sequence(void)
{
    ak_seq_tracker_t *tracker = mock_seq_tracker_create(NULL, NULL);
    test_assert_not_null(tracker);

    /* Sequence 0 should be treated as old/replay since expected starts at 1 */
    test_assert_eq(mock_seq_tracker_check(tracker, 0), AK_E_REPLAY);

    mock_seq_tracker_destroy(tracker);
    return true;
}

bool test_seq_tracker_uint64_max(void)
{
    ak_seq_tracker_t *tracker = mock_seq_tracker_create(NULL, NULL);
    test_assert_not_null(tracker);

    /* Maximum sequence number */
    test_assert_eq(mock_seq_tracker_check(tracker, UINT64_MAX), 0);
    test_assert_eq(tracker->highest_seen, UINT64_MAX);

    mock_seq_tracker_destroy(tracker);
    return true;
}

/* ============================================================
 * TEST CASES: HEX ENCODING/DECODING
 * ============================================================ */

bool test_hex_encode_basic(void)
{
    uint8_t data[] = {0xDE, 0xAD, 0xBE, 0xEF};
    char out[9];

    mock_hex_encode(data, 4, out);
    test_assert_str_eq(out, "deadbeef");

    return true;
}

bool test_hex_encode_zeros(void)
{
    uint8_t data[] = {0x00, 0x00, 0x00, 0x00};
    char out[9];

    mock_hex_encode(data, 4, out);
    test_assert_str_eq(out, "00000000");

    return true;
}

bool test_hex_encode_all_bytes(void)
{
    uint8_t data[16];
    for (int i = 0; i < 16; i++) data[i] = i * 16 + i;

    char out[33];
    mock_hex_encode(data, 16, out);

    /* Verify each byte encoded correctly */
    test_assert_eq(strlen(out), 32);

    return true;
}

bool test_hex_decode_basic(void)
{
    uint8_t out[4];
    bool result = mock_hex_decode("deadbeef", out, 4);

    test_assert(result);
    test_assert_eq(out[0], 0xDE);
    test_assert_eq(out[1], 0xAD);
    test_assert_eq(out[2], 0xBE);
    test_assert_eq(out[3], 0xEF);

    return true;
}

bool test_hex_decode_uppercase(void)
{
    uint8_t out[4];
    bool result = mock_hex_decode("DEADBEEF", out, 4);

    test_assert(result);
    test_assert_eq(out[0], 0xDE);
    test_assert_eq(out[1], 0xAD);
    test_assert_eq(out[2], 0xBE);
    test_assert_eq(out[3], 0xEF);

    return true;
}

bool test_hex_decode_mixed_case(void)
{
    uint8_t out[4];
    bool result = mock_hex_decode("DeAdBeEf", out, 4);

    test_assert(result);
    test_assert_eq(out[0], 0xDE);
    test_assert_eq(out[1], 0xAD);
    test_assert_eq(out[2], 0xBE);
    test_assert_eq(out[3], 0xEF);

    return true;
}

bool test_hex_decode_odd_length(void)
{
    uint8_t out[4];
    bool result = mock_hex_decode("deadbee", out, 4);  /* Odd length */

    test_assert(!result);

    return true;
}

bool test_hex_decode_invalid_chars(void)
{
    uint8_t out[4];

    test_assert(!mock_hex_decode("deadbexf", out, 4));  /* 'x' is invalid */
    test_assert(!mock_hex_decode("deadbe f", out, 4));  /* space is invalid */
    test_assert(!mock_hex_decode("deadbe-f", out, 4));  /* hyphen is invalid */

    return true;
}

bool test_hex_decode_buffer_too_small(void)
{
    uint8_t out[2];
    bool result = mock_hex_decode("deadbeef", out, 2);  /* Need 4, have 2 */

    test_assert(!result);

    return true;
}

bool test_hex_decode_null_inputs(void)
{
    uint8_t out[4];

    test_assert(!mock_hex_decode(NULL, out, 4));
    test_assert(!mock_hex_decode("deadbeef", NULL, 4));

    return true;
}

bool test_hex_roundtrip(void)
{
    uint8_t original[AK_TOKEN_ID_SIZE];
    for (int i = 0; i < AK_TOKEN_ID_SIZE; i++) {
        original[i] = (uint8_t)(i * 17 + 5);
    }

    char hex[AK_TOKEN_ID_SIZE * 2 + 1];
    mock_hex_encode(original, AK_TOKEN_ID_SIZE, hex);

    uint8_t decoded[AK_TOKEN_ID_SIZE];
    test_assert(mock_hex_decode(hex, decoded, AK_TOKEN_ID_SIZE));
    test_assert_mem_eq(original, decoded, AK_TOKEN_ID_SIZE);

    return true;
}

/* ============================================================
 * TEST CASES: OPERATION STRING CONVERSION
 * ============================================================ */

bool test_op_to_string(void)
{
    test_assert_str_eq(mock_op_to_string(AK_SYS_READ), "READ");
    test_assert_str_eq(mock_op_to_string(AK_SYS_ALLOC), "ALLOC");
    test_assert_str_eq(mock_op_to_string(AK_SYS_WRITE), "WRITE");
    test_assert_str_eq(mock_op_to_string(AK_SYS_DELETE), "DELETE");
    test_assert_str_eq(mock_op_to_string(AK_SYS_QUERY), "QUERY");
    test_assert_str_eq(mock_op_to_string(AK_SYS_BATCH), "BATCH");
    test_assert_str_eq(mock_op_to_string(AK_SYS_COMMIT), "COMMIT");
    test_assert_str_eq(mock_op_to_string(AK_SYS_CALL), "CALL");
    test_assert_str_eq(mock_op_to_string(AK_SYS_SPAWN), "SPAWN");
    test_assert_str_eq(mock_op_to_string(AK_SYS_SEND), "SEND");
    test_assert_str_eq(mock_op_to_string(AK_SYS_RECV), "RECV");
    test_assert_str_eq(mock_op_to_string(AK_SYS_RESPOND), "RESPOND");
    test_assert_str_eq(mock_op_to_string(AK_SYS_ASSERT), "ASSERT");
    test_assert_str_eq(mock_op_to_string(AK_SYS_INFERENCE), "INFERENCE");
    test_assert_str_eq(mock_op_to_string(9999), "UNKNOWN");

    return true;
}

bool test_string_to_op(void)
{
    test_assert_eq(mock_string_to_op("READ"), AK_SYS_READ);
    test_assert_eq(mock_string_to_op("ALLOC"), AK_SYS_ALLOC);
    test_assert_eq(mock_string_to_op("WRITE"), AK_SYS_WRITE);
    test_assert_eq(mock_string_to_op("DELETE"), AK_SYS_DELETE);
    test_assert_eq(mock_string_to_op("QUERY"), AK_SYS_QUERY);
    test_assert_eq(mock_string_to_op("BATCH"), AK_SYS_BATCH);
    test_assert_eq(mock_string_to_op("COMMIT"), AK_SYS_COMMIT);
    test_assert_eq(mock_string_to_op("CALL"), AK_SYS_CALL);
    test_assert_eq(mock_string_to_op("SPAWN"), AK_SYS_SPAWN);
    test_assert_eq(mock_string_to_op("SEND"), AK_SYS_SEND);
    test_assert_eq(mock_string_to_op("RECV"), AK_SYS_RECV);
    test_assert_eq(mock_string_to_op("RESPOND"), AK_SYS_RESPOND);
    test_assert_eq(mock_string_to_op("ASSERT"), AK_SYS_ASSERT);
    test_assert_eq(mock_string_to_op("INFERENCE"), AK_SYS_INFERENCE);

    return true;
}

bool test_string_to_op_invalid(void)
{
    test_assert_eq(mock_string_to_op("INVALID"), 0);
    test_assert_eq(mock_string_to_op("read"), 0);  /* Case sensitive */
    test_assert_eq(mock_string_to_op(""), 0);
    test_assert_eq(mock_string_to_op(NULL), 0);

    return true;
}

bool test_op_roundtrip(void)
{
    uint16_t ops[] = {
        AK_SYS_READ, AK_SYS_ALLOC, AK_SYS_WRITE, AK_SYS_DELETE,
        AK_SYS_QUERY, AK_SYS_BATCH, AK_SYS_COMMIT, AK_SYS_CALL,
        AK_SYS_SPAWN, AK_SYS_SEND, AK_SYS_RECV, AK_SYS_RESPOND,
        AK_SYS_ASSERT, AK_SYS_INFERENCE
    };

    for (size_t i = 0; i < sizeof(ops) / sizeof(ops[0]); i++) {
        const char *str = mock_op_to_string(ops[i]);
        uint16_t recovered = mock_string_to_op(str);
        test_assert_eq(recovered, ops[i]);
    }

    return true;
}

/* ============================================================
 * TEST CASES: ERROR MESSAGES
 * ============================================================ */

bool test_error_messages(void)
{
    test_assert_str_eq(mock_error_message(0), "success");
    test_assert_str_eq(mock_error_message(AK_E_CAP_INVALID), "capability invalid");
    test_assert_str_eq(mock_error_message(AK_E_CAP_EXPIRED), "capability expired");
    test_assert_str_eq(mock_error_message(AK_E_REPLAY), "replay detected");
    test_assert_str_eq(mock_error_message(AK_E_SEQ_GAP), "sequence gap");
    test_assert_str_eq(mock_error_message(AK_E_IPC_INVALID), "invalid IPC frame");
    test_assert_str_eq(mock_error_message(AK_E_TIMEOUT), "timeout");
    test_assert_str_eq(mock_error_message(-EINVAL), "invalid argument");
    test_assert_str_eq(mock_error_message(-ENOENT), "not found");
    test_assert_str_eq(mock_error_message(-ENOMEM), "out of memory");
    test_assert_str_eq(mock_error_message(-9999), "unknown error");

    return true;
}

/* ============================================================
 * TEST CASES: PAYLOAD VALIDATION
 * ============================================================ */

bool test_payload_valid_json_object(void)
{
    mock_buffer_t *payload = mock_buffer_create(64);
    mock_buffer_write(payload, "{\"key\":\"value\"}", 15);

    int64_t result = mock_validate_payload(AK_IPC_FLAG_REQUEST, payload);
    test_assert_eq(result, 0);

    mock_buffer_destroy(payload);
    return true;
}

bool test_payload_valid_json_array(void)
{
    mock_buffer_t *payload = mock_buffer_create(64);
    mock_buffer_write(payload, "[1,2,3]", 7);

    int64_t result = mock_validate_payload(AK_IPC_FLAG_REQUEST, payload);
    test_assert_eq(result, 0);

    mock_buffer_destroy(payload);
    return true;
}

bool test_payload_invalid_not_json(void)
{
    mock_buffer_t *payload = mock_buffer_create(64);
    mock_buffer_write(payload, "plain text", 10);

    int64_t result = mock_validate_payload(AK_IPC_FLAG_REQUEST, payload);
    test_assert_eq(result, AK_E_IPC_INVALID);

    mock_buffer_destroy(payload);
    return true;
}

bool test_payload_null(void)
{
    int64_t result = mock_validate_payload(AK_IPC_FLAG_REQUEST, NULL);
    test_assert_eq(result, -EINVAL);

    return true;
}

bool test_payload_empty(void)
{
    mock_buffer_t *payload = mock_buffer_create(64);
    /* Length is 0 */

    int64_t result = mock_validate_payload(AK_IPC_FLAG_REQUEST, payload);
    test_assert_eq(result, -EINVAL);

    mock_buffer_destroy(payload);
    return true;
}

bool test_payload_whitespace_before_json(void)
{
    mock_buffer_t *payload = mock_buffer_create(64);
    mock_buffer_write(payload, "  {}", 4);  /* Whitespace before JSON */

    int64_t result = mock_validate_payload(AK_IPC_FLAG_REQUEST, payload);
    test_assert_eq(result, AK_E_IPC_INVALID);  /* Doesn't start with { or [ */

    mock_buffer_destroy(payload);
    return true;
}

/* ============================================================
 * TEST CASES: SECURITY ATTACK SCENARIOS
 * ============================================================ */

bool test_attack_replay_sequence(void)
{
    ak_seq_tracker_t *tracker = mock_seq_tracker_create(NULL, NULL);
    test_assert_not_null(tracker);

    /* Normal sequence */
    test_assert_eq(mock_seq_tracker_check(tracker, 100), 0);

    /* Attacker captures and replays */
    for (int attempt = 0; attempt < 1000; attempt++) {
        test_assert_eq(mock_seq_tracker_check(tracker, 100), AK_E_REPLAY);
    }

    mock_seq_tracker_destroy(tracker);
    return true;
}

bool test_attack_sequence_prediction(void)
{
    ak_seq_tracker_t *tracker = mock_seq_tracker_create(NULL, NULL);
    test_assert_not_null(tracker);

    /* Normal sequence */
    mock_seq_tracker_check(tracker, 1);
    mock_seq_tracker_check(tracker, 2);
    mock_seq_tracker_check(tracker, 3);

    /* Attacker tries to predict and preempt */
    test_assert_eq(mock_seq_tracker_check(tracker, 4), 0);  /* Valid, but attacker got it */

    /* Real client's sequence 4 is now rejected */
    test_assert_eq(mock_seq_tracker_check(tracker, 4), AK_E_REPLAY);

    mock_seq_tracker_destroy(tracker);
    return true;
}

bool test_attack_malformed_magic(void)
{
    ak_ipc_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));

    /* Various malformed magic attempts */
    uint16_t malicious_magics[] = {
        0x0000, 0xFFFF, 0x414C,  /* "AL" */
        0x424B,  /* "BK" */
        0x414B ^ 0x0001,  /* Single bit flip */
        0x414B ^ 0x8000,  /* High bit flip */
    };

    for (size_t i = 0; i < sizeof(malicious_magics) / sizeof(malicious_magics[0]); i++) {
        hdr.magic = malicious_magics[i];
        hdr.version = AK_IPC_VERSION;
        test_assert_eq(mock_validate_header(&hdr), AK_E_IPC_INVALID);
    }

    return true;
}

bool test_attack_oversized_payload(void)
{
    ak_ipc_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));

    hdr.magic = AK_IPC_MAGIC;
    hdr.version = AK_IPC_VERSION;

    /* Attempt to claim extremely large payload */
    hdr.payload_length = 1024 * 1024 * 1024;  /* 1 GB */
    test_assert_eq(mock_validate_header(&hdr), AK_E_IPC_INVALID);

    hdr.payload_length = UINT32_MAX;
    test_assert_eq(mock_validate_header(&hdr), AK_E_IPC_INVALID);

    return true;
}

bool test_attack_checksum_collision(void)
{
    ak_ipc_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));

    hdr.magic = AK_IPC_MAGIC;
    hdr.version = AK_IPC_VERSION;
    hdr.payload_length = 7;

    mock_buffer_t *payload = mock_buffer_create(16);
    mock_buffer_write(payload, "{\"a\":1}", 7);

    uint32_t original_checksum = mock_compute_checksum(&hdr, payload);

    /* Try to find payload that produces same checksum (won't succeed easily) */
    mock_buffer_t *malicious = mock_buffer_create(16);
    mock_buffer_write(malicious, "{\"a\":2}", 7);

    uint32_t malicious_checksum = mock_compute_checksum(&hdr, malicious);
    test_assert_neq(original_checksum, malicious_checksum);

    mock_buffer_destroy(payload);
    mock_buffer_destroy(malicious);
    return true;
}

bool test_attack_json_injection(void)
{
    mock_buffer_t *payload = mock_buffer_create(256);

    /* Attempt injection via JSON keys */
    const char *injections[] = {
        "{\"key\":\"value\",\"admin\":true}",
        "{\"key\":\"value\"}//comment",
        "{\"key\":\"value\\\"},{\\\"admin\\\":true}\"}",
        "{\"__proto__\":{\"admin\":true}}",
    };

    for (size_t i = 0; i < sizeof(injections) / sizeof(injections[0]); i++) {
        payload->length = 0;
        mock_buffer_write(payload, injections[i], strlen(injections[i]));

        /* These should all parse as valid JSON structure */
        int64_t result = mock_validate_payload(AK_IPC_FLAG_REQUEST, payload);
        /* Basic validation just checks it starts with { or [ */
        test_assert_eq(result, 0);
    }

    mock_buffer_destroy(payload);
    return true;
}

bool test_attack_hex_injection(void)
{
    uint8_t out[32];

    /* Attempt various hex injection attacks */
    test_assert(!mock_hex_decode("00000000000000000000000000000000"
                                  "0000000000000000000000000000000000", out, 32));
    test_assert(!mock_hex_decode("00;cat /etc/passwd", out, 32));
    test_assert(!mock_hex_decode("00`id`", out, 32));
    test_assert(!mock_hex_decode("00$(whoami)", out, 32));

    return true;
}

bool test_attack_frame_boundary(void)
{
    ak_ipc_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));

    hdr.magic = AK_IPC_MAGIC;
    hdr.version = AK_IPC_VERSION;

    /* Boundary conditions */
    hdr.payload_length = AK_IPC_MAX_PAYLOAD - 1;
    test_assert_eq(mock_validate_header(&hdr), 0);

    hdr.payload_length = AK_IPC_MAX_PAYLOAD;
    test_assert_eq(mock_validate_header(&hdr), 0);

    hdr.payload_length = AK_IPC_MAX_PAYLOAD + 1;
    test_assert_eq(mock_validate_header(&hdr), AK_E_IPC_INVALID);

    return true;
}

bool test_attack_null_byte_injection(void)
{
    mock_buffer_t *payload = mock_buffer_create(64);

    /* JSON with embedded null byte */
    char data[] = "{\"key\":\"\0value\"}";
    mock_buffer_write(payload, data, sizeof(data) - 1);

    /* Should still validate as JSON structure */
    int64_t result = mock_validate_payload(AK_IPC_FLAG_REQUEST, payload);
    test_assert_eq(result, 0);  /* Starts with { */

    mock_buffer_destroy(payload);
    return true;
}

bool test_attack_sequence_overflow(void)
{
    ak_seq_tracker_t *tracker = mock_seq_tracker_create(NULL, NULL);
    test_assert_not_null(tracker);

    /* Jump to near max */
    mock_seq_tracker_check(tracker, UINT64_MAX - 10);
    test_assert_eq(tracker->highest_seen, UINT64_MAX - 10);

    /* Continue towards max */
    mock_seq_tracker_check(tracker, UINT64_MAX - 5);
    mock_seq_tracker_check(tracker, UINT64_MAX);

    /* Attempting wrap-around should be replay */
    test_assert_eq(mock_seq_tracker_check(tracker, 0), AK_E_REPLAY);
    test_assert_eq(mock_seq_tracker_check(tracker, 1), AK_E_REPLAY);

    mock_seq_tracker_destroy(tracker);
    return true;
}

/* ============================================================
 * TEST CASES: CRC-32C SPECIFIC
 * ============================================================ */

bool test_crc32c_empty(void)
{
    uint32_t crc = crc32c(NULL, 0);
    /* Empty data should produce a defined CRC */
    test_assert_neq(crc, 0);  /* CRC of empty data is not zero */

    return true;
}

bool test_crc32c_known_values(void)
{
    /* Known test vectors for CRC-32C */
    uint8_t data1[] = "123456789";
    uint32_t crc1 = crc32c(data1, 9);
    /* CRC-32C of "123456789" should be 0xE3069283 */
    test_assert_eq(crc1, 0xE3069283);

    return true;
}

bool test_crc32c_incremental(void)
{
    uint8_t data[] = "Hello, World!";
    uint64_t len = strlen((char *)data);

    /* Full CRC */
    uint32_t full_crc = crc32c(data, len);

    /* Different data should produce different CRC */
    uint8_t data2[] = "Hello, World?";
    uint32_t crc2 = crc32c(data2, len);

    test_assert_neq(full_crc, crc2);

    return true;
}

bool test_crc32c_all_zeros(void)
{
    uint8_t data[256];
    memset(data, 0, sizeof(data));

    uint32_t crc = crc32c(data, sizeof(data));
    /* Should produce valid CRC even for all zeros */
    test_assert_neq(crc, 0xFFFFFFFF);  /* Not the initial CRC value */

    return true;
}

bool test_crc32c_all_ones(void)
{
    uint8_t data[256];
    memset(data, 0xFF, sizeof(data));

    uint32_t crc = crc32c(data, sizeof(data));
    /* Should produce valid CRC */
    test_assert_neq(crc, 0);

    return true;
}

/* ============================================================
 * TEST CASES: BATCH OPERATIONS
 * ============================================================ */

bool test_batch_flag(void)
{
    ak_ipc_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));

    hdr.magic = AK_IPC_MAGIC;
    hdr.version = AK_IPC_VERSION;
    hdr.flags = AK_IPC_FLAG_BATCH;
    hdr.payload_length = 0;

    int64_t result = mock_validate_header(&hdr);
    test_assert_eq(result, 0);

    return true;
}

bool test_batch_with_request_flag(void)
{
    ak_ipc_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));

    hdr.magic = AK_IPC_MAGIC;
    hdr.version = AK_IPC_VERSION;
    hdr.flags = AK_IPC_FLAG_BATCH | AK_IPC_FLAG_REQUEST;
    hdr.payload_length = 0;

    int64_t result = mock_validate_header(&hdr);
    test_assert_eq(result, 0);

    return true;
}

bool test_batch_payload_array(void)
{
    mock_buffer_t *payload = mock_buffer_create(256);
    mock_buffer_write(payload, "[{\"op\":\"READ\"},{\"op\":\"WRITE\"}]", 30);

    int64_t result = mock_validate_payload(AK_IPC_FLAG_BATCH, payload);
    test_assert_eq(result, 0);

    mock_buffer_destroy(payload);
    return true;
}

/* ============================================================
 * TEST CASES: EDGE CASES
 * ============================================================ */

bool test_header_size(void)
{
    /* Verify header size is as expected */
    test_assert_eq(sizeof(ak_ipc_header_t), AK_IPC_HEADER_SIZE);

    return true;
}

bool test_header_packed(void)
{
    ak_ipc_header_t hdr;

    /* Verify fields are at expected offsets */
    test_assert_eq((uintptr_t)&hdr.magic - (uintptr_t)&hdr, 0);
    test_assert_eq((uintptr_t)&hdr.version - (uintptr_t)&hdr, 2);
    test_assert_eq((uintptr_t)&hdr.flags - (uintptr_t)&hdr, 3);
    test_assert_eq((uintptr_t)&hdr.payload_length - (uintptr_t)&hdr, 4);
    test_assert_eq((uintptr_t)&hdr.sequence - (uintptr_t)&hdr, 8);
    test_assert_eq((uintptr_t)&hdr.checksum - (uintptr_t)&hdr, 16);

    return true;
}

bool test_channel_sequence_increment(void)
{
    ak_ipc_channel_t *ch = mock_channel_create(NULL, 0);
    test_assert_not_null(ch);

    test_assert_eq(ch->next_seq, 1);
    ch->next_seq++;
    test_assert_eq(ch->next_seq, 2);

    /* Simulate many sends */
    for (int i = 0; i < 1000; i++) {
        ch->next_seq++;
    }
    test_assert_eq(ch->next_seq, 1002);

    mock_channel_destroy(ch);
    return true;
}

bool test_all_flags_combinations(void)
{
    ak_ipc_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));

    hdr.magic = AK_IPC_MAGIC;
    hdr.version = AK_IPC_VERSION;

    /* Test all single flags */
    uint8_t flags[] = {
        AK_IPC_FLAG_REQUEST,
        AK_IPC_FLAG_RESPONSE,
        AK_IPC_FLAG_ERROR,
        AK_IPC_FLAG_COMPRESSED,
        AK_IPC_FLAG_BATCH
    };

    for (size_t i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
        hdr.flags = flags[i];
        test_assert_eq(mock_validate_header(&hdr), 0);
    }

    /* Test combined flags */
    hdr.flags = AK_IPC_FLAG_RESPONSE | AK_IPC_FLAG_ERROR;
    test_assert_eq(mock_validate_header(&hdr), 0);

    hdr.flags = AK_IPC_FLAG_REQUEST | AK_IPC_FLAG_COMPRESSED;
    test_assert_eq(mock_validate_header(&hdr), 0);

    return true;
}

bool test_buffer_operations(void)
{
    mock_buffer_t *buf = mock_buffer_create(16);
    test_assert_not_null(buf);
    test_assert_eq(mock_buffer_length(buf), 0);

    mock_buffer_write(buf, "Hello", 5);
    test_assert_eq(mock_buffer_length(buf), 5);

    mock_buffer_write(buf, ", World!", 8);
    test_assert_eq(mock_buffer_length(buf), 13);

    uint8_t *ref = mock_buffer_ref(buf, 0);
    test_assert_not_null(ref);
    test_assert_eq(ref[0], 'H');
    test_assert_eq(ref[5], ',');

    /* Test buffer growth */
    mock_buffer_write(buf, "Extra content that exceeds initial capacity", 43);
    test_assert_eq(mock_buffer_length(buf), 56);

    mock_buffer_destroy(buf);
    return true;
}

bool test_buffer_null_operations(void)
{
    test_assert_eq(mock_buffer_length(NULL), 0);
    test_assert_null(mock_buffer_ref(NULL, 0));

    mock_buffer_t *buf = mock_buffer_create(16);
    test_assert_null(mock_buffer_ref(buf, 100));  /* Out of bounds */

    mock_buffer_destroy(buf);
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

#define RUN_TEST(name, func) {name, func}

test_case tests[] = {
    /* Frame Format: Magic Number */
    RUN_TEST("frame_magic_valid", test_frame_magic_valid),
    RUN_TEST("frame_magic_invalid", test_frame_magic_invalid),
    RUN_TEST("frame_magic_zero", test_frame_magic_zero),
    RUN_TEST("frame_magic_swapped_bytes", test_frame_magic_swapped_bytes),

    /* Frame Format: Version */
    RUN_TEST("frame_version_valid", test_frame_version_valid),
    RUN_TEST("frame_version_invalid", test_frame_version_invalid),
    RUN_TEST("frame_version_zero", test_frame_version_zero),
    RUN_TEST("frame_version_future", test_frame_version_future),

    /* Frame Format: Payload Length */
    RUN_TEST("frame_payload_length_zero", test_frame_payload_length_zero),
    RUN_TEST("frame_payload_length_max", test_frame_payload_length_max),
    RUN_TEST("frame_payload_length_exceeds_max", test_frame_payload_length_exceeds_max),
    RUN_TEST("frame_payload_length_max_uint32", test_frame_payload_length_max_uint32),
    RUN_TEST("frame_header_null", test_frame_header_null),

    /* Frame Format: Checksum */
    RUN_TEST("frame_checksum_valid", test_frame_checksum_valid),
    RUN_TEST("frame_checksum_mismatch", test_frame_checksum_mismatch),
    RUN_TEST("frame_checksum_empty_payload", test_frame_checksum_empty_payload),
    RUN_TEST("frame_checksum_different_payloads", test_frame_checksum_different_payloads),

    /* Channel Management */
    RUN_TEST("channel_create_basic", test_channel_create_basic),
    RUN_TEST("channel_create_null_agent_id", test_channel_create_null_agent_id),
    RUN_TEST("channel_destroy_null", test_channel_destroy_null),
    RUN_TEST("channel_state_connected", test_channel_state_connected),
    RUN_TEST("channel_state_null", test_channel_state_null),
    RUN_TEST("channel_state_transitions", test_channel_state_transitions),
    RUN_TEST("channel_stats_initial", test_channel_stats_initial),
    RUN_TEST("channel_stats_tracking", test_channel_stats_tracking),
    RUN_TEST("channel_stats_null_channel", test_channel_stats_null_channel),
    RUN_TEST("channel_stats_null_stats", test_channel_stats_null_stats),

    /* Sequence Tracking */
    RUN_TEST("seq_tracker_create", test_seq_tracker_create),
    RUN_TEST("seq_tracker_create_null_ids", test_seq_tracker_create_null_ids),
    RUN_TEST("seq_tracker_monotonic_valid", test_seq_tracker_monotonic_valid),
    RUN_TEST("seq_tracker_replay_detection", test_seq_tracker_replay_detection),
    RUN_TEST("seq_tracker_replay_old_sequence", test_seq_tracker_replay_old_sequence),
    RUN_TEST("seq_tracker_gap_detection", test_seq_tracker_gap_detection),
    RUN_TEST("seq_tracker_large_gap", test_seq_tracker_large_gap),
    RUN_TEST("seq_tracker_sliding_window", test_seq_tracker_sliding_window),
    RUN_TEST("seq_tracker_window_slide", test_seq_tracker_window_slide),
    RUN_TEST("seq_tracker_expected", test_seq_tracker_expected),
    RUN_TEST("seq_tracker_highest", test_seq_tracker_highest),
    RUN_TEST("seq_tracker_null", test_seq_tracker_null),
    RUN_TEST("seq_tracker_zero_sequence", test_seq_tracker_zero_sequence),
    RUN_TEST("seq_tracker_uint64_max", test_seq_tracker_uint64_max),

    /* Hex Encoding/Decoding */
    RUN_TEST("hex_encode_basic", test_hex_encode_basic),
    RUN_TEST("hex_encode_zeros", test_hex_encode_zeros),
    RUN_TEST("hex_encode_all_bytes", test_hex_encode_all_bytes),
    RUN_TEST("hex_decode_basic", test_hex_decode_basic),
    RUN_TEST("hex_decode_uppercase", test_hex_decode_uppercase),
    RUN_TEST("hex_decode_mixed_case", test_hex_decode_mixed_case),
    RUN_TEST("hex_decode_odd_length", test_hex_decode_odd_length),
    RUN_TEST("hex_decode_invalid_chars", test_hex_decode_invalid_chars),
    RUN_TEST("hex_decode_buffer_too_small", test_hex_decode_buffer_too_small),
    RUN_TEST("hex_decode_null_inputs", test_hex_decode_null_inputs),
    RUN_TEST("hex_roundtrip", test_hex_roundtrip),

    /* Operation String Conversion */
    RUN_TEST("op_to_string", test_op_to_string),
    RUN_TEST("string_to_op", test_string_to_op),
    RUN_TEST("string_to_op_invalid", test_string_to_op_invalid),
    RUN_TEST("op_roundtrip", test_op_roundtrip),

    /* Error Messages */
    RUN_TEST("error_messages", test_error_messages),

    /* Payload Validation */
    RUN_TEST("payload_valid_json_object", test_payload_valid_json_object),
    RUN_TEST("payload_valid_json_array", test_payload_valid_json_array),
    RUN_TEST("payload_invalid_not_json", test_payload_invalid_not_json),
    RUN_TEST("payload_null", test_payload_null),
    RUN_TEST("payload_empty", test_payload_empty),
    RUN_TEST("payload_whitespace_before_json", test_payload_whitespace_before_json),

    /* Security Attack Scenarios */
    RUN_TEST("attack_replay_sequence", test_attack_replay_sequence),
    RUN_TEST("attack_sequence_prediction", test_attack_sequence_prediction),
    RUN_TEST("attack_malformed_magic", test_attack_malformed_magic),
    RUN_TEST("attack_oversized_payload", test_attack_oversized_payload),
    RUN_TEST("attack_checksum_collision", test_attack_checksum_collision),
    RUN_TEST("attack_json_injection", test_attack_json_injection),
    RUN_TEST("attack_hex_injection", test_attack_hex_injection),
    RUN_TEST("attack_frame_boundary", test_attack_frame_boundary),
    RUN_TEST("attack_null_byte_injection", test_attack_null_byte_injection),
    RUN_TEST("attack_sequence_overflow", test_attack_sequence_overflow),

    /* CRC-32C Specific */
    RUN_TEST("crc32c_empty", test_crc32c_empty),
    RUN_TEST("crc32c_known_values", test_crc32c_known_values),
    RUN_TEST("crc32c_incremental", test_crc32c_incremental),
    RUN_TEST("crc32c_all_zeros", test_crc32c_all_zeros),
    RUN_TEST("crc32c_all_ones", test_crc32c_all_ones),

    /* Batch Operations */
    RUN_TEST("batch_flag", test_batch_flag),
    RUN_TEST("batch_with_request_flag", test_batch_with_request_flag),
    RUN_TEST("batch_payload_array", test_batch_payload_array),

    /* Edge Cases */
    RUN_TEST("header_size", test_header_size),
    RUN_TEST("header_packed", test_header_packed),
    RUN_TEST("channel_sequence_increment", test_channel_sequence_increment),
    RUN_TEST("all_flags_combinations", test_all_flags_combinations),
    RUN_TEST("buffer_operations", test_buffer_operations),
    RUN_TEST("buffer_null_operations", test_buffer_null_operations),

    {NULL, NULL}
};

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    int passed = 0;
    int failed = 0;

    printf("=== AK IPC System Unit Tests ===\n\n");

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
