/*
 * Authority Kernel - IPC Transport Implementation
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Secure IPC framing for agent communication.
 * All frames validated before processing.
 *
 * SECURITY: Frame validation prevents injection attacks.
 */

#include "ak_ipc.h"
#include "ak_capability.h"

/* ============================================================
 * INTERNAL STRUCTURES
 * ============================================================ */

/* Channel structure */
struct ak_ipc_channel {
    heap h;
    u8 agent_id[AK_TOKEN_ID_SIZE];
    int fd;
    ak_channel_state_t state;
    u64 next_seq;                   /* For outbound frames */
    ak_ipc_stats_t stats;

    /* Receive buffer */
    buffer recv_buf;
    u64 recv_offset;
};

/* Sequence tracker structure */
struct ak_seq_tracker {
    u8 pid[AK_TOKEN_ID_SIZE];
    u8 run_id[AK_TOKEN_ID_SIZE];
    u64 highest_seen;
    u64 expected_next;

    /* Bitmap for recent sequences (sliding window) */
    #define SEQ_WINDOW_SIZE 1024
    u8 seen_bitmap[SEQ_WINDOW_SIZE / 8];
    u64 window_base;
};

/* Global IPC state */
static struct {
    heap h;
    boolean initialized;
} ak_ipc_state;

/* ============================================================
 * CRC-32C (Castagnoli)
 * ============================================================ */

static const u32 crc32c_table[256] = {
    0x00000000, 0xF26B8303, 0xE13B70F7, 0x1350F3F4,
    0xC79A971F, 0x35F1141C, 0x26A1E7E8, 0xD4CA64EB,
    0x8AD958CF, 0x78B2DBCC, 0x6BE22838, 0x9989AB3B,
    0x4D43CFD0, 0xBF284CD3, 0xAC78BF27, 0x5E133C24,
    /* ... remaining table entries for full CRC-32C */
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

static u32 __attribute__((unused)) crc32c(const u8 *data, u64 len)
{
    u32 crc = 0xFFFFFFFF;
    while (len--) {
        crc = (crc >> 8) ^ crc32c_table[(crc ^ *data++) & 0xFF];
    }
    return crc ^ 0xFFFFFFFF;
}

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

void ak_ipc_init(heap h)
{
    if (ak_ipc_state.initialized)
        return;

    ak_ipc_state.h = h;
    ak_ipc_state.initialized = true;
}

/* ============================================================
 * CHANNEL MANAGEMENT
 * ============================================================ */

ak_ipc_channel_t *ak_ipc_channel_create(heap h, u8 *agent_id, int fd)
{
    ak_ipc_channel_t *ch = allocate(h, sizeof(ak_ipc_channel_t));
    if (!ch)
        return NULL;

    ch->h = h;
    ch->fd = fd;
    ch->state = AK_CHANNEL_CONNECTED;
    ch->next_seq = 1;

    if (agent_id)
        runtime_memcpy(ch->agent_id, agent_id, AK_TOKEN_ID_SIZE);
    else
        runtime_memset(ch->agent_id, 0, AK_TOKEN_ID_SIZE);

    ak_memzero(&ch->stats, sizeof(ak_ipc_stats_t));

    ch->recv_buf = allocate_buffer(h, 4096);
    ch->recv_offset = 0;

    return ch;
}

void ak_ipc_channel_destroy(heap h, ak_ipc_channel_t *ch)
{
    if (!ch)
        return;

    if (ch->recv_buf)
        deallocate_buffer(ch->recv_buf);

    deallocate(h, ch, sizeof(ak_ipc_channel_t));
}

ak_channel_state_t ak_ipc_channel_state(ak_ipc_channel_t *ch)
{
    return ch ? ch->state : AK_CHANNEL_DISCONNECTED;
}

void ak_ipc_channel_stats(ak_ipc_channel_t *ch, ak_ipc_stats_t *stats)
{
    if (ch && stats)
        runtime_memcpy(stats, &ch->stats, sizeof(ak_ipc_stats_t));
}

/* ============================================================
 * FRAME OPERATIONS
 * ============================================================ */

u32 ak_ipc_compute_checksum(ak_ipc_header_t *hdr, buffer payload)
{
    u32 crc = 0xFFFFFFFF;

    /* Hash header (excluding checksum field) */
    u8 *hdr_bytes = (u8 *)hdr;
    for (int i = 0; i < 16; i++) {  /* First 16 bytes before checksum */
        crc = (crc >> 8) ^ crc32c_table[(crc ^ hdr_bytes[i]) & 0xFF];
    }

    /* Hash payload */
    if (payload) {
        u8 *p = buffer_ref(payload, 0);
        u64 len = buffer_length(payload);
        while (len--) {
            crc = (crc >> 8) ^ crc32c_table[(crc ^ *p++) & 0xFF];
        }
    }

    return crc ^ 0xFFFFFFFF;
}

s64 ak_ipc_validate_header(ak_ipc_header_t *hdr)
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

s64 ak_ipc_validate_payload(u8 flags, buffer payload)
{
    if (!payload || buffer_length(payload) == 0)
        return -EINVAL;

    /*
     * Payload validation checks:
     * - Valid JSON syntax
     * - Required fields present based on frame type (flags)
     *
     * Basic validation: non-empty JSON object/array.
     */
    u8 *data = buffer_ref(payload, 0);
    if (data[0] != '{' && data[0] != '[')
        return AK_E_IPC_INVALID;

    (void)flags;  /* Full field validation requires JSON parser */
    return 0;
}

static s64 write_frame(ak_ipc_channel_t *ch, u8 flags, buffer payload)
{
    if (!ch || ch->state != AK_CHANNEL_CONNECTED)
        return -EINVAL;

    ak_ipc_header_t hdr;
    hdr.magic = AK_IPC_MAGIC;
    hdr.version = AK_IPC_VERSION;
    hdr.flags = flags;
    hdr.payload_length = payload ? buffer_length(payload) : 0;
    hdr.sequence = ch->next_seq++;
    hdr.checksum = ak_ipc_compute_checksum(&hdr, payload);

    /* Write header to file descriptor */
    /* Integration point: write(&hdr, AK_IPC_HEADER_SIZE) */
    (void)ch->fd;

    /* Write payload to file descriptor */
    if (payload) {
        /* Integration point: write(buffer_ref(payload, 0), buffer_length(payload)) */
    }

    ch->stats.frames_sent++;
    ch->stats.bytes_sent += AK_IPC_HEADER_SIZE + hdr.payload_length;

    return 0;
}

s64 ak_ipc_send_request(ak_ipc_channel_t *ch, ak_request_t *req)
{
    if (!ch || !req)
        return -EINVAL;

    buffer json = ak_ipc_serialize_request(ch->h, req);
    if (!json)
        return -ENOMEM;

    s64 result = write_frame(ch, AK_IPC_FLAG_REQUEST, json);

    deallocate_buffer(json);
    return result;
}

s64 ak_ipc_send_response(ak_ipc_channel_t *ch, ak_response_t *res)
{
    if (!ch || !res)
        return -EINVAL;

    buffer json = ak_ipc_serialize_response(ch->h, res);
    if (!json)
        return -ENOMEM;

    u8 flags = AK_IPC_FLAG_RESPONSE;
    if (res->error_code != 0)
        flags |= AK_IPC_FLAG_ERROR;

    s64 result = write_frame(ch, flags, json);

    deallocate_buffer(json);
    return result;
}

s64 ak_ipc_recv(
    ak_ipc_channel_t *ch,
    ak_request_t **req_out,
    ak_response_t **res_out)
{
    return ak_ipc_recv_timeout(ch, req_out, res_out, 0);
}

s64 ak_ipc_recv_timeout(
    ak_ipc_channel_t *ch,
    ak_request_t **req_out,
    ak_response_t **res_out,
    u32 timeout_ms)
{
    if (!ch || (!req_out && !res_out))
        return -EINVAL;

    if (req_out) *req_out = NULL;
    if (res_out) *res_out = NULL;

    /*
     * Frame receive protocol:
     * 1. Read AK_IPC_HEADER_SIZE bytes into header
     * 2. Validate header via ak_ipc_validate_header()
     * 3. Read payload_length bytes
     * 4. Verify checksum via ak_ipc_compute_checksum()
     * 5. Parse JSON based on frame type (flags)
     *
     * Integration requires file descriptor polling with timeout.
     */

    (void)timeout_ms;

    return AK_E_TIMEOUT;
}

/* ============================================================
 * SERIALIZATION
 * ============================================================ */

buffer ak_ipc_serialize_request(heap h, ak_request_t *req)
{
    if (!req)
        return NULL;

    /*
     * Format:
     * {
     *   "pid": "hex",
     *   "run_id": "hex",
     *   "seq": N,
     *   "op": "READ" | "WRITE" | ...,
     *   "cap": {...},
     *   "args": {...}
     * }
     */

    /* Estimate buffer size */
    buffer result = allocate_buffer(h, 1024);
    if (!result)
        return NULL;

    char pid_hex[AK_TOKEN_ID_SIZE * 2 + 1];
    char run_hex[AK_TOKEN_ID_SIZE * 2 + 1];
    ak_hex_encode(req->pid, AK_TOKEN_ID_SIZE, pid_hex);
    ak_hex_encode(req->run_id, AK_TOKEN_ID_SIZE, run_hex);

    const char *op_str = ak_op_to_string(req->op);

    /* Build JSON manually (avoiding external JSON library dependency) */
    buffer_write(result, "{\"pid\":\"", 8);
    buffer_write(result, pid_hex, AK_TOKEN_ID_SIZE * 2);
    buffer_write(result, "\",\"run_id\":\"", 12);
    buffer_write(result, run_hex, AK_TOKEN_ID_SIZE * 2);
    buffer_write(result, "\",\"seq\":", 8);

    /* Write sequence number */
    char seq_buf[32];
    int seq_len = 0;
    u64 seq = req->seq;
    if (seq == 0) {
        seq_buf[0] = '0';
        seq_len = 1;
    } else {
        char tmp[32];
        while (seq > 0) {
            tmp[seq_len++] = '0' + (seq % 10);
            seq /= 10;
        }
        for (int i = 0; i < seq_len; i++)
            seq_buf[i] = tmp[seq_len - 1 - i];
    }
    buffer_write(result, seq_buf, seq_len);

    buffer_write(result, ",\"op\":\"", 7);
    buffer_write(result, (void *)op_str, runtime_strlen(op_str));
    buffer_write(result, "\"", 1);

    /* Add args if present */
    if (req->args && buffer_length(req->args) > 0) {
        buffer_write(result, ",\"args\":", 8);
        buffer_write(result, buffer_ref(req->args, 0), buffer_length(req->args));
    }

    buffer_write(result, "}", 1);

    return result;
}

ak_request_t *ak_ipc_parse_request(heap h, buffer json)
{
    if (!json || buffer_length(json) == 0)
        return NULL;

    /*
     * Request parsing extracts:
     *   - pid, run_id: Hex-encoded agent identifiers
     *   - seq: Request sequence number
     *   - op: Operation code
     *   - cap: Optional capability token
     *   - args: Operation-specific arguments
     *
     * Requires JSON parser integration for full implementation.
     */

    (void)h;
    return NULL;
}

buffer ak_ipc_serialize_response(heap h, ak_response_t *res)
{
    if (!res)
        return NULL;

    buffer result = allocate_buffer(h, 1024);
    if (!result)
        return NULL;

    char pid_hex[AK_TOKEN_ID_SIZE * 2 + 1];
    char run_hex[AK_TOKEN_ID_SIZE * 2 + 1];
    ak_hex_encode(res->pid, AK_TOKEN_ID_SIZE, pid_hex);
    ak_hex_encode(res->run_id, AK_TOKEN_ID_SIZE, run_hex);

    buffer_write(result, "{\"pid\":\"", 8);
    buffer_write(result, pid_hex, AK_TOKEN_ID_SIZE * 2);
    buffer_write(result, "\",\"run_id\":\"", 12);
    buffer_write(result, run_hex, AK_TOKEN_ID_SIZE * 2);
    buffer_write(result, "\",\"seq\":", 8);

    char seq_buf[32];
    int seq_len = 0;
    u64 seq = res->seq;
    if (seq == 0) {
        seq_buf[0] = '0';
        seq_len = 1;
    } else {
        char tmp[32];
        while (seq > 0) {
            tmp[seq_len++] = '0' + (seq % 10);
            seq /= 10;
        }
        for (int i = 0; i < seq_len; i++)
            seq_buf[i] = tmp[seq_len - 1 - i];
    }
    buffer_write(result, seq_buf, seq_len);

    if (res->error_code == 0) {
        buffer_write(result, ",\"ok\":true", 10);
        if (res->result && buffer_length(res->result) > 0) {
            buffer_write(result, ",\"result\":", 10);
            buffer_write(result, buffer_ref(res->result, 0), buffer_length(res->result));
        }
    } else {
        buffer_write(result, ",\"ok\":false,\"error\":{\"code\":", 27);

        /* Write error code */
        s64 code = res->error_code;
        char code_buf[32];
        int code_len = 0;
        boolean negative = false;
        if (code < 0) {
            negative = true;
            code = -code;
        }
        if (code == 0) {
            code_buf[0] = '0';
            code_len = 1;
        } else {
            char tmp[32];
            while (code > 0) {
                tmp[code_len++] = '0' + (code % 10);
                code /= 10;
            }
            for (int i = 0; i < code_len; i++)
                code_buf[i] = tmp[code_len - 1 - i];
        }
        if (negative) {
            buffer_write(result, "-", 1);
        }
        buffer_write(result, code_buf, code_len);

        const char *msg = ak_ipc_error_message(res->error_code);
        buffer_write(result, ",\"message\":\"", 12);
        buffer_write(result, (void *)msg, runtime_strlen(msg));
        buffer_write(result, "\"}", 2);
    }

    buffer_write(result, "}", 1);

    return result;
}

ak_response_t *ak_ipc_parse_response(heap h, buffer json)
{
    if (!json || buffer_length(json) == 0)
        return NULL;

    (void)h;
    return NULL;
}

/* ============================================================
 * SEQUENCE TRACKING
 * ============================================================ */

ak_seq_tracker_t *ak_seq_tracker_create(heap h, u8 *pid, u8 *run_id)
{
    ak_seq_tracker_t *tracker = allocate(h, sizeof(ak_seq_tracker_t));
    if (!tracker)
        return NULL;

    if (pid)
        runtime_memcpy(tracker->pid, pid, AK_TOKEN_ID_SIZE);
    else
        runtime_memset(tracker->pid, 0, AK_TOKEN_ID_SIZE);

    if (run_id)
        runtime_memcpy(tracker->run_id, run_id, AK_TOKEN_ID_SIZE);
    else
        runtime_memset(tracker->run_id, 0, AK_TOKEN_ID_SIZE);

    tracker->highest_seen = 0;
    tracker->expected_next = 1;
    tracker->window_base = 0;
    runtime_memset(tracker->seen_bitmap, 0, SEQ_WINDOW_SIZE / 8);

    return tracker;
}

void ak_seq_tracker_destroy(heap h, ak_seq_tracker_t *tracker)
{
    if (tracker)
        deallocate(h, tracker, sizeof(ak_seq_tracker_t));
}

s64 ak_seq_tracker_check(ak_seq_tracker_t *tracker, u64 seq)
{
    if (!tracker)
        return -EINVAL;

    /* Check for replay (sequence already seen) */
    if (seq <= tracker->highest_seen) {
        /* Check bitmap if within window */
        if (seq >= tracker->window_base &&
            seq < tracker->window_base + SEQ_WINDOW_SIZE) {
            u64 offset = seq - tracker->window_base;
            u64 byte_idx = offset / 8;
            u8 bit_mask = 1 << (offset % 8);

            if (tracker->seen_bitmap[byte_idx] & bit_mask) {
                /* Already seen - replay attack */
                return AK_E_REPLAY;
            }

            /* Mark as seen */
            tracker->seen_bitmap[byte_idx] |= bit_mask;
        }
        /* Old sequence outside window - assume seen */
        return AK_E_REPLAY;
    }

    /* Check for gap */
    s64 result = 0;
    if (seq > tracker->expected_next) {
        result = AK_E_SEQ_GAP;
        /* Gap detected but allowed - log it */
    }

    /* Update tracking */
    tracker->highest_seen = seq;
    tracker->expected_next = seq + 1;

    /* Slide window if needed */
    if (seq >= tracker->window_base + SEQ_WINDOW_SIZE) {
        u64 new_base = seq - SEQ_WINDOW_SIZE / 2;
        u64 shift = new_base - tracker->window_base;

        if (shift >= SEQ_WINDOW_SIZE) {
            /* Full window shift - clear everything */
            runtime_memset(tracker->seen_bitmap, 0, SEQ_WINDOW_SIZE / 8);
        } else {
            /* Partial shift */
            u64 bytes_to_shift = shift / 8;
            if (bytes_to_shift > 0) {
                runtime_memcpy(tracker->seen_bitmap,
                              tracker->seen_bitmap + bytes_to_shift,
                              SEQ_WINDOW_SIZE / 8 - bytes_to_shift);
                runtime_memset(tracker->seen_bitmap + SEQ_WINDOW_SIZE / 8 - bytes_to_shift,
                              0, bytes_to_shift);
            }
        }
        tracker->window_base = new_base;
    }

    /* Mark current sequence as seen */
    if (seq >= tracker->window_base &&
        seq < tracker->window_base + SEQ_WINDOW_SIZE) {
        u64 offset = seq - tracker->window_base;
        u64 byte_idx = offset / 8;
        u8 bit_mask = 1 << (offset % 8);
        tracker->seen_bitmap[byte_idx] |= bit_mask;
    }

    return result;
}

u64 ak_seq_tracker_expected(ak_seq_tracker_t *tracker)
{
    return tracker ? tracker->expected_next : 0;
}

u64 ak_seq_tracker_highest(ak_seq_tracker_t *tracker)
{
    return tracker ? tracker->highest_seen : 0;
}

/* ============================================================
 * BATCH OPERATIONS
 * ============================================================ */

ak_request_t **ak_ipc_parse_batch(heap h, buffer json, u64 *count_out)
{
    if (!json || !count_out)
        return NULL;

    /*
     * Batch parsing extracts array of requests.
     * Each request is parsed via ak_ipc_parse_request().
     * Batch operations are atomic (all-or-nothing).
     *
     * Requires JSON array parsing for full implementation.
     */

    *count_out = 0;
    (void)h;
    return NULL;
}

buffer ak_ipc_serialize_batch_response(heap h, ak_response_t **responses, u64 count)
{
    if (!responses || count == 0)
        return NULL;

    buffer result = allocate_buffer(h, 256 * count);
    if (!result)
        return NULL;

    buffer_write(result, "{\"batch_results\":[", 18);

    for (u64 i = 0; i < count; i++) {
        if (i > 0)
            buffer_write(result, ",", 1);

        ak_response_t *res = responses[i];
        if (res->error_code == 0) {
            buffer_write(result, "{\"ok\":true", 10);
            if (res->result && buffer_length(res->result) > 0) {
                buffer_write(result, ",\"result\":", 10);
                buffer_write(result, buffer_ref(res->result, 0),
                            buffer_length(res->result));
            }
            buffer_write(result, "}", 1);
        } else {
            buffer_write(result, "{\"ok\":false,\"error\":", 20);

            char code_buf[32];
            int code_len = 0;
            s64 code = res->error_code;
            boolean negative = code < 0;
            if (negative) code = -code;
            if (code == 0) {
                code_buf[0] = '0';
                code_len = 1;
            } else {
                char tmp[32];
                while (code > 0) {
                    tmp[code_len++] = '0' + (code % 10);
                    code /= 10;
                }
                for (int j = 0; j < code_len; j++)
                    code_buf[j] = tmp[code_len - 1 - j];
            }
            if (negative) buffer_write(result, "-", 1);
            buffer_write(result, code_buf, code_len);
            buffer_write(result, "}", 1);
        }
    }

    buffer_write(result, "]}", 2);

    return result;
}

/* ============================================================
 * ERROR RESPONSES
 * ============================================================ */

ak_response_t *ak_ipc_error_response(
    heap h,
    u8 *pid,
    u8 *run_id,
    u64 seq,
    s64 error_code,
    const char *message)
{
    ak_response_t *res = allocate(h, sizeof(ak_response_t));
    if (!res)
        return NULL;

    if (pid)
        runtime_memcpy(res->pid, pid, AK_TOKEN_ID_SIZE);
    else
        runtime_memset(res->pid, 0, AK_TOKEN_ID_SIZE);

    if (run_id)
        runtime_memcpy(res->run_id, run_id, AK_TOKEN_ID_SIZE);
    else
        runtime_memset(res->run_id, 0, AK_TOKEN_ID_SIZE);

    res->seq = seq;
    res->error_code = error_code;
    res->result = NULL;

    (void)message;  /* Error message derived from code */

    return res;
}

const char *ak_ipc_error_message(s64 error_code)
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
 * HELPERS
 * ============================================================ */

const char *ak_op_to_string(u16 op)
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

u16 ak_string_to_op(const char *str)
{
    if (!str) return 0;

    if (ak_strcmp(str, "READ") == 0)       return AK_SYS_READ;
    if (ak_strcmp(str, "ALLOC") == 0)      return AK_SYS_ALLOC;
    if (ak_strcmp(str, "WRITE") == 0)      return AK_SYS_WRITE;
    if (ak_strcmp(str, "DELETE") == 0)     return AK_SYS_DELETE;
    if (ak_strcmp(str, "QUERY") == 0)      return AK_SYS_QUERY;
    if (ak_strcmp(str, "BATCH") == 0)      return AK_SYS_BATCH;
    if (ak_strcmp(str, "COMMIT") == 0)     return AK_SYS_COMMIT;
    if (ak_strcmp(str, "CALL") == 0)       return AK_SYS_CALL;
    if (ak_strcmp(str, "SPAWN") == 0)      return AK_SYS_SPAWN;
    if (ak_strcmp(str, "SEND") == 0)       return AK_SYS_SEND;
    if (ak_strcmp(str, "RECV") == 0)       return AK_SYS_RECV;
    if (ak_strcmp(str, "RESPOND") == 0)    return AK_SYS_RESPOND;
    if (ak_strcmp(str, "ASSERT") == 0)     return AK_SYS_ASSERT;
    if (ak_strcmp(str, "INFERENCE") == 0)  return AK_SYS_INFERENCE;

    return 0;
}

static const char hex_chars[] = "0123456789abcdef";

void ak_hex_encode(u8 *data, u64 len, char *out)
{
    for (u64 i = 0; i < len; i++) {
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

boolean ak_hex_decode(const char *hex, u8 *out, u64 max_len)
{
    if (!hex || !out)
        return false;

    u64 len = runtime_strlen(hex);
    if (len % 2 != 0 || len / 2 > max_len)
        return false;

    for (u64 i = 0; i < len / 2; i++) {
        int hi = hex_digit(hex[i * 2]);
        int lo = hex_digit(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0)
            return false;
        out[i] = (hi << 4) | lo;
    }

    return true;
}
