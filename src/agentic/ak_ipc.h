/*
 * Authority Kernel - IPC Transport
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Implements secure IPC framing for agent communication.
 * Handles request/response serialization with validation.
 *
 * SECURITY: Frame validation prevents injection attacks.
 * All frames include integrity checks.
 */

#ifndef AK_IPC_H
#define AK_IPC_H

#include "ak_types.h"

/* ============================================================
 * FRAME FORMAT
 * ============================================================
 *
 * Wire format (little-endian):
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     Magic (0x414B)            |    Version    |     Flags     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                        Payload Length                         |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                       Sequence Number                         |
 *  |                                                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                                                               |
 *  |                     Checksum (CRC-32C)                        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                                                               |
 *  |                        Payload (JSON)                         |
 *  |                                                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

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

/* Frame header */
typedef struct ak_ipc_header {
    u16 magic;
    u8 version;
    u8 flags;
    u32 payload_length;
    u64 sequence;
    u32 checksum;
} __attribute__((packed)) ak_ipc_header_t;

/* ============================================================
 * CHANNEL MANAGEMENT
 * ============================================================ */

typedef struct ak_ipc_channel ak_ipc_channel_t;

/* Channel state */
typedef enum ak_channel_state {
    AK_CHANNEL_DISCONNECTED,
    AK_CHANNEL_CONNECTING,
    AK_CHANNEL_CONNECTED,
    AK_CHANNEL_ERROR
} ak_channel_state_t;

/* Channel statistics */
typedef struct ak_ipc_stats {
    u64 frames_sent;
    u64 frames_received;
    u64 bytes_sent;
    u64 bytes_received;
    u64 errors;
    u64 checksum_failures;
} ak_ipc_stats_t;

/* Initialize IPC subsystem */
void ak_ipc_init(heap h);

/* Create channel (connects to agent) */
ak_ipc_channel_t *ak_ipc_channel_create(
    heap h,
    u8 *agent_id,
    int fd                          /* Unix domain socket / pipe fd */
);

/* Destroy channel */
void ak_ipc_channel_destroy(heap h, ak_ipc_channel_t *ch);

/* Get channel state */
ak_channel_state_t ak_ipc_channel_state(ak_ipc_channel_t *ch);

/* Get channel statistics */
void ak_ipc_channel_stats(ak_ipc_channel_t *ch, ak_ipc_stats_t *stats);

/* ============================================================
 * FRAME OPERATIONS
 * ============================================================ */

/*
 * Send request frame.
 *
 * Serializes request to JSON and frames it.
 * Returns: 0 on success, negative error on failure.
 */
s64 ak_ipc_send_request(
    ak_ipc_channel_t *ch,
    ak_request_t *req
);

/*
 * Send response frame.
 *
 * Serializes response to JSON and frames it.
 * Returns: 0 on success, negative error on failure.
 */
s64 ak_ipc_send_response(
    ak_ipc_channel_t *ch,
    ak_response_t *res
);

/*
 * Receive frame (blocking).
 *
 * Returns:
 *   > 0  - Received request/response
 *   0    - Channel closed
 *   < 0  - Error
 *
 * Output: either req_out OR res_out is populated based on frame type.
 */
s64 ak_ipc_recv(
    ak_ipc_channel_t *ch,
    ak_request_t **req_out,
    ak_response_t **res_out
);

/*
 * Receive with timeout.
 *
 * Returns AK_E_TIMEOUT if no frame within timeout_ms.
 */
s64 ak_ipc_recv_timeout(
    ak_ipc_channel_t *ch,
    ak_request_t **req_out,
    ak_response_t **res_out,
    u32 timeout_ms
);

/* ============================================================
 * FRAME VALIDATION
 * ============================================================
 * SECURITY: All received frames must pass validation.
 */

/*
 * Validate frame header.
 *
 * Checks:
 *   - Magic matches
 *   - Version supported
 *   - Payload length within bounds
 *   - Checksum valid
 */
s64 ak_ipc_validate_header(ak_ipc_header_t *hdr);

/*
 * Validate frame payload.
 *
 * Checks:
 *   - Valid JSON
 *   - Required fields present
 *   - Field types correct
 */
s64 ak_ipc_validate_payload(u8 flags, buffer payload);

/*
 * Compute frame checksum.
 *
 * CRC-32C (Castagnoli) over header (excluding checksum field) + payload.
 */
u32 ak_ipc_compute_checksum(ak_ipc_header_t *hdr, buffer payload);

/* ============================================================
 * REQUEST SERIALIZATION
 * ============================================================ */

/*
 * Serialize request to JSON.
 *
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
buffer ak_ipc_serialize_request(heap h, ak_request_t *req);

/*
 * Parse request from JSON.
 *
 * Returns NULL on parse error.
 */
ak_request_t *ak_ipc_parse_request(heap h, buffer json);

/* ============================================================
 * RESPONSE SERIALIZATION
 * ============================================================ */

/*
 * Serialize response to JSON.
 *
 * Format (success):
 * {
 *   "pid": "hex",
 *   "run_id": "hex",
 *   "seq": N,
 *   "ok": true,
 *   "result": {...}
 * }
 *
 * Format (error):
 * {
 *   "pid": "hex",
 *   "run_id": "hex",
 *   "seq": N,
 *   "ok": false,
 *   "error": {
 *     "code": N,
 *     "message": "..."
 *   }
 * }
 */
buffer ak_ipc_serialize_response(heap h, ak_response_t *res);

/*
 * Parse response from JSON.
 *
 * Returns NULL on parse error.
 */
ak_response_t *ak_ipc_parse_response(heap h, buffer json);

/* ============================================================
 * SEQUENCE NUMBER MANAGEMENT
 * ============================================================
 * SECURITY: Prevents replay attacks (REQ-006).
 */

typedef struct ak_seq_tracker ak_seq_tracker_t;

/*
 * Create sequence tracker for (pid, run_id) pair.
 */
ak_seq_tracker_t *ak_seq_tracker_create(heap h, u8 *pid, u8 *run_id);

/*
 * Destroy sequence tracker.
 */
void ak_seq_tracker_destroy(heap h, ak_seq_tracker_t *tracker);

/*
 * Check and advance sequence number.
 *
 * Returns:
 *   0               - Valid, tracker updated
 *   AK_E_REPLAY     - Sequence already seen
 *   AK_E_SEQ_GAP    - Unexpected gap (logged but allowed)
 *
 * SECURITY: Monotonic check prevents replay.
 * Gaps are logged but allowed to handle network reordering.
 */
s64 ak_seq_tracker_check(ak_seq_tracker_t *tracker, u64 seq);

/*
 * Get next expected sequence number.
 */
u64 ak_seq_tracker_expected(ak_seq_tracker_t *tracker);

/*
 * Get highest seen sequence number.
 */
u64 ak_seq_tracker_highest(ak_seq_tracker_t *tracker);

/* ============================================================
 * BATCH OPERATIONS
 * ============================================================ */

/*
 * Parse batch request.
 *
 * A batch request has flag AK_IPC_FLAG_BATCH and contains:
 * {
 *   "batch": [
 *     {op: ..., args: ...},
 *     {op: ..., args: ...},
 *     ...
 *   ]
 * }
 *
 * Returns array of individual requests.
 */
ak_request_t **ak_ipc_parse_batch(
    heap h,
    buffer json,
    u64 *count_out
);

/*
 * Serialize batch response.
 *
 * {
 *   "batch_results": [
 *     {ok: true, result: ...},
 *     {ok: false, error: ...},
 *     ...
 *   ]
 * }
 */
buffer ak_ipc_serialize_batch_response(
    heap h,
    ak_response_t **responses,
    u64 count
);

/* ============================================================
 * ERROR RESPONSES
 * ============================================================ */

/* Create error response */
ak_response_t *ak_ipc_error_response(
    heap h,
    u8 *pid,
    u8 *run_id,
    u64 seq,
    s64 error_code,
    const char *message
);

/* Standard error messages */
const char *ak_ipc_error_message(s64 error_code);

/* ============================================================
 * HELPERS
 * ============================================================ */

/* Convert operation code to string */
const char *ak_op_to_string(u16 op);

/* Parse operation string to code */
u16 ak_string_to_op(const char *str);

/* Hex encode/decode for IDs */
void ak_hex_encode(u8 *data, u64 len, char *out);
boolean ak_hex_decode(const char *hex, u8 *out, u64 max_len);

#endif /* AK_IPC_H */
