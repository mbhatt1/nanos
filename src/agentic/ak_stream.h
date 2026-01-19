/*
 * Authority Kernel - Streaming Support
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Provides streaming support for:
 *   1. Server-Sent Events (SSE) - HTTP streaming
 *   2. WebSocket connections - Bidirectional streaming
 *   3. LLM token streams - Token-by-token inference responses
 *
 * All streaming operations are:
 *   - Budget-tracked (INV-3) - bytes and tokens counted
 *   - Capability-gated through parent operation
 *   - Audit-logged (INV-4) - session start/end logged
 *
 * SECURITY: Stream budgets enforce resource limits per session.
 */

#ifndef AK_STREAM_H
#define AK_STREAM_H

#include "ak_types.h"
#include "ak_capability.h"

/* ============================================================
 * STREAMING SESSION TYPES
 * ============================================================ */

/* Stream type classification */
typedef enum ak_stream_type {
    AK_STREAM_NONE = 0,         /* Invalid/uninitialized */
    AK_STREAM_SSE = 1,          /* Server-Sent Events */
    AK_STREAM_WEBSOCKET = 2,    /* WebSocket */
    AK_STREAM_LLM_TOKENS = 3,   /* LLM token stream */
    AK_STREAM_TOOL_RESPONSE = 4, /* Streaming tool response */
} ak_stream_type_t;

/* Stream state */
typedef enum ak_stream_state {
    AK_STREAM_STATE_INIT = 0,       /* Created but not started */
    AK_STREAM_STATE_ACTIVE = 1,     /* Actively streaming */
    AK_STREAM_STATE_PAUSED = 2,     /* Temporarily paused */
    AK_STREAM_STATE_CLOSED = 3,     /* Gracefully closed */
    AK_STREAM_STATE_ERROR = 4,      /* Closed due to error */
    AK_STREAM_STATE_BUDGET = 5,     /* Closed - budget exceeded */
    AK_STREAM_STATE_TIMEOUT = 6,    /* Closed - timeout */
} ak_stream_state_t;

/* Stream direction */
typedef enum ak_stream_direction {
    AK_STREAM_DIR_OUTBOUND = 1,     /* Server to client */
    AK_STREAM_DIR_INBOUND = 2,      /* Client to server */
    AK_STREAM_DIR_BIDIRECTIONAL = 3, /* Both directions (WebSocket) */
} ak_stream_direction_t;

/* ============================================================
 * STREAMING BUDGET CONFIGURATION
 * ============================================================
 */

typedef struct ak_stream_budget {
    /* Byte limits */
    u64 bytes_limit;            /* Max bytes to send (0 = unlimited) */
    u64 bytes_per_second;       /* Rate limit: bytes/second */

    /* Token limits (for LLM streams) */
    u64 tokens_limit;           /* Max tokens to send */
    u64 tokens_per_second;      /* Rate limit: tokens/second */

    /* Chunk limits */
    u64 chunks_limit;           /* Max chunks/messages */
    u64 max_chunk_size;         /* Max size per chunk */

    /* Time limits */
    u64 timeout_ms;             /* Total session timeout */
    u64 idle_timeout_ms;        /* Timeout between chunks */
} ak_stream_budget_t;

/* Default budget values */
#define AK_STREAM_DEFAULT_BYTES_LIMIT       (100 * 1024 * 1024)  /* 100 MB */
#define AK_STREAM_DEFAULT_TOKENS_LIMIT      (100000)              /* 100K tokens */
#define AK_STREAM_DEFAULT_CHUNKS_LIMIT      (10000)               /* 10K chunks */
#define AK_STREAM_DEFAULT_MAX_CHUNK_SIZE    (64 * 1024)           /* 64 KB */
#define AK_STREAM_DEFAULT_TIMEOUT_MS        (300000)              /* 5 minutes */
#define AK_STREAM_DEFAULT_IDLE_TIMEOUT_MS   (60000)               /* 1 minute */

/* ============================================================
 * FORWARD DECLARATIONS FOR CALLBACK TYPES
 * ============================================================
 */

/* Forward declarations needed for callback type definitions */
struct ak_stream_session;
struct ak_stream_chunk;

/* Callback invoked for each chunk sent */
typedef void (*ak_stream_on_chunk_t)(
    struct ak_stream_session *session,
    struct ak_stream_chunk *chunk,
    void *ctx
);

/* Callback invoked when stream closes */
typedef void (*ak_stream_on_close_t)(
    struct ak_stream_session *session,
    ak_stream_state_t reason,
    void *ctx
);

/* Callback for token streaming (LLM) */
typedef void (*ak_stream_on_token_t)(
    struct ak_stream_session *session,
    const char *token,
    u32 token_len,
    boolean is_final,
    void *ctx
);

/* ============================================================
 * STREAMING SESSION STRUCTURE
 * ============================================================
 */

/* Stop sequence entry for LLM streams */
typedef struct ak_stop_sequence {
    char *sequence;
    u32 sequence_len;
    u32 match_pos;              /* Current match position */
} ak_stop_sequence_t;

/* Streaming session */
typedef struct ak_stream_session {
    /* Identity */
    u64 session_id;
    u8 session_uuid[AK_TOKEN_ID_SIZE];

    /* Type and direction */
    ak_stream_type_t type;
    ak_stream_direction_t direction;

    /* State */
    ak_stream_state_t state;
    boolean active;

    /* Timing */
    u64 start_ns;               /* Session start timestamp (nanoseconds) */
    u64 last_chunk_ns;          /* Last chunk sent/received timestamp */
    u64 end_ns;                 /* Session end timestamp (if closed) */

    /* Budget tracking - bytes */
    u64 bytes_sent;
    u64 bytes_received;
    u64 bytes_limit;

    /* Budget tracking - tokens (LLM) */
    u64 tokens_sent;
    u64 tokens_received;
    u64 tokens_limit;

    /* Budget tracking - chunks */
    u64 chunks_sent;
    u64 chunks_received;
    u64 chunks_limit;
    u64 max_chunk_size;

    /* Rate limiting state */
    u64 rate_window_start_ns;
    u64 rate_bytes_in_window;
    u64 rate_tokens_in_window;
    u64 bytes_per_second;
    u64 tokens_per_second;

    /* Timeout tracking */
    u64 timeout_ms;
    u64 idle_timeout_ms;

    /* LLM-specific: stop sequences */
    ak_stop_sequence_t *stop_sequences;
    u32 stop_sequence_count;
    boolean stop_triggered;
    u32 triggered_stop_index;

    /* LLM-specific: partial token buffer */
    buffer partial_token_buffer;
    u32 partial_token_threshold;    /* Min bytes before flushing */

    /* Agent context linkage */
    ak_agent_context_t *agent;
    ak_capability_t *cap;

    /* Error information */
    s64 error_code;
    char error_msg[256];

    /* Audit linkage */
    u64 audit_start_seq;
    u64 audit_end_seq;

    /* Memory management */
    heap session_heap;

    /* Callback storage */
    ak_stream_on_chunk_t on_chunk_callback;
    void *on_chunk_ctx;
    ak_stream_on_close_t on_close_callback;
    void *on_close_ctx;
    ak_stream_on_token_t on_token_callback;
    void *on_token_ctx;

    /* Cancellation support */
    boolean cancelled;
    char cancel_reason[128];

    /* Backpressure support */
    u64 backpressure_high_water;    /* High-water mark (default 64KB) */
    u64 bytes_pending;              /* Bytes waiting for consumer */
    boolean backpressure_active;    /* True if consumer is slow */

    /* Linked list for session tracking */
    struct ak_stream_session *next;
    struct ak_stream_session *prev;
} ak_stream_session_t;

/* ============================================================
 * STREAM CHUNK STRUCTURE
 * ============================================================
 */

typedef enum ak_chunk_type {
    AK_CHUNK_DATA = 0,          /* Regular data chunk */
    AK_CHUNK_EVENT = 1,         /* SSE event with type */
    AK_CHUNK_TOKEN = 2,         /* LLM token */
    AK_CHUNK_CONTROL = 3,       /* Control message (ping/pong) */
    AK_CHUNK_ERROR = 4,         /* Error message */
    AK_CHUNK_CLOSE = 5,         /* Close frame */
} ak_chunk_type_t;

typedef struct ak_stream_chunk {
    ak_chunk_type_t type;
    buffer data;
    u64 data_len;

    /* SSE-specific */
    char event_type[64];        /* Event type for SSE */
    char event_id[64];          /* Event ID for SSE */

    /* Token-specific */
    u32 token_id;               /* Token ID for LLM */
    boolean is_final;           /* Last token in stream */

    /* Metadata */
    u64 sequence;               /* Chunk sequence number */
    u64 timestamp_ns;
} ak_stream_chunk_t;

/* ============================================================
 * SESSION STATISTICS
 * ============================================================
 */

typedef struct ak_stream_stats {
    /* Byte statistics */
    u64 bytes_sent;
    u64 bytes_received;
    u64 bytes_limit;
    u64 bytes_remaining;

    /* Token statistics (LLM) */
    u64 tokens_sent;
    u64 tokens_received;
    u64 tokens_limit;
    u64 tokens_remaining;

    /* Chunk statistics */
    u64 chunks_sent;
    u64 chunks_received;

    /* Timing */
    u64 duration_ns;
    u64 avg_chunk_interval_ns;
    u64 time_remaining_ms;

    /* Rate */
    u64 current_bytes_per_sec;
    u64 current_tokens_per_sec;

    /* State */
    ak_stream_state_t state;
    boolean budget_exceeded;
    boolean timeout_exceeded;
} ak_stream_stats_t;

/* ============================================================
 * INITIALIZATION
 * ============================================================
 */

/*
 * Initialize streaming subsystem.
 */
void ak_stream_init(heap h);

/*
 * Shutdown streaming subsystem.
 */
void ak_stream_shutdown(void);

/* ============================================================
 * SESSION LIFECYCLE
 * ============================================================
 */

/*
 * Create new streaming session.
 *
 * PRECONDITIONS:
 *   - type must be valid ak_stream_type_t
 *   - budget may be NULL (uses defaults)
 *   - agent may be NULL (standalone session)
 *
 * POSTCONDITIONS:
 *   - Returns session in AK_STREAM_STATE_INIT
 *   - Session ID assigned
 *   - Budget limits applied
 *
 * Returns: Valid session on success, NULL on failure.
 */
ak_stream_session_t *ak_stream_create(
    heap h,
    ak_stream_type_t type,
    ak_stream_budget_t *budget,
    ak_agent_context_t *agent,
    ak_capability_t *cap
);

/*
 * Start streaming session.
 *
 * Transitions from INIT to ACTIVE state.
 * Records start timestamp for timeout tracking.
 *
 * Returns: 0 on success, error code on failure.
 */
s64 ak_stream_start(ak_stream_session_t *session);

/*
 * Pause streaming session.
 *
 * Transitions from ACTIVE to PAUSED state.
 * Idle timeout is suspended while paused.
 */
s64 ak_stream_pause(ak_stream_session_t *session);

/*
 * Resume streaming session.
 *
 * Transitions from PAUSED to ACTIVE state.
 */
s64 ak_stream_resume(ak_stream_session_t *session);

/*
 * Close streaming session gracefully.
 *
 * POSTCONDITIONS:
 *   - State transitions to CLOSED
 *   - Final statistics recorded
 *   - Audit log entry created
 *
 * Returns: 0 on success, error code on failure.
 */
s64 ak_stream_close(ak_stream_session_t *session);

/*
 * Abort streaming session due to error.
 *
 * @param error_code  Error code to record
 * @param error_msg   Human-readable error message
 */
s64 ak_stream_abort(
    ak_stream_session_t *session,
    s64 error_code,
    const char *error_msg
);

/*
 * Destroy session and free resources.
 *
 * PRECONDITIONS:
 *   - Session must be in CLOSED or ERROR state
 */
void ak_stream_destroy(heap h, ak_stream_session_t *session);

/* ============================================================
 * DATA TRANSMISSION
 * ============================================================
 */

/*
 * Send data chunk through stream.
 *
 * PRECONDITIONS:
 *   - Session must be ACTIVE
 *   - data must not be NULL if len > 0
 *
 * POSTCONDITIONS:
 *   - bytes_sent incremented by len
 *   - chunks_sent incremented by 1
 *   - Budget checked and enforced
 *
 * Returns:
 *   >= 0          - Bytes sent
 *   AK_E_BUDGET_EXCEEDED - Would exceed byte limit
 *   AK_E_RATE_LIMIT      - Rate limit exceeded
 *   AK_E_TIMEOUT         - Session timeout
 *   Other negative       - Error code
 */
s64 ak_stream_send_chunk(
    ak_stream_session_t *session,
    const u8 *data,
    u64 len
);

/*
 * Send typed chunk (with metadata).
 */
s64 ak_stream_send_typed_chunk(
    ak_stream_session_t *session,
    ak_stream_chunk_t *chunk
);

/*
 * Send SSE event.
 *
 * Formats data as SSE event:
 *   event: <event_type>
 *   id: <event_id>
 *   data: <data>
 */
s64 ak_stream_send_sse_event(
    ak_stream_session_t *session,
    const char *event_type,
    const char *event_id,
    const u8 *data,
    u64 data_len
);

/*
 * Send WebSocket frame.
 *
 * @param opcode  WebSocket opcode (text=1, binary=2, etc.)
 * @param fin     Final frame flag
 */
s64 ak_stream_send_ws_frame(
    ak_stream_session_t *session,
    u8 opcode,
    boolean fin,
    const u8 *data,
    u64 data_len
);

/* ============================================================
 * LLM TOKEN STREAMING
 * ============================================================
 */

/*
 * Send single LLM token.
 *
 * PRECONDITIONS:
 *   - Session type must be AK_STREAM_LLM_TOKENS
 *   - Session must be ACTIVE
 *
 * POSTCONDITIONS:
 *   - tokens_sent incremented by 1
 *   - Token budget checked
 *   - Stop sequences checked
 *
 * Returns:
 *   0             - Token sent
 *   1             - Stop sequence triggered (stream should end)
 *   AK_E_BUDGET_EXCEEDED - Token limit exceeded
 *   Other negative - Error
 */
s64 ak_stream_send_token(
    ak_stream_session_t *session,
    const char *token,
    u32 token_len
);

/*
 * Send multiple tokens.
 *
 * Convenience function for batched token delivery.
 *
 * @param tokens      Array of token strings
 * @param token_lens  Array of token lengths
 * @param count       Number of tokens
 *
 * Returns: Number of tokens sent, or negative error code.
 */
s64 ak_stream_send_tokens(
    ak_stream_session_t *session,
    const char **tokens,
    const u32 *token_lens,
    u32 count
);

/*
 * Flush partial token buffer.
 *
 * For LLM streams, tokens may be buffered until a minimum
 * threshold is reached. This forces immediate delivery.
 */
s64 ak_stream_flush_tokens(ak_stream_session_t *session);

/*
 * Set stop sequences for LLM stream.
 *
 * When a stop sequence is detected in the token stream,
 * streaming stops automatically.
 *
 * @param sequences  Array of null-terminated stop sequences
 * @param count      Number of stop sequences
 */
s64 ak_stream_set_stop_sequences(
    ak_stream_session_t *session,
    const char **sequences,
    u32 count
);

/*
 * Check if stop sequence was triggered.
 *
 * @param triggered_index  Output: which stop sequence triggered (if any)
 *
 * Returns: true if a stop sequence was matched.
 */
boolean ak_stream_stop_triggered(
    ak_stream_session_t *session,
    u32 *triggered_index
);

/*
 * Set partial token buffering threshold.
 *
 * Tokens are accumulated until buffer reaches threshold,
 * then flushed together. Set to 0 for immediate delivery.
 */
void ak_stream_set_token_buffer_threshold(
    ak_stream_session_t *session,
    u32 threshold_bytes
);

/* ============================================================
 * BUDGET MANAGEMENT
 * ============================================================
 */

/*
 * Check if budget allows sending more data.
 *
 * @param additional_bytes  Bytes to be sent
 * @param additional_tokens Tokens to be sent (LLM)
 *
 * Returns: true if budget allows, false otherwise.
 */
boolean ak_stream_budget_check(
    ak_stream_session_t *session,
    u64 additional_bytes,
    u64 additional_tokens
);

/*
 * Get remaining budget.
 *
 * @param bytes_remaining   Output: bytes remaining (may be NULL)
 * @param tokens_remaining  Output: tokens remaining (may be NULL)
 */
void ak_stream_budget_remaining(
    ak_stream_session_t *session,
    u64 *bytes_remaining,
    u64 *tokens_remaining
);

/*
 * Update budget limits mid-stream.
 *
 * Can only increase limits, not decrease below current usage.
 */
s64 ak_stream_budget_update(
    ak_stream_session_t *session,
    ak_stream_budget_t *new_budget
);

/*
 * Check rate limit.
 *
 * Returns: true if within rate limit, false if would exceed.
 */
boolean ak_stream_rate_check(
    ak_stream_session_t *session,
    u64 bytes,
    u64 tokens
);

/* ============================================================
 * STATISTICS AND MONITORING
 * ============================================================
 */

/*
 * Get session statistics.
 */
void ak_stream_get_stats(
    ak_stream_session_t *session,
    ak_stream_stats_t *stats
);

/*
 * Get session by ID.
 */
ak_stream_session_t *ak_stream_get_by_id(u64 session_id);

/*
 * Get session by UUID.
 */
ak_stream_session_t *ak_stream_get_by_uuid(u8 *uuid);

/*
 * List all active sessions.
 *
 * @param sessions  Output array
 * @param max_count Maximum sessions to return
 *
 * Returns: Number of active sessions.
 */
u32 ak_stream_list_active(
    ak_stream_session_t **sessions,
    u32 max_count
);

/* ============================================================
 * CALLBACK REGISTRATION
 * ============================================================
 */

/*
 * Register chunk callback.
 */
void ak_stream_on_chunk(
    ak_stream_session_t *session,
    ak_stream_on_chunk_t callback,
    void *ctx
);

/*
 * Register close callback.
 */
void ak_stream_on_close(
    ak_stream_session_t *session,
    ak_stream_on_close_t callback,
    void *ctx
);

/*
 * Register token callback (LLM streams).
 */
void ak_stream_on_token(
    ak_stream_session_t *session,
    ak_stream_on_token_t callback,
    void *ctx
);

/* ============================================================
 * TIMEOUT MANAGEMENT
 * ============================================================
 */

/*
 * Check and enforce timeout.
 *
 * Called periodically to check session timeouts.
 *
 * Returns: true if session timed out and was closed.
 */
boolean ak_stream_check_timeout(ak_stream_session_t *session);

/*
 * Reset idle timeout.
 *
 * Called after each chunk to reset idle timer.
 */
void ak_stream_reset_idle_timeout(ak_stream_session_t *session);

/*
 * Check all sessions for timeout (maintenance task).
 *
 * Returns: Number of sessions timed out.
 */
u32 ak_stream_check_all_timeouts(void);

/* ============================================================
 * CANCELLATION SUPPORT
 * ============================================================
 */

/*
 * Cancel streaming session mid-generation.
 *
 * Gracefully aborts the stream and invokes close callback with
 * AK_STREAM_STATE_CLOSED. Use ak_stream_abort() for error cases.
 *
 * @param session  Session to cancel
 * @param reason   Human-readable cancellation reason
 *
 * Returns: 0 on success, error code on failure.
 */
s64 ak_stream_cancel(
    ak_stream_session_t *session,
    const char *reason
);

/*
 * Check if session is cancelled.
 *
 * Returns: true if session was cancelled.
 */
boolean ak_stream_is_cancelled(ak_stream_session_t *session);

/* ============================================================
 * BACKPRESSURE SUPPORT
 * ============================================================
 */

/*
 * Check if consumer can accept more data.
 *
 * Returns true if consumer is ready, false if backpressure is active.
 * When backpressure is active, the producer should pause sending.
 *
 * @param session         Session to check
 * @param bytes_pending   Number of bytes waiting to be consumed
 *
 * Returns: true if ready for more data, false if should pause.
 */
boolean ak_stream_can_send(
    ak_stream_session_t *session,
    u64 bytes_pending
);

/*
 * Signal consumer is ready for more data.
 *
 * Called by the consumer to indicate it has processed pending data
 * and is ready to receive more. This resets backpressure state.
 *
 * @param session  Session to signal
 */
void ak_stream_consumer_ready(ak_stream_session_t *session);

/*
 * Set high-water mark for backpressure.
 *
 * When pending bytes exceed this threshold, backpressure is activated.
 * Default is 64KB.
 *
 * @param session     Session to configure
 * @param high_water  High-water mark in bytes (0 to disable)
 */
void ak_stream_set_backpressure_limit(
    ak_stream_session_t *session,
    u64 high_water
);

/* ============================================================
 * GLOBAL STATISTICS
 * ============================================================
 */

typedef struct ak_stream_global_stats {
    u64 sessions_created;
    u64 sessions_active;
    u64 sessions_closed_ok;
    u64 sessions_closed_error;
    u64 sessions_closed_budget;
    u64 sessions_closed_timeout;
    u64 total_bytes_sent;
    u64 total_bytes_received;
    u64 total_tokens_sent;
    u64 total_tokens_received;
    u64 total_chunks_sent;
    u64 budget_exceeded_count;
    u64 rate_limit_count;
} ak_stream_global_stats_t;

void ak_stream_get_global_stats(ak_stream_global_stats_t *stats);

/* ============================================================
 * ERROR CODES
 * ============================================================
 */

#define AK_E_STREAM_INVALID         (-4700)  /* Invalid session */
#define AK_E_STREAM_NOT_ACTIVE      (-4701)  /* Session not active */
#define AK_E_STREAM_ALREADY_ACTIVE  (-4702)  /* Session already active */
#define AK_E_STREAM_CLOSED          (-4703)  /* Session closed */
#define AK_E_STREAM_CHUNK_TOO_LARGE (-4704)  /* Chunk exceeds max size */
#define AK_E_STREAM_TYPE_MISMATCH   (-4705)  /* Wrong operation for type */
#define AK_E_STREAM_STOP_TRIGGERED  (-4706)  /* Stop sequence triggered */
#define AK_E_STREAM_CANCELLED       (-4707)  /* Stream was cancelled */
#define AK_E_STREAM_BACKPRESSURE    (-4708)  /* Consumer slow, backpressure active */

#endif /* AK_STREAM_H */
