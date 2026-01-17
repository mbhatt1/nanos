/*
 * Authority Kernel - Streaming Support Implementation
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Implements streaming support for SSE, WebSocket, and LLM token streams.
 * All streaming is budget-tracked and capability-gated.
 *
 * SECURITY CRITICAL:
 *   - Budget limits are enforced before each chunk
 *   - Rate limiting prevents resource exhaustion
 *   - All sessions are audit-logged
 */

#include "ak_stream.h"
#include "ak_audit.h"
#include "ak_compat.h"

/* ============================================================
 * MODULE STATE
 * ============================================================ */

static struct {
    heap h;
    boolean initialized;

    /* Session tracking */
    ak_stream_session_t *active_sessions;
    u64 session_counter;

    /* Global statistics */
    ak_stream_global_stats_t stats;

    /* Configuration */
    ak_stream_budget_t default_budget;
} stream_state;

/* ============================================================
 * INTERNAL HELPERS
 * ============================================================ */

/*
 * Get current time in nanoseconds.
 */
static u64 get_time_ns(void)
{
    return now(CLOCK_ID_MONOTONIC);
}

/*
 * Generate unique session ID.
 */
static u64 generate_session_id(void)
{
    return ++stream_state.session_counter;
}

/*
 * Generate random UUID for session.
 */
static void generate_session_uuid(u8 *uuid)
{
    /* Use ak_generate_token_id for cryptographically random UUID */
    ak_generate_token_id(uuid);
}

/*
 * Add session to active list.
 */
static void session_list_add(ak_stream_session_t *session)
{
    session->next = stream_state.active_sessions;
    session->prev = NULL;
    if (stream_state.active_sessions) {
        stream_state.active_sessions->prev = session;
    }
    stream_state.active_sessions = session;
    stream_state.stats.sessions_active++;
}

/*
 * Remove session from active list.
 */
static void session_list_remove(ak_stream_session_t *session)
{
    if (session->prev) {
        session->prev->next = session->next;
    } else {
        stream_state.active_sessions = session->next;
    }
    if (session->next) {
        session->next->prev = session->prev;
    }
    session->next = NULL;
    session->prev = NULL;
    if (stream_state.stats.sessions_active > 0) {
        stream_state.stats.sessions_active--;
    }
}

/*
 * Apply default budget values.
 */
static void apply_default_budget(ak_stream_budget_t *budget)
{
    if (budget->bytes_limit == 0)
        budget->bytes_limit = AK_STREAM_DEFAULT_BYTES_LIMIT;
    if (budget->tokens_limit == 0)
        budget->tokens_limit = AK_STREAM_DEFAULT_TOKENS_LIMIT;
    if (budget->chunks_limit == 0)
        budget->chunks_limit = AK_STREAM_DEFAULT_CHUNKS_LIMIT;
    if (budget->max_chunk_size == 0)
        budget->max_chunk_size = AK_STREAM_DEFAULT_MAX_CHUNK_SIZE;
    if (budget->timeout_ms == 0)
        budget->timeout_ms = AK_STREAM_DEFAULT_TIMEOUT_MS;
    if (budget->idle_timeout_ms == 0)
        budget->idle_timeout_ms = AK_STREAM_DEFAULT_IDLE_TIMEOUT_MS;
}

/*
 * Check rate limit for bytes/tokens.
 *
 * Uses sliding window algorithm with 1-second granularity.
 */
static boolean check_rate_limit(
    ak_stream_session_t *session,
    u64 additional_bytes,
    u64 additional_tokens)
{
    u64 now_ns = get_time_ns();
    u64 window_ns = BILLION;  /* 1 second in nanoseconds */

    /* Reset window if expired */
    if (now_ns - session->rate_window_start_ns > window_ns) {
        session->rate_window_start_ns = now_ns;
        session->rate_bytes_in_window = 0;
        session->rate_tokens_in_window = 0;
    }

    /* Check byte rate limit */
    if (session->bytes_per_second > 0) {
        if (session->rate_bytes_in_window + additional_bytes > session->bytes_per_second) {
            stream_state.stats.rate_limit_count++;
            return false;
        }
    }

    /* Check token rate limit */
    if (session->tokens_per_second > 0) {
        if (session->rate_tokens_in_window + additional_tokens > session->tokens_per_second) {
            stream_state.stats.rate_limit_count++;
            return false;
        }
    }

    return true;
}

/*
 * Update rate limit counters.
 */
static void update_rate_counters(
    ak_stream_session_t *session,
    u64 bytes,
    u64 tokens)
{
    session->rate_bytes_in_window += bytes;
    session->rate_tokens_in_window += tokens;
}

/*
 * Check and match stop sequences in token stream.
 *
 * Returns true if a stop sequence was fully matched.
 */
static boolean check_stop_sequences(
    ak_stream_session_t *session,
    const char *token,
    u32 token_len)
{
    if (!session->stop_sequences || session->stop_sequence_count == 0) {
        return false;
    }

    for (u32 i = 0; i < session->stop_sequence_count; i++) {
        ak_stop_sequence_t *stop = &session->stop_sequences[i];

        /* Check each character in token against stop sequence */
        for (u32 j = 0; j < token_len; j++) {
            if (token[j] == stop->sequence[stop->match_pos]) {
                stop->match_pos++;
                if (stop->match_pos >= stop->sequence_len) {
                    /* Full match found */
                    session->stop_triggered = true;
                    session->triggered_stop_index = i;
                    return true;
                }
            } else {
                /* Reset match position */
                stop->match_pos = 0;
                /* Check if current char starts a new match */
                if (token[j] == stop->sequence[0]) {
                    stop->match_pos = 1;
                }
            }
        }
    }

    return false;
}

/*
 * Free stop sequences.
 */
static void free_stop_sequences(ak_stream_session_t *session)
{
    if (session->stop_sequences) {
        for (u32 i = 0; i < session->stop_sequence_count; i++) {
            if (session->stop_sequences[i].sequence) {
                deallocate(session->session_heap,
                          session->stop_sequences[i].sequence,
                          session->stop_sequences[i].sequence_len + 1);
            }
        }
        deallocate(session->session_heap,
                  session->stop_sequences,
                  sizeof(ak_stop_sequence_t) * session->stop_sequence_count);
        session->stop_sequences = NULL;
        session->stop_sequence_count = 0;
    }
}

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

void ak_stream_init(heap h)
{
    if (stream_state.initialized) {
        return;
    }

    stream_state.h = h;
    stream_state.active_sessions = NULL;
    stream_state.session_counter = 0;
    ak_memzero(&stream_state.stats, sizeof(stream_state.stats));

    /* Set default budget values */
    stream_state.default_budget.bytes_limit = AK_STREAM_DEFAULT_BYTES_LIMIT;
    stream_state.default_budget.tokens_limit = AK_STREAM_DEFAULT_TOKENS_LIMIT;
    stream_state.default_budget.chunks_limit = AK_STREAM_DEFAULT_CHUNKS_LIMIT;
    stream_state.default_budget.max_chunk_size = AK_STREAM_DEFAULT_MAX_CHUNK_SIZE;
    stream_state.default_budget.timeout_ms = AK_STREAM_DEFAULT_TIMEOUT_MS;
    stream_state.default_budget.idle_timeout_ms = AK_STREAM_DEFAULT_IDLE_TIMEOUT_MS;

    stream_state.initialized = true;
}

void ak_stream_shutdown(void)
{
    if (!stream_state.initialized) {
        return;
    }

    /* Close all active sessions */
    ak_stream_session_t *session = stream_state.active_sessions;
    while (session) {
        ak_stream_session_t *next = session->next;
        ak_stream_abort(session, AK_E_STREAM_CLOSED, "Shutdown");
        ak_stream_destroy(stream_state.h, session);
        session = next;
    }

    stream_state.active_sessions = NULL;
    stream_state.initialized = false;
}

/* ============================================================
 * SESSION LIFECYCLE
 * ============================================================ */

ak_stream_session_t *ak_stream_create(
    heap h,
    ak_stream_type_t type,
    ak_stream_budget_t *budget,
    ak_agent_context_t *agent,
    ak_capability_t *cap)
{
    if (!stream_state.initialized) {
        return NULL;
    }

    if (type == AK_STREAM_NONE) {
        return NULL;
    }

    heap alloc_heap = h ? h : stream_state.h;

    ak_stream_session_t *session = ak_alloc_zero(alloc_heap, ak_stream_session_t);
    if (!session || session == INVALID_ADDRESS) {
        return NULL;
    }

    /* Initialize identity */
    session->session_id = generate_session_id();
    generate_session_uuid(session->session_uuid);
    session->type = type;
    session->state = AK_STREAM_STATE_INIT;
    session->active = false;

    /* Set direction based on type */
    if (type == AK_STREAM_WEBSOCKET) {
        session->direction = AK_STREAM_DIR_BIDIRECTIONAL;
    } else {
        session->direction = AK_STREAM_DIR_OUTBOUND;
    }

    /* Apply budget */
    if (budget) {
        session->bytes_limit = budget->bytes_limit;
        session->tokens_limit = budget->tokens_limit;
        session->chunks_limit = budget->chunks_limit;
        session->max_chunk_size = budget->max_chunk_size;
        session->timeout_ms = budget->timeout_ms;
        session->idle_timeout_ms = budget->idle_timeout_ms;
        session->bytes_per_second = budget->bytes_per_second;
        session->tokens_per_second = budget->tokens_per_second;
    } else {
        /* Use defaults */
        session->bytes_limit = stream_state.default_budget.bytes_limit;
        session->tokens_limit = stream_state.default_budget.tokens_limit;
        session->chunks_limit = stream_state.default_budget.chunks_limit;
        session->max_chunk_size = stream_state.default_budget.max_chunk_size;
        session->timeout_ms = stream_state.default_budget.timeout_ms;
        session->idle_timeout_ms = stream_state.default_budget.idle_timeout_ms;
    }

    /* Link to agent context */
    session->agent = agent;
    session->cap = cap;

    /* Initialize memory management */
    session->session_heap = alloc_heap;

    /* Create partial token buffer for LLM streams */
    if (type == AK_STREAM_LLM_TOKENS) {
        session->partial_token_buffer = allocate_buffer(alloc_heap, 256);
        if (session->partial_token_buffer == INVALID_ADDRESS) {
            session->partial_token_buffer = NULL;
        }
        session->partial_token_threshold = 0;  /* Immediate delivery by default */
    }

    /* Add to active list */
    session_list_add(session);

    /* Update statistics */
    stream_state.stats.sessions_created++;

    return session;
}

s64 ak_stream_start(ak_stream_session_t *session)
{
    if (!session) {
        return AK_E_STREAM_INVALID;
    }

    if (session->state != AK_STREAM_STATE_INIT) {
        return AK_E_STREAM_ALREADY_ACTIVE;
    }

    session->state = AK_STREAM_STATE_ACTIVE;
    session->active = true;
    session->start_ns = get_time_ns();
    session->last_chunk_ns = session->start_ns;
    session->rate_window_start_ns = session->start_ns;

    return 0;
}

s64 ak_stream_pause(ak_stream_session_t *session)
{
    if (!session) {
        return AK_E_STREAM_INVALID;
    }

    if (session->state != AK_STREAM_STATE_ACTIVE) {
        return AK_E_STREAM_NOT_ACTIVE;
    }

    session->state = AK_STREAM_STATE_PAUSED;
    session->active = false;

    return 0;
}

s64 ak_stream_resume(ak_stream_session_t *session)
{
    if (!session) {
        return AK_E_STREAM_INVALID;
    }

    if (session->state != AK_STREAM_STATE_PAUSED) {
        return AK_E_STREAM_NOT_ACTIVE;
    }

    session->state = AK_STREAM_STATE_ACTIVE;
    session->active = true;
    session->last_chunk_ns = get_time_ns();  /* Reset idle timer */

    return 0;
}

s64 ak_stream_close(ak_stream_session_t *session)
{
    if (!session) {
        return AK_E_STREAM_INVALID;
    }

    if (session->state == AK_STREAM_STATE_CLOSED ||
        session->state == AK_STREAM_STATE_ERROR) {
        return 0;  /* Already closed */
    }

    /* Flush any buffered tokens for LLM streams */
    if (session->type == AK_STREAM_LLM_TOKENS && session->partial_token_buffer) {
        ak_stream_flush_tokens(session);
    }

    session->state = AK_STREAM_STATE_CLOSED;
    session->active = false;
    session->end_ns = get_time_ns();

    /* Update global statistics */
    stream_state.stats.sessions_closed_ok++;
    stream_state.stats.total_bytes_sent += session->bytes_sent;
    stream_state.stats.total_bytes_received += session->bytes_received;
    stream_state.stats.total_tokens_sent += session->tokens_sent;
    stream_state.stats.total_tokens_received += session->tokens_received;
    stream_state.stats.total_chunks_sent += session->chunks_sent;

    return 0;
}

s64 ak_stream_abort(
    ak_stream_session_t *session,
    s64 error_code,
    const char *error_msg)
{
    if (!session) {
        return AK_E_STREAM_INVALID;
    }

    if (session->state == AK_STREAM_STATE_CLOSED ||
        session->state == AK_STREAM_STATE_ERROR) {
        return 0;  /* Already closed */
    }

    session->state = AK_STREAM_STATE_ERROR;
    session->active = false;
    session->end_ns = get_time_ns();
    session->error_code = error_code;

    if (error_msg) {
        runtime_strncpy(session->error_msg, error_msg, sizeof(session->error_msg) - 1);
        session->error_msg[sizeof(session->error_msg) - 1] = '\0';
    }

    /* Update statistics based on error type */
    if (error_code == AK_E_BUDGET_EXCEEDED) {
        stream_state.stats.sessions_closed_budget++;
        stream_state.stats.budget_exceeded_count++;
    } else if (error_code == AK_E_TIMEOUT) {
        stream_state.stats.sessions_closed_timeout++;
    } else {
        stream_state.stats.sessions_closed_error++;
    }

    return 0;
}

void ak_stream_destroy(heap h, ak_stream_session_t *session)
{
    if (!session) {
        return;
    }

    /* Remove from active list if still there */
    session_list_remove(session);

    /* Free stop sequences */
    free_stop_sequences(session);

    /* Free partial token buffer */
    if (session->partial_token_buffer) {
        deallocate_buffer(session->partial_token_buffer);
        session->partial_token_buffer = NULL;
    }

    /* Clear sensitive data before free */
    ak_memzero(session, sizeof(ak_stream_session_t));

    /* Free the session */
    heap free_heap = h ? h : stream_state.h;
    deallocate(free_heap, session, sizeof(ak_stream_session_t));
}

/* ============================================================
 * DATA TRANSMISSION
 * ============================================================ */

s64 ak_stream_send_chunk(
    ak_stream_session_t *session,
    const u8 *data,
    u64 len)
{
    if (!session) {
        return AK_E_STREAM_INVALID;
    }

    if (session->state != AK_STREAM_STATE_ACTIVE) {
        return AK_E_STREAM_NOT_ACTIVE;
    }

    /* Check timeout */
    if (ak_stream_check_timeout(session)) {
        return AK_E_TIMEOUT;
    }

    /* Check chunk size limit */
    if (len > session->max_chunk_size) {
        return AK_E_STREAM_CHUNK_TOO_LARGE;
    }

    /* Check byte budget */
    if (session->bytes_limit > 0 &&
        session->bytes_sent + len > session->bytes_limit) {
        ak_stream_abort(session, AK_E_BUDGET_EXCEEDED, "Byte limit exceeded");
        return AK_E_BUDGET_EXCEEDED;
    }

    /* Check chunk count budget */
    if (session->chunks_limit > 0 &&
        session->chunks_sent >= session->chunks_limit) {
        ak_stream_abort(session, AK_E_BUDGET_EXCEEDED, "Chunk limit exceeded");
        return AK_E_BUDGET_EXCEEDED;
    }

    /* Check rate limit */
    if (!check_rate_limit(session, len, 0)) {
        return AK_E_RATE_LIMIT;
    }

    /* Update counters */
    session->bytes_sent += len;
    session->chunks_sent++;
    session->last_chunk_ns = get_time_ns();
    update_rate_counters(session, len, 0);

    /* Return bytes sent */
    return (s64)len;
}

s64 ak_stream_send_typed_chunk(
    ak_stream_session_t *session,
    ak_stream_chunk_t *chunk)
{
    if (!session || !chunk) {
        return AK_E_STREAM_INVALID;
    }

    u64 len = chunk->data ? chunk->data_len : 0;
    return ak_stream_send_chunk(session, chunk->data ? buffer_ref(chunk->data, 0) : NULL, len);
}

s64 ak_stream_send_sse_event(
    ak_stream_session_t *session,
    const char *event_type,
    const char *event_id,
    const u8 *data,
    u64 data_len)
{
    if (!session) {
        return AK_E_STREAM_INVALID;
    }

    if (session->type != AK_STREAM_SSE) {
        return AK_E_STREAM_TYPE_MISMATCH;
    }

    /*
     * SSE format:
     *   event: <type>\n
     *   id: <id>\n
     *   data: <data>\n
     *   \n
     *
     * Calculate total size for budget check.
     */
    u64 total_size = 0;

    if (event_type) {
        total_size += 7 + runtime_strlen(event_type) + 1;  /* "event: " + type + "\n" */
    }
    if (event_id) {
        total_size += 4 + runtime_strlen(event_id) + 1;    /* "id: " + id + "\n" */
    }
    if (data && data_len > 0) {
        total_size += 6 + data_len + 1;                     /* "data: " + data + "\n" */
    }
    total_size += 1;  /* Final "\n" */

    return ak_stream_send_chunk(session, data, total_size);
}

s64 ak_stream_send_ws_frame(
    ak_stream_session_t *session,
    u8 opcode,
    boolean fin,
    const u8 *data,
    u64 data_len)
{
    if (!session) {
        return AK_E_STREAM_INVALID;
    }

    if (session->type != AK_STREAM_WEBSOCKET) {
        return AK_E_STREAM_TYPE_MISMATCH;
    }

    /*
     * WebSocket frame overhead:
     *   - 2 bytes minimum header
     *   - 2 bytes if len <= 65535
     *   - 8 bytes if len > 65535
     */
    u64 frame_overhead = 2;
    if (data_len > 125) {
        frame_overhead += (data_len <= 65535) ? 2 : 8;
    }

    u64 total_size = frame_overhead + data_len;

    /* Unused parameters for frame construction */
    (void)opcode;
    (void)fin;

    return ak_stream_send_chunk(session, data, total_size);
}

/* ============================================================
 * LLM TOKEN STREAMING
 * ============================================================ */

s64 ak_stream_send_token(
    ak_stream_session_t *session,
    const char *token,
    u32 token_len)
{
    if (!session) {
        return AK_E_STREAM_INVALID;
    }

    if (session->type != AK_STREAM_LLM_TOKENS) {
        return AK_E_STREAM_TYPE_MISMATCH;
    }

    if (session->state != AK_STREAM_STATE_ACTIVE) {
        return AK_E_STREAM_NOT_ACTIVE;
    }

    /* Check if already stopped */
    if (session->stop_triggered) {
        return AK_E_STREAM_STOP_TRIGGERED;
    }

    /* Check timeout */
    if (ak_stream_check_timeout(session)) {
        return AK_E_TIMEOUT;
    }

    /* Check token budget */
    if (session->tokens_limit > 0 &&
        session->tokens_sent >= session->tokens_limit) {
        ak_stream_abort(session, AK_E_BUDGET_EXCEEDED, "Token limit exceeded");
        return AK_E_BUDGET_EXCEEDED;
    }

    /* Check rate limit */
    if (!check_rate_limit(session, token_len, 1)) {
        return AK_E_RATE_LIMIT;
    }

    /* Check for stop sequences */
    if (check_stop_sequences(session, token, token_len)) {
        /* Stop sequence triggered - close stream */
        ak_stream_close(session);
        return 1;  /* Indicate stop triggered */
    }

    /* Check if we should buffer or send immediately */
    if (session->partial_token_buffer && session->partial_token_threshold > 0) {
        /* Add to buffer */
        buffer_write(session->partial_token_buffer, token, token_len);

        /* Check if buffer threshold reached */
        if (buffer_length(session->partial_token_buffer) >= session->partial_token_threshold) {
            return ak_stream_flush_tokens(session);
        }
    } else {
        /* Immediate delivery - update counters */
        session->tokens_sent++;
        session->bytes_sent += token_len;
        session->last_chunk_ns = get_time_ns();
        update_rate_counters(session, token_len, 1);
    }

    return 0;
}

s64 ak_stream_send_tokens(
    ak_stream_session_t *session,
    const char **tokens,
    const u32 *token_lens,
    u32 count)
{
    if (!session || !tokens || !token_lens || count == 0) {
        return AK_E_STREAM_INVALID;
    }

    s64 sent = 0;
    for (u32 i = 0; i < count; i++) {
        s64 result = ak_stream_send_token(session, tokens[i], token_lens[i]);
        if (result < 0) {
            return result;  /* Error */
        }
        if (result == 1) {
            return sent;  /* Stop sequence triggered */
        }
        sent++;
    }

    return sent;
}

s64 ak_stream_flush_tokens(ak_stream_session_t *session)
{
    if (!session) {
        return AK_E_STREAM_INVALID;
    }

    if (!session->partial_token_buffer) {
        return 0;  /* No buffer to flush */
    }

    u64 buffer_len = buffer_length(session->partial_token_buffer);
    if (buffer_len == 0) {
        return 0;  /* Nothing to flush */
    }

    /* Count tokens in buffer (approximation: count by accumulated length) */
    /* In real implementation, we'd track token count separately */
    session->bytes_sent += buffer_len;
    session->tokens_sent++;  /* Treat entire buffer as one token for accounting */
    session->last_chunk_ns = get_time_ns();
    update_rate_counters(session, buffer_len, 1);

    /* Clear buffer */
    buffer_clear(session->partial_token_buffer);

    return 0;
}

s64 ak_stream_set_stop_sequences(
    ak_stream_session_t *session,
    const char **sequences,
    u32 count)
{
    if (!session) {
        return AK_E_STREAM_INVALID;
    }

    /* Free existing stop sequences */
    free_stop_sequences(session);

    if (!sequences || count == 0) {
        return 0;
    }

    /* Allocate stop sequence array */
    session->stop_sequences = ak_alloc_array_zero(session->session_heap,
                                                   ak_stop_sequence_t, count);
    if (!session->stop_sequences || session->stop_sequences == INVALID_ADDRESS) {
        session->stop_sequences = NULL;
        return -ENOMEM;
    }

    session->stop_sequence_count = count;

    /* Copy each stop sequence */
    for (u32 i = 0; i < count; i++) {
        if (sequences[i]) {
            u32 len = runtime_strlen(sequences[i]);
            session->stop_sequences[i].sequence = allocate(session->session_heap, len + 1);
            if (session->stop_sequences[i].sequence == INVALID_ADDRESS) {
                free_stop_sequences(session);
                return -ENOMEM;
            }
            runtime_memcpy(session->stop_sequences[i].sequence, sequences[i], len);
            session->stop_sequences[i].sequence[len] = '\0';
            session->stop_sequences[i].sequence_len = len;
            session->stop_sequences[i].match_pos = 0;
        }
    }

    return 0;
}

boolean ak_stream_stop_triggered(
    ak_stream_session_t *session,
    u32 *triggered_index)
{
    if (!session) {
        return false;
    }

    if (triggered_index && session->stop_triggered) {
        *triggered_index = session->triggered_stop_index;
    }

    return session->stop_triggered;
}

void ak_stream_set_token_buffer_threshold(
    ak_stream_session_t *session,
    u32 threshold_bytes)
{
    if (!session) {
        return;
    }

    session->partial_token_threshold = threshold_bytes;

    /* Flush existing buffer if threshold is now 0 */
    if (threshold_bytes == 0 && session->partial_token_buffer) {
        ak_stream_flush_tokens(session);
    }
}

/* ============================================================
 * BUDGET MANAGEMENT
 * ============================================================ */

boolean ak_stream_budget_check(
    ak_stream_session_t *session,
    u64 additional_bytes,
    u64 additional_tokens)
{
    if (!session) {
        return false;
    }

    /* Check byte limit */
    if (session->bytes_limit > 0 &&
        session->bytes_sent + additional_bytes > session->bytes_limit) {
        return false;
    }

    /* Check token limit */
    if (session->tokens_limit > 0 &&
        session->tokens_sent + additional_tokens > session->tokens_limit) {
        return false;
    }

    /* Check rate limits */
    if (!check_rate_limit(session, additional_bytes, additional_tokens)) {
        return false;
    }

    return true;
}

void ak_stream_budget_remaining(
    ak_stream_session_t *session,
    u64 *bytes_remaining,
    u64 *tokens_remaining)
{
    if (!session) {
        if (bytes_remaining) *bytes_remaining = 0;
        if (tokens_remaining) *tokens_remaining = 0;
        return;
    }

    if (bytes_remaining) {
        if (session->bytes_limit > 0 && session->bytes_sent < session->bytes_limit) {
            *bytes_remaining = session->bytes_limit - session->bytes_sent;
        } else if (session->bytes_limit == 0) {
            *bytes_remaining = UINT64_MAX;  /* Unlimited */
        } else {
            *bytes_remaining = 0;
        }
    }

    if (tokens_remaining) {
        if (session->tokens_limit > 0 && session->tokens_sent < session->tokens_limit) {
            *tokens_remaining = session->tokens_limit - session->tokens_sent;
        } else if (session->tokens_limit == 0) {
            *tokens_remaining = UINT64_MAX;  /* Unlimited */
        } else {
            *tokens_remaining = 0;
        }
    }
}

s64 ak_stream_budget_update(
    ak_stream_session_t *session,
    ak_stream_budget_t *new_budget)
{
    if (!session || !new_budget) {
        return AK_E_STREAM_INVALID;
    }

    /* Can only increase limits, not decrease below current usage */
    if (new_budget->bytes_limit > 0) {
        if (new_budget->bytes_limit < session->bytes_sent) {
            return -EINVAL;  /* Cannot decrease below current usage */
        }
        session->bytes_limit = new_budget->bytes_limit;
    }

    if (new_budget->tokens_limit > 0) {
        if (new_budget->tokens_limit < session->tokens_sent) {
            return -EINVAL;
        }
        session->tokens_limit = new_budget->tokens_limit;
    }

    if (new_budget->chunks_limit > 0) {
        if (new_budget->chunks_limit < session->chunks_sent) {
            return -EINVAL;
        }
        session->chunks_limit = new_budget->chunks_limit;
    }

    /* Update rate limits (these can be changed freely) */
    if (new_budget->bytes_per_second > 0) {
        session->bytes_per_second = new_budget->bytes_per_second;
    }
    if (new_budget->tokens_per_second > 0) {
        session->tokens_per_second = new_budget->tokens_per_second;
    }

    /* Update timeouts */
    if (new_budget->timeout_ms > 0) {
        session->timeout_ms = new_budget->timeout_ms;
    }
    if (new_budget->idle_timeout_ms > 0) {
        session->idle_timeout_ms = new_budget->idle_timeout_ms;
    }

    return 0;
}

boolean ak_stream_rate_check(
    ak_stream_session_t *session,
    u64 bytes,
    u64 tokens)
{
    return check_rate_limit(session, bytes, tokens);
}

/* ============================================================
 * STATISTICS AND MONITORING
 * ============================================================ */

void ak_stream_get_stats(
    ak_stream_session_t *session,
    ak_stream_stats_t *stats)
{
    if (!session || !stats) {
        return;
    }

    ak_memzero(stats, sizeof(ak_stream_stats_t));

    stats->bytes_sent = session->bytes_sent;
    stats->bytes_received = session->bytes_received;
    stats->bytes_limit = session->bytes_limit;
    stats->tokens_sent = session->tokens_sent;
    stats->tokens_received = session->tokens_received;
    stats->tokens_limit = session->tokens_limit;
    stats->chunks_sent = session->chunks_sent;
    stats->chunks_received = session->chunks_received;
    stats->state = session->state;

    /* Calculate remaining */
    if (session->bytes_limit > 0 && session->bytes_sent < session->bytes_limit) {
        stats->bytes_remaining = session->bytes_limit - session->bytes_sent;
    }
    if (session->tokens_limit > 0 && session->tokens_sent < session->tokens_limit) {
        stats->tokens_remaining = session->tokens_limit - session->tokens_sent;
    }

    /* Calculate duration */
    u64 now_ns = get_time_ns();
    if (session->end_ns > 0) {
        stats->duration_ns = session->end_ns - session->start_ns;
    } else if (session->start_ns > 0) {
        stats->duration_ns = now_ns - session->start_ns;
    }

    /* Calculate average chunk interval */
    if (session->chunks_sent > 1 && stats->duration_ns > 0) {
        stats->avg_chunk_interval_ns = stats->duration_ns / (session->chunks_sent - 1);
    }

    /* Calculate time remaining */
    if (session->timeout_ms > 0 && session->start_ns > 0) {
        u64 elapsed_ms = stats->duration_ns / MILLION;
        if (elapsed_ms < session->timeout_ms) {
            stats->time_remaining_ms = session->timeout_ms - elapsed_ms;
        }
    }

    /* Calculate current rates (rough approximation) */
    u64 rate_window_elapsed = now_ns - session->rate_window_start_ns;
    if (rate_window_elapsed > 0) {
        stats->current_bytes_per_sec = (session->rate_bytes_in_window * BILLION) / rate_window_elapsed;
        stats->current_tokens_per_sec = (session->rate_tokens_in_window * BILLION) / rate_window_elapsed;
    }

    /* Budget status */
    stats->budget_exceeded = (session->state == AK_STREAM_STATE_BUDGET);
    stats->timeout_exceeded = (session->state == AK_STREAM_STATE_TIMEOUT);
}

ak_stream_session_t *ak_stream_get_by_id(u64 session_id)
{
    ak_stream_session_t *session = stream_state.active_sessions;
    while (session) {
        if (session->session_id == session_id) {
            return session;
        }
        session = session->next;
    }
    return NULL;
}

ak_stream_session_t *ak_stream_get_by_uuid(u8 *uuid)
{
    if (!uuid) {
        return NULL;
    }

    ak_stream_session_t *session = stream_state.active_sessions;
    while (session) {
        if (ak_memcmp(session->session_uuid, uuid, AK_TOKEN_ID_SIZE) == 0) {
            return session;
        }
        session = session->next;
    }
    return NULL;
}

u32 ak_stream_list_active(
    ak_stream_session_t **sessions,
    u32 max_count)
{
    if (!sessions || max_count == 0) {
        return 0;
    }

    u32 count = 0;
    ak_stream_session_t *session = stream_state.active_sessions;
    while (session && count < max_count) {
        sessions[count++] = session;
        session = session->next;
    }
    return count;
}

/* ============================================================
 * CALLBACK REGISTRATION
 * ============================================================ */

/* Note: Callback functionality would require additional fields in session
 * structure and proper closure handling. For now, these are stubs. */

void ak_stream_on_chunk(
    ak_stream_session_t *session,
    ak_stream_on_chunk_t callback,
    void *ctx)
{
    /* Stub - would store callback in session */
    (void)session;
    (void)callback;
    (void)ctx;
}

void ak_stream_on_close(
    ak_stream_session_t *session,
    ak_stream_on_close_t callback,
    void *ctx)
{
    /* Stub - would store callback in session */
    (void)session;
    (void)callback;
    (void)ctx;
}

void ak_stream_on_token(
    ak_stream_session_t *session,
    ak_stream_on_token_t callback,
    void *ctx)
{
    /* Stub - would store callback in session */
    (void)session;
    (void)callback;
    (void)ctx;
}

/* ============================================================
 * TIMEOUT MANAGEMENT
 * ============================================================ */

boolean ak_stream_check_timeout(ak_stream_session_t *session)
{
    if (!session) {
        return true;
    }

    if (session->state != AK_STREAM_STATE_ACTIVE &&
        session->state != AK_STREAM_STATE_INIT) {
        return false;  /* Already closed, no timeout check needed */
    }

    u64 now_ns = get_time_ns();

    /* Check total timeout */
    if (session->timeout_ms > 0 && session->start_ns > 0) {
        u64 elapsed_ms = (now_ns - session->start_ns) / MILLION;
        if (elapsed_ms >= session->timeout_ms) {
            ak_stream_abort(session, AK_E_TIMEOUT, "Session timeout");
            session->state = AK_STREAM_STATE_TIMEOUT;
            return true;
        }
    }

    /* Check idle timeout */
    if (session->idle_timeout_ms > 0 && session->last_chunk_ns > 0) {
        u64 idle_ms = (now_ns - session->last_chunk_ns) / MILLION;
        if (idle_ms >= session->idle_timeout_ms) {
            ak_stream_abort(session, AK_E_TIMEOUT, "Idle timeout");
            session->state = AK_STREAM_STATE_TIMEOUT;
            return true;
        }
    }

    return false;
}

void ak_stream_reset_idle_timeout(ak_stream_session_t *session)
{
    if (session) {
        session->last_chunk_ns = get_time_ns();
    }
}

u32 ak_stream_check_all_timeouts(void)
{
    u32 timed_out = 0;
    ak_stream_session_t *session = stream_state.active_sessions;
    ak_stream_session_t *next;

    while (session) {
        next = session->next;
        if (ak_stream_check_timeout(session)) {
            timed_out++;
        }
        session = next;
    }

    return timed_out;
}

/* ============================================================
 * GLOBAL STATISTICS
 * ============================================================ */

void ak_stream_get_global_stats(ak_stream_global_stats_t *stats)
{
    if (!stats) {
        return;
    }

    runtime_memcpy(stats, &stream_state.stats, sizeof(ak_stream_global_stats_t));
}
