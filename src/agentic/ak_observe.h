/*
 * Authority Kernel - Observability Infrastructure
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Provides comprehensive observability for the Authority Kernel:
 *   1. Metrics export (Prometheus, JSON)
 *   2. Distributed tracing (OpenTelemetry compatible)
 *   3. Decision replay for debugging
 *
 * All observability operations are:
 *   - Thread-safe with lock-free counters where possible
 *   - Low-overhead for hot paths
 *   - Exportable in standard formats
 *
 * SECURITY: Trace data may contain sensitive effect information.
 * Export paths should be access-controlled.
 */

#ifndef AK_OBSERVE_H
#define AK_OBSERVE_H

#include "ak_types.h"
#include "ak_effects.h"

/* ============================================================
 * METRIC TYPES
 * ============================================================
 */

typedef enum ak_metric_type {
    AK_METRIC_COUNTER = 0,      /* Monotonically increasing counter */
    AK_METRIC_GAUGE = 1,        /* Point-in-time value (can go up/down) */
    AK_METRIC_HISTOGRAM = 2,    /* Distribution of values */
} ak_metric_type_t;

/* Histogram bucket boundaries (in appropriate units for each metric) */
#define AK_HISTOGRAM_BUCKETS    16

/* Histogram bucket configuration for latency metrics (nanoseconds) */
static const u64 AK_LATENCY_BUCKETS[AK_HISTOGRAM_BUCKETS] = {
    1000,           /* 1us */
    5000,           /* 5us */
    10000,          /* 10us */
    50000,          /* 50us */
    100000,         /* 100us */
    500000,         /* 500us */
    1000000,        /* 1ms */
    5000000,        /* 5ms */
    10000000,       /* 10ms */
    50000000,       /* 50ms */
    100000000,      /* 100ms */
    500000000,      /* 500ms */
    1000000000,     /* 1s */
    5000000000,     /* 5s */
    10000000000,    /* 10s */
    UINT64_MAX      /* +Inf */
};

/* ============================================================
 * METRIC STRUCTURE
 * ============================================================
 */

typedef struct ak_metric {
    char name[64];              /* Metric name (e.g., "ak_effects_total") */
    char help[128];             /* Human-readable description */
    ak_metric_type_t type;
    char labels[256];           /* Label set as "key=value,key=value" */

    union {
        /* Counter: monotonically increasing */
        u64 counter;

        /* Gauge: can go up or down */
        s64 gauge;

        /* Histogram: distribution tracking */
        struct {
            u64 sum;            /* Sum of all observed values */
            u64 count;          /* Number of observations */
            u64 buckets[AK_HISTOGRAM_BUCKETS];  /* Cumulative bucket counts */
        } histogram;
    } value;
} ak_metric_t;

/* ============================================================
 * DISTRIBUTED TRACE SPAN
 * ============================================================
 * OpenTelemetry-compatible trace span for correlation across
 * effects, agents, and external services.
 */

/* Trace/span ID sizes (W3C Trace Context) */
#define AK_TRACE_ID_SIZE        16      /* 128-bit trace ID */
#define AK_SPAN_ID_SIZE         8       /* 64-bit span ID */

typedef struct ak_trace_span {
    /* Identity */
    u8 trace_id[AK_TRACE_ID_SIZE];      /* Unique trace identifier */
    u8 span_id[AK_SPAN_ID_SIZE];        /* Unique span identifier */
    u8 parent_span_id[AK_SPAN_ID_SIZE]; /* Parent span (0 for root) */

    /* Operation */
    char operation[64];                  /* Operation name */
    ak_effect_op_t effect_op;           /* Effect operation type */

    /* Timing */
    u64 start_ns;                       /* Start timestamp (nanoseconds) */
    u64 end_ns;                         /* End timestamp (0 if in-progress) */

    /* Result */
    boolean allowed;                    /* true if effect was allowed */
    ak_deny_reason_t deny_reason;       /* Reason if denied */
    int errno_equiv;                    /* Errno equivalent if denied */

    /* Attributes (JSON key-values for context) */
    char attributes[512];               /* Extensible attributes */
    u32 attributes_len;

    /* Linkage */
    struct ak_trace_span *next;         /* For span pool management */

    /* State */
    boolean active;                     /* Span is still in-progress */
    boolean recorded;                   /* Span has been exported/recorded */
} ak_trace_span_t;

/* ============================================================
 * DECISION LOG ENTRY
 * ============================================================
 * Detailed record of authorization decisions for replay and debugging.
 */

typedef struct ak_decision_log_entry {
    /* Identity */
    u8 trace_id[AK_TRACE_ID_SIZE];
    u64 sequence;                       /* Monotonic sequence number */

    /* Timestamp */
    u64 timestamp_ns;

    /* Effect request (copy of relevant fields) */
    ak_effect_op_t op;
    char target[AK_MAX_TARGET];
    u8 params[AK_MAX_PARAMS];
    u32 params_len;

    /* Context at decision time */
    ak_mode_t mode;
    boolean boot_capsule_active;
    u8 policy_hash[AK_HASH_SIZE];       /* Hash of active policy */

    /* Decision result */
    boolean allowed;
    ak_deny_reason_t reason;
    char missing_cap[AK_MAX_CAPSTR];
    char suggested_snippet[AK_MAX_SUGGEST];

    /* Timing */
    u64 decision_latency_ns;

    /* Chain for storage */
    struct ak_decision_log_entry *next;
} ak_decision_log_entry_t;

/* ============================================================
 * INITIALIZATION
 * ============================================================
 */

/*
 * Initialize observability subsystem.
 *
 * PRECONDITIONS:
 *   - h must be valid heap
 *   - Must be called after ak_effects_init()
 *
 * POSTCONDITIONS:
 *   - Metrics subsystem ready
 *   - Tracing subsystem ready
 *   - Decision logging disabled by default
 */
void ak_observe_init(heap h);

/*
 * Shutdown observability subsystem.
 */
void ak_observe_shutdown(void);

/* ============================================================
 * METRICS API
 * ============================================================
 */

/*
 * Initialize metrics subsystem.
 *
 * Called automatically by ak_observe_init(), but can be called
 * separately for standalone metrics usage.
 */
void ak_metrics_init(heap h);

/*
 * Shutdown metrics subsystem.
 */
void ak_metrics_shutdown(void);

/*
 * Increment a counter metric.
 *
 * @param name      Metric name (e.g., "ak_effects_total")
 * @param labels    Label string "key=value,key=value" or NULL
 *
 * Thread-safe. Creates metric if it doesn't exist.
 */
void ak_metric_inc(const char *name, const char *labels);

/*
 * Add value to a counter metric.
 *
 * @param name      Metric name
 * @param labels    Label string or NULL
 * @param delta     Value to add (must be >= 0)
 */
void ak_metric_add(const char *name, const char *labels, u64 delta);

/*
 * Set a gauge metric value.
 *
 * @param name      Metric name
 * @param labels    Label string or NULL
 * @param value     New gauge value (can be negative)
 */
void ak_metric_set(const char *name, const char *labels, s64 value);

/*
 * Increment a gauge metric.
 *
 * @param name      Metric name
 * @param labels    Label string or NULL
 */
void ak_metric_gauge_inc(const char *name, const char *labels);

/*
 * Decrement a gauge metric.
 *
 * @param name      Metric name
 * @param labels    Label string or NULL
 */
void ak_metric_gauge_dec(const char *name, const char *labels);

/*
 * Record an observation in a histogram metric.
 *
 * @param name      Metric name
 * @param labels    Label string or NULL
 * @param value     Observed value
 */
void ak_metric_observe(const char *name, const char *labels, u64 value);

/*
 * Export metrics in Prometheus text format.
 *
 * @param buf       Output buffer
 * @param max_len   Maximum bytes to write
 *
 * Returns: Bytes written, or negative on error.
 */
s64 ak_metrics_export_prometheus(char *buf, u64 max_len);

/*
 * Export metrics in JSON format.
 *
 * @param buf       Output buffer
 * @param max_len   Maximum bytes to write
 *
 * Returns: Bytes written, or negative on error.
 */
s64 ak_metrics_export_json(char *buf, u64 max_len);

/* ============================================================
 * BUILT-IN METRICS
 * ============================================================
 * These metrics are automatically tracked by the observability subsystem.
 */

/* Metric names */
#define AK_METRIC_EFFECTS_TOTAL         "ak_effects_total"
#define AK_METRIC_EFFECTS_LATENCY       "ak_effects_latency_seconds"
#define AK_METRIC_DENIALS_TOTAL         "ak_denials_total"
#define AK_METRIC_BUDGET_USAGE          "ak_budget_usage"
#define AK_METRIC_ACTIVE_AGENTS         "ak_active_agents"
#define AK_METRIC_STREAMS_ACTIVE        "ak_streams_active"
#define AK_METRIC_TOKENS_TOTAL          "ak_tokens_total"
#define AK_METRIC_SPANS_ACTIVE          "ak_spans_active"
#define AK_METRIC_DECISION_LOG_SIZE     "ak_decision_log_size"

/*
 * Record an effect completion for built-in metrics.
 *
 * Called automatically by ak_authorize_and_execute() when
 * observability is integrated.
 *
 * @param op        Effect operation type
 * @param allowed   Whether effect was allowed
 * @param reason    Deny reason if not allowed
 * @param latency_ns Latency in nanoseconds
 */
void ak_observe_effect(
    ak_effect_op_t op,
    boolean allowed,
    ak_deny_reason_t reason,
    u64 latency_ns
);

/* ============================================================
 * DISTRIBUTED TRACING API
 * ============================================================
 */

/*
 * Start a new trace span.
 *
 * @param operation     Operation name for the span
 * @param parent_trace  Parent trace ID (NULL for new trace)
 * @param parent_span   Parent span ID (NULL for root span)
 *
 * Returns: New span on success, NULL on failure.
 *
 * POSTCONDITIONS:
 *   - Span is marked active
 *   - start_ns is set to current time
 *   - Unique span_id generated
 */
ak_trace_span_t *ak_trace_start(
    const char *operation,
    const u8 *parent_trace,
    const u8 *parent_span
);

/*
 * End a trace span.
 *
 * @param span      Span to end
 *
 * POSTCONDITIONS:
 *   - end_ns is set to current time
 *   - Span is marked inactive
 *   - Span is added to export queue
 */
void ak_trace_end(ak_trace_span_t *span);

/*
 * Set a span attribute.
 *
 * @param span      Span to modify
 * @param key       Attribute key
 * @param value     Attribute value (will be JSON-escaped)
 */
void ak_trace_set_attribute(
    ak_trace_span_t *span,
    const char *key,
    const char *value
);

/*
 * Set span effect details.
 *
 * @param span      Span to modify
 * @param op        Effect operation type
 * @param target    Effect target
 * @param allowed   Whether effect was allowed
 * @param reason    Deny reason if not allowed
 */
void ak_trace_set_effect(
    ak_trace_span_t *span,
    ak_effect_op_t op,
    const char *target,
    boolean allowed,
    ak_deny_reason_t reason
);

/*
 * Get current active span for this thread.
 *
 * Returns: Active span or NULL if none.
 */
ak_trace_span_t *ak_trace_current(void);

/*
 * Set current active span for this thread.
 *
 * Used for propagating trace context through call chains.
 */
void ak_trace_set_current(ak_trace_span_t *span);

/*
 * Export spans in OpenTelemetry Protocol (OTLP) format.
 *
 * @param buf       Output buffer (JSON format)
 * @param max_len   Maximum bytes to write
 *
 * Returns: Bytes written, or negative on error.
 */
s64 ak_trace_export_otlp(char *buf, u64 max_len);

/*
 * Format trace ID as hex string.
 *
 * @param trace_id  16-byte trace ID
 * @param buf       Output buffer (must be at least 33 bytes)
 */
void ak_trace_id_to_hex(const u8 *trace_id, char *buf);

/*
 * Format span ID as hex string.
 *
 * @param span_id   8-byte span ID
 * @param buf       Output buffer (must be at least 17 bytes)
 */
void ak_span_id_to_hex(const u8 *span_id, char *buf);

/*
 * Parse trace ID from hex string.
 *
 * @param hex       32-character hex string
 * @param trace_id  Output 16-byte trace ID
 *
 * Returns: 0 on success, -EINVAL on parse error.
 */
int ak_trace_id_from_hex(const char *hex, u8 *trace_id);

/*
 * Parse span ID from hex string.
 *
 * @param hex       16-character hex string
 * @param span_id   Output 8-byte span ID
 *
 * Returns: 0 on success, -EINVAL on parse error.
 */
int ak_span_id_from_hex(const char *hex, u8 *span_id);

/* ============================================================
 * DECISION REPLAY API
 * ============================================================
 * Enables detailed logging and replay of authorization decisions
 * for debugging and audit purposes.
 */

/*
 * Enable decision logging.
 *
 * When enabled, every authorization decision is recorded with
 * full context for later replay.
 *
 * CAUTION: Decision logging has storage overhead. Enable only
 * when debugging or when full audit trail is required.
 */
void ak_decision_log_enable(void);

/*
 * Disable decision logging.
 */
void ak_decision_log_disable(void);

/*
 * Check if decision logging is enabled.
 */
boolean ak_decision_log_is_enabled(void);

/*
 * Record a decision for the log.
 *
 * Called automatically by ak_authorize_and_execute() when
 * decision logging is enabled.
 *
 * @param ctx       AK context
 * @param req       Effect request
 * @param decision  Authorization decision
 *
 * Returns: 0 on success, negative on error.
 */
int ak_decision_log_record(
    ak_ctx_t *ctx,
    const ak_effect_req_t *req,
    const ak_decision_t *decision
);

/*
 * Replay a decision from the log.
 *
 * Reconstructs the decision context and re-evaluates the policy
 * to verify consistency.
 *
 * @param trace_id  Trace ID of the decision to replay
 * @param result    Output buffer for replay result
 * @param max_len   Maximum bytes to write
 *
 * Returns: 0 on success and match, 1 on success with different result,
 *          negative on error.
 */
int ak_decision_replay(
    const u8 *trace_id,
    char *result,
    u64 max_len
);

/*
 * Query decision log entries.
 *
 * @param h             Heap for result allocation
 * @param start_time_ns Start timestamp filter (0 for no filter)
 * @param end_time_ns   End timestamp filter (UINT64_MAX for no filter)
 * @param op_filter     Operation filter (0 for all)
 * @param allowed_filter Filter by allowed (0=all, 1=allowed only, 2=denied only)
 * @param count_out     Output: number of entries returned
 *
 * Returns: Array of decision log entries (caller must free).
 */
ak_decision_log_entry_t **ak_decision_log_query(
    heap h,
    u64 start_time_ns,
    u64 end_time_ns,
    ak_effect_op_t op_filter,
    int allowed_filter,
    u64 *count_out
);

/*
 * Export decision log as JSON.
 *
 * @param buf       Output buffer
 * @param max_len   Maximum bytes to write
 * @param limit     Maximum entries to export (0 for all)
 *
 * Returns: Bytes written, or negative on error.
 */
s64 ak_decision_log_export_json(char *buf, u64 max_len, u64 limit);

/*
 * Clear decision log.
 *
 * Removes all recorded decisions. Use with caution.
 */
void ak_decision_log_clear(void);

/*
 * Get decision log statistics.
 */
typedef struct ak_decision_log_stats {
    u64 total_entries;
    u64 allowed_count;
    u64 denied_count;
    u64 oldest_timestamp_ns;
    u64 newest_timestamp_ns;
    u64 storage_bytes;
} ak_decision_log_stats_t;

void ak_decision_log_get_stats(ak_decision_log_stats_t *stats);

/* ============================================================
 * INTEGRATION HELPERS
 * ============================================================
 * These functions provide integration points for the observability
 * subsystem with other AK components.
 */

/*
 * Create a trace span for an effect authorization.
 *
 * Called at the start of ak_authorize_and_execute().
 *
 * @param ctx   AK context
 * @param req   Effect request
 *
 * Returns: Span for this authorization, or NULL if tracing disabled.
 */
ak_trace_span_t *ak_observe_effect_start(
    ak_ctx_t *ctx,
    const ak_effect_req_t *req
);

/*
 * Complete a trace span for an effect authorization.
 *
 * Called at the end of ak_authorize_and_execute().
 *
 * @param span      Span to complete
 * @param decision  Authorization decision
 */
void ak_observe_effect_end(
    ak_trace_span_t *span,
    const ak_decision_t *decision
);

/* ============================================================
 * ERROR CODES
 * ============================================================
 */

#define AK_E_OBSERVE_NOT_INIT       (-4800)
#define AK_E_OBSERVE_METRIC_EXISTS  (-4801)
#define AK_E_OBSERVE_METRIC_NOT_FOUND (-4802)
#define AK_E_OBSERVE_SPAN_LIMIT     (-4803)
#define AK_E_OBSERVE_LOG_FULL       (-4804)
#define AK_E_OBSERVE_REPLAY_NOT_FOUND (-4805)

/* ============================================================
 * CONFIGURATION
 * ============================================================
 */

#define AK_OBSERVE_MAX_METRICS      256
#define AK_OBSERVE_MAX_SPANS        1024
#define AK_OBSERVE_SPAN_POOL_SIZE   64
#define AK_OBSERVE_DECISION_LOG_MAX 10000

#endif /* AK_OBSERVE_H */
