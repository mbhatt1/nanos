/*
 * Authority Kernel - Observability Infrastructure Implementation
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Implements comprehensive observability for the Authority Kernel:
 *   1. Metrics export (Prometheus, JSON formats)
 *   2. Distributed tracing (OpenTelemetry compatible)
 *   3. Decision replay for debugging
 *
 * PERFORMANCE: Uses lock-free atomics for counter metrics.
 * SECURITY: Trace data may contain sensitive information.
 */

#include "ak_observe.h"
#include "ak_assert.h"
#include "ak_compat.h"

/* ============================================================
 * MODULE STATE
 * ============================================================
 */

/* Global heap for observability subsystem */
static heap observe_heap = NULL;

/* Metrics subsystem state */
static struct {
  struct spinlock lock;
  ak_metric_t metrics[AK_OBSERVE_MAX_METRICS];
  u32 metric_count;
  boolean initialized;
} metrics_state;

/* Tracing subsystem state */
static struct {
  struct spinlock lock;

  /* Span pool for reuse */
  ak_trace_span_t span_pool[AK_OBSERVE_SPAN_POOL_SIZE];
  u32 pool_used;

  /* Active spans (dynamically allocated beyond pool) */
  ak_trace_span_t *active_spans;
  u32 active_count;

  /* Completed spans pending export */
  ak_trace_span_t *export_queue;
  u32 export_queue_size;

  /* Trace ID generation counter */
  volatile u64 trace_counter;
  volatile u64 span_counter;

  boolean initialized;
} trace_state;

/* Decision log state */
static struct {
  struct spinlock lock;

  ak_decision_log_entry_t *entries;
  u64 entry_count;
  u64 sequence;

  /* Circular buffer management */
  u64 head; /* Next write position */
  u64 capacity;

  /* Statistics */
  u64 allowed_count;
  u64 denied_count;
  u64 oldest_timestamp_ns;
  u64 newest_timestamp_ns;

  boolean enabled;
  boolean initialized;
} decision_log;

/* Per-thread current span */
static __thread ak_trace_span_t *current_span = NULL;

/* ============================================================
 * INITIALIZATION
 * ============================================================
 */

void ak_observe_init(heap h) {
  AK_CHECK_NOT_NULL_VOID(h);
  if (h == INVALID_ADDRESS) {
    ak_error("ak_observe_init: INVALID_ADDRESS heap");
    return;
  }

  observe_heap = h;

  /* Initialize metrics */
  ak_metrics_init(h);

  /* Initialize tracing */
  spin_lock_init(&trace_state.lock);
  ak_memzero(&trace_state.span_pool, sizeof(trace_state.span_pool));
  trace_state.pool_used = 0;
  trace_state.active_spans = NULL;
  trace_state.active_count = 0;
  trace_state.export_queue = NULL;
  trace_state.export_queue_size = 0;

  /* Initialize trace counters with entropy */
  trace_state.trace_counter = ak_now_ms() ^ 0xDEADBEEF12345678ULL;
  trace_state.span_counter = ak_now_ms() ^ 0xCAFEBABE87654321ULL;
  trace_state.initialized = true;

  /* Initialize decision log */
  spin_lock_init(&decision_log.lock);
  decision_log.capacity = AK_OBSERVE_DECISION_LOG_MAX;
  decision_log.entries =
      ak_alloc_array_zero(h, ak_decision_log_entry_t, decision_log.capacity);
  if (!decision_log.entries || decision_log.entries == INVALID_ADDRESS) {
    decision_log.entries = NULL;
    decision_log.capacity = 0;
  }
  decision_log.entry_count = 0;
  decision_log.sequence = 0;
  decision_log.head = 0;
  decision_log.allowed_count = 0;
  decision_log.denied_count = 0;
  decision_log.oldest_timestamp_ns = 0;
  decision_log.newest_timestamp_ns = 0;
  decision_log.enabled = false;
  decision_log.initialized = true;

  ak_debug("ak_observe: initialized");
}

void ak_observe_shutdown(void) {
  ak_metrics_shutdown();

  /* Clean up tracing */
  spin_lock(&trace_state.lock);

  /* Free dynamically allocated spans */
  ak_trace_span_t *span = trace_state.active_spans;
  while (span) {
    ak_trace_span_t *next = span->next;
    deallocate(observe_heap, span, sizeof(ak_trace_span_t));
    span = next;
  }

  span = trace_state.export_queue;
  while (span) {
    ak_trace_span_t *next = span->next;
    deallocate(observe_heap, span, sizeof(ak_trace_span_t));
    span = next;
  }

  trace_state.active_spans = NULL;
  trace_state.export_queue = NULL;
  trace_state.initialized = false;
  spin_unlock(&trace_state.lock);

  /* Clean up decision log */
  spin_lock(&decision_log.lock);
  if (decision_log.entries && decision_log.capacity > 0) {
    deallocate(observe_heap, decision_log.entries,
               sizeof(ak_decision_log_entry_t) * decision_log.capacity);
  }
  decision_log.entries = NULL;
  decision_log.capacity = 0;
  decision_log.initialized = false;
  spin_unlock(&decision_log.lock);

  observe_heap = NULL;
  ak_debug("ak_observe: shutdown");
}

/* ============================================================
 * METRICS IMPLEMENTATION
 * ============================================================
 */

void ak_metrics_init(heap h) {
  (void)h; /* Uses observe_heap */

  spin_lock_init(&metrics_state.lock);
  ak_memzero(&metrics_state.metrics, sizeof(metrics_state.metrics));
  metrics_state.metric_count = 0;
  metrics_state.initialized = true;

  ak_debug("ak_metrics: initialized");
}

void ak_metrics_shutdown(void) {
  spin_lock(&metrics_state.lock);
  metrics_state.metric_count = 0;
  metrics_state.initialized = false;
  spin_unlock(&metrics_state.lock);
}

/* Find or create a metric by name and labels */
static ak_metric_t *ak_metric_find_or_create(const char *name,
                                             const char *labels,
                                             ak_metric_type_t type) {
  if (!metrics_state.initialized)
    return NULL;

  spin_lock(&metrics_state.lock);

  /* Search for existing metric */
  for (u32 i = 0; i < metrics_state.metric_count; i++) {
    ak_metric_t *m = &metrics_state.metrics[i];
    if (ak_strcmp(m->name, name) == 0) {
      /* Check labels match */
      if ((labels == NULL && m->labels[0] == '\0') ||
          (labels && ak_strcmp(m->labels, labels) == 0)) {
        spin_unlock(&metrics_state.lock);
        return m;
      }
    }
  }

  /* Create new metric if space available */
  if (metrics_state.metric_count >= AK_OBSERVE_MAX_METRICS) {
    spin_unlock(&metrics_state.lock);
    return NULL;
  }

  ak_metric_t *m = &metrics_state.metrics[metrics_state.metric_count++];
  ak_memzero(m, sizeof(*m));

  runtime_strncpy(m->name, name, sizeof(m->name) - 1);
  if (labels) {
    runtime_strncpy(m->labels, labels, sizeof(m->labels) - 1);
  }
  m->type = type;

  spin_unlock(&metrics_state.lock);
  return m;
}

void ak_metric_inc(const char *name, const char *labels) {
  ak_metric_add(name, labels, 1);
}

void ak_metric_add(const char *name, const char *labels, u64 delta) {
  if (!name)
    return;

  ak_metric_t *m = ak_metric_find_or_create(name, labels, AK_METRIC_COUNTER);
  if (!m)
    return;

  /* Atomic increment for thread safety */
  __sync_fetch_and_add(&m->value.counter, delta);
}

void ak_metric_set(const char *name, const char *labels, s64 value) {
  if (!name)
    return;

  ak_metric_t *m = ak_metric_find_or_create(name, labels, AK_METRIC_GAUGE);
  if (!m)
    return;

  /* Use atomic exchange for thread safety */
  __sync_lock_test_and_set(&m->value.gauge, value);
}

void ak_metric_gauge_inc(const char *name, const char *labels) {
  if (!name)
    return;

  ak_metric_t *m = ak_metric_find_or_create(name, labels, AK_METRIC_GAUGE);
  if (!m)
    return;

  __sync_fetch_and_add(&m->value.gauge, 1);
}

void ak_metric_gauge_dec(const char *name, const char *labels) {
  if (!name)
    return;

  ak_metric_t *m = ak_metric_find_or_create(name, labels, AK_METRIC_GAUGE);
  if (!m)
    return;

  __sync_fetch_and_sub(&m->value.gauge, 1);
}

void ak_metric_observe(const char *name, const char *labels, u64 value) {
  if (!name)
    return;

  ak_metric_t *m = ak_metric_find_or_create(name, labels, AK_METRIC_HISTOGRAM);
  if (!m)
    return;

  spin_lock(&metrics_state.lock);

  /* Update sum and count */
  m->value.histogram.sum += value;
  m->value.histogram.count++;

  /* Update bucket counts (cumulative) */
  for (int i = 0; i < AK_HISTOGRAM_BUCKETS; i++) {
    if (value <= AK_LATENCY_BUCKETS[i]) {
      m->value.histogram.buckets[i]++;
    }
  }

  spin_unlock(&metrics_state.lock);
}

/* Helper to format labels for Prometheus */
static int ak_format_prometheus_labels(const char *labels, char *buf,
                                       u64 max_len) {
  if (!labels || labels[0] == '\0')
    return 0;

  /* Format: {key="value",key="value"} */
  int len = 0;
  buf[len++] = '{';

  const char *p = labels;
  while (*p && (u64)len < max_len - 2) {
    /* Copy until = or , or end */
    if (*p == '=') {
      buf[len++] = '=';
      buf[len++] = '"';
      p++;
      /* Copy value */
      while (*p && *p != ',' && (u64)len < max_len - 2) {
        buf[len++] = *p++;
      }
      buf[len++] = '"';
      if (*p == ',') {
        buf[len++] = ',';
        p++;
      }
    } else {
      buf[len++] = *p++;
    }
  }

  buf[len++] = '}';
  buf[len] = '\0';
  return len;
}

s64 ak_metrics_export_prometheus(char *buf, u64 max_len) {
  if (!buf || max_len < 64)
    return -EINVAL;

  if (!metrics_state.initialized)
    return -AK_E_OBSERVE_NOT_INIT;

  spin_lock(&metrics_state.lock);

  s64 pos = 0;

  for (u32 i = 0; i < metrics_state.metric_count && (u64)pos < max_len - 256;
       i++) {
    ak_metric_t *m = &metrics_state.metrics[i];

    char label_buf[512];
    int label_len =
        ak_format_prometheus_labels(m->labels, label_buf, sizeof(label_buf));

    switch (m->type) {
    case AK_METRIC_COUNTER:
      /* # HELP and # TYPE comments */
      if (m->help[0]) {
        pos += bsnprintf(buf + pos, max_len - pos, "# HELP %s %s\n", m->name,
                         m->help);
      }
      pos +=
          bsnprintf(buf + pos, max_len - pos, "# TYPE %s counter\n", m->name);
      if (label_len > 0) {
        pos += bsnprintf(buf + pos, max_len - pos, "%s%s %llu\n", m->name,
                         label_buf, m->value.counter);
      } else {
        pos += bsnprintf(buf + pos, max_len - pos, "%s %llu\n", m->name,
                         m->value.counter);
      }
      break;

    case AK_METRIC_GAUGE:
      if (m->help[0]) {
        pos += bsnprintf(buf + pos, max_len - pos, "# HELP %s %s\n", m->name,
                         m->help);
      }
      pos += bsnprintf(buf + pos, max_len - pos, "# TYPE %s gauge\n", m->name);
      if (label_len > 0) {
        pos += bsnprintf(buf + pos, max_len - pos, "%s%s %lld\n", m->name,
                         label_buf, m->value.gauge);
      } else {
        pos += bsnprintf(buf + pos, max_len - pos, "%s %lld\n", m->name,
                         m->value.gauge);
      }
      break;

    case AK_METRIC_HISTOGRAM:
      if (m->help[0]) {
        pos += bsnprintf(buf + pos, max_len - pos, "# HELP %s %s\n", m->name,
                         m->help);
      }
      pos +=
          bsnprintf(buf + pos, max_len - pos, "# TYPE %s histogram\n", m->name);

      /* Bucket entries */
      for (int b = 0; b < AK_HISTOGRAM_BUCKETS && (u64)pos < max_len - 128;
           b++) {
        u64 bucket_val = AK_LATENCY_BUCKETS[b];
        if (bucket_val == UINT64_MAX) {
          pos += bsnprintf(buf + pos, max_len - pos,
                           "%s_bucket{le=\"+Inf\"} %llu\n", m->name,
                           m->value.histogram.buckets[b]);
        } else {
          /* Convert to seconds for Prometheus */
          double secs = (double)bucket_val / 1000000000.0;
          pos += bsnprintf(buf + pos, max_len - pos,
                           "%s_bucket{le=\"%.9f\"} %llu\n", m->name, secs,
                           m->value.histogram.buckets[b]);
        }
      }

      /* Sum and count */
      double sum_secs = (double)m->value.histogram.sum / 1000000000.0;
      pos += bsnprintf(buf + pos, max_len - pos, "%s_sum %.9f\n", m->name,
                       sum_secs);
      pos += bsnprintf(buf + pos, max_len - pos, "%s_count %llu\n", m->name,
                       m->value.histogram.count);
      break;
    }
  }

  spin_unlock(&metrics_state.lock);
  return pos;
}

s64 ak_metrics_export_json(char *buf, u64 max_len) {
  if (!buf || max_len < 64)
    return -EINVAL;

  if (!metrics_state.initialized)
    return -AK_E_OBSERVE_NOT_INIT;

  spin_lock(&metrics_state.lock);

  s64 pos = 0;
  pos += bsnprintf(buf + pos, max_len - pos, "{\"metrics\":[");

  for (u32 i = 0; i < metrics_state.metric_count && (u64)pos < max_len - 256;
       i++) {
    ak_metric_t *m = &metrics_state.metrics[i];

    if (i > 0) {
      buf[pos++] = ',';
    }

    const char *type_str;
    switch (m->type) {
    case AK_METRIC_COUNTER:
      type_str = "counter";
      break;
    case AK_METRIC_GAUGE:
      type_str = "gauge";
      break;
    case AK_METRIC_HISTOGRAM:
      type_str = "histogram";
      break;
    default:
      type_str = "unknown";
      break;
    }

    pos += bsnprintf(buf + pos, max_len - pos,
                     "{\"name\":\"%s\",\"type\":\"%s\"", m->name, type_str);

    if (m->labels[0]) {
      pos +=
          bsnprintf(buf + pos, max_len - pos, ",\"labels\":\"%s\"", m->labels);
    }

    switch (m->type) {
    case AK_METRIC_COUNTER:
      pos += bsnprintf(buf + pos, max_len - pos, ",\"value\":%llu}",
                       m->value.counter);
      break;
    case AK_METRIC_GAUGE:
      pos += bsnprintf(buf + pos, max_len - pos, ",\"value\":%lld}",
                       m->value.gauge);
      break;
    case AK_METRIC_HISTOGRAM:
      pos +=
          bsnprintf(buf + pos, max_len - pos, ",\"sum\":%llu,\"count\":%llu}",
                    m->value.histogram.sum, m->value.histogram.count);
      break;
    }
  }

  pos += bsnprintf(buf + pos, max_len - pos, "]}");

  spin_unlock(&metrics_state.lock);
  return pos;
}

/* ============================================================
 * BUILT-IN METRICS RECORDING
 * ============================================================
 */

/* Effect operation to string for labels */
static const char *ak_effect_op_label(ak_effect_op_t op) {
  switch (op) {
  case AK_E_FS_OPEN:
    return "fs_open";
  case AK_E_FS_UNLINK:
    return "fs_unlink";
  case AK_E_FS_RENAME:
    return "fs_rename";
  case AK_E_FS_MKDIR:
    return "fs_mkdir";
  case AK_E_FS_RMDIR:
    return "fs_rmdir";
  case AK_E_FS_STAT:
    return "fs_stat";
  case AK_E_NET_CONNECT:
    return "net_connect";
  case AK_E_NET_DNS_RESOLVE:
    return "net_dns";
  case AK_E_NET_BIND:
    return "net_bind";
  case AK_E_NET_LISTEN:
    return "net_listen";
  case AK_E_NET_ACCEPT:
    return "net_accept";
  case AK_E_PROC_SPAWN:
    return "proc_spawn";
  case AK_E_PROC_SIGNAL:
    return "proc_signal";
  case AK_E_PROC_WAIT:
    return "proc_wait";
  case AK_E_TOOL_CALL:
    return "tool_call";
  case AK_E_WASM_INVOKE:
    return "wasm_invoke";
  case AK_E_INFER:
    return "infer";
  default:
    return "unknown";
  }
}

/* Deny reason to string for labels */
static const char *ak_deny_reason_label(ak_deny_reason_t reason) {
  switch (reason) {
  case AK_DENY_NONE:
    return "none";
  case AK_DENY_NO_POLICY:
    return "no_policy";
  case AK_DENY_NO_CAP:
    return "no_cap";
  case AK_DENY_CAP_EXPIRED:
    return "cap_expired";
  case AK_DENY_PATTERN_MISMATCH:
    return "pattern_mismatch";
  case AK_DENY_BUDGET_EXCEEDED:
    return "budget_exceeded";
  case AK_DENY_RATE_LIMITED:
    return "rate_limited";
  case AK_DENY_TAINT:
    return "taint";
  case AK_DENY_REVOKED:
    return "revoked";
  case AK_DENY_MODE:
    return "mode";
  case AK_DENY_BOOT_CAPSULE:
    return "boot_capsule";
  default:
    return "unknown";
  }
}

void ak_observe_effect(ak_effect_op_t op, boolean allowed,
                       ak_deny_reason_t reason, u64 latency_ns) {
  char labels[128];

  /* ak_effects_total{op=xxx, allowed=true/false} */
  bsnprintf(labels, sizeof(labels), "op=%s,allowed=%s", ak_effect_op_label(op),
            allowed ? "true" : "false");
  ak_metric_inc(AK_METRIC_EFFECTS_TOTAL, labels);

  /* ak_effects_latency_seconds{op=xxx} */
  bsnprintf(labels, sizeof(labels), "op=%s", ak_effect_op_label(op));
  ak_metric_observe(AK_METRIC_EFFECTS_LATENCY, labels, latency_ns);

  /* ak_denials_total{op=xxx, reason=xxx} */
  if (!allowed) {
    bsnprintf(labels, sizeof(labels), "op=%s,reason=%s", ak_effect_op_label(op),
              ak_deny_reason_label(reason));
    ak_metric_inc(AK_METRIC_DENIALS_TOTAL, labels);
  }
}

/* ============================================================
 * DISTRIBUTED TRACING IMPLEMENTATION
 * ============================================================
 */

/* Generate a random-ish trace ID */
static void ak_generate_trace_id(u8 *trace_id) {
  u64 ts = ak_now_ms();
  u64 counter = __sync_fetch_and_add(&trace_state.trace_counter, 1);

  /* First 8 bytes: timestamp-based */
  trace_id[0] = (ts >> 56) & 0xFF;
  trace_id[1] = (ts >> 48) & 0xFF;
  trace_id[2] = (ts >> 40) & 0xFF;
  trace_id[3] = (ts >> 32) & 0xFF;
  trace_id[4] = (ts >> 24) & 0xFF;
  trace_id[5] = (ts >> 16) & 0xFF;
  trace_id[6] = (ts >> 8) & 0xFF;
  trace_id[7] = ts & 0xFF;

  /* Second 8 bytes: counter-based */
  trace_id[8] = (counter >> 56) & 0xFF;
  trace_id[9] = (counter >> 48) & 0xFF;
  trace_id[10] = (counter >> 40) & 0xFF;
  trace_id[11] = (counter >> 32) & 0xFF;
  trace_id[12] = (counter >> 24) & 0xFF;
  trace_id[13] = (counter >> 16) & 0xFF;
  trace_id[14] = (counter >> 8) & 0xFF;
  trace_id[15] = counter & 0xFF;
}

/* Generate a span ID */
static void ak_generate_span_id(u8 *span_id) {
  u64 counter = __sync_fetch_and_add(&trace_state.span_counter, 1);
  u64 ts = ak_now_ms();

  /* Mix timestamp and counter */
  u64 val = (ts << 32) | (counter & 0xFFFFFFFF);
  for (int i = 0; i < 8; i++) {
    span_id[7 - i] = val & 0xFF;
    val >>= 8;
  }
}

/* Allocate a span from pool or heap */
static ak_trace_span_t *ak_span_alloc(void) {
  spin_lock(&trace_state.lock);

  /* Try pool first */
  for (u32 i = 0; i < AK_OBSERVE_SPAN_POOL_SIZE; i++) {
    if (!trace_state.span_pool[i].active &&
        !trace_state.span_pool[i].recorded) {
      ak_trace_span_t *span = &trace_state.span_pool[i];
      ak_memzero(span, sizeof(*span));
      trace_state.pool_used++;
      spin_unlock(&trace_state.lock);
      return span;
    }
  }

  /* Check limit */
  if (trace_state.active_count >= AK_OBSERVE_MAX_SPANS) {
    spin_unlock(&trace_state.lock);
    return NULL;
  }

  /* Allocate from heap */
  ak_trace_span_t *span = ak_alloc_zero(observe_heap, ak_trace_span_t);
  if (!span || span == INVALID_ADDRESS) {
    spin_unlock(&trace_state.lock);
    return NULL;
  }

  /* Add to active list */
  span->next = trace_state.active_spans;
  trace_state.active_spans = span;
  trace_state.active_count++;

  spin_unlock(&trace_state.lock);
  return span;
}

ak_trace_span_t *ak_trace_start(const char *operation, const u8 *parent_trace,
                                const u8 *parent_span) {
  if (!trace_state.initialized || !operation)
    return NULL;

  ak_trace_span_t *span = ak_span_alloc();
  if (!span)
    return NULL;

  /* Generate or inherit trace ID */
  if (parent_trace) {
    runtime_memcpy(span->trace_id, parent_trace, AK_TRACE_ID_SIZE);
  } else {
    ak_generate_trace_id(span->trace_id);
  }

  /* Generate span ID */
  ak_generate_span_id(span->span_id);

  /* Set parent span ID */
  if (parent_span) {
    runtime_memcpy(span->parent_span_id, parent_span, AK_SPAN_ID_SIZE);
  } else {
    ak_memzero(span->parent_span_id, AK_SPAN_ID_SIZE);
  }

  /* Set operation */
  runtime_strncpy(span->operation, operation, sizeof(span->operation) - 1);

  /* Set timing */
  span->start_ns = ak_now();
  span->end_ns = 0;

  /* Mark as active */
  span->active = true;
  span->recorded = false;

  /* Update active spans metric */
  ak_metric_gauge_inc(AK_METRIC_SPANS_ACTIVE, NULL);

  return span;
}

void ak_trace_end(ak_trace_span_t *span) {
  if (!span)
    return;

  span->end_ns = ak_now();
  span->active = false;

  /* Update active spans metric */
  ak_metric_gauge_dec(AK_METRIC_SPANS_ACTIVE, NULL);

  /* Add to export queue */
  spin_lock(&trace_state.lock);

  span->next = trace_state.export_queue;
  trace_state.export_queue = span;
  trace_state.export_queue_size++;

  spin_unlock(&trace_state.lock);
}

void ak_trace_set_attribute(ak_trace_span_t *span, const char *key,
                            const char *value) {
  if (!span || !key || !value)
    return;

  u32 current_len = span->attributes_len;
  u32 remaining = sizeof(span->attributes) - current_len;

  if (remaining < 32)
    return; /* Not enough space */

  char *p = span->attributes + current_len;

  /* Add comma if not first attribute */
  if (current_len > 0) {
    *p++ = ',';
    remaining--;
  }

  /* Format: "key":"value" */
  int written = bsnprintf(p, remaining, "\"%s\":\"%s\"", key, value);
  if (written > 0) {
    span->attributes_len = current_len + (current_len > 0 ? 1 : 0) + written;
  }
}

void ak_trace_set_effect(ak_trace_span_t *span, ak_effect_op_t op,
                         const char *target, boolean allowed,
                         ak_deny_reason_t reason) {
  if (!span)
    return;

  span->effect_op = op;
  span->allowed = allowed;
  span->deny_reason = reason;

  ak_trace_set_attribute(span, "effect.op", ak_effect_op_label(op));
  if (target) {
    ak_trace_set_attribute(span, "effect.target", target);
  }
  ak_trace_set_attribute(span, "effect.allowed", allowed ? "true" : "false");
  if (!allowed) {
    ak_trace_set_attribute(span, "effect.deny_reason",
                           ak_deny_reason_label(reason));
  }
}

ak_trace_span_t *ak_trace_current(void) { return current_span; }

void ak_trace_set_current(ak_trace_span_t *span) { current_span = span; }

/* Hex character table */
static const char hex_chars[] = "0123456789abcdef";

void ak_trace_id_to_hex(const u8 *trace_id, char *buf) {
  for (int i = 0; i < AK_TRACE_ID_SIZE; i++) {
    buf[i * 2] = hex_chars[(trace_id[i] >> 4) & 0xF];
    buf[i * 2 + 1] = hex_chars[trace_id[i] & 0xF];
  }
  buf[AK_TRACE_ID_SIZE * 2] = '\0';
}

void ak_span_id_to_hex(const u8 *span_id, char *buf) {
  for (int i = 0; i < AK_SPAN_ID_SIZE; i++) {
    buf[i * 2] = hex_chars[(span_id[i] >> 4) & 0xF];
    buf[i * 2 + 1] = hex_chars[span_id[i] & 0xF];
  }
  buf[AK_SPAN_ID_SIZE * 2] = '\0';
}

static int hex_char_to_nibble(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

int ak_trace_id_from_hex(const char *hex, u8 *trace_id) {
  if (!hex || !trace_id)
    return -EINVAL;

  for (int i = 0; i < AK_TRACE_ID_SIZE; i++) {
    int hi = hex_char_to_nibble(hex[i * 2]);
    int lo = hex_char_to_nibble(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0)
      return -EINVAL;
    trace_id[i] = (hi << 4) | lo;
  }
  return 0;
}

int ak_span_id_from_hex(const char *hex, u8 *span_id) {
  if (!hex || !span_id)
    return -EINVAL;

  for (int i = 0; i < AK_SPAN_ID_SIZE; i++) {
    int hi = hex_char_to_nibble(hex[i * 2]);
    int lo = hex_char_to_nibble(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0)
      return -EINVAL;
    span_id[i] = (hi << 4) | lo;
  }
  return 0;
}

s64 ak_trace_export_otlp(char *buf, u64 max_len) {
  if (!buf || max_len < 256)
    return -EINVAL;

  if (!trace_state.initialized)
    return -AK_E_OBSERVE_NOT_INIT;

  spin_lock(&trace_state.lock);

  s64 pos = 0;

  /* OTLP JSON format */
  pos += bsnprintf(buf + pos, max_len - pos,
                   "{\"resourceSpans\":[{\"scopeSpans\":[{\"spans\":[");

  ak_trace_span_t *span = trace_state.export_queue;
  boolean first = true;

  while (span && (u64)pos < max_len - 512) {
    if (!first) {
      buf[pos++] = ',';
    }
    first = false;

    char trace_hex[33], span_hex[17], parent_hex[17];
    ak_trace_id_to_hex(span->trace_id, trace_hex);
    ak_span_id_to_hex(span->span_id, span_hex);
    ak_span_id_to_hex(span->parent_span_id, parent_hex);

    pos +=
        bsnprintf(buf + pos, max_len - pos,
                  "{\"traceId\":\"%s\",\"spanId\":\"%s\"", trace_hex, span_hex);

    /* Parent span ID (if not zero) */
    boolean has_parent = false;
    for (int i = 0; i < AK_SPAN_ID_SIZE; i++) {
      if (span->parent_span_id[i] != 0) {
        has_parent = true;
        break;
      }
    }
    if (has_parent) {
      pos += bsnprintf(buf + pos, max_len - pos, ",\"parentSpanId\":\"%s\"",
                       parent_hex);
    }

    pos += bsnprintf(buf + pos, max_len - pos, ",\"name\":\"%s\"",
                     span->operation);

    /* Timing (in nanoseconds) */
    pos += bsnprintf(buf + pos, max_len - pos, ",\"startTimeUnixNano\":%llu",
                     span->start_ns);
    if (span->end_ns > 0) {
      pos += bsnprintf(buf + pos, max_len - pos, ",\"endTimeUnixNano\":%llu",
                       span->end_ns);
    }

    /* Status */
    pos += bsnprintf(buf + pos, max_len - pos, ",\"status\":{\"code\":\"%s\"}",
                     span->allowed ? "OK" : "ERROR");

    /* Attributes */
    if (span->attributes_len > 0) {
      pos += bsnprintf(buf + pos, max_len - pos, ",\"attributes\":{%s}",
                       span->attributes);
    }

    pos += bsnprintf(buf + pos, max_len - pos, "}");

    /* Mark as recorded and move to next */
    span->recorded = true;
    span = span->next;
  }

  pos += bsnprintf(buf + pos, max_len - pos, "]}]}]}");

  /* Clear export queue for recorded spans */
  trace_state.export_queue = NULL;
  trace_state.export_queue_size = 0;

  spin_unlock(&trace_state.lock);
  return pos;
}

/* ============================================================
 * DECISION REPLAY IMPLEMENTATION
 * ============================================================
 */

void ak_decision_log_enable(void) {
  if (!decision_log.initialized)
    return;

  spin_lock(&decision_log.lock);
  decision_log.enabled = true;
  spin_unlock(&decision_log.lock);

  ak_debug("ak_observe: decision logging enabled");
}

void ak_decision_log_disable(void) {
  spin_lock(&decision_log.lock);
  decision_log.enabled = false;
  spin_unlock(&decision_log.lock);

  ak_debug("ak_observe: decision logging disabled");
}

boolean ak_decision_log_is_enabled(void) { return decision_log.enabled; }

int ak_decision_log_record(ak_ctx_t *ctx, const ak_effect_req_t *req,
                           const ak_decision_t *decision) {
  if (!decision_log.initialized || !decision_log.enabled)
    return 0;

  if (!ctx || !req || !decision)
    return -EINVAL;

  if (!decision_log.entries || decision_log.capacity == 0)
    return -AK_E_OBSERVE_LOG_FULL;

  spin_lock(&decision_log.lock);

  /* Get entry at head position (circular buffer) */
  u64 idx = decision_log.head % decision_log.capacity;
  ak_decision_log_entry_t *entry = &decision_log.entries[idx];

  /* Fill entry */
  /* Generate trace ID from request trace_id (convert u64 to bytes) */
  ak_memzero(entry->trace_id, AK_TRACE_ID_SIZE);
  u64 trace_val = req->trace_id;
  for (int i = 7; i >= 0; i--) {
    entry->trace_id[i] = trace_val & 0xFF;
    trace_val >>= 8;
  }

  entry->sequence = ++decision_log.sequence;
  entry->timestamp_ns = ak_now();

  /* Copy effect request details */
  entry->op = req->op;
  runtime_strncpy(entry->target, req->target, AK_MAX_TARGET);
  if (req->params_len > 0 && req->params_len <= AK_MAX_PARAMS) {
    runtime_memcpy(entry->params, req->params, req->params_len);
    entry->params_len = req->params_len;
  } else {
    entry->params_len = 0;
  }

  /* Context at decision time */
  entry->mode = ctx->mode;
  entry->boot_capsule_active = ak_ctx_boot_capsule_active(ctx);
  /* Policy hash would come from policy subsystem if available */
  ak_memzero(entry->policy_hash, AK_HASH_SIZE);

  /* Decision result */
  entry->allowed = decision->allow;
  entry->reason = decision->reason_code;
  runtime_strncpy(entry->missing_cap, decision->missing_cap, AK_MAX_CAPSTR);
  runtime_strncpy(entry->suggested_snippet, decision->suggested_snippet,
                  AK_MAX_SUGGEST);

  /* Timing */
  entry->decision_latency_ns = decision->decision_ns;

  /* Update statistics */
  if (decision->allow) {
    decision_log.allowed_count++;
  } else {
    decision_log.denied_count++;
  }

  decision_log.newest_timestamp_ns = entry->timestamp_ns;
  if (decision_log.entry_count == 0) {
    decision_log.oldest_timestamp_ns = entry->timestamp_ns;
  }

  /* Advance head */
  decision_log.head++;
  if (decision_log.entry_count < decision_log.capacity) {
    decision_log.entry_count++;
  } else {
    /* Circular buffer wrapped - update oldest timestamp */
    u64 oldest_idx = decision_log.head % decision_log.capacity;
    decision_log.oldest_timestamp_ns =
        decision_log.entries[oldest_idx].timestamp_ns;
  }

  /* Update metric */
  ak_metric_set(AK_METRIC_DECISION_LOG_SIZE, NULL, decision_log.entry_count);

  spin_unlock(&decision_log.lock);
  return 0;
}

int ak_decision_replay(const u8 *trace_id, char *result, u64 max_len) {
  if (!decision_log.initialized)
    return -AK_E_OBSERVE_NOT_INIT;

  if (!trace_id || !result || max_len < 256)
    return -EINVAL;

  spin_lock(&decision_log.lock);

  /* Search for entry with matching trace_id */
  ak_decision_log_entry_t *found = NULL;

  for (u64 i = 0; i < decision_log.entry_count; i++) {
    u64 idx = (decision_log.head - 1 - i + decision_log.capacity) %
              decision_log.capacity;
    ak_decision_log_entry_t *entry = &decision_log.entries[idx];

    if (runtime_memcmp(entry->trace_id, trace_id, AK_TRACE_ID_SIZE) == 0) {
      found = entry;
      break;
    }
  }

  if (!found) {
    spin_unlock(&decision_log.lock);
    return -AK_E_OBSERVE_REPLAY_NOT_FOUND;
  }

  /* Format replay result as JSON */
  char trace_hex[33];
  ak_trace_id_to_hex(found->trace_id, trace_hex);

  s64 pos = 0;
  pos += bsnprintf(result + pos, max_len - pos,
                   "{\"trace_id\":\"%s\",\"sequence\":%llu", trace_hex,
                   found->sequence);

  pos += bsnprintf(result + pos, max_len - pos, ",\"timestamp_ns\":%llu",
                   found->timestamp_ns);

  pos +=
      bsnprintf(result + pos, max_len - pos, ",\"op\":\"%s\",\"target\":\"%s\"",
                ak_effect_op_label(found->op), found->target);

  pos += bsnprintf(result + pos, max_len - pos,
                   ",\"mode\":%d,\"boot_capsule_active\":%s", found->mode,
                   found->boot_capsule_active ? "true" : "false");

  pos += bsnprintf(result + pos, max_len - pos,
                   ",\"decision\":{\"allowed\":%s,\"reason\":\"%s\"",
                   found->allowed ? "true" : "false",
                   ak_deny_reason_label(found->reason));

  if (found->missing_cap[0]) {
    pos += bsnprintf(result + pos, max_len - pos, ",\"missing_cap\":\"%s\"",
                     found->missing_cap);
  }

  pos += bsnprintf(result + pos, max_len - pos, ",\"latency_ns\":%llu}",
                   found->decision_latency_ns);

  pos += bsnprintf(result + pos, max_len - pos, "}");

  spin_unlock(&decision_log.lock);
  return 0;
}

ak_decision_log_entry_t **ak_decision_log_query(heap h, u64 start_time_ns,
                                                u64 end_time_ns,
                                                ak_effect_op_t op_filter,
                                                int allowed_filter,
                                                u64 *count_out) {
  if (!decision_log.initialized || !count_out) {
    if (count_out)
      *count_out = 0;
    return NULL;
  }

  spin_lock(&decision_log.lock);

  /* First pass: count matching entries */
  u64 match_count = 0;
  for (u64 i = 0; i < decision_log.entry_count; i++) {
    u64 idx = (decision_log.head - 1 - i + decision_log.capacity) %
              decision_log.capacity;
    ak_decision_log_entry_t *entry = &decision_log.entries[idx];

    /* Apply filters */
    if (entry->timestamp_ns < start_time_ns)
      continue;
    if (entry->timestamp_ns > end_time_ns)
      continue;
    if (op_filter != 0 && entry->op != op_filter)
      continue;
    if (allowed_filter == 1 && !entry->allowed)
      continue;
    if (allowed_filter == 2 && entry->allowed)
      continue;

    match_count++;
  }

  if (match_count == 0) {
    spin_unlock(&decision_log.lock);
    *count_out = 0;
    return NULL;
  }

  /* Allocate result array */
  ak_decision_log_entry_t **results =
      ak_alloc_array(h, ak_decision_log_entry_t *, match_count);
  if (!results || results == INVALID_ADDRESS) {
    spin_unlock(&decision_log.lock);
    *count_out = 0;
    return NULL;
  }

  /* Second pass: collect matching entries */
  u64 result_idx = 0;
  for (u64 i = 0; i < decision_log.entry_count && result_idx < match_count;
       i++) {
    u64 idx = (decision_log.head - 1 - i + decision_log.capacity) %
              decision_log.capacity;
    ak_decision_log_entry_t *entry = &decision_log.entries[idx];

    /* Apply same filters */
    if (entry->timestamp_ns < start_time_ns)
      continue;
    if (entry->timestamp_ns > end_time_ns)
      continue;
    if (op_filter != 0 && entry->op != op_filter)
      continue;
    if (allowed_filter == 1 && !entry->allowed)
      continue;
    if (allowed_filter == 2 && entry->allowed)
      continue;

    results[result_idx++] = entry;
  }

  spin_unlock(&decision_log.lock);

  *count_out = match_count;
  return results;
}

s64 ak_decision_log_export_json(char *buf, u64 max_len, u64 limit) {
  if (!buf || max_len < 128)
    return -EINVAL;

  if (!decision_log.initialized)
    return -AK_E_OBSERVE_NOT_INIT;

  spin_lock(&decision_log.lock);

  s64 pos = 0;
  pos += bsnprintf(buf + pos, max_len - pos, "{\"decisions\":[");

  u64 export_count = decision_log.entry_count;
  if (limit > 0 && limit < export_count) {
    export_count = limit;
  }

  for (u64 i = 0; i < export_count && (u64)pos < max_len - 512; i++) {
    /* Export from newest to oldest */
    u64 idx = (decision_log.head - 1 - i + decision_log.capacity) %
              decision_log.capacity;
    ak_decision_log_entry_t *entry = &decision_log.entries[idx];

    if (i > 0) {
      buf[pos++] = ',';
    }

    char trace_hex[33];
    ak_trace_id_to_hex(entry->trace_id, trace_hex);

    pos += bsnprintf(buf + pos, max_len - pos,
                     "{\"trace_id\":\"%s\",\"seq\":%llu,\"ts\":%llu", trace_hex,
                     entry->sequence, entry->timestamp_ns);

    pos +=
        bsnprintf(buf + pos, max_len - pos, ",\"op\":\"%s\",\"target\":\"%s\"",
                  ak_effect_op_label(entry->op), entry->target);

    pos += bsnprintf(
        buf + pos, max_len - pos, ",\"allowed\":%s,\"reason\":\"%s\"",
        entry->allowed ? "true" : "false", ak_deny_reason_label(entry->reason));

    pos += bsnprintf(buf + pos, max_len - pos, ",\"latency_ns\":%llu}",
                     entry->decision_latency_ns);
  }

  pos +=
      bsnprintf(buf + pos, max_len - pos, "],\"total\":%llu,\"exported\":%llu}",
                decision_log.entry_count, export_count);

  spin_unlock(&decision_log.lock);
  return pos;
}

void ak_decision_log_clear(void) {
  if (!decision_log.initialized)
    return;

  spin_lock(&decision_log.lock);

  decision_log.head = 0;
  decision_log.entry_count = 0;
  decision_log.sequence = 0;
  decision_log.allowed_count = 0;
  decision_log.denied_count = 0;
  decision_log.oldest_timestamp_ns = 0;
  decision_log.newest_timestamp_ns = 0;

  ak_metric_set(AK_METRIC_DECISION_LOG_SIZE, NULL, 0);

  spin_unlock(&decision_log.lock);

  ak_debug("ak_observe: decision log cleared");
}

void ak_decision_log_get_stats(ak_decision_log_stats_t *stats) {
  if (!stats)
    return;

  spin_lock(&decision_log.lock);

  stats->total_entries = decision_log.entry_count;
  stats->allowed_count = decision_log.allowed_count;
  stats->denied_count = decision_log.denied_count;
  stats->oldest_timestamp_ns = decision_log.oldest_timestamp_ns;
  stats->newest_timestamp_ns = decision_log.newest_timestamp_ns;
  stats->storage_bytes =
      decision_log.capacity * sizeof(ak_decision_log_entry_t);

  spin_unlock(&decision_log.lock);
}

/* ============================================================
 * INTEGRATION HELPERS
 * ============================================================
 */

ak_trace_span_t *ak_observe_effect_start(ak_ctx_t *ctx,
                                         const ak_effect_req_t *req) {
  if (!trace_state.initialized || !req)
    return NULL;

  /* Get operation name */
  const char *op_name = ak_effect_op_label(req->op);

  /* Check for parent span context */
  ak_trace_span_t *parent = ak_trace_current();
  const u8 *parent_trace = parent ? parent->trace_id : NULL;
  const u8 *parent_span_id = parent ? parent->span_id : NULL;

  /* Create span */
  ak_trace_span_t *span = ak_trace_start(op_name, parent_trace, parent_span_id);
  if (!span)
    return NULL;

  /* Set effect details */
  ak_trace_set_attribute(span, "ak.effect.target", req->target);

  char trace_id_str[32];
  bsnprintf(trace_id_str, sizeof(trace_id_str), "%llu", req->trace_id);
  ak_trace_set_attribute(span, "ak.effect.trace_id", trace_id_str);

  /* Set as current span */
  ak_trace_set_current(span);

  return span;
}

void ak_observe_effect_end(ak_trace_span_t *span,
                           const ak_decision_t *decision) {
  if (!span)
    return;

  if (decision) {
    span->allowed = decision->allow;
    span->deny_reason = decision->reason_code;
    span->errno_equiv = decision->errno_equiv;

    ak_trace_set_attribute(span, "ak.decision.allowed",
                           decision->allow ? "true" : "false");

    if (!decision->allow) {
      ak_trace_set_attribute(span, "ak.decision.reason",
                             ak_deny_reason_label(decision->reason_code));
      if (decision->missing_cap[0]) {
        ak_trace_set_attribute(span, "ak.decision.missing_cap",
                               decision->missing_cap);
      }
    }

    char latency_str[32];
    bsnprintf(latency_str, sizeof(latency_str), "%llu", decision->decision_ns);
    ak_trace_set_attribute(span, "ak.decision.latency_ns", latency_str);
  }

  /* End span */
  ak_trace_end(span);

  /* Clear current span if this was it */
  if (ak_trace_current() == span) {
    ak_trace_set_current(NULL);
  }
}
