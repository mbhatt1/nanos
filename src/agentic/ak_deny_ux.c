/*
 * Authority Kernel - Deny UX Implementation
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Owner: Agent C
 *
 * This file implements the user experience layer for denied operations.
 * Key features:
 *   - AK_SYS_LAST_ERROR syscall handler
 *   - Rate-limited denial logging
 *   - Errno mapping
 *   - Policy suggestion generation
 *   - Trace ring buffer
 *   - Record mode for suggestion export
 */

#include "ak_deny_ux.h"
#include "ak_compat.h"
#include "ak_record.h"

/* ============================================================
 * MODULE STATE
 * ============================================================ */

/* Heap for allocations */
static heap deny_ux_heap = NULL;

/* Rate limiting state */
typedef struct {
    u64 window_start_ns;
    u32 count_by_category[16];
    u32 total_count;
    u64 suppressed_count;
} deny_log_state_t;

static __thread deny_log_state_t log_state;

/* Trace ring buffer */
typedef struct {
    ak_trace_entry_t *entries;
    u32 capacity;
    u64 head;       /* Next write position */
    u64 tail;       /* Oldest valid position */
} trace_ring_t;

static trace_ring_t trace_ring;

/* Record mode state */
typedef struct {
    boolean enabled;
    u32 count;
    u32 capacity;
    /* Simplified: just track unique targets per operation type */
    struct {
        ak_effect_op_t op;
        char target[AK_MAX_TARGET];
    } *denials;
} record_state_t;

static record_state_t record_state;

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

void ak_deny_ux_init(heap h)
{
    deny_ux_heap = h;

    /* Initialize logging */
    ak_deny_log_init();

    /* Initialize trace ring */
    ak_trace_ring_init(h);

    /* Initialize record mode (disabled by default) */
    ak_record_init(h);

    ak_debug("ak_deny_ux: initialized");
}

void ak_deny_ux_shutdown(void)
{
    /* Free trace ring */
    if (trace_ring.entries && deny_ux_heap) {
        deallocate(deny_ux_heap, trace_ring.entries,
                   trace_ring.capacity * sizeof(ak_trace_entry_t));
        trace_ring.entries = NULL;
    }

    /* Free record state */
    if (record_state.denials && deny_ux_heap) {
        deallocate(deny_ux_heap, record_state.denials,
                   record_state.capacity * sizeof(*record_state.denials));
        record_state.denials = NULL;
    }

    deny_ux_heap = NULL;
    ak_debug("ak_deny_ux: shutdown");
}

/* ============================================================
 * DENY LOGGING
 * ============================================================ */

void ak_deny_log_init(void)
{
    ak_memzero(&log_state, sizeof(log_state));
    log_state.window_start_ns = ak_now() * 1000;  /* Approximate ns */
}

void ak_deny_log_reset(void)
{
    u64 suppressed = log_state.suppressed_count;
    ak_memzero(&log_state, sizeof(log_state));
    log_state.window_start_ns = ak_now() * 1000;

    /* Log suppression summary if any */
    if (suppressed > 0) {
        rprintf("AK DENY: %llu entries suppressed due to rate limiting\n",
                suppressed);
    }
}

boolean ak_deny_log_entry(const ak_effect_req_t *req,
                          const ak_decision_t *decision)
{
    if (!req || !decision)
        return false;

    u64 now_ns = ak_now() * 1000;

    /* Check if window expired */
    if (now_ns - log_state.window_start_ns > AK_DENY_LOG_WINDOW_NS) {
        ak_deny_log_reset();
    }

    /* Check total rate limit */
    if (log_state.total_count >= AK_DENY_LOG_MAX_TOTAL) {
        log_state.suppressed_count++;
        return false;
    }

    /* Check per-category rate limit */
    u32 category = (req->op >> 8) & 0x0F;
    if (category >= 16)
        category = 15;

    if (log_state.count_by_category[category] >= AK_DENY_LOG_MAX_PER_CAT) {
        log_state.suppressed_count++;
        return false;
    }

    /* Update counters */
    log_state.count_by_category[category]++;
    log_state.total_count++;

    /* Log the denial */
    rprintf("AK DENY %s %s missing %s. Fix: %s (trace=%lx)\n",
            ak_effect_op_to_string(req->op),
            req->target,
            decision->missing_cap,
            decision->suggested_snippet,
            decision->trace_id);

    return true;
}

u64 ak_deny_log_get_suppressed(void)
{
    return log_state.suppressed_count;
}

/* ============================================================
 * ERRNO MAPPING
 * ============================================================ */

int ak_deny_to_errno(ak_effect_op_t op, ak_deny_reason_t reason)
{
    u32 category = (op >> 8) & 0xFF;

    switch (category) {
    case 0x01:  /* Filesystem */
        switch (reason) {
        case AK_DENY_NO_CAP:
        case AK_DENY_PATTERN_MISMATCH:
            return EACCES;
        case AK_DENY_NO_POLICY:
        case AK_DENY_REVOKED:
        case AK_DENY_MODE:
            return EPERM;
        case AK_DENY_BUDGET_EXCEEDED:
            return ENOSPC;
        case AK_DENY_RATE_LIMITED:
            return EAGAIN;
        default:
            return EACCES;
        }

    case 0x02:  /* Network */
        switch (reason) {
        case AK_DENY_NO_CAP:
        case AK_DENY_PATTERN_MISMATCH:
            return ECONNREFUSED;
        case AK_DENY_RATE_LIMITED:
            return EAGAIN;
        case AK_DENY_NO_POLICY:
        case AK_DENY_REVOKED:
            return ENETUNREACH;
        default:
            return ECONNREFUSED;
        }

    case 0x03:  /* Process */
        return EPERM;

    case 0x04:  /* Agentic (tools, wasm, inference) */
        switch (reason) {
        case AK_DENY_BUDGET_EXCEEDED:
            return ENOSPC;
        case AK_DENY_RATE_LIMITED:
            return EAGAIN;
        default:
            return EPERM;
        }

    default:
        return EPERM;
    }
}

/* ============================================================
 * OPERATION NAME STRINGS
 * ============================================================ */

const char *ak_effect_op_to_string(ak_effect_op_t op)
{
    switch (op) {
    case AK_E_FS_OPEN:         return "FS_OPEN";
    case AK_E_FS_UNLINK:       return "FS_UNLINK";
    case AK_E_FS_RENAME:       return "FS_RENAME";
    case AK_E_FS_MKDIR:        return "FS_MKDIR";
    case AK_E_FS_RMDIR:        return "FS_RMDIR";
    case AK_E_FS_STAT:         return "FS_STAT";
    case AK_E_NET_CONNECT:     return "NET_CONNECT";
    case AK_E_NET_DNS_RESOLVE: return "NET_DNS_RESOLVE";
    case AK_E_NET_BIND:        return "NET_BIND";
    case AK_E_NET_LISTEN:      return "NET_LISTEN";
    case AK_E_NET_ACCEPT:      return "NET_ACCEPT";
    case AK_E_PROC_SPAWN:      return "PROC_SPAWN";
    case AK_E_PROC_SIGNAL:     return "PROC_SIGNAL";
    case AK_E_PROC_WAIT:       return "PROC_WAIT";
    case AK_E_TOOL_CALL:       return "TOOL_CALL";
    case AK_E_WASM_INVOKE:     return "WASM_INVOKE";
    case AK_E_INFER:           return "INFER";
    default:                   return "UNKNOWN";
    }
}

const char *ak_deny_reason_to_string(ak_deny_reason_t reason)
{
    switch (reason) {
    case AK_DENY_NONE:            return "NONE";
    case AK_DENY_NO_POLICY:       return "NO_POLICY";
    case AK_DENY_NO_CAP:          return "NO_CAP";
    case AK_DENY_CAP_EXPIRED:     return "CAP_EXPIRED";
    case AK_DENY_PATTERN_MISMATCH: return "PATTERN_MISMATCH";
    case AK_DENY_BUDGET_EXCEEDED: return "BUDGET_EXCEEDED";
    case AK_DENY_RATE_LIMITED:    return "RATE_LIMITED";
    case AK_DENY_TAINT:           return "TAINT";
    case AK_DENY_REVOKED:         return "REVOKED";
    case AK_DENY_MODE:            return "MODE";
    case AK_DENY_BOOT_CAPSULE:    return "BOOT_CAPSULE";
    default:                      return "UNKNOWN";
    }
}

/* ============================================================
 * JSON SERIALIZATION HELPERS
 * ============================================================ */

/* Write a JSON string value, escaping as needed */
static int json_write_string(char *buf, u32 buf_len, const char *str)
{
    if (!buf || buf_len < 3)
        return 0;

    int pos = 0;
    buf[pos++] = '"';

    if (str) {
        while (*str && pos < (int)buf_len - 2) {
            char c = *str++;
            switch (c) {
            case '"':
                if (pos + 2 < (int)buf_len) {
                    buf[pos++] = '\\';
                    buf[pos++] = '"';
                }
                break;
            case '\\':
                if (pos + 2 < (int)buf_len) {
                    buf[pos++] = '\\';
                    buf[pos++] = '\\';
                }
                break;
            case '\n':
                if (pos + 2 < (int)buf_len) {
                    buf[pos++] = '\\';
                    buf[pos++] = 'n';
                }
                break;
            case '\r':
                if (pos + 2 < (int)buf_len) {
                    buf[pos++] = '\\';
                    buf[pos++] = 'r';
                }
                break;
            case '\t':
                if (pos + 2 < (int)buf_len) {
                    buf[pos++] = '\\';
                    buf[pos++] = 't';
                }
                break;
            default:
                if (c >= 32 && c < 127) {
                    buf[pos++] = c;
                }
                /* Skip other control characters */
                break;
            }
        }
    }

    buf[pos++] = '"';
    return pos;
}

/* Write a JSON integer value */
static int json_write_int(char *buf, u32 buf_len, s64 val)
{
    if (!buf || buf_len < 2)
        return 0;

    char tmp[24];
    int tmp_len = 0;
    boolean negative = false;

    if (val < 0) {
        negative = true;
        val = -val;
    }

    if (val == 0) {
        tmp[tmp_len++] = '0';
    } else {
        while (val > 0 && tmp_len < 20) {
            tmp[tmp_len++] = '0' + (val % 10);
            val /= 10;
        }
    }

    int pos = 0;
    if (negative && pos < (int)buf_len)
        buf[pos++] = '-';

    /* Reverse the digits */
    for (int i = tmp_len - 1; i >= 0 && pos < (int)buf_len; i--) {
        buf[pos++] = tmp[i];
    }

    return pos;
}

/* Write a JSON hex string (for trace_id) */
static int json_write_hex(char *buf, u32 buf_len, u64 val)
{
    if (!buf || buf_len < 18)
        return 0;

    static const char hex[] = "0123456789abcdef";
    int pos = 0;

    buf[pos++] = '"';
    for (int i = 15; i >= 0 && pos < (int)buf_len - 1; i--) {
        buf[pos++] = hex[(val >> (i * 4)) & 0xF];
    }
    buf[pos++] = '"';

    return pos;
}

/* ============================================================
 * AK_SYS_LAST_ERROR SYSCALL
 * ============================================================ */

sysreturn ak_sys_last_error(u8 *buf, u64 buf_len)
{
    if (!buf || buf_len < 64)
        return -EINVAL;

    ak_ctx_t *ctx = ak_ctx_current();
    if (!ctx)
        return -EPERM;

    const ak_last_deny_t *last = ak_get_last_deny(ctx);
    if (!last || last->timestamp_ns == 0)
        return -ENOENT;

    /* Build JSON response */
    /* FIX(BUG-022): Guard against integer underflow in remaining calculation */
    char *out = (char *)buf;
    int pos = 0;
    int remaining = (int)(buf_len - 1);

    /* Early exit if buffer too small */
    if (remaining <= 0 || pos >= (int)buf_len - 1) {
        out[0] = '\0';
        return 0;
    }

    /* Start object */
    out[pos++] = '{';
    remaining--;

    /* "op": "OP_NAME" */
    if (remaining > 10 && pos < (int)buf_len - 1) {
        runtime_memcpy(out + pos, "\"op\":", 5);
        pos += 5;
        remaining -= 5;
        pos += json_write_string(out + pos, remaining,
                                 ak_effect_op_to_string(last->op));
        remaining = (int)buf_len - 1 - pos;
        if (remaining < 0) remaining = 0;
    }

    /* ,"target": "..." */
    if (remaining > 15 && pos < (int)buf_len - 1) {
        runtime_memcpy(out + pos, ",\"target\":", 10);
        pos += 10;
        remaining -= 10;
        pos += json_write_string(out + pos, remaining, last->target);
        remaining = (int)buf_len - 1 - pos;
        if (remaining < 0) remaining = 0;
    }

    /* ,"reason": "..." */
    if (remaining > 15 && pos < (int)buf_len - 1) {
        runtime_memcpy(out + pos, ",\"reason\":", 10);
        pos += 10;
        remaining -= 10;
        pos += json_write_string(out + pos, remaining,
                                 ak_deny_reason_to_string(last->reason));
        remaining = (int)buf_len - 1 - pos;
        if (remaining < 0) remaining = 0;
    }

    /* ,"reason_code": N */
    if (remaining > 18 && pos < (int)buf_len - 1) {
        runtime_memcpy(out + pos, ",\"reason_code\":", 15);
        pos += 15;
        remaining -= 15;
        pos += json_write_int(out + pos, remaining, last->reason);
        remaining = (int)buf_len - 1 - pos;
        if (remaining < 0) remaining = 0;
    }

    /* ,"errno": N */
    if (remaining > 12 && pos < (int)buf_len - 1) {
        runtime_memcpy(out + pos, ",\"errno\":", 9);
        pos += 9;
        remaining -= 9;
        pos += json_write_int(out + pos, remaining, last->errno_equiv);
        remaining = (int)buf_len - 1 - pos;
        if (remaining < 0) remaining = 0;
    }

    /* ,"missing_cap": "..." */
    if (remaining > 20 && pos < (int)buf_len - 1) {
        runtime_memcpy(out + pos, ",\"missing_cap\":", 15);
        pos += 15;
        remaining -= 15;
        pos += json_write_string(out + pos, remaining, last->missing_cap);
        remaining = (int)buf_len - 1 - pos;
        if (remaining < 0) remaining = 0;
    }

    /* ,"suggested_snippet": "..." */
    if (remaining > 25 && pos < (int)buf_len - 1) {
        runtime_memcpy(out + pos, ",\"suggested_snippet\":", 21);
        pos += 21;
        remaining -= 21;
        pos += json_write_string(out + pos, remaining, last->suggested_snippet);
        remaining = (int)buf_len - 1 - pos;
        if (remaining < 0) remaining = 0;
    }

    /* ,"trace_id": "hex" */
    if (remaining > 25 && pos < (int)buf_len - 1) {
        runtime_memcpy(out + pos, ",\"trace_id\":", 12);
        pos += 12;
        remaining -= 12;
        pos += json_write_hex(out + pos, remaining, last->trace_id);
        remaining = (int)buf_len - 1 - pos;
        if (remaining < 0) remaining = 0;
    }

    /* ,"timestamp_ns": N */
    if (remaining > 20 && pos < (int)buf_len - 1) {
        runtime_memcpy(out + pos, ",\"timestamp_ns\":", 16);
        pos += 16;
        remaining -= 16;
        pos += json_write_int(out + pos, remaining, last->timestamp_ns);
        remaining = (int)buf_len - 1 - pos;
        if (remaining < 0) remaining = 0;
    }

    /* Close object */
    if (remaining > 0 && pos < (int)buf_len - 1) {
        out[pos++] = '}';
    }

    out[pos] = '\0';

    return pos;
}

/* ============================================================
 * AK_SYS_SET_MODE SYSCALL
 * ============================================================ */

sysreturn ak_sys_set_mode(u64 mode)
{
    ak_ctx_t *ctx = ak_ctx_current();
    if (!ctx)
        return -EPERM;

    if (mode > AK_MODE_RECORD)
        return -EINVAL;

    /* Security: Don't allow downgrading from HARD to SOFT/OFF
     * unless explicitly permitted by policy */
    if (ctx->mode == AK_MODE_HARD && mode < AK_MODE_HARD) {
        /* Check if policy allows mode downgrade */
        /* For now, deny all downgrades from HARD mode */
        return -EPERM;
    }

    /* Handle special case of switching to RECORD mode */
    if (mode == AK_MODE_RECORD) {
        /* Initialize record state if needed */
        heap h = NULL;
        if (ctx->agent && ctx->agent->heap) {
            h = ctx->agent->heap;
        } else if (deny_ux_heap) {
            h = deny_ux_heap;
        } else {
            return -ENOMEM;
        }
        return ak_ctx_enable_record_mode(ctx, h);
    }

    /* Handle switching out of RECORD mode */
    if (ctx->mode == AK_MODE_RECORD && mode != AK_MODE_RECORD) {
        ak_ctx_disable_record_mode(ctx);
        /* Continue to set the new mode below */
    }

    ak_ctx_set_mode(ctx, (ak_mode_t)mode);
    return 0;
}

/* ============================================================
 * TRACE RING BUFFER
 * ============================================================ */

void ak_trace_ring_init(heap h)
{
    trace_ring.capacity = AK_TRACE_RING_SIZE;
    trace_ring.entries = allocate_zero(h,
                                       trace_ring.capacity * sizeof(ak_trace_entry_t));
    if (ak_is_invalid_address(trace_ring.entries)) {
        trace_ring.entries = NULL;
        trace_ring.capacity = 0;
    }
    trace_ring.head = 0;
    trace_ring.tail = 0;
}

void ak_trace_ring_push(const ak_effect_req_t *req,
                        const ak_decision_t *decision)
{
    if (!trace_ring.entries || !req || !decision)
        return;

    u32 idx = trace_ring.head % trace_ring.capacity;
    ak_trace_entry_t *entry = &trace_ring.entries[idx];

    entry->timestamp_ns = ak_now() * 1000;
    entry->trace_id = req->trace_id;
    entry->op = req->op;
    entry->allowed = decision->allow;
    entry->reason = decision->reason_code;

    /* FIX(BUG-003): Clamp target_len to sizeof(entry->target)-1 to prevent buffer overflow */
    u64 target_len = runtime_strlen(req->target);
    if (target_len >= sizeof(entry->target)) {
        target_len = sizeof(entry->target) - 1;
    }
    /* Additional safety: ensure target_len won't cause buffer overflow */
    if (target_len > AK_MAX_TARGET - 1) {
        target_len = AK_MAX_TARGET - 1;
    }
    runtime_memcpy(entry->target, req->target, target_len);
    entry->target[target_len] = '\0';

    runtime_strncpy(entry->missing_cap, decision->missing_cap, AK_MAX_CAPSTR);

    trace_ring.head++;

    /* Advance tail if buffer is full */
    if (trace_ring.head - trace_ring.tail > trace_ring.capacity) {
        trace_ring.tail = trace_ring.head - trace_ring.capacity;
    }
}

u32 ak_trace_ring_read(ak_trace_entry_t *entries, u32 max_entries,
                       u64 *offset)
{
    if (!trace_ring.entries || !entries || max_entries == 0)
        return 0;

    u64 start = offset ? *offset : trace_ring.tail;

    /* Clamp to valid range */
    if (start < trace_ring.tail)
        start = trace_ring.tail;
    if (start >= trace_ring.head)
        return 0;

    u32 count = 0;
    while (start < trace_ring.head && count < max_entries) {
        u32 idx = start % trace_ring.capacity;
        runtime_memcpy(&entries[count], &trace_ring.entries[idx],
                       sizeof(ak_trace_entry_t));
        count++;
        start++;
    }

    if (offset)
        *offset = start;

    return count;
}

sysreturn ak_sys_trace_ring_read(u8 *buf, u64 buf_len, u64 *offset)
{
    if (!buf || buf_len < sizeof(ak_trace_entry_t))
        return -EINVAL;

    u32 max_entries = buf_len / sizeof(ak_trace_entry_t);
    u64 local_offset = offset ? *offset : 0;

    u32 count = ak_trace_ring_read((ak_trace_entry_t *)buf, max_entries,
                                   &local_offset);

    if (offset)
        *offset = local_offset;

    if (count == 0)
        return -EAGAIN;

    return count * sizeof(ak_trace_entry_t);
}

/* ============================================================
 * RECORD MODE
 * ============================================================ */

#define RECORD_MAX_DENIALS 1024

void ak_record_init(heap h)
{
    record_state.enabled = false;
    record_state.count = 0;
    record_state.capacity = RECORD_MAX_DENIALS;

    record_state.denials = allocate_zero(h,
                                         record_state.capacity * sizeof(*record_state.denials));
    if (ak_is_invalid_address(record_state.denials)) {
        record_state.denials = NULL;
        record_state.capacity = 0;
    }
}

void ak_record_deny(const ak_effect_req_t *req,
                    const ak_decision_t *decision)
{
    (void)decision;  /* Currently unused */

    if (!record_state.denials || !req)
        return;

    if (record_state.count >= record_state.capacity)
        return;

    /* Check for duplicates (same op + target) */
    for (u32 i = 0; i < record_state.count; i++) {
        if (record_state.denials[i].op == req->op &&
            ak_strcmp(record_state.denials[i].target, req->target) == 0) {
            return;  /* Already recorded */
        }
    }

    /* Add new entry */
    u32 idx = record_state.count++;
    record_state.denials[idx].op = req->op;
    runtime_strncpy(record_state.denials[idx].target, req->target, AK_MAX_TARGET);
}

void ak_record_clear(void)
{
    record_state.count = 0;
    if (record_state.denials) {
        ak_memzero(record_state.denials,
                   record_state.capacity * sizeof(*record_state.denials));
    }
}

u32 ak_record_count(void)
{
    return record_state.count;
}

u64 ak_record_export(char *buf, u64 buf_len)
{
    if (!buf || buf_len < 64 || !record_state.denials)
        return 0;

    u64 pos = 0;

    /* Header */
    const char *header = "# Auto-generated policy suggestions\n"
                         "# Review carefully before using!\n\n";
    u64 header_len = runtime_strlen(header);
    if (pos + header_len < buf_len) {
        runtime_memcpy(buf + pos, header, header_len);
        pos += header_len;
    }

    /* Group by operation type and generate suggestions */
    for (u32 i = 0; i < record_state.count && pos < buf_len - 128; i++) {
        ak_effect_req_t fake_req;
        ak_memzero(&fake_req, sizeof(fake_req));
        fake_req.op = record_state.denials[i].op;
        runtime_strncpy(fake_req.target, record_state.denials[i].target,
                        AK_MAX_TARGET);

        char suggestion[AK_MAX_SUGGEST];
        ak_generate_suggestion(&fake_req, suggestion, sizeof(suggestion));

        u64 suggest_len = runtime_strlen(suggestion);
        if (pos + suggest_len + 2 < buf_len) {
            runtime_memcpy(buf + pos, suggestion, suggest_len);
            pos += suggest_len;
            buf[pos++] = '\n';
            buf[pos++] = '\n';
        }
    }

    buf[pos] = '\0';
    return pos;
}

sysreturn ak_sys_policy_suggest(u8 *buf, u64 buf_len)
{
    if (!buf || buf_len < 64)
        return -EINVAL;

    if (!record_state.denials || record_state.count == 0)
        return -ENOENT;

    return ak_record_export((char *)buf, buf_len);
}

/* ============================================================
 * SUGGESTION GENERATION (BY TYPE)
 * ============================================================ */

int ak_suggest_for_fs(const ak_effect_req_t *req, char *buf, u32 buf_len)
{
    if (!req || !buf || buf_len < 64)
        return 0;

    int pos = 0;
    const char *path = req->target;

    /* Determine if read or write based on operation */
    boolean is_write = (req->op == AK_E_FS_UNLINK ||
                       req->op == AK_E_FS_RENAME ||
                       req->op == AK_E_FS_MKDIR ||
                       req->op == AK_E_FS_RMDIR);

    /* Check flags for FS_OPEN - look for write flags in params */
    if (req->op == AK_E_FS_OPEN && req->params_len > 0) {
        /* Simple check: if params contain "f": with value >= 1, assume write */
        /* This is a simplification - full implementation would parse JSON */
    }

    pos += runtime_strncpy(buf + pos, "[[fs.allow]]\n", buf_len - pos) ? 13 : 0;
    pos += runtime_strncpy(buf + pos, "path = \"", buf_len - pos) ? 8 : 0;

    u64 path_len = runtime_strlen(path);
    if (pos + path_len + 20 < buf_len) {
        runtime_memcpy(buf + pos, path, path_len);
        pos += path_len;
    }

    buf[pos++] = '"';
    buf[pos++] = '\n';

    if (is_write) {
        pos += runtime_strncpy(buf + pos, "write = true", buf_len - pos) ? 12 : 0;
    } else {
        pos += runtime_strncpy(buf + pos, "read = true", buf_len - pos) ? 11 : 0;
    }

    buf[pos] = '\0';
    return pos;
}

int ak_suggest_for_net(const ak_effect_req_t *req, char *buf, u32 buf_len)
{
    if (!req || !buf || buf_len < 64)
        return 0;

    int pos = 0;

    if (req->op == AK_E_NET_DNS_RESOLVE) {
        /* DNS suggestion */
        pos += runtime_strncpy(buf + pos, "[[dns.allow]]\n", buf_len - pos) ? 14 : 0;
        pos += runtime_strncpy(buf + pos, "pattern = \"", buf_len - pos) ? 11 : 0;

        /* Extract hostname from dns:hostname */
        const char *host = req->target;
        if (runtime_strncmp(host, "dns:", 4) == 0)
            host += 4;

        u64 host_len = runtime_strlen(host);
        if (pos + host_len + 2 < buf_len) {
            runtime_memcpy(buf + pos, host, host_len);
            pos += host_len;
        }

        buf[pos++] = '"';
        buf[pos] = '\0';
    } else {
        /* Network connection suggestion */
        pos += runtime_strncpy(buf + pos, "[[net.allow]]\n", buf_len - pos) ? 14 : 0;
        pos += runtime_strncpy(buf + pos, "pattern = \"", buf_len - pos) ? 11 : 0;

        u64 target_len = runtime_strlen(req->target);
        if (pos + target_len + 20 < buf_len) {
            runtime_memcpy(buf + pos, req->target, target_len);
            pos += target_len;
        }

        buf[pos++] = '"';
        buf[pos++] = '\n';

        switch (req->op) {
        case AK_E_NET_CONNECT:
            pos += runtime_strncpy(buf + pos, "connect = true", buf_len - pos) ? 14 : 0;
            break;
        case AK_E_NET_BIND:
            pos += runtime_strncpy(buf + pos, "bind = true", buf_len - pos) ? 11 : 0;
            break;
        case AK_E_NET_LISTEN:
            pos += runtime_strncpy(buf + pos, "listen = true", buf_len - pos) ? 13 : 0;
            break;
        default:
            break;
        }

        buf[pos] = '\0';
    }

    return pos;
}

int ak_suggest_for_tool(const ak_effect_req_t *req, char *buf, u32 buf_len)
{
    if (!req || !buf || buf_len < 64)
        return 0;

    int pos = 0;

    pos += runtime_strncpy(buf + pos, "[[tools.allow]]\n", buf_len - pos) ? 16 : 0;
    pos += runtime_strncpy(buf + pos, "name = \"", buf_len - pos) ? 8 : 0;

    /* Extract tool name from tool:<name>:<version> */
    const char *name = req->target;
    if (runtime_strncmp(name, "tool:", 5) == 0)
        name += 5;

    /* Find end of name (before :version) */
    u64 name_len = 0;
    while (name[name_len] && name[name_len] != ':')
        name_len++;

    if (pos + name_len + 2 < buf_len) {
        runtime_memcpy(buf + pos, name, name_len);
        pos += name_len;
    }

    buf[pos++] = '"';
    buf[pos] = '\0';

    return pos;
}

int ak_suggest_for_infer(const ak_effect_req_t *req, char *buf, u32 buf_len)
{
    if (!req || !buf || buf_len < 64)
        return 0;

    int pos = 0;

    pos += runtime_strncpy(buf + pos, "[[inference.allow]]\n", buf_len - pos) ? 20 : 0;
    pos += runtime_strncpy(buf + pos, "model = \"", buf_len - pos) ? 9 : 0;

    /* Extract model name from model:<name>:<version> */
    const char *model = req->target;
    if (runtime_strncmp(model, "model:", 6) == 0)
        model += 6;

    /* Find end of model name (before :version) */
    u64 model_len = 0;
    while (model[model_len] && model[model_len] != ':')
        model_len++;

    if (pos + model_len + 2 < buf_len) {
        runtime_memcpy(buf + pos, model, model_len);
        pos += model_len;
    }

    buf[pos++] = '"';
    buf[pos] = '\0';

    return pos;
}

/* ============================================================
 * AK_SYS_GET_SUGGESTIONS SYSCALL
 * ============================================================
 * Retrieves accumulated policy suggestions from record mode.
 *
 * When the AK context is in AK_MODE_RECORD, denied effects are
 * recorded but allowed to proceed. This syscall retrieves the
 * complete policy document that would allow all recorded effects.
 *
 * Parameters:
 *   buf     - Output buffer for JSON policy document
 *   buf_len - Size of output buffer
 *   format  - Output format: 0 = JSON, 1 = TOML
 *
 * Returns:
 *   >= 0    - Number of bytes written (excluding null terminator)
 *   -EINVAL - Invalid parameters
 *   -EPERM  - No context or record mode not initialized
 *   -ENOENT - No effects recorded
 *   -ERANGE - Buffer too small
 */
sysreturn ak_sys_get_suggestions(u8 *buf, u64 buf_len, u64 format)
{
    if (!buf || buf_len < 64)
        return -EINVAL;

    ak_ctx_t *ctx = ak_ctx_current();
    if (!ctx)
        return -EPERM;

    ak_record_state_t *record = ak_ctx_get_record_state(ctx);
    if (!record)
        return -EPERM;

    u32 count = ak_record_count(record);
    if (count == 0)
        return -ENOENT;

    sysreturn result;

    if (format == 1) {
        /* TOML format */
        result = ak_record_get_suggestions_toml(record, (char *)buf, buf_len);
    } else {
        /* JSON format (default) */
        result = ak_record_get_suggestions(record, (char *)buf, buf_len);
    }

    return result;
}

/* ============================================================
 * AK_SYS_RECORD_CONTROL SYSCALL
 * ============================================================
 * Control record mode state.
 *
 * Parameters:
 *   cmd - Command to execute:
 *         0 = Enable recording (start AK_MODE_RECORD)
 *         1 = Disable recording (return to AK_MODE_SOFT)
 *         2 = Clear recorded effects
 *         3 = Get count of recorded effects
 *
 * Returns:
 *   >= 0    - Success (for cmd=3, returns count)
 *   -EINVAL - Invalid command
 *   -EPERM  - No context
 *   -ENOMEM - Allocation failed (for enable)
 */
sysreturn ak_sys_record_control(u64 cmd)
{
    ak_ctx_t *ctx = ak_ctx_current();
    if (!ctx)
        return -EPERM;

    switch (cmd) {
    case 0:  /* Enable recording */
        {
            heap h = NULL;
            if (ctx->agent && ctx->agent->heap) {
                h = ctx->agent->heap;
            } else if (deny_ux_heap) {
                h = deny_ux_heap;
            } else {
                return -ENOMEM;
            }
            return ak_ctx_enable_record_mode(ctx, h);
        }

    case 1:  /* Disable recording */
        ak_ctx_disable_record_mode(ctx);
        return 0;

    case 2:  /* Clear recorded effects */
        {
            ak_record_state_t *record = ak_ctx_get_record_state(ctx);
            if (record) {
                ak_record_clear(record);
            }
            return 0;
        }

    case 3:  /* Get count */
        {
            ak_record_state_t *record = ak_ctx_get_record_state(ctx);
            return record ? ak_record_count(record) : 0;
        }

    default:
        return -EINVAL;
    }
}
