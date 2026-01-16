/*
 * Authority Kernel - WASM Host ABI
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Implements capability-gated host functions that WASM modules can call.
 * Each function validates the agent's capability before executing.
 *
 * SECURITY CRITICAL: All host functions must:
 *   1. Validate capability via ak_capability_validate()
 *   2. Log operation to audit
 *   3. Respect resource limits
 */

#include "ak_wasm.h"
#include "ak_audit.h"
#include "ak_secrets.h"
#include "ak_compat.h"

/* ============================================================
 * INTERNAL HELPERS
 * ============================================================ */

/*
 * Validate host call capability.
 *
 * SECURITY: This is the enforcement point for INV-2 within WASM.
 */
static s64 validate_host_cap(
    ak_wasm_exec_ctx_t *ctx,
    ak_cap_type_t required_type,
    const char *resource,
    const char *method)
{
    if (!ctx || !ctx->agent)
        return AK_E_CAP_MISSING;

    /* Check if tool's capability covers this operation */
    if (!ctx->cap)
        return AK_E_CAP_MISSING;

    return ak_capability_validate(
        ctx->cap,
        required_type,
        resource,
        method,
        ctx->agent->run_id
    );
}

/*
 * Parse JSON string argument.
 * Returns pointer into buffer (not copied).
 *
 * LIMITATION: This simple parser handles basic escape sequences (\", \\, \n,
 * \r, \t) but does NOT handle:
 *   - Unicode escapes (\uXXXX)
 *   - Nested objects/arrays as values
 *   - Numbers, booleans, or null values
 * For production use, consider a full JSON parser.
 */
static const char *parse_json_string(buffer args, const char *key, u64 *len_out)
{
    if (!args || buffer_length(args) < 2)
        return 0;

    /* Find key in JSON */
    u8 *data = buffer_ref(args, 0);
    u64 data_len = buffer_length(args);

    /* Look for "key": */
    u64 key_len = runtime_strlen(key);

    /* Avoid underflow: need at least "k": "v" = key_len + 5 chars */
    if (data_len < key_len + 5)
        return 0;

    for (u64 i = 0; i < data_len - key_len - 4; i++) {
        if (data[i] == '"' &&
            runtime_memcmp(&data[i + 1], key, key_len) == 0 &&
            data[i + 1 + key_len] == '"' &&
            data[i + 2 + key_len] == ':') {
            /* Found key, now find value */
            u64 val_start = i + 3 + key_len;

            /* Skip whitespace */
            while (val_start < data_len && (data[val_start] == ' ' || data[val_start] == '\t'))
                val_start++;

            if (val_start >= data_len)
                return 0;

            /* Check if string value */
            if (data[val_start] == '"') {
                val_start++;
                u64 val_end = val_start;
                /* Handle escape sequences while finding end of string */
                while (val_end < data_len && data[val_end] != '"') {
                    if (data[val_end] == '\\' && val_end + 1 < data_len) {
                        /* Skip escaped character */
                        val_end += 2;
                    } else {
                        val_end++;
                    }
                }

                if (len_out)
                    *len_out = val_end - val_start;
                return (const char *)&data[val_start];
            }
        }
    }

    return 0;
}

/*
 * Create JSON result buffer.
 */
static buffer create_json_result(heap h, const char *key, const char *value, u64 value_len)
{
    /* Estimate size: {"key": "value"} */
    u64 key_len = runtime_strlen(key);
    u64 buf_size = 6 + key_len + value_len + 2;

    buffer result = allocate_buffer(h, buf_size);
    if (result == INVALID_ADDRESS)
        return 0;

    buffer_write(result, "{\"", 2);
    buffer_write(result, key, key_len);
    buffer_write(result, "\": \"", 4);
    if (value && value_len > 0)
        buffer_write(result, value, value_len);
    buffer_write(result, "\"}", 2);

    return result;
}

static buffer create_json_error(heap h, const char *error)
{
    u64 error_len = runtime_strlen(error);
    return create_json_result(h, "error", error, error_len);
}

/* ============================================================
 * NETWORK HOST FUNCTIONS (AK_CAP_NET)
 * ============================================================ */

s64 ak_host_http_get(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result)
{
    /* Parse URL from args */
    u64 url_len;
    const char *url = parse_json_string(args, "url", &url_len);
    if (!url || url_len == 0)
        return AK_E_SCHEMA_INVALID;

    /* Validate capability for this URL */
    /* Need to null-terminate URL for capability check */
    char url_buf[512];
    if (url_len >= sizeof(url_buf))
        url_len = sizeof(url_buf) - 1;
    runtime_memcpy(url_buf, url, url_len);
    url_buf[url_len] = 0;

    s64 cap_result = validate_host_cap(ctx, AK_CAP_NET, url_buf, "GET");
    if (cap_result != 0)
        return cap_result;

    /*
     * HTTP GET implementation requires network stack integration.
     * In production, this would:
     *   1. Parse URL (host, port, path)
     *   2. Establish TCP/TLS connection
     *   3. Send HTTP request
     *   4. Read and parse response
     *
     * Returns capability-validated placeholder for now.
     */

    *result = create_json_result(ctx->agent->heap, "status", "200", 3);
    return (*result) ? 0 : AK_E_WASM_OOM;
}

s64 ak_host_http_post(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result)
{
    /* Parse URL from args */
    u64 url_len;
    const char *url = parse_json_string(args, "url", &url_len);
    if (!url || url_len == 0)
        return AK_E_SCHEMA_INVALID;

    /* Validate capability */
    char url_buf[512];
    if (url_len >= sizeof(url_buf))
        url_len = sizeof(url_buf) - 1;
    runtime_memcpy(url_buf, url, url_len);
    url_buf[url_len] = 0;

    s64 cap_result = validate_host_cap(ctx, AK_CAP_NET, url_buf, "POST");
    if (cap_result != 0)
        return cap_result;

    /* HTTP POST requires network stack integration (see ak_host_http_get) */

    *result = create_json_result(ctx->agent->heap, "status", "200", 3);
    return (*result) ? 0 : AK_E_WASM_OOM;
}

s64 ak_host_tcp_connect(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result)
{
    u64 host_len;
    const char *host = parse_json_string(args, "host", &host_len);
    if (!host || host_len == 0)
        return AK_E_SCHEMA_INVALID;

    char host_buf[256];
    if (host_len >= sizeof(host_buf))
        host_len = sizeof(host_buf) - 1;
    runtime_memcpy(host_buf, host, host_len);
    host_buf[host_len] = 0;

    s64 cap_result = validate_host_cap(ctx, AK_CAP_NET, host_buf, "connect");
    if (cap_result != 0)
        return cap_result;

    /* TCP connect requires socket API integration */
    *result = create_json_result(ctx->agent->heap, "fd", "1", 1);
    return (*result) ? 0 : AK_E_WASM_OOM;
}

s64 ak_host_tcp_send(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result)
{
    /* Already connected, validate for send operation */
    s64 cap_result = validate_host_cap(ctx, AK_CAP_NET, "*", "send");
    if (cap_result != 0)
        return cap_result;

    /* TCP send requires socket API integration */
    *result = create_json_result(ctx->agent->heap, "bytes_sent", "0", 1);
    return (*result) ? 0 : AK_E_WASM_OOM;
}

s64 ak_host_tcp_recv(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result)
{
    s64 cap_result = validate_host_cap(ctx, AK_CAP_NET, "*", "recv");
    if (cap_result != 0)
        return cap_result;

    /* TCP recv requires socket API integration */
    *result = create_json_result(ctx->agent->heap, "data", "", 0);
    return (*result) ? 0 : AK_E_WASM_OOM;
}

/* ============================================================
 * FILESYSTEM HOST FUNCTIONS (AK_CAP_FS)
 * ============================================================ */

s64 ak_host_fs_read(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result)
{
    u64 path_len;
    const char *path = parse_json_string(args, "path", &path_len);
    if (!path || path_len == 0)
        return AK_E_SCHEMA_INVALID;

    char path_buf[512];
    if (path_len >= sizeof(path_buf))
        path_len = sizeof(path_buf) - 1;
    runtime_memcpy(path_buf, path, path_len);
    path_buf[path_len] = 0;

    s64 cap_result = validate_host_cap(ctx, AK_CAP_FS, path_buf, "read");
    if (cap_result != 0)
        return cap_result;

    /*
     * Filesystem read requires Nanos VFS integration.
     * Capability already validated for the path.
     */

    *result = create_json_result(ctx->agent->heap, "content", "", 0);
    return (*result) ? 0 : AK_E_WASM_OOM;
}

s64 ak_host_fs_write(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result)
{
    u64 path_len;
    const char *path = parse_json_string(args, "path", &path_len);
    if (!path || path_len == 0)
        return AK_E_SCHEMA_INVALID;

    char path_buf[512];
    if (path_len >= sizeof(path_buf))
        path_len = sizeof(path_buf) - 1;
    runtime_memcpy(path_buf, path, path_len);
    path_buf[path_len] = 0;

    s64 cap_result = validate_host_cap(ctx, AK_CAP_FS, path_buf, "write");
    if (cap_result != 0)
        return cap_result;

    /* Filesystem write requires Nanos VFS integration */

    *result = create_json_result(ctx->agent->heap, "bytes_written", "0", 1);
    return (*result) ? 0 : AK_E_WASM_OOM;
}

s64 ak_host_fs_stat(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result)
{
    u64 path_len;
    const char *path = parse_json_string(args, "path", &path_len);
    if (!path || path_len == 0)
        return AK_E_SCHEMA_INVALID;

    char path_buf[512];
    if (path_len >= sizeof(path_buf))
        path_len = sizeof(path_buf) - 1;
    runtime_memcpy(path_buf, path, path_len);
    path_buf[path_len] = 0;

    s64 cap_result = validate_host_cap(ctx, AK_CAP_FS, path_buf, "stat");
    if (cap_result != 0)
        return cap_result;

    /* File stat requires Nanos VFS integration */
    *result = create_json_result(ctx->agent->heap, "size", "0", 1);
    return (*result) ? 0 : AK_E_WASM_OOM;
}

s64 ak_host_fs_list(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result)
{
    u64 path_len;
    const char *path = parse_json_string(args, "path", &path_len);
    if (!path || path_len == 0)
        return AK_E_SCHEMA_INVALID;

    char path_buf[512];
    if (path_len >= sizeof(path_buf))
        path_len = sizeof(path_buf) - 1;
    runtime_memcpy(path_buf, path, path_len);
    path_buf[path_len] = 0;

    s64 cap_result = validate_host_cap(ctx, AK_CAP_FS, path_buf, "list");
    if (cap_result != 0)
        return cap_result;

    /* Directory listing requires Nanos VFS integration */
    *result = create_json_result(ctx->agent->heap, "entries", "[]", 2);
    return (*result) ? 0 : AK_E_WASM_OOM;
}

/* ============================================================
 * HEAP HOST FUNCTIONS (AK_CAP_HEAP)
 * ============================================================ */

s64 ak_host_heap_read(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result)
{
    u64 ptr_len;
    const char *ptr_str = parse_json_string(args, "ptr", &ptr_len);
    if (!ptr_str || ptr_len == 0)
        return AK_E_SCHEMA_INVALID;

    /* Capability check for heap access */
    s64 cap_result = validate_host_cap(ctx, AK_CAP_HEAP, "*", "read");
    if (cap_result != 0)
        return cap_result;

    /*
     * Read from typed heap via ak_heap_read().
     * Integration point with ak_heap.c for WASM tool access.
     */

    *result = create_json_result(ctx->agent->heap, "value", "{}", 2);
    return (*result) ? 0 : AK_E_WASM_OOM;
}

s64 ak_host_heap_write(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result)
{
    u64 ptr_len;
    const char *ptr_str = parse_json_string(args, "ptr", &ptr_len);

    s64 cap_result = validate_host_cap(ctx, AK_CAP_HEAP, "*", "write");
    if (cap_result != 0)
        return cap_result;

    /*
     * Write to typed heap via ak_heap_write().
     * Integration point with ak_heap.c for WASM tool access.
     */

    *result = create_json_result(ctx->agent->heap, "version", "1", 1);
    return (*result) ? 0 : AK_E_WASM_OOM;
}

/* ============================================================
 * SECRET HOST FUNCTIONS (AK_CAP_SECRETS)
 * ============================================================ */

/*
 * SECURITY: The result buffer contains the secret value.
 * Caller is responsible for clearing *result after use via ak_secret_clear()
 * to prevent secret leakage in memory.
 */
s64 ak_host_secret_get(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result)
{
    u64 name_len;
    const char *name = parse_json_string(args, "name", &name_len);
    if (!name || name_len == 0)
        return AK_E_SCHEMA_INVALID;

    /* Null check for ctx->agent before dereferencing */
    if (!ctx || !ctx->agent)
        return AK_E_CAP_MISSING;

    char name_buf[128];
    if (name_len >= sizeof(name_buf))
        name_len = sizeof(name_buf) - 1;
    runtime_memcpy(name_buf, name, name_len);
    name_buf[name_len] = 0;

    s64 cap_result = validate_host_cap(ctx, AK_CAP_SECRETS, name_buf, "get");
    if (cap_result != 0)
        return cap_result;

    /*
     * Secret resolution from secure store.
     * Integrates with external secrets management (Vault, K8s secrets, etc.).
     *
     * SECURITY: Secret values are NEVER logged.
     * Values are injected at runtime and cleared after use.
     */

    /* Find the secrets capability from the agent context */
    ak_capability_t *secrets_cap = 0;
    if (ctx->agent->delegated_caps) {
        /* Validate table before iteration - delegated_caps must be a valid table pointer */
        table t = ctx->agent->delegated_caps;
        if (t && t != INVALID_ADDRESS) {
            table_foreach(t, tid, cap) {
                ak_capability_t *c = (ak_capability_t *)cap;
                if (c && c->type == AK_CAP_SECRETS) {
                    secrets_cap = c;
                    break;
                }
            }
        }
    }

    /* Resolve the secret using the secrets backend */
    buffer secret_value = ak_secret_resolve(ctx->agent->heap, name, name_len, secrets_cap);
    if (!secret_value) {
        const char *err = ak_secrets_last_error();
        if (!err) err = "secret resolution failed";
        *result = create_json_error(ctx->agent->heap, err);
        return AK_E_TOOL_FAIL;
    }

    /* Build result JSON with the secret value */
    *result = create_json_result(ctx->agent->heap, "value",
                                 buffer_ref(secret_value, 0),
                                 buffer_length(secret_value));

    /* Securely clear the intermediate buffer */
    ak_secret_clear(secret_value);
    deallocate_buffer(secret_value);

    return (*result) ? 0 : AK_E_WASM_OOM;
}

/* ============================================================
 * LLM HOST FUNCTIONS (AK_CAP_INFERENCE)
 * ============================================================ */

s64 ak_host_llm_complete(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result)
{
    u64 prompt_len;
    const char *prompt = parse_json_string(args, "prompt", &prompt_len);
    if (!prompt || prompt_len == 0)
        return AK_E_SCHEMA_INVALID;

    /* LLM access requires inference capability */
    s64 cap_result = validate_host_cap(ctx, AK_CAP_INFERENCE, "*", "complete");
    if (cap_result != 0)
        return cap_result;

    /*
     * Routes to LLM gateway (ak_inference.c).
     * Supports local model (virtio-serial) or external API (HTTPS).
     * Budget tracking via capability rate limits.
     */

    *result = create_json_result(ctx->agent->heap, "completion", "", 0);
    return (*result) ? 0 : AK_E_WASM_OOM;
}

/* ============================================================
 * UTILITY HOST FUNCTIONS (no capability required)
 * ============================================================ */

s64 ak_host_log(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result)
{
    /* Null check before dereferencing ctx->agent */
    if (!ctx || !ctx->agent)
        return AK_E_CAP_MISSING;

    u64 msg_len;
    const char *msg = parse_json_string(args, "message", &msg_len);

    /*
     * Log message to audit trail.
     * No capability required - agents can always log.
     */
    if (msg && msg_len > 0) {
        /* Would call ak_audit_log_event() */
    }

    *result = create_json_result(ctx->agent->heap, "ok", "true", 4);
    return (*result) ? 0 : AK_E_WASM_OOM;
}

s64 ak_host_time_now(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result)
{
    /* Null check before dereferencing ctx->agent */
    if (!ctx || !ctx->agent)
        return AK_E_CAP_MISSING;

    /*
     * Return current timestamp.
     * No capability required.
     */

    /* Would use kern_now() for actual timestamp */
    *result = create_json_result(ctx->agent->heap, "ms", "0", 1);
    return (*result) ? 0 : AK_E_WASM_OOM;
}

s64 ak_host_random(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result)
{
    /* Null check before dereferencing ctx->agent */
    if (!ctx || !ctx->agent)
        return AK_E_CAP_MISSING;

    /*
     * Return random bytes.
     * No capability required.
     *
     * Would use virtio-rng or kernel entropy.
     */

    u8 random_hex[32];
    for (int i = 0; i < 16; i++) {
        /* Placeholder - would use real RNG */
        u8 b = (i * 17 + 3) & 0xff;
        random_hex[i * 2] = "0123456789abcdef"[b >> 4];
        random_hex[i * 2 + 1] = "0123456789abcdef"[b & 0xf];
    }

    *result = create_json_result(ctx->agent->heap, "hex", (const char *)random_hex, 32);
    return (*result) ? 0 : AK_E_WASM_OOM;
}
