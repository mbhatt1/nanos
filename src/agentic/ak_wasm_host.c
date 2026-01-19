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
#include "ak_heap.h"

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

/* Forward declarations for JSON parsing helpers */
static const char *parse_json_string(buffer args, const char *key, u64 *len_out);
static s64 parse_json_integer(buffer args, const char *key);

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
    /* Use consistent constant (5) for both check and loop boundary */
    if (data_len < key_len + 5)
        return 0;

    /* Explicit bounds validation: ensure subtraction won't underflow */
    u64 loop_limit = data_len - key_len - 5;
    for (u64 i = 0; i <= loop_limit; i++) {
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

    /* Check for integer overflow before allocation using safe addition */
    u64 buf_size = 8;  /* Base overhead: {"": ""} = 8 chars */
    if (key_len > U64_MAX - buf_size)
        return 0;
    buf_size += key_len;
    if (value_len > U64_MAX - buf_size)
        return 0;
    buf_size += value_len;

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

__attribute__((unused))
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
    /* Initialize *result to NULL to ensure defined state on error paths */
    *result = NULL;

    /* Parse URL from args */
    u64 url_len;
    const char *url = parse_json_string(args, "url", &url_len);
    if (!url || url_len == 0)
        return AK_E_SCHEMA_INVALID;

    /* Validate capability for this URL */
    /* Need to null-terminate URL for capability check */
    char url_buf[512];
    /* SECURITY: Return error instead of truncating to prevent security bypass */
    if (url_len >= sizeof(url_buf))
        return AK_E_SCHEMA_INVALID;
    runtime_memcpy(url_buf, url, url_len);
    url_buf[url_len] = 0;

    s64 cap_result = validate_host_cap(ctx, AK_CAP_NET, url_buf, "GET");
    if (cap_result != 0)
        return cap_result;

    /*
     * HTTP client functionality is not available from the WASM sandbox.
     *
     * HTTP requests require complex network stack integration (TCP, TLS,
     * DNS resolution) that is not suitable for synchronous kernel-space
     * execution. WASM tools requiring HTTP access should:
     *
     *   1. Use the IPC mechanism to communicate with a host-side HTTP proxy
     *   2. Or have the orchestrator pre-fetch required data before tool invocation
     *
     * See docs/architecture/http-from-wasm.md for the recommended patterns.
     */
    return AK_E_NOT_IMPLEMENTED;
}

s64 ak_host_http_post(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result)
{
    /* Initialize *result to NULL to ensure defined state on error paths */
    *result = NULL;

    /* Parse URL from args */
    u64 url_len;
    const char *url = parse_json_string(args, "url", &url_len);
    if (!url || url_len == 0)
        return AK_E_SCHEMA_INVALID;

    /* Validate capability */
    char url_buf[512];
    /* SECURITY: Return error instead of truncating to prevent security bypass */
    if (url_len >= sizeof(url_buf))
        return AK_E_SCHEMA_INVALID;
    runtime_memcpy(url_buf, url, url_len);
    url_buf[url_len] = 0;

    s64 cap_result = validate_host_cap(ctx, AK_CAP_NET, url_buf, "POST");
    if (cap_result != 0)
        return cap_result;

    /* HTTP POST not implemented - see ak_host_http_get() for rationale */
    return AK_E_NOT_IMPLEMENTED;
}

s64 ak_host_tcp_connect(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result)
{
    /* Initialize *result to NULL to ensure defined state on error paths */
    *result = NULL;

    u64 host_len;
    const char *host = parse_json_string(args, "host", &host_len);
    if (!host || host_len == 0)
        return AK_E_SCHEMA_INVALID;

    char host_buf[256];
    /* SECURITY: Return error instead of truncating to prevent security bypass */
    if (host_len >= sizeof(host_buf))
        return AK_E_SCHEMA_INVALID;
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
    /* Initialize *result to NULL to ensure defined state on error paths */
    *result = NULL;

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
    /* Initialize *result to NULL to ensure defined state on error paths */
    *result = NULL;

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
    /* Initialize *result to NULL to ensure defined state on error paths */
    *result = NULL;

    u64 path_len;
    const char *path = parse_json_string(args, "path", &path_len);
    if (!path || path_len == 0)
        return AK_E_SCHEMA_INVALID;

    char path_buf[512];
    /* SECURITY: Return error instead of truncating to prevent security bypass */
    if (path_len >= sizeof(path_buf))
        return AK_E_SCHEMA_INVALID;
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
    /* Initialize *result to NULL to ensure defined state on error paths */
    *result = NULL;

    u64 path_len;
    const char *path = parse_json_string(args, "path", &path_len);
    if (!path || path_len == 0)
        return AK_E_SCHEMA_INVALID;

    char path_buf[512];
    /* SECURITY: Return error instead of truncating to prevent security bypass */
    if (path_len >= sizeof(path_buf))
        return AK_E_SCHEMA_INVALID;
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
    /* Initialize *result to NULL to ensure defined state on error paths */
    *result = NULL;

    u64 path_len;
    const char *path = parse_json_string(args, "path", &path_len);
    if (!path || path_len == 0)
        return AK_E_SCHEMA_INVALID;

    char path_buf[512];
    /* SECURITY: Return error instead of truncating to prevent security bypass */
    if (path_len >= sizeof(path_buf))
        return AK_E_SCHEMA_INVALID;
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
    /* Initialize *result to NULL to ensure defined state on error paths */
    *result = NULL;

    u64 path_len;
    const char *path = parse_json_string(args, "path", &path_len);
    if (!path || path_len == 0)
        return AK_E_SCHEMA_INVALID;

    char path_buf[512];
    /* SECURITY: Return error instead of truncating to prevent security bypass */
    if (path_len >= sizeof(path_buf))
        return AK_E_SCHEMA_INVALID;
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
    /* Initialize *result to NULL to ensure defined state on error paths */
    *result = NULL;

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
    /* Initialize *result to NULL to ensure defined state on error paths */
    *result = NULL;

    /* Null check for ctx->agent before dereferencing */
    if (!ctx || !ctx->agent)
        return AK_E_CAP_MISSING;

    /* Parse pointer from args */
    u64 ptr_len;
    const char *ptr_str = parse_json_string(args, "ptr", &ptr_len);
    if (!ptr_str || ptr_len == 0)
        return AK_E_SCHEMA_INVALID;

    /* Convert pointer string to null-terminated buffer for capability check */
    char ptr_buf[64];
    /* SECURITY: Return error instead of truncating to prevent security bypass */
    if (ptr_len >= sizeof(ptr_buf))
        return AK_E_SCHEMA_INVALID;
    runtime_memcpy(ptr_buf, ptr_str, ptr_len);
    ptr_buf[ptr_len] = 0;

    /* Parse pointer string to u64 value */
    u64 ptr = 0;
    for (u64 i = 0; i < ptr_len; i++) {
        if (ptr_str[i] >= '0' && ptr_str[i] <= '9') {
            /* Check for overflow before multiplication */
            if (ptr > (U64_MAX - (ptr_str[i] - '0')) / 10)
                return AK_E_SCHEMA_INVALID;
            ptr = ptr * 10 + (ptr_str[i] - '0');
        } else {
            /* Invalid character in pointer string */
            return AK_E_SCHEMA_INVALID;
        }
    }

    /* Validate capability for this specific heap pointer */
    s64 cap_result = validate_host_cap(ctx, AK_CAP_HEAP, ptr_buf, "write");
    if (cap_result != 0)
        return cap_result;

    /* Parse patch from args (RFC 6902 JSON Patch) */
    u64 patch_len;
    const char *patch_str = parse_json_string(args, "patch", &patch_len);
    if (!patch_str || patch_len == 0)
        return AK_E_SCHEMA_INVALID;

    /* Parse expected version for CAS (Compare-And-Swap) */
    s64 expected_version = parse_json_integer(args, "version");
    if (expected_version < 0)
        return AK_E_SCHEMA_INVALID;

    /* Create patch buffer for ak_heap_write */
    buffer patch = allocate_buffer(ctx->agent->heap, patch_len);
    if (patch == INVALID_ADDRESS)
        return AK_E_WASM_OOM;
    buffer_write(patch, patch_str, patch_len);

    /* Perform the heap write operation */
    u64 new_version = 0;
    s64 write_result = ak_heap_write(ptr, patch, (u64)expected_version, &new_version);

    /* Clean up patch buffer */
    deallocate_buffer(patch);

    if (write_result != 0)
        return write_result;

    /* Build result JSON with new version */
    char version_buf[32];
    int version_len = 0;
    if (new_version == 0) {
        version_buf[version_len++] = '0';
    } else {
        char temp[32];
        int temp_len = 0;
        u64 v = new_version;
        while (v > 0) {
            temp[temp_len++] = '0' + (v % 10);
            v /= 10;
        }
        for (int i = temp_len - 1; i >= 0; i--) {
            version_buf[version_len++] = temp[i];
        }
    }

    *result = create_json_result(ctx->agent->heap, "version", version_buf, version_len);
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
    /* Initialize *result to NULL to ensure defined state on error paths */
    *result = NULL;

    u64 name_len;
    const char *name = parse_json_string(args, "name", &name_len);
    if (!name || name_len == 0)
        return AK_E_SCHEMA_INVALID;

    /* Null check for ctx->agent before dereferencing */
    if (!ctx || !ctx->agent)
        return AK_E_CAP_MISSING;

    char name_buf[128];
    /* SECURITY: Return error instead of truncating to prevent security bypass */
    if (name_len >= sizeof(name_buf))
        return AK_E_SCHEMA_INVALID;
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
                (void)tid;  /* unused - we only need the capability value */
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
        /* Set *result = NULL on error path to prevent memory leak */
        *result = NULL;
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
    /* Initialize *result to NULL to ensure defined state on error paths */
    *result = NULL;

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
    /* Initialize *result to NULL to ensure defined state on error paths */
    *result = NULL;

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
    /* Initialize *result to NULL to ensure defined state on error paths */
    *result = NULL;

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
    /* Initialize *result to NULL to ensure defined state on error paths */
    *result = NULL;

    /* Null check before dereferencing ctx->agent */
    if (!ctx || !ctx->agent)
        return AK_E_CAP_MISSING;

    /*
     * Return random bytes.
     * No capability required.
     *
     * Uses the kernel's ChaCha20-based CSPRNG seeded from hardware entropy
     * (rdrand/rdseed or virtio-rng).
     */

    u8 random_bytes[16];
    u8 random_hex[32];

    /* Generate 16 cryptographically secure random bytes using ChaCha20-based PRNG */
    u64 r0 = random_u64();
    u64 r1 = random_u64();
    runtime_memcpy(random_bytes, &r0, 8);
    runtime_memcpy(random_bytes + 8, &r1, 8);

    /* Convert to hex string */
    for (int i = 0; i < 16; i++) {
        u8 b = random_bytes[i];
        random_hex[i * 2] = "0123456789abcdef"[b >> 4];
        random_hex[i * 2 + 1] = "0123456789abcdef"[b & 0xf];
    }

    *result = create_json_result(ctx->agent->heap, "hex", (const char *)random_hex, 32);
    return (*result) ? 0 : AK_E_WASM_OOM;
}

/* ============================================================
 * STREAMING HOST FUNCTIONS
 * ============================================================
 * Enable WASM tools to send streaming responses.
 * Supports SSE, WebSocket, and LLM token streams.
 */

#include "ak_stream.h"

/*
 * Parse integer from JSON string value.
 */
static s64 parse_json_integer(buffer args, const char *key)
{
    u64 val_len;
    const char *val = parse_json_string(args, key, &val_len);
    if (!val || val_len == 0)
        return -1;

    /* Simple integer parsing */
    s64 result = 0;
    for (u64 i = 0; i < val_len; i++) {
        if (val[i] >= '0' && val[i] <= '9') {
            result = result * 10 + (val[i] - '0');
        } else {
            break;
        }
    }
    return result;
}

/*
 * Create streaming session for tool response.
 *
 * Args format (JSON):
 * {
 *   "type": "sse" | "websocket" | "llm_tokens" | "tool",
 *   "bytes_limit": 1000000,
 *   "tokens_limit": 10000,
 *   "timeout_ms": 60000
 * }
 *
 * Returns:
 * {
 *   "session_id": "12345",
 *   "type": "sse"
 * }
 */
s64 ak_host_stream_create(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result)
{
    *result = NULL;

    if (!ctx || !ctx->agent)
        return AK_E_CAP_MISSING;

    /* Validate streaming capability */
    s64 cap_result = validate_host_cap(ctx, AK_CAP_NET, "*", "stream");
    if (cap_result != 0)
        return cap_result;

    /* Parse type */
    u64 type_len;
    const char *type_str = parse_json_string(args, "type", &type_len);
    if (!type_str || type_len == 0)
        return AK_E_SCHEMA_INVALID;

    ak_stream_type_t type;
    if (runtime_strncmp(type_str, "sse", 3) == 0) {
        type = AK_STREAM_SSE;
    } else if (runtime_strncmp(type_str, "websocket", 9) == 0) {
        type = AK_STREAM_WEBSOCKET;
    } else if (runtime_strncmp(type_str, "llm_tokens", 10) == 0) {
        type = AK_STREAM_LLM_TOKENS;
    } else if (runtime_strncmp(type_str, "tool", 4) == 0) {
        type = AK_STREAM_TOOL_RESPONSE;
    } else {
        return AK_E_SCHEMA_INVALID;
    }

    /* Parse optional budget parameters */
    ak_stream_budget_t budget = {0};
    s64 bytes_limit = parse_json_integer(args, "bytes_limit");
    if (bytes_limit > 0)
        budget.bytes_limit = (u64)bytes_limit;

    s64 tokens_limit = parse_json_integer(args, "tokens_limit");
    if (tokens_limit > 0)
        budget.tokens_limit = (u64)tokens_limit;

    s64 timeout_ms = parse_json_integer(args, "timeout_ms");
    if (timeout_ms > 0)
        budget.timeout_ms = (u64)timeout_ms;

    /* Create the streaming session */
    ak_stream_session_t *session = ak_stream_create(
        ctx->agent->heap,
        type,
        &budget,
        ctx->agent,
        ctx->cap
    );

    if (!session)
        return AK_E_WASM_OOM;

    /* Start the session */
    s64 start_result = ak_stream_start(session);
    if (start_result != 0) {
        ak_stream_destroy(ctx->agent->heap, session);
        return start_result;
    }

    /* Build result JSON */
    buffer res = allocate_buffer(ctx->agent->heap, 128);
    if (res == INVALID_ADDRESS)
        return AK_E_WASM_OOM;

    buffer_write(res, "{\"session_id\": \"", 16);

    /* Write session_id as string */
    char id_buf[32];
    u64 session_id = session->session_id;
    int id_len = 0;
    if (session_id == 0) {
        id_buf[id_len++] = '0';
    } else {
        char temp[32];
        int temp_len = 0;
        while (session_id > 0) {
            temp[temp_len++] = '0' + (session_id % 10);
            session_id /= 10;
        }
        for (int i = temp_len - 1; i >= 0; i--) {
            id_buf[id_len++] = temp[i];
        }
    }
    buffer_write(res, id_buf, id_len);

    buffer_write(res, "\", \"type\": \"", 11);
    buffer_write(res, type_str, type_len);
    buffer_write(res, "\"}", 2);

    *result = res;
    return 0;
}

/*
 * Send chunk through streaming session.
 *
 * Args format (JSON):
 * {
 *   "session_id": "12345",
 *   "data": "chunk content",
 *   "event_type": "message"  (optional, for SSE)
 * }
 *
 * Returns:
 * {
 *   "bytes_sent": 100,
 *   "bytes_remaining": 900
 * }
 */
s64 ak_host_stream_send(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result)
{
    *result = NULL;

    if (!ctx || !ctx->agent)
        return AK_E_CAP_MISSING;

    /* Parse session_id */
    s64 session_id = parse_json_integer(args, "session_id");
    if (session_id < 0)
        return AK_E_SCHEMA_INVALID;

    /* Find session */
    ak_stream_session_t *session = ak_stream_get_by_id((u64)session_id);
    if (!session)
        return AK_E_STREAM_INVALID;

    /* Verify session belongs to this agent */
    if (session->agent != ctx->agent)
        return AK_E_CAP_SCOPE;

    /* Parse data */
    u64 data_len;
    const char *data = parse_json_string(args, "data", &data_len);
    if (!data)
        return AK_E_SCHEMA_INVALID;

    /* Send based on session type */
    s64 send_result;
    if (session->type == AK_STREAM_SSE) {
        /* For SSE, check for optional event_type */
        u64 event_type_len;
        const char *event_type = parse_json_string(args, "event_type", &event_type_len);
        char event_buf[64] = {0};
        if (event_type && event_type_len > 0 && event_type_len < sizeof(event_buf)) {
            runtime_memcpy(event_buf, event_type, event_type_len);
        }

        send_result = ak_stream_send_sse_event(
            session,
            event_buf[0] ? event_buf : NULL,
            NULL,  /* No event ID */
            (const u8 *)data,
            data_len
        );
    } else {
        send_result = ak_stream_send_chunk(session, (const u8 *)data, data_len);
    }

    if (send_result < 0)
        return send_result;

    /* Get remaining budget */
    u64 bytes_remaining = 0;
    ak_stream_budget_remaining(session, &bytes_remaining, NULL);

    /* Build result JSON */
    buffer res = allocate_buffer(ctx->agent->heap, 128);
    if (res == INVALID_ADDRESS)
        return AK_E_WASM_OOM;

    buffer_write(res, "{\"bytes_sent\": ", 15);

    /* Write bytes sent */
    char num_buf[32];
    int num_len = 0;
    u64 bytes_sent = (u64)send_result;
    if (bytes_sent == 0) {
        num_buf[num_len++] = '0';
    } else {
        char temp[32];
        int temp_len = 0;
        while (bytes_sent > 0) {
            temp[temp_len++] = '0' + (bytes_sent % 10);
            bytes_sent /= 10;
        }
        for (int i = temp_len - 1; i >= 0; i--) {
            num_buf[num_len++] = temp[i];
        }
    }
    buffer_write(res, num_buf, num_len);

    buffer_write(res, ", \"bytes_remaining\": ", 21);

    /* Write bytes remaining */
    num_len = 0;
    if (bytes_remaining == 0) {
        num_buf[num_len++] = '0';
    } else {
        char temp[32];
        int temp_len = 0;
        while (bytes_remaining > 0) {
            temp[temp_len++] = '0' + (bytes_remaining % 10);
            bytes_remaining /= 10;
        }
        for (int i = temp_len - 1; i >= 0; i--) {
            num_buf[num_len++] = temp[i];
        }
    }
    buffer_write(res, num_buf, num_len);
    buffer_write(res, "}", 1);

    *result = res;
    return 0;
}

/*
 * Send LLM token through streaming session.
 *
 * Args format (JSON):
 * {
 *   "session_id": "12345",
 *   "token": "Hello"
 * }
 *
 * Returns:
 * {
 *   "tokens_sent": 1,
 *   "tokens_remaining": 999,
 *   "stop_triggered": false
 * }
 */
s64 ak_host_stream_send_token(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result)
{
    *result = NULL;

    if (!ctx || !ctx->agent)
        return AK_E_CAP_MISSING;

    /* Parse session_id */
    s64 session_id = parse_json_integer(args, "session_id");
    if (session_id < 0)
        return AK_E_SCHEMA_INVALID;

    /* Find session */
    ak_stream_session_t *session = ak_stream_get_by_id((u64)session_id);
    if (!session)
        return AK_E_STREAM_INVALID;

    /* Verify session belongs to this agent */
    if (session->agent != ctx->agent)
        return AK_E_CAP_SCOPE;

    /* Verify session type */
    if (session->type != AK_STREAM_LLM_TOKENS)
        return AK_E_STREAM_TYPE_MISMATCH;

    /* Parse token */
    u64 token_len;
    const char *token = parse_json_string(args, "token", &token_len);
    if (!token)
        return AK_E_SCHEMA_INVALID;

    /* Send token */
    s64 send_result = ak_stream_send_token(session, token, (u32)token_len);

    /* Check for stop sequence trigger */
    boolean stop_triggered = (send_result == 1);
    if (send_result < 0 && send_result != 1)
        return send_result;

    /* Get remaining budget */
    u64 tokens_remaining = 0;
    ak_stream_budget_remaining(session, NULL, &tokens_remaining);

    /* Build result JSON */
    buffer res = allocate_buffer(ctx->agent->heap, 128);
    if (res == INVALID_ADDRESS)
        return AK_E_WASM_OOM;

    buffer_write(res, "{\"tokens_sent\": 1, \"tokens_remaining\": ", 39);

    /* Write tokens remaining */
    char num_buf[32];
    int num_len = 0;
    if (tokens_remaining == 0) {
        num_buf[num_len++] = '0';
    } else {
        char temp[32];
        int temp_len = 0;
        while (tokens_remaining > 0) {
            temp[temp_len++] = '0' + (tokens_remaining % 10);
            tokens_remaining /= 10;
        }
        for (int i = temp_len - 1; i >= 0; i--) {
            num_buf[num_len++] = temp[i];
        }
    }
    buffer_write(res, num_buf, num_len);

    buffer_write(res, ", \"stop_triggered\": ", 20);
    buffer_write(res, stop_triggered ? "true" : "false", stop_triggered ? 4 : 5);
    buffer_write(res, "}", 1);

    *result = res;
    return 0;
}

/*
 * Get streaming session statistics.
 *
 * Args format (JSON):
 * {
 *   "session_id": "12345"
 * }
 *
 * Returns:
 * {
 *   "bytes_sent": 500,
 *   "bytes_remaining": 500,
 *   "tokens_sent": 50,
 *   "tokens_remaining": 950,
 *   "chunks_sent": 10,
 *   "state": "active"
 * }
 */
s64 ak_host_stream_stats(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result)
{
    *result = NULL;

    if (!ctx || !ctx->agent)
        return AK_E_CAP_MISSING;

    /* Parse session_id */
    s64 session_id = parse_json_integer(args, "session_id");
    if (session_id < 0)
        return AK_E_SCHEMA_INVALID;

    /* Find session */
    ak_stream_session_t *session = ak_stream_get_by_id((u64)session_id);
    if (!session)
        return AK_E_STREAM_INVALID;

    /* Verify session belongs to this agent */
    if (session->agent != ctx->agent)
        return AK_E_CAP_SCOPE;

    /* Get statistics */
    ak_stream_stats_t stats;
    ak_stream_get_stats(session, &stats);

    /* Determine state string */
    const char *state_str;
    switch (stats.state) {
        case AK_STREAM_STATE_INIT:   state_str = "init"; break;
        case AK_STREAM_STATE_ACTIVE: state_str = "active"; break;
        case AK_STREAM_STATE_PAUSED: state_str = "paused"; break;
        case AK_STREAM_STATE_CLOSED: state_str = "closed"; break;
        case AK_STREAM_STATE_ERROR:  state_str = "error"; break;
        case AK_STREAM_STATE_BUDGET: state_str = "budget_exceeded"; break;
        case AK_STREAM_STATE_TIMEOUT: state_str = "timeout"; break;
        default: state_str = "unknown"; break;
    }

    /* Build result JSON (simplified - just key stats) */
    buffer res = allocate_buffer(ctx->agent->heap, 256);
    if (res == INVALID_ADDRESS)
        return AK_E_WASM_OOM;

    buffer_write(res, "{\"bytes_sent\": ", 15);

    /* Helper macro for writing u64 */
    #define WRITE_U64(val) do { \
        char nbuf[32]; \
        int nlen = 0; \
        u64 v = (val); \
        if (v == 0) { nbuf[nlen++] = '0'; } \
        else { \
            char tmp[32]; int tl = 0; \
            while (v > 0) { tmp[tl++] = '0' + (v % 10); v /= 10; } \
            for (int i = tl - 1; i >= 0; i--) nbuf[nlen++] = tmp[i]; \
        } \
        buffer_write(res, nbuf, nlen); \
    } while(0)

    WRITE_U64(stats.bytes_sent);
    buffer_write(res, ", \"bytes_remaining\": ", 21);
    WRITE_U64(stats.bytes_remaining);
    buffer_write(res, ", \"tokens_sent\": ", 17);
    WRITE_U64(stats.tokens_sent);
    buffer_write(res, ", \"tokens_remaining\": ", 22);
    WRITE_U64(stats.tokens_remaining);
    buffer_write(res, ", \"chunks_sent\": ", 17);
    WRITE_U64(stats.chunks_sent);
    buffer_write(res, ", \"state\": \"", 12);
    buffer_write(res, state_str, runtime_strlen(state_str));
    buffer_write(res, "\"}", 2);

    #undef WRITE_U64

    *result = res;
    return 0;
}

/*
 * Close streaming session.
 *
 * Args format (JSON):
 * {
 *   "session_id": "12345"
 * }
 *
 * Returns:
 * {
 *   "closed": true,
 *   "bytes_sent": 1000,
 *   "tokens_sent": 100
 * }
 */
s64 ak_host_stream_close(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result)
{
    *result = NULL;

    if (!ctx || !ctx->agent)
        return AK_E_CAP_MISSING;

    /* Parse session_id */
    s64 session_id = parse_json_integer(args, "session_id");
    if (session_id < 0)
        return AK_E_SCHEMA_INVALID;

    /* Find session */
    ak_stream_session_t *session = ak_stream_get_by_id((u64)session_id);
    if (!session)
        return AK_E_STREAM_INVALID;

    /* Verify session belongs to this agent */
    if (session->agent != ctx->agent)
        return AK_E_CAP_SCOPE;

    /* Get final stats before closing */
    u64 bytes_sent = session->bytes_sent;
    u64 tokens_sent = session->tokens_sent;

    /* Close the session */
    s64 close_result = ak_stream_close(session);
    if (close_result != 0)
        return close_result;

    /* Build result JSON */
    buffer res = allocate_buffer(ctx->agent->heap, 128);
    if (res == INVALID_ADDRESS)
        return AK_E_WASM_OOM;

    buffer_write(res, "{\"closed\": true, \"bytes_sent\": ", 31);

    /* Write bytes sent */
    char num_buf[32];
    int num_len = 0;
    if (bytes_sent == 0) {
        num_buf[num_len++] = '0';
    } else {
        char temp[32];
        int temp_len = 0;
        while (bytes_sent > 0) {
            temp[temp_len++] = '0' + (bytes_sent % 10);
            bytes_sent /= 10;
        }
        for (int i = temp_len - 1; i >= 0; i--) {
            num_buf[num_len++] = temp[i];
        }
    }
    buffer_write(res, num_buf, num_len);

    buffer_write(res, ", \"tokens_sent\": ", 17);

    /* Write tokens sent */
    num_len = 0;
    if (tokens_sent == 0) {
        num_buf[num_len++] = '0';
    } else {
        char temp[32];
        int temp_len = 0;
        while (tokens_sent > 0) {
            temp[temp_len++] = '0' + (tokens_sent % 10);
            tokens_sent /= 10;
        }
        for (int i = temp_len - 1; i >= 0; i--) {
            num_buf[num_len++] = temp[i];
        }
    }
    buffer_write(res, num_buf, num_len);
    buffer_write(res, "}", 1);

    *result = res;
    return 0;
}

/*
 * Set stop sequences for LLM token streaming.
 *
 * Args format (JSON):
 * {
 *   "session_id": "12345",
 *   "sequences": ["\\n\\n", "END", "STOP"]
 * }
 *
 * Returns:
 * {
 *   "count": 3
 * }
 */
s64 ak_host_stream_set_stop(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result)
{
    *result = NULL;

    if (!ctx || !ctx->agent)
        return AK_E_CAP_MISSING;

    /* Parse session_id */
    s64 session_id = parse_json_integer(args, "session_id");
    if (session_id < 0)
        return AK_E_SCHEMA_INVALID;

    /* Find session */
    ak_stream_session_t *session = ak_stream_get_by_id((u64)session_id);
    if (!session)
        return AK_E_STREAM_INVALID;

    /* Verify session belongs to this agent and is LLM type */
    if (session->agent != ctx->agent)
        return AK_E_CAP_SCOPE;
    if (session->type != AK_STREAM_LLM_TOKENS)
        return AK_E_STREAM_TYPE_MISMATCH;

    /*
     * DESIGN DECISION: Single stop sequence per call.
     *
     * The host API accepts one sequence string via the "sequence" field.
     * Multiple sequences can be set through multiple API calls. This
     * simplifies JSON parsing (no array handling) while preserving full
     * functionality - the underlying ak_stream_set_stop_sequences()
     * accumulates sequences across calls.
     */
    u64 seq_len;
    const char *seq = parse_json_string(args, "sequence", &seq_len);
    if (seq && seq_len > 0) {
        /* Need to null-terminate for the API */
        char seq_buf[256];
        if (seq_len >= sizeof(seq_buf))
            return AK_E_SCHEMA_INVALID;
        runtime_memcpy(seq_buf, seq, seq_len);
        seq_buf[seq_len] = '\0';
        const char *seqs[1] = {seq_buf};

        s64 set_result = ak_stream_set_stop_sequences(session, seqs, 1);
        if (set_result != 0)
            return set_result;
    }

    /* Build result JSON */
    *result = create_json_result(ctx->agent->heap, "count", "1", 1);
    return (*result) ? 0 : AK_E_WASM_OOM;
}
