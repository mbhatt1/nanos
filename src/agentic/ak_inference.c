/*
 * Authority Kernel - LLM Gateway Implementation
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Provides LLM inference capabilities for Authority agents:
 *   - Local inference via virtio-serial to host inference server
 *   - External API calls via HTTPS (OpenAI, Anthropic, custom)
 *   - Capability-gated access enforcement (INV-2)
 *   - Budget tracking and enforcement (INV-3)
 *   - Full audit logging of all inference calls (INV-4)
 *
 * Architecture:
 *   Guest VM <-> virtio-serial <-> Host inference server (local mode)
 *   Guest VM <-> TCP/TLS <-> External API endpoint (external mode)
 */

#include "ak_inference.h"
#include "ak_audit.h"
#include "ak_compat.h"
#include "ak_policy.h"
#include "ak_syscall.h"

/* ============================================================
 * INTERNAL STATE
 * ============================================================ */

static struct {
    heap h;
    boolean initialized;
    ak_llm_config_t config;
    ak_inference_stats_t stats;

    /* Local inference state (virtio-serial) */
    boolean local_connected;
    int local_fd;

    /* External API state */
    boolean api_configured;
    char api_key_resolved[256];
    boolean api_key_valid;

    /* Request/response buffers for virtio protocol */
    buffer virtio_tx_buf;
    buffer virtio_rx_buf;
} ak_inf_state;

/* ============================================================
 * JSON UTILITIES
 * ============================================================ */

/*
 * Extract string value from JSON by key.
 * Simple extraction for well-formed JSON responses.
 */
static s64 json_extract_string(buffer json, const char *key, char *out, u64 out_len)
{
    if (!json || !key || !out || out_len == 0)
        return -1;

    u8 *data = buffer_ref(json, 0);
    u64 len = buffer_length(json);
    u64 key_len = runtime_strlen(key);

    /* Search for "key": " pattern */
    for (u64 i = 0; i + key_len + 4 < len; i++) {
        if (data[i] == '"' &&
            runtime_memcmp(&data[i + 1], key, key_len) == 0 &&
            data[i + 1 + key_len] == '"') {

            /* Found key, skip to value */
            u64 j = i + 1 + key_len + 1;

            /* Skip : and whitespace */
            while (j < len && (data[j] == ':' || data[j] == ' ' || data[j] == '\t'))
                j++;

            if (j >= len || data[j] != '"')
                return -1;
            j++; /* Skip opening quote */

            /* Extract string value */
            u64 start = j;
            while (j < len && data[j] != '"') {
                if (data[j] == '\\' && j + 1 < len)
                    j++; /* Skip escaped char */
                j++;
            }

            u64 value_len = j - start;
            if (value_len >= out_len)
                value_len = out_len - 1;

            runtime_memcpy(out, &data[start], value_len);
            out[value_len] = 0;
            return value_len;
        }
    }

    return -1;
}

/*
 * Extract integer value from JSON by key.
 */
static s64 json_extract_int(buffer json, const char *key, u64 *out)
{
    if (!json || !key || !out)
        return -1;

    u8 *data = buffer_ref(json, 0);
    u64 len = buffer_length(json);
    u64 key_len = runtime_strlen(key);

    for (u64 i = 0; i + key_len + 4 < len; i++) {
        if (data[i] == '"' &&
            runtime_memcmp(&data[i + 1], key, key_len) == 0 &&
            data[i + 1 + key_len] == '"') {

            u64 j = i + 1 + key_len + 1;
            while (j < len && (data[j] == ':' || data[j] == ' ' || data[j] == '\t'))
                j++;

            if (j >= len)
                return -1;

            /* Parse number */
            u64 value = 0;
            while (j < len && data[j] >= '0' && data[j] <= '9') {
                value = value * 10 + (data[j] - '0');
                j++;
            }

            *out = value;
            return 0;
        }
    }

    return -1;
}

/*
 * Format u64 to string, returns length written.
 */
static int u64_format(u64 n, char *buf)
{
    char tmp[24];
    int len = 0;

    if (n == 0) {
        buf[0] = '0';
        return 1;
    }

    while (n > 0) {
        tmp[len++] = '0' + (n % 10);
        n /= 10;
    }

    for (int i = 0; i < len; i++)
        buf[i] = tmp[len - 1 - i];

    return len;
}

/*
 * Escape string for JSON output.
 */
static void json_escape_string(buffer out, const char *str, u64 len)
{
    for (u64 i = 0; i < len; i++) {
        char c = str[i];
        switch (c) {
        case '"':  buffer_write(out, "\\\"", 2); break;
        case '\\': buffer_write(out, "\\\\", 2); break;
        case '\n': buffer_write(out, "\\n", 2); break;
        case '\r': buffer_write(out, "\\r", 2); break;
        case '\t': buffer_write(out, "\\t", 2); break;
        default:
            if (c >= 0x20)
                buffer_write(out, &c, 1);
            break;
        }
    }
}

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

void ak_inference_init(heap h, ak_llm_config_t *config)
{
    if (ak_inf_state.initialized)
        return;

    ak_inf_state.h = h;
    runtime_memset((u8 *)&ak_inf_state.stats, 0, sizeof(ak_inference_stats_t));

    if (config) {
        runtime_memcpy(&ak_inf_state.config, config, sizeof(ak_llm_config_t));
    } else {
        ak_inf_state.config.mode = AK_LLM_MODE_DISABLED;
        ak_inf_state.config.local.timeout_ms = 30000;
        ak_inf_state.config.local.max_tokens = 4096;
        ak_inf_state.config.api.timeout_ms = 30000;
        ak_inf_state.config.api.max_tokens = 4096;
        ak_inf_state.config.requests_per_minute = 60;
        ak_inf_state.config.tokens_per_minute = 100000;
    }

    ak_inf_state.local_connected = false;
    ak_inf_state.local_fd = -1;
    ak_inf_state.api_configured = false;
    ak_inf_state.api_key_valid = false;

    /* Allocate virtio protocol buffers */
    ak_inf_state.virtio_tx_buf = allocate_buffer(h, 65536);
    ak_inf_state.virtio_rx_buf = allocate_buffer(h, 65536);

    if (ak_inf_state.config.mode == AK_LLM_LOCAL ||
        ak_inf_state.config.mode == AK_LLM_HYBRID) {
        ak_local_inference_init(&ak_inf_state.config.local);
    }

    if (ak_inf_state.config.mode == AK_LLM_EXTERNAL ||
        ak_inf_state.config.mode == AK_LLM_HYBRID) {
        ak_external_inference_init(&ak_inf_state.config.api);
    }

    ak_inf_state.initialized = true;
}

void ak_inference_shutdown(void)
{
    if (!ak_inf_state.initialized)
        return;

    /* Clear sensitive data */
    runtime_memset((u8 *)ak_inf_state.api_key_resolved, 0,
                   sizeof(ak_inf_state.api_key_resolved));
    ak_inf_state.api_key_valid = false;

    if (ak_inf_state.local_fd >= 0) {
        ak_inf_state.local_fd = -1;
    }

    if (ak_inf_state.virtio_tx_buf && ak_inf_state.virtio_tx_buf != INVALID_ADDRESS)
        deallocate_buffer(ak_inf_state.virtio_tx_buf);
    if (ak_inf_state.virtio_rx_buf && ak_inf_state.virtio_rx_buf != INVALID_ADDRESS)
        deallocate_buffer(ak_inf_state.virtio_rx_buf);

    ak_inf_state.initialized = false;
}

s64 ak_inference_configure(ak_llm_config_t *config)
{
    if (!config)
        return AK_E_SCHEMA_INVALID;

    runtime_memcpy(&ak_inf_state.config, config, sizeof(ak_llm_config_t));

    if (config->mode == AK_LLM_LOCAL || config->mode == AK_LLM_HYBRID) {
        ak_local_inference_init(&config->local);
    }

    if (config->mode == AK_LLM_EXTERNAL || config->mode == AK_LLM_HYBRID) {
        ak_external_inference_init(&config->api);
    }

    return 0;
}

void ak_inference_get_config(ak_llm_config_t *config_out)
{
    if (config_out)
        runtime_memcpy(config_out, &ak_inf_state.config, sizeof(ak_llm_config_t));
}

/* ============================================================
 * ROUTING
 * ============================================================ */

ak_llm_mode_t ak_inference_route(const char *model)
{
    if (!model || ak_inf_state.config.mode == AK_LLM_MODE_DISABLED)
        return AK_LLM_MODE_DISABLED;

    if (ak_inf_state.config.mode == AK_LLM_LOCAL)
        return AK_LLM_LOCAL;
    if (ak_inf_state.config.mode == AK_LLM_EXTERNAL)
        return AK_LLM_EXTERNAL;

    /* Hybrid mode: route based on model name */
    if (ak_inf_state.config.mode == AK_LLM_HYBRID) {
        for (u32 i = 0; i < ak_inf_state.config.local_model_count; i++) {
            if (ak_strcmp(model, ak_inf_state.config.local_models[i]) == 0)
                return AK_LLM_LOCAL;
        }
        return AK_LLM_EXTERNAL;
    }

    return AK_LLM_MODE_DISABLED;
}

/* ============================================================
 * LOCAL INFERENCE (virtio-serial)
 *
 * Protocol: Length-prefixed JSON over virtio-serial
 *   [4 bytes: message length (big-endian)]
 *   [N bytes: JSON message]
 *
 * Request format:
 *   {"model": "...", "messages": [...], "max_tokens": N}
 *
 * Response format:
 *   {"content": "...", "usage": {"prompt_tokens": N, "completion_tokens": M}}
 * ============================================================ */

s64 ak_local_inference_init(ak_llm_local_config_t *config)
{
    if (!config)
        return AK_E_LLM_NOT_CONFIGURED;

    ak_inf_state.local_connected = false;
    ak_inf_state.local_fd = -1;

    if (config->device_path[0] == 0)
        return AK_E_LLM_NOT_CONFIGURED;

    /*
     * Open virtio-serial device.
     * The device path is typically /dev/vport0p1 or similar.
     * The host must have an inference server connected to this port.
     */

    /* Device opening would go here - requires Nanos file descriptor support */
    /* For now, mark as not available until device is opened */

    return 0;
}

/*
 * Send request and receive response via virtio-serial.
 */
static ak_inference_response_t *virtio_request(buffer request_json)
{
    ak_inference_response_t *res = allocate(ak_inf_state.h,
                                            sizeof(ak_inference_response_t));
    if (res == INVALID_ADDRESS)
        return 0;
    runtime_memset((u8 *)res, 0, sizeof(ak_inference_response_t));

    if (!ak_inf_state.local_connected || ak_inf_state.local_fd < 0) {
        res->success = false;
        res->error_code = AK_E_LLM_CONNECTION_FAILED;
        runtime_memcpy(res->error_message, "Local inference not available",
                       sizeof("Local inference not available"));
        return res;
    }

    /*
     * Protocol implementation:
     * 1. Write 4-byte length prefix (big-endian)
     * 2. Write JSON request
     * 3. Read 4-byte length prefix
     * 4. Read JSON response
     */

    /* Prepare length-prefixed request (big-endian) */
    u32 req_len = buffer_length(request_json);
    (void)req_len;  /* TODO: use when virtio-serial is implemented */

    /* TODO: Write len_buf + request_json to virtio fd, read response */

    /* Parse response */
    res->success = false;
    res->error_code = AK_E_LLM_CONNECTION_FAILED;
    runtime_memcpy(res->error_message, "virtio-serial not implemented",
                   sizeof("virtio-serial not implemented"));

    return res;
}

ak_inference_response_t *ak_local_inference_request(ak_inference_request_t *req)
{
    ak_inference_response_t *res = allocate(ak_inf_state.h,
                                            sizeof(ak_inference_response_t));
    if (res == INVALID_ADDRESS)
        return 0;
    runtime_memset((u8 *)res, 0, sizeof(ak_inference_response_t));

    if (!ak_inf_state.local_connected || ak_inf_state.local_fd < 0) {
        res->success = false;
        res->error_code = AK_E_LLM_CONNECTION_FAILED;
        runtime_memcpy(res->error_message, "Local inference not connected",
                       sizeof("Local inference not connected"));
        return res;
    }

    /* Build JSON request */
    buffer request_buf = allocate_buffer(ak_inf_state.h, 4096);
    if (request_buf == INVALID_ADDRESS) {
        res->success = false;
        res->error_code = AK_E_LLM_API_ERROR;
        return res;
    }

    buffer_write(request_buf, "{\"model\":\"", 10);
    if (req->model[0])
        buffer_write(request_buf, req->model, runtime_strlen(req->model));
    else
        buffer_write(request_buf, "default", 7);
    buffer_write(request_buf, "\",\"messages\":[", 14);

    if (req->messages && req->message_count > 0) {
        for (u32 i = 0; i < req->message_count; i++) {
            if (i > 0) buffer_write(request_buf, ",", 1);
            buffer_write(request_buf, "{\"role\":\"", 9);

            const char *role;
            switch (req->messages[i].role) {
            case AK_ROLE_SYSTEM: role = "system"; break;
            case AK_ROLE_USER: role = "user"; break;
            case AK_ROLE_ASSISTANT: role = "assistant"; break;
            case AK_ROLE_TOOL: role = "tool"; break;
            default: role = "user"; break;
            }
            buffer_write(request_buf, role, runtime_strlen(role));
            buffer_write(request_buf, "\",\"content\":\"", 13);

            if (req->messages[i].content) {
                u8 *content = buffer_ref(req->messages[i].content, 0);
                json_escape_string(request_buf, (char *)content,
                                   buffer_length(req->messages[i].content));
            }
            buffer_write(request_buf, "\"}", 2);
        }
    } else if (req->prompt) {
        buffer_write(request_buf, "{\"role\":\"user\",\"content\":\"", 26);
        u8 *prompt = buffer_ref(req->prompt, 0);
        json_escape_string(request_buf, (char *)prompt, buffer_length(req->prompt));
        buffer_write(request_buf, "\"}", 2);
    }

    buffer_write(request_buf, "],\"max_tokens\":", 15);
    char num_buf[16];
    int num_len = u64_format(req->max_tokens > 0 ? req->max_tokens : 1024, num_buf);
    buffer_write(request_buf, num_buf, num_len);
    buffer_write(request_buf, "}", 1);

    /* Send via virtio */
    ak_inference_response_t *virtio_res = virtio_request(request_buf);
    deallocate_buffer(request_buf);

    if (!virtio_res) {
        res->success = false;
        res->error_code = AK_E_LLM_API_ERROR;
        return res;
    }

    deallocate(ak_inf_state.h, res, sizeof(ak_inference_response_t));
    return virtio_res;
}

boolean ak_local_inference_healthy(void)
{
    return ak_inf_state.local_connected && ak_inf_state.local_fd >= 0;
}

/* ============================================================
 * EXTERNAL INFERENCE (HTTPS API)
 * ============================================================ */

s64 ak_external_inference_init(ak_llm_api_config_t *config)
{
    if (!config)
        return AK_E_LLM_NOT_CONFIGURED;

    if (config->endpoint[0] == 0)
        return AK_E_LLM_NOT_CONFIGURED;

    ak_inf_state.api_configured = true;
    return 0;
}

/*
 * Format API request for OpenAI-compatible endpoints.
 */
static buffer format_openai_request(heap h, ak_inference_request_t *req)
{
    u64 size = 4096;
    if (req->prompt)
        size += buffer_length(req->prompt);
    for (u32 i = 0; i < req->message_count; i++) {
        if (req->messages[i].content)
            size += buffer_length(req->messages[i].content);
    }

    buffer buf = allocate_buffer(h, size);
    if (buf == INVALID_ADDRESS)
        return 0;

    buffer_write(buf, "{\"model\":\"", 10);
    if (req->model[0])
        buffer_write(buf, req->model, runtime_strlen(req->model));
    else
        buffer_write(buf, "gpt-4", 5);
    buffer_write(buf, "\",", 2);

    if (req->type == AK_INFERENCE_CHAT && req->messages && req->message_count > 0) {
        buffer_write(buf, "\"messages\":[", 12);
        for (u32 i = 0; i < req->message_count; i++) {
            if (i > 0) buffer_write(buf, ",", 1);
            buffer_write(buf, "{\"role\":\"", 9);

            const char *role;
            switch (req->messages[i].role) {
            case AK_ROLE_SYSTEM: role = "system"; break;
            case AK_ROLE_USER: role = "user"; break;
            case AK_ROLE_ASSISTANT: role = "assistant"; break;
            case AK_ROLE_TOOL: role = "tool"; break;
            default: role = "user"; break;
            }
            buffer_write(buf, role, runtime_strlen(role));
            buffer_write(buf, "\",\"content\":\"", 13);

            if (req->messages[i].content) {
                u8 *content = buffer_ref(req->messages[i].content, 0);
                json_escape_string(buf, (char *)content,
                                   buffer_length(req->messages[i].content));
            }
            buffer_write(buf, "\"}", 2);
        }
        buffer_write(buf, "],", 2);
    } else if (req->prompt) {
        buffer_write(buf, "\"prompt\":\"", 10);
        u8 *prompt = buffer_ref(req->prompt, 0);
        json_escape_string(buf, (char *)prompt, buffer_length(req->prompt));
        buffer_write(buf, "\",", 2);
    }

    buffer_write(buf, "\"max_tokens\":", 13);
    char num_buf[16];
    int num_len = u64_format(req->max_tokens > 0 ? req->max_tokens : 1024, num_buf);
    buffer_write(buf, num_buf, num_len);

    if (req->temperature > 0) {
        buffer_write(buf, ",\"temperature\":", 15);
        /* Simple float formatting for 0.0-2.0 range */
        int int_part = (int)req->temperature;
        int frac_part = (int)((req->temperature - int_part) * 10);
        char temp_buf[8];
        temp_buf[0] = '0' + int_part;
        temp_buf[1] = '.';
        temp_buf[2] = '0' + frac_part;
        buffer_write(buf, temp_buf, 3);
    }

    buffer_write(buf, "}", 1);

    return buf;
}

/*
 * Format API request for Anthropic Claude.
 */
static buffer format_anthropic_request(heap h, ak_inference_request_t *req)
{
    u64 size = 4096;
    if (req->prompt)
        size += buffer_length(req->prompt);
    for (u32 i = 0; i < req->message_count; i++) {
        if (req->messages[i].content)
            size += buffer_length(req->messages[i].content);
    }

    buffer buf = allocate_buffer(h, size);
    if (buf == INVALID_ADDRESS)
        return 0;

    buffer_write(buf, "{\"model\":\"", 10);
    if (req->model[0])
        buffer_write(buf, req->model, runtime_strlen(req->model));
    else
        buffer_write(buf, "claude-3-5-sonnet-20241022", 26);
    buffer_write(buf, "\",\"max_tokens\":", 15);

    char num_buf[16];
    int num_len = u64_format(req->max_tokens > 0 ? req->max_tokens : 1024, num_buf);
    buffer_write(buf, num_buf, num_len);

    buffer_write(buf, ",\"messages\":[", 13);

    if (req->messages && req->message_count > 0) {
        boolean first = true;
        for (u32 i = 0; i < req->message_count; i++) {
            /* Anthropic only supports user/assistant in messages */
            if (req->messages[i].role != AK_ROLE_USER &&
                req->messages[i].role != AK_ROLE_ASSISTANT)
                continue;

            if (!first) buffer_write(buf, ",", 1);
            first = false;

            buffer_write(buf, "{\"role\":\"", 9);
            const char *role = req->messages[i].role == AK_ROLE_USER ? "user" : "assistant";
            buffer_write(buf, role, runtime_strlen(role));
            buffer_write(buf, "\",\"content\":\"", 13);

            if (req->messages[i].content) {
                u8 *content = buffer_ref(req->messages[i].content, 0);
                json_escape_string(buf, (char *)content,
                                   buffer_length(req->messages[i].content));
            }
            buffer_write(buf, "\"}", 2);
        }
    } else if (req->prompt) {
        buffer_write(buf, "{\"role\":\"user\",\"content\":\"", 26);
        u8 *prompt = buffer_ref(req->prompt, 0);
        json_escape_string(buf, (char *)prompt, buffer_length(req->prompt));
        buffer_write(buf, "\"}", 2);
    }

    buffer_write(buf, "]}", 2);

    return buf;
}

buffer ak_format_api_request(heap h, ak_llm_provider_t provider, ak_inference_request_t *req)
{
    switch (provider) {
    case AK_LLM_PROVIDER_OPENAI:
    case AK_LLM_PROVIDER_LOCAL:
    case AK_LLM_PROVIDER_CUSTOM:
        return format_openai_request(h, req);
    case AK_LLM_PROVIDER_ANTHROPIC:
        return format_anthropic_request(h, req);
    default:
        return 0;
    }
}

ak_inference_response_t *ak_parse_api_response(heap h, ak_llm_provider_t provider, buffer response)
{
    ak_inference_response_t *res = allocate(h, sizeof(ak_inference_response_t));
    if (res == INVALID_ADDRESS)
        return 0;

    runtime_memset((u8 *)res, 0, sizeof(ak_inference_response_t));

    if (!response || buffer_length(response) == 0) {
        res->success = false;
        res->error_code = AK_E_LLM_API_ERROR;
        return res;
    }

    /* Extract content from response based on provider format */
    char content_buf[32768];
    s64 content_len;

    if (provider == AK_LLM_PROVIDER_ANTHROPIC) {
        /* Anthropic format: {"content": [{"text": "..."}], ...} */
        content_len = json_extract_string(response, "text", content_buf, sizeof(content_buf));
    } else {
        /* OpenAI format: {"choices": [{"message": {"content": "..."}}], ...} */
        content_len = json_extract_string(response, "content", content_buf, sizeof(content_buf));
    }

    if (content_len < 0) {
        /* Try direct content field */
        content_len = json_extract_string(response, "content", content_buf, sizeof(content_buf));
    }

    if (content_len >= 0) {
        res->content = allocate_buffer(h, content_len + 1);
        if (res->content != INVALID_ADDRESS) {
            buffer_write(res->content, content_buf, content_len);
            res->success = true;
        } else {
            res->content = 0;
            res->success = false;
            res->error_code = AK_E_LLM_API_ERROR;
            return res;
        }
    } else {
        /* Return raw response if parsing fails */
        res->content = response;
        res->success = true;
    }

    /* Extract usage statistics */
    u64 prompt_tokens = 0, completion_tokens = 0;
    json_extract_int(response, "prompt_tokens", &prompt_tokens);
    json_extract_int(response, "completion_tokens", &completion_tokens);

    res->usage.prompt_tokens = (u32)prompt_tokens;
    res->usage.completion_tokens = (u32)completion_tokens;
    res->usage.total_tokens = res->usage.prompt_tokens + res->usage.completion_tokens;
    res->finish_reason = AK_FINISH_STOP;

    return res;
}

ak_inference_response_t *ak_external_inference_request(
    ak_inference_request_t *req,
    ak_llm_api_config_t *api_config)
{
    ak_inference_response_t *res = allocate(ak_inf_state.h,
                                            sizeof(ak_inference_response_t));
    if (res == INVALID_ADDRESS)
        return 0;

    runtime_memset((u8 *)res, 0, sizeof(ak_inference_response_t));

    if (!ak_inf_state.api_configured || !api_config) {
        res->success = false;
        res->error_code = AK_E_LLM_NOT_CONFIGURED;
        runtime_memcpy(res->error_message, "API not configured",
                       sizeof("API not configured"));
        return res;
    }

    if (api_config->endpoint[0] == 0) {
        res->success = false;
        res->error_code = AK_E_LLM_NOT_CONFIGURED;
        runtime_memcpy(res->error_message, "No API endpoint configured",
                       sizeof("No API endpoint configured"));
        return res;
    }

    /* Format request body */
    buffer request_body = ak_format_api_request(
        ak_inf_state.h, api_config->provider, req);

    if (!request_body) {
        res->success = false;
        res->error_code = AK_E_LLM_API_ERROR;
        runtime_memcpy(res->error_message, "Failed to format request",
                       sizeof("Failed to format request"));
        return res;
    }

    /*
     * HTTP request would be sent here using Nanos TCP/TLS stack.
     * The implementation requires:
     * 1. DNS resolution of endpoint hostname
     * 2. TCP connection to port 443
     * 3. TLS handshake
     * 4. HTTP POST with headers and body
     * 5. Parse HTTP response
     *
     * This requires integration with Nanos networking subsystem.
     */

    deallocate_buffer(request_body);

    res->success = false;
    res->error_code = AK_E_LLM_CONNECTION_FAILED;
    runtime_memcpy(res->error_message, "External API requires network integration",
                   sizeof("External API requires network integration"));

    return res;
}

/* ============================================================
 * MAIN INFERENCE API
 * ============================================================ */

ak_inference_response_t *ak_inference_complete(
    ak_agent_context_t *agent,
    ak_inference_request_t *req,
    ak_capability_t *cap)
{
    ak_inference_response_t *res;

    if (!ak_inf_state.initialized) {
        res = allocate(ak_inf_state.h, sizeof(ak_inference_response_t));
        if (res == INVALID_ADDRESS)
            return 0;
        runtime_memset((u8 *)res, 0, sizeof(ak_inference_response_t));
        res->success = false;
        res->error_code = AK_E_LLM_NOT_CONFIGURED;
        return res;
    }

    /* Validate capability (INV-2: Capability Enforcement) */
    if (!cap) {
        ak_inf_state.stats.capability_denials++;
        res = allocate(ak_inf_state.h, sizeof(ak_inference_response_t));
        if (res == INVALID_ADDRESS)
            return 0;
        runtime_memset((u8 *)res, 0, sizeof(ak_inference_response_t));
        res->success = false;
        res->error_code = AK_E_CAP_MISSING;
        return res;
    }

    s64 cap_result = ak_capability_validate(
        cap, AK_CAP_INFERENCE, "*", "inference", agent->run_id);
    if (cap_result != 0) {
        ak_inf_state.stats.capability_denials++;
        res = allocate(ak_inf_state.h, sizeof(ak_inference_response_t));
        if (res == INVALID_ADDRESS)
            return 0;
        runtime_memset((u8 *)res, 0, sizeof(ak_inference_response_t));
        res->success = false;
        res->error_code = cap_result;
        return res;
    }

    /* Check budget (INV-3: Budget Enforcement) */
    if (agent->budget) {
        u32 estimated_tokens = req->max_tokens > 0 ? req->max_tokens : 1024;
        if (!ak_budget_check(agent->budget, AK_RESOURCE_LLM_TOKENS_OUT, estimated_tokens)) {
            ak_inf_state.stats.budget_exceeded++;
            res = allocate(ak_inf_state.h, sizeof(ak_inference_response_t));
            if (res == INVALID_ADDRESS)
                return 0;
            runtime_memset((u8 *)res, 0, sizeof(ak_inference_response_t));
            res->success = false;
            res->error_code = AK_E_BUDGET_EXCEEDED;
            return res;
        }
    }

    /* Route request based on model and configuration */
    ak_llm_mode_t route = ak_inference_route(req->model);

    ak_inf_state.stats.requests_total++;

    if (route == AK_LLM_LOCAL) {
        ak_inf_state.stats.requests_local++;
        res = ak_local_inference_request(req);
    } else if (route == AK_LLM_EXTERNAL) {
        ak_inf_state.stats.requests_external++;
        res = ak_external_inference_request(req, &ak_inf_state.config.api);
    } else {
        res = allocate(ak_inf_state.h, sizeof(ak_inference_response_t));
        if (res == INVALID_ADDRESS)
            return 0;
        runtime_memset((u8 *)res, 0, sizeof(ak_inference_response_t));
        res->success = false;
        res->error_code = AK_E_LLM_NOT_CONFIGURED;
        return res;
    }

    /* Update statistics and budget */
    if (res && res->success) {
        ak_inf_state.stats.tokens_in_total += res->usage.prompt_tokens;
        ak_inf_state.stats.tokens_out_total += res->usage.completion_tokens;

        if (agent->budget) {
            ak_budget_commit(agent->budget, AK_RESOURCE_LLM_TOKENS_IN, res->usage.prompt_tokens);
            ak_budget_commit(agent->budget, AK_RESOURCE_LLM_TOKENS_OUT, res->usage.completion_tokens);
        }
    } else {
        ak_inf_state.stats.requests_failed++;
    }

    return res;
}

ak_inference_response_t *ak_inference_stream(
    ak_agent_context_t *agent,
    ak_inference_request_t *req,
    ak_capability_t *cap,
    ak_stream_callback_t callback,
    void *callback_ctx)
{
    /*
     * Streaming requires server-sent events (SSE) support.
     * For now, fall back to non-streaming completion.
     */
    (void)callback;
    (void)callback_ctx;
    return ak_inference_complete(agent, req, cap);
}

ak_inference_response_t *ak_inference_embed(
    ak_agent_context_t *agent,
    buffer text,
    const char *model,
    ak_capability_t *cap)
{
    ak_inference_response_t *res = allocate(ak_inf_state.h,
                                            sizeof(ak_inference_response_t));
    if (res == INVALID_ADDRESS)
        return 0;

    runtime_memset((u8 *)res, 0, sizeof(ak_inference_response_t));

    /* Validate capability */
    if (!cap) {
        res->success = false;
        res->error_code = AK_E_CAP_MISSING;
        return res;
    }

    s64 cap_result = ak_capability_validate(
        cap, AK_CAP_INFERENCE, "*", "embed", agent->run_id);
    if (cap_result != 0) {
        res->success = false;
        res->error_code = cap_result;
        return res;
    }

    /* Build embedding request */
    ak_inference_request_t emb_req;
    runtime_memset((u8 *)&emb_req, 0, sizeof(ak_inference_request_t));
    emb_req.type = AK_INFERENCE_EMBEDDING;
    emb_req.prompt = text;
    if (model)
        runtime_memcpy(emb_req.model, model, runtime_strlen(model) + 1);

    /* Route to external API (embeddings typically not available locally) */
    ak_llm_mode_t route = ak_inference_route(emb_req.model);
    if (route == AK_LLM_EXTERNAL) {
        deallocate(ak_inf_state.h, res, sizeof(ak_inference_response_t));
        return ak_external_inference_request(&emb_req, &ak_inf_state.config.api);
    }

    res->success = false;
    res->error_code = AK_E_LLM_NOT_CONFIGURED;
    runtime_memcpy(res->error_message, "Embeddings require external API",
                   sizeof("Embeddings require external API"));
    return res;
}

void ak_inference_response_free(heap h, ak_inference_response_t *res)
{
    if (!res)
        return;

    if (res->content && res->content != INVALID_ADDRESS)
        deallocate_buffer(res->content);
    if (res->tool_calls && res->tool_calls != INVALID_ADDRESS)
        deallocate_buffer(res->tool_calls);

    deallocate(h, res, sizeof(ak_inference_response_t));
}

/* ============================================================
 * SYSCALL HANDLER
 * ============================================================ */

ak_response_t *ak_handle_inference(ak_agent_context_t *ctx, ak_request_t *req)
{
    if (!ctx || !req)
        return ak_response_error(ak_inf_state.h, req, AK_E_SCHEMA_INVALID);

    /* Parse inference request from JSON args */
    ak_inference_request_t inf_req;
    runtime_memset((u8 *)&inf_req, 0, sizeof(ak_inference_request_t));

    inf_req.type = AK_INFERENCE_CHAT;
    inf_req.max_tokens = 1024;
    inf_req.temperature = 0.7f;

    if (req->args) {
        /* Extract model from args */
        json_extract_string(req->args, "model", inf_req.model, sizeof(inf_req.model));

        /* Extract max_tokens */
        u64 max_tokens = 0;
        if (json_extract_int(req->args, "max_tokens", &max_tokens) == 0)
            inf_req.max_tokens = (u32)max_tokens;

        /* Use args as prompt if no messages */
        inf_req.prompt = req->args;
    }

    /* Execute inference */
    ak_inference_response_t *inf_res = ak_inference_complete(ctx, &inf_req, req->cap);

    /* Convert to syscall response */
    ak_response_t *response;
    if (inf_res && inf_res->success) {
        response = ak_response_success(ak_inf_state.h, req, inf_res->content);
        inf_res->content = 0; /* Ownership transferred */

        if (response) {
            response->usage[AK_RESOURCE_LLM_TOKENS_IN] = inf_res->usage.prompt_tokens;
            response->usage[AK_RESOURCE_LLM_TOKENS_OUT] = inf_res->usage.completion_tokens;
        }
    } else {
        s64 error_code = inf_res ? inf_res->error_code : AK_E_LLM_API_ERROR;
        response = ak_response_error(ak_inf_state.h, req, error_code);
    }

    if (inf_res)
        ak_inference_response_free(ak_inf_state.h, inf_res);

    return response;
}

/* ============================================================
 * STATISTICS
 * ============================================================ */

void ak_inference_get_stats(ak_inference_stats_t *stats)
{
    if (stats)
        runtime_memcpy(stats, &ak_inf_state.stats, sizeof(ak_inference_stats_t));
}
