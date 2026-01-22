/*
 * Authority Kernel - Virtio-Serial Proxy Client Implementation
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Communicates with host akproxy daemon via virtio-serial device.
 * Protocol: Newline-delimited JSON.
 */

#include "ak_virtio_proxy.h"
#include "../virtio/virtio_serial.h"

/* Global state */
static struct {
    heap h;
    boolean initialized;
    boolean connected;
    u64 request_id;

    /* Virtio-serial device handle (platform-specific) */
    void *virtio_handle;

    /* Request/response buffers */
    buffer request_buf;
    buffer response_buf;
} ak_proxy_state;

/* Forward declarations for platform-specific I/O */
static s64 virtio_write(void *handle, buffer data);
static s64 virtio_read_line(void *handle, buffer out, u64 timeout_ms);

/* ============================================================
 * JSON HELPERS
 * ============================================================ */

/* Simple JSON string escape */
static void json_escape_string(buffer out, const char *str, u64 len)
{
    buffer_write(out, "\"", 1);
    for (u64 i = 0; i < len; i++) {
        char c = str[i];
        switch (c) {
        case '"':  buffer_write(out, "\\\"", 2); break;
        case '\\': buffer_write(out, "\\\\", 2); break;
        case '\n': buffer_write(out, "\\n", 2); break;
        case '\r': buffer_write(out, "\\r", 2); break;
        case '\t': buffer_write(out, "\\t", 2); break;
        default:
            if (c >= 32 && c < 127) {
                buffer_write(out, &c, 1);
            } else {
                /* Escape as \uXXXX */
                char hex[7];
                hex[0] = '\\';
                hex[1] = 'u';
                hex[2] = '0';
                hex[3] = '0';
                hex[4] = "0123456789abcdef"[(c >> 4) & 0xf];
                hex[5] = "0123456789abcdef"[c & 0xf];
                buffer_write(out, hex, 6);
            }
        }
    }
    buffer_write(out, "\"", 1);
}

/* Generate unique request ID */
static void gen_request_id(char *out, u64 size)
{
    u64 id = __sync_fetch_and_add(&ak_proxy_state.request_id, 1);

    /* Simple hex encoding */
    const char *hex = "0123456789abcdef";
    u64 pos = 0;
    for (int i = 15; i >= 0 && pos < size - 1; i--) {
        out[pos++] = hex[(id >> (i * 4)) & 0xf];
    }
    out[pos] = 0;
}

/* Extract string from JSON response */
static s64 json_get_string(buffer json, const char *key, char *out, u64 out_len)
{
    if (!json || !key || !out || out_len == 0)
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

            if (j >= len || data[j] != '"')
                return -1;
            j++;

            u64 start = j;
            while (j < len && data[j] != '"') {
                if (data[j] == '\\' && j + 1 < len)
                    j++;
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

/* Extract number from JSON */
static s64 json_get_number(buffer json, const char *key, s64 *out)
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
            boolean negative = false;
            if (data[j] == '-') {
                negative = true;
                j++;
            }

            s64 value = 0;
            while (j < len && data[j] >= '0' && data[j] <= '9') {
                value = value * 10 + (data[j] - '0');
                j++;
            }

            *out = negative ? -value : value;
            return 0;
        }
    }
    return -1;
}

/* Extract boolean from JSON */
static s64 json_get_bool(buffer json, const char *key, boolean *out)
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

            if (j + 4 <= len && runtime_memcmp(&data[j], "true", 4) == 0) {
                *out = true;
                return 0;
            }
            if (j + 5 <= len && runtime_memcmp(&data[j], "false", 5) == 0) {
                *out = false;
                return 0;
            }
            return -1;
        }
    }
    return -1;
}

/* Extract nested object/string value from JSON (returns buffer view) */
static buffer json_get_value(buffer json, const char *key)
{
    if (!json || !key)
        return 0;

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
                return 0;

            u64 start = j;

            /* Handle string */
            if (data[j] == '"') {
                j++;
                while (j < len && data[j] != '"') {
                    if (data[j] == '\\' && j + 1 < len)
                        j++;
                    j++;
                }
                j++; /* Include closing quote */

                buffer result = allocate_buffer(ak_proxy_state.h, j - start);
                buffer_write(result, &data[start], j - start);
                return result;
            }

            /* Handle object or array */
            if (data[j] == '{' || data[j] == '[') {
                int depth = 1;
                char open = data[j];
                char close = (open == '{') ? '}' : ']';
                j++;

                while (j < len && depth > 0) {
                    if (data[j] == '"') {
                        j++;
                        while (j < len && data[j] != '"') {
                            if (data[j] == '\\' && j + 1 < len)
                                j++;
                            j++;
                        }
                    } else if (data[j] == open) {
                        depth++;
                    } else if (data[j] == close) {
                        depth--;
                    }
                    j++;
                }

                buffer result = allocate_buffer(ak_proxy_state.h, j - start);
                buffer_write(result, &data[start], j - start);
                return result;
            }

            /* Handle number/bool/null */
            while (j < len && data[j] != ',' && data[j] != '}' && data[j] != ']' &&
                   data[j] != ' ' && data[j] != '\t' && data[j] != '\n')
                j++;

            buffer result = allocate_buffer(ak_proxy_state.h, j - start);
            buffer_write(result, &data[start], j - start);
            return result;
        }
    }
    return 0;
}

/* ============================================================
 * PLATFORM-SPECIFIC I/O (Nanos virtio-serial)
 * ============================================================ */

/*
 * In Nanos, virtio-serial is accessed through the virtio subsystem.
 * For now, we provide a stub that can be wired to the actual virtio device.
 * The minops tool can also wire this to a Unix socket for testing.
 */

/*
 * Virtio I/O implementation using virtio-serial driver.
 * For minops/host testing, ak_proxy_set_fd() can set a different fd.
 */

/* Set the virtio fd (called from platform init or minops) */
void ak_proxy_set_fd(int fd)
{
    (void)fd;
    /* In kernel mode, we use virtio_serial_connected() to check connection */
    /* The fd is ignored - virtio-serial is the transport */
}

static s64 virtio_write(void *handle, buffer data)
{
    (void)handle;

    if (!virtio_serial_connected())
        return AK_PROXY_E_NOT_CONNECTED;

    u8 *buf = buffer_ref(data, 0);
    u64 len = buffer_length(data);

    /* Write data followed by newline */
    s64 written = virtio_serial_write(buf, len);
    if (written < 0)
        return written;

    /* Send newline delimiter */
    char nl = '\n';
    s64 nl_written = virtio_serial_write(&nl, 1);
    if (nl_written < 0)
        return nl_written;

    return written;
}

static s64 virtio_read_line(void *handle, buffer out, u64 timeout_ms)
{
    (void)handle;

    if (!virtio_serial_connected())
        return AK_PROXY_E_NOT_CONNECTED;

    /* Ensure buffer has space */
    u64 max_len = 64 * 1024; /* 64KB max response */
    u8 *buf = allocate(ak_proxy_state.h, max_len);
    if (buf == INVALID_ADDRESS)
        return -ENOMEM;

    s64 len = virtio_serial_read_line(buf, max_len, timeout_ms);
    if (len < 0) {
        deallocate(ak_proxy_state.h, buf, max_len);
        return len;
    }

    if (len == 0) {
        deallocate(ak_proxy_state.h, buf, max_len);
        return AK_PROXY_E_TIMEOUT;
    }

    /* Remove trailing newline if present */
    if (len > 0 && buf[len - 1] == '\n')
        len--;

    /* Copy to output buffer */
    buffer_write(out, buf, len);
    deallocate(ak_proxy_state.h, buf, max_len);

    return len;
}

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

void ak_proxy_init(heap h)
{
    if (ak_proxy_state.initialized)
        return;

    ak_proxy_state.h = h;
    ak_proxy_state.request_id = 1;
    ak_proxy_state.virtio_handle = 0;

    /* Allocate reusable buffers */
    ak_proxy_state.request_buf = allocate_buffer(h, 4096);
    ak_proxy_state.response_buf = allocate_buffer(h, 4096);

    ak_proxy_state.initialized = true;

    /* Connection state is determined by virtio-serial driver */
    ak_proxy_state.connected = virtio_serial_connected() ? true : false;
}

boolean ak_proxy_connected(void)
{
    /* Check live connection status from virtio-serial driver */
    if (!ak_proxy_state.initialized)
        return false;
    return virtio_serial_connected() ? true : false;
}

/* ============================================================
 * HTTP OPERATIONS
 * ============================================================ */

s64 ak_proxy_http_get(
    const char *url,
    buffer headers_json,
    ak_http_response_t *response)
{
    return ak_proxy_http_request("GET", url, headers_json, 0, response);
}

s64 ak_proxy_http_post(
    const char *url,
    buffer headers_json,
    buffer body,
    ak_http_response_t *response)
{
    return ak_proxy_http_request("POST", url, headers_json, body, response);
}

s64 ak_proxy_http_request(
    const char *method,
    const char *url,
    buffer headers_json,
    buffer body,
    ak_http_response_t *response)
{
    if (!ak_proxy_state.initialized)
        return AK_PROXY_E_NOT_CONNECTED;

    if (!ak_proxy_state.connected)
        return AK_PROXY_E_NOT_CONNECTED;

    if (!url || !response)
        return -EINVAL;

    /* Build request JSON */
    buffer req = allocate_buffer(ak_proxy_state.h, 1024);
    if (!req)
        return -ENOMEM;

    char req_id[32];
    gen_request_id(req_id, sizeof(req_id));

    buffer_write(req, "{\"id\":\"", 7);
    buffer_write(req, req_id, runtime_strlen(req_id));
    buffer_write(req, "\",\"op\":\"http_request\",\"method\":\"", 32);
    buffer_write(req, method, runtime_strlen(method));
    buffer_write(req, "\",\"url\":", 8);
    json_escape_string(req, url, runtime_strlen(url));

    if (headers_json && buffer_length(headers_json) > 0) {
        buffer_write(req, ",\"headers\":", 11);
        buffer_write(req, buffer_ref(headers_json, 0), buffer_length(headers_json));
    }

    if (body && buffer_length(body) > 0) {
        buffer_write(req, ",\"body\":", 8);
        json_escape_string(req, (char *)buffer_ref(body, 0), buffer_length(body));
    }

    buffer_write(req, "}", 1);

    /* Send request */
    s64 err = virtio_write(ak_proxy_state.virtio_handle, req);
    deallocate_buffer(req);

    if (err < 0)
        return err;

    /* Read response */
    buffer resp = allocate_buffer(ak_proxy_state.h, 4096);
    if (!resp)
        return -ENOMEM;

    err = virtio_read_line(ak_proxy_state.virtio_handle, resp, AK_PROXY_TIMEOUT_MS);
    if (err < 0) {
        deallocate_buffer(resp);
        return err;
    }

    /* Parse response */
    boolean ok = false;
    if (json_get_bool(resp, "ok", &ok) < 0 || !ok) {
        char error[256];
        json_get_string(resp, "error", error, sizeof(error));
        deallocate_buffer(resp);
        return AK_PROXY_E_REMOTE;
    }

    /* Extract data.status */
    buffer data = json_get_value(resp, "data");
    if (!data) {
        deallocate_buffer(resp);
        return AK_PROXY_E_PARSE;
    }

    s64 status = 0;
    json_get_number(data, "status", &status);
    response->status = (int)status;

    /* Extract headers */
    response->headers = json_get_value(data, "headers");

    /* Extract body */
    buffer body_val = json_get_value(data, "body");
    if (body_val) {
        /* Remove surrounding quotes if present */
        u8 *bdata = buffer_ref(body_val, 0);
        u64 blen = buffer_length(body_val);
        if (blen >= 2 && bdata[0] == '"' && bdata[blen-1] == '"') {
            response->body = allocate_buffer(ak_proxy_state.h, blen - 2);
            /* TODO: unescape JSON string */
            buffer_write(response->body, bdata + 1, blen - 2);
            deallocate_buffer(body_val);
        } else {
            response->body = body_val;
        }
    } else {
        response->body = 0;
    }

    deallocate_buffer(data);
    deallocate_buffer(resp);

    return 0;
}

void ak_proxy_free_http_response(ak_http_response_t *response)
{
    if (!response)
        return;
    if (response->headers)
        deallocate_buffer(response->headers);
    if (response->body)
        deallocate_buffer(response->body);
    response->headers = 0;
    response->body = 0;
}

/* ============================================================
 * FILESYSTEM OPERATIONS
 * ============================================================ */

s64 ak_proxy_fs_read(const char *path, buffer *content)
{
    if (!ak_proxy_state.initialized || !ak_proxy_state.connected)
        return AK_PROXY_E_NOT_CONNECTED;

    if (!path || !content)
        return -EINVAL;

    /* Build request */
    buffer req = allocate_buffer(ak_proxy_state.h, 512);
    if (!req)
        return -ENOMEM;

    char req_id[32];
    gen_request_id(req_id, sizeof(req_id));

    buffer_write(req, "{\"id\":\"", 7);
    buffer_write(req, req_id, runtime_strlen(req_id));
    buffer_write(req, "\",\"op\":\"fs_read\",\"path\":", 24);
    json_escape_string(req, path, runtime_strlen(path));
    buffer_write(req, "}", 1);

    s64 err = virtio_write(ak_proxy_state.virtio_handle, req);
    deallocate_buffer(req);

    if (err < 0)
        return err;

    /* Read response */
    buffer resp = allocate_buffer(ak_proxy_state.h, 4096);
    if (!resp)
        return -ENOMEM;

    err = virtio_read_line(ak_proxy_state.virtio_handle, resp, AK_PROXY_TIMEOUT_MS);
    if (err < 0) {
        deallocate_buffer(resp);
        return err;
    }

    boolean ok = false;
    if (json_get_bool(resp, "ok", &ok) < 0 || !ok) {
        deallocate_buffer(resp);
        return AK_PROXY_E_REMOTE;
    }

    /* Extract content from data.content */
    buffer data = json_get_value(resp, "data");
    if (data) {
        *content = json_get_value(data, "content");
        /* Remove quotes if string */
        if (*content) {
            u8 *cdata = buffer_ref(*content, 0);
            u64 clen = buffer_length(*content);
            if (clen >= 2 && cdata[0] == '"' && cdata[clen-1] == '"') {
                buffer unquoted = allocate_buffer(ak_proxy_state.h, clen - 2);
                buffer_write(unquoted, cdata + 1, clen - 2);
                deallocate_buffer(*content);
                *content = unquoted;
            }
        }
        deallocate_buffer(data);
    } else {
        *content = 0;
    }

    deallocate_buffer(resp);
    return 0;
}

s64 ak_proxy_fs_write(const char *path, buffer content)
{
    if (!ak_proxy_state.initialized || !ak_proxy_state.connected)
        return AK_PROXY_E_NOT_CONNECTED;

    if (!path || !content)
        return -EINVAL;

    /* Build request */
    buffer req = allocate_buffer(ak_proxy_state.h, buffer_length(content) + 512);
    if (!req)
        return -ENOMEM;

    char req_id[32];
    gen_request_id(req_id, sizeof(req_id));

    buffer_write(req, "{\"id\":\"", 7);
    buffer_write(req, req_id, runtime_strlen(req_id));
    buffer_write(req, "\",\"op\":\"fs_write\",\"path\":", 25);
    json_escape_string(req, path, runtime_strlen(path));
    buffer_write(req, ",\"data\":", 8);
    json_escape_string(req, (char *)buffer_ref(content, 0), buffer_length(content));
    buffer_write(req, "}", 1);

    s64 err = virtio_write(ak_proxy_state.virtio_handle, req);
    deallocate_buffer(req);

    if (err < 0)
        return err;

    /* Read response */
    buffer resp = allocate_buffer(ak_proxy_state.h, 256);
    if (!resp)
        return -ENOMEM;

    err = virtio_read_line(ak_proxy_state.virtio_handle, resp, AK_PROXY_TIMEOUT_MS);
    if (err < 0) {
        deallocate_buffer(resp);
        return err;
    }

    boolean ok = false;
    if (json_get_bool(resp, "ok", &ok) < 0 || !ok) {
        deallocate_buffer(resp);
        return AK_PROXY_E_REMOTE;
    }

    /* Extract bytes_written */
    buffer data = json_get_value(resp, "data");
    s64 bytes_written = 0;
    if (data) {
        json_get_number(data, "bytes_written", &bytes_written);
        deallocate_buffer(data);
    }

    deallocate_buffer(resp);
    return bytes_written;
}

s64 ak_proxy_fs_stat(const char *path, ak_file_info_t *info)
{
    if (!ak_proxy_state.initialized || !ak_proxy_state.connected)
        return AK_PROXY_E_NOT_CONNECTED;

    if (!path || !info)
        return -EINVAL;

    /* Build request */
    buffer req = allocate_buffer(ak_proxy_state.h, 512);
    if (!req)
        return -ENOMEM;

    char req_id[32];
    gen_request_id(req_id, sizeof(req_id));

    buffer_write(req, "{\"id\":\"", 7);
    buffer_write(req, req_id, runtime_strlen(req_id));
    buffer_write(req, "\",\"op\":\"fs_stat\",\"path\":", 24);
    json_escape_string(req, path, runtime_strlen(path));
    buffer_write(req, "}", 1);

    s64 err = virtio_write(ak_proxy_state.virtio_handle, req);
    deallocate_buffer(req);

    if (err < 0)
        return err;

    /* Read response */
    buffer resp = allocate_buffer(ak_proxy_state.h, 1024);
    if (!resp)
        return -ENOMEM;

    err = virtio_read_line(ak_proxy_state.virtio_handle, resp, AK_PROXY_TIMEOUT_MS);
    if (err < 0) {
        deallocate_buffer(resp);
        return err;
    }

    boolean ok = false;
    if (json_get_bool(resp, "ok", &ok) < 0 || !ok) {
        deallocate_buffer(resp);
        return AK_PROXY_E_REMOTE;
    }

    /* Extract file info from data */
    buffer data = json_get_value(resp, "data");
    if (data) {
        json_get_string(data, "name", info->name, sizeof(info->name));
        s64 size = 0;
        json_get_number(data, "size", &size);
        info->size = size;
        json_get_string(data, "mode", info->mode, sizeof(info->mode));
        json_get_bool(data, "is_dir", &info->is_dir);
        s64 mod_time = 0;
        json_get_number(data, "mod_time", &mod_time);
        info->mod_time_ms = mod_time;
        deallocate_buffer(data);
    }

    deallocate_buffer(resp);
    return 0;
}

s64 ak_proxy_fs_list(const char *path, ak_file_info_t **entries, u64 *count)
{
    if (!ak_proxy_state.initialized || !ak_proxy_state.connected)
        return AK_PROXY_E_NOT_CONNECTED;

    if (!path || !entries || !count)
        return -EINVAL;

    *entries = 0;
    *count = 0;

    /* Build request */
    buffer req = allocate_buffer(ak_proxy_state.h, 512);
    if (!req)
        return -ENOMEM;

    char req_id[32];
    gen_request_id(req_id, sizeof(req_id));

    buffer_write(req, "{\"id\":\"", 7);
    buffer_write(req, req_id, runtime_strlen(req_id));
    buffer_write(req, "\",\"op\":\"fs_list\",\"path\":", 24);
    json_escape_string(req, path, runtime_strlen(path));
    buffer_write(req, "}", 1);

    s64 err = virtio_write(ak_proxy_state.virtio_handle, req);
    deallocate_buffer(req);

    if (err < 0)
        return err;

    /* Read response */
    buffer resp = allocate_buffer(ak_proxy_state.h, 64 * 1024);
    if (!resp)
        return -ENOMEM;

    err = virtio_read_line(ak_proxy_state.virtio_handle, resp, AK_PROXY_TIMEOUT_MS);
    if (err < 0) {
        deallocate_buffer(resp);
        return err;
    }

    boolean ok = false;
    if (json_get_bool(resp, "ok", &ok) < 0 || !ok) {
        deallocate_buffer(resp);
        return AK_PROXY_E_REMOTE;
    }

    /* TODO: Parse entries array */
    /* For now, return empty list */

    deallocate_buffer(resp);
    return 0;
}

/* ============================================================
 * LLM OPERATIONS
 * ============================================================ */

s64 ak_proxy_llm_complete(
    const char *model,
    const char *prompt,
    u64 max_tokens,
    ak_llm_response_t *response)
{
    if (!ak_proxy_state.initialized || !ak_proxy_state.connected)
        return AK_PROXY_E_NOT_CONNECTED;

    if (!prompt || !response)
        return -EINVAL;

    /* Build request */
    buffer req = allocate_buffer(ak_proxy_state.h, runtime_strlen(prompt) + 512);
    if (!req)
        return -ENOMEM;

    char req_id[32];
    gen_request_id(req_id, sizeof(req_id));

    buffer_write(req, "{\"id\":\"", 7);
    buffer_write(req, req_id, runtime_strlen(req_id));
    buffer_write(req, "\",\"op\":\"llm_complete\"", 21);

    if (model && model[0]) {
        buffer_write(req, ",\"model\":", 9);
        json_escape_string(req, model, runtime_strlen(model));
    }

    buffer_write(req, ",\"prompt\":", 10);
    json_escape_string(req, prompt, runtime_strlen(prompt));

    if (max_tokens > 0) {
        char num[32];
        int nlen = 0;
        u64 t = max_tokens;
        char tmp[32];
        while (t > 0) {
            tmp[nlen++] = '0' + (t % 10);
            t /= 10;
        }
        for (int i = 0; i < nlen; i++)
            num[i] = tmp[nlen - 1 - i];
        num[nlen] = 0;

        buffer_write(req, ",\"max_tokens\":", 14);
        buffer_write(req, num, nlen);
    }

    buffer_write(req, "}", 1);

    s64 err = virtio_write(ak_proxy_state.virtio_handle, req);
    deallocate_buffer(req);

    if (err < 0)
        return err;

    /* Read response */
    buffer resp = allocate_buffer(ak_proxy_state.h, 64 * 1024);
    if (!resp)
        return -ENOMEM;

    err = virtio_read_line(ak_proxy_state.virtio_handle, resp, AK_PROXY_TIMEOUT_MS);
    if (err < 0) {
        deallocate_buffer(resp);
        return err;
    }

    boolean ok = false;
    if (json_get_bool(resp, "ok", &ok) < 0 || !ok) {
        char error[256];
        json_get_string(resp, "error", error, sizeof(error));
        deallocate_buffer(resp);
        return AK_PROXY_E_REMOTE;
    }

    /* Parse LLM response */
    buffer data = json_get_value(resp, "data");
    if (data) {
        response->content = json_get_value(data, "content");
        /* Remove quotes */
        if (response->content) {
            u8 *cdata = buffer_ref(response->content, 0);
            u64 clen = buffer_length(response->content);
            if (clen >= 2 && cdata[0] == '"' && cdata[clen-1] == '"') {
                buffer unquoted = allocate_buffer(ak_proxy_state.h, clen - 2);
                buffer_write(unquoted, cdata + 1, clen - 2);
                deallocate_buffer(response->content);
                response->content = unquoted;
            }
        }

        json_get_string(data, "model", response->model, sizeof(response->model));
        json_get_string(data, "finish_reason", response->finish_reason, sizeof(response->finish_reason));

        /* Parse usage */
        buffer usage = json_get_value(data, "usage");
        if (usage) {
            s64 val = 0;
            json_get_number(usage, "prompt_tokens", &val);
            response->prompt_tokens = val;
            json_get_number(usage, "completion_tokens", &val);
            response->completion_tokens = val;
            json_get_number(usage, "total_tokens", &val);
            response->total_tokens = val;
            deallocate_buffer(usage);
        }

        deallocate_buffer(data);
    }

    deallocate_buffer(resp);
    return 0;
}

s64 ak_proxy_llm_chat(
    const char *model,
    buffer messages_json,
    u64 max_tokens,
    ak_llm_response_t *response)
{
    if (!ak_proxy_state.initialized || !ak_proxy_state.connected)
        return AK_PROXY_E_NOT_CONNECTED;

    if (!messages_json || !response)
        return -EINVAL;

    /* Build request */
    buffer req = allocate_buffer(ak_proxy_state.h, buffer_length(messages_json) + 512);
    if (!req)
        return -ENOMEM;

    char req_id[32];
    gen_request_id(req_id, sizeof(req_id));

    buffer_write(req, "{\"id\":\"", 7);
    buffer_write(req, req_id, runtime_strlen(req_id));
    buffer_write(req, "\",\"op\":\"llm_chat\"", 17);

    if (model && model[0]) {
        buffer_write(req, ",\"model\":", 9);
        json_escape_string(req, model, runtime_strlen(model));
    }

    buffer_write(req, ",\"messages\":", 12);
    buffer_write(req, buffer_ref(messages_json, 0), buffer_length(messages_json));

    if (max_tokens > 0) {
        char num[32];
        int nlen = 0;
        u64 t = max_tokens;
        char tmp[32];
        while (t > 0) {
            tmp[nlen++] = '0' + (t % 10);
            t /= 10;
        }
        for (int i = 0; i < nlen; i++)
            num[i] = tmp[nlen - 1 - i];
        num[nlen] = 0;

        buffer_write(req, ",\"max_tokens\":", 14);
        buffer_write(req, num, nlen);
    }

    buffer_write(req, "}", 1);

    s64 err = virtio_write(ak_proxy_state.virtio_handle, req);
    deallocate_buffer(req);

    if (err < 0)
        return err;

    /* Read response - same as llm_complete */
    buffer resp = allocate_buffer(ak_proxy_state.h, 64 * 1024);
    if (!resp)
        return -ENOMEM;

    err = virtio_read_line(ak_proxy_state.virtio_handle, resp, AK_PROXY_TIMEOUT_MS);
    if (err < 0) {
        deallocate_buffer(resp);
        return err;
    }

    boolean ok = false;
    if (json_get_bool(resp, "ok", &ok) < 0 || !ok) {
        deallocate_buffer(resp);
        return AK_PROXY_E_REMOTE;
    }

    /* Parse response (same format as llm_complete) */
    buffer data = json_get_value(resp, "data");
    if (data) {
        response->content = json_get_value(data, "content");
        if (response->content) {
            u8 *cdata = buffer_ref(response->content, 0);
            u64 clen = buffer_length(response->content);
            if (clen >= 2 && cdata[0] == '"' && cdata[clen-1] == '"') {
                buffer unquoted = allocate_buffer(ak_proxy_state.h, clen - 2);
                buffer_write(unquoted, cdata + 1, clen - 2);
                deallocate_buffer(response->content);
                response->content = unquoted;
            }
        }

        json_get_string(data, "model", response->model, sizeof(response->model));
        json_get_string(data, "finish_reason", response->finish_reason, sizeof(response->finish_reason));

        buffer usage = json_get_value(data, "usage");
        if (usage) {
            s64 val = 0;
            json_get_number(usage, "prompt_tokens", &val);
            response->prompt_tokens = val;
            json_get_number(usage, "completion_tokens", &val);
            response->completion_tokens = val;
            json_get_number(usage, "total_tokens", &val);
            response->total_tokens = val;
            deallocate_buffer(usage);
        }

        deallocate_buffer(data);
    }

    deallocate_buffer(resp);
    return 0;
}

void ak_proxy_free_llm_response(ak_llm_response_t *response)
{
    if (!response)
        return;
    if (response->content)
        deallocate_buffer(response->content);
    response->content = 0;
}
