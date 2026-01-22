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

/* JSON string unescape - inverse of json_escape_string */
static u64 json_unescape_string(buffer out, const u8 *str, u64 len)
{
    u64 written = 0;
    for (u64 i = 0; i < len; i++) {
        if (str[i] == '\\' && i + 1 < len) {
            switch (str[i + 1]) {
            case '"':  buffer_write(out, "\"", 1); written++; i++; break;
            case '\\': buffer_write(out, "\\", 1); written++; i++; break;
            case 'n':  buffer_write(out, "\n", 1); written++; i++; break;
            case 'r':  buffer_write(out, "\r", 1); written++; i++; break;
            case 't':  buffer_write(out, "\t", 1); written++; i++; break;
            case '/':  buffer_write(out, "/", 1); written++; i++; break;
            case 'b':  buffer_write(out, "\b", 1); written++; i++; break;
            case 'f':  buffer_write(out, "\f", 1); written++; i++; break;
            case 'u':
                /* \uXXXX - handle basic ASCII range */
                if (i + 5 < len) {
                    u32 code = 0;
                    boolean valid = true;
                    for (int j = 0; j < 4; j++) {
                        char c = str[i + 2 + j];
                        u32 digit;
                        if (c >= '0' && c <= '9') digit = c - '0';
                        else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
                        else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
                        else { valid = false; break; }
                        code = (code << 4) | digit;
                    }
                    if (valid && code < 128) {
                        char ch = (char)code;
                        buffer_write(out, &ch, 1);
                        written++;
                        i += 5;
                    } else {
                        /* Pass through non-ASCII unicode or invalid */
                        buffer_write(out, &str[i], 1);
                        written++;
                    }
                } else {
                    buffer_write(out, &str[i], 1);
                    written++;
                }
                break;
            default:
                /* Unknown escape, pass through */
                buffer_write(out, &str[i], 1);
                written++;
            }
        } else {
            buffer_write(out, &str[i], 1);
            written++;
        }
    }
    return written;
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
            response->body = allocate_buffer(ak_proxy_state.h, blen);
            json_unescape_string(response->body, bdata + 1, blen - 2);
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

    /* Parse entries array from data */
    buffer data = json_get_value(resp, "data");
    if (!data) {
        deallocate_buffer(resp);
        return 0;  /* Empty result */
    }

    buffer entries_arr = json_get_value(data, "entries");
    if (!entries_arr) {
        deallocate_buffer(data);
        deallocate_buffer(resp);
        return 0;  /* Empty result */
    }

    /* Count entries in the array by counting objects */
    u8 *arr_data = buffer_ref(entries_arr, 0);
    u64 arr_len = buffer_length(entries_arr);

    /* Skip opening bracket */
    u64 pos = 0;
    while (pos < arr_len && (arr_data[pos] == '[' || arr_data[pos] == ' ' || arr_data[pos] == '\t' || arr_data[pos] == '\n'))
        pos++;

    /* Count objects by counting '{' at depth 0 */
    u64 entry_count = 0;
    int depth = 0;
    for (u64 i = pos; i < arr_len; i++) {
        if (arr_data[i] == '"') {
            /* Skip string content */
            i++;
            while (i < arr_len && arr_data[i] != '"') {
                if (arr_data[i] == '\\' && i + 1 < arr_len)
                    i++;
                i++;
            }
        } else if (arr_data[i] == '{') {
            if (depth == 0)
                entry_count++;
            depth++;
        } else if (arr_data[i] == '}') {
            depth--;
        }
    }

    if (entry_count == 0) {
        deallocate_buffer(entries_arr);
        deallocate_buffer(data);
        deallocate_buffer(resp);
        return 0;
    }

    /* Allocate entries array */
    ak_file_info_t *result = allocate(ak_proxy_state.h, entry_count * sizeof(ak_file_info_t));
    if (result == INVALID_ADDRESS) {
        deallocate_buffer(entries_arr);
        deallocate_buffer(data);
        deallocate_buffer(resp);
        return -ENOMEM;
    }
    runtime_memset((u8 *)result, 0, entry_count * sizeof(ak_file_info_t));

    /* Parse each entry object */
    u64 entry_idx = 0;
    depth = 0;
    u64 obj_start = 0;

    for (u64 i = pos; i < arr_len && entry_idx < entry_count; i++) {
        if (arr_data[i] == '"') {
            /* Skip string content */
            i++;
            while (i < arr_len && arr_data[i] != '"') {
                if (arr_data[i] == '\\' && i + 1 < arr_len)
                    i++;
                i++;
            }
        } else if (arr_data[i] == '{') {
            if (depth == 0)
                obj_start = i;
            depth++;
        } else if (arr_data[i] == '}') {
            depth--;
            if (depth == 0) {
                /* Found complete object from obj_start to i (inclusive) */
                u64 obj_len = i - obj_start + 1;
                buffer obj = allocate_buffer(ak_proxy_state.h, obj_len);
                if (obj) {
                    buffer_write(obj, &arr_data[obj_start], obj_len);

                    /* Parse fields from this object */
                    json_get_string(obj, "name", result[entry_idx].name, sizeof(result[entry_idx].name));

                    s64 size = 0;
                    json_get_number(obj, "size", &size);
                    result[entry_idx].size = size;

                    json_get_string(obj, "mode", result[entry_idx].mode, sizeof(result[entry_idx].mode));
                    json_get_bool(obj, "is_dir", &result[entry_idx].is_dir);

                    s64 mod_time = 0;
                    json_get_number(obj, "mod_time", &mod_time);
                    result[entry_idx].mod_time_ms = mod_time;

                    deallocate_buffer(obj);
                }
                entry_idx++;
            }
        }
    }

    *entries = result;
    *count = entry_idx;

    deallocate_buffer(entries_arr);
    deallocate_buffer(data);
    deallocate_buffer(resp);
    return entry_idx;
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

/* ============================================================
 * LLM STREAMING OPERATIONS
 * ============================================================ */

s64 ak_proxy_llm_stream(
    const char *model,
    const char *prompt,
    u64 max_tokens,
    ak_llm_stream_cb callback,
    void *ctx)
{
    if (!ak_proxy_state.initialized || !ak_proxy_state.connected)
        return AK_PROXY_E_NOT_CONNECTED;

    if (!prompt || !callback)
        return -EINVAL;

    /* Build request with stream flag */
    buffer req = allocate_buffer(ak_proxy_state.h, runtime_strlen(prompt) + 512);
    if (!req)
        return -ENOMEM;

    char req_id[32];
    gen_request_id(req_id, sizeof(req_id));

    buffer_write(req, "{\"id\":\"", 7);
    buffer_write(req, req_id, runtime_strlen(req_id));
    buffer_write(req, "\",\"op\":\"llm_stream\"", 19);

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

    buffer_write(req, ",\"stream\":true}", 15);

    s64 err = virtio_write(ak_proxy_state.virtio_handle, req);
    deallocate_buffer(req);

    if (err < 0)
        return err;

    /* Read streaming responses until done */
    buffer chunk_buf = allocate_buffer(ak_proxy_state.h, 4096);
    if (!chunk_buf)
        return -ENOMEM;

    boolean done = false;
    while (!done) {
        buffer_clear(chunk_buf);
        err = virtio_read_line(ak_proxy_state.virtio_handle, chunk_buf, AK_PROXY_TIMEOUT_MS);
        if (err < 0) {
            deallocate_buffer(chunk_buf);
            return err;
        }

        /* Parse chunk response */
        boolean ok = false;
        if (json_get_bool(chunk_buf, "ok", &ok) < 0 || !ok) {
            deallocate_buffer(chunk_buf);
            return AK_PROXY_E_REMOTE;
        }

        /* Check if this is the final chunk */
        json_get_bool(chunk_buf, "done", &done);

        /* Extract and deliver the chunk content */
        buffer data = json_get_value(chunk_buf, "data");
        if (data) {
            buffer content = json_get_value(data, "chunk");
            if (content) {
                u8 *cdata = buffer_ref(content, 0);
                u64 clen = buffer_length(content);
                /* Remove quotes if present */
                if (clen >= 2 && cdata[0] == '"' && cdata[clen-1] == '"') {
                    cdata++;
                    clen -= 2;
                }

                /* Unescape the chunk and deliver to callback */
                buffer unescaped = allocate_buffer(ak_proxy_state.h, clen);
                if (unescaped) {
                    json_unescape_string(unescaped, cdata, clen);
                    boolean cont = callback((const char *)buffer_ref(unescaped, 0),
                                           buffer_length(unescaped), ctx);
                    deallocate_buffer(unescaped);
                    if (!cont) {
                        deallocate_buffer(content);
                        deallocate_buffer(data);
                        break;  /* Callback requested abort */
                    }
                }
                deallocate_buffer(content);
            }
            deallocate_buffer(data);
        }
    }

    deallocate_buffer(chunk_buf);
    return 0;
}

s64 ak_proxy_llm_stream_chat(
    const char *model,
    buffer messages_json,
    u64 max_tokens,
    ak_llm_stream_cb callback,
    void *ctx)
{
    if (!ak_proxy_state.initialized || !ak_proxy_state.connected)
        return AK_PROXY_E_NOT_CONNECTED;

    if (!messages_json || !callback)
        return -EINVAL;

    /* Build request with stream flag */
    buffer req = allocate_buffer(ak_proxy_state.h, buffer_length(messages_json) + 512);
    if (!req)
        return -ENOMEM;

    char req_id[32];
    gen_request_id(req_id, sizeof(req_id));

    buffer_write(req, "{\"id\":\"", 7);
    buffer_write(req, req_id, runtime_strlen(req_id));
    buffer_write(req, "\",\"op\":\"llm_stream_chat\"", 24);

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

    buffer_write(req, ",\"stream\":true}", 15);

    s64 err = virtio_write(ak_proxy_state.virtio_handle, req);
    deallocate_buffer(req);

    if (err < 0)
        return err;

    /* Read streaming responses until done */
    buffer chunk_buf = allocate_buffer(ak_proxy_state.h, 4096);
    if (!chunk_buf)
        return -ENOMEM;

    boolean done = false;
    while (!done) {
        buffer_clear(chunk_buf);
        err = virtio_read_line(ak_proxy_state.virtio_handle, chunk_buf, AK_PROXY_TIMEOUT_MS);
        if (err < 0) {
            deallocate_buffer(chunk_buf);
            return err;
        }

        /* Parse chunk response */
        boolean ok = false;
        if (json_get_bool(chunk_buf, "ok", &ok) < 0 || !ok) {
            deallocate_buffer(chunk_buf);
            return AK_PROXY_E_REMOTE;
        }

        /* Check if this is the final chunk */
        json_get_bool(chunk_buf, "done", &done);

        /* Extract and deliver the chunk content */
        buffer data = json_get_value(chunk_buf, "data");
        if (data) {
            buffer content = json_get_value(data, "chunk");
            if (content) {
                u8 *cdata = buffer_ref(content, 0);
                u64 clen = buffer_length(content);
                /* Remove quotes if present */
                if (clen >= 2 && cdata[0] == '"' && cdata[clen-1] == '"') {
                    cdata++;
                    clen -= 2;
                }

                /* Unescape the chunk and deliver to callback */
                buffer unescaped = allocate_buffer(ak_proxy_state.h, clen);
                if (unescaped) {
                    json_unescape_string(unescaped, cdata, clen);
                    boolean cont = callback((const char *)buffer_ref(unescaped, 0),
                                           buffer_length(unescaped), ctx);
                    deallocate_buffer(unescaped);
                    if (!cont) {
                        deallocate_buffer(content);
                        deallocate_buffer(data);
                        break;  /* Callback requested abort */
                    }
                }
                deallocate_buffer(content);
            }
            deallocate_buffer(data);
        }
    }

    deallocate_buffer(chunk_buf);
    return 0;
}

/* ============================================================
 * TCP OPERATIONS
 * ============================================================ */

/* Helper to write a u64 as decimal string */
static int u64_to_decimal(char *buf, u64 val)
{
    if (val == 0) {
        buf[0] = '0';
        return 1;
    }
    char tmp[24];
    int len = 0;
    while (val > 0) {
        tmp[len++] = '0' + (val % 10);
        val /= 10;
    }
    for (int i = 0; i < len; i++)
        buf[i] = tmp[len - 1 - i];
    return len;
}

s64 ak_proxy_tcp_connect(const char *host, u16 port, ak_tcp_connection_t *conn)
{
    if (!ak_proxy_state.initialized || !ak_proxy_state.connected)
        return AK_PROXY_E_NOT_CONNECTED;

    if (!host || !conn)
        return -EINVAL;

    /* Build request */
    buffer req = allocate_buffer(ak_proxy_state.h, 512);
    if (!req)
        return -ENOMEM;

    char req_id[32];
    gen_request_id(req_id, sizeof(req_id));

    buffer_write(req, "{\"id\":\"", 7);
    buffer_write(req, req_id, runtime_strlen(req_id));
    buffer_write(req, "\",\"op\":\"tcp_connect\",\"host\":", 28);
    json_escape_string(req, host, runtime_strlen(host));
    buffer_write(req, ",\"port\":", 8);

    char port_buf[16];
    int port_len = u64_to_decimal(port_buf, port);
    buffer_write(req, port_buf, port_len);
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

    /* Extract connection info from data */
    buffer data = json_get_value(resp, "data");
    if (data) {
        s64 conn_id = 0;
        json_get_number(data, "conn_id", &conn_id);
        conn->conn_id = (u64)conn_id;
        json_get_string(data, "local_addr", conn->local_addr, sizeof(conn->local_addr));
        json_get_string(data, "remote_addr", conn->remote_addr, sizeof(conn->remote_addr));
        deallocate_buffer(data);
    }

    deallocate_buffer(resp);
    return 0;
}

s64 ak_proxy_tcp_send(u64 conn_id, const void *data, u64 len)
{
    if (!ak_proxy_state.initialized || !ak_proxy_state.connected)
        return AK_PROXY_E_NOT_CONNECTED;

    if (!data || len == 0)
        return 0;

    /* Build request */
    buffer req = allocate_buffer(ak_proxy_state.h, len * 2 + 256);  /* Base64 overhead */
    if (!req)
        return -ENOMEM;

    char req_id[32];
    gen_request_id(req_id, sizeof(req_id));

    buffer_write(req, "{\"id\":\"", 7);
    buffer_write(req, req_id, runtime_strlen(req_id));
    buffer_write(req, "\",\"op\":\"tcp_send\",\"conn_id\":", 28);

    char id_buf[24];
    int id_len = u64_to_decimal(id_buf, conn_id);
    buffer_write(req, id_buf, id_len);

    /* Encode data as base64 */
    buffer_write(req, ",\"data\":\"", 9);
    static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const u8 *src = data;
    for (u64 i = 0; i < len; i += 3) {
        u32 n = ((u32)src[i]) << 16;
        if (i + 1 < len) n |= ((u32)src[i + 1]) << 8;
        if (i + 2 < len) n |= src[i + 2];

        char out[4];
        out[0] = base64_chars[(n >> 18) & 0x3f];
        out[1] = base64_chars[(n >> 12) & 0x3f];
        out[2] = (i + 1 < len) ? base64_chars[(n >> 6) & 0x3f] : '=';
        out[3] = (i + 2 < len) ? base64_chars[n & 0x3f] : '=';
        buffer_write(req, out, 4);
    }
    buffer_write(req, "\"}", 2);

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

    /* Get bytes sent */
    buffer rdata = json_get_value(resp, "data");
    s64 sent = len;  /* Assume all sent if not specified */
    if (rdata) {
        json_get_number(rdata, "bytes_sent", &sent);
        deallocate_buffer(rdata);
    }

    deallocate_buffer(resp);
    return sent;
}

s64 ak_proxy_tcp_recv(u64 conn_id, void *buf, u64 maxlen)
{
    if (!ak_proxy_state.initialized || !ak_proxy_state.connected)
        return AK_PROXY_E_NOT_CONNECTED;

    if (!buf || maxlen == 0)
        return 0;

    /* Build request */
    buffer req = allocate_buffer(ak_proxy_state.h, 256);
    if (!req)
        return -ENOMEM;

    char req_id[32];
    gen_request_id(req_id, sizeof(req_id));

    buffer_write(req, "{\"id\":\"", 7);
    buffer_write(req, req_id, runtime_strlen(req_id));
    buffer_write(req, "\",\"op\":\"tcp_recv\",\"conn_id\":", 28);

    char id_buf[24];
    int id_len = u64_to_decimal(id_buf, conn_id);
    buffer_write(req, id_buf, id_len);

    buffer_write(req, ",\"maxlen\":", 10);
    char len_buf[24];
    int len_len = u64_to_decimal(len_buf, maxlen);
    buffer_write(req, len_buf, len_len);
    buffer_write(req, "}", 1);

    s64 err = virtio_write(ak_proxy_state.virtio_handle, req);
    deallocate_buffer(req);

    if (err < 0)
        return err;

    /* Read response */
    buffer resp = allocate_buffer(ak_proxy_state.h, maxlen * 2 + 256);
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

    /* Decode base64 data */
    buffer rdata = json_get_value(resp, "data");
    if (!rdata) {
        deallocate_buffer(resp);
        return 0;  /* No data available */
    }

    buffer b64 = json_get_value(rdata, "data");
    deallocate_buffer(rdata);
    if (!b64) {
        deallocate_buffer(resp);
        return 0;
    }

    /* Base64 decode */
    u8 *src = buffer_ref(b64, 0);
    u64 src_len = buffer_length(b64);
    /* Skip quotes if present */
    if (src_len >= 2 && src[0] == '"') {
        src++;
        src_len -= 2;
    }

    u8 *dst = buf;
    u64 dst_idx = 0;
    u32 accum = 0;
    int bits = 0;

    for (u64 i = 0; i < src_len && dst_idx < maxlen; i++) {
        int val = -1;
        if (src[i] >= 'A' && src[i] <= 'Z') val = src[i] - 'A';
        else if (src[i] >= 'a' && src[i] <= 'z') val = src[i] - 'a' + 26;
        else if (src[i] >= '0' && src[i] <= '9') val = src[i] - '0' + 52;
        else if (src[i] == '+') val = 62;
        else if (src[i] == '/') val = 63;
        else if (src[i] == '=') break;
        else continue;  /* Skip whitespace etc */

        accum = (accum << 6) | val;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            dst[dst_idx++] = (accum >> bits) & 0xff;
        }
    }

    deallocate_buffer(b64);
    deallocate_buffer(resp);
    return dst_idx;
}

s64 ak_proxy_tcp_close(u64 conn_id)
{
    if (!ak_proxy_state.initialized || !ak_proxy_state.connected)
        return AK_PROXY_E_NOT_CONNECTED;

    /* Build request */
    buffer req = allocate_buffer(ak_proxy_state.h, 128);
    if (!req)
        return -ENOMEM;

    char req_id[32];
    gen_request_id(req_id, sizeof(req_id));

    buffer_write(req, "{\"id\":\"", 7);
    buffer_write(req, req_id, runtime_strlen(req_id));
    buffer_write(req, "\",\"op\":\"tcp_close\",\"conn_id\":", 29);

    char id_buf[24];
    int id_len = u64_to_decimal(id_buf, conn_id);
    buffer_write(req, id_buf, id_len);
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

    deallocate_buffer(resp);
    return 0;
}
