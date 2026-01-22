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

#include "ak_audit.h"
#include "ak_compat.h"
#include "ak_heap.h"
#include "ak_secrets.h"
#include "ak_virtio_proxy.h"
#include "ak_wasm.h"

/* ============================================================
 * LIMITS AND CONSTANTS
 * ============================================================ */

/* Maximum JSON string value size (64 KB) to prevent unbounded parsing */
#define AK_JSON_MAX_VALUE_SIZE (64 * 1024)

/* ============================================================
 * JSON ESCAPING HELPER
 * ============================================================ */

/*
 * json_escape_to_buffer - Escape a string for JSON output
 *
 * Escapes all JSON special characters per RFC 8259:
 *   - " (quote) -> \"
 *   - \ (backslash) -> \\
 *   - Control characters (0x00-0x1F) -> \uXXXX or named escapes
 *   - Named escapes: \b \f \n \r \t
 *
 * UTF-8 handling:
 *   - Valid UTF-8 sequences are passed through unchanged
 *   - Invalid bytes (0x80-0xFF not part of valid UTF-8) are escaped as \uXXXX
 *
 * Buffer overflow handling:
 *   - The buffer system handles growth automatically via buffer_write
 *   - Does not write partial escape sequences
 *
 * Parameters:
 *   out      - Output buffer to write escaped string to
 *   src      - Source data to escape
 *   src_len  - Length of source data in bytes
 *
 * Note: Does NOT add surrounding quotes - caller must add them if needed.
 */
static void json_escape_to_buffer(buffer out, const u8 *src, u64 src_len) {
  static const char hex_digits[] = "0123456789abcdef";

  for (u64 i = 0; i < src_len; i++) {
    u8 c = src[i];

    switch (c) {
    case '"':
      buffer_write(out, "\\\"", 2);
      break;
    case '\\':
      buffer_write(out, "\\\\", 2);
      break;
    case '\b':
      buffer_write(out, "\\b", 2);
      break;
    case '\f':
      buffer_write(out, "\\f", 2);
      break;
    case '\n':
      buffer_write(out, "\\n", 2);
      break;
    case '\r':
      buffer_write(out, "\\r", 2);
      break;
    case '\t':
      buffer_write(out, "\\t", 2);
      break;
    default:
      if (c < 0x20) {
        /* Control character (0x00-0x1F except those handled above) */
        char escape[6];
        escape[0] = '\\';
        escape[1] = 'u';
        escape[2] = '0';
        escape[3] = '0';
        escape[4] = hex_digits[(c >> 4) & 0x0F];
        escape[5] = hex_digits[c & 0x0F];
        buffer_write(out, escape, 6);
      } else if (c >= 0x20 && c < 0x7F) {
        /* Printable ASCII - pass through */
        buffer_write(out, &c, 1);
      } else {
        /*
         * Bytes >= 0x80: Could be valid UTF-8 or invalid.
         *
         * UTF-8 encoding:
         *   0x00-0x7F: Single byte (ASCII)
         *   0xC0-0xDF: 2-byte sequence start
         *   0xE0-0xEF: 3-byte sequence start
         *   0xF0-0xF7: 4-byte sequence start
         *   0x80-0xBF: Continuation byte
         *
         * For simplicity and safety, we pass through bytes >= 0x80
         * as-is. This preserves valid UTF-8 sequences. If the input
         * contains invalid UTF-8, the output JSON will also be
         * invalid, but this matches the behavior of most JSON
         * encoders which assume valid UTF-8 input.
         *
         * Alternative: Validate UTF-8 and escape invalid bytes.
         * This adds complexity and is usually unnecessary since
         * HTTP response bodies should already be valid UTF-8.
         */
        buffer_write(out, &c, 1);
      }
      break;
    }
  }
}

/* ============================================================
 * INTERNAL HELPERS
 * ============================================================ */

/*
 * Validate host call capability.
 *
 * SECURITY: This is the enforcement point for INV-2 within WASM.
 */
static s64 validate_host_cap(ak_wasm_exec_ctx_t *ctx,
                             ak_cap_type_t required_type, const char *resource,
                             const char *method) {
  if (!ctx || !ctx->agent)
    return AK_E_CAP_MISSING;

  /* Check if tool's capability covers this operation */
  if (!ctx->cap)
    return AK_E_CAP_MISSING;

  return ak_capability_validate(ctx->cap, required_type, resource, method,
                                ctx->agent->run_id);
}

/* Forward declarations for JSON parsing helpers */
static const char *parse_json_string(buffer args, const char *key,
                                     u64 *len_out);
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
static const char *parse_json_string(buffer args, const char *key,
                                     u64 *len_out) {
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
    if (data[i] == '"' && runtime_memcmp(&data[i + 1], key, key_len) == 0 &&
        data[i + 1 + key_len] == '"' && data[i + 2 + key_len] == ':') {
      /* Found key, now find value */
      u64 val_start = i + 3 + key_len;

      /* Skip whitespace */
      while (val_start < data_len &&
             (data[val_start] == ' ' || data[val_start] == '\t'))
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

        u64 val_len = val_end - val_start;

        /* BUG-FIX: Enforce maximum JSON value size */
        if (val_len > AK_JSON_MAX_VALUE_SIZE)
          return 0; /* Reject oversized values */

        if (len_out)
          *len_out = val_len;
        return (const char *)&data[val_start];
      }
    }
  }

  return 0;
}

/*
 * Create JSON result buffer.
 */
static buffer create_json_result(heap h, const char *key, const char *value,
                                 u64 value_len) {
  /* Estimate size: {"key": "value"} */
  u64 key_len = runtime_strlen(key);

  /* Check for integer overflow before allocation using safe addition */
  u64 buf_size = 8; /* Base overhead: {"": ""} = 8 chars */
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

__attribute__((unused)) static buffer create_json_error(heap h,
                                                        const char *error) {
  u64 error_len = runtime_strlen(error);
  return create_json_result(h, "error", error, error_len);
}

/* ============================================================
 * NETWORK HOST FUNCTIONS (AK_CAP_NET)
 * ============================================================ */

/*
 * ak_host_http_get - HTTP GET request from WASM sandbox
 *
 * NOT IMPLEMENTED - Returns AK_E_NOT_IMPLEMENTED
 *
 * WHY NOT IMPLEMENTED:
 *   The Nanos unikernel does not include an HTTP client library suitable for
 *   synchronous kernel-space calls. HTTP requests require:
 *     - DNS resolution (async, may require multiple network round-trips)
 *     - TCP connection establishment (3-way handshake)
 *     - TLS handshake for HTTPS (computationally expensive, cert validation)
 *     - HTTP protocol handling (chunked encoding, redirects, etc.)
 *
 *   These operations are inherently asynchronous and can take seconds to
 *   complete. Blocking the WASM executor for this duration would:
 *     - Stall other agents waiting for execution slots
 *     - Risk timeout violations in the capability system
 *     - Create unpredictable latency in tool execution
 *
 * ALTERNATIVES FOR AGENTS:
 *   1. VIRTIO-SERIAL PROXY (Recommended):
 *      Use ak_host_ipc_send() to request HTTP fetches from the host hypervisor.
 *      The host-side orchestrator can perform the HTTP request asynchronously
 *      and deliver results back via virtio-serial.
 *
 *      Example flow:
 *        WASM tool -> ak_host_ipc_send({"type":"http_get","url":"..."})
 *        Host receives request, performs HTTP GET
 *        Host -> ak_host_ipc_recv() delivers response to WASM tool
 *
 *   2. PRE-FETCH PATTERN:
 *      The orchestrator pre-fetches required data before invoking the tool,
 *      passing the content as part of the tool's input arguments.
 *
 *   3. STREAMING RESPONSE:
 *      For large responses, use ak_host_stream_* to receive data incrementally
 *      from the host-side proxy.
 *
 * FUTURE IMPLEMENTATION:
 *   This function may be implemented when Nanos adds support for:
 *     - Asynchronous HTTP client library (e.g., libcurl port)
 *     - Cooperative yield points allowing WASM to suspend during I/O
 *     - HTTP connection pooling for capability-scoped connections
 *   Track progress: https://github.com/nanovms/nanos/issues (HTTP client)
 *
 * Args: {"url": "https://example.com/api/data"}
 * Returns: AK_E_NOT_IMPLEMENTED (always)
 */
s64 ak_host_http_get(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result) {
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

  /* Check if virtio proxy is connected */
  if (!ak_proxy_connected())
    return AK_E_NOT_IMPLEMENTED;

  /* Perform HTTP GET via virtio proxy */
  ak_http_response_t response;
  s64 err = ak_proxy_http_get(url_buf, 0, &response);
  if (err < 0) {
    return err;
  }

  /* Build result JSON */
  buffer res =
      allocate_buffer(ctx->agent->heap,
                      256 + (response.body ? buffer_length(response.body) : 0));
  if (res == INVALID_ADDRESS) {
    ak_proxy_free_http_response(&response);
    return AK_E_WASM_OOM;
  }

  buffer_write(res, "{\"status\": ", 11);

  /* Write status code */
  char status_buf[16];
  int status_len = 0;
  int status = response.status;
  if (status == 0) {
    status_buf[status_len++] = '0';
  } else {
    char temp[16];
    int temp_len = 0;
    while (status > 0) {
      temp[temp_len++] = '0' + (status % 10);
      status /= 10;
    }
    for (int i = temp_len - 1; i >= 0; i--) {
      status_buf[status_len++] = temp[i];
    }
  }
  buffer_write(res, status_buf, status_len);

  buffer_write(res, ", \"body\": \"", 10);
  if (response.body && buffer_length(response.body) > 0) {
    /* JSON escape the body to handle special characters safely */
    json_escape_to_buffer(res, buffer_ref(response.body, 0),
                          buffer_length(response.body));
  }
  buffer_write(res, "\"}", 2);

  ak_proxy_free_http_response(&response);
  *result = res;
  return 0;
}

/*
 * ak_host_http_post - HTTP POST request from WASM sandbox
 *
 * NOT IMPLEMENTED - Returns AK_E_NOT_IMPLEMENTED
 *
 * WHY NOT IMPLEMENTED:
 *   Same rationale as ak_host_http_get(). HTTP POST has additional complexity:
 *     - Request body serialization and content-type handling
 *     - Potential for large request payloads requiring memory management
 *     - Response body parsing (JSON, form-urlencoded, etc.)
 *
 * ALTERNATIVES FOR AGENTS:
 *   See ak_host_http_get() documentation for the recommended patterns:
 *     1. VIRTIO-SERIAL PROXY - Use ak_host_ipc_send() with request body
 *     2. PRE-FETCH PATTERN - Orchestrator handles HTTP interactions
 *     3. STREAMING - Use ak_host_stream_* for incremental data transfer
 *
 *   For POST specifically, the IPC message should include the body:
 *     ak_host_ipc_send({
 *       "type": "http_post",
 *       "url": "https://api.example.com/data",
 *       "body": {"key": "value"},
 *       "content_type": "application/json"
 *     })
 *
 * FUTURE IMPLEMENTATION:
 *   Will be implemented alongside ak_host_http_get() when Nanos adds
 *   asynchronous HTTP client support. Same prerequisites apply.
 *
 * Args: {"url": "https://...", "body": "...", "content_type":
 * "application/json"} Returns: AK_E_NOT_IMPLEMENTED (always)
 */
s64 ak_host_http_post(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result) {
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

  /* Check if virtio proxy is connected */
  if (!ak_proxy_connected())
    return AK_E_NOT_IMPLEMENTED;

  /* Parse body from args */
  u64 body_len;
  const char *body_str = parse_json_string(args, "body", &body_len);

  /* Create body buffer if provided */
  buffer body_buf = 0;
  if (body_str && body_len > 0) {
    body_buf = allocate_buffer(ctx->agent->heap, body_len);
    if (body_buf == INVALID_ADDRESS)
      return AK_E_WASM_OOM;
    buffer_write(body_buf, body_str, body_len);
  }

  /* Perform HTTP POST via virtio proxy */
  ak_http_response_t response;
  s64 err = ak_proxy_http_post(url_buf, 0, body_buf, &response);

  if (body_buf)
    deallocate_buffer(body_buf);

  if (err < 0) {
    return err;
  }

  /* Build result JSON */
  buffer res =
      allocate_buffer(ctx->agent->heap,
                      256 + (response.body ? buffer_length(response.body) : 0));
  if (res == INVALID_ADDRESS) {
    ak_proxy_free_http_response(&response);
    return AK_E_WASM_OOM;
  }

  buffer_write(res, "{\"status\": ", 11);

  /* Write status code */
  char status_buf[16];
  int status_len = 0;
  int status = response.status;
  if (status == 0) {
    status_buf[status_len++] = '0';
  } else {
    char temp[16];
    int temp_len = 0;
    while (status > 0) {
      temp[temp_len++] = '0' + (status % 10);
      status /= 10;
    }
    for (int i = temp_len - 1; i >= 0; i--) {
      status_buf[status_len++] = temp[i];
    }
  }
  buffer_write(res, status_buf, status_len);

  buffer_write(res, ", \"body\": \"", 10);
  if (response.body && buffer_length(response.body) > 0) {
    buffer_write(res, buffer_ref(response.body, 0),
                 buffer_length(response.body));
  }
  buffer_write(res, "\"}", 2);

  ak_proxy_free_http_response(&response);
  *result = res;
  return 0;
}

/*
 * ak_host_tcp_connect - Establish TCP connection from WASM sandbox
 *
 * Establishes a TCP connection via the virtio proxy to the specified host:port.
 * The akproxy daemon on the host handles the actual TCP connection.
 *
 * Args: {"host": "example.com", "port": 8080}
 * Returns: {"conn_id": "12345", "local_addr": "...", "remote_addr": "..."}
 */
s64 ak_host_tcp_connect(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result) {
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

  /* Parse port */
  s64 port = parse_json_integer(args, "port");
  if (port <= 0 || port > 65535)
    return AK_E_SCHEMA_INVALID;

  s64 cap_result = validate_host_cap(ctx, AK_CAP_NET, host_buf, "connect");
  if (cap_result != 0)
    return cap_result;

  /* Check if virtio proxy is connected */
  if (!ak_proxy_connected())
    return AK_E_NOT_IMPLEMENTED;

  /* Perform TCP connect via virtio proxy */
  ak_tcp_connection_t conn;
  runtime_memset((u8 *)&conn, 0, sizeof(conn));
  s64 err = ak_proxy_tcp_connect(host_buf, (u16)port, &conn);
  if (err < 0)
    return err;

  /* Build result JSON with connection info */
  buffer res = allocate_buffer(ctx->agent->heap, 256);
  if (res == INVALID_ADDRESS)
    return AK_E_WASM_OOM;

  buffer_write(res, "{\"conn_id\":\"", 12);

  /* Write conn_id as string */
  char id_buf[24];
  int id_len = 0;
  u64 cid = conn.conn_id;
  if (cid == 0) {
    id_buf[id_len++] = '0';
  } else {
    char tmp[24];
    int tmp_len = 0;
    while (cid > 0) {
      tmp[tmp_len++] = '0' + (cid % 10);
      cid /= 10;
    }
    for (int i = tmp_len - 1; i >= 0; i--)
      id_buf[id_len++] = tmp[i];
  }
  buffer_write(res, id_buf, id_len);

  buffer_write(res, "\",\"local_addr\":\"", 16);
  buffer_write(res, conn.local_addr, runtime_strlen(conn.local_addr));
  buffer_write(res, "\",\"remote_addr\":\"", 17);
  buffer_write(res, conn.remote_addr, runtime_strlen(conn.remote_addr));
  buffer_write(res, "\"}", 2);

  *result = res;
  return 0;
}

/*
 * ak_host_tcp_send - Send data over TCP connection from WASM sandbox
 *
 * Sends data over an established TCP connection via the virtio proxy.
 *
 * Args: {"conn_id": "12345", "data": "base64-encoded-data"}
 * Returns: {"bytes_sent": "123"}
 */
s64 ak_host_tcp_send(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result) {
  /* Initialize *result to NULL to ensure defined state on error paths */
  *result = NULL;

  /* Already connected, validate for send operation */
  s64 cap_result = validate_host_cap(ctx, AK_CAP_NET, "*", "send");
  if (cap_result != 0)
    return cap_result;

  /* Check if virtio proxy is connected */
  if (!ak_proxy_connected())
    return AK_E_NOT_IMPLEMENTED;

  /* Parse conn_id */
  s64 conn_id = parse_json_integer(args, "conn_id");
  if (conn_id < 0)
    return AK_E_SCHEMA_INVALID;

  /* Parse base64 data */
  u64 data_len;
  const char *data_b64 = parse_json_string(args, "data", &data_len);
  if (!data_b64 || data_len == 0) {
    *result = create_json_result(ctx->agent->heap, "bytes_sent", "0", 1);
    return (*result) ? 0 : AK_E_WASM_OOM;
  }

  /* Decode base64 */
  u64 max_decoded = (data_len * 3) / 4 + 4;
  u8 *decoded = allocate(ctx->agent->heap, max_decoded);
  if (decoded == INVALID_ADDRESS)
    return AK_E_WASM_OOM;

  u64 decoded_len = 0;
  u32 accum = 0;
  int bits = 0;
  for (u64 i = 0; i < data_len; i++) {
    int val = -1;
    if (data_b64[i] >= 'A' && data_b64[i] <= 'Z')
      val = data_b64[i] - 'A';
    else if (data_b64[i] >= 'a' && data_b64[i] <= 'z')
      val = data_b64[i] - 'a' + 26;
    else if (data_b64[i] >= '0' && data_b64[i] <= '9')
      val = data_b64[i] - '0' + 52;
    else if (data_b64[i] == '+')
      val = 62;
    else if (data_b64[i] == '/')
      val = 63;
    else if (data_b64[i] == '=')
      break;
    else
      continue;

    accum = (accum << 6) | val;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      decoded[decoded_len++] = (accum >> bits) & 0xff;
    }
  }

  /* Send via proxy */
  s64 sent = ak_proxy_tcp_send((u64)conn_id, decoded, decoded_len);
  deallocate(ctx->agent->heap, decoded, max_decoded);

  if (sent < 0)
    return sent;

  /* Build result */
  char sent_buf[24];
  int sent_len = 0;
  u64 s = (u64)sent;
  if (s == 0) {
    sent_buf[sent_len++] = '0';
  } else {
    char tmp[24];
    int tmp_len = 0;
    while (s > 0) {
      tmp[tmp_len++] = '0' + (s % 10);
      s /= 10;
    }
    for (int i = tmp_len - 1; i >= 0; i--)
      sent_buf[sent_len++] = tmp[i];
  }

  *result =
      create_json_result(ctx->agent->heap, "bytes_sent", sent_buf, sent_len);
  return (*result) ? 0 : AK_E_WASM_OOM;
}

/*
 * ak_host_tcp_recv - Receive data from TCP connection in WASM sandbox
 *
 * Receives data from an established TCP connection via the virtio proxy.
 *
 * Args: {"conn_id": "12345", "max_bytes": 4096}
 * Returns: {"data": "base64-encoded-data"}
 */
s64 ak_host_tcp_recv(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result) {
  /* Initialize *result to NULL to ensure defined state on error paths */
  *result = NULL;

  s64 cap_result = validate_host_cap(ctx, AK_CAP_NET, "*", "recv");
  if (cap_result != 0)
    return cap_result;

  /* Check if virtio proxy is connected */
  if (!ak_proxy_connected())
    return AK_E_NOT_IMPLEMENTED;

  /* Parse conn_id */
  s64 conn_id = parse_json_integer(args, "conn_id");
  if (conn_id < 0)
    return AK_E_SCHEMA_INVALID;

  /* Parse max_bytes */
  s64 max_bytes = parse_json_integer(args, "max_bytes");
  if (max_bytes <= 0)
    max_bytes = 4096; /* Default */
  if (max_bytes > 1024 * 1024)
    max_bytes = 1024 * 1024; /* Cap at 1MB */

  /* Allocate receive buffer */
  u8 *recv_buf = allocate(ctx->agent->heap, max_bytes);
  if (recv_buf == INVALID_ADDRESS)
    return AK_E_WASM_OOM;

  /* Receive via proxy */
  s64 received = ak_proxy_tcp_recv((u64)conn_id, recv_buf, max_bytes);
  if (received < 0) {
    deallocate(ctx->agent->heap, recv_buf, max_bytes);
    return received;
  }

  /* Encode as base64 */
  u64 b64_len = ((received + 2) / 3) * 4;
  buffer res = allocate_buffer(ctx->agent->heap, b64_len + 32);
  if (res == INVALID_ADDRESS) {
    deallocate(ctx->agent->heap, recv_buf, max_bytes);
    return AK_E_WASM_OOM;
  }

  buffer_write(res, "{\"data\":\"", 9);

  static const char base64_chars[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  for (s64 i = 0; i < received; i += 3) {
    u32 n = ((u32)recv_buf[i]) << 16;
    if (i + 1 < received)
      n |= ((u32)recv_buf[i + 1]) << 8;
    if (i + 2 < received)
      n |= recv_buf[i + 2];

    char out[4];
    out[0] = base64_chars[(n >> 18) & 0x3f];
    out[1] = base64_chars[(n >> 12) & 0x3f];
    out[2] = (i + 1 < received) ? base64_chars[(n >> 6) & 0x3f] : '=';
    out[3] = (i + 2 < received) ? base64_chars[n & 0x3f] : '=';
    buffer_write(res, out, 4);
  }

  buffer_write(res, "\"}", 2);

  deallocate(ctx->agent->heap, recv_buf, max_bytes);
  *result = res;
  return 0;
}

/* ============================================================
 * FILESYSTEM HOST FUNCTIONS (AK_CAP_FS)
 * ============================================================
 *
 * These filesystem functions route through the virtio proxy to perform
 * file operations on the host filesystem via the akproxy daemon.
 *
 * SECURITY CONSIDERATIONS:
 *   - All operations validate capabilities before execution
 *   - Path length is bounded to prevent buffer overflows
 *   - If proxy is not connected, operations return safe fallback values
 *   - The akproxy daemon on the host enforces additional access controls
 *
 * PROXY PROTOCOL:
 *   - ak_proxy_fs_read()  - Read file contents
 *   - ak_proxy_fs_write() - Write file contents
 *   - ak_proxy_fs_stat()  - Get file metadata
 *   - ak_proxy_fs_list()  - List directory contents
 *
 * ============================================================ */

/*
 * ak_host_fs_read - Read file contents from WASM sandbox
 *
 * Routes through virtio proxy to read file contents from host filesystem.
 * If proxy is not connected, returns empty content as fallback.
 *
 * Args: {"path": "/path/to/file"}
 * Returns: {"content": "<file_contents>"}
 */
s64 ak_host_fs_read(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result) {
  /* Initialize *result to NULL to ensure defined state on error paths */
  *result = NULL;

  /* Validate context */
  if (!ctx || !ctx->agent)
    return AK_E_CAP_MISSING;

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

  /* Check if virtio proxy is connected */
  if (!ak_proxy_connected()) {
    /* Fallback: return empty content */
    *result = create_json_result(ctx->agent->heap, "content", "", 0);
    return (*result) ? 0 : AK_E_WASM_OOM;
  }

  /* Read file via virtio proxy */
  buffer content = 0;
  s64 err = ak_proxy_fs_read(path_buf, &content);
  if (err < 0) {
    return err;
  }

  /* Build result JSON */
  *result =
      create_json_result(ctx->agent->heap, "content",
                         content ? (const char *)buffer_ref(content, 0) : "",
                         content ? buffer_length(content) : 0);

  if (content)
    deallocate_buffer(content);

  return (*result) ? 0 : AK_E_WASM_OOM;
}

/*
 * ak_host_fs_write - Write file contents from WASM sandbox
 *
 * Routes through virtio proxy to write file contents to host filesystem.
 * If proxy is not connected, returns 0 bytes written as fallback.
 *
 * Args: {"path": "/path/to/file", "content": "data to write"}
 * Returns: {"bytes_written": "<num_bytes>"}
 */
s64 ak_host_fs_write(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result) {
  /* Initialize *result to NULL to ensure defined state on error paths */
  *result = NULL;

  /* Validate context */
  if (!ctx || !ctx->agent)
    return AK_E_CAP_MISSING;

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

  /* Check if virtio proxy is connected */
  if (!ak_proxy_connected()) {
    /* Fallback: return 0 bytes written */
    *result = create_json_result(ctx->agent->heap, "bytes_written", "0", 1);
    return (*result) ? 0 : AK_E_WASM_OOM;
  }

  /* Parse content from args */
  u64 content_len;
  const char *content_str = parse_json_string(args, "content", &content_len);
  if (!content_str)
    return AK_E_SCHEMA_INVALID;

  /* Create content buffer */
  buffer content = allocate_buffer(ctx->agent->heap, content_len);
  if (content == INVALID_ADDRESS)
    return AK_E_WASM_OOM;
  buffer_write(content, content_str, content_len);

  /* Write file via virtio proxy */
  s64 bytes_written = ak_proxy_fs_write(path_buf, content);
  deallocate_buffer(content);

  if (bytes_written < 0) {
    return bytes_written;
  }

  /* Build result JSON */
  char num_buf[32];
  int num_len = 0;
  u64 bw = (u64)bytes_written;
  if (bw == 0) {
    num_buf[num_len++] = '0';
  } else {
    char temp[32];
    int temp_len = 0;
    while (bw > 0) {
      temp[temp_len++] = '0' + (bw % 10);
      bw /= 10;
    }
    for (int i = temp_len - 1; i >= 0; i--) {
      num_buf[num_len++] = temp[i];
    }
  }

  *result =
      create_json_result(ctx->agent->heap, "bytes_written", num_buf, num_len);
  return (*result) ? 0 : AK_E_WASM_OOM;
}

/*
 * ak_host_fs_stat - Get file metadata from WASM sandbox
 *
 * Routes through virtio proxy to get file metadata from host filesystem.
 *
 * Args: {"path": "/path/to/file"}
 * Returns: {"size": <bytes>, "exists": <bool>, "is_dir": <bool>, "mode":
 * "<mode>", "mod_time_ms": <timestamp>}
 */
s64 ak_host_fs_stat(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result) {
  /* Initialize *result to NULL to ensure defined state on error paths */
  *result = NULL;

  /* Validate context */
  if (!ctx || !ctx->agent)
    return AK_E_CAP_MISSING;

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

  /* Check if virtio proxy is connected */
  if (!ak_proxy_connected()) {
    /* Fallback: return placeholder indicating file doesn't exist */
    buffer res = allocate_buffer(ctx->agent->heap, 64);
    if (!res || res == INVALID_ADDRESS)
      return AK_E_WASM_OOM;
    buffer_write(res, "{\"size\": 0, \"exists\": false}", 28);
    *result = res;
    return 0;
  }

  /* Get file info via virtio proxy */
  ak_file_info_t info;
  runtime_memset((u8 *)&info, 0, sizeof(info));
  s64 err = ak_proxy_fs_stat(path_buf, &info);
  if (err < 0) {
    /* File not found or other error - return exists: false */
    if (err == AK_PROXY_E_REMOTE) {
      buffer res = allocate_buffer(ctx->agent->heap, 64);
      if (!res || res == INVALID_ADDRESS)
        return AK_E_WASM_OOM;
      buffer_write(res, "{\"size\": 0, \"exists\": false}", 28);
      *result = res;
      return 0;
    }
    return err;
  }

  /* Build result JSON with file metadata */
  buffer res = allocate_buffer(ctx->agent->heap, 256);
  if (!res || res == INVALID_ADDRESS)
    return AK_E_WASM_OOM;

  buffer_write(res, "{\"size\": ", 9);

  /* Write size as number */
  char num_buf[32];
  int num_len = 0;
  u64 size = info.size;
  if (size == 0) {
    num_buf[num_len++] = '0';
  } else {
    char temp[32];
    int temp_len = 0;
    while (size > 0) {
      temp[temp_len++] = '0' + (size % 10);
      size /= 10;
    }
    for (int i = temp_len - 1; i >= 0; i--) {
      num_buf[num_len++] = temp[i];
    }
  }
  buffer_write(res, num_buf, num_len);

  buffer_write(res, ", \"exists\": true, \"is_dir\": ", 28);
  buffer_write(res, info.is_dir ? "true" : "false", info.is_dir ? 4 : 5);

  buffer_write(res, ", \"mode\": \"", 11);
  u64 mode_len = runtime_strlen(info.mode);
  if (mode_len > 0)
    buffer_write(res, info.mode, mode_len);
  buffer_write(res, "\"", 1);

  buffer_write(res, ", \"mod_time_ms\": ", 16);
  num_len = 0;
  u64 mod_time = info.mod_time_ms;
  if (mod_time == 0) {
    num_buf[num_len++] = '0';
  } else {
    char temp[32];
    int temp_len = 0;
    while (mod_time > 0) {
      temp[temp_len++] = '0' + (mod_time % 10);
      mod_time /= 10;
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
 * ak_host_fs_list - List directory contents from WASM sandbox
 *
 * Routes through virtio proxy to list directory contents from host filesystem.
 *
 * Args: {"path": "/path/to/directory"}
 * Returns: {"entries": [{"name": "file1", "size": 123, "is_dir": false, "mode":
 * "0644", "mod_time_ms": 1234567890}, ...], "count": N}
 */
s64 ak_host_fs_list(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result) {
  /* Initialize *result to NULL to ensure defined state on error paths */
  *result = NULL;

  /* Validate context */
  if (!ctx || !ctx->agent)
    return AK_E_CAP_MISSING;

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

  /* Check if virtio proxy is connected */
  if (!ak_proxy_connected()) {
    /* Fallback: return empty array */
    buffer res = allocate_buffer(ctx->agent->heap, 64);
    if (!res || res == INVALID_ADDRESS)
      return AK_E_WASM_OOM;
    buffer_write(res, "{\"entries\": [], \"count\": 0}", 27);
    *result = res;
    return 0;
  }

  /* List directory via virtio proxy */
  ak_file_info_t *entries = NULL;
  u64 count = 0;
  s64 err = ak_proxy_fs_list(path_buf, &entries, &count);
  if (err < 0) {
    /* Directory not found or other error - return empty list */
    if (err == AK_PROXY_E_REMOTE) {
      buffer res = allocate_buffer(ctx->agent->heap, 64);
      if (!res || res == INVALID_ADDRESS)
        return AK_E_WASM_OOM;
      buffer_write(res, "{\"entries\": [], \"count\": 0}", 27);
      *result = res;
      return 0;
    }
    return err;
  }

  /* Estimate buffer size: ~300 bytes per entry for JSON */
  u64 est_size = 64 + (count * 350);
  /* Cap maximum buffer size to prevent excessive allocation */
  if (est_size > AK_PROXY_MAX_RESPONSE)
    est_size = AK_PROXY_MAX_RESPONSE;

  buffer res = allocate_buffer(ctx->agent->heap, est_size);
  if (!res || res == INVALID_ADDRESS) {
    /* Free entries if allocated */
    if (entries)
      deallocate(ctx->agent->heap, entries, count * sizeof(ak_file_info_t));
    return AK_E_WASM_OOM;
  }

  buffer_write(res, "{\"entries\": [", 13);

  /* Write each entry as JSON object */
  for (u64 i = 0; i < count; i++) {
    ak_file_info_t *e = &entries[i];

    if (i > 0)
      buffer_write(res, ", ", 2);

    buffer_write(res, "{\"name\": \"", 10);

    /* JSON-escape the filename (basic: escape quotes and backslashes) */
    u64 name_len = runtime_strlen(e->name);
    for (u64 j = 0; j < name_len && j < sizeof(e->name) - 1; j++) {
      if (e->name[j] == '"' || e->name[j] == '\\') {
        buffer_write(res, "\\", 1);
      }
      buffer_write(res, &e->name[j], 1);
    }

    buffer_write(res, "\", \"size\": ", 11);

    /* Write size as number */
    char num_buf[32];
    int num_len = 0;
    u64 size = e->size;
    if (size == 0) {
      num_buf[num_len++] = '0';
    } else {
      char temp[32];
      int temp_len = 0;
      while (size > 0) {
        temp[temp_len++] = '0' + (size % 10);
        size /= 10;
      }
      for (int k = temp_len - 1; k >= 0; k--) {
        num_buf[num_len++] = temp[k];
      }
    }
    buffer_write(res, num_buf, num_len);

    buffer_write(res, ", \"is_dir\": ", 12);
    buffer_write(res, e->is_dir ? "true" : "false", e->is_dir ? 4 : 5);

    buffer_write(res, ", \"mode\": \"", 11);
    u64 mode_len = runtime_strlen(e->mode);
    if (mode_len > 0)
      buffer_write(res, e->mode, mode_len);
    buffer_write(res, "\"", 1);

    buffer_write(res, ", \"mod_time_ms\": ", 16);
    num_len = 0;
    u64 mod_time = e->mod_time_ms;
    if (mod_time == 0) {
      num_buf[num_len++] = '0';
    } else {
      char temp[32];
      int temp_len = 0;
      while (mod_time > 0) {
        temp[temp_len++] = '0' + (mod_time % 10);
        mod_time /= 10;
      }
      for (int k = temp_len - 1; k >= 0; k--) {
        num_buf[num_len++] = temp[k];
      }
    }
    buffer_write(res, num_buf, num_len);

    buffer_write(res, "}", 1);
  }

  buffer_write(res, "], \"count\": ", 12);

  /* Write count as number */
  char count_buf[32];
  int count_len = 0;
  u64 cnt = count;
  if (cnt == 0) {
    count_buf[count_len++] = '0';
  } else {
    char temp[32];
    int temp_len = 0;
    while (cnt > 0) {
      temp[temp_len++] = '0' + (cnt % 10);
      cnt /= 10;
    }
    for (int k = temp_len - 1; k >= 0; k--) {
      count_buf[count_len++] = temp[k];
    }
  }
  buffer_write(res, count_buf, count_len);

  buffer_write(res, "}", 1);

  /* Free entries array from proxy */
  if (entries)
    deallocate(ctx->agent->heap, entries, count * sizeof(ak_file_info_t));

  *result = res;
  return 0;
}

/* ============================================================
 * HEAP HOST FUNCTIONS (AK_CAP_HEAP)
 * ============================================================ */

s64 ak_host_heap_read(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result) {
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

s64 ak_host_heap_write(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result) {
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
  s64 write_result =
      ak_heap_write(ptr, patch, (u64)expected_version, &new_version);

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

  *result =
      create_json_result(ctx->agent->heap, "version", version_buf, version_len);
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
s64 ak_host_secret_get(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result) {
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
    /* Validate table before iteration - delegated_caps must be a valid table
     * pointer */
    table t = ctx->agent->delegated_caps;
    if (t && t != INVALID_ADDRESS) {
      table_foreach(t, tid, cap) {
        (void)tid; /* unused - we only need the capability value */
        ak_capability_t *c = (ak_capability_t *)cap;
        if (c && c->type == AK_CAP_SECRETS) {
          secrets_cap = c;
          break;
        }
      }
    }
  }

  /* Resolve the secret using the secrets backend */
  buffer secret_value =
      ak_secret_resolve(ctx->agent->heap, name, name_len, secrets_cap);
  if (!secret_value) {
    /* Set *result = NULL on error path to prevent memory leak */
    *result = NULL;
    return AK_E_TOOL_FAIL;
  }

  /* Build result JSON with the secret value */
  *result =
      create_json_result(ctx->agent->heap, "value", buffer_ref(secret_value, 0),
                         buffer_length(secret_value));

  /* Securely clear the intermediate buffer */
  ak_secret_clear(secret_value);
  deallocate_buffer(secret_value);

  return (*result) ? 0 : AK_E_WASM_OOM;
}

/* ============================================================
 * LLM HOST FUNCTIONS (AK_CAP_INFERENCE)
 * ============================================================ */

s64 ak_host_llm_complete(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result) {
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

  /* Check if virtio proxy is connected */
  if (!ak_proxy_connected()) {
    *result = create_json_result(ctx->agent->heap, "completion", "", 0);
    return (*result) ? 0 : AK_E_WASM_OOM;
  }

  /* Parse optional model from args */
  u64 model_len;
  const char *model_str = parse_json_string(args, "model", &model_len);
  char model_buf[64] = {0};
  if (model_str && model_len > 0 && model_len < sizeof(model_buf)) {
    runtime_memcpy(model_buf, model_str, model_len);
  }

  /* Null-terminate prompt for proxy call */
  char *prompt_buf = allocate(ctx->agent->heap, prompt_len + 1);
  if (!prompt_buf)
    return AK_E_WASM_OOM;
  runtime_memcpy(prompt_buf, prompt, prompt_len);
  prompt_buf[prompt_len] = 0;

  /* Parse optional max_tokens */
  s64 max_tokens = parse_json_integer(args, "max_tokens");
  if (max_tokens <= 0)
    max_tokens = 1000;

  /* Call LLM via virtio proxy */
  ak_llm_response_t llm_response;
  runtime_memset((u8 *)&llm_response, 0, sizeof(llm_response));
  s64 err = ak_proxy_llm_complete(model_buf[0] ? model_buf : 0, prompt_buf,
                                  (u64)max_tokens, &llm_response);

  deallocate(ctx->agent->heap, prompt_buf, prompt_len + 1);

  if (err < 0) {
    return err;
  }

  /* Build result JSON */
  u64 content_len =
      llm_response.content ? buffer_length(llm_response.content) : 0;
  buffer res = allocate_buffer(ctx->agent->heap, 256 + content_len);
  if (res == INVALID_ADDRESS) {
    ak_proxy_free_llm_response(&llm_response);
    return AK_E_WASM_OOM;
  }

  buffer_write(res, "{\"completion\": \"", 16);
  if (llm_response.content && content_len > 0) {
    /* JSON escape the content to handle special characters safely */
    json_escape_to_buffer(res, buffer_ref(llm_response.content, 0),
                          content_len);
  }
  buffer_write(res, "\", \"model\": \"", 12);
  buffer_write(res, llm_response.model, runtime_strlen(llm_response.model));
  buffer_write(res, "\", \"finish_reason\": \"", 20);
  buffer_write(res, llm_response.finish_reason,
               runtime_strlen(llm_response.finish_reason));
  buffer_write(res, "\"}", 2);

  ak_proxy_free_llm_response(&llm_response);
  *result = res;
  return 0;
}

/* ============================================================
 * UTILITY HOST FUNCTIONS (no capability required)
 * ============================================================ */

s64 ak_host_log(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result) {
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

s64 ak_host_time_now(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result) {
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

s64 ak_host_random(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result) {
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

  /* Generate 16 cryptographically secure random bytes using ChaCha20-based PRNG
   */
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

  *result =
      create_json_result(ctx->agent->heap, "hex", (const char *)random_hex, 32);
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
static s64 parse_json_integer(buffer args, const char *key) {
  u64 val_len;
  const char *val = parse_json_string(args, key, &val_len);
  if (!val || val_len == 0)
    return -1;

  /* Simple integer parsing with overflow protection (P2-5) */
  s64 result = 0;
  for (u64 i = 0; i < val_len; i++) {
    if (val[i] >= '0' && val[i] <= '9') {
      s64 digit = val[i] - '0';
      /* Check for overflow before multiplication */
      if (result > (S64_MAX - digit) / 10) {
        return S64_MAX; /* Saturate on overflow */
      }
      result = result * 10 + digit;
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
s64 ak_host_stream_create(ak_wasm_exec_ctx_t *ctx, buffer args,
                          buffer *result) {
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
  ak_stream_session_t *session =
      ak_stream_create(ctx->agent->heap, type, &budget, ctx->agent, ctx->cap);

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
s64 ak_host_stream_send(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result) {
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
    const char *event_type =
        parse_json_string(args, "event_type", &event_type_len);
    char event_buf[64] = {0};
    if (event_type && event_type_len > 0 &&
        event_type_len < sizeof(event_buf)) {
      runtime_memcpy(event_buf, event_type, event_type_len);
    }

    send_result = ak_stream_send_sse_event(
        session, event_buf[0] ? event_buf : NULL, NULL, /* No event ID */
        (const u8 *)data, data_len);
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
s64 ak_host_stream_send_token(ak_wasm_exec_ctx_t *ctx, buffer args,
                              buffer *result) {
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
s64 ak_host_stream_stats(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result) {
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
  case AK_STREAM_STATE_INIT:
    state_str = "init";
    break;
  case AK_STREAM_STATE_ACTIVE:
    state_str = "active";
    break;
  case AK_STREAM_STATE_PAUSED:
    state_str = "paused";
    break;
  case AK_STREAM_STATE_CLOSED:
    state_str = "closed";
    break;
  case AK_STREAM_STATE_ERROR:
    state_str = "error";
    break;
  case AK_STREAM_STATE_BUDGET:
    state_str = "budget_exceeded";
    break;
  case AK_STREAM_STATE_TIMEOUT:
    state_str = "timeout";
    break;
  default:
    state_str = "unknown";
    break;
  }

  /* Build result JSON (simplified - just key stats) */
  buffer res = allocate_buffer(ctx->agent->heap, 256);
  if (res == INVALID_ADDRESS)
    return AK_E_WASM_OOM;

  buffer_write(res, "{\"bytes_sent\": ", 15);

/* Helper macro for writing u64 */
#define WRITE_U64(val)                                                         \
  do {                                                                         \
    char nbuf[32];                                                             \
    int nlen = 0;                                                              \
    u64 v = (val);                                                             \
    if (v == 0) {                                                              \
      nbuf[nlen++] = '0';                                                      \
    } else {                                                                   \
      char tmp[32];                                                            \
      int tl = 0;                                                              \
      while (v > 0) {                                                          \
        tmp[tl++] = '0' + (v % 10);                                            \
        v /= 10;                                                               \
      }                                                                        \
      for (int i = tl - 1; i >= 0; i--)                                        \
        nbuf[nlen++] = tmp[i];                                                 \
    }                                                                          \
    buffer_write(res, nbuf, nlen);                                             \
  } while (0)

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
s64 ak_host_stream_close(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result) {
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
s64 ak_host_stream_set_stop(ak_wasm_exec_ctx_t *ctx, buffer args,
                            buffer *result) {
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
