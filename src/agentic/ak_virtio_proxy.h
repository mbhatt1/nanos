/*
 * Authority Kernel - Virtio-Serial Proxy Client
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Client for communicating with the host akproxy daemon via virtio-serial.
 * Provides HTTP, filesystem, and LLM operations for agents.
 */

#ifndef AK_VIRTIO_PROXY_H
#define AK_VIRTIO_PROXY_H

#include "ak_types.h"

/* Maximum sizes */
#define AK_PROXY_MAX_REQUEST (1024 * 1024)       /* 1MB max request */
#define AK_PROXY_MAX_RESPONSE (10 * 1024 * 1024) /* 10MB max response */
#define AK_PROXY_TIMEOUT_MS 30000                /* 30 second timeout */

/* Error codes */
#define AK_PROXY_E_NOT_CONNECTED (-200)
#define AK_PROXY_E_TIMEOUT (-201)
#define AK_PROXY_E_OVERFLOW (-202)
#define AK_PROXY_E_PARSE (-203)
#define AK_PROXY_E_REMOTE (-204)

/* HTTP response */
typedef struct ak_http_response {
  int status;
  buffer headers; /* JSON object as string */
  buffer body;
} ak_http_response_t;

/* File info */
typedef struct ak_file_info {
  char name[256];
  u64 size;
  char mode[16];
  boolean is_dir;
  u64 mod_time_ms;
} ak_file_info_t;

/* LLM response */
typedef struct ak_llm_response {
  buffer content;
  char model[64];
  char finish_reason[32];
  u64 prompt_tokens;
  u64 completion_tokens;
  u64 total_tokens;
} ak_llm_response_t;

/* TCP connection info */
typedef struct ak_tcp_connection {
  u64 conn_id;          /* Connection ID for subsequent send/recv */
  char local_addr[64];  /* Local address (IP:port) */
  char remote_addr[64]; /* Remote address (IP:port) */
} ak_tcp_connection_t;

/*
 * Initialize the virtio proxy client.
 * Called during AK initialization.
 */
void ak_proxy_init(heap h);

/*
 * Check if proxy is connected.
 */
boolean ak_proxy_connected(void);

/*
 * HTTP GET request.
 * Returns 0 on success, negative error code on failure.
 * Caller must free response->headers and response->body.
 */
s64 ak_proxy_http_get(
    const char *url,
    buffer headers_json, /* Optional: {"Header": "Value", ...} */
    ak_http_response_t *response);

/*
 * HTTP POST request.
 * Returns 0 on success, negative error code on failure.
 */
s64 ak_proxy_http_post(const char *url, buffer headers_json, buffer body,
                       ak_http_response_t *response);

/*
 * Generic HTTP request.
 * Returns 0 on success, negative error code on failure.
 */
s64 ak_proxy_http_request(const char *method, const char *url,
                          buffer headers_json, buffer body,
                          ak_http_response_t *response);

/*
 * Read file contents.
 * Returns 0 on success, negative error code on failure.
 * Caller must free *content.
 */
s64 ak_proxy_fs_read(const char *path, buffer *content);

/*
 * Write file contents.
 * Returns bytes written on success, negative error code on failure.
 */
s64 ak_proxy_fs_write(const char *path, buffer content);

/*
 * Get file info.
 * Returns 0 on success, negative error code on failure.
 */
s64 ak_proxy_fs_stat(const char *path, ak_file_info_t *info);

/*
 * List directory contents.
 * Returns number of entries on success, negative error code on failure.
 * Caller must free entries array.
 */
s64 ak_proxy_fs_list(const char *path, ak_file_info_t **entries, u64 *count);

/*
 * LLM completion (simple prompt).
 * Returns 0 on success, negative error code on failure.
 * Caller must free response->content.
 */
s64 ak_proxy_llm_complete(const char *model, const char *prompt, u64 max_tokens,
                          ak_llm_response_t *response);

/*
 * LLM chat (multi-turn).
 * messages_json: [{"role":"user","content":"..."},...]
 * Returns 0 on success, negative error code on failure.
 */
s64 ak_proxy_llm_chat(const char *model, buffer messages_json, u64 max_tokens,
                      ak_llm_response_t *response);

/*
 * Free HTTP response buffers.
 */
void ak_proxy_free_http_response(ak_http_response_t *response);

/*
 * Free LLM response buffers.
 */
void ak_proxy_free_llm_response(ak_llm_response_t *response);

/* ============================================================
 * LLM STREAMING OPERATIONS
 * ============================================================ */

/* Streaming callback - called for each chunk of LLM response */
typedef boolean (*ak_llm_stream_cb)(const char *chunk, u64 len, void *ctx);

/*
 * LLM streaming completion.
 *
 * Calls callback for each chunk of response as it arrives.
 * Returns 0 on success, negative error code on failure.
 *
 * The callback should return true to continue, false to abort.
 */
s64 ak_proxy_llm_stream(const char *model, const char *prompt, u64 max_tokens,
                        ak_llm_stream_cb callback, void *ctx);

/*
 * LLM streaming chat.
 *
 * Calls callback for each chunk of response as it arrives.
 * Returns 0 on success, negative error code on failure.
 */
s64 ak_proxy_llm_stream_chat(const char *model, buffer messages_json,
                             u64 max_tokens, ak_llm_stream_cb callback,
                             void *ctx);

/*
 * TCP connect via proxy.
 * Returns 0 on success, negative error code on failure.
 */
s64 ak_proxy_tcp_connect(const char *host, u16 port, ak_tcp_connection_t *conn);

/*
 * TCP send data via proxy.
 * Returns bytes sent on success, negative error code on failure.
 */
s64 ak_proxy_tcp_send(u64 conn_id, const void *data, u64 len);

/*
 * TCP receive data via proxy.
 * Returns bytes received on success, 0 if no data, negative error code on
 * failure.
 */
s64 ak_proxy_tcp_recv(u64 conn_id, void *buf, u64 maxlen);

/*
 * TCP close connection via proxy.
 * Returns 0 on success, negative error code on failure.
 */
s64 ak_proxy_tcp_close(u64 conn_id);

#endif /* AK_VIRTIO_PROXY_H */
