/**
 * libak - The Authority Kernel C Library Implementation
 *
 * Serializes requests as JSON to match kernel's ak_syscall_handler format.
 *
 * Kernel syscall convention:
 *   arg0: agent_id pointer (u8[16]) or 0 to use root context
 *   arg1: request buffer pointer (JSON)
 *   arg2: request buffer length
 *   arg3: response buffer pointer (output)
 *   arg4: response buffer max length
 */

#include "libak.h"
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

/* ============================================================================
   INTERNAL HELPERS
   ============================================================================
 */

/* Response buffer size */
#define RESP_BUF_SIZE 4096

/* Simple JSON number parser - extract uint64 by key */
static uint64_t json_get_u64(const char *json, size_t len, const char *key) {
  if (!json || !key || len == 0)
    return 0;

  size_t key_len = strlen(key);
  for (size_t i = 0; i + key_len + 3 < len; i++) {
    if (json[i] == '"' && memcmp(&json[i + 1], key, key_len) == 0 &&
        json[i + 1 + key_len] == '"') {

      size_t j = i + 1 + key_len + 1;
      while (j < len && (json[j] == ':' || json[j] == ' ' || json[j] == '\t'))
        j++;

      if (j >= len)
        return 0;

      uint64_t value = 0;
      while (j < len && json[j] >= '0' && json[j] <= '9') {
        value = value * 10 + (json[j] - '0');
        j++;
      }
      return value;
    }
  }
  return 0;
}

/* Simple JSON string extractor */
static int json_get_string(const char *json, size_t len, const char *key,
                           char *out, size_t out_max) {
  if (!json || !key || !out || len == 0 || out_max == 0)
    return -1;

  size_t key_len = strlen(key);
  for (size_t i = 0; i + key_len + 4 < len; i++) {
    if (json[i] == '"' && memcmp(&json[i + 1], key, key_len) == 0 &&
        json[i + 1 + key_len] == '"') {

      size_t j = i + 1 + key_len + 1;
      while (j < len && (json[j] == ':' || json[j] == ' ' || json[j] == '\t'))
        j++;

      if (j >= len || json[j] != '"')
        return -1;
      j++; /* skip opening quote */

      size_t start = j;
      while (j < len && json[j] != '"') {
        if (json[j] == '\\' && j + 1 < len)
          j++;
        j++;
      }

      size_t value_len = j - start;
      if (value_len >= out_max)
        value_len = out_max - 1;
      memcpy(out, &json[start], value_len);
      out[value_len] = '\0';
      return (int)value_len;
    }
  }
  return -1;
}

/* ============================================================================
   SYSCALL WRAPPER
   ============================================================================
 */

/**
 * Low-level syscall wrapper using kernel's expected format.
 *
 * Kernel convention:
 *   arg0 = 0 (use root context)
 *   arg1 = request JSON buffer
 *   arg2 = request length
 *   arg3 = response buffer
 *   arg4 = response max length
 *
 * Returns bytes written to response, or negative error code.
 */
static long ak_raw_syscall(uint64_t sysnum, const char *req_json,
                           size_t req_len, char *resp_buf, size_t resp_max) {
  long result;

  errno = 0;
  result = syscall(sysnum, (uint64_t)0, /* arg0: use root context */
                   (uint64_t)req_json,  /* arg1: request buffer */
                   (uint64_t)req_len,   /* arg2: request length */
                   (uint64_t)resp_buf,  /* arg3: response buffer */
                   (uint64_t)resp_max); /* arg4: response max */

  /* musl's syscall() returns -1 and sets errno on error.
   * We need to return the actual kernel error code. */
  if (result == -1 && errno != 0) {
    return -errno; /* Return negative errno as error code */
  }

  return result;
}

/* Legacy syscall wrapper for compatibility */
ak_err_t ak_syscall(uint64_t sysnum, uint64_t arg0, uint64_t arg1,
                    uint64_t arg2, uint64_t arg3, uint64_t arg4) {
  long result = syscall(sysnum, arg0, arg1, arg2, arg3, arg4);
  if (result < 0) {
    return (ak_err_t)result;
  }
  return AK_OK;
}

/* ============================================================================
   INITIALIZATION
   ============================================================================
 */

static bool libak_initialized = false;

ak_err_t ak_init(void) {
  if (libak_initialized) {
    return AK_OK;
  }
  libak_initialized = true;
  return AK_OK;
}

void ak_shutdown(void) { libak_initialized = false; }

/* ============================================================================
   TYPED HEAP OPERATIONS
   ============================================================================
 */

/**
 * Allocate object in typed heap.
 *
 * Request: {"type": <hash>, "value": <initial_value_json>}
 * Response: {"ptr": <ptr>, "version": 1}
 */
ak_err_t ak_alloc(const char *type_name, const uint8_t *initial_value,
                  size_t value_len, ak_handle_t *out_handle) {
  if (!type_name || !out_handle) {
    return AK_E_INVAL;
  }

  /* Compute simple hash of type name */
  uint64_t type_hash = 0;
  for (const char *p = type_name; *p; p++) {
    type_hash = type_hash * 31 + (uint8_t)*p;
  }

  /* Build JSON request */
  char req_buf[2048];
  int req_len;

  if (initial_value && value_len > 0) {
    /* Include value - assume it's already JSON */
    req_len = snprintf(
        req_buf, sizeof(req_buf), "{\"type\":%lu,\"value\":%.*s}",
        (unsigned long)type_hash, (int)value_len, (const char *)initial_value);
  } else {
    req_len =
        snprintf(req_buf, sizeof(req_buf), "{\"type\":%lu,\"value\":null}",
                 (unsigned long)type_hash);
  }

  if (req_len < 0 || (size_t)req_len >= sizeof(req_buf)) {
    return AK_E_OVERFLOW;
  }

  /* Make syscall */
  char resp_buf[RESP_BUF_SIZE];
  long result = ak_raw_syscall(AK_SYS_ALLOC, req_buf, req_len, resp_buf,
                               sizeof(resp_buf));

  if (result < 0) {
    return (ak_err_t)result;
  }

  /* Parse response: {"ptr": N, "version": N} */
  out_handle->id = json_get_u64(resp_buf, result, "ptr");
  out_handle->version = (uint32_t)json_get_u64(resp_buf, result, "version");

  if (out_handle->id == 0) {
    return AK_E_NOMEM;
  }

  return AK_OK;
}

/**
 * Read object from typed heap.
 *
 * Request: {"ptr": <ptr>}
 * Response: {"value": <json>, "version": N}
 */
ak_err_t ak_read(ak_handle_t handle, uint8_t *out_value, size_t max_len,
                 size_t *out_len) {
  if (!out_value || !out_len) {
    return AK_E_INVAL;
  }

  /* Build JSON request */
  char req_buf[128];
  int req_len = snprintf(req_buf, sizeof(req_buf), "{\"ptr\":%lu}",
                         (unsigned long)handle.id);

  if (req_len < 0 || (size_t)req_len >= sizeof(req_buf)) {
    return AK_E_OVERFLOW;
  }

  /* Make syscall */
  char resp_buf[RESP_BUF_SIZE];
  long result =
      ak_raw_syscall(AK_SYS_READ, req_buf, req_len, resp_buf, sizeof(resp_buf));

  if (result < 0) {
    return (ak_err_t)result;
  }

  /* Extract value from response - look for "value": */
  const char *value_start = strstr(resp_buf, "\"value\":");
  if (value_start) {
    value_start += 8; /* skip "value": */
    while (*value_start == ' ' || *value_start == '\t')
      value_start++;

    /* Find end of value (next comma or closing brace at same level) */
    const char *value_end = value_start;
    int depth = 0;
    bool in_string = false;
    while (*value_end) {
      if (in_string) {
        if (*value_end == '\\' && *(value_end + 1)) {
          value_end++;
        } else if (*value_end == '"') {
          in_string = false;
        }
      } else {
        if (*value_end == '"')
          in_string = true;
        else if (*value_end == '{' || *value_end == '[')
          depth++;
        else if (*value_end == '}' || *value_end == ']') {
          if (depth == 0)
            break;
          depth--;
        } else if (*value_end == ',' && depth == 0)
          break;
      }
      value_end++;
    }

    size_t value_len = value_end - value_start;
    if (value_len > max_len)
      value_len = max_len;
    memcpy(out_value, value_start, value_len);
    *out_len = value_len;
  } else {
    *out_len = 0;
  }

  return AK_OK;
}

/**
 * Write (update) object in typed heap.
 *
 * Request: {"ptr": <ptr>, "version": <expected>, "patch": <json_patch>}
 * Response: {"version": N}
 */
ak_err_t ak_write(ak_handle_t handle, const uint8_t *patch, size_t patch_len,
                  uint32_t expected_version, uint32_t *out_new_version) {
  if (!patch) {
    return AK_E_INVAL;
  }

  /* Build JSON request */
  char req_buf[2048];
  int req_len = snprintf(req_buf, sizeof(req_buf),
                         "{\"ptr\":%lu,\"version\":%u,\"patch\":%.*s}",
                         (unsigned long)handle.id, expected_version,
                         (int)patch_len, (const char *)patch);

  if (req_len < 0 || (size_t)req_len >= sizeof(req_buf)) {
    return AK_E_OVERFLOW;
  }

  /* Make syscall */
  char resp_buf[RESP_BUF_SIZE];
  long result = ak_raw_syscall(AK_SYS_WRITE, req_buf, req_len, resp_buf,
                               sizeof(resp_buf));

  if (result < 0) {
    return (ak_err_t)result;
  }

  /* Parse response: {"version": N} */
  if (out_new_version) {
    *out_new_version = (uint32_t)json_get_u64(resp_buf, result, "version");
  }

  return AK_OK;
}

/**
 * Delete object from typed heap.
 *
 * Request: {"ptr": <ptr>, "version": <expected>}
 * Response: {"deleted": true}
 */
ak_err_t ak_delete(ak_handle_t handle) {
  /* Build JSON request */
  char req_buf[128];
  int req_len =
      snprintf(req_buf, sizeof(req_buf), "{\"ptr\":%lu,\"version\":%u}",
               (unsigned long)handle.id, handle.version);

  if (req_len < 0 || (size_t)req_len >= sizeof(req_buf)) {
    return AK_E_OVERFLOW;
  }

  /* Make syscall */
  char resp_buf[RESP_BUF_SIZE];
  long result = ak_raw_syscall(AK_SYS_DELETE, req_buf, req_len, resp_buf,
                               sizeof(resp_buf));

  if (result < 0) {
    return (ak_err_t)result;
  }

  return AK_OK;
}

/* ============================================================================
   TOOL EXECUTION
   ============================================================================
 */

/**
 * Execute tool in WASM sandbox.
 *
 * Request: {"tool": "<name>", "args": <json>}
 * Response: {"result": <json>}
 */
ak_err_t ak_call_tool(const ak_tool_call_t *tool_call, uint8_t *out_result,
                      size_t max_len, size_t *out_len) {
  if (!tool_call || !out_result || !out_len) {
    return AK_E_INVAL;
  }

  /* Build JSON request */
  char req_buf[4096];
  int req_len =
      snprintf(req_buf, sizeof(req_buf), "{\"tool\":\"%s\",\"args\":%.*s}",
               tool_call->tool_name, (int)tool_call->args_len,
               (const char *)tool_call->args_json);

  if (req_len < 0 || (size_t)req_len >= sizeof(req_buf)) {
    return AK_E_OVERFLOW;
  }

  /* Make syscall */
  char resp_buf[RESP_BUF_SIZE];
  long result =
      ak_raw_syscall(AK_SYS_CALL, req_buf, req_len, resp_buf, sizeof(resp_buf));

  if (result < 0) {
    return (ak_err_t)result;
  }

  /* Copy response (could parse "result" field, but return whole response) */
  size_t copy_len = (size_t)result < max_len ? (size_t)result : max_len;
  memcpy(out_result, resp_buf, copy_len);
  *out_len = copy_len;

  return AK_OK;
}

/**
 * List available tools.
 *
 * Request: {"query": "tools"}
 * Response: {"tools": [...]}
 */
ak_err_t ak_list_tools(uint8_t *out_tools, size_t max_len, size_t *out_len) {
  if (!out_tools || !out_len) {
    return AK_E_INVAL;
  }

  const char *req_buf = "{\"query\":\"tools\"}";
  size_t req_len = strlen(req_buf);

  char resp_buf[RESP_BUF_SIZE];
  long result = ak_raw_syscall(AK_SYS_QUERY, req_buf, req_len, resp_buf,
                               sizeof(resp_buf));

  if (result < 0) {
    return (ak_err_t)result;
  }

  size_t copy_len = (size_t)result < max_len ? (size_t)result : max_len;
  memcpy(out_tools, resp_buf, copy_len);
  *out_len = copy_len;

  return AK_OK;
}

/* ============================================================================
   LLM INFERENCE
   ============================================================================
 */

/**
 * Request LLM inference.
 *
 * Request: {"model": "<name>", "max_tokens": N, "prompt": "<text>"}
 * Response: {"response": "<text>", "tokens_used": N}
 */
ak_err_t ak_inference(const ak_inference_req_t *req, uint8_t *out_response,
                      size_t max_len, size_t *out_len) {
  if (!req || !out_response || !out_len) {
    return AK_E_INVAL;
  }

  /* Build JSON request - escape prompt for JSON */
  char req_buf[8192];
  int req_len = snprintf(
      req_buf, sizeof(req_buf),
      "{\"model\":\"%s\",\"max_tokens\":%u,\"prompt\":\"%.*s\"}", req->model,
      req->max_tokens, (int)req->prompt_len, (const char *)req->prompt);

  if (req_len < 0 || (size_t)req_len >= sizeof(req_buf)) {
    return AK_E_OVERFLOW;
  }

  char resp_buf[RESP_BUF_SIZE];
  long result = ak_raw_syscall(AK_SYS_INFERENCE, req_buf, req_len, resp_buf,
                               sizeof(resp_buf));

  if (result < 0) {
    return (ak_err_t)result;
  }

  size_t copy_len = (size_t)result < max_len ? (size_t)result : max_len;
  memcpy(out_response, resp_buf, copy_len);
  *out_len = copy_len;

  return AK_OK;
}

/* ============================================================================
   POLICY & AUTHORIZATION
   ============================================================================
 */

/**
 * Check if operation is authorized.
 *
 * Request: {"check": "<op>", "target": "<path>"}
 * Response: {"allowed": true/false}
 */
ak_err_t ak_authorize(uint16_t effect_op, const char *target) {
  if (!target) {
    return AK_E_INVAL;
  }

  char req_buf[1024];
  int req_len = snprintf(req_buf, sizeof(req_buf),
                         "{\"check\":%u,\"target\":\"%s\"}", effect_op, target);

  if (req_len < 0 || (size_t)req_len >= sizeof(req_buf)) {
    return AK_E_OVERFLOW;
  }

  char resp_buf[RESP_BUF_SIZE];
  long result = ak_raw_syscall(AK_SYS_QUERY, req_buf, req_len, resp_buf,
                               sizeof(resp_buf));

  if (result < 0) {
    return (ak_err_t)result;
  }

  /* Check if allowed */
  if (strstr(resp_buf, "\"allowed\":true") ||
      strstr(resp_buf, "\"allowed\": true")) {
    return AK_OK;
  }

  return AK_E_DENIED;
}

ak_err_t ak_authorize_details(uint16_t effect_op, const char *target,
                              uint8_t *out_details, size_t max_len) {
  if (!target || !out_details) {
    return AK_E_INVAL;
  }

  char req_buf[1024];
  int req_len = snprintf(req_buf, sizeof(req_buf),
                         "{\"query\":\"auth\",\"op\":%u,\"target\":\"%s\"}",
                         effect_op, target);

  if (req_len < 0 || (size_t)req_len >= sizeof(req_buf)) {
    return AK_E_OVERFLOW;
  }

  char resp_buf[RESP_BUF_SIZE];
  long result = ak_raw_syscall(AK_SYS_QUERY, req_buf, req_len, resp_buf,
                               sizeof(resp_buf));

  if (result < 0) {
    return (ak_err_t)result;
  }

  size_t copy_len = (size_t)result < max_len ? (size_t)result : max_len;
  memcpy(out_details, resp_buf, copy_len);

  return AK_OK;
}

/* ============================================================================
   BUDGET TRACKING
   ============================================================================
 */

ak_err_t ak_budget_status(const char *resource_type, uint64_t *out_used,
                          uint64_t *out_remaining) {
  if (!resource_type || !out_used || !out_remaining) {
    return AK_E_INVAL;
  }

  char req_buf[256];
  int req_len =
      snprintf(req_buf, sizeof(req_buf),
               "{\"query\":\"budget\",\"resource\":\"%s\"}", resource_type);

  if (req_len < 0 || (size_t)req_len >= sizeof(req_buf)) {
    return AK_E_OVERFLOW;
  }

  char resp_buf[RESP_BUF_SIZE];
  long result = ak_raw_syscall(AK_SYS_QUERY, req_buf, req_len, resp_buf,
                               sizeof(resp_buf));

  if (result < 0) {
    return (ak_err_t)result;
  }

  *out_used = json_get_u64(resp_buf, result, "used");
  *out_remaining = json_get_u64(resp_buf, result, "remaining");

  return AK_OK;
}

ak_err_t ak_budget_reserve(const char *resource_type, uint64_t amount) {
  if (!resource_type) {
    return AK_E_INVAL;
  }

  char req_buf[256];
  int req_len =
      snprintf(req_buf, sizeof(req_buf), "{\"reserve\":\"%s\",\"amount\":%lu}",
               resource_type, (unsigned long)amount);

  if (req_len < 0 || (size_t)req_len >= sizeof(req_buf)) {
    return AK_E_OVERFLOW;
  }

  char resp_buf[RESP_BUF_SIZE];
  long result = ak_raw_syscall(AK_SYS_ALLOC, req_buf, req_len, resp_buf,
                               sizeof(resp_buf));

  if (result < 0) {
    return (ak_err_t)result;
  }

  return AK_OK;
}

/* ============================================================================
   AUDIT & LOGGING
   ============================================================================
 */

/**
 * Log audit event.
 *
 * Request: {"event": "<type>", "details": <json>}
 */
ak_err_t ak_audit_log(const char *event_type, const uint8_t *details,
                      size_t details_len) {
  if (!event_type) {
    return AK_E_INVAL;
  }

  char req_buf[2048];
  int req_len;

  if (details && details_len > 0) {
    req_len = snprintf(req_buf, sizeof(req_buf),
                       "{\"event\":\"%s\",\"details\":%.*s}", event_type,
                       (int)details_len, (const char *)details);
  } else {
    req_len =
        snprintf(req_buf, sizeof(req_buf), "{\"event\":\"%s\"}", event_type);
  }

  if (req_len < 0 || (size_t)req_len >= sizeof(req_buf)) {
    return AK_E_OVERFLOW;
  }

  char resp_buf[RESP_BUF_SIZE];
  long result = ak_raw_syscall(AK_SYS_ASSERT, req_buf, req_len, resp_buf,
                               sizeof(resp_buf));

  if (result < 0) {
    return (ak_err_t)result;
  }

  return AK_OK;
}

ak_err_t ak_get_last_denial(uint8_t *out_reason, size_t max_len) {
  if (!out_reason) {
    return AK_E_INVAL;
  }

  const char *req_buf = "{\"query\":\"last_denial\"}";
  size_t req_len = strlen(req_buf);

  char resp_buf[RESP_BUF_SIZE];
  long result = ak_raw_syscall(AK_SYS_QUERY, req_buf, req_len, resp_buf,
                               sizeof(resp_buf));

  if (result < 0) {
    return (ak_err_t)result;
  }

  size_t copy_len = (size_t)result < max_len ? (size_t)result : max_len;
  memcpy(out_reason, resp_buf, copy_len);

  return AK_OK;
}

/* ============================================================================
   CONVENIENCE FUNCTIONS
   ============================================================================
 */

ak_err_t ak_file_read(const char *path, uint8_t *out_data, size_t max_len,
                      size_t *out_len) {
  if (!path || !out_data || !out_len) {
    return AK_E_INVAL;
  }

  /* Use POSIX read - routes through policy in kernel */
  FILE *f = fopen(path, "rb");
  if (!f) {
    return AK_E_NOENT;
  }

  size_t n = fread(out_data, 1, max_len, f);
  int err_flag = ferror(f);
  fclose(f);

  if (err_flag) {
    return AK_E_INVAL;
  }

  *out_len = n;
  return AK_OK;
}

ak_err_t ak_file_write(const char *path, const uint8_t *data, size_t len) {
  if (!path || !data) {
    return AK_E_INVAL;
  }

  FILE *f = fopen(path, "wb");
  if (!f) {
    return AK_E_NOENT;
  }

  size_t n = fwrite(data, 1, len, f);
  fclose(f);

  if (n != len) {
    return AK_E_OVERFLOW;
  }

  return AK_OK;
}

ak_err_t ak_http_request(const char *method, const char *url,
                         const uint8_t *body, size_t body_len,
                         uint8_t *out_response, size_t max_len,
                         size_t *out_len) {
  if (!method || !url || !out_response || !out_len) {
    return AK_E_INVAL;
  }

  if (body_len > 0 && !body) {
    return AK_E_INVAL;
  }

  /* Build tool call for http_request */
  ak_tool_call_t tool_call = {0};
  strncpy(tool_call.tool_name, "http_request", sizeof(tool_call.tool_name) - 1);

  int json_len =
      snprintf((char *)tool_call.args_json, sizeof(tool_call.args_json),
               "{\"method\":\"%s\",\"url\":\"%s\",\"body_len\":%zu}", method,
               url, body_len);

  if (json_len < 0 || (size_t)json_len >= sizeof(tool_call.args_json)) {
    return AK_E_OVERFLOW;
  }

  tool_call.args_len = (uint32_t)json_len;

  return ak_call_tool(&tool_call, out_response, max_len, out_len);
}

/* ============================================================================
   ERROR HANDLING
   ============================================================================
 */

const char *ak_strerror(ak_err_t err) {
  switch (err) {
  case AK_OK:
    return "Success";
  case AK_E_DENIED:
    return "Operation denied by policy";
  case AK_E_CAP_INVALID:
    return "Invalid capability";
  case AK_E_CAP_EXPIRED:
    return "Capability expired";
  case AK_E_CAP_REVOKED:
    return "Capability revoked";
  case AK_E_BUDGET:
    return "Budget exceeded";
  case AK_E_NOMEM:
    return "Out of memory";
  case AK_E_INVAL:
    return "Invalid argument";
  case AK_E_NOENT:
    return "Not found";
  case AK_E_OVERFLOW:
    return "Buffer overflow";
  case AK_E_TIMEOUT:
    return "Operation timeout";
  default:
    if (err < 0) {
      /* Map Linux errno to description */
      static char buf[64];
      snprintf(buf, sizeof(buf), "System error %d", -err);
      return buf;
    }
    return "Unknown error";
  }
}

bool ak_is_fatal(ak_err_t err) {
  switch (err) {
  case AK_E_CAP_REVOKED:
  case AK_E_NOMEM:
    return true;
  default:
    return false;
  }
}

/* ============================================================================
   DEBUG & INTROSPECTION
   ============================================================================
 */

static bool debug_enabled = false;

ak_err_t ak_get_context(uint8_t *out_info, size_t max_len) {
  if (!out_info) {
    return AK_E_INVAL;
  }

  const char *req_buf = "{\"query\":\"context\"}";
  size_t req_len = strlen(req_buf);

  char resp_buf[RESP_BUF_SIZE];
  long result = ak_raw_syscall(AK_SYS_QUERY, req_buf, req_len, resp_buf,
                               sizeof(resp_buf));

  if (result < 0) {
    return (ak_err_t)result;
  }

  size_t copy_len = (size_t)result < max_len ? (size_t)result : max_len;
  memcpy(out_info, resp_buf, copy_len);

  return AK_OK;
}

void ak_debug_enable(void) { debug_enabled = true; }

void ak_debug_disable(void) { debug_enabled = false; }
