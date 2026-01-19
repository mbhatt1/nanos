/**
 * libak - The Authority Kernel C Library Implementation
 */

#include "libak.h"
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>

/* ============================================================================
   SYSCALL WRAPPER
   ============================================================================ */

/**
 * Low-level syscall wrapper
 * Invokes AK syscalls (1024-1100)
 */
ak_err_t ak_syscall(uint64_t sysnum, uint64_t arg0, uint64_t arg1,
                    uint64_t arg2, uint64_t arg3, uint64_t arg4)
{
    long result;

    result = syscall(sysnum, arg0, arg1, arg2, arg3, arg4);

    if (result < 0) {
        return (ak_err_t)result;
    }
    return AK_OK;
}

/* ============================================================================
   INITIALIZATION
   ============================================================================ */

static bool libak_initialized = false;

ak_err_t ak_init(void)
{
    if (libak_initialized) {
        return AK_OK;
    }

    libak_initialized = true;
    return AK_OK;
}

void ak_shutdown(void)
{
    libak_initialized = false;
}

/* ============================================================================
   TYPED HEAP OPERATIONS
   ============================================================================ */

ak_err_t ak_alloc(const char *type_name, const uint8_t *initial_value,
                  size_t value_len, ak_handle_t *out_handle)
{
    if (!type_name || !out_handle) {
        return AK_E_INVAL;
    }

    if (value_len > sizeof(((ak_effect_req_t *)0)->params)) {
        return AK_E_OVERFLOW;
    }

    ak_effect_req_t req = {
        .op = AK_SYS_ALLOC,
        .trace_id = 0,
    };

    /* Pack type name into target */
    strncpy(req.target, type_name, sizeof(req.target) - 1);

    /* Pack initial value into params */
    if (initial_value && value_len > 0) {
        memcpy(req.params, initial_value, value_len);
    }
    req.params_len = value_len;

    /* Make syscall */
    ak_effect_resp_t resp = {0};
    ak_err_t err = ak_syscall(AK_SYS_ALLOC, (uint64_t)&req, (uint64_t)&resp, 0, 0, 0);

    if (err == AK_OK && out_handle) {
        /* Parse handle from response */
        if (resp.result_len >= sizeof(ak_handle_t)) {
            memcpy(out_handle, resp.result, sizeof(ak_handle_t));
        }
    }

    return err;
}

ak_err_t ak_read(ak_handle_t handle, uint8_t *out_value,
                 size_t max_len, size_t *out_len)
{
    if (!out_value || !out_len) {
        return AK_E_INVAL;
    }

    ak_effect_req_t req = {
        .op = AK_SYS_READ,
        .trace_id = 0,
    };

    /* Pack handle into params */
    memcpy(req.params, &handle, sizeof(ak_handle_t));
    req.params_len = sizeof(ak_handle_t);

    ak_effect_resp_t resp = {0};
    ak_err_t err = ak_syscall(AK_SYS_READ, (uint64_t)&req, (uint64_t)&resp, 0, 0, 0);

    if (err == AK_OK) {
        size_t copy_len = (resp.result_len < max_len) ? resp.result_len : max_len;
        memcpy(out_value, resp.result, copy_len);
        *out_len = copy_len;
    }

    return err;
}

ak_err_t ak_write(ak_handle_t handle, const uint8_t *patch, size_t patch_len,
                  uint32_t expected_version, uint32_t *out_new_version)
{
    if (!patch) {
        return AK_E_INVAL;
    }

    if (patch_len > sizeof(((ak_effect_req_t *)0)->params) - sizeof(ak_handle_t) - 4) {
        return AK_E_OVERFLOW;
    }

    ak_effect_req_t req = {
        .op = AK_SYS_WRITE,
        .trace_id = 0,
    };

    /* Pack handle, version, and patch into params */
    uint8_t *p = req.params;
    memcpy(p, &handle, sizeof(ak_handle_t));
    p += sizeof(ak_handle_t);
    memcpy(p, &expected_version, sizeof(uint32_t));
    p += sizeof(uint32_t);
    memcpy(p, patch, patch_len);

    req.params_len = sizeof(ak_handle_t) + sizeof(uint32_t) + patch_len;

    ak_effect_resp_t resp = {0};
    ak_err_t err = ak_syscall(AK_SYS_WRITE, (uint64_t)&req, (uint64_t)&resp, 0, 0, 0);

    if (err == AK_OK && resp.result_len >= sizeof(uint32_t) && out_new_version) {
        memcpy(out_new_version, resp.result, sizeof(uint32_t));
    }

    return err;
}

ak_err_t ak_delete(ak_handle_t handle)
{
    ak_effect_req_t req = {
        .op = AK_SYS_DELETE,
        .trace_id = 0,
    };

    memcpy(req.params, &handle, sizeof(ak_handle_t));
    req.params_len = sizeof(ak_handle_t);

    ak_effect_resp_t resp = {0};
    return ak_syscall(AK_SYS_DELETE, (uint64_t)&req, (uint64_t)&resp, 0, 0, 0);
}

/* ============================================================================
   TOOL EXECUTION
   ============================================================================ */

ak_err_t ak_call_tool(const ak_tool_call_t *tool_call,
                      uint8_t *out_result, size_t max_len, size_t *out_len)
{
    if (!tool_call || !out_result || !out_len) {
        return AK_E_INVAL;
    }

    ak_effect_req_t req = {
        .op = AK_SYS_CALL,
        .trace_id = 0,
    };

    /* Pack tool call into target and params */
    strncpy(req.target, tool_call->tool_name, sizeof(req.target) - 1);

    if (tool_call->args_len > sizeof(req.params)) {
        return AK_E_OVERFLOW;
    }

    memcpy(req.params, tool_call->args_json, tool_call->args_len);
    req.params_len = tool_call->args_len;

    ak_effect_resp_t resp = {0};
    ak_err_t err = ak_syscall(AK_SYS_CALL, (uint64_t)&req, (uint64_t)&resp, 0, 0, 0);

    if (err == AK_OK) {
        size_t copy_len = (resp.result_len < max_len) ? resp.result_len : max_len;
        memcpy(out_result, resp.result, copy_len);
        *out_len = copy_len;
    }

    return err;
}

ak_err_t ak_list_tools(uint8_t *out_tools, size_t max_len, size_t *out_len)
{
    if (!out_tools || !out_len) {
        return AK_E_INVAL;
    }

    ak_effect_req_t req = {
        .op = AK_SYS_QUERY,
        .trace_id = 0,
    };

    strncpy(req.target, "tools", sizeof(req.target) - 1);
    req.target[sizeof(req.target) - 1] = '\0';
    req.params_len = 0;

    ak_effect_resp_t resp = {0};
    ak_err_t err = ak_syscall(AK_SYS_QUERY, (uint64_t)&req, (uint64_t)&resp, 0, 0, 0);

    if (err == AK_OK) {
        size_t copy_len = (resp.result_len < max_len) ? resp.result_len : max_len;
        memcpy(out_tools, resp.result, copy_len);
        *out_len = copy_len;
    }

    return err;
}

/* ============================================================================
   LLM INFERENCE
   ============================================================================ */

ak_err_t ak_inference(const ak_inference_req_t *req,
                      uint8_t *out_response, size_t max_len, size_t *out_len)
{
    if (!req || !out_response || !out_len) {
        return AK_E_INVAL;
    }

    if (req->prompt_len > sizeof(((ak_effect_req_t *)0)->params)) {
        return AK_E_OVERFLOW;
    }

    ak_effect_req_t effect_req = {
        .op = AK_SYS_INFERENCE,
        .trace_id = 0,
    };

    strncpy(effect_req.target, req->model, sizeof(effect_req.target) - 1);

    /* Pack max_tokens + prompt into params */
    uint8_t *p = effect_req.params;
    memcpy(p, &req->max_tokens, sizeof(uint32_t));
    p += sizeof(uint32_t);
    memcpy(p, req->prompt, req->prompt_len);

    effect_req.params_len = sizeof(uint32_t) + req->prompt_len;

    ak_effect_resp_t resp = {0};
    ak_err_t err = ak_syscall(AK_SYS_INFERENCE, (uint64_t)&effect_req,
                              (uint64_t)&resp, 0, 0, 0);

    if (err == AK_OK) {
        size_t copy_len = (resp.result_len < max_len) ? resp.result_len : max_len;
        memcpy(out_response, resp.result, copy_len);
        *out_len = copy_len;
    }

    return err;
}

/* ============================================================================
   POLICY & AUTHORIZATION
   ============================================================================ */

ak_err_t ak_authorize(uint16_t effect_op, const char *target)
{
    if (!target) {
        return AK_E_INVAL;
    }

    ak_effect_req_t req = {
        .op = effect_op,
        .trace_id = 0,
    };

    strncpy(req.target, target, sizeof(req.target) - 1);
    req.params_len = 0;

    ak_effect_resp_t resp = {0};
    return ak_syscall(effect_op, (uint64_t)&req, (uint64_t)&resp, 0, 0, 0);
}

ak_err_t ak_authorize_details(uint16_t effect_op, const char *target,
                              uint8_t *out_details, size_t max_len)
{
    if (!target || !out_details) {
        return AK_E_INVAL;
    }

    /* Query authorization details */
    ak_effect_req_t req = {
        .op = AK_SYS_QUERY,
        .trace_id = 0,
    };

    snprintf(req.target, sizeof(req.target), "auth:%u:%s", effect_op, target);
    req.params_len = 0;

    ak_effect_resp_t resp = {0};
    ak_err_t err = ak_syscall(AK_SYS_QUERY, (uint64_t)&req, (uint64_t)&resp, 0, 0, 0);

    if (err == AK_OK) {
        size_t copy_len = (resp.result_len < max_len) ? resp.result_len : max_len;
        memcpy(out_details, resp.result, copy_len);
    }

    return err;
}

/* ============================================================================
   BUDGET TRACKING
   ============================================================================ */

ak_err_t ak_budget_status(const char *resource_type,
                          uint64_t *out_used, uint64_t *out_remaining)
{
    if (!resource_type || !out_used || !out_remaining) {
        return AK_E_INVAL;
    }

    ak_effect_req_t req = {
        .op = AK_SYS_QUERY,
        .trace_id = 0,
    };

    snprintf(req.target, sizeof(req.target), "budget:%s", resource_type);
    req.params_len = 0;

    ak_effect_resp_t resp = {0};
    ak_err_t err = ak_syscall(AK_SYS_QUERY, (uint64_t)&req, (uint64_t)&resp, 0, 0, 0);

    if (err == AK_OK && resp.result_len >= sizeof(uint64_t) * 2) {
        memcpy(out_used, resp.result, sizeof(uint64_t));
        memcpy(out_remaining, resp.result + sizeof(uint64_t), sizeof(uint64_t));
    }

    return err;
}

ak_err_t ak_budget_reserve(const char *resource_type, uint64_t amount)
{
    if (!resource_type) {
        return AK_E_INVAL;
    }

    ak_effect_req_t req = {
        .op = AK_SYS_ALLOC,
        .trace_id = 0,
    };

    snprintf(req.target, sizeof(req.target), "budget:%s", resource_type);
    memcpy(req.params, &amount, sizeof(uint64_t));
    req.params_len = sizeof(uint64_t);

    ak_effect_resp_t resp = {0};
    return ak_syscall(AK_SYS_ALLOC, (uint64_t)&req, (uint64_t)&resp, 0, 0, 0);
}

/* ============================================================================
   AUDIT & LOGGING
   ============================================================================ */

ak_err_t ak_audit_log(const char *event_type, const uint8_t *details,
                      size_t details_len)
{
    if (!event_type) {
        return AK_E_INVAL;
    }

    ak_effect_req_t req = {
        .op = AK_SYS_ASSERT,
        .trace_id = 0,
    };

    strncpy(req.target, event_type, sizeof(req.target) - 1);

    if (details && details_len > 0) {
        if (details_len > sizeof(req.params)) {
            return AK_E_OVERFLOW;
        }
        memcpy(req.params, details, details_len);
        req.params_len = details_len;
    } else {
        req.params_len = 0;
    }

    ak_effect_resp_t resp = {0};
    return ak_syscall(AK_SYS_ASSERT, (uint64_t)&req, (uint64_t)&resp, 0, 0, 0);
}

ak_err_t ak_get_last_denial(uint8_t *out_reason, size_t max_len)
{
    if (!out_reason) {
        return AK_E_INVAL;
    }

    ak_effect_req_t req = {
        .op = AK_SYS_QUERY,
        .trace_id = 0,
    };

    strncpy(req.target, "last_denial", sizeof(req.target) - 1);
    req.target[sizeof(req.target) - 1] = '\0';
    req.params_len = 0;

    ak_effect_resp_t resp = {0};
    ak_err_t err = ak_syscall(AK_SYS_QUERY, (uint64_t)&req, (uint64_t)&resp, 0, 0, 0);

    if (err == AK_OK) {
        size_t copy_len = (resp.result_len < max_len) ? resp.result_len : max_len;
        memcpy(out_reason, resp.result, copy_len);
    }

    return err;
}

/* ============================================================================
   CONVENIENCE FUNCTIONS
   ============================================================================ */

ak_err_t ak_file_read(const char *path, uint8_t *out_data,
                      size_t max_len, size_t *out_len)
{
    if (!path || !out_data || !out_len) {
        return AK_E_INVAL;
    }

    /* Use POSIX read - routes through policy */
    FILE *f = fopen(path, "rb");
    if (!f) {
        return AK_E_NOENT;
    }

    size_t n = fread(out_data, 1, max_len, f);
    int err_flag = ferror(f);
    fclose(f);

    /* Check for I/O errors (not just EOF) */
    if (err_flag) {
        return AK_E_INVAL;  /* I/O error occurred */
    }

    *out_len = n;
    return AK_OK;
}

ak_err_t ak_file_write(const char *path, const uint8_t *data, size_t len)
{
    if (!path || !data) {
        return AK_E_INVAL;
    }

    /* Use POSIX write - routes through policy */
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
                         uint8_t *out_response, size_t max_len, size_t *out_len)
{
    if (!method || !url || !out_response || !out_len) {
        return AK_E_INVAL;
    }

    if (body_len > 0 && !body) {
        return AK_E_INVAL;
    }

    /* Use http_request tool through ak_call_tool */
    ak_tool_call_t tool_call = {0};
    snprintf(tool_call.tool_name, sizeof(tool_call.tool_name), "http_request");

    /* Construct JSON payload: {"method": "GET", "url": "...", "body_len": ...} */
    int json_len = snprintf((char *)tool_call.args_json, sizeof(tool_call.args_json),
                            "{\"method\":\"%s\",\"url\":\"%s\",\"body_len\":%zu}",
                            method, url, body_len);

    if (json_len < 0 || (size_t)json_len >= sizeof(tool_call.args_json)) {
        return AK_E_OVERFLOW;
    }

    tool_call.args_len = (uint32_t)json_len;

    /* If there's a body, validate it fits with the JSON metadata */
    if (body_len > 0) {
        /* Body is passed separately in the actual implementation */
        /* For now, we encode body_len in the JSON which the tool parses */
    }

    return ak_call_tool(&tool_call, out_response, max_len, out_len);
}

/* ============================================================================
   ERROR HANDLING
   ============================================================================ */

const char *ak_strerror(ak_err_t err)
{
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
        return "Unknown error";
    }
}

bool ak_is_fatal(ak_err_t err)
{
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
   ============================================================================ */

static bool debug_enabled = false;

ak_err_t ak_get_context(uint8_t *out_info, size_t max_len)
{
    if (!out_info) {
        return AK_E_INVAL;
    }

    ak_effect_req_t req = {
        .op = AK_SYS_QUERY,
        .trace_id = 0,
    };

    strncpy(req.target, "context", sizeof(req.target) - 1);
    req.target[sizeof(req.target) - 1] = '\0';
    req.params_len = 0;

    ak_effect_resp_t resp = {0};
    ak_err_t err = ak_syscall(AK_SYS_QUERY, (uint64_t)&req, (uint64_t)&resp, 0, 0, 0);

    if (err == AK_OK) {
        size_t copy_len = (resp.result_len < max_len) ? resp.result_len : max_len;
        memcpy(out_info, resp.result, copy_len);
    }

    return err;
}

void ak_debug_enable(void)
{
    debug_enabled = true;
}

void ak_debug_disable(void)
{
    debug_enabled = false;
}
