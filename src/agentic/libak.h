/**
 * libak.h - The Authority Kernel C Library API
 *
 * Public interface for userspace applications to interact with the Authority
 * Kernel through syscalls and system calls.
 */

#ifndef __LIBAK_H__
#define __LIBAK_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
   SYSCALL NUMBERS
   ============================================================================
 */

enum {
  AK_SYS_READ = 1024,
  AK_SYS_ALLOC = 1025,
  AK_SYS_WRITE = 1026,
  AK_SYS_DELETE = 1027,
  AK_SYS_QUERY = 1028,
  AK_SYS_BATCH = 1029,
  AK_SYS_COMMIT = 1030,
  AK_SYS_CALL = 1031,
  AK_SYS_SPAWN = 1032,
  AK_SYS_SEND = 1033,
  AK_SYS_RECV = 1034,
  AK_SYS_RESPOND = 1035,
  AK_SYS_ASSERT = 1036,
  AK_SYS_INFERENCE = 1037,
};

/* ============================================================================
   ERROR CODES
   ============================================================================
 */

typedef int32_t ak_err_t;

enum {
  AK_OK = 0,
  AK_E_DENIED = -1,      /* Operation denied by policy */
  AK_E_CAP_INVALID = -2, /* Invalid capability */
  AK_E_CAP_EXPIRED = -3, /* Capability expired */
  AK_E_CAP_REVOKED = -4, /* Capability revoked */
  AK_E_BUDGET = -5,      /* Budget exceeded */
  AK_E_NOMEM = -6,       /* Out of memory */
  AK_E_INVAL = -7,       /* Invalid argument */
  AK_E_NOENT = -8,       /* Not found */
  AK_E_OVERFLOW = -9,    /* Buffer overflow */
  AK_E_TIMEOUT = -10,    /* Operation timeout */
};

/* ============================================================================
   DATA STRUCTURES
   ============================================================================
 */

typedef struct {
  uint64_t id;
  uint32_t version;
} ak_handle_t;

typedef struct {
  uint16_t op;
  uint16_t trace_id;
  char target[512];
  uint8_t params[1024];
  uint32_t params_len;
} ak_effect_req_t;

typedef struct {
  uint8_t result[1024];
  uint32_t result_len;
} ak_effect_resp_t;

typedef struct {
  char tool_name[64];
  uint8_t args_json[2048];
  uint32_t args_len;
} ak_tool_call_t;

typedef struct {
  char model[64];
  uint32_t max_tokens;
  uint8_t prompt[4096];
  uint32_t prompt_len;
} ak_inference_req_t;

typedef struct {
  uint8_t token[256];
  uint32_t ttl_ms;
} ak_capability_t;

/* ============================================================================
   INITIALIZATION
   ============================================================================
 */

/**
 * Initialize the libak library
 * Must be called once before using other functions
 */
ak_err_t ak_init(void);

/**
 * Shutdown the libak library and cleanup resources
 */
void ak_shutdown(void);

/* ============================================================================
   LOW-LEVEL SYSCALL
   ============================================================================
 */

/**
 * Low-level syscall wrapper for AK syscalls (1024-1100)
 * Returns AK_OK on success, or negative error code on failure
 */
ak_err_t ak_syscall(uint64_t sysnum, uint64_t arg0, uint64_t arg1,
                    uint64_t arg2, uint64_t arg3, uint64_t arg4);

/* ============================================================================
   TYPED HEAP OPERATIONS
   ============================================================================
 */

/**
 * Allocate an object in the typed heap
 * Returns handle to the allocated object, or error code
 */
ak_err_t ak_alloc(const char *type_name, const uint8_t *initial_value,
                  size_t value_len, ak_handle_t *out_handle);

/**
 * Read an object from the typed heap
 * Returns AK_OK and fills out_value, or error code
 */
ak_err_t ak_read(ak_handle_t handle, uint8_t *out_value, size_t max_len,
                 size_t *out_len);

/**
 * Update an object with JSON Patch (CAS semantics)
 * Returns AK_OK and new version, or error code
 */
ak_err_t ak_write(ak_handle_t handle, const uint8_t *patch, size_t patch_len,
                  uint32_t expected_version, uint32_t *out_new_version);

/**
 * Delete an object from the typed heap
 */
ak_err_t ak_delete(ak_handle_t handle);

/* ============================================================================
   TOOL EXECUTION
   ============================================================================
 */

/**
 * Call a tool with JSON arguments
 * Returns AK_OK and fills out_result, or error code
 */
ak_err_t ak_call_tool(const ak_tool_call_t *tool_call, uint8_t *out_result,
                      size_t max_len, size_t *out_len);

/**
 * List available tools
 * Returns AK_OK and fills out_tools with JSON list, or error code
 */
ak_err_t ak_list_tools(uint8_t *out_tools, size_t max_len, size_t *out_len);

/* ============================================================================
   LLM INFERENCE
   ============================================================================
 */

/**
 * Invoke LLM for inference
 * Returns AK_OK and fills out_response, or error code
 */
ak_err_t ak_inference(const ak_inference_req_t *req, uint8_t *out_response,
                      size_t max_len, size_t *out_len);

/* ============================================================================
   AUTHORIZATION & CAPABILITIES
   ============================================================================
 */

/**
 * Check if operation is authorized by policy
 * Returns AK_OK if authorized, or AK_E_DENIED if not
 */
ak_err_t ak_authorize(uint16_t effect_op, const char *target);

/**
 * Get detailed authorization information
 * Returns AK_OK and fills out_details with JSON, or error code
 */
ak_err_t ak_authorize_details(uint16_t effect_op, const char *target,
                              uint8_t *out_details, size_t max_len);

/* ============================================================================
   BUDGET TRACKING
   ============================================================================
 */

/**
 * Get current budget status for a resource type
 * Returns AK_OK and fills out_used/out_remaining, or error code
 */
ak_err_t ak_budget_status(const char *resource_type, uint64_t *out_used,
                          uint64_t *out_remaining);

/**
 * Reserve budget for a resource type
 * Returns AK_OK if reserved, or AK_E_BUDGET if insufficient, or error code
 */
ak_err_t ak_budget_reserve(const char *resource_type, uint64_t amount);

/* ============================================================================
   AUDIT & LOGGING
   ============================================================================
 */

/**
 * Write an event to the audit log
 * Returns AK_OK on success, or error code
 */
ak_err_t ak_audit_log(const char *event_type, const uint8_t *details,
                      size_t details_len);

/**
 * Get the last denial reason from the kernel
 * Returns AK_OK and fills out_reason, or error code
 */
ak_err_t ak_get_last_denial(uint8_t *out_reason, size_t max_len);

/* ============================================================================
   FILE I/O
   ============================================================================
 */

/**
 * Read file with policy enforcement
 * Returns AK_OK and fills out_data, or error code
 */
ak_err_t ak_file_read(const char *path, uint8_t *out_data, size_t max_len,
                      size_t *out_len);

/**
 * Write file with policy enforcement
 * Returns AK_OK on success, or error code
 */
ak_err_t ak_file_write(const char *path, const uint8_t *data, size_t len);

/* ============================================================================
   HTTP REQUESTS
   ============================================================================
 */

/**
 * Make HTTP request with policy enforcement
 * Returns AK_OK and fills out_response, or error code
 */
ak_err_t ak_http_request(const char *method, const char *url,
                         const uint8_t *body, size_t body_len,
                         uint8_t *out_response, size_t max_len,
                         size_t *out_len);

/* ============================================================================
   ERROR HANDLING & INTROSPECTION
   ============================================================================
 */

/**
 * Get human-readable error message for error code
 */
const char *ak_strerror(ak_err_t err);

/**
 * Check if error is fatal (should terminate)
 */
bool ak_is_fatal(ak_err_t err);

/**
 * Get kernel context information as JSON
 * Returns AK_OK and fills out_info, or error code
 */
ak_err_t ak_get_context(uint8_t *out_info, size_t max_len);

/**
 * Enable debug logging in libak
 */
void ak_debug_enable(void);

/**
 * Disable debug logging in libak
 */
void ak_debug_disable(void);

#ifdef __cplusplus
}
#endif

#endif /* __LIBAK_H__ */
