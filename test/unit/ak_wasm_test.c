/*
 * Authority Kernel - WASM Sandbox System Unit Tests
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Comprehensive tests for the WASM sandbox system:
 *   - Module management (loading, validation, hash computation)
 *   - Tool registry (registration, lookup, unregistration)
 *   - Execution context (creation, state transitions, resource tracking)
 *   - Async execution (suspension, resumption, timeouts)
 *   - Host function registration
 *   - Security (signature verification, capability gating)
 *   - Statistics tracking
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* ============================================================
 * TEST FRAMEWORK
 * ============================================================ */

#define test_assert(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "FAIL: %s at %s:%d\n", #expr, __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

#define test_assert_eq(a, b) do { \
    if ((a) != (b)) { \
        fprintf(stderr, "FAIL: %s != %s (%lld != %lld) at %s:%d\n", \
                #a, #b, (long long)(a), (long long)(b), __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

#define test_assert_neq(a, b) do { \
    if ((a) == (b)) { \
        fprintf(stderr, "FAIL: %s == %s at %s:%d\n", #a, #b, __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

#define test_assert_null(ptr) do { \
    if ((ptr) != NULL) { \
        fprintf(stderr, "FAIL: %s is not NULL at %s:%d\n", #ptr, __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

#define test_assert_not_null(ptr) do { \
    if ((ptr) == NULL) { \
        fprintf(stderr, "FAIL: %s is NULL at %s:%d\n", #ptr, __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

/* ============================================================
 * MOCK TYPE DEFINITIONS
 * ============================================================ */

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t s64;
typedef bool boolean;

#define AK_TOKEN_ID_SIZE        16
#define AK_HASH_SIZE            32
#define AK_KEY_SIZE             32
#define AK_ED25519_PUBLIC_KEY_SIZE  32
#define AK_ED25519_SIGNATURE_SIZE   64
#define AK_MAX_WASM_MODULES     64
#define AK_MAX_TOOLS            256
#define AK_MAX_HOST_FUNCTIONS   128

/* WASM Constants */
#define WASM_MAGIC              0x6d736100
#define WASM_VERSION            1

/* Resource limit defaults */
#define AK_WASM_DEFAULT_MAX_MEMORY      (64 * 1024 * 1024)
#define AK_WASM_DEFAULT_MAX_STACK       4096
#define AK_WASM_DEFAULT_MAX_INSTRUCTIONS (100 * 1000 * 1000)
#define AK_WASM_DEFAULT_MAX_RUNTIME_MS  30000
#define AK_WASM_MAX_CALL_DEPTH          16

/* Error codes */
#define AK_E_WASM_INVALID_MODULE    (-4500)
#define AK_E_WASM_LOAD_FAILED       (-4501)
#define AK_E_WASM_EXPORT_NOT_FOUND  (-4502)
#define AK_E_WASM_TYPE_MISMATCH     (-4503)
#define AK_E_WASM_TRAP              (-4504)
#define AK_E_WASM_OOM               (-4505)
#define AK_E_WASM_TIMEOUT           (-4506)
#define AK_E_WASM_HOST_ERROR        (-4507)
#define AK_E_WASM_DEPTH_EXCEEDED    (-4508)

#define AK_E_CAP_MISSING            (-4100)
#define AK_E_CAP_INVALID            (-4101)
#define AK_E_CAP_SCOPE              (-4103)
#define AK_E_CONFLICT               (-4400)
#define AK_E_TOOL_NOT_FOUND         (-4403)
#define AK_E_QUOTA_EXCEEDED         (-4303)

/* Capability types */
typedef enum ak_cap_type {
    AK_CAP_NONE = 0,
    AK_CAP_NET = 1,
    AK_CAP_FS = 2,
    AK_CAP_TOOL = 3,
    AK_CAP_SECRETS = 4,
    AK_CAP_SPAWN = 5,
    AK_CAP_HEAP = 6,
    AK_CAP_INFERENCE = 7,
    AK_CAP_IPC = 8,
    AK_CAP_ANY = 254,
    AK_CAP_ADMIN = 255,
} ak_cap_type_t;

/* WASM source types */
typedef enum ak_wasm_source {
    AK_WASM_SOURCE_EMBEDDED,
    AK_WASM_SOURCE_NETWORK,
    AK_WASM_SOURCE_HEAP,
} ak_wasm_source_t;

/* Execution states */
typedef enum ak_wasm_exec_state {
    AK_WASM_STATE_INIT,
    AK_WASM_STATE_RUNNING,
    AK_WASM_STATE_SUSPENDED,
    AK_WASM_STATE_COMPLETED,
    AK_WASM_STATE_FAILED,
    AK_WASM_STATE_TIMEOUT,
    AK_WASM_STATE_OOM,
} ak_wasm_exec_state_t;

/* Suspension reasons */
typedef enum ak_wasm_suspend_reason {
    AK_WASM_SUSPEND_NONE = 0,
    AK_WASM_SUSPEND_HOST_CALL,
    AK_WASM_SUSPEND_APPROVAL,
    AK_WASM_SUSPEND_RESOURCE,
    AK_WASM_SUSPEND_IO,
} ak_wasm_suspend_reason_t;

/* Mock buffer type */
typedef struct mock_buffer {
    u8 *data;
    u64 length;
    u64 capacity;
} mock_buffer_t;

/* Mock capability */
typedef struct ak_capability {
    ak_cap_type_t type;
    u8 resource[256];
    u16 resource_len;
    u8 run_id[AK_TOKEN_ID_SIZE];
    u8 tid[AK_TOKEN_ID_SIZE];
    boolean valid;
    boolean revoked;
} ak_capability_t;

/* Mock agent context */
typedef struct ak_agent_context {
    u8 pid[AK_TOKEN_ID_SIZE];
    u8 run_id[AK_TOKEN_ID_SIZE];
    boolean active;
} ak_agent_context_t;

/* WASM module structure */
typedef struct ak_wasm_module {
    u8 module_id[AK_TOKEN_ID_SIZE];
    char name[64];
    u8 hash[AK_HASH_SIZE];
    ak_wasm_source_t source;
    char source_url[256];
    mock_buffer_t *bytecode;
    u64 bytecode_len;
    char **export_names;
    u32 export_count;
    ak_cap_type_t required_caps[8];
    u32 required_cap_count;
    u64 max_memory;
    u64 max_stack;
    u64 max_instructions;
    u64 max_runtime_ms;
    boolean verified;
    boolean sandboxed;
    u8 signature[64];
    u8 signing_key[32];
    u64 loaded_ms;
    u64 last_used_ms;
    u64 invocation_count;
} ak_wasm_module_t;

/* Tool structure */
typedef struct ak_tool {
    char name[64];
    char description[256];
    ak_wasm_module_t *module;
    char export_name[64];
    ak_cap_type_t cap_type;
    char cap_resource[256];
    char *cap_methods[8];
    u32 cap_method_count;
    mock_buffer_t *input_schema;
    mock_buffer_t *output_schema;
    u32 default_rate_limit;
    u32 default_rate_window_ms;
    boolean log_args;
    boolean log_result;
    boolean sensitive;
} ak_tool_t;

/* Execution context */
typedef struct ak_wasm_suspension {
    ak_wasm_suspend_reason_t reason;
    u64 suspend_time_ms;
    void *resume_data;
    u64 resume_data_len;
    void *resume_callback;
    u64 timeout_ms;
    u64 approval_id;
} ak_wasm_suspension_t;

typedef struct ak_wasm_exec_ctx {
    u8 exec_id[AK_TOKEN_ID_SIZE];
    ak_agent_context_t *agent;
    ak_wasm_module_t *module;
    ak_tool_t *tool;
    ak_capability_t *cap;
    mock_buffer_t *input;
    mock_buffer_t *output;
    s64 result_code;
    ak_wasm_exec_state_t state;
    ak_wasm_suspension_t suspension;
    u64 instructions_used;
    u64 memory_used;
    u64 start_ms;
    u64 elapsed_ms;
    struct ak_wasm_exec_ctx *parent;
    u32 depth;
    char error_msg[256];
} ak_wasm_exec_ctx_t;

/* Host function entry */
typedef s64 (*ak_host_fn_t)(ak_wasm_exec_ctx_t *ctx, mock_buffer_t *args, mock_buffer_t **result);

typedef struct ak_host_fn_entry {
    char name[64];
    ak_host_fn_t fn;
    ak_cap_type_t cap_type;
    boolean async_capable;
} ak_host_fn_entry_t;

/* Statistics */
typedef struct ak_wasm_stats {
    u64 modules_loaded;
    u64 tools_registered;
    u64 executions_total;
    u64 executions_success;
    u64 executions_failed;
    u64 executions_timeout;
    u64 executions_oom;
    u64 total_instructions;
    u64 total_runtime_ms;
    u64 host_calls_total;
    u64 host_calls_denied;
    u64 signature_failures;
} ak_wasm_stats_t;

/* Response structure */
typedef struct ak_response {
    u8 pid[AK_TOKEN_ID_SIZE];
    u8 run_id[AK_TOKEN_ID_SIZE];
    s64 error_code;
    mock_buffer_t *result;
} ak_response_t;

/* ============================================================
 * MOCK STATE
 * ============================================================ */

static struct {
    boolean initialized;

    /* Module registry */
    ak_wasm_module_t *modules[AK_MAX_WASM_MODULES];
    u32 module_count;

    /* Tool registry */
    ak_tool_t *tools[AK_MAX_TOOLS];
    u32 tool_count;

    /* Host function registry */
    ak_host_fn_entry_t host_fns[AK_MAX_HOST_FUNCTIONS];
    u32 host_fn_count;

    /* Trusted Ed25519 keys */
    u8 trusted_keys[16][AK_ED25519_PUBLIC_KEY_SIZE];
    u32 trusted_key_count;

    /* Mock signature verification state */
    boolean next_sig_verify_result;

    /* Statistics */
    ak_wasm_stats_t stats;
} mock_state;

/* ============================================================
 * MOCK HELPER FUNCTIONS
 * ============================================================ */

static void generate_token_id(u8 *out)
{
    for (int i = 0; i < AK_TOKEN_ID_SIZE; i++)
        out[i] = (u8)(rand() & 0xFF);
}

static mock_buffer_t *mock_buffer_create(u64 capacity)
{
    mock_buffer_t *buf = calloc(1, sizeof(mock_buffer_t));
    if (!buf) return NULL;

    buf->data = calloc(1, capacity);
    if (!buf->data) {
        free(buf);
        return NULL;
    }

    buf->length = 0;
    buf->capacity = capacity;
    return buf;
}

static void mock_buffer_free(mock_buffer_t *buf)
{
    if (buf) {
        if (buf->data) free(buf->data);
        free(buf);
    }
}

static u64 mock_buffer_length(mock_buffer_t *buf)
{
    return buf ? buf->length : 0;
}

static u8 *mock_buffer_ref(mock_buffer_t *buf, u64 offset)
{
    if (!buf || offset >= buf->length) return NULL;
    return buf->data + offset;
}

static void mock_buffer_write(mock_buffer_t *buf, const void *data, u64 len)
{
    if (!buf || !data) return;
    if (buf->length + len > buf->capacity) return;

    memcpy(buf->data + buf->length, data, len);
    buf->length += len;
}

/* Create valid WASM bytecode header */
static mock_buffer_t *create_valid_wasm_bytecode(void)
{
    mock_buffer_t *buf = mock_buffer_create(256);
    if (!buf) return NULL;

    /* WASM magic: \0asm (little endian: 0x6d736100) */
    u8 header[8] = {0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00};
    mock_buffer_write(buf, header, 8);

    /* Add some dummy content */
    u8 content[24] = {0};
    mock_buffer_write(buf, content, 24);

    return buf;
}

/* Create invalid WASM bytecode (bad magic) */
static mock_buffer_t *create_invalid_wasm_bytecode(void)
{
    mock_buffer_t *buf = mock_buffer_create(256);
    if (!buf) return NULL;

    /* Invalid magic */
    u8 header[8] = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x00, 0x00, 0x00};
    mock_buffer_write(buf, header, 8);

    return buf;
}

/* Create WASM bytecode with wrong version */
static mock_buffer_t *create_wasm_wrong_version(void)
{
    mock_buffer_t *buf = mock_buffer_create(256);
    if (!buf) return NULL;

    /* Valid magic but wrong version (2 instead of 1) */
    u8 header[8] = {0x00, 0x61, 0x73, 0x6d, 0x02, 0x00, 0x00, 0x00};
    mock_buffer_write(buf, header, 8);

    return buf;
}

/* Create too-short bytecode */
static mock_buffer_t *create_short_wasm_bytecode(void)
{
    mock_buffer_t *buf = mock_buffer_create(4);
    if (!buf) return NULL;

    /* Only 4 bytes - too short */
    u8 data[4] = {0x00, 0x61, 0x73, 0x6d};
    mock_buffer_write(buf, data, 4);

    return buf;
}

/* ============================================================
 * MOCK WASM FUNCTIONS
 * ============================================================ */

static void mock_wasm_init(void)
{
    memset(&mock_state, 0, sizeof(mock_state));
    mock_state.initialized = true;
    mock_state.next_sig_verify_result = true;
}

static void mock_wasm_shutdown(void)
{
    /* Free all modules */
    for (u32 i = 0; i < mock_state.module_count; i++) {
        if (mock_state.modules[i]) {
            if (mock_state.modules[i]->bytecode) {
                mock_buffer_free(mock_state.modules[i]->bytecode);
            }
            free(mock_state.modules[i]);
            mock_state.modules[i] = NULL;
        }
    }

    /* Free all tools */
    for (u32 i = 0; i < mock_state.tool_count; i++) {
        if (mock_state.tools[i]) {
            free(mock_state.tools[i]);
            mock_state.tools[i] = NULL;
        }
    }

    mock_state.module_count = 0;
    mock_state.tool_count = 0;
    mock_state.host_fn_count = 0;
    mock_state.trusted_key_count = 0;
    mock_state.initialized = false;
}

/* Validate WASM header */
static boolean validate_wasm_header(mock_buffer_t *bytecode)
{
    if (mock_buffer_length(bytecode) < 8)
        return false;

    u8 *data = mock_buffer_ref(bytecode, 0);
    u32 magic = (u32)data[0] | ((u32)data[1] << 8) | ((u32)data[2] << 16) | ((u32)data[3] << 24);
    u32 version = (u32)data[4] | ((u32)data[5] << 8) | ((u32)data[6] << 16) | ((u32)data[7] << 24);

    return (magic == WASM_MAGIC) && (version == WASM_VERSION);
}

/* Compute module hash */
static void compute_module_hash(mock_buffer_t *bytecode, u8 *hash_out)
{
    u64 len = mock_buffer_length(bytecode);
    u8 *data = mock_buffer_ref(bytecode, 0);

    /* Simple FNV-1a hash for testing */
    u64 h = 0xcbf29ce484222325ULL;
    for (u64 i = 0; i < len; i++) {
        h ^= data[i];
        h *= 0x100000001b3ULL;
    }

    for (int i = 0; i < AK_HASH_SIZE; i++) {
        hash_out[i] = (h >> (i % 8 * 8)) & 0xff;
        if (i % 8 == 7)
            h = h * 0x100000001b3ULL + (u64)i;
    }
}

/* Mock Ed25519 verification */
static boolean mock_ed25519_verify(const u8 *message, u64 message_len,
                                    const u8 *signature,
                                    const u8 *public_key)
{
    (void)message;
    (void)message_len;
    (void)signature;
    (void)public_key;
    return mock_state.next_sig_verify_result;
}

/* Mock Ed25519 is trusted */
static boolean mock_ed25519_is_trusted(const u8 *public_key)
{
    for (u32 i = 0; i < mock_state.trusted_key_count; i++) {
        if (memcmp(mock_state.trusted_keys[i], public_key, AK_ED25519_PUBLIC_KEY_SIZE) == 0)
            return true;
    }
    return false;
}

/* Add trusted key */
static boolean mock_ed25519_add_trusted_key(const u8 *public_key)
{
    if (mock_state.trusted_key_count >= 16)
        return false;

    memcpy(mock_state.trusted_keys[mock_state.trusted_key_count],
           public_key, AK_ED25519_PUBLIC_KEY_SIZE);
    mock_state.trusted_key_count++;
    return true;
}

/* Load WASM module */
static ak_wasm_module_t *mock_wasm_module_load(
    const char *name,
    mock_buffer_t *bytecode,
    ak_wasm_source_t source,
    const char *source_url)
{
    if (!mock_state.initialized)
        return NULL;

    if (mock_state.module_count >= AK_MAX_WASM_MODULES)
        return NULL;

    if (!validate_wasm_header(bytecode))
        return NULL;

    ak_wasm_module_t *module = calloc(1, sizeof(ak_wasm_module_t));
    if (!module) return NULL;

    generate_token_id(module->module_id);

    size_t name_len = strlen(name);
    if (name_len >= sizeof(module->name))
        name_len = sizeof(module->name) - 1;
    memcpy(module->name, name, name_len);
    module->name[name_len] = '\0';

    compute_module_hash(bytecode, module->hash);

    module->source = source;
    if (source_url) {
        size_t url_len = strlen(source_url);
        if (url_len >= sizeof(module->source_url))
            url_len = sizeof(module->source_url) - 1;
        memcpy(module->source_url, source_url, url_len);
        module->source_url[url_len] = '\0';
    }

    /* Clone bytecode */
    module->bytecode = mock_buffer_create(bytecode->capacity);
    if (!module->bytecode) {
        free(module);
        return NULL;
    }
    mock_buffer_write(module->bytecode, bytecode->data, bytecode->length);
    module->bytecode_len = bytecode->length;

    /* Set defaults */
    module->max_memory = AK_WASM_DEFAULT_MAX_MEMORY;
    module->max_stack = AK_WASM_DEFAULT_MAX_STACK;
    module->max_instructions = AK_WASM_DEFAULT_MAX_INSTRUCTIONS;
    module->max_runtime_ms = AK_WASM_DEFAULT_MAX_RUNTIME_MS;
    module->sandboxed = true;
    module->verified = false;

    mock_state.modules[mock_state.module_count++] = module;
    mock_state.stats.modules_loaded++;

    return module;
}

/* Load verified module */
static ak_wasm_module_t *mock_wasm_module_load_verified(
    const char *name,
    mock_buffer_t *bytecode,
    ak_wasm_source_t source,
    const char *source_url,
    const u8 *signature,
    const u8 *public_key)
{
    if (!mock_state.initialized)
        return NULL;

    if (!signature || !public_key)
        return NULL;

    /* Check trusted key */
    if (!mock_ed25519_is_trusted(public_key)) {
        mock_state.stats.signature_failures++;
        return NULL;
    }

    /* Verify signature */
    if (!mock_ed25519_verify(mock_buffer_ref(bytecode, 0),
                             mock_buffer_length(bytecode),
                             signature, public_key)) {
        mock_state.stats.signature_failures++;
        return NULL;
    }

    /* Load normally */
    ak_wasm_module_t *module = mock_wasm_module_load(name, bytecode, source, source_url);
    if (!module)
        return NULL;

    /* Mark verified and copy signature info */
    module->verified = true;
    memcpy(module->signature, signature, AK_ED25519_SIGNATURE_SIZE);
    memcpy(module->signing_key, public_key, AK_ED25519_PUBLIC_KEY_SIZE);

    return module;
}

/* Unload module */
static void mock_wasm_module_unload(ak_wasm_module_t *module)
{
    if (!module) return;

    for (u32 i = 0; i < mock_state.module_count; i++) {
        if (mock_state.modules[i] == module) {
            if (module->bytecode)
                mock_buffer_free(module->bytecode);
            free(module);

            for (u32 j = i; j < mock_state.module_count - 1; j++)
                mock_state.modules[j] = mock_state.modules[j + 1];
            mock_state.modules[--mock_state.module_count] = NULL;
            return;
        }
    }
}

/* Get module by name */
static ak_wasm_module_t *mock_wasm_module_get(const char *name)
{
    for (u32 i = 0; i < mock_state.module_count; i++) {
        if (mock_state.modules[i] && strcmp(mock_state.modules[i]->name, name) == 0)
            return mock_state.modules[i];
    }
    return NULL;
}

/* Get module by hash */
static ak_wasm_module_t *mock_wasm_module_get_by_hash(u8 *hash)
{
    for (u32 i = 0; i < mock_state.module_count; i++) {
        if (mock_state.modules[i] &&
            memcmp(mock_state.modules[i]->hash, hash, AK_HASH_SIZE) == 0)
            return mock_state.modules[i];
    }
    return NULL;
}

/* Register tool */
static s64 mock_tool_register(
    const char *name,
    ak_wasm_module_t *module,
    const char *export_name,
    ak_cap_type_t cap_type,
    const char *cap_resource)
{
    if (!mock_state.initialized)
        return AK_E_WASM_LOAD_FAILED;

    if (mock_state.tool_count >= AK_MAX_TOOLS)
        return AK_E_QUOTA_EXCEEDED;

    /* Check for duplicate name */
    for (u32 i = 0; i < mock_state.tool_count; i++) {
        if (mock_state.tools[i] && strcmp(mock_state.tools[i]->name, name) == 0)
            return AK_E_CONFLICT;
    }

    ak_tool_t *tool = calloc(1, sizeof(ak_tool_t));
    if (!tool) return AK_E_WASM_OOM;

    size_t name_len = strlen(name);
    if (name_len >= sizeof(tool->name))
        name_len = sizeof(tool->name) - 1;
    memcpy(tool->name, name, name_len);

    size_t export_len = strlen(export_name);
    if (export_len >= sizeof(tool->export_name))
        export_len = sizeof(tool->export_name) - 1;
    memcpy(tool->export_name, export_name, export_len);

    tool->module = module;
    tool->cap_type = cap_type;

    if (cap_resource) {
        size_t res_len = strlen(cap_resource);
        if (res_len >= sizeof(tool->cap_resource))
            res_len = sizeof(tool->cap_resource) - 1;
        memcpy(tool->cap_resource, cap_resource, res_len);
    }

    tool->default_rate_limit = 100;
    tool->default_rate_window_ms = 60000;
    tool->log_args = true;
    tool->log_result = true;
    tool->sensitive = false;

    mock_state.tools[mock_state.tool_count++] = tool;
    mock_state.stats.tools_registered++;

    return 0;
}

/* Unregister tool */
static void mock_tool_unregister(const char *name)
{
    for (u32 i = 0; i < mock_state.tool_count; i++) {
        if (mock_state.tools[i] && strcmp(mock_state.tools[i]->name, name) == 0) {
            free(mock_state.tools[i]);

            for (u32 j = i; j < mock_state.tool_count - 1; j++)
                mock_state.tools[j] = mock_state.tools[j + 1];
            mock_state.tools[--mock_state.tool_count] = NULL;
            return;
        }
    }
}

/* Get tool by name */
static ak_tool_t *mock_tool_get(const char *name)
{
    for (u32 i = 0; i < mock_state.tool_count; i++) {
        if (mock_state.tools[i] && strcmp(mock_state.tools[i]->name, name) == 0)
            return mock_state.tools[i];
    }
    return NULL;
}

/* Register host function */
static s64 mock_host_fn_register(
    const char *name,
    ak_host_fn_t fn,
    ak_cap_type_t cap_type,
    boolean async_capable)
{
    if (mock_state.host_fn_count >= AK_MAX_HOST_FUNCTIONS)
        return AK_E_QUOTA_EXCEEDED;

    ak_host_fn_entry_t *entry = &mock_state.host_fns[mock_state.host_fn_count];

    size_t name_len = strlen(name);
    if (name_len >= sizeof(entry->name))
        name_len = sizeof(entry->name) - 1;
    memcpy(entry->name, name, name_len);
    entry->name[name_len] = '\0';

    entry->fn = fn;
    entry->cap_type = cap_type;
    entry->async_capable = async_capable;

    mock_state.host_fn_count++;
    return 0;
}

/* Get host function */
static ak_host_fn_entry_t *mock_host_fn_get(const char *name)
{
    for (u32 i = 0; i < mock_state.host_fn_count; i++) {
        if (strcmp(mock_state.host_fns[i].name, name) == 0)
            return &mock_state.host_fns[i];
    }
    return NULL;
}

/* Create execution context */
static ak_wasm_exec_ctx_t *mock_exec_create(
    ak_agent_context_t *agent,
    ak_tool_t *tool,
    ak_capability_t *cap)
{
    ak_wasm_exec_ctx_t *ctx = calloc(1, sizeof(ak_wasm_exec_ctx_t));
    if (!ctx) return NULL;

    generate_token_id(ctx->exec_id);
    ctx->agent = agent;
    ctx->module = tool->module;
    ctx->tool = tool;
    ctx->cap = cap;
    ctx->state = AK_WASM_STATE_INIT;
    ctx->depth = 0;
    ctx->parent = NULL;

    return ctx;
}

/* Destroy execution context */
static void mock_exec_destroy(ak_wasm_exec_ctx_t *ctx)
{
    if (!ctx) return;

    /* Note: input is NOT freed here - it's owned by the caller */
    if (ctx->output) mock_buffer_free(ctx->output);
    if (ctx->suspension.resume_data)
        free(ctx->suspension.resume_data);

    free(ctx);
}

/* Suspend execution */
static s64 mock_exec_suspend(
    ak_wasm_exec_ctx_t *ctx,
    ak_wasm_suspend_reason_t reason,
    void *data,
    u64 data_len,
    void *resume_cb,
    u64 timeout_ms)
{
    if (!ctx) return AK_E_WASM_TRAP;
    if (ctx->state != AK_WASM_STATE_RUNNING) return AK_E_WASM_TRAP;

    ctx->state = AK_WASM_STATE_SUSPENDED;
    ctx->suspension.reason = reason;
    ctx->suspension.resume_callback = resume_cb;
    ctx->suspension.timeout_ms = timeout_ms;

    if (data && data_len > 0) {
        ctx->suspension.resume_data = malloc(data_len);
        if (!ctx->suspension.resume_data) {
            ctx->state = AK_WASM_STATE_OOM;
            return AK_E_WASM_OOM;
        }
        memcpy(ctx->suspension.resume_data, data, data_len);
        ctx->suspension.resume_data_len = data_len;
    }

    return 0;
}

/* Resume execution */
static s64 mock_exec_resume(ak_wasm_exec_ctx_t *ctx, void *result, u64 result_len)
{
    if (!ctx) return AK_E_WASM_TRAP;
    if (ctx->state != AK_WASM_STATE_SUSPENDED) return AK_E_WASM_TRAP;

    /* Free old data */
    if (ctx->suspension.resume_data) {
        free(ctx->suspension.resume_data);
        ctx->suspension.resume_data = NULL;
        ctx->suspension.resume_data_len = 0;
    }

    /* Store new result */
    if (result && result_len > 0) {
        ctx->suspension.resume_data = malloc(result_len);
        if (!ctx->suspension.resume_data) {
            ctx->state = AK_WASM_STATE_OOM;
            return AK_E_WASM_OOM;
        }
        memcpy(ctx->suspension.resume_data, result, result_len);
        ctx->suspension.resume_data_len = result_len;
    }

    ctx->state = AK_WASM_STATE_RUNNING;
    ctx->suspension.reason = AK_WASM_SUSPEND_NONE;

    return 0;
}

/* Run execution */
static s64 mock_exec_run(ak_wasm_exec_ctx_t *ctx, mock_buffer_t *input)
{
    if (!ctx || ctx->state != AK_WASM_STATE_INIT)
        return AK_E_WASM_TRAP;

    ctx->input = input;
    ctx->state = AK_WASM_STATE_RUNNING;

    /* Mock execution - create empty output */
    ctx->output = mock_buffer_create(64);
    if (!ctx->output) {
        ctx->state = AK_WASM_STATE_OOM;
        ctx->result_code = AK_E_WASM_OOM;
        mock_state.stats.executions_total++;
        mock_state.stats.executions_oom++;
        return AK_E_WASM_OOM;
    }

    mock_buffer_write(ctx->output, "{}", 2);
    ctx->state = AK_WASM_STATE_COMPLETED;
    ctx->result_code = 0;

    mock_state.stats.executions_total++;
    mock_state.stats.executions_success++;

    return 0;
}

/* Validate capability for tool execution */
static s64 mock_capability_validate(
    ak_capability_t *cap,
    ak_cap_type_t required_type,
    const char *resource,
    const char *method,
    u8 *run_id)
{
    (void)resource;
    (void)method;

    if (!cap) return AK_E_CAP_MISSING;
    if (!cap->valid) return AK_E_CAP_INVALID;

    if (cap->type != required_type && cap->type != AK_CAP_ANY)
        return AK_E_CAP_SCOPE;

    if (run_id && memcmp(cap->run_id, run_id, AK_TOKEN_ID_SIZE) != 0)
        return AK_E_CAP_SCOPE;

    return 0;
}

/* Execute tool */
static ak_response_t *mock_wasm_execute_tool(
    ak_agent_context_t *agent,
    const char *tool_name,
    mock_buffer_t *args,
    ak_capability_t *cap)
{
    ak_response_t *response = calloc(1, sizeof(ak_response_t));
    if (!response) return NULL;

    if (!mock_state.initialized) {
        response->error_code = AK_E_WASM_LOAD_FAILED;
        return response;
    }

    /* Look up tool */
    ak_tool_t *tool = mock_tool_get(tool_name);
    if (!tool) {
        response->error_code = AK_E_TOOL_NOT_FOUND;
        return response;
    }

    /* Validate capability (INV-2) */
    if (tool->cap_type != AK_CAP_NONE) {
        s64 result = mock_capability_validate(cap, tool->cap_type,
                                               tool->cap_resource, tool->name,
                                               agent->run_id);
        if (result != 0) {
            mock_state.stats.host_calls_denied++;
            response->error_code = result;
            return response;
        }
    }

    /* Create and run execution context */
    ak_wasm_exec_ctx_t *ctx = mock_exec_create(agent, tool, cap);
    if (!ctx) {
        response->error_code = AK_E_WASM_OOM;
        return response;
    }

    s64 result = mock_exec_run(ctx, args);

    if (result == 0 && ctx->state == AK_WASM_STATE_COMPLETED) {
        response->error_code = 0;
        response->result = ctx->output;
        ctx->output = NULL;
    } else {
        switch (ctx->state) {
        case AK_WASM_STATE_TIMEOUT:
            response->error_code = AK_E_WASM_TIMEOUT;
            mock_state.stats.executions_timeout++;
            break;
        case AK_WASM_STATE_OOM:
            response->error_code = AK_E_WASM_OOM;
            break;
        default:
            response->error_code = AK_E_WASM_TRAP;
            mock_state.stats.executions_failed++;
            break;
        }
    }

    if (tool->module) {
        tool->module->last_used_ms = 1000;
        tool->module->invocation_count++;
    }

    mock_exec_destroy(ctx);

    return response;
}

/* Get statistics */
static void mock_wasm_get_stats(ak_wasm_stats_t *stats)
{
    if (stats)
        memcpy(stats, &mock_state.stats, sizeof(ak_wasm_stats_t));
}

/* ============================================================
 * TEST CASES: MODULE MANAGEMENT
 * ============================================================ */

bool test_module_load_valid(void)
{
    mock_wasm_init();

    mock_buffer_t *bytecode = create_valid_wasm_bytecode();
    test_assert_not_null(bytecode);

    ak_wasm_module_t *module = mock_wasm_module_load(
        "test_module", bytecode, AK_WASM_SOURCE_EMBEDDED, NULL);

    test_assert_not_null(module);
    test_assert(strcmp(module->name, "test_module") == 0);
    test_assert_eq(module->source, AK_WASM_SOURCE_EMBEDDED);
    test_assert(module->sandboxed);
    test_assert(!module->verified);
    test_assert_eq(module->max_memory, AK_WASM_DEFAULT_MAX_MEMORY);

    mock_buffer_free(bytecode);
    mock_wasm_shutdown();
    return true;
}

bool test_module_load_invalid_magic(void)
{
    mock_wasm_init();

    mock_buffer_t *bytecode = create_invalid_wasm_bytecode();
    test_assert_not_null(bytecode);

    ak_wasm_module_t *module = mock_wasm_module_load(
        "bad_module", bytecode, AK_WASM_SOURCE_EMBEDDED, NULL);

    test_assert_null(module);

    mock_buffer_free(bytecode);
    mock_wasm_shutdown();
    return true;
}

bool test_module_load_wrong_version(void)
{
    mock_wasm_init();

    mock_buffer_t *bytecode = create_wasm_wrong_version();
    test_assert_not_null(bytecode);

    ak_wasm_module_t *module = mock_wasm_module_load(
        "bad_version", bytecode, AK_WASM_SOURCE_EMBEDDED, NULL);

    test_assert_null(module);

    mock_buffer_free(bytecode);
    mock_wasm_shutdown();
    return true;
}

bool test_module_load_too_short(void)
{
    mock_wasm_init();

    mock_buffer_t *bytecode = create_short_wasm_bytecode();
    test_assert_not_null(bytecode);

    ak_wasm_module_t *module = mock_wasm_module_load(
        "short_module", bytecode, AK_WASM_SOURCE_EMBEDDED, NULL);

    test_assert_null(module);

    mock_buffer_free(bytecode);
    mock_wasm_shutdown();
    return true;
}

bool test_module_hash_computation(void)
{
    mock_wasm_init();

    mock_buffer_t *bytecode = create_valid_wasm_bytecode();
    test_assert_not_null(bytecode);

    ak_wasm_module_t *module = mock_wasm_module_load(
        "hash_test", bytecode, AK_WASM_SOURCE_EMBEDDED, NULL);

    test_assert_not_null(module);

    /* Hash should be non-zero */
    bool all_zero = true;
    for (int i = 0; i < AK_HASH_SIZE; i++) {
        if (module->hash[i] != 0) {
            all_zero = false;
            break;
        }
    }
    test_assert(!all_zero);

    mock_buffer_free(bytecode);
    mock_wasm_shutdown();
    return true;
}

bool test_module_get_by_name(void)
{
    mock_wasm_init();

    mock_buffer_t *bytecode = create_valid_wasm_bytecode();
    ak_wasm_module_t *module = mock_wasm_module_load(
        "findme", bytecode, AK_WASM_SOURCE_EMBEDDED, NULL);

    test_assert_not_null(module);

    ak_wasm_module_t *found = mock_wasm_module_get("findme");
    test_assert_eq(found, module);

    ak_wasm_module_t *not_found = mock_wasm_module_get("notexist");
    test_assert_null(not_found);

    mock_buffer_free(bytecode);
    mock_wasm_shutdown();
    return true;
}

bool test_module_get_by_hash(void)
{
    mock_wasm_init();

    mock_buffer_t *bytecode = create_valid_wasm_bytecode();
    ak_wasm_module_t *module = mock_wasm_module_load(
        "hashfind", bytecode, AK_WASM_SOURCE_EMBEDDED, NULL);

    test_assert_not_null(module);

    ak_wasm_module_t *found = mock_wasm_module_get_by_hash(module->hash);
    test_assert_eq(found, module);

    u8 bad_hash[AK_HASH_SIZE] = {0xFF};
    ak_wasm_module_t *not_found = mock_wasm_module_get_by_hash(bad_hash);
    test_assert_null(not_found);

    mock_buffer_free(bytecode);
    mock_wasm_shutdown();
    return true;
}

bool test_module_unload(void)
{
    mock_wasm_init();

    mock_buffer_t *bytecode = create_valid_wasm_bytecode();
    ak_wasm_module_t *module = mock_wasm_module_load(
        "unloadme", bytecode, AK_WASM_SOURCE_EMBEDDED, NULL);

    test_assert_not_null(module);
    test_assert_eq(mock_state.module_count, 1);

    mock_wasm_module_unload(module);
    test_assert_eq(mock_state.module_count, 0);

    ak_wasm_module_t *not_found = mock_wasm_module_get("unloadme");
    test_assert_null(not_found);

    mock_buffer_free(bytecode);
    mock_wasm_shutdown();
    return true;
}

bool test_module_registry_limit(void)
{
    mock_wasm_init();

    mock_buffer_t *bytecode = create_valid_wasm_bytecode();
    test_assert_not_null(bytecode);

    /* Fill registry to max */
    for (int i = 0; i < AK_MAX_WASM_MODULES; i++) {
        char name[32];
        snprintf(name, sizeof(name), "module_%d", i);
        ak_wasm_module_t *m = mock_wasm_module_load(name, bytecode,
                                                     AK_WASM_SOURCE_EMBEDDED, NULL);
        test_assert_not_null(m);
    }

    test_assert_eq(mock_state.module_count, AK_MAX_WASM_MODULES);

    /* Next one should fail */
    ak_wasm_module_t *overflow = mock_wasm_module_load("overflow", bytecode,
                                                        AK_WASM_SOURCE_EMBEDDED, NULL);
    test_assert_null(overflow);

    mock_buffer_free(bytecode);
    mock_wasm_shutdown();
    return true;
}

bool test_module_with_source_url(void)
{
    mock_wasm_init();

    mock_buffer_t *bytecode = create_valid_wasm_bytecode();
    ak_wasm_module_t *module = mock_wasm_module_load(
        "network_mod", bytecode, AK_WASM_SOURCE_NETWORK, "https://example.com/module.wasm");

    test_assert_not_null(module);
    test_assert_eq(module->source, AK_WASM_SOURCE_NETWORK);
    test_assert(strcmp(module->source_url, "https://example.com/module.wasm") == 0);

    mock_buffer_free(bytecode);
    mock_wasm_shutdown();
    return true;
}

/* ============================================================
 * TEST CASES: VERIFIED MODULE LOADING
 * ============================================================ */

bool test_verified_module_load_success(void)
{
    mock_wasm_init();

    /* Add trusted key */
    u8 public_key[AK_ED25519_PUBLIC_KEY_SIZE] = {1, 2, 3, 4};
    mock_ed25519_add_trusted_key(public_key);

    mock_buffer_t *bytecode = create_valid_wasm_bytecode();
    u8 signature[AK_ED25519_SIGNATURE_SIZE] = {0xAA, 0xBB};

    mock_state.next_sig_verify_result = true;

    ak_wasm_module_t *module = mock_wasm_module_load_verified(
        "verified_mod", bytecode, AK_WASM_SOURCE_EMBEDDED, NULL,
        signature, public_key);

    test_assert_not_null(module);
    test_assert(module->verified);
    test_assert(memcmp(module->signing_key, public_key, AK_ED25519_PUBLIC_KEY_SIZE) == 0);

    mock_buffer_free(bytecode);
    mock_wasm_shutdown();
    return true;
}

bool test_verified_module_untrusted_key(void)
{
    mock_wasm_init();

    /* Key is NOT added to trusted set */
    u8 public_key[AK_ED25519_PUBLIC_KEY_SIZE] = {9, 9, 9, 9};
    u8 signature[AK_ED25519_SIGNATURE_SIZE] = {0xAA};

    mock_buffer_t *bytecode = create_valid_wasm_bytecode();

    ak_wasm_module_t *module = mock_wasm_module_load_verified(
        "untrusted", bytecode, AK_WASM_SOURCE_EMBEDDED, NULL,
        signature, public_key);

    test_assert_null(module);
    test_assert_eq(mock_state.stats.signature_failures, 1);

    mock_buffer_free(bytecode);
    mock_wasm_shutdown();
    return true;
}

bool test_verified_module_bad_signature(void)
{
    mock_wasm_init();

    /* Add trusted key */
    u8 public_key[AK_ED25519_PUBLIC_KEY_SIZE] = {1, 2, 3, 4};
    mock_ed25519_add_trusted_key(public_key);

    mock_buffer_t *bytecode = create_valid_wasm_bytecode();
    u8 signature[AK_ED25519_SIGNATURE_SIZE] = {0xAA};

    /* Force signature verification to fail */
    mock_state.next_sig_verify_result = false;

    ak_wasm_module_t *module = mock_wasm_module_load_verified(
        "badsig", bytecode, AK_WASM_SOURCE_EMBEDDED, NULL,
        signature, public_key);

    test_assert_null(module);
    test_assert_eq(mock_state.stats.signature_failures, 1);

    mock_buffer_free(bytecode);
    mock_wasm_shutdown();
    return true;
}

bool test_verified_module_null_params(void)
{
    mock_wasm_init();

    mock_buffer_t *bytecode = create_valid_wasm_bytecode();
    u8 public_key[AK_ED25519_PUBLIC_KEY_SIZE] = {1};
    u8 signature[AK_ED25519_SIGNATURE_SIZE] = {1};

    /* Null signature */
    ak_wasm_module_t *m1 = mock_wasm_module_load_verified(
        "null_sig", bytecode, AK_WASM_SOURCE_EMBEDDED, NULL,
        NULL, public_key);
    test_assert_null(m1);

    /* Null public key */
    ak_wasm_module_t *m2 = mock_wasm_module_load_verified(
        "null_key", bytecode, AK_WASM_SOURCE_EMBEDDED, NULL,
        signature, NULL);
    test_assert_null(m2);

    mock_buffer_free(bytecode);
    mock_wasm_shutdown();
    return true;
}

/* ============================================================
 * TEST CASES: TOOL REGISTRY
 * ============================================================ */

bool test_tool_register_basic(void)
{
    mock_wasm_init();

    mock_buffer_t *bytecode = create_valid_wasm_bytecode();
    ak_wasm_module_t *module = mock_wasm_module_load(
        "toolmod", bytecode, AK_WASM_SOURCE_EMBEDDED, NULL);

    s64 result = mock_tool_register("my_tool", module, "exported_fn",
                                     AK_CAP_NET, "*.example.com");

    test_assert_eq(result, 0);
    test_assert_eq(mock_state.tool_count, 1);

    ak_tool_t *tool = mock_tool_get("my_tool");
    test_assert_not_null(tool);
    test_assert(strcmp(tool->name, "my_tool") == 0);
    test_assert(strcmp(tool->export_name, "exported_fn") == 0);
    test_assert_eq(tool->cap_type, AK_CAP_NET);
    test_assert_eq(tool->module, module);

    mock_buffer_free(bytecode);
    mock_wasm_shutdown();
    return true;
}

bool test_tool_register_duplicate_name(void)
{
    mock_wasm_init();

    mock_buffer_t *bytecode = create_valid_wasm_bytecode();
    ak_wasm_module_t *module = mock_wasm_module_load(
        "toolmod", bytecode, AK_WASM_SOURCE_EMBEDDED, NULL);

    s64 result1 = mock_tool_register("same_name", module, "fn1", AK_CAP_NONE, NULL);
    test_assert_eq(result1, 0);

    s64 result2 = mock_tool_register("same_name", module, "fn2", AK_CAP_NONE, NULL);
    test_assert_eq(result2, AK_E_CONFLICT);

    test_assert_eq(mock_state.tool_count, 1);

    mock_buffer_free(bytecode);
    mock_wasm_shutdown();
    return true;
}

bool test_tool_unregister(void)
{
    mock_wasm_init();

    mock_buffer_t *bytecode = create_valid_wasm_bytecode();
    ak_wasm_module_t *module = mock_wasm_module_load(
        "toolmod", bytecode, AK_WASM_SOURCE_EMBEDDED, NULL);

    mock_tool_register("to_remove", module, "fn", AK_CAP_NONE, NULL);
    test_assert_eq(mock_state.tool_count, 1);

    mock_tool_unregister("to_remove");
    test_assert_eq(mock_state.tool_count, 0);

    ak_tool_t *not_found = mock_tool_get("to_remove");
    test_assert_null(not_found);

    mock_buffer_free(bytecode);
    mock_wasm_shutdown();
    return true;
}

bool test_tool_lookup_not_found(void)
{
    mock_wasm_init();

    ak_tool_t *tool = mock_tool_get("nonexistent");
    test_assert_null(tool);

    mock_wasm_shutdown();
    return true;
}

bool test_tool_capability_requirements(void)
{
    mock_wasm_init();

    mock_buffer_t *bytecode = create_valid_wasm_bytecode();
    ak_wasm_module_t *module = mock_wasm_module_load(
        "toolmod", bytecode, AK_WASM_SOURCE_EMBEDDED, NULL);

    /* Register tools with different capability requirements */
    mock_tool_register("net_tool", module, "fn", AK_CAP_NET, "api.example.com");
    mock_tool_register("fs_tool", module, "fn", AK_CAP_FS, "/data/*");
    mock_tool_register("any_tool", module, "fn", AK_CAP_NONE, NULL);

    ak_tool_t *net = mock_tool_get("net_tool");
    test_assert_eq(net->cap_type, AK_CAP_NET);

    ak_tool_t *fs = mock_tool_get("fs_tool");
    test_assert_eq(fs->cap_type, AK_CAP_FS);

    ak_tool_t *any = mock_tool_get("any_tool");
    test_assert_eq(any->cap_type, AK_CAP_NONE);

    mock_buffer_free(bytecode);
    mock_wasm_shutdown();
    return true;
}

/* ============================================================
 * TEST CASES: EXECUTION CONTEXT
 * ============================================================ */

bool test_exec_context_create(void)
{
    mock_wasm_init();

    mock_buffer_t *bytecode = create_valid_wasm_bytecode();
    ak_wasm_module_t *module = mock_wasm_module_load(
        "mod", bytecode, AK_WASM_SOURCE_EMBEDDED, NULL);
    mock_tool_register("tool", module, "fn", AK_CAP_NONE, NULL);

    ak_tool_t *tool = mock_tool_get("tool");
    ak_agent_context_t agent = {0};
    generate_token_id(agent.run_id);

    ak_wasm_exec_ctx_t *ctx = mock_exec_create(&agent, tool, NULL);

    test_assert_not_null(ctx);
    test_assert_eq(ctx->state, AK_WASM_STATE_INIT);
    test_assert_eq(ctx->agent, &agent);
    test_assert_eq(ctx->module, module);
    test_assert_eq(ctx->tool, tool);
    test_assert_eq(ctx->depth, 0);
    test_assert_null(ctx->parent);

    mock_exec_destroy(ctx);
    mock_buffer_free(bytecode);
    mock_wasm_shutdown();
    return true;
}

bool test_exec_state_transitions(void)
{
    mock_wasm_init();

    mock_buffer_t *bytecode = create_valid_wasm_bytecode();
    ak_wasm_module_t *module = mock_wasm_module_load(
        "mod", bytecode, AK_WASM_SOURCE_EMBEDDED, NULL);
    mock_tool_register("tool", module, "fn", AK_CAP_NONE, NULL);

    ak_tool_t *tool = mock_tool_get("tool");
    ak_agent_context_t agent = {0};

    ak_wasm_exec_ctx_t *ctx = mock_exec_create(&agent, tool, NULL);
    test_assert_eq(ctx->state, AK_WASM_STATE_INIT);

    mock_buffer_t *input = mock_buffer_create(64);
    mock_buffer_write(input, "{}", 2);

    s64 result = mock_exec_run(ctx, input);
    test_assert_eq(result, 0);
    test_assert_eq(ctx->state, AK_WASM_STATE_COMPLETED);

    mock_exec_destroy(ctx);
    mock_buffer_free(bytecode);
    mock_wasm_shutdown();
    return true;
}

bool test_exec_resource_tracking(void)
{
    mock_wasm_init();

    mock_buffer_t *bytecode = create_valid_wasm_bytecode();
    ak_wasm_module_t *module = mock_wasm_module_load(
        "mod", bytecode, AK_WASM_SOURCE_EMBEDDED, NULL);
    mock_tool_register("tool", module, "fn", AK_CAP_NONE, NULL);

    ak_tool_t *tool = mock_tool_get("tool");
    ak_agent_context_t agent = {0};

    ak_wasm_exec_ctx_t *ctx = mock_exec_create(&agent, tool, NULL);

    /* Initial resource tracking */
    test_assert_eq(ctx->instructions_used, 0);
    test_assert_eq(ctx->memory_used, 0);

    mock_exec_destroy(ctx);
    mock_buffer_free(bytecode);
    mock_wasm_shutdown();
    return true;
}

/* ============================================================
 * TEST CASES: ASYNC EXECUTION
 * ============================================================ */

bool test_exec_suspend_for_host_call(void)
{
    mock_wasm_init();

    mock_buffer_t *bytecode = create_valid_wasm_bytecode();
    ak_wasm_module_t *module = mock_wasm_module_load(
        "mod", bytecode, AK_WASM_SOURCE_EMBEDDED, NULL);
    mock_tool_register("tool", module, "fn", AK_CAP_NONE, NULL);

    ak_tool_t *tool = mock_tool_get("tool");
    ak_agent_context_t agent = {0};

    ak_wasm_exec_ctx_t *ctx = mock_exec_create(&agent, tool, NULL);
    ctx->state = AK_WASM_STATE_RUNNING;  /* Simulate running state */

    char data[] = "pending_call_data";
    s64 result = mock_exec_suspend(ctx, AK_WASM_SUSPEND_HOST_CALL,
                                    data, sizeof(data), NULL, 5000);

    test_assert_eq(result, 0);
    test_assert_eq(ctx->state, AK_WASM_STATE_SUSPENDED);
    test_assert_eq(ctx->suspension.reason, AK_WASM_SUSPEND_HOST_CALL);
    test_assert_eq(ctx->suspension.timeout_ms, 5000);
    test_assert_not_null(ctx->suspension.resume_data);

    mock_exec_destroy(ctx);
    mock_buffer_free(bytecode);
    mock_wasm_shutdown();
    return true;
}

bool test_exec_suspend_for_approval(void)
{
    mock_wasm_init();

    mock_buffer_t *bytecode = create_valid_wasm_bytecode();
    ak_wasm_module_t *module = mock_wasm_module_load(
        "mod", bytecode, AK_WASM_SOURCE_EMBEDDED, NULL);
    mock_tool_register("tool", module, "fn", AK_CAP_NONE, NULL);

    ak_tool_t *tool = mock_tool_get("tool");
    ak_agent_context_t agent = {0};

    ak_wasm_exec_ctx_t *ctx = mock_exec_create(&agent, tool, NULL);
    ctx->state = AK_WASM_STATE_RUNNING;

    s64 result = mock_exec_suspend(ctx, AK_WASM_SUSPEND_APPROVAL,
                                    NULL, 0, NULL, 0);

    test_assert_eq(result, 0);
    test_assert_eq(ctx->suspension.reason, AK_WASM_SUSPEND_APPROVAL);

    mock_exec_destroy(ctx);
    mock_buffer_free(bytecode);
    mock_wasm_shutdown();
    return true;
}

bool test_exec_resume_with_result(void)
{
    mock_wasm_init();

    mock_buffer_t *bytecode = create_valid_wasm_bytecode();
    ak_wasm_module_t *module = mock_wasm_module_load(
        "mod", bytecode, AK_WASM_SOURCE_EMBEDDED, NULL);
    mock_tool_register("tool", module, "fn", AK_CAP_NONE, NULL);

    ak_tool_t *tool = mock_tool_get("tool");
    ak_agent_context_t agent = {0};

    ak_wasm_exec_ctx_t *ctx = mock_exec_create(&agent, tool, NULL);
    ctx->state = AK_WASM_STATE_RUNNING;

    /* Suspend */
    mock_exec_suspend(ctx, AK_WASM_SUSPEND_HOST_CALL, NULL, 0, NULL, 1000);
    test_assert_eq(ctx->state, AK_WASM_STATE_SUSPENDED);

    /* Resume with result */
    char result_data[] = "{\"status\":\"ok\"}";
    s64 result = mock_exec_resume(ctx, result_data, sizeof(result_data));

    test_assert_eq(result, 0);
    test_assert_eq(ctx->state, AK_WASM_STATE_RUNNING);
    test_assert_eq(ctx->suspension.reason, AK_WASM_SUSPEND_NONE);
    test_assert_not_null(ctx->suspension.resume_data);

    mock_exec_destroy(ctx);
    mock_buffer_free(bytecode);
    mock_wasm_shutdown();
    return true;
}

bool test_exec_suspend_wrong_state(void)
{
    mock_wasm_init();

    mock_buffer_t *bytecode = create_valid_wasm_bytecode();
    ak_wasm_module_t *module = mock_wasm_module_load(
        "mod", bytecode, AK_WASM_SOURCE_EMBEDDED, NULL);
    mock_tool_register("tool", module, "fn", AK_CAP_NONE, NULL);

    ak_tool_t *tool = mock_tool_get("tool");
    ak_agent_context_t agent = {0};

    ak_wasm_exec_ctx_t *ctx = mock_exec_create(&agent, tool, NULL);
    /* State is INIT, not RUNNING */

    s64 result = mock_exec_suspend(ctx, AK_WASM_SUSPEND_HOST_CALL, NULL, 0, NULL, 0);
    test_assert_eq(result, AK_E_WASM_TRAP);

    mock_exec_destroy(ctx);
    mock_buffer_free(bytecode);
    mock_wasm_shutdown();
    return true;
}

bool test_exec_resume_wrong_state(void)
{
    mock_wasm_init();

    mock_buffer_t *bytecode = create_valid_wasm_bytecode();
    ak_wasm_module_t *module = mock_wasm_module_load(
        "mod", bytecode, AK_WASM_SOURCE_EMBEDDED, NULL);
    mock_tool_register("tool", module, "fn", AK_CAP_NONE, NULL);

    ak_tool_t *tool = mock_tool_get("tool");
    ak_agent_context_t agent = {0};

    ak_wasm_exec_ctx_t *ctx = mock_exec_create(&agent, tool, NULL);
    ctx->state = AK_WASM_STATE_RUNNING;  /* Not suspended */

    s64 result = mock_exec_resume(ctx, NULL, 0);
    test_assert_eq(result, AK_E_WASM_TRAP);

    mock_exec_destroy(ctx);
    mock_buffer_free(bytecode);
    mock_wasm_shutdown();
    return true;
}

/* ============================================================
 * TEST CASES: HOST FUNCTION REGISTRATION
 * ============================================================ */

static s64 mock_host_fn_impl(ak_wasm_exec_ctx_t *ctx, mock_buffer_t *args,
                             mock_buffer_t **result)
{
    (void)ctx;
    (void)args;
    (void)result;
    return 0;
}

bool test_host_fn_register(void)
{
    mock_wasm_init();

    s64 result = mock_host_fn_register("test_fn", mock_host_fn_impl,
                                        AK_CAP_NET, true);
    test_assert_eq(result, 0);
    test_assert_eq(mock_state.host_fn_count, 1);

    ak_host_fn_entry_t *entry = mock_host_fn_get("test_fn");
    test_assert_not_null(entry);
    test_assert(strcmp(entry->name, "test_fn") == 0);
    test_assert_eq(entry->cap_type, AK_CAP_NET);
    test_assert(entry->async_capable);

    mock_wasm_shutdown();
    return true;
}

bool test_host_fn_register_multiple(void)
{
    mock_wasm_init();

    mock_host_fn_register("fn1", mock_host_fn_impl, AK_CAP_NET, true);
    mock_host_fn_register("fn2", mock_host_fn_impl, AK_CAP_FS, false);
    mock_host_fn_register("fn3", mock_host_fn_impl, AK_CAP_NONE, false);

    test_assert_eq(mock_state.host_fn_count, 3);

    ak_host_fn_entry_t *fn1 = mock_host_fn_get("fn1");
    ak_host_fn_entry_t *fn2 = mock_host_fn_get("fn2");
    ak_host_fn_entry_t *fn3 = mock_host_fn_get("fn3");

    test_assert_not_null(fn1);
    test_assert_not_null(fn2);
    test_assert_not_null(fn3);

    test_assert_eq(fn1->cap_type, AK_CAP_NET);
    test_assert_eq(fn2->cap_type, AK_CAP_FS);
    test_assert_eq(fn3->cap_type, AK_CAP_NONE);

    mock_wasm_shutdown();
    return true;
}

bool test_host_fn_lookup_not_found(void)
{
    mock_wasm_init();

    ak_host_fn_entry_t *entry = mock_host_fn_get("nonexistent");
    test_assert_null(entry);

    mock_wasm_shutdown();
    return true;
}

/* ============================================================
 * TEST CASES: TOOL EXECUTION
 * ============================================================ */

bool test_tool_execute_success(void)
{
    mock_wasm_init();

    mock_buffer_t *bytecode = create_valid_wasm_bytecode();
    ak_wasm_module_t *module = mock_wasm_module_load(
        "mod", bytecode, AK_WASM_SOURCE_EMBEDDED, NULL);
    mock_tool_register("exec_tool", module, "fn", AK_CAP_NONE, NULL);

    ak_agent_context_t agent = {0};
    generate_token_id(agent.run_id);

    mock_buffer_t *args = mock_buffer_create(64);
    mock_buffer_write(args, "{\"x\":1}", 7);

    ak_response_t *response = mock_wasm_execute_tool(&agent, "exec_tool", args, NULL);

    test_assert_not_null(response);
    test_assert_eq(response->error_code, 0);
    test_assert_not_null(response->result);

    mock_buffer_free(response->result);
    free(response);
    mock_buffer_free(args);
    mock_buffer_free(bytecode);
    mock_wasm_shutdown();
    return true;
}

bool test_tool_execute_not_found(void)
{
    mock_wasm_init();

    ak_agent_context_t agent = {0};
    mock_buffer_t *args = mock_buffer_create(64);

    ak_response_t *response = mock_wasm_execute_tool(&agent, "nonexistent", args, NULL);

    test_assert_not_null(response);
    test_assert_eq(response->error_code, AK_E_TOOL_NOT_FOUND);

    free(response);
    mock_buffer_free(args);
    mock_wasm_shutdown();
    return true;
}

bool test_tool_execute_missing_capability(void)
{
    mock_wasm_init();

    mock_buffer_t *bytecode = create_valid_wasm_bytecode();
    ak_wasm_module_t *module = mock_wasm_module_load(
        "mod", bytecode, AK_WASM_SOURCE_EMBEDDED, NULL);
    mock_tool_register("net_tool", module, "fn", AK_CAP_NET, "api.example.com");

    ak_agent_context_t agent = {0};
    generate_token_id(agent.run_id);

    mock_buffer_t *args = mock_buffer_create(64);

    /* Execute without providing required capability */
    ak_response_t *response = mock_wasm_execute_tool(&agent, "net_tool", args, NULL);

    test_assert_not_null(response);
    test_assert_eq(response->error_code, AK_E_CAP_MISSING);
    test_assert_eq(mock_state.stats.host_calls_denied, 1);

    free(response);
    mock_buffer_free(args);
    mock_buffer_free(bytecode);
    mock_wasm_shutdown();
    return true;
}

bool test_tool_execute_with_valid_capability(void)
{
    mock_wasm_init();

    mock_buffer_t *bytecode = create_valid_wasm_bytecode();
    ak_wasm_module_t *module = mock_wasm_module_load(
        "mod", bytecode, AK_WASM_SOURCE_EMBEDDED, NULL);
    mock_tool_register("net_tool", module, "fn", AK_CAP_NET, "api.example.com");

    ak_agent_context_t agent = {0};
    generate_token_id(agent.run_id);

    ak_capability_t cap = {0};
    cap.type = AK_CAP_NET;
    cap.valid = true;
    memcpy(cap.run_id, agent.run_id, AK_TOKEN_ID_SIZE);

    mock_buffer_t *args = mock_buffer_create(64);

    ak_response_t *response = mock_wasm_execute_tool(&agent, "net_tool", args, &cap);

    test_assert_not_null(response);
    test_assert_eq(response->error_code, 0);

    mock_buffer_free(response->result);
    free(response);
    mock_buffer_free(args);
    mock_buffer_free(bytecode);
    mock_wasm_shutdown();
    return true;
}

bool test_tool_execute_wrong_capability_type(void)
{
    mock_wasm_init();

    mock_buffer_t *bytecode = create_valid_wasm_bytecode();
    ak_wasm_module_t *module = mock_wasm_module_load(
        "mod", bytecode, AK_WASM_SOURCE_EMBEDDED, NULL);
    mock_tool_register("net_tool", module, "fn", AK_CAP_NET, "api.example.com");

    ak_agent_context_t agent = {0};
    generate_token_id(agent.run_id);

    /* Wrong capability type */
    ak_capability_t cap = {0};
    cap.type = AK_CAP_FS;  /* FS, not NET */
    cap.valid = true;
    memcpy(cap.run_id, agent.run_id, AK_TOKEN_ID_SIZE);

    mock_buffer_t *args = mock_buffer_create(64);

    ak_response_t *response = mock_wasm_execute_tool(&agent, "net_tool", args, &cap);

    test_assert_not_null(response);
    test_assert_eq(response->error_code, AK_E_CAP_SCOPE);

    free(response);
    mock_buffer_free(args);
    mock_buffer_free(bytecode);
    mock_wasm_shutdown();
    return true;
}

bool test_tool_invocation_count(void)
{
    mock_wasm_init();

    mock_buffer_t *bytecode = create_valid_wasm_bytecode();
    ak_wasm_module_t *module = mock_wasm_module_load(
        "mod", bytecode, AK_WASM_SOURCE_EMBEDDED, NULL);
    mock_tool_register("count_tool", module, "fn", AK_CAP_NONE, NULL);

    test_assert_eq(module->invocation_count, 0);

    ak_agent_context_t agent = {0};
    mock_buffer_t *args = mock_buffer_create(64);

    for (int i = 0; i < 5; i++) {
        ak_response_t *response = mock_wasm_execute_tool(&agent, "count_tool", args, NULL);
        mock_buffer_free(response->result);
        free(response);
    }

    test_assert_eq(module->invocation_count, 5);

    mock_buffer_free(args);
    mock_buffer_free(bytecode);
    mock_wasm_shutdown();
    return true;
}

/* ============================================================
 * TEST CASES: STATISTICS
 * ============================================================ */

bool test_stats_modules_loaded(void)
{
    mock_wasm_init();

    mock_buffer_t *bytecode = create_valid_wasm_bytecode();

    mock_wasm_module_load("mod1", bytecode, AK_WASM_SOURCE_EMBEDDED, NULL);
    mock_wasm_module_load("mod2", bytecode, AK_WASM_SOURCE_EMBEDDED, NULL);
    mock_wasm_module_load("mod3", bytecode, AK_WASM_SOURCE_EMBEDDED, NULL);

    ak_wasm_stats_t stats;
    mock_wasm_get_stats(&stats);

    test_assert_eq(stats.modules_loaded, 3);

    mock_buffer_free(bytecode);
    mock_wasm_shutdown();
    return true;
}

bool test_stats_tools_registered(void)
{
    mock_wasm_init();

    mock_buffer_t *bytecode = create_valid_wasm_bytecode();
    ak_wasm_module_t *module = mock_wasm_module_load(
        "mod", bytecode, AK_WASM_SOURCE_EMBEDDED, NULL);

    mock_tool_register("tool1", module, "fn", AK_CAP_NONE, NULL);
    mock_tool_register("tool2", module, "fn", AK_CAP_NONE, NULL);

    ak_wasm_stats_t stats;
    mock_wasm_get_stats(&stats);

    test_assert_eq(stats.tools_registered, 2);

    mock_buffer_free(bytecode);
    mock_wasm_shutdown();
    return true;
}

bool test_stats_executions(void)
{
    mock_wasm_init();

    mock_buffer_t *bytecode = create_valid_wasm_bytecode();
    ak_wasm_module_t *module = mock_wasm_module_load(
        "mod", bytecode, AK_WASM_SOURCE_EMBEDDED, NULL);
    mock_tool_register("tool", module, "fn", AK_CAP_NONE, NULL);

    ak_agent_context_t agent = {0};
    mock_buffer_t *args = mock_buffer_create(64);

    for (int i = 0; i < 10; i++) {
        ak_response_t *response = mock_wasm_execute_tool(&agent, "tool", args, NULL);
        mock_buffer_free(response->result);
        free(response);
    }

    ak_wasm_stats_t stats;
    mock_wasm_get_stats(&stats);

    test_assert_eq(stats.executions_total, 10);
    test_assert_eq(stats.executions_success, 10);
    test_assert_eq(stats.executions_failed, 0);

    mock_buffer_free(args);
    mock_buffer_free(bytecode);
    mock_wasm_shutdown();
    return true;
}

bool test_stats_signature_failures(void)
{
    mock_wasm_init();

    mock_buffer_t *bytecode = create_valid_wasm_bytecode();
    u8 public_key[AK_ED25519_PUBLIC_KEY_SIZE] = {1, 2, 3};
    u8 signature[AK_ED25519_SIGNATURE_SIZE] = {0xAA};

    /* Key not trusted */
    mock_wasm_module_load_verified("v1", bytecode, AK_WASM_SOURCE_EMBEDDED,
                                    NULL, signature, public_key);

    /* Add key but fail verification */
    mock_ed25519_add_trusted_key(public_key);
    mock_state.next_sig_verify_result = false;
    mock_wasm_module_load_verified("v2", bytecode, AK_WASM_SOURCE_EMBEDDED,
                                    NULL, signature, public_key);

    ak_wasm_stats_t stats;
    mock_wasm_get_stats(&stats);

    test_assert_eq(stats.signature_failures, 2);

    mock_buffer_free(bytecode);
    mock_wasm_shutdown();
    return true;
}

bool test_stats_host_calls_denied(void)
{
    mock_wasm_init();

    mock_buffer_t *bytecode = create_valid_wasm_bytecode();
    ak_wasm_module_t *module = mock_wasm_module_load(
        "mod", bytecode, AK_WASM_SOURCE_EMBEDDED, NULL);
    mock_tool_register("secure_tool", module, "fn", AK_CAP_NET, NULL);

    ak_agent_context_t agent = {0};
    mock_buffer_t *args = mock_buffer_create(64);

    /* Execute without capability - should be denied */
    for (int i = 0; i < 3; i++) {
        ak_response_t *response = mock_wasm_execute_tool(&agent, "secure_tool", args, NULL);
        free(response);
    }

    ak_wasm_stats_t stats;
    mock_wasm_get_stats(&stats);

    test_assert_eq(stats.host_calls_denied, 3);

    mock_buffer_free(args);
    mock_buffer_free(bytecode);
    mock_wasm_shutdown();
    return true;
}

/* ============================================================
 * TEST CASES: SECURITY
 * ============================================================ */

bool test_security_uninitialized_load(void)
{
    /* Don't call mock_wasm_init() */
    mock_state.initialized = false;

    mock_buffer_t *bytecode = create_valid_wasm_bytecode();
    ak_wasm_module_t *module = mock_wasm_module_load(
        "mod", bytecode, AK_WASM_SOURCE_EMBEDDED, NULL);

    test_assert_null(module);

    mock_buffer_free(bytecode);
    return true;
}

bool test_security_cap_run_id_mismatch(void)
{
    mock_wasm_init();

    mock_buffer_t *bytecode = create_valid_wasm_bytecode();
    ak_wasm_module_t *module = mock_wasm_module_load(
        "mod", bytecode, AK_WASM_SOURCE_EMBEDDED, NULL);
    mock_tool_register("tool", module, "fn", AK_CAP_NET, NULL);

    ak_agent_context_t agent = {0};
    generate_token_id(agent.run_id);

    /* Capability with different run_id */
    ak_capability_t cap = {0};
    cap.type = AK_CAP_NET;
    cap.valid = true;
    generate_token_id(cap.run_id);  /* Different from agent.run_id */

    mock_buffer_t *args = mock_buffer_create(64);

    ak_response_t *response = mock_wasm_execute_tool(&agent, "tool", args, &cap);

    test_assert_not_null(response);
    test_assert_eq(response->error_code, AK_E_CAP_SCOPE);

    free(response);
    mock_buffer_free(args);
    mock_buffer_free(bytecode);
    mock_wasm_shutdown();
    return true;
}

bool test_security_invalid_capability(void)
{
    mock_wasm_init();

    mock_buffer_t *bytecode = create_valid_wasm_bytecode();
    ak_wasm_module_t *module = mock_wasm_module_load(
        "mod", bytecode, AK_WASM_SOURCE_EMBEDDED, NULL);
    mock_tool_register("tool", module, "fn", AK_CAP_NET, NULL);

    ak_agent_context_t agent = {0};
    generate_token_id(agent.run_id);

    /* Invalid capability */
    ak_capability_t cap = {0};
    cap.type = AK_CAP_NET;
    cap.valid = false;  /* INVALID */
    memcpy(cap.run_id, agent.run_id, AK_TOKEN_ID_SIZE);

    mock_buffer_t *args = mock_buffer_create(64);

    ak_response_t *response = mock_wasm_execute_tool(&agent, "tool", args, &cap);

    test_assert_not_null(response);
    test_assert_eq(response->error_code, AK_E_CAP_INVALID);

    free(response);
    mock_buffer_free(args);
    mock_buffer_free(bytecode);
    mock_wasm_shutdown();
    return true;
}

bool test_security_any_capability_type(void)
{
    mock_wasm_init();

    mock_buffer_t *bytecode = create_valid_wasm_bytecode();
    ak_wasm_module_t *module = mock_wasm_module_load(
        "mod", bytecode, AK_WASM_SOURCE_EMBEDDED, NULL);
    mock_tool_register("net_tool", module, "fn", AK_CAP_NET, NULL);

    ak_agent_context_t agent = {0};
    generate_token_id(agent.run_id);

    /* ANY capability should work for any tool */
    ak_capability_t cap = {0};
    cap.type = AK_CAP_ANY;
    cap.valid = true;
    memcpy(cap.run_id, agent.run_id, AK_TOKEN_ID_SIZE);

    mock_buffer_t *args = mock_buffer_create(64);

    ak_response_t *response = mock_wasm_execute_tool(&agent, "net_tool", args, &cap);

    test_assert_not_null(response);
    test_assert_eq(response->error_code, 0);

    mock_buffer_free(response->result);
    free(response);
    mock_buffer_free(args);
    mock_buffer_free(bytecode);
    mock_wasm_shutdown();
    return true;
}

/* ============================================================
 * TEST CASES: EDGE CASES
 * ============================================================ */

bool test_edge_null_context_exec(void)
{
    mock_wasm_init();

    s64 result = mock_exec_run(NULL, NULL);
    test_assert_eq(result, AK_E_WASM_TRAP);

    mock_wasm_shutdown();
    return true;
}

bool test_edge_null_suspend_ctx(void)
{
    s64 result = mock_exec_suspend(NULL, AK_WASM_SUSPEND_HOST_CALL, NULL, 0, NULL, 0);
    test_assert_eq(result, AK_E_WASM_TRAP);
    return true;
}

bool test_edge_null_resume_ctx(void)
{
    s64 result = mock_exec_resume(NULL, NULL, 0);
    test_assert_eq(result, AK_E_WASM_TRAP);
    return true;
}

bool test_edge_empty_bytecode(void)
{
    mock_wasm_init();

    mock_buffer_t *bytecode = mock_buffer_create(0);
    ak_wasm_module_t *module = mock_wasm_module_load(
        "empty", bytecode, AK_WASM_SOURCE_EMBEDDED, NULL);

    test_assert_null(module);

    mock_buffer_free(bytecode);
    mock_wasm_shutdown();
    return true;
}

bool test_edge_long_module_name(void)
{
    mock_wasm_init();

    mock_buffer_t *bytecode = create_valid_wasm_bytecode();

    /* Create a very long name */
    char long_name[256];
    memset(long_name, 'x', sizeof(long_name) - 1);
    long_name[sizeof(long_name) - 1] = '\0';

    ak_wasm_module_t *module = mock_wasm_module_load(
        long_name, bytecode, AK_WASM_SOURCE_EMBEDDED, NULL);

    test_assert_not_null(module);
    /* Name should be truncated */
    test_assert(strlen(module->name) < 64);

    mock_buffer_free(bytecode);
    mock_wasm_shutdown();
    return true;
}

/* ============================================================
 * TEST RUNNER
 * ============================================================ */

typedef bool (*test_func)(void);

typedef struct {
    const char *name;
    test_func func;
} test_case;

test_case tests[] = {
    /* Module management tests */
    {"module_load_valid", test_module_load_valid},
    {"module_load_invalid_magic", test_module_load_invalid_magic},
    {"module_load_wrong_version", test_module_load_wrong_version},
    {"module_load_too_short", test_module_load_too_short},
    {"module_hash_computation", test_module_hash_computation},
    {"module_get_by_name", test_module_get_by_name},
    {"module_get_by_hash", test_module_get_by_hash},
    {"module_unload", test_module_unload},
    {"module_registry_limit", test_module_registry_limit},
    {"module_with_source_url", test_module_with_source_url},

    /* Verified module tests */
    {"verified_module_load_success", test_verified_module_load_success},
    {"verified_module_untrusted_key", test_verified_module_untrusted_key},
    {"verified_module_bad_signature", test_verified_module_bad_signature},
    {"verified_module_null_params", test_verified_module_null_params},

    /* Tool registry tests */
    {"tool_register_basic", test_tool_register_basic},
    {"tool_register_duplicate_name", test_tool_register_duplicate_name},
    {"tool_unregister", test_tool_unregister},
    {"tool_lookup_not_found", test_tool_lookup_not_found},
    {"tool_capability_requirements", test_tool_capability_requirements},

    /* Execution context tests */
    {"exec_context_create", test_exec_context_create},
    {"exec_state_transitions", test_exec_state_transitions},
    {"exec_resource_tracking", test_exec_resource_tracking},

    /* Async execution tests */
    {"exec_suspend_for_host_call", test_exec_suspend_for_host_call},
    {"exec_suspend_for_approval", test_exec_suspend_for_approval},
    {"exec_resume_with_result", test_exec_resume_with_result},
    {"exec_suspend_wrong_state", test_exec_suspend_wrong_state},
    {"exec_resume_wrong_state", test_exec_resume_wrong_state},

    /* Host function tests */
    {"host_fn_register", test_host_fn_register},
    {"host_fn_register_multiple", test_host_fn_register_multiple},
    {"host_fn_lookup_not_found", test_host_fn_lookup_not_found},

    /* Tool execution tests */
    {"tool_execute_success", test_tool_execute_success},
    {"tool_execute_not_found", test_tool_execute_not_found},
    {"tool_execute_missing_capability", test_tool_execute_missing_capability},
    {"tool_execute_with_valid_capability", test_tool_execute_with_valid_capability},
    {"tool_execute_wrong_capability_type", test_tool_execute_wrong_capability_type},
    {"tool_invocation_count", test_tool_invocation_count},

    /* Statistics tests */
    {"stats_modules_loaded", test_stats_modules_loaded},
    {"stats_tools_registered", test_stats_tools_registered},
    {"stats_executions", test_stats_executions},
    {"stats_signature_failures", test_stats_signature_failures},
    {"stats_host_calls_denied", test_stats_host_calls_denied},

    /* Security tests */
    {"security_uninitialized_load", test_security_uninitialized_load},
    {"security_cap_run_id_mismatch", test_security_cap_run_id_mismatch},
    {"security_invalid_capability", test_security_invalid_capability},
    {"security_any_capability_type", test_security_any_capability_type},

    /* Edge case tests */
    {"edge_null_context_exec", test_edge_null_context_exec},
    {"edge_null_suspend_ctx", test_edge_null_suspend_ctx},
    {"edge_null_resume_ctx", test_edge_null_resume_ctx},
    {"edge_empty_bytecode", test_edge_empty_bytecode},
    {"edge_long_module_name", test_edge_long_module_name},

    {NULL, NULL}
};

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    int passed = 0;
    int failed = 0;

    srand(12345);  /* Deterministic for reproducibility */

    printf("=== AK WASM Sandbox System Tests ===\n\n");

    for (int i = 0; tests[i].name != NULL; i++) {
        printf("Running %s... ", tests[i].name);
        fflush(stdout);

        if (tests[i].func()) {
            printf("PASS\n");
            passed++;
        } else {
            printf("FAIL\n");
            failed++;
        }
    }

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);

    return (failed > 0) ? 1 : 0;
}
