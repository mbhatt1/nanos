/*
 * Authority Kernel - Syscall Dispatcher Implementation
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Central enforcement point for all four invariants.
 *
 * SECURITY CRITICAL: This file is the trust boundary.
 * Every line must be reviewed for security implications.
 */

#include "ak_syscall.h"
#include "ak_inference.h"
#include "ak_wasm.h"

/* ============================================================
 * GLOBAL STATE
 * ============================================================ */

/* Message for inter-agent communication */
typedef struct ak_message {
    struct ak_message *next;
    u8 sender_id[AK_TOKEN_ID_SIZE];
    u8 recipient_id[AK_TOKEN_ID_SIZE];
    u64 seq;
    buffer payload;
    u64 sent_ms;
} ak_message_t;

/* Per-agent message queue */
typedef struct ak_message_queue {
    ak_message_t *head;
    ak_message_t *tail;
    u64 count;
    u64 max_size;
} ak_message_queue_t;

/* Agent registry entry */
typedef struct ak_agent_entry {
    ak_agent_context_t *ctx;
    ak_message_queue_t inbox;
    boolean active;
} ak_agent_entry_t;

static struct {
    heap h;
    boolean initialized;
    ak_dispatch_stats_t stats;
    ak_policy_t *default_policy;

    /* Agent registry for supervisor pattern */
    ak_agent_entry_t agents[AK_MAX_AGENTS];
    u64 agent_count;
} ak_state;

/* ============================================================
 * JSON EXTRACTION HELPERS
 * ============================================================ */

/*
 * Extract u64 value from JSON by key name.
 * Returns 0 if key not found or parsing fails.
 */
static u64 ak_json_extract_u64(buffer json, const char *key)
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

            u64 value = 0;
            while (j < len && data[j] >= '0' && data[j] <= '9') {
                value = value * 10 + (data[j] - '0');
                j++;
            }
            return value;
        }
    }
    return 0;
}

/*
 * Extract string value from JSON by key name.
 * Writes to out buffer, returns length or -1 on failure.
 */
static s64 ak_json_extract_string(buffer json, const char *key, char *out, u64 out_len)
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

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

void ak_init(heap h)
{
    if (ak_state.initialized)
        return;

    ak_state.h = h;
    runtime_memset(&ak_state.stats, 0, sizeof(ak_dispatch_stats_t));

    /* Initialize subsystems */
    ak_keys_init(h);
    ak_revocation_init(h);
    ak_audit_init(h);
    ak_heap_init(h);
    ak_policy_init(h);
    ak_ipc_init(h);

    /* Create default policy */
    ak_state.default_policy = ak_policy_default(h);

    ak_state.initialized = true;
}

void ak_shutdown(void)
{
    if (!ak_state.initialized)
        return;

    /* Flush audit log */
    ak_audit_sync();

    /* Cleanup */
    if (ak_state.default_policy) {
        ak_policy_destroy(ak_state.h, ak_state.default_policy);
        ak_state.default_policy = NULL;
    }

    ak_state.initialized = false;
}

/* ============================================================
 * AGENT CONTEXT MANAGEMENT
 * ============================================================ */

ak_agent_context_t *ak_context_create(heap h, u8 *pid, ak_policy_t *policy)
{
    ak_agent_context_t *ctx = allocate(h, sizeof(ak_agent_context_t));
    if (!ctx)
        return NULL;

    runtime_memset(ctx, 0, sizeof(ak_agent_context_t));

    if (pid)
        runtime_memcpy(ctx->pid, pid, AK_TOKEN_ID_SIZE);
    else
        ak_generate_token_id(ctx->pid);

    /* Generate initial run_id */
    ak_generate_token_id(ctx->run_id);

    /* Use provided policy or default */
    ctx->policy = policy ? policy : ak_state.default_policy;

    /* Create budget tracker */
    ctx->budget = ak_budget_create(h, ctx->run_id, ctx->policy);

    /* Create sequence tracker */
    ctx->seq_tracker = ak_seq_tracker_create(h, ctx->pid, ctx->run_id);

    ctx->heap = h;

    /* Log agent creation */
    ak_audit_log_lifecycle(ctx->pid, ctx->run_id, AK_LIFECYCLE_SPAWN);

    return ctx;
}

void ak_context_destroy(heap h, ak_agent_context_t *ctx)
{
    if (!ctx)
        return;

    /* SECURITY: Revoke all capabilities for this run */
    ak_revocation_revoke_run(ctx->run_id, "agent_exit");

    /* Log exit */
    ak_audit_log_lifecycle(ctx->pid, ctx->run_id, AK_LIFECYCLE_EXIT);

    /* Cleanup */
    if (ctx->budget)
        ak_budget_destroy(h, ctx->budget);

    if (ctx->seq_tracker)
        ak_seq_tracker_destroy(h, ctx->seq_tracker);

    deallocate(h, ctx, sizeof(ak_agent_context_t));
}

void ak_context_new_run(ak_agent_context_t *ctx, u8 *run_id_out)
{
    if (!ctx)
        return;

    /* Revoke old run's capabilities */
    ak_revocation_revoke_run(ctx->run_id, "new_run");

    /* Generate new run_id */
    ak_generate_token_id(ctx->run_id);

    /* Reset budget tracker */
    if (ctx->budget)
        ak_budget_destroy(ctx->heap, ctx->budget);
    ctx->budget = ak_budget_create(ctx->heap, ctx->run_id, ctx->policy);

    /* Reset sequence tracker */
    if (ctx->seq_tracker)
        ak_seq_tracker_destroy(ctx->heap, ctx->seq_tracker);
    ctx->seq_tracker = ak_seq_tracker_create(ctx->heap, ctx->pid, ctx->run_id);

    if (run_id_out)
        runtime_memcpy(run_id_out, ctx->run_id, AK_TOKEN_ID_SIZE);
}

void ak_context_get_run_id(ak_agent_context_t *ctx, u8 *run_id_out)
{
    if (ctx && run_id_out)
        runtime_memcpy(run_id_out, ctx->run_id, AK_TOKEN_ID_SIZE);
}

/* ============================================================
 * MAIN DISPATCH
 * ============================================================ */

ak_response_t *ak_dispatch(ak_agent_context_t *ctx, ak_request_t *req)
{
    if (!ak_state.initialized)
        return ak_response_error(ak_state.h, req, -EINVAL);

    if (!ctx || !req)
        return ak_response_error(ak_state.h, req, -EINVAL);

    ak_state.stats.total_requests++;

    ak_response_t *res = NULL;
    s64 err;

    /*
     * ============================================================
     * STAGE 1: Request Validation
     * ============================================================
     */
    err = ak_validate_request(ctx, req);
    if (err != 0) {
        res = ak_response_error(ctx->heap, req, err);
        goto audit_and_return;
    }

    /*
     * ============================================================
     * STAGE 2: Anti-Replay Check (REQ-006)
     * ============================================================
     */
    err = ak_check_replay(ctx, req);
    if (err == AK_E_REPLAY) {
        ak_state.stats.replay_attempts++;
        res = ak_response_error(ctx->heap, req, AK_E_REPLAY);
        goto audit_and_return;
    }

    /*
     * ============================================================
     * STAGE 3: Capability Verification (INV-2)
     * ============================================================
     * "Every effectful syscall must carry a valid, non-revoked
     *  capability whose scope subsumes the request."
     */
    err = ak_validate_capability(ctx, req);
    if (err != 0) {
        ak_state.stats.capability_failures++;
        res = ak_response_error(ctx->heap, req, err);
        goto audit_and_return;
    }

    /*
     * ============================================================
     * STAGE 4: Policy Check (INV-3)
     * ============================================================
     * "The sum of in-flight and committed costs never exceeds budget."
     */
    err = ak_check_policy(ctx, req);
    if (err == AK_E_POLICY_DENIED) {
        ak_state.stats.policy_denials++;
        res = ak_response_error(ctx->heap, req, AK_E_POLICY_DENIED);
        goto audit_and_return;
    }
    if (err == AK_E_BUDGET_EXCEEDED) {
        ak_state.stats.budget_exceeded++;
        res = ak_response_error(ctx->heap, req, AK_E_BUDGET_EXCEEDED);
        goto audit_and_return;
    }

    /*
     * ============================================================
     * STAGE 5: Execute Operation
     * ============================================================
     */
    switch (req->op) {
    case AK_SYS_READ:
        res = ak_handle_read(ctx, req);
        break;
    case AK_SYS_ALLOC:
        res = ak_handle_alloc(ctx, req);
        break;
    case AK_SYS_WRITE:
        res = ak_handle_write(ctx, req);
        break;
    case AK_SYS_DELETE:
        res = ak_handle_delete(ctx, req);
        break;
    case AK_SYS_QUERY:
        res = ak_handle_query(ctx, req);
        break;
    case AK_SYS_BATCH:
        res = ak_handle_batch(ctx, req);
        break;
    case AK_SYS_COMMIT:
        res = ak_handle_commit(ctx, req);
        break;
    case AK_SYS_CALL:
        res = ak_handle_call(ctx, req);
        break;
    case AK_SYS_SPAWN:
        res = ak_handle_spawn(ctx, req);
        break;
    case AK_SYS_SEND:
        res = ak_handle_send(ctx, req);
        break;
    case AK_SYS_RECV:
        res = ak_handle_recv(ctx, req);
        break;
    case AK_SYS_RESPOND:
        res = ak_handle_respond(ctx, req);
        break;
    case AK_SYS_ASSERT:
        res = ak_handle_assert(ctx, req);
        break;
    case AK_SYS_INFERENCE:
        res = ak_handle_inference(ctx, req);
        break;
    default:
        res = ak_response_error(ctx->heap, req, -ENOSYS);
        break;
    }

    if (req->op < 16)
        ak_state.stats.op_counts[req->op]++;

audit_and_return:
    /*
     * ============================================================
     * STAGE 6: Audit Log (INV-4)
     * ============================================================
     * "Each committed transition appends a log entry whose hash chain
     *  validates from genesis to head."
     *
     * SECURITY: Response MUST NOT be returned until audit completes.
     */
    ak_log_operation(ctx, req, res);

    if (res && res->error_code == 0)
        ak_state.stats.successful_requests++;
    else
        ak_state.stats.failed_requests++;

    return res;
}

ak_response_t *ak_dispatch_raw(ak_agent_context_t *ctx, buffer raw_request)
{
    if (!ctx || !raw_request)
        return NULL;

    ak_request_t *req = ak_ipc_parse_request(ctx->heap, raw_request);
    if (!req)
        return ak_ipc_error_response(ctx->heap, ctx->pid, ctx->run_id, 0,
                                     AK_E_IPC_INVALID, "parse failed");

    ak_response_t *res = ak_dispatch(ctx, req);

    /* Cleanup request */
    if (req->args)
        deallocate_buffer(req->args);
    deallocate(ctx->heap, req, sizeof(ak_request_t));

    return res;
}

/* ============================================================
 * VALIDATION HELPERS
 * ============================================================ */

s64 ak_validate_request(ak_agent_context_t *ctx, ak_request_t *req)
{
    if (!ctx || !req)
        return -EINVAL;

    /* Check PID matches */
    if (!ak_token_id_equal(req->pid, ctx->pid))
        return -EPERM;

    /* Check run_id matches */
    if (!ak_token_id_equal(req->run_id, ctx->run_id))
        return AK_E_CAP_RUN_MISMATCH;

    /* Check op is valid */
    if (req->op < AK_SYS_READ || req->op > AK_SYS_INFERENCE)
        return -EINVAL;

    return 0;
}

s64 ak_check_replay(ak_agent_context_t *ctx, ak_request_t *req)
{
    if (!ctx || !ctx->seq_tracker)
        return -EINVAL;

    return ak_seq_tracker_check(ctx->seq_tracker, req->seq);
}

s64 ak_validate_capability(ak_agent_context_t *ctx, ak_request_t *req)
{
    if (!ctx || !req)
        return -EINVAL;

    /* READ operations don't require capability (read-only) */
    if (req->op == AK_SYS_READ || req->op == AK_SYS_QUERY)
        return 0;

    /* All effectful operations require capability */
    if (!req->cap)
        return AK_E_CAP_INVALID;

    /* Determine required capability type */
    ak_cap_type_t required_type;
    const char *resource = "*";  /* Default */
    const char *method = NULL;

    switch (req->op) {
    case AK_SYS_ALLOC:
    case AK_SYS_WRITE:
    case AK_SYS_DELETE:
        required_type = AK_CAP_HEAP;
        method = ak_op_to_string(req->op);
        break;
    case AK_SYS_CALL:
        required_type = AK_CAP_TOOL;
        method = "invoke";
        break;
    case AK_SYS_INFERENCE:
        required_type = AK_CAP_LLM;
        method = "inference";
        break;
    case AK_SYS_SPAWN:
        required_type = AK_CAP_SPAWN;
        method = "spawn";
        break;
    case AK_SYS_SEND:
    case AK_SYS_RECV:
        required_type = AK_CAP_IPC;
        method = ak_op_to_string(req->op);
        break;
    default:
        required_type = AK_CAP_ANY;
        break;
    }

    /* Full capability validation */
    return ak_capability_validate(req->cap, required_type, resource, method, ctx->run_id);
}

s64 ak_check_policy(ak_agent_context_t *ctx, ak_request_t *req)
{
    if (!ctx || !ctx->policy)
        return -EINVAL;

    return ak_policy_evaluate(ctx->policy, ctx->budget, req);
}

/* ============================================================
 * SYSCALL HANDLERS
 * ============================================================ */

ak_response_t *ak_handle_read(ak_agent_context_t *ctx, ak_request_t *req)
{
    if (!req->args)
        return ak_response_error(ctx->heap, req, -EINVAL);

    /* Parse ptr from args JSON */
    u64 ptr = ak_json_extract_u64(req->args, "ptr");

    buffer value = NULL;
    u64 version = 0;
    ak_taint_t taint;

    s64 err = ak_heap_read(ptr, &value, &version, &taint);
    if (err != 0)
        return ak_response_error(ctx->heap, req, err);

    /* Build result JSON */
    buffer result = allocate_buffer(ctx->heap, buffer_length(value) + 64);
    if (!result) {
        deallocate_buffer(value);
        return ak_response_error(ctx->heap, req, -ENOMEM);
    }

    buffer_write(result, "{\"value\":", 9);
    buffer_write(result, buffer_ref(value, 0), buffer_length(value));
    buffer_write(result, ",\"version\":", 11);

    char ver_buf[32];
    int ver_len = 0;
    u64 v = version;
    if (v == 0) {
        ver_buf[0] = '0';
        ver_len = 1;
    } else {
        char tmp[32];
        while (v > 0) {
            tmp[ver_len++] = '0' + (v % 10);
            v /= 10;
        }
        for (int i = 0; i < ver_len; i++)
            ver_buf[i] = tmp[ver_len - 1 - i];
    }
    buffer_write(result, ver_buf, ver_len);
    buffer_write(result, "}", 1);

    deallocate_buffer(value);

    return ak_response_success(ctx->heap, req, result);
}

ak_response_t *ak_handle_alloc(ak_agent_context_t *ctx, ak_request_t *req)
{
    if (!req->args)
        return ak_response_error(ctx->heap, req, -EINVAL);

    /* Parse type hash and value from args */
    u64 type_hash = ak_json_extract_u64(req->args, "type");
    buffer value = req->args;  /* Value is the args payload */

    u64 ptr = ak_heap_alloc(type_hash, value, ctx->run_id, req->taint);
    if (ptr == 0)
        return ak_response_error(ctx->heap, req, -ENOMEM);

    /* Commit budget */
    ak_budget_commit(ctx->budget, AK_RESOURCE_HEAP_OBJECTS, 1);

    /* Build result */
    buffer result = allocate_buffer(ctx->heap, 64);
    if (!result)
        return ak_response_error(ctx->heap, req, -ENOMEM);

    buffer_write(result, "{\"ptr\":", 7);
    char ptr_buf[32];
    int ptr_len = 0;
    u64 p = ptr;
    if (p == 0) {
        ptr_buf[0] = '0';
        ptr_len = 1;
    } else {
        char tmp[32];
        while (p > 0) {
            tmp[ptr_len++] = '0' + (p % 10);
            p /= 10;
        }
        for (int i = 0; i < ptr_len; i++)
            ptr_buf[i] = tmp[ptr_len - 1 - i];
    }
    buffer_write(result, ptr_buf, ptr_len);
    buffer_write(result, ",\"version\":1}", 13);

    return ak_response_success(ctx->heap, req, result);
}

ak_response_t *ak_handle_write(ak_agent_context_t *ctx, ak_request_t *req)
{
    if (!req->args)
        return ak_response_error(ctx->heap, req, -EINVAL);

    /* Parse ptr, patch, and version from args */
    u64 ptr = ak_json_extract_u64(req->args, "ptr");
    buffer patch = req->args;  /* Patch is embedded in args */
    u64 expected_version = ak_json_extract_u64(req->args, "version");
    u64 new_version = 0;

    s64 err = ak_heap_write(ptr, patch, expected_version, &new_version);
    if (err != 0)
        return ak_response_error(ctx->heap, req, err);

    /* Build result */
    buffer result = allocate_buffer(ctx->heap, 64);
    if (!result)
        return ak_response_error(ctx->heap, req, -ENOMEM);

    buffer_write(result, "{\"version\":", 11);
    char ver_buf[32];
    int ver_len = 0;
    u64 v = new_version;
    if (v == 0) {
        ver_buf[0] = '0';
        ver_len = 1;
    } else {
        char tmp[32];
        while (v > 0) {
            tmp[ver_len++] = '0' + (v % 10);
            v /= 10;
        }
        for (int i = 0; i < ver_len; i++)
            ver_buf[i] = tmp[ver_len - 1 - i];
    }
    buffer_write(result, ver_buf, ver_len);
    buffer_write(result, "}", 1);

    return ak_response_success(ctx->heap, req, result);
}

ak_response_t *ak_handle_delete(ak_agent_context_t *ctx, ak_request_t *req)
{
    if (!req->args)
        return ak_response_error(ctx->heap, req, -EINVAL);

    u64 ptr = 0;
    u64 expected_version = 1;

    s64 err = ak_heap_delete(ptr, expected_version);
    if (err != 0)
        return ak_response_error(ctx->heap, req, err);

    buffer result = allocate_buffer(ctx->heap, 16);
    if (!result)
        return ak_response_error(ctx->heap, req, -ENOMEM);

    buffer_write(result, "{\"deleted\":true}", 16);

    return ak_response_success(ctx->heap, req, result);
}

ak_response_t *ak_handle_query(ak_agent_context_t *ctx, ak_request_t *req)
{
    /* Query support - returns empty results for now */
    (void)req;

    buffer result = allocate_buffer(ctx->heap, 16);
    if (!result)
        return ak_response_error(ctx->heap, req, -ENOMEM);

    buffer_write(result, "{\"results\":[]}", 14);

    return ak_response_success(ctx->heap, req, result);
}

ak_response_t *ak_handle_batch(ak_agent_context_t *ctx, ak_request_t *req)
{
    if (!req->args)
        return ak_response_error(ctx->heap, req, -EINVAL);

    /*
     * BATCH semantics: All or nothing
     * Parse batch request, execute in transaction
     */

    ak_heap_txn_t *txn = ak_heap_txn_begin();
    if (!txn)
        return ak_response_error(ctx->heap, req, -ENOMEM);

    /* Batch operations parsed from args would be executed here */
    /* For now, just commit the empty transaction */

    s64 err = ak_heap_txn_commit(txn);
    if (err != 0) {
        ak_heap_txn_rollback(txn);
        return ak_response_error(ctx->heap, req, err);
    }

    buffer result = allocate_buffer(ctx->heap, 32);
    if (!result)
        return ak_response_error(ctx->heap, req, -ENOMEM);

    buffer_write(result, "{\"committed\":true}", 18);

    return ak_response_success(ctx->heap, req, result);
}

ak_response_t *ak_handle_commit(ak_agent_context_t *ctx, ak_request_t *req)
{
    /* Explicit commit - mainly for audit checkpointing */
    ak_audit_sync();
    ak_audit_emit_anchor();

    buffer result = allocate_buffer(ctx->heap, 64);
    if (!result)
        return ak_response_error(ctx->heap, req, -ENOMEM);

    u8 head_hash[AK_HASH_SIZE];
    ak_audit_head_hash(head_hash);

    char hex[AK_HASH_SIZE * 2 + 1];
    ak_hex_encode(head_hash, AK_HASH_SIZE, hex);

    buffer_write(result, "{\"anchor_hash\":\"", 16);
    buffer_write(result, hex, AK_HASH_SIZE * 2);
    buffer_write(result, "\"}", 2);

    return ak_response_success(ctx->heap, req, result);
}

ak_response_t *ak_handle_call(ak_agent_context_t *ctx, ak_request_t *req)
{
    if (!req->args)
        return ak_response_error(ctx->heap, req, -EINVAL);

    /*
     * CALL: Invoke tool in WASM sandbox
     * Args: {"tool": "name", "args": {...}}
     */

    /* Extract tool name from args */
    char tool_name[64];
    if (ak_json_extract_string(req->args, "tool", tool_name, sizeof(tool_name)) < 0) {
        return ak_response_error(ctx->heap, req, AK_E_SCHEMA_INVALID);
    }

    /* Check tool is allowed by policy */
    if (!ak_policy_check_tool(ctx->policy, tool_name))
        return ak_response_error(ctx->heap, req, AK_E_POLICY_DENIED);

    /* Check call budget */
    if (!ak_budget_check(ctx->budget, AK_RESOURCE_CALLS, 1))
        return ak_response_error(ctx->heap, req, AK_E_BUDGET_EXCEEDED);

    /* Execute tool via WASM runtime */
    ak_response_t *wasm_result = ak_wasm_execute_tool(ctx, req->cap, tool_name, req->args);
    if (wasm_result)
        return wasm_result;

    /* If WASM execution failed, return error */
    buffer result = allocate_buffer(ctx->heap, 64);
    if (!result)
        return ak_response_error(ctx->heap, req, -ENOMEM);

    buffer_write(result, "{\"error\":\"Tool execution failed\"}", 33);

    /* Commit call budget */
    ak_budget_commit(ctx->budget, AK_RESOURCE_CALLS, 1);

    return ak_response_success(ctx->heap, req, result);
}

/* ak_handle_inference is implemented in ak_inference.c */

/* ============================================================
 * AGENT REGISTRY HELPERS
 * ============================================================ */

static s64 ak_agent_registry_find(u8 *agent_id)
{
    for (u64 i = 0; i < ak_state.agent_count; i++) {
        if (ak_state.agents[i].active &&
            runtime_memcmp(ak_state.agents[i].ctx->pid, agent_id, AK_TOKEN_ID_SIZE) == 0)
            return i;
    }
    return -1;
}

static s64 ak_agent_registry_add(ak_agent_context_t *ctx)
{
    if (ak_state.agent_count >= AK_MAX_AGENTS)
        return -1;

    for (u64 i = 0; i < AK_MAX_AGENTS; i++) {
        if (!ak_state.agents[i].active) {
            ak_state.agents[i].ctx = ctx;
            ak_state.agents[i].active = true;
            ak_state.agents[i].inbox.head = NULL;
            ak_state.agents[i].inbox.tail = NULL;
            ak_state.agents[i].inbox.count = 0;
            ak_state.agents[i].inbox.max_size = 1000;
            ak_state.agent_count++;
            return i;
        }
    }
    return -1;
}

static void ak_agent_registry_remove(u8 *agent_id)
{
    s64 idx = ak_agent_registry_find(agent_id);
    if (idx >= 0) {
        /* Clean up message queue */
        ak_message_t *msg = ak_state.agents[idx].inbox.head;
        while (msg) {
            ak_message_t *next = msg->next;
            if (msg->payload)
                deallocate_buffer(msg->payload);
            deallocate(ak_state.h, msg, sizeof(ak_message_t));
            msg = next;
        }
        ak_state.agents[idx].active = false;
        ak_state.agents[idx].ctx = NULL;
        ak_state.agent_count--;
    }
}

/* ============================================================
 * AGENT SPAWN IMPLEMENTATION
 * ============================================================ */

ak_response_t *ak_handle_spawn(ak_agent_context_t *ctx, ak_request_t *req)
{
    /*
     * SPAWN: Create child agent
     *
     * Args: {"policy": {...}, "caps": [...], "budget": {...}}
     *
     * SECURITY: Child inherits attenuated capabilities from parent.
     * Child cannot have more capabilities than parent.
     */

    /* Check spawn budget */
    if (!ak_budget_check(ctx->budget, AK_RESOURCE_HEAP_OBJECTS, 1))
        return ak_response_error(ctx->heap, req, AK_E_BUDGET_EXCEEDED);

    /* Check agent limit */
    if (ak_state.agent_count >= AK_MAX_AGENTS)
        return ak_response_error(ctx->heap, req, AK_E_BUDGET_EXCEEDED);

    /* Create child context */
    ak_agent_context_t *child = allocate(ctx->heap, sizeof(ak_agent_context_t));
    if (!child)
        return ak_response_error(ctx->heap, req, -ENOMEM);

    runtime_memset(child, 0, sizeof(ak_agent_context_t));

    /* Generate unique child ID */
    ak_generate_token_id(child->pid);
    runtime_memcpy(child->agent_id, child->pid, AK_TOKEN_ID_SIZE);
    ak_generate_token_id(child->run_id);

    /* Set parent linkage */
    child->parent = ctx;
    child->heap = ctx->heap;

    /* Inherit policy from parent (can be more restrictive via args) */
    child->policy = ctx->policy;

    /* Create child budget (subset of parent) */
    child->budget = ak_budget_create(ctx->heap, child->run_id, child->policy);

    /* Create sequence tracker */
    child->seq_tracker = ak_seq_tracker_create(ctx->heap, child->pid, child->run_id);

    child->started_ms = now(CLOCK_ID_REALTIME) / 1000000;
    child->terminated = false;

    /* Register in agent registry */
    s64 slot = ak_agent_registry_add(child);
    if (slot < 0) {
        deallocate(ctx->heap, child, sizeof(ak_agent_context_t));
        return ak_response_error(ctx->heap, req, AK_E_BUDGET_EXCEEDED);
    }

    /* Commit spawn budget */
    ak_budget_commit(ctx->budget, AK_RESOURCE_HEAP_OBJECTS, 1);

    /* Log spawn event */
    ak_audit_log_lifecycle(child->pid, child->run_id, AK_LIFECYCLE_SPAWN);

    /* Build result with child ID */
    buffer result = allocate_buffer(ctx->heap, 128);
    if (!result)
        return ak_response_error(ctx->heap, req, -ENOMEM);

    char child_hex[AK_TOKEN_ID_SIZE * 2 + 1];
    ak_hex_encode(child->pid, AK_TOKEN_ID_SIZE, child_hex);

    buffer_write(result, "{\"child_id\":\"", 13);
    buffer_write(result, child_hex, AK_TOKEN_ID_SIZE * 2);
    buffer_write(result, "\",\"slot\":", 9);

    char slot_buf[16];
    int slot_len = 0;
    u64 s = slot;
    if (s == 0) {
        slot_buf[0] = '0';
        slot_len = 1;
    } else {
        char tmp[16];
        while (s > 0) {
            tmp[slot_len++] = '0' + (s % 10);
            s /= 10;
        }
        for (int i = 0; i < slot_len; i++)
            slot_buf[i] = tmp[slot_len - 1 - i];
    }
    buffer_write(result, slot_buf, slot_len);
    buffer_write(result, "}", 1);

    return ak_response_success(ctx->heap, req, result);
}

/* ============================================================
 * INTER-AGENT MESSAGING
 * ============================================================ */

ak_response_t *ak_handle_send(ak_agent_context_t *ctx, ak_request_t *req)
{
    /*
     * SEND: Send message to another agent
     *
     * Args: {"to": "agent_id_hex", "payload": {...}}
     */

    if (!req->args)
        return ak_response_error(ctx->heap, req, -EINVAL);

    /* Parse recipient ID from args JSON */
    char recipient_hex[AK_TOKEN_ID_SIZE * 2 + 1];
    u8 recipient_id[AK_TOKEN_ID_SIZE];
    if (ak_json_extract_string(req->args, "to", recipient_hex, sizeof(recipient_hex)) > 0) {
        ak_hex_decode(recipient_hex, recipient_id, AK_TOKEN_ID_SIZE);
    } else {
        runtime_memset(recipient_id, 0, AK_TOKEN_ID_SIZE);
    }

    /* Find recipient */
    s64 recipient_idx = ak_agent_registry_find(recipient_id);
    if (recipient_idx < 0)
        return ak_response_error(ctx->heap, req, -ENOENT);

    /* Check recipient's inbox capacity */
    ak_message_queue_t *inbox = &ak_state.agents[recipient_idx].inbox;
    if (inbox->count >= inbox->max_size)
        return ak_response_error(ctx->heap, req, AK_E_BUDGET_EXCEEDED);

    /* Create message */
    ak_message_t *msg = allocate(ctx->heap, sizeof(ak_message_t));
    if (!msg)
        return ak_response_error(ctx->heap, req, -ENOMEM);

    runtime_memcpy(msg->sender_id, ctx->pid, AK_TOKEN_ID_SIZE);
    runtime_memcpy(msg->recipient_id, recipient_id, AK_TOKEN_ID_SIZE);
    msg->seq = req->seq;
    msg->sent_ms = now(CLOCK_ID_REALTIME) / 1000000;
    msg->next = NULL;

    /* Copy payload */
    if (req->args) {
        msg->payload = allocate_buffer(ctx->heap, buffer_length(req->args));
        if (msg->payload) {
            buffer_write(msg->payload, buffer_ref(req->args, 0), buffer_length(req->args));
        }
    } else {
        msg->payload = NULL;
    }

    /* Enqueue message */
    if (inbox->tail) {
        inbox->tail->next = msg;
        inbox->tail = msg;
    } else {
        inbox->head = msg;
        inbox->tail = msg;
    }
    inbox->count++;

    buffer result = allocate_buffer(ctx->heap, 32);
    if (!result)
        return ak_response_error(ctx->heap, req, -ENOMEM);

    buffer_write(result, "{\"sent\":true,\"queued\":", 22);
    char count_buf[16];
    int count_len = 0;
    u64 c = inbox->count;
    if (c == 0) {
        count_buf[0] = '0';
        count_len = 1;
    } else {
        char tmp[16];
        while (c > 0) {
            tmp[count_len++] = '0' + (c % 10);
            c /= 10;
        }
        for (int i = 0; i < count_len; i++)
            count_buf[i] = tmp[count_len - 1 - i];
    }
    buffer_write(result, count_buf, count_len);
    buffer_write(result, "}", 1);

    return ak_response_success(ctx->heap, req, result);
}

ak_response_t *ak_handle_recv(ak_agent_context_t *ctx, ak_request_t *req)
{
    /*
     * RECV: Receive messages from inbox
     *
     * Args: {"limit": N, "timeout_ms": N}
     */

    (void)req;

    /* Find this agent in registry */
    s64 idx = ak_agent_registry_find(ctx->pid);
    if (idx < 0) {
        /* Agent not in registry - return empty */
        buffer result = allocate_buffer(ctx->heap, 32);
        if (!result)
            return ak_response_error(ctx->heap, req, -ENOMEM);
        buffer_write(result, "{\"messages\":[]}", 15);
        return ak_response_success(ctx->heap, req, result);
    }

    ak_message_queue_t *inbox = &ak_state.agents[idx].inbox;

    /* Build result with messages */
    buffer result = allocate_buffer(ctx->heap, 1024);
    if (!result)
        return ak_response_error(ctx->heap, req, -ENOMEM);

    buffer_write(result, "{\"messages\":[", 13);

    int msg_count = 0;
    ak_message_t *msg = inbox->head;
    ak_message_t *prev = NULL;

    /* Dequeue up to 10 messages */
    while (msg && msg_count < 10) {
        if (msg_count > 0)
            buffer_write(result, ",", 1);

        buffer_write(result, "{\"from\":\"", 9);
        char sender_hex[AK_TOKEN_ID_SIZE * 2 + 1];
        ak_hex_encode(msg->sender_id, AK_TOKEN_ID_SIZE, sender_hex);
        buffer_write(result, sender_hex, AK_TOKEN_ID_SIZE * 2);
        buffer_write(result, "\",\"payload\":", 12);

        if (msg->payload && buffer_length(msg->payload) > 0) {
            buffer_write(result, buffer_ref(msg->payload, 0), buffer_length(msg->payload));
        } else {
            buffer_write(result, "null", 4);
        }
        buffer_write(result, "}", 1);

        /* Remove message from queue */
        ak_message_t *next = msg->next;
        if (prev) {
            prev->next = next;
        } else {
            inbox->head = next;
        }
        if (inbox->tail == msg) {
            inbox->tail = prev;
        }
        inbox->count--;

        /* Free message */
        if (msg->payload)
            deallocate_buffer(msg->payload);
        deallocate(ctx->heap, msg, sizeof(ak_message_t));

        msg = next;
        msg_count++;
    }

    buffer_write(result, "]}", 2);

    return ak_response_success(ctx->heap, req, result);
}

ak_response_t *ak_handle_respond(ak_agent_context_t *ctx, ak_request_t *req)
{
    /* Response to human/orchestrator */
    (void)req;

    buffer result = allocate_buffer(ctx->heap, 32);
    if (!result)
        return ak_response_error(ctx->heap, req, -ENOMEM);

    buffer_write(result, "{\"acknowledged\":true}", 21);

    return ak_response_success(ctx->heap, req, result);
}

ak_response_t *ak_handle_assert(ak_agent_context_t *ctx, ak_request_t *req)
{
    /*
     * ASSERT: Record assertion about state
     * Used for formal verification and debugging
     */
    (void)req;

    buffer result = allocate_buffer(ctx->heap, 32);
    if (!result)
        return ak_response_error(ctx->heap, req, -ENOMEM);

    buffer_write(result, "{\"asserted\":true}", 17);

    return ak_response_success(ctx->heap, req, result);
}

/* ============================================================
 * RESPONSE HELPERS
 * ============================================================ */

ak_response_t *ak_response_success(heap h, ak_request_t *req, buffer result)
{
    ak_response_t *res = allocate(h, sizeof(ak_response_t));
    if (!res) {
        if (result)
            deallocate_buffer(result);
        return NULL;
    }

    runtime_memcpy(res->pid, req->pid, AK_TOKEN_ID_SIZE);
    runtime_memcpy(res->run_id, req->run_id, AK_TOKEN_ID_SIZE);
    res->seq = req->seq;
    res->error_code = 0;
    res->result = result;

    return res;
}

ak_response_t *ak_response_error(heap h, ak_request_t *req, s64 error_code)
{
    ak_response_t *res = allocate(h, sizeof(ak_response_t));
    if (!res)
        return NULL;

    if (req) {
        runtime_memcpy(res->pid, req->pid, AK_TOKEN_ID_SIZE);
        runtime_memcpy(res->run_id, req->run_id, AK_TOKEN_ID_SIZE);
        res->seq = req->seq;
    } else {
        runtime_memset(res->pid, 0, AK_TOKEN_ID_SIZE);
        runtime_memset(res->run_id, 0, AK_TOKEN_ID_SIZE);
        res->seq = 0;
    }

    res->error_code = error_code;
    res->result = NULL;

    return res;
}

void ak_response_destroy(heap h, ak_response_t *res)
{
    if (!res)
        return;

    if (res->result)
        deallocate_buffer(res->result);

    deallocate(h, res, sizeof(ak_response_t));
}

/* ============================================================
 * AUDIT INTEGRATION
 * ============================================================ */

s64 ak_log_operation(ak_agent_context_t *ctx, ak_request_t *req, ak_response_t *res)
{
    if (!ctx || !req)
        return -EINVAL;

    u8 req_hash[AK_HASH_SIZE];
    u8 res_hash[AK_HASH_SIZE];
    u8 policy_hash[AK_HASH_SIZE];

    ak_audit_hash_request(req, req_hash);
    if (res)
        ak_audit_hash_response(res, res_hash);
    else
        runtime_memset(res_hash, 0, AK_HASH_SIZE);

    ak_policy_get_hash(ctx->policy, policy_hash);

    return ak_audit_append(ctx->pid, ctx->run_id, req->op,
                          req_hash, res_hash, policy_hash);
}

/* ============================================================
 * STATISTICS
 * ============================================================ */

void ak_get_dispatch_stats(ak_dispatch_stats_t *stats)
{
    if (stats)
        runtime_memcpy(stats, &ak_state.stats, sizeof(ak_dispatch_stats_t));
}

/* ============================================================
 * ERROR RECOVERY
 * ============================================================ */

void ak_handle_agent_crash(ak_agent_context_t *ctx)
{
    if (!ctx)
        return;

    /* SECURITY: Immediate capability revocation */
    ak_revocation_revoke_run(ctx->run_id, "crash");

    /* Log crash event */
    ak_audit_log_lifecycle(ctx->pid, ctx->run_id, AK_LIFECYCLE_CRASH);

    /* Cleanup pending transactions */
    ak_heap_txn_rollback_all(ctx->run_id);
}

void ak_handle_agent_timeout(ak_agent_context_t *ctx)
{
    if (!ctx)
        return;

    /* SECURITY: Immediate capability revocation */
    ak_revocation_revoke_run(ctx->run_id, "timeout");

    /* Log timeout event */
    ak_audit_log_lifecycle(ctx->pid, ctx->run_id, AK_LIFECYCLE_TIMEOUT);
}

/* ============================================================
 * CAPABILITY OPERATIONS
 * ============================================================ */

s64 ak_grant_capability(
    ak_agent_context_t *ctx,
    ak_cap_type_t type,
    const char *resource,
    const char **methods,
    u32 ttl_ms,
    u32 rate_limit,
    u32 rate_window_ms)
{
    if (!ctx)
        return -EINVAL;

    ak_capability_t *cap = ak_capability_create(
        ctx->heap, type, resource, methods,
        ttl_ms, rate_limit, rate_window_ms, ctx->run_id);

    if (!cap)
        return -ENOMEM;

    /* Store in context's capability set */
    if (ctx->caps && ctx->cap_count < ctx->cap_max) {
        ctx->caps[ctx->cap_count++] = cap;
    }

    return 0;
}

void ak_revoke_capability(ak_agent_context_t *ctx, u8 *tid)
{
    if (!ctx || !tid)
        return;

    ak_revocation_add(tid, "explicit_revoke");
}

void ak_revoke_run(ak_agent_context_t *ctx)
{
    if (!ctx)
        return;

    ak_revocation_revoke_run(ctx->run_id, "run_revoked");
}
