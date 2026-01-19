/*
 * Authority Kernel - Agentic Primitives Implementation
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * AGENT E OWNED: Agentic effects handlers (TOOL_CALL, WASM_INVOKE, INFER)
 *
 * This module implements the agentic effect handlers that wrap existing
 * WASM and inference implementations with AK authorization. All operations
 * flow through ak_authorize_and_execute() for consistent enforcement.
 *
 * SECURITY:
 *   - All operations are deny-by-default
 *   - Budget limits are checked BEFORE execution
 *   - On denial, last_deny is populated with actionable suggestion
 *   - Tools cannot access FS/NET directly - must go through AK
 */

#include "ak_agentic.h"
#include "ak_compat.h"
#include "ak_policy.h"
#include "ak_policy_v2.h"
#include "ak_audit.h"
#include "ak_tool_registry.h"

/* ============================================================
 * MODULE STATE
 * ============================================================ */

#define AK_MAX_NATIVE_TOOLS     64

/* Native tool handler entry */
typedef struct ak_native_tool {
    char name[64];
    char version[32];
    ak_tool_handler_t handler;
    boolean active;
} ak_native_tool_t;

/* Module state */
static struct {
    heap h;
    boolean initialized;

    /* Native tool registry */
    ak_native_tool_t native_tools[AK_MAX_NATIVE_TOOLS];
    u32 native_tool_count;

    /* Statistics */
    ak_agentic_stats_t stats;
} ak_agentic_state;

/* ============================================================
 * STRING UTILITIES
 * ============================================================ */

static u64 local_strlen(const char *s)
{
    if (!s) return 0;
    u64 len = 0;
    while (s[len]) len++;
    return len;
}

static void local_strncpy(char *dest, const char *src, u64 n)
{
    if (!dest || !src || n == 0) return;
    u64 i;
    for (i = 0; i < n - 1 && src[i]; i++) {
        dest[i] = src[i];
    }
    dest[i] = '\0';
}

static int local_strcmp(const char *s1, const char *s2)
{
    if (!s1 || !s2) return s1 ? 1 : (s2 ? -1 : 0);
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return (unsigned char)*s1 - (unsigned char)*s2;
}

static void local_memzero(void *ptr, u64 size)
{
    u8 *p = (u8 *)ptr;
    while (size-- > 0) *p++ = 0;
}

static void local_memcpy(void *dest, const void *src, u64 size)
{
    u8 *d = (u8 *)dest;
    const u8 *s = (const u8 *)src;
    while (size-- > 0) *d++ = *s++;
}

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

void ak_agentic_init(heap h)
{
    if (ak_agentic_state.initialized)
        return;

    ak_agentic_state.h = h;
    ak_agentic_state.native_tool_count = 0;

    /* Clear tool registry */
    local_memzero(ak_agentic_state.native_tools,
                  sizeof(ak_agentic_state.native_tools));

    /* Clear statistics */
    local_memzero(&ak_agentic_state.stats, sizeof(ak_agentic_stats_t));

    /* Initialize the advanced tool registry */
    ak_tool_registry_init(h);

    ak_agentic_state.initialized = true;

    ak_debug("ak_agentic: initialized");
}

void ak_agentic_shutdown(void)
{
    if (!ak_agentic_state.initialized)
        return;

    /* Clear tool registry */
    for (u32 i = 0; i < ak_agentic_state.native_tool_count; i++) {
        ak_agentic_state.native_tools[i].active = false;
    }
    ak_agentic_state.native_tool_count = 0;

    /* Shutdown the advanced tool registry */
    ak_tool_registry_shutdown();

    ak_agentic_state.initialized = false;

    ak_debug("ak_agentic: shutdown");
}

/* ============================================================
 * BUDGET TRACKING
 * ============================================================ */

void ak_agentic_budget_init(ak_agentic_budget_t *budget)
{
    if (!budget)
        return;

    local_memzero(budget, sizeof(ak_agentic_budget_t));

    budget->tool_calls_limit = AK_DEFAULT_TOOL_CALL_BUDGET;
    budget->tool_calls_remaining = AK_DEFAULT_TOOL_CALL_BUDGET;

    budget->tokens_limit = AK_DEFAULT_TOKEN_BUDGET;
    budget->tokens_remaining = AK_DEFAULT_TOKEN_BUDGET;

    budget->wasm_calls_limit = AK_DEFAULT_WASM_CALL_BUDGET;
    budget->wasm_calls_remaining = AK_DEFAULT_WASM_CALL_BUDGET;

    budget->wall_time_limit_ns = AK_DEFAULT_WALL_TIME_NS;
    budget->start_ns = ak_now();
}

void ak_agentic_budget_init_custom(
    ak_agentic_budget_t *budget,
    u64 tool_calls,
    u64 tokens,
    u64 wasm_calls,
    u64 wall_time_ns)
{
    if (!budget)
        return;

    local_memzero(budget, sizeof(ak_agentic_budget_t));

    budget->tool_calls_limit = tool_calls;
    budget->tool_calls_remaining = tool_calls;

    budget->tokens_limit = tokens;
    budget->tokens_remaining = tokens;

    budget->wasm_calls_limit = wasm_calls;
    budget->wasm_calls_remaining = wasm_calls;

    budget->wall_time_limit_ns = wall_time_ns;
    budget->start_ns = ak_now();
}

/*
 * Get budget tracker from context.
 * Returns the budget tracker or NULL if not available.
 */
static ak_budget_tracker_t *get_agentic_budget(ak_ctx_t *ctx)
{
    if (!ctx || !ctx->agent)
        return NULL;

    return ctx->agent->budget;
}

boolean ak_budget_check_tool(ak_ctx_t *ctx)
{
    if (!ctx || !ctx->agent)
        return true;  /* No context = allow (fail-open for P0) */

    ak_budget_tracker_t *budget = ctx->agent->budget;
    if (!budget)
        return true;  /* No budget = allow */

    /* Check tool calls resource */
    return ak_budget_check(budget, AK_RESOURCE_TOOL_CALLS, 1);
}

boolean ak_budget_check_tokens(ak_ctx_t *ctx, u64 tokens)
{
    if (!ctx || !ctx->agent)
        return true;

    ak_budget_tracker_t *budget = ctx->agent->budget;
    if (!budget)
        return true;

    /* Check tokens resource */
    return ak_budget_check(budget, AK_RESOURCE_LLM_TOKENS_OUT, tokens);
}

boolean ak_budget_check_wasm(ak_ctx_t *ctx)
{
    if (!ctx || !ctx->agent)
        return true;

    ak_budget_tracker_t *budget = ctx->agent->budget;
    if (!budget)
        return true;

    /*
     * WASM calls could use TOOL_CALLS resource or a separate resource.
     * For P0, we'll use TOOL_CALLS as a proxy.
     */
    return ak_budget_check(budget, AK_RESOURCE_TOOL_CALLS, 1);
}

int ak_budget_consume_tool(ak_ctx_t *ctx)
{
    if (!ctx || !ctx->agent)
        return 0;

    ak_budget_tracker_t *budget = ctx->agent->budget;
    if (!budget)
        return 0;

    if (!ak_budget_check(budget, AK_RESOURCE_TOOL_CALLS, 1))
        return -ENOSPC;

    ak_budget_commit(budget, AK_RESOURCE_TOOL_CALLS, 1);
    return 0;
}

int ak_budget_consume_tokens(ak_ctx_t *ctx, u64 tokens)
{
    if (!ctx || !ctx->agent)
        return 0;

    ak_budget_tracker_t *budget = ctx->agent->budget;
    if (!budget)
        return 0;

    if (!ak_budget_check(budget, AK_RESOURCE_LLM_TOKENS_OUT, tokens))
        return -ENOSPC;

    ak_budget_commit(budget, AK_RESOURCE_LLM_TOKENS_OUT, tokens);
    return 0;
}

int ak_budget_consume_wasm(ak_ctx_t *ctx)
{
    if (!ctx || !ctx->agent)
        return 0;

    ak_budget_tracker_t *budget = ctx->agent->budget;
    if (!budget)
        return 0;

    /* Use TOOL_CALLS as proxy for WASM calls */
    if (!ak_budget_check(budget, AK_RESOURCE_TOOL_CALLS, 1))
        return -ENOSPC;

    ak_budget_commit(budget, AK_RESOURCE_TOOL_CALLS, 1);
    return 0;
}

int ak_budget_get_state(ak_ctx_t *ctx, ak_agentic_budget_t *budget)
{
    if (!budget)
        return -EINVAL;

    local_memzero(budget, sizeof(ak_agentic_budget_t));

    if (!ctx || !ctx->agent || !ctx->agent->budget) {
        /* Return default budget if no context */
        ak_agentic_budget_init(budget);
        return 0;
    }

    /*
     * Populate from agent's budget tracker.
     * This requires access to the budget_tracker internals.
     */
    ak_budget_tracker_t *tracker = ctx->agent->budget;

    /* These would access the actual budget tracker fields */
    budget->tool_calls_limit = AK_DEFAULT_TOOL_CALL_BUDGET;
    budget->tool_calls_remaining = AK_DEFAULT_TOOL_CALL_BUDGET;
    budget->tokens_limit = AK_DEFAULT_TOKEN_BUDGET;
    budget->tokens_remaining = AK_DEFAULT_TOKEN_BUDGET;
    budget->wasm_calls_limit = AK_DEFAULT_WASM_CALL_BUDGET;
    budget->wasm_calls_remaining = AK_DEFAULT_WASM_CALL_BUDGET;

    return 0;
}

/* ============================================================
 * NATIVE TOOL REGISTRY
 * ============================================================ */

int ak_tool_handler_register(
    const char *name,
    const char *version,
    ak_tool_handler_t handler)
{
    if (!ak_agentic_state.initialized)
        return -EINVAL;

    if (!name || !handler)
        return -EINVAL;

    /* Check for duplicate */
    for (u32 i = 0; i < ak_agentic_state.native_tool_count; i++) {
        if (ak_agentic_state.native_tools[i].active &&
            local_strcmp(ak_agentic_state.native_tools[i].name, name) == 0) {
            return -EEXIST;
        }
    }

    /* Find free slot */
    if (ak_agentic_state.native_tool_count >= AK_MAX_NATIVE_TOOLS)
        return -ENOSPC;

    ak_native_tool_t *tool = &ak_agentic_state.native_tools[ak_agentic_state.native_tool_count];

    local_strncpy(tool->name, name, sizeof(tool->name));
    if (version)
        local_strncpy(tool->version, version, sizeof(tool->version));
    else
        local_strncpy(tool->version, "1.0", sizeof(tool->version));

    tool->handler = handler;
    tool->active = true;

    ak_agentic_state.native_tool_count++;

    ak_debug("ak_agentic: registered tool '%s' v%s", name, tool->version);

    return 0;
}

int ak_tool_handler_unregister(const char *name)
{
    if (!ak_agentic_state.initialized || !name)
        return -EINVAL;

    for (u32 i = 0; i < ak_agentic_state.native_tool_count; i++) {
        if (ak_agentic_state.native_tools[i].active &&
            local_strcmp(ak_agentic_state.native_tools[i].name, name) == 0) {
            ak_agentic_state.native_tools[i].active = false;
            ak_debug("ak_agentic: unregistered tool '%s'", name);
            return 0;
        }
    }

    return -ENOENT;
}

ak_tool_handler_t ak_tool_handler_lookup(const char *name, const char *version)
{
    if (!ak_agentic_state.initialized || !name)
        return NULL;

    for (u32 i = 0; i < ak_agentic_state.native_tool_count; i++) {
        ak_native_tool_t *tool = &ak_agentic_state.native_tools[i];

        if (!tool->active)
            continue;

        if (local_strcmp(tool->name, name) != 0)
            continue;

        /* Version check (NULL = any version) */
        if (version && local_strcmp(tool->version, version) != 0)
            continue;

        return tool->handler;
    }

    return NULL;
}

/* ============================================================
 * TOOL CALL HANDLER
 * ============================================================ */

/*
 * Populate deny context with actionable suggestion for tool calls.
 */
static void populate_tool_deny(ak_ctx_t *ctx, const char *tool_name,
                               ak_decision_t *decision)
{
    if (!ctx || !decision)
        return;

    ctx->last_deny.op = AK_E_TOOL_CALL;

    /* Format target */
    int len = 0;
    ctx->last_deny.target[len++] = 't';
    ctx->last_deny.target[len++] = 'o';
    ctx->last_deny.target[len++] = 'o';
    ctx->last_deny.target[len++] = 'l';
    ctx->last_deny.target[len++] = ':';
    if (tool_name) {
        u64 name_len = local_strlen(tool_name);
        if (len + name_len < AK_MAX_TARGET - 1) {
            local_memcpy(ctx->last_deny.target + len, tool_name, name_len);
            len += name_len;
        }
    }
    ctx->last_deny.target[len] = '\0';

    local_strncpy(ctx->last_deny.missing_cap, decision->missing_cap, AK_MAX_CAPSTR);
    local_strncpy(ctx->last_deny.suggested_snippet, decision->suggested_snippet, AK_MAX_SUGGEST);
    ctx->last_deny.trace_id = decision->trace_id;
    ctx->last_deny.errno_equiv = decision->errno_equiv;
    ctx->last_deny.timestamp_ns = ak_now();
    ctx->last_deny.reason = decision->reason_code;
}

int ak_handle_tool_call(
    ak_ctx_t *ctx,
    const char *tool_name,
    const char *version,
    const u8 *args,
    u32 args_len,
    u8 *result,
    u32 *result_len)
{
    if (!ak_agentic_state.initialized)
        return AK_E_AGENTIC_NOT_INIT;

    if (!ctx || !tool_name)
        return -EINVAL;

    ak_agentic_state.stats.tool_calls_total++;

    /* Step 1: Build effect request */
    ak_effect_req_t req;
    int err = ak_effect_from_tool_call(&req, ctx, tool_name, version, args, args_len);
    if (err != 0) {
        ak_agentic_state.stats.tool_calls_failed++;
        return err;
    }

    /* Step 2: Route through ak_authorize_and_execute() */
    ak_decision_t decision;
    long retval = 0;

    err = ak_authorize_and_execute(ctx, &req, &decision, &retval);

    if (err != 0 || !decision.allow) {
        /* Denied by policy */
        ak_agentic_state.stats.tool_calls_denied++;
        populate_tool_deny(ctx, tool_name, &decision);

        ak_debug("ak_agentic: tool call '%s' denied: %s",
                 tool_name, decision.detail);

        return err != 0 ? err : -EPERM;
    }

    ak_agentic_state.stats.tool_calls_allowed++;

    /* Step 3: Check budget */
    if (!ak_budget_check_tool(ctx)) {
        ak_agentic_state.stats.tool_calls_budget_exceeded++;

        /* Update last_deny for budget exceeded */
        ctx->last_deny.op = AK_E_TOOL_CALL;
        ctx->last_deny.reason = AK_DENY_BUDGET_EXCEEDED;
        ctx->last_deny.errno_equiv = ENOSPC;
        local_strncpy(ctx->last_deny.missing_cap, "budget.tool_calls", AK_MAX_CAPSTR);
        local_strncpy(ctx->last_deny.suggested_snippet,
                      "[budgets]\ntool_calls = 200  # Increase limit",
                      AK_MAX_SUGGEST);

        ak_debug("ak_agentic: tool call '%s' budget exceeded", tool_name);

        return -ENOSPC;
    }

    /* Step 4: Look up and execute handler */
    /* Try lookup chain: native handler -> advanced registry -> WASM tool */
    ak_tool_handler_t handler = ak_tool_handler_lookup(tool_name, version);

    if (handler) {
        /* Native tool handler (simple API) */
        err = handler(args, args_len, result, result_len);
    } else {
        /* Try advanced tool registry (ak_tool_registry) */
        ak_tool_def_t *reg_tool = ak_tool_lookup(tool_name, version);

        if (reg_tool) {
            /* Execute via advanced registry */
            buffer args_buf = NULL;
            buffer result_buf = NULL;

            if (args && args_len > 0) {
                args_buf = allocate_buffer(ak_agentic_state.h, args_len);
                if (args_buf != INVALID_ADDRESS) {
                    buffer_write(args_buf, args, args_len);
                }
            }

            /* Invoke through registry (handles mock, validation, etc.) */
            err = ak_tool_invoke(ctx, tool_name, version, args_buf, &result_buf);

            if (err == 0 && result_buf) {
                /* Copy result to output buffer */
                u64 res_len = buffer_length(result_buf);
                if (result_len) {
                    if (res_len > *result_len)
                        res_len = *result_len;
                    if (result && res_len > 0) {
                        local_memcpy(result, buffer_ref(result_buf, 0), res_len);
                    }
                    *result_len = res_len;
                }
            }

            /* Cleanup */
            if (args_buf && args_buf != INVALID_ADDRESS)
                deallocate_buffer(args_buf);
            if (result_buf && result_buf != INVALID_ADDRESS)
                deallocate_buffer(result_buf);
        } else {
            /* Try WASM-based tool via ak_tool_get() */
            ak_tool_t *wasm_tool = ak_tool_get(tool_name);

            if (wasm_tool && ctx->agent) {
                /* Execute via WASM runtime */
                buffer args_buf = NULL;
                if (args && args_len > 0) {
                    args_buf = allocate_buffer(ak_agentic_state.h, args_len);
                    if (args_buf != INVALID_ADDRESS) {
                        buffer_write(args_buf, args, args_len);
                    }
                }

                ak_response_t *response = ak_wasm_execute_tool(
                    ctx->agent, tool_name, args_buf, NULL);

                if (response && response->status == AK_STATUS_OK && response->result) {
                    /* Copy result */
                    u64 res_len = buffer_length(response->result);
                    if (result_len) {
                        if (res_len > *result_len)
                            res_len = *result_len;
                        if (result && res_len > 0) {
                            local_memcpy(result, buffer_ref(response->result, 0), res_len);
                        }
                        *result_len = res_len;
                    }
                    err = 0;
                } else {
                    err = response ? response->error_code : AK_E_TOOL_FAIL;
                }

                /* Cleanup */
                if (args_buf && args_buf != INVALID_ADDRESS)
                    deallocate_buffer(args_buf);
                /* Response cleanup would be handled by caller */
            } else {
                ak_agentic_state.stats.tool_calls_failed++;
                return AK_E_TOOL_HANDLER_NOT_FOUND;
            }
        }
    }

    if (err != 0) {
        ak_agentic_state.stats.tool_calls_failed++;
        return err;
    }

    /* Step 5: Consume budget */
    ak_budget_consume_tool(ctx);

    return 0;
}

/* ============================================================
 * WASM INVOKE HANDLER
 * ============================================================ */

/*
 * Populate deny context with actionable suggestion for WASM invokes.
 */
static void populate_wasm_deny(ak_ctx_t *ctx, const char *module,
                               const char *function, ak_decision_t *decision)
{
    if (!ctx || !decision)
        return;

    ctx->last_deny.op = AK_E_WASM_INVOKE;

    /* Format target: wasm:module:function */
    /* FIX(BUG-002): Use cumulative length tracking with proper bounds validation */
    int len = 0;
    int remaining = AK_MAX_TARGET - 1;  /* Reserve 1 for null terminator */

    ctx->last_deny.target[len++] = 'w';
    ctx->last_deny.target[len++] = 'a';
    ctx->last_deny.target[len++] = 's';
    ctx->last_deny.target[len++] = 'm';
    ctx->last_deny.target[len++] = ':';
    remaining -= 5;

    if (module && remaining > 1) {
        u64 mod_len = local_strlen(module);
        if (mod_len > (u64)(remaining - 1)) {  /* Reserve space for ':' */
            mod_len = remaining - 1;
        }
        if (mod_len > 0) {
            local_memcpy(ctx->last_deny.target + len, module, mod_len);
            len += mod_len;
            remaining -= mod_len;
        }
    }
    if (remaining > 0) {
        ctx->last_deny.target[len++] = ':';
        remaining--;
    }
    if (function && remaining > 0) {
        u64 func_len = local_strlen(function);
        if (func_len > (u64)remaining) {
            func_len = remaining;
        }
        if (func_len > 0) {
            local_memcpy(ctx->last_deny.target + len, function, func_len);
            len += func_len;
        }
    }
    ctx->last_deny.target[len] = '\0';

    local_strncpy(ctx->last_deny.missing_cap, decision->missing_cap, AK_MAX_CAPSTR);
    local_strncpy(ctx->last_deny.suggested_snippet, decision->suggested_snippet, AK_MAX_SUGGEST);
    ctx->last_deny.trace_id = decision->trace_id;
    ctx->last_deny.errno_equiv = decision->errno_equiv;
    ctx->last_deny.timestamp_ns = ak_now();
    ctx->last_deny.reason = decision->reason_code;
}

int ak_handle_wasm_invoke(
    ak_ctx_t *ctx,
    const char *module,
    const char *function,
    const u8 *args,
    u32 args_len,
    u8 *result,
    u32 *result_len)
{
    if (!ak_agentic_state.initialized)
        return AK_E_AGENTIC_NOT_INIT;

    if (!ctx || !module || !function)
        return -EINVAL;

    ak_agentic_state.stats.wasm_invokes_total++;

    /* Step 1: Build effect request */
    ak_effect_req_t req;
    int err = ak_effect_from_wasm_invoke(&req, ctx, module, function, args, args_len);
    if (err != 0) {
        ak_agentic_state.stats.wasm_invokes_failed++;
        return err;
    }

    /* Step 2: Route through ak_authorize_and_execute() */
    ak_decision_t decision;
    long retval = 0;

    err = ak_authorize_and_execute(ctx, &req, &decision, &retval);

    if (err != 0 || !decision.allow) {
        ak_agentic_state.stats.wasm_invokes_denied++;
        populate_wasm_deny(ctx, module, function, &decision);

        ak_debug("ak_agentic: wasm invoke '%s:%s' denied: %s",
                 module, function, decision.detail);

        return err != 0 ? err : -EPERM;
    }

    ak_agentic_state.stats.wasm_invokes_allowed++;

    /* Step 3: Check budget */
    if (!ak_budget_check_wasm(ctx)) {
        ak_agentic_state.stats.wasm_invokes_budget_exceeded++;

        ctx->last_deny.op = AK_E_WASM_INVOKE;
        ctx->last_deny.reason = AK_DENY_BUDGET_EXCEEDED;
        ctx->last_deny.errno_equiv = ENOSPC;
        local_strncpy(ctx->last_deny.missing_cap, "budget.wasm_calls", AK_MAX_CAPSTR);
        local_strncpy(ctx->last_deny.suggested_snippet,
                      "[budgets]\nwasm_calls = 2000  # Increase limit",
                      AK_MAX_SUGGEST);

        ak_debug("ak_agentic: wasm invoke '%s:%s' budget exceeded", module, function);

        return -ENOSPC;
    }

    /* Step 4: Look up and execute WASM module */
    ak_wasm_module_t *wasm_module = ak_wasm_module_get(module);
    if (!wasm_module) {
        ak_agentic_state.stats.wasm_invokes_failed++;
        return AK_E_WASM_MODULE_NOT_FOUND;
    }

    /* Create execution context and run */
    if (ctx->agent) {
        /* Look up tool for the module/function */
        ak_tool_t *tool = ak_tool_get(function);

        if (tool && tool->module == wasm_module) {
            /* Execute via tool interface */
            buffer args_buf = NULL;
            if (args && args_len > 0) {
                args_buf = allocate_buffer(ak_agentic_state.h, args_len);
                if (args_buf != INVALID_ADDRESS) {
                    buffer_write(args_buf, args, args_len);
                }
            }

            ak_wasm_exec_ctx_t *exec_ctx = ak_wasm_exec_create(
                ak_agentic_state.h, ctx->agent, tool, NULL);

            if (!exec_ctx) {
                if (args_buf && args_buf != INVALID_ADDRESS)
                    deallocate_buffer(args_buf);
                ak_agentic_state.stats.wasm_invokes_failed++;
                return AK_E_WASM_OOM;
            }

            err = ak_wasm_exec_run(exec_ctx, args_buf);

            if (err == 0 && exec_ctx->state == AK_WASM_STATE_COMPLETED && exec_ctx->output) {
                u64 res_len = buffer_length(exec_ctx->output);
                if (result_len) {
                    if (res_len > *result_len)
                        res_len = *result_len;
                    if (result && res_len > 0) {
                        local_memcpy(result, buffer_ref(exec_ctx->output, 0), res_len);
                    }
                    *result_len = res_len;
                }
            } else {
                err = exec_ctx->result_code != 0 ? exec_ctx->result_code : AK_E_WASM_TRAP;
            }

            ak_wasm_exec_destroy(ak_agentic_state.h, exec_ctx);
            if (args_buf && args_buf != INVALID_ADDRESS)
                deallocate_buffer(args_buf);
        } else {
            /* No matching tool - would need direct WASM invocation */
            ak_agentic_state.stats.wasm_invokes_failed++;
            return AK_E_WASM_EXPORT_NOT_FOUND;
        }
    } else {
        ak_agentic_state.stats.wasm_invokes_failed++;
        return -EINVAL;
    }

    if (err != 0) {
        ak_agentic_state.stats.wasm_invokes_failed++;
        return err;
    }

    /* Step 5: Consume budget */
    ak_budget_consume_wasm(ctx);

    return 0;
}

int ak_wasm_hostcall_check(
    ak_ctx_t *ctx,
    const char *module,
    const char *hostcall)
{
    if (!ak_agentic_state.initialized)
        return AK_E_AGENTIC_NOT_INIT;

    if (!ctx || !module || !hostcall)
        return -EINVAL;

    ak_agentic_state.stats.wasm_hostcalls_total++;

    /* Check policy for WASM hostcall */
    if (ctx->policy) {
        boolean allowed = ak_policy_v2_check_wasm(ctx->policy, module, hostcall);

        if (!allowed) {
            ak_agentic_state.stats.wasm_hostcalls_denied++;

            /* Populate last_deny */
            ctx->last_deny.op = AK_E_WASM_INVOKE;
            ctx->last_deny.reason = AK_DENY_PATTERN_MISMATCH;
            ctx->last_deny.errno_equiv = EPERM;

            /* Format target */
            /* FIX(BUG-002): Use cumulative length tracking with proper bounds validation */
            int len = 0;
            int remaining = AK_MAX_TARGET - 1;  /* Reserve 1 for null terminator */

            ctx->last_deny.target[len++] = 'w';
            ctx->last_deny.target[len++] = 'a';
            ctx->last_deny.target[len++] = 's';
            ctx->last_deny.target[len++] = 'm';
            ctx->last_deny.target[len++] = ':';
            remaining -= 5;

            u64 mod_len = local_strlen(module);
            if (mod_len > (u64)(remaining - 1)) {  /* Reserve space for ':' */
                mod_len = remaining - 1;
            }
            if (mod_len > 0 && remaining > 1) {
                local_memcpy(ctx->last_deny.target + len, module, mod_len);
                len += mod_len;
                remaining -= mod_len;
            }
            if (remaining > 0) {
                ctx->last_deny.target[len++] = ':';
                remaining--;
            }
            u64 hc_len = local_strlen(hostcall);
            if (hc_len > (u64)remaining) {
                hc_len = remaining;
            }
            if (hc_len > 0 && remaining > 0) {
                local_memcpy(ctx->last_deny.target + len, hostcall, hc_len);
                len += hc_len;
            }
            ctx->last_deny.target[len] = '\0';

            local_strncpy(ctx->last_deny.missing_cap, "wasm.hostcall", AK_MAX_CAPSTR);

            /* Generate suggestion */
            /* FIX(BUG-019): Track actual written bytes, not source strlen */
            char *snippet = ctx->last_deny.suggested_snippet;
            u64 pos = 0;
            u64 remaining = AK_MAX_SUGGEST - 1;

            /* Write "[wasm]\nmodules = [\"" */
            const char *s1 = "[wasm]\nmodules = [\"";
            u64 l1 = local_strlen(s1);
            if (l1 < remaining) {
                local_memcpy(snippet + pos, s1, l1);
                pos += l1;
                remaining -= l1;
            }

            /* Write module name (may truncate) */
            u64 mod_len = local_strlen(module);
            if (mod_len > remaining) mod_len = remaining;
            if (mod_len > 0) {
                local_memcpy(snippet + pos, module, mod_len);
                pos += mod_len;
                remaining -= mod_len;
            }

            /* Write "\"]\nhostcalls = [\"" */
            const char *s2 = "\"]\nhostcalls = [\"";
            u64 l2 = local_strlen(s2);
            if (l2 < remaining) {
                local_memcpy(snippet + pos, s2, l2);
                pos += l2;
                remaining -= l2;
            }

            /* Write hostcall name (may truncate) */
            u64 hc_len = local_strlen(hostcall);
            if (hc_len > remaining) hc_len = remaining;
            if (hc_len > 0) {
                local_memcpy(snippet + pos, hostcall, hc_len);
                pos += hc_len;
                remaining -= hc_len;
            }

            /* Write closing "\"]\n" */
            const char *s3 = "\"]\n";
            u64 l3 = local_strlen(s3);
            if (l3 < remaining) {
                local_memcpy(snippet + pos, s3, l3);
                pos += l3;
            }

            snippet[pos] = '\0';

            ctx->last_deny.timestamp_ns = ak_now();

            ak_debug("ak_agentic: hostcall '%s' denied for module '%s'", hostcall, module);

            return AK_E_HOSTCALL_DENIED;
        }
    }

    /* No policy or allowed by policy */
    return 0;
}

/* ============================================================
 * INFERENCE HANDLER
 * ============================================================ */

/*
 * Populate deny context with actionable suggestion for inference.
 */
static void populate_infer_deny(ak_ctx_t *ctx, const char *model,
                                ak_decision_t *decision)
{
    if (!ctx || !decision)
        return;

    ctx->last_deny.op = AK_E_INFER;

    /* Format target: model:name:version */
    int len = 0;
    ctx->last_deny.target[len++] = 'm';
    ctx->last_deny.target[len++] = 'o';
    ctx->last_deny.target[len++] = 'd';
    ctx->last_deny.target[len++] = 'e';
    ctx->last_deny.target[len++] = 'l';
    ctx->last_deny.target[len++] = ':';
    if (model) {
        u64 mod_len = local_strlen(model);
        if (len + mod_len < AK_MAX_TARGET - 1) {
            local_memcpy(ctx->last_deny.target + len, model, mod_len);
            len += mod_len;
        }
    }
    ctx->last_deny.target[len] = '\0';

    local_strncpy(ctx->last_deny.missing_cap, decision->missing_cap, AK_MAX_CAPSTR);
    local_strncpy(ctx->last_deny.suggested_snippet, decision->suggested_snippet, AK_MAX_SUGGEST);
    ctx->last_deny.trace_id = decision->trace_id;
    ctx->last_deny.errno_equiv = decision->errno_equiv;
    ctx->last_deny.timestamp_ns = ak_now();
    ctx->last_deny.reason = decision->reason_code;
}

int ak_handle_infer(
    ak_ctx_t *ctx,
    const char *model,
    const char *version,
    const u8 *prompt,
    u32 prompt_len,
    u64 max_tokens,
    u8 *response,
    u32 *response_len)
{
    if (!ak_agentic_state.initialized)
        return AK_E_AGENTIC_NOT_INIT;

    if (!ctx || !model || !prompt)
        return -EINVAL;

    ak_agentic_state.stats.infer_requests_total++;

    /* Step 1: Build effect request */
    ak_effect_req_t req;
    int err = ak_effect_from_infer(&req, ctx, model, version, max_tokens);
    if (err != 0) {
        ak_agentic_state.stats.infer_requests_failed++;
        return err;
    }

    /* Step 2: Route through ak_authorize_and_execute() */
    ak_decision_t decision;
    long retval = 0;

    err = ak_authorize_and_execute(ctx, &req, &decision, &retval);

    if (err != 0 || !decision.allow) {
        ak_agentic_state.stats.infer_requests_denied++;
        populate_infer_deny(ctx, model, &decision);

        ak_debug("ak_agentic: infer '%s' denied: %s", model, decision.detail);

        return err != 0 ? err : -EPERM;
    }

    ak_agentic_state.stats.infer_requests_allowed++;

    /* Step 3: Check token budget */
    if (!ak_budget_check_tokens(ctx, max_tokens)) {
        ak_agentic_state.stats.infer_requests_budget_exceeded++;

        ctx->last_deny.op = AK_E_INFER;
        ctx->last_deny.reason = AK_DENY_BUDGET_EXCEEDED;
        ctx->last_deny.errno_equiv = ENOSPC;
        local_strncpy(ctx->last_deny.missing_cap, "budget.tokens", AK_MAX_CAPSTR);
        local_strncpy(ctx->last_deny.suggested_snippet,
                      "[budgets]\ntokens = 200000  # Increase limit",
                      AK_MAX_SUGGEST);

        ak_debug("ak_agentic: infer '%s' budget exceeded", model);

        return -ENOSPC;
    }

    /* Step 4: Execute inference via ak_inference */
    if (ctx->agent) {
        /* Build inference request */
        ak_inference_request_t inf_req;
        local_memzero(&inf_req, sizeof(ak_inference_request_t));

        inf_req.type = AK_INFERENCE_CHAT;
        local_strncpy(inf_req.model, model, sizeof(inf_req.model));
        inf_req.max_tokens = max_tokens;

        /* Create prompt buffer */
        buffer prompt_buf = allocate_buffer(ak_agentic_state.h, prompt_len);
        if (prompt_buf == INVALID_ADDRESS) {
            ak_agentic_state.stats.infer_requests_failed++;
            return AK_E_LLM_API_ERROR;
        }
        buffer_write(prompt_buf, prompt, prompt_len);
        inf_req.prompt = prompt_buf;

        /* Execute inference */
        ak_inference_response_t *inf_res = ak_inference_complete(ctx->agent, &inf_req, NULL);

        /* Copy result */
        if (inf_res && inf_res->success && inf_res->content) {
            u64 res_len = buffer_length(inf_res->content);
            if (response_len) {
                if (res_len > *response_len)
                    res_len = *response_len;
                if (response && res_len > 0) {
                    local_memcpy(response, buffer_ref(inf_res->content, 0), res_len);
                }
                *response_len = res_len;
            }

            /* Track token usage */
            u64 tokens_used = inf_res->usage.total_tokens;
            ak_agentic_state.stats.infer_tokens_in += inf_res->usage.prompt_tokens;
            ak_agentic_state.stats.infer_tokens_out += inf_res->usage.completion_tokens;

            /* Consume from budget */
            ak_budget_consume_tokens(ctx, tokens_used);

            err = 0;
        } else {
            err = inf_res ? inf_res->error_code : AK_E_LLM_API_ERROR;
        }

        /* Cleanup */
        if (prompt_buf && prompt_buf != INVALID_ADDRESS)
            deallocate_buffer(prompt_buf);
        if (inf_res)
            ak_inference_response_free(ak_agentic_state.h, inf_res);
    } else {
        ak_agentic_state.stats.infer_requests_failed++;
        return -EINVAL;
    }

    if (err != 0) {
        ak_agentic_state.stats.infer_requests_failed++;
        return err;
    }

    return 0;
}

/* ============================================================
 * STATISTICS
 * ============================================================ */

void ak_agentic_get_stats(ak_agentic_stats_t *stats)
{
    if (!stats)
        return;

    local_memcpy(stats, &ak_agentic_state.stats, sizeof(ak_agentic_stats_t));
}
