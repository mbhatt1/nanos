/*
 * Authority Kernel - Agentic Primitives Interface
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * AGENT E OWNED: Agentic effects handlers (TOOL_CALL, WASM_INVOKE, INFER)
 *
 * This module provides the agentic effect handlers that wrap existing
 * WASM and inference implementations with AK authorization:
 *
 *   - TOOL_CALL: Execute registered tools via ak_authorize_and_execute()
 *   - WASM_INVOKE: Run WASM modules with policy-gated hostcalls
 *   - INFER: LLM inference with budget tracking
 *
 * All operations flow through the single authority gate for consistent
 * enforcement of deny-by-default security policy.
 *
 * SECURITY INVARIANTS:
 *   - All tool calls must pass policy check
 *   - All WASM invocations must pass policy check
 *   - Each WASM hostcall must pass policy check
 *   - All inference requests must pass policy check
 *   - Budget limits are enforced before execution
 */

#ifndef AK_AGENTIC_H
#define AK_AGENTIC_H

#include "ak_types.h"
#include "ak_effects.h"
#include "ak_wasm.h"
#include "ak_inference.h"
#include "ak_tool_registry.h"

/* ============================================================
 * BUDGET TRACKING
 * ============================================================
 * Per-context budget tracking for agentic operations.
 * Enforced before execution to prevent resource exhaustion.
 */

typedef struct ak_agentic_budget {
    /* Tool call budget */
    u64 tool_calls_limit;
    u64 tool_calls_remaining;
    u64 tool_calls_used;

    /* Token budget (for inference) */
    u64 tokens_limit;
    u64 tokens_remaining;
    u64 tokens_used;

    /* WASM call budget */
    u64 wasm_calls_limit;
    u64 wasm_calls_remaining;
    u64 wasm_calls_used;

    /* Time tracking */
    u64 start_ns;
    u64 wall_time_limit_ns;
} ak_agentic_budget_t;

/*
 * Initialize agentic budget with default limits.
 *
 * @param budget    Budget structure to initialize
 */
void ak_agentic_budget_init(ak_agentic_budget_t *budget);

/*
 * Initialize agentic budget with custom limits.
 *
 * @param budget        Budget structure to initialize
 * @param tool_calls    Maximum tool calls
 * @param tokens        Maximum tokens
 * @param wasm_calls    Maximum WASM calls
 * @param wall_time_ns  Maximum wall time in nanoseconds
 */
void ak_agentic_budget_init_custom(
    ak_agentic_budget_t *budget,
    u64 tool_calls,
    u64 tokens,
    u64 wasm_calls,
    u64 wall_time_ns
);

/*
 * Check if tool call budget is available.
 *
 * @param ctx   AK context with budget
 * @return      true if at least one tool call remaining
 */
boolean ak_budget_check_tool(ak_ctx_t *ctx);

/*
 * Check if token budget is available for requested amount.
 *
 * @param ctx       AK context with budget
 * @param tokens    Number of tokens requested
 * @return          true if tokens available
 */
boolean ak_budget_check_tokens(ak_ctx_t *ctx, u64 tokens);

/*
 * Check if WASM call budget is available.
 *
 * @param ctx   AK context with budget
 * @return      true if at least one WASM call remaining
 */
boolean ak_budget_check_wasm(ak_ctx_t *ctx);

/*
 * Consume one tool call from budget.
 *
 * @param ctx   AK context with budget
 * @return      0 on success, -ENOSPC if budget exceeded
 */
int ak_budget_consume_tool(ak_ctx_t *ctx);

/*
 * Consume tokens from budget.
 *
 * @param ctx       AK context with budget
 * @param tokens    Number of tokens to consume
 * @return          0 on success, -ENOSPC if budget exceeded
 */
int ak_budget_consume_tokens(ak_ctx_t *ctx, u64 tokens);

/*
 * Consume one WASM call from budget.
 *
 * @param ctx   AK context with budget
 * @return      0 on success, -ENOSPC if budget exceeded
 */
int ak_budget_consume_wasm(ak_ctx_t *ctx);

/*
 * Get current budget state.
 *
 * @param ctx       AK context
 * @param budget    Output budget structure
 * @return          0 on success, -EINVAL if no budget
 */
int ak_budget_get_state(ak_ctx_t *ctx, ak_agentic_budget_t *budget);

/* ============================================================
 * TOOL REGISTRY (Simple Handler API)
 * ============================================================
 * In addition to WASM-based tools, we support native tool handlers
 * for built-in functionality.
 */

/*
 * Native tool handler function signature.
 *
 * @param args          Input arguments (JSON)
 * @param args_len      Length of arguments
 * @param result        Output buffer for result
 * @param result_len    In: max result size, Out: actual result size
 * @return              0 on success, negative error code on failure
 */
typedef int (*ak_tool_handler_t)(
    const u8 *args,
    u32 args_len,
    u8 *result,
    u32 *result_len
);

/*
 * Register a native tool handler.
 *
 * @param name      Tool name (must be unique)
 * @param version   Tool version (e.g., "1.0")
 * @param handler   Handler function
 * @return          0 on success, -EEXIST if name exists
 */
int ak_tool_handler_register(
    const char *name,
    const char *version,
    ak_tool_handler_t handler
);

/*
 * Unregister a native tool handler.
 *
 * @param name  Tool name to unregister
 * @return      0 on success, -ENOENT if not found
 */
int ak_tool_handler_unregister(const char *name);

/*
 * Lookup a native tool handler.
 *
 * @param name      Tool name
 * @param version   Tool version (NULL for any)
 * @return          Handler function or NULL if not found
 */
ak_tool_handler_t ak_tool_handler_lookup(const char *name, const char *version);

/* ============================================================
 * TOOL CALL HANDLER
 * ============================================================
 * Entry point for TOOL_CALL effects. Routes through AK authorization
 * before dispatching to registered tool handler.
 */

/*
 * Handle a tool call with AK authorization.
 *
 * Pipeline:
 *   1. Build AK_E_TOOL_CALL effect
 *   2. Route through ak_authorize_and_execute()
 *   3. If allowed, check budget
 *   4. If budget available, dispatch to handler
 *   5. Track tool call usage
 *
 * @param ctx           AK context
 * @param tool_name     Name of tool to call
 * @param version       Tool version (NULL for any)
 * @param args          JSON arguments
 * @param args_len      Length of arguments
 * @param result        Output buffer for result
 * @param result_len    In: max result size, Out: actual result size
 * @return              0 on success, negative error on denial/failure
 */
int ak_handle_tool_call(
    ak_ctx_t *ctx,
    const char *tool_name,
    const char *version,
    const u8 *args,
    u32 args_len,
    u8 *result,
    u32 *result_len
);

/* ============================================================
 * WASM INVOKE HANDLER
 * ============================================================
 * Entry point for WASM_INVOKE effects. Routes through AK authorization
 * and provides hostcall gating.
 */

/*
 * Handle a WASM module invocation with AK authorization.
 *
 * Pipeline:
 *   1. Build AK_E_WASM_INVOKE effect
 *   2. Route through ak_authorize_and_execute()
 *   3. If allowed, check budget
 *   4. If budget available, invoke WASM module
 *   5. Track WASM call usage
 *
 * @param ctx           AK context
 * @param module        WASM module name
 * @param function      Function to invoke
 * @param args          Input arguments
 * @param args_len      Length of arguments
 * @param result        Output buffer for result
 * @param result_len    In: max result size, Out: actual result size
 * @return              0 on success, negative error on denial/failure
 */
int ak_handle_wasm_invoke(
    ak_ctx_t *ctx,
    const char *module,
    const char *function,
    const u8 *args,
    u32 args_len,
    u8 *result,
    u32 *result_len
);

/*
 * Check if a WASM hostcall is allowed by policy.
 *
 * Called by the WASM runtime before executing any hostcall.
 * This enforces fine-grained control over what host functions
 * a WASM module can access.
 *
 * @param ctx       AK context
 * @param module    WASM module making the call
 * @param hostcall  Name of hostcall being attempted
 * @return          0 if allowed, -EPERM if denied
 */
int ak_wasm_hostcall_check(
    ak_ctx_t *ctx,
    const char *module,
    const char *hostcall
);

/* ============================================================
 * INFERENCE HANDLER
 * ============================================================
 * Entry point for INFER effects. Routes through AK authorization
 * with token budget tracking.
 */

/*
 * Handle an inference request with AK authorization.
 *
 * Pipeline:
 *   1. Build AK_E_INFER effect
 *   2. Route through ak_authorize_and_execute()
 *   3. If allowed, check token budget
 *   4. If budget available, dispatch to inference backend
 *   5. Track token usage (both input and output)
 *
 * @param ctx           AK context
 * @param model         Model name (e.g., "gpt-4", "claude-3")
 * @param version       Model version (NULL for latest)
 * @param prompt        Input prompt
 * @param prompt_len    Length of prompt
 * @param max_tokens    Maximum tokens to generate
 * @param response      Output buffer for response
 * @param response_len  In: max response size, Out: actual response size
 * @return              0 on success, negative error on denial/failure
 */
int ak_handle_infer(
    ak_ctx_t *ctx,
    const char *model,
    const char *version,
    const u8 *prompt,
    u32 prompt_len,
    u64 max_tokens,
    u8 *response,
    u32 *response_len
);

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

/*
 * Initialize agentic primitives subsystem.
 *
 * Must be called after ak_effects_init() and ak_wasm_init().
 *
 * @param h     Heap for allocations
 */
void ak_agentic_init(heap h);

/*
 * Shutdown agentic primitives subsystem.
 */
void ak_agentic_shutdown(void);

/* ============================================================
 * STATISTICS
 * ============================================================ */

typedef struct ak_agentic_stats {
    /* Tool calls */
    u64 tool_calls_total;
    u64 tool_calls_allowed;
    u64 tool_calls_denied;
    u64 tool_calls_budget_exceeded;
    u64 tool_calls_failed;

    /* WASM invocations */
    u64 wasm_invokes_total;
    u64 wasm_invokes_allowed;
    u64 wasm_invokes_denied;
    u64 wasm_invokes_budget_exceeded;
    u64 wasm_invokes_failed;
    u64 wasm_hostcalls_total;
    u64 wasm_hostcalls_denied;

    /* Inference */
    u64 infer_requests_total;
    u64 infer_requests_allowed;
    u64 infer_requests_denied;
    u64 infer_requests_budget_exceeded;
    u64 infer_requests_failed;
    u64 infer_tokens_in;
    u64 infer_tokens_out;
} ak_agentic_stats_t;

/*
 * Get agentic subsystem statistics.
 *
 * @param stats     Output statistics structure
 */
void ak_agentic_get_stats(ak_agentic_stats_t *stats);

/* ============================================================
 * ERROR CODES
 * ============================================================ */

#define AK_E_AGENTIC_NOT_INIT       (-4700)
#define AK_E_TOOL_HANDLER_NOT_FOUND (-4701)
#define AK_E_WASM_MODULE_NOT_FOUND  (-4702)
#define AK_E_INFER_MODEL_NOT_FOUND  (-4703)
#define AK_E_HOSTCALL_DENIED        (-4704)

/* ============================================================
 * DEFAULT BUDGETS
 * ============================================================ */

#define AK_DEFAULT_TOOL_CALL_BUDGET     100
#define AK_DEFAULT_TOKEN_BUDGET         100000
#define AK_DEFAULT_WASM_CALL_BUDGET     1000
#define AK_DEFAULT_WALL_TIME_NS         (300ULL * 1000000000ULL)  /* 5 minutes */

#endif /* AK_AGENTIC_H */
