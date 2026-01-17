/*
 * Authority Kernel - Syscall Dispatcher Tests
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Comprehensive tests for syscall routing, validation, and enforcement
 * of all four security invariants:
 *   INV-1: No-Bypass (all effects through syscalls)
 *   INV-2: Capability (every effectful syscall validated)
 *   INV-3: Budget (admission control)
 *   INV-4: Log Commitment (audit before response)
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

/* Type definitions to replace runtime.h types */
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t s64;
typedef bool boolean;

/* ============================================================
 * MOCK DEFINITIONS
 * ============================================================ */

#define AK_TOKEN_ID_SIZE    16
#define AK_HASH_SIZE        32
#define AK_MAX_AGENTS       64

/* Syscall operation codes */
#define AK_SYS_BASE         1024
#define AK_SYS_READ         0
#define AK_SYS_ALLOC        1
#define AK_SYS_WRITE        2
#define AK_SYS_DELETE       3
#define AK_SYS_QUERY        4
#define AK_SYS_BATCH        5
#define AK_SYS_COMMIT       6
#define AK_SYS_CALL         7
#define AK_SYS_SPAWN        8
#define AK_SYS_SEND         9
#define AK_SYS_RECV         10
#define AK_SYS_RESPOND      11
#define AK_SYS_ASSERT       12
#define AK_SYS_INFERENCE    13

/* Error codes */
#define AK_E_CAP_INVALID        (-4001)
#define AK_E_CAP_EXPIRED        (-4002)
#define AK_E_CAP_SCOPE          (-4003)
#define AK_E_CAP_RUN_MISMATCH   (-4005)
#define AK_E_REPLAY             (-4101)
#define AK_E_POLICY_DENIED      (-4201)
#define AK_E_BUDGET_EXCEEDED    (-4202)
#define AK_E_SCHEMA_INVALID     (-4301)
#define AK_E_TIMEOUT            (-4601)

/* Capability types */
typedef enum ak_cap_type {
    AK_CAP_NONE = 0,
    AK_CAP_ANY = 1,
    AK_CAP_HEAP = 2,
    AK_CAP_NET = 3,
    AK_CAP_FS = 4,
    AK_CAP_TOOL = 5,
    AK_CAP_LLM = 6,
    AK_CAP_SPAWN = 7,
    AK_CAP_IPC = 8,
} ak_cap_type_t;

/* Mock structures */
typedef struct ak_capability {
    u8 tid[AK_TOKEN_ID_SIZE];
    ak_cap_type_t type;
    char resource[256];
    u8 run_id[AK_TOKEN_ID_SIZE];
    u64 created_ms;
    u32 ttl_ms;
    u32 rate_limit;
    u32 rate_window_ms;
    u32 uses;
    boolean valid;
    boolean revoked;
} ak_capability_t;

typedef struct ak_request {
    u8 pid[AK_TOKEN_ID_SIZE];
    u8 run_id[AK_TOKEN_ID_SIZE];
    u64 seq;
    u16 op;
    ak_capability_t *cap;
    void *args;
    u64 args_len;
} ak_request_t;

typedef struct ak_response {
    u8 pid[AK_TOKEN_ID_SIZE];
    u8 run_id[AK_TOKEN_ID_SIZE];
    u64 seq;
    s64 error_code;
    void *result;
    u64 result_len;
} ak_response_t;

typedef struct ak_budget_tracker {
    u64 budget_calls;
    u64 used_calls;
    u64 budget_tokens;
    u64 used_tokens;
} ak_budget_tracker_t;

typedef struct ak_seq_tracker {
    u64 highest_seen;
    u64 expected_next;
    u8 seen_bitmap[128];
    u64 window_base;
} ak_seq_tracker_t;

typedef struct ak_policy {
    boolean initialized;
    char allowed_tools[16][64];
    u32 tool_count;
} ak_policy_t;

typedef struct ak_agent_context {
    u8 pid[AK_TOKEN_ID_SIZE];
    u8 run_id[AK_TOKEN_ID_SIZE];
    ak_policy_t *policy;
    ak_budget_tracker_t *budget;
    ak_seq_tracker_t *seq_tracker;
    u64 last_seq;
    boolean active;
} ak_agent_context_t;

typedef struct ak_dispatch_stats {
    u64 total_requests;
    u64 successful_requests;
    u64 failed_requests;
    u64 replay_attempts;
    u64 capability_failures;
    u64 policy_denials;
    u64 budget_exceeded;
    u64 op_counts[16];
} ak_dispatch_stats_t;

/* Audit tracking for INV-4 verification */
typedef struct {
    u8 pid[AK_TOKEN_ID_SIZE];
    u8 run_id[AK_TOKEN_ID_SIZE];
    u16 op;
    u64 seq;
    s64 result_code;
    u64 timestamp;
} audit_entry_t;

/* Mock global state */
static struct {
    boolean initialized;
    ak_agent_context_t *agents[AK_MAX_AGENTS];
    u32 agent_count;
    ak_dispatch_stats_t stats;
    ak_policy_t default_policy;

    /* Audit log for INV-4 testing */
    audit_entry_t audit_log[1024];
    u32 audit_count;
    boolean audit_before_response;
} mock_state;

/* ============================================================
 * MOCK IMPLEMENTATIONS
 * ============================================================ */

static void mock_init(void)
{
    memset(&mock_state, 0, sizeof(mock_state));
    mock_state.initialized = true;
    mock_state.default_policy.initialized = true;
    mock_state.audit_before_response = true;
}

static void mock_shutdown(void)
{
    for (u32 i = 0; i < mock_state.agent_count; i++) {
        if (mock_state.agents[i]) {
            if (mock_state.agents[i]->budget)
                free(mock_state.agents[i]->budget);
            if (mock_state.agents[i]->seq_tracker)
                free(mock_state.agents[i]->seq_tracker);
            if (mock_state.agents[i]->policy != &mock_state.default_policy)
                free(mock_state.agents[i]->policy);
            free(mock_state.agents[i]);
        }
    }
    mock_state.initialized = false;
}

static void generate_token_id(u8 *out)
{
    for (int i = 0; i < AK_TOKEN_ID_SIZE; i++)
        out[i] = (u8)(rand() & 0xFF);
}

static ak_agent_context_t *mock_context_create(void)
{
    if (mock_state.agent_count >= AK_MAX_AGENTS)
        return NULL;

    ak_agent_context_t *ctx = calloc(1, sizeof(ak_agent_context_t));
    if (!ctx) return NULL;

    generate_token_id(ctx->pid);
    generate_token_id(ctx->run_id);

    ctx->policy = &mock_state.default_policy;

    ctx->budget = calloc(1, sizeof(ak_budget_tracker_t));
    if (!ctx->budget) {
        free(ctx);
        return NULL;
    }
    ctx->budget->budget_calls = 1000;
    ctx->budget->budget_tokens = 1000000;

    ctx->seq_tracker = calloc(1, sizeof(ak_seq_tracker_t));
    if (!ctx->seq_tracker) {
        free(ctx->budget);
        free(ctx);
        return NULL;
    }
    ctx->seq_tracker->expected_next = 1;

    ctx->last_seq = 0;
    ctx->active = true;

    mock_state.agents[mock_state.agent_count++] = ctx;
    return ctx;
}

__attribute__((unused))
static void mock_context_destroy(ak_agent_context_t *ctx)
{
    if (!ctx) return;

    for (u32 i = 0; i < mock_state.agent_count; i++) {
        if (mock_state.agents[i] == ctx) {
            for (u32 j = i; j < mock_state.agent_count - 1; j++)
                mock_state.agents[j] = mock_state.agents[j + 1];
            mock_state.agent_count--;
            break;
        }
    }

    if (ctx->budget) free(ctx->budget);
    if (ctx->seq_tracker) free(ctx->seq_tracker);
    ctx->active = false;
}

/* Audit logging mock - must be called BEFORE response */
static void mock_audit_log(ak_agent_context_t *ctx, ak_request_t *req, s64 result_code)
{
    if (mock_state.audit_count >= 1024)
        return;

    audit_entry_t *entry = &mock_state.audit_log[mock_state.audit_count++];
    memcpy(entry->pid, ctx->pid, AK_TOKEN_ID_SIZE);
    memcpy(entry->run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
    entry->op = req->op;
    entry->seq = req->seq;
    entry->result_code = result_code;
    entry->timestamp = (u64)mock_state.audit_count; /* Simple ordering */
}

/* Request validation */
static s64 mock_validate_request(ak_agent_context_t *ctx, ak_request_t *req)
{
    if (!ctx || !req)
        return -EINVAL;

    /* Check PID matches */
    if (memcmp(req->pid, ctx->pid, AK_TOKEN_ID_SIZE) != 0)
        return -EPERM;

    /* Check run_id matches */
    if (memcmp(req->run_id, ctx->run_id, AK_TOKEN_ID_SIZE) != 0)
        return AK_E_CAP_RUN_MISMATCH;

    /* Check op is valid */
    if (req->op > AK_SYS_INFERENCE)
        return -EINVAL;

    return 0;
}

/* Anti-replay check (REQ-006) */
static s64 mock_check_replay(ak_agent_context_t *ctx, ak_request_t *req)
{
    if (!ctx || !ctx->seq_tracker)
        return -EINVAL;

    ak_seq_tracker_t *tracker = ctx->seq_tracker;

    /* Check for replay */
    if (req->seq <= tracker->highest_seen && req->seq > 0) {
        mock_state.stats.replay_attempts++;
        return AK_E_REPLAY;
    }

    /* Update tracking */
    if (req->seq > tracker->highest_seen)
        tracker->highest_seen = req->seq;
    tracker->expected_next = req->seq + 1;

    return 0;
}

/* Capability validation (INV-2) */
static s64 mock_validate_capability(ak_agent_context_t *ctx, ak_request_t *req)
{
    /* READ and QUERY don't require capability */
    if (req->op == AK_SYS_READ || req->op == AK_SYS_QUERY)
        return 0;

    /* All effectful operations require capability */
    if (!req->cap) {
        mock_state.stats.capability_failures++;
        return AK_E_CAP_INVALID;
    }

    ak_capability_t *cap = req->cap;

    /* Check capability is valid */
    if (!cap->valid) {
        mock_state.stats.capability_failures++;
        return AK_E_CAP_INVALID;
    }

    /* Check not revoked */
    if (cap->revoked) {
        mock_state.stats.capability_failures++;
        return AK_E_CAP_INVALID;
    }

    /* Check run_id binding */
    if (memcmp(cap->run_id, ctx->run_id, AK_TOKEN_ID_SIZE) != 0) {
        mock_state.stats.capability_failures++;
        return AK_E_CAP_RUN_MISMATCH;
    }

    /* Check type matches operation */
    ak_cap_type_t required;
    switch (req->op) {
    case AK_SYS_ALLOC:
    case AK_SYS_WRITE:
    case AK_SYS_DELETE:
        required = AK_CAP_HEAP;
        break;
    case AK_SYS_CALL:
        required = AK_CAP_TOOL;
        break;
    case AK_SYS_INFERENCE:
        required = AK_CAP_LLM;
        break;
    case AK_SYS_SPAWN:
        required = AK_CAP_SPAWN;
        break;
    case AK_SYS_SEND:
    case AK_SYS_RECV:
        required = AK_CAP_IPC;
        break;
    default:
        required = AK_CAP_ANY;
        break;
    }

    if (cap->type != required && cap->type != AK_CAP_ANY) {
        mock_state.stats.capability_failures++;
        return AK_E_CAP_SCOPE;
    }

    return 0;
}

/* Budget check (INV-3) */
static s64 mock_check_budget(ak_agent_context_t *ctx, ak_request_t *req)
{
    if (!ctx || !ctx->budget)
        return -EINVAL;

    /* Check call budget for tool calls */
    if (req->op == AK_SYS_CALL || req->op == AK_SYS_INFERENCE) {
        if (ctx->budget->used_calls >= ctx->budget->budget_calls) {
            mock_state.stats.budget_exceeded++;
            return AK_E_BUDGET_EXCEEDED;
        }
    }

    return 0;
}

/* Policy check */
static s64 mock_check_policy(ak_agent_context_t *ctx, ak_request_t *req)
{
    (void)req; /* Unused in simplified mock */

    if (!ctx || !ctx->policy)
        return AK_E_POLICY_DENIED;

    /* For now, allow all operations if policy is initialized */
    if (!ctx->policy->initialized) {
        mock_state.stats.policy_denials++;
        return AK_E_POLICY_DENIED;
    }

    return 0;
}

/* Main dispatch function */
static ak_response_t *mock_dispatch(ak_agent_context_t *ctx, ak_request_t *req)
{
    if (!mock_state.initialized)
        return NULL;

    if (!ctx || !req)
        return NULL;

    mock_state.stats.total_requests++;

    ak_response_t *res = calloc(1, sizeof(ak_response_t));
    if (!res) return NULL;

    memcpy(res->pid, req->pid, AK_TOKEN_ID_SIZE);
    memcpy(res->run_id, req->run_id, AK_TOKEN_ID_SIZE);
    res->seq = req->seq;

    s64 err;

    /* STAGE 1: Request Validation */
    err = mock_validate_request(ctx, req);
    if (err != 0) {
        res->error_code = err;
        mock_state.stats.failed_requests++;
        goto audit_and_return;
    }

    /* STAGE 2: Anti-Replay Check */
    err = mock_check_replay(ctx, req);
    if (err != 0) {
        res->error_code = err;
        mock_state.stats.failed_requests++;
        goto audit_and_return;
    }

    /* STAGE 3: Capability Verification (INV-2) */
    err = mock_validate_capability(ctx, req);
    if (err != 0) {
        res->error_code = err;
        mock_state.stats.failed_requests++;
        goto audit_and_return;
    }

    /* STAGE 4: Budget Check (INV-3) */
    err = mock_check_budget(ctx, req);
    if (err != 0) {
        res->error_code = err;
        mock_state.stats.failed_requests++;
        goto audit_and_return;
    }

    /* STAGE 5: Policy Check */
    err = mock_check_policy(ctx, req);
    if (err != 0) {
        res->error_code = err;
        mock_state.stats.failed_requests++;
        goto audit_and_return;
    }

    /* STAGE 6: Execute operation (simplified) */
    res->error_code = 0;
    mock_state.stats.successful_requests++;

    if (req->op < 16)
        mock_state.stats.op_counts[req->op]++;

    /* Commit budget on success */
    if (req->op == AK_SYS_CALL || req->op == AK_SYS_INFERENCE)
        ctx->budget->used_calls++;

audit_and_return:
    /* STAGE 7: Audit Log (INV-4) - MUST complete before response */
    if (mock_state.audit_before_response) {
        mock_audit_log(ctx, req, res->error_code);
    }

    return res;
}

/* ============================================================
 * TEST FRAMEWORK
 * ============================================================ */

static int tests_run = 0;
static int tests_passed = 0;

#define test_assert(condition, message) do { \
    if (!(condition)) { \
        printf("  FAIL: %s\n", message); \
        return 0; \
    } \
} while(0)

#define RUN_TEST(test_func) do { \
    tests_run++; \
    printf("Running %s...\n", #test_func); \
    if (test_func()) { \
        tests_passed++; \
        printf("  PASS\n"); \
    } \
} while(0)

/* ============================================================
 * BASIC DISPATCH TESTS
 * ============================================================ */

static int test_dispatch_basic_read(void)
{
    mock_init();
    ak_agent_context_t *ctx = mock_context_create();
    test_assert(ctx != NULL, "Context creation failed");

    ak_request_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.pid, ctx->pid, AK_TOKEN_ID_SIZE);
    memcpy(req.run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
    req.seq = 1;
    req.op = AK_SYS_READ;
    req.cap = NULL; /* READ doesn't require cap */

    ak_response_t *res = mock_dispatch(ctx, &req);
    test_assert(res != NULL, "Dispatch returned NULL");
    test_assert(res->error_code == 0, "READ should succeed without capability");

    free(res);
    mock_shutdown();
    return 1;
}

static int test_dispatch_basic_query(void)
{
    mock_init();
    ak_agent_context_t *ctx = mock_context_create();
    test_assert(ctx != NULL, "Context creation failed");

    ak_request_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.pid, ctx->pid, AK_TOKEN_ID_SIZE);
    memcpy(req.run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
    req.seq = 1;
    req.op = AK_SYS_QUERY;
    req.cap = NULL;

    ak_response_t *res = mock_dispatch(ctx, &req);
    test_assert(res != NULL, "Dispatch returned NULL");
    test_assert(res->error_code == 0, "QUERY should succeed without capability");

    free(res);
    mock_shutdown();
    return 1;
}

static int test_dispatch_effectful_requires_cap(void)
{
    mock_init();
    ak_agent_context_t *ctx = mock_context_create();
    test_assert(ctx != NULL, "Context creation failed");

    /* Test WRITE without capability */
    ak_request_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.pid, ctx->pid, AK_TOKEN_ID_SIZE);
    memcpy(req.run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
    req.seq = 1;
    req.op = AK_SYS_WRITE;
    req.cap = NULL;

    ak_response_t *res = mock_dispatch(ctx, &req);
    test_assert(res != NULL, "Dispatch returned NULL");
    test_assert(res->error_code == AK_E_CAP_INVALID, "WRITE without cap should fail");

    free(res);
    mock_shutdown();
    return 1;
}

static int test_dispatch_with_valid_cap(void)
{
    mock_init();
    ak_agent_context_t *ctx = mock_context_create();
    test_assert(ctx != NULL, "Context creation failed");

    /* Create valid capability */
    ak_capability_t cap;
    memset(&cap, 0, sizeof(cap));
    generate_token_id(cap.tid);
    cap.type = AK_CAP_HEAP;
    memcpy(cap.run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
    cap.valid = true;
    cap.revoked = false;

    ak_request_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.pid, ctx->pid, AK_TOKEN_ID_SIZE);
    memcpy(req.run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
    req.seq = 1;
    req.op = AK_SYS_WRITE;
    req.cap = &cap;

    ak_response_t *res = mock_dispatch(ctx, &req);
    test_assert(res != NULL, "Dispatch returned NULL");
    test_assert(res->error_code == 0, "WRITE with valid cap should succeed");

    free(res);
    mock_shutdown();
    return 1;
}

/* ============================================================
 * REQUEST VALIDATION TESTS
 * ============================================================ */

static int test_dispatch_pid_mismatch(void)
{
    mock_init();
    ak_agent_context_t *ctx = mock_context_create();
    test_assert(ctx != NULL, "Context creation failed");

    ak_request_t req;
    memset(&req, 0, sizeof(req));
    generate_token_id(req.pid); /* Different PID */
    memcpy(req.run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
    req.seq = 1;
    req.op = AK_SYS_READ;

    ak_response_t *res = mock_dispatch(ctx, &req);
    test_assert(res != NULL, "Dispatch returned NULL");
    test_assert(res->error_code == -EPERM, "PID mismatch should fail with EPERM");

    free(res);
    mock_shutdown();
    return 1;
}

static int test_dispatch_run_id_mismatch(void)
{
    mock_init();
    ak_agent_context_t *ctx = mock_context_create();
    test_assert(ctx != NULL, "Context creation failed");

    ak_request_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.pid, ctx->pid, AK_TOKEN_ID_SIZE);
    generate_token_id(req.run_id); /* Different run_id */
    req.seq = 1;
    req.op = AK_SYS_READ;

    ak_response_t *res = mock_dispatch(ctx, &req);
    test_assert(res != NULL, "Dispatch returned NULL");
    test_assert(res->error_code == AK_E_CAP_RUN_MISMATCH, "Run ID mismatch should fail");

    free(res);
    mock_shutdown();
    return 1;
}

static int test_dispatch_invalid_op(void)
{
    mock_init();
    ak_agent_context_t *ctx = mock_context_create();
    test_assert(ctx != NULL, "Context creation failed");

    ak_request_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.pid, ctx->pid, AK_TOKEN_ID_SIZE);
    memcpy(req.run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
    req.seq = 1;
    req.op = 999; /* Invalid operation */

    ak_response_t *res = mock_dispatch(ctx, &req);
    test_assert(res != NULL, "Dispatch returned NULL");
    test_assert(res->error_code == -EINVAL, "Invalid op should fail with EINVAL");

    free(res);
    mock_shutdown();
    return 1;
}

/* ============================================================
 * ANTI-REPLAY TESTS (REQ-006)
 * ============================================================ */

static int test_dispatch_replay_detection(void)
{
    mock_init();
    ak_agent_context_t *ctx = mock_context_create();
    test_assert(ctx != NULL, "Context creation failed");

    ak_request_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.pid, ctx->pid, AK_TOKEN_ID_SIZE);
    memcpy(req.run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
    req.seq = 5;
    req.op = AK_SYS_READ;

    /* First request should succeed */
    ak_response_t *res1 = mock_dispatch(ctx, &req);
    test_assert(res1 != NULL, "First dispatch returned NULL");
    test_assert(res1->error_code == 0, "First request should succeed");
    free(res1);

    /* Replay same sequence should fail */
    ak_response_t *res2 = mock_dispatch(ctx, &req);
    test_assert(res2 != NULL, "Replay dispatch returned NULL");
    test_assert(res2->error_code == AK_E_REPLAY, "Replay should be detected");
    free(res2);

    mock_shutdown();
    return 1;
}

static int test_dispatch_sequence_monotonic(void)
{
    mock_init();
    ak_agent_context_t *ctx = mock_context_create();
    test_assert(ctx != NULL, "Context creation failed");

    ak_request_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.pid, ctx->pid, AK_TOKEN_ID_SIZE);
    memcpy(req.run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
    req.op = AK_SYS_READ;

    /* Sequence 10 */
    req.seq = 10;
    ak_response_t *res1 = mock_dispatch(ctx, &req);
    test_assert(res1->error_code == 0, "Seq 10 should succeed");
    free(res1);

    /* Sequence 5 (lower) should fail */
    req.seq = 5;
    ak_response_t *res2 = mock_dispatch(ctx, &req);
    test_assert(res2->error_code == AK_E_REPLAY, "Lower seq should fail");
    free(res2);

    /* Sequence 11 should succeed */
    req.seq = 11;
    ak_response_t *res3 = mock_dispatch(ctx, &req);
    test_assert(res3->error_code == 0, "Seq 11 should succeed");
    free(res3);

    mock_shutdown();
    return 1;
}

static int test_dispatch_replay_stats(void)
{
    mock_init();
    u64 initial_replays = mock_state.stats.replay_attempts;

    ak_agent_context_t *ctx = mock_context_create();
    test_assert(ctx != NULL, "Context creation failed");

    ak_request_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.pid, ctx->pid, AK_TOKEN_ID_SIZE);
    memcpy(req.run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
    req.seq = 1;
    req.op = AK_SYS_READ;

    ak_response_t *res1 = mock_dispatch(ctx, &req);
    free(res1);

    /* Attempt replays */
    for (int i = 0; i < 5; i++) {
        ak_response_t *res = mock_dispatch(ctx, &req);
        free(res);
    }

    test_assert(mock_state.stats.replay_attempts == initial_replays + 5,
                "Replay attempts should be counted");

    mock_shutdown();
    return 1;
}

/* ============================================================
 * CAPABILITY VALIDATION TESTS (INV-2)
 * ============================================================ */

static int test_dispatch_revoked_cap(void)
{
    mock_init();
    ak_agent_context_t *ctx = mock_context_create();
    test_assert(ctx != NULL, "Context creation failed");

    /* Create revoked capability */
    ak_capability_t cap;
    memset(&cap, 0, sizeof(cap));
    cap.type = AK_CAP_HEAP;
    memcpy(cap.run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
    cap.valid = true;
    cap.revoked = true; /* REVOKED */

    ak_request_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.pid, ctx->pid, AK_TOKEN_ID_SIZE);
    memcpy(req.run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
    req.seq = 1;
    req.op = AK_SYS_WRITE;
    req.cap = &cap;

    ak_response_t *res = mock_dispatch(ctx, &req);
    test_assert(res != NULL, "Dispatch returned NULL");
    test_assert(res->error_code == AK_E_CAP_INVALID, "Revoked cap should fail");

    free(res);
    mock_shutdown();
    return 1;
}

static int test_dispatch_wrong_cap_type(void)
{
    mock_init();
    ak_agent_context_t *ctx = mock_context_create();
    test_assert(ctx != NULL, "Context creation failed");

    /* Create TOOL capability for WRITE operation */
    ak_capability_t cap;
    memset(&cap, 0, sizeof(cap));
    cap.type = AK_CAP_TOOL; /* Wrong type for WRITE */
    memcpy(cap.run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
    cap.valid = true;
    cap.revoked = false;

    ak_request_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.pid, ctx->pid, AK_TOKEN_ID_SIZE);
    memcpy(req.run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
    req.seq = 1;
    req.op = AK_SYS_WRITE; /* Requires HEAP cap */
    req.cap = &cap;

    ak_response_t *res = mock_dispatch(ctx, &req);
    test_assert(res != NULL, "Dispatch returned NULL");
    test_assert(res->error_code == AK_E_CAP_SCOPE, "Wrong cap type should fail");

    free(res);
    mock_shutdown();
    return 1;
}

static int test_dispatch_cap_run_id_mismatch(void)
{
    mock_init();
    ak_agent_context_t *ctx = mock_context_create();
    test_assert(ctx != NULL, "Context creation failed");

    /* Create capability with different run_id */
    ak_capability_t cap;
    memset(&cap, 0, sizeof(cap));
    cap.type = AK_CAP_HEAP;
    generate_token_id(cap.run_id); /* Different run_id */
    cap.valid = true;
    cap.revoked = false;

    ak_request_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.pid, ctx->pid, AK_TOKEN_ID_SIZE);
    memcpy(req.run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
    req.seq = 1;
    req.op = AK_SYS_WRITE;
    req.cap = &cap;

    ak_response_t *res = mock_dispatch(ctx, &req);
    test_assert(res != NULL, "Dispatch returned NULL");
    test_assert(res->error_code == AK_E_CAP_RUN_MISMATCH, "Cap run_id mismatch should fail");

    free(res);
    mock_shutdown();
    return 1;
}

static int test_dispatch_capability_stats(void)
{
    mock_init();
    u64 initial_failures = mock_state.stats.capability_failures;

    ak_agent_context_t *ctx = mock_context_create();
    test_assert(ctx != NULL, "Context creation failed");

    ak_request_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.pid, ctx->pid, AK_TOKEN_ID_SIZE);
    memcpy(req.run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
    req.seq = 1;
    req.op = AK_SYS_WRITE;
    req.cap = NULL; /* No capability */

    ak_response_t *res = mock_dispatch(ctx, &req);
    free(res);

    test_assert(mock_state.stats.capability_failures == initial_failures + 1,
                "Capability failure should be counted");

    mock_shutdown();
    return 1;
}

/* ============================================================
 * BUDGET ENFORCEMENT TESTS (INV-3)
 * ============================================================ */

static int test_dispatch_budget_enforcement(void)
{
    mock_init();
    ak_agent_context_t *ctx = mock_context_create();
    test_assert(ctx != NULL, "Context creation failed");

    /* Set budget to 3 calls */
    ctx->budget->budget_calls = 3;
    ctx->budget->used_calls = 0;

    ak_capability_t cap;
    memset(&cap, 0, sizeof(cap));
    cap.type = AK_CAP_TOOL;
    memcpy(cap.run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
    cap.valid = true;
    cap.revoked = false;

    ak_request_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.pid, ctx->pid, AK_TOKEN_ID_SIZE);
    memcpy(req.run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
    req.op = AK_SYS_CALL;
    req.cap = &cap;

    /* First 3 calls should succeed */
    for (int i = 0; i < 3; i++) {
        req.seq = (u64)(i + 1);
        ak_response_t *res = mock_dispatch(ctx, &req);
        test_assert(res->error_code == 0, "Call within budget should succeed");
        free(res);
    }

    /* 4th call should fail */
    req.seq = 4;
    ak_response_t *res4 = mock_dispatch(ctx, &req);
    test_assert(res4->error_code == AK_E_BUDGET_EXCEEDED, "Call over budget should fail");
    free(res4);

    mock_shutdown();
    return 1;
}

static int test_dispatch_budget_stats(void)
{
    mock_init();
    u64 initial_exceeded = mock_state.stats.budget_exceeded;

    ak_agent_context_t *ctx = mock_context_create();
    test_assert(ctx != NULL, "Context creation failed");

    /* Set budget to 0 */
    ctx->budget->budget_calls = 0;

    ak_capability_t cap;
    memset(&cap, 0, sizeof(cap));
    cap.type = AK_CAP_TOOL;
    memcpy(cap.run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
    cap.valid = true;

    ak_request_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.pid, ctx->pid, AK_TOKEN_ID_SIZE);
    memcpy(req.run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
    req.seq = 1;
    req.op = AK_SYS_CALL;
    req.cap = &cap;

    ak_response_t *res = mock_dispatch(ctx, &req);
    free(res);

    test_assert(mock_state.stats.budget_exceeded == initial_exceeded + 1,
                "Budget exceeded should be counted");

    mock_shutdown();
    return 1;
}

/* ============================================================
 * AUDIT LOGGING TESTS (INV-4)
 * ============================================================ */

static int test_dispatch_audit_before_response(void)
{
    mock_init();
    mock_state.audit_count = 0;
    mock_state.audit_before_response = true;

    ak_agent_context_t *ctx = mock_context_create();
    test_assert(ctx != NULL, "Context creation failed");

    ak_request_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.pid, ctx->pid, AK_TOKEN_ID_SIZE);
    memcpy(req.run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
    req.seq = 1;
    req.op = AK_SYS_READ;

    ak_response_t *res = mock_dispatch(ctx, &req);

    /* Audit should be logged before response */
    test_assert(mock_state.audit_count == 1, "Audit entry should exist");
    test_assert(mock_state.audit_log[0].op == AK_SYS_READ, "Audit should log operation");
    test_assert(mock_state.audit_log[0].seq == 1, "Audit should log sequence");

    free(res);
    mock_shutdown();
    return 1;
}

static int test_dispatch_audit_logs_errors(void)
{
    mock_init();
    mock_state.audit_count = 0;

    ak_agent_context_t *ctx = mock_context_create();
    test_assert(ctx != NULL, "Context creation failed");

    /* Make a request that will fail */
    ak_request_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.pid, ctx->pid, AK_TOKEN_ID_SIZE);
    memcpy(req.run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
    req.seq = 1;
    req.op = AK_SYS_WRITE;
    req.cap = NULL; /* Missing capability */

    ak_response_t *res = mock_dispatch(ctx, &req);

    /* Even failures should be audited */
    test_assert(mock_state.audit_count == 1, "Failed requests should be audited");
    test_assert(mock_state.audit_log[0].result_code == AK_E_CAP_INVALID,
                "Audit should log error code");

    free(res);
    mock_shutdown();
    return 1;
}

static int test_dispatch_audit_all_operations(void)
{
    mock_init();
    mock_state.audit_count = 0;

    ak_agent_context_t *ctx = mock_context_create();
    test_assert(ctx != NULL, "Context creation failed");

    ak_capability_t cap;
    memset(&cap, 0, sizeof(cap));
    cap.type = AK_CAP_ANY;
    memcpy(cap.run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
    cap.valid = true;

    /* Test multiple operations */
    u16 ops[] = {AK_SYS_READ, AK_SYS_QUERY, AK_SYS_ALLOC, AK_SYS_COMMIT};

    for (int i = 0; i < 4; i++) {
        cap.type = (ops[i] == AK_SYS_ALLOC) ? AK_CAP_HEAP : AK_CAP_ANY;

        ak_request_t req;
        memset(&req, 0, sizeof(req));
        memcpy(req.pid, ctx->pid, AK_TOKEN_ID_SIZE);
        memcpy(req.run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
        req.seq = (u64)(i + 1);
        req.op = ops[i];
        req.cap = (ops[i] == AK_SYS_READ || ops[i] == AK_SYS_QUERY) ? NULL : &cap;

        ak_response_t *res = mock_dispatch(ctx, &req);
        free(res);
    }

    test_assert(mock_state.audit_count == 4, "All operations should be audited");

    mock_shutdown();
    return 1;
}

/* ============================================================
 * STATISTICS TESTS
 * ============================================================ */

static int test_dispatch_stats_total_requests(void)
{
    mock_init();
    mock_state.stats.total_requests = 0;

    ak_agent_context_t *ctx = mock_context_create();
    test_assert(ctx != NULL, "Context creation failed");

    ak_request_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.pid, ctx->pid, AK_TOKEN_ID_SIZE);
    memcpy(req.run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
    req.op = AK_SYS_READ;

    for (int i = 0; i < 10; i++) {
        req.seq = (u64)(i + 1);
        ak_response_t *res = mock_dispatch(ctx, &req);
        free(res);
    }

    test_assert(mock_state.stats.total_requests == 10, "Total requests should be 10");

    mock_shutdown();
    return 1;
}

static int test_dispatch_stats_success_failure(void)
{
    mock_init();
    mock_state.stats.successful_requests = 0;
    mock_state.stats.failed_requests = 0;

    ak_agent_context_t *ctx = mock_context_create();
    test_assert(ctx != NULL, "Context creation failed");

    /* 5 successful reads */
    for (int i = 0; i < 5; i++) {
        ak_request_t req;
        memset(&req, 0, sizeof(req));
        memcpy(req.pid, ctx->pid, AK_TOKEN_ID_SIZE);
        memcpy(req.run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
        req.seq = (u64)(i + 1);
        req.op = AK_SYS_READ;

        ak_response_t *res = mock_dispatch(ctx, &req);
        free(res);
    }

    /* 3 failed writes (no cap) */
    for (int i = 0; i < 3; i++) {
        ak_request_t req;
        memset(&req, 0, sizeof(req));
        memcpy(req.pid, ctx->pid, AK_TOKEN_ID_SIZE);
        memcpy(req.run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
        req.seq = (u64)(i + 6);
        req.op = AK_SYS_WRITE;
        req.cap = NULL;

        ak_response_t *res = mock_dispatch(ctx, &req);
        free(res);
    }

    test_assert(mock_state.stats.successful_requests == 5, "Should have 5 successes");
    test_assert(mock_state.stats.failed_requests == 3, "Should have 3 failures");

    mock_shutdown();
    return 1;
}

static int test_dispatch_stats_op_counts(void)
{
    mock_init();
    memset(mock_state.stats.op_counts, 0, sizeof(mock_state.stats.op_counts));

    ak_agent_context_t *ctx = mock_context_create();
    test_assert(ctx != NULL, "Context creation failed");

    ak_capability_t cap;
    memset(&cap, 0, sizeof(cap));
    cap.type = AK_CAP_ANY;
    memcpy(cap.run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
    cap.valid = true;

    /* 3 READs, 2 QUERYs, 1 COMMIT */
    for (int i = 0; i < 3; i++) {
        ak_request_t req;
        memset(&req, 0, sizeof(req));
        memcpy(req.pid, ctx->pid, AK_TOKEN_ID_SIZE);
        memcpy(req.run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
        req.seq = (u64)(i + 1);
        req.op = AK_SYS_READ;

        ak_response_t *res = mock_dispatch(ctx, &req);
        free(res);
    }

    for (int i = 0; i < 2; i++) {
        ak_request_t req;
        memset(&req, 0, sizeof(req));
        memcpy(req.pid, ctx->pid, AK_TOKEN_ID_SIZE);
        memcpy(req.run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
        req.seq = (u64)(i + 4);
        req.op = AK_SYS_QUERY;

        ak_response_t *res = mock_dispatch(ctx, &req);
        free(res);
    }

    ak_request_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.pid, ctx->pid, AK_TOKEN_ID_SIZE);
    memcpy(req.run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
    req.seq = 6;
    req.op = AK_SYS_COMMIT;
    req.cap = &cap;

    ak_response_t *res = mock_dispatch(ctx, &req);
    free(res);

    test_assert(mock_state.stats.op_counts[AK_SYS_READ] == 3, "Should have 3 READs");
    test_assert(mock_state.stats.op_counts[AK_SYS_QUERY] == 2, "Should have 2 QUERYs");
    test_assert(mock_state.stats.op_counts[AK_SYS_COMMIT] == 1, "Should have 1 COMMIT");

    mock_shutdown();
    return 1;
}

/* ============================================================
 * EDGE CASE TESTS
 * ============================================================ */

static int test_dispatch_null_context(void)
{
    mock_init();

    ak_request_t req;
    memset(&req, 0, sizeof(req));
    req.op = AK_SYS_READ;

    ak_response_t *res = mock_dispatch(NULL, &req);
    test_assert(res == NULL, "NULL context should return NULL");

    mock_shutdown();
    return 1;
}

static int test_dispatch_null_request(void)
{
    mock_init();
    ak_agent_context_t *ctx = mock_context_create();
    test_assert(ctx != NULL, "Context creation failed");

    ak_response_t *res = mock_dispatch(ctx, NULL);
    test_assert(res == NULL, "NULL request should return NULL");

    mock_shutdown();
    return 1;
}

static int test_dispatch_uninitialized(void)
{
    /* Don't call mock_init() */
    mock_state.initialized = false;

    ak_agent_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    ak_request_t req;
    memset(&req, 0, sizeof(req));
    req.op = AK_SYS_READ;

    ak_response_t *res = mock_dispatch(&ctx, &req);
    test_assert(res == NULL, "Uninitialized should return NULL");

    return 1;
}

static int test_dispatch_max_sequence(void)
{
    mock_init();
    ak_agent_context_t *ctx = mock_context_create();
    test_assert(ctx != NULL, "Context creation failed");

    ak_request_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.pid, ctx->pid, AK_TOKEN_ID_SIZE);
    memcpy(req.run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
    req.seq = UINT64_MAX;
    req.op = AK_SYS_READ;

    ak_response_t *res = mock_dispatch(ctx, &req);
    test_assert(res != NULL, "Max sequence should be handled");
    test_assert(res->error_code == 0, "Max sequence should succeed");

    free(res);
    mock_shutdown();
    return 1;
}

/* ============================================================
 * CONCURRENT AGENT TESTS
 * ============================================================ */

static int test_dispatch_multiple_agents(void)
{
    mock_init();

    /* Create multiple agents */
    ak_agent_context_t *agents[4];
    for (int i = 0; i < 4; i++) {
        agents[i] = mock_context_create();
        test_assert(agents[i] != NULL, "Agent creation failed");
    }

    /* Each agent makes requests */
    for (int a = 0; a < 4; a++) {
        ak_request_t req;
        memset(&req, 0, sizeof(req));
        memcpy(req.pid, agents[a]->pid, AK_TOKEN_ID_SIZE);
        memcpy(req.run_id, agents[a]->run_id, AK_TOKEN_ID_SIZE);
        req.seq = 1;
        req.op = AK_SYS_READ;

        ak_response_t *res = mock_dispatch(agents[a], &req);
        test_assert(res->error_code == 0, "Agent request should succeed");
        free(res);
    }

    test_assert(mock_state.agent_count == 4, "Should have 4 agents");

    mock_shutdown();
    return 1;
}

static int test_dispatch_agent_isolation(void)
{
    mock_init();

    ak_agent_context_t *agent1 = mock_context_create();
    ak_agent_context_t *agent2 = mock_context_create();
    test_assert(agent1 != NULL && agent2 != NULL, "Agents creation failed");

    /* Agent1 makes request with agent2's PID - should fail */
    ak_request_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.pid, agent2->pid, AK_TOKEN_ID_SIZE); /* Wrong PID */
    memcpy(req.run_id, agent1->run_id, AK_TOKEN_ID_SIZE);
    req.seq = 1;
    req.op = AK_SYS_READ;

    ak_response_t *res = mock_dispatch(agent1, &req);
    test_assert(res->error_code == -EPERM, "Cross-agent request should fail");

    free(res);
    mock_shutdown();
    return 1;
}

/* ============================================================
 * OPERATION-SPECIFIC CAPABILITY TESTS
 * ============================================================ */

static int test_dispatch_call_requires_tool_cap(void)
{
    mock_init();
    ak_agent_context_t *ctx = mock_context_create();
    test_assert(ctx != NULL, "Context creation failed");

    /* Use HEAP cap for CALL - should fail */
    ak_capability_t cap;
    memset(&cap, 0, sizeof(cap));
    cap.type = AK_CAP_HEAP; /* Wrong type */
    memcpy(cap.run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
    cap.valid = true;

    ak_request_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.pid, ctx->pid, AK_TOKEN_ID_SIZE);
    memcpy(req.run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
    req.seq = 1;
    req.op = AK_SYS_CALL;
    req.cap = &cap;

    ak_response_t *res = mock_dispatch(ctx, &req);
    test_assert(res->error_code == AK_E_CAP_SCOPE, "CALL requires TOOL cap");

    free(res);
    mock_shutdown();
    return 1;
}

static int test_dispatch_spawn_requires_spawn_cap(void)
{
    mock_init();
    ak_agent_context_t *ctx = mock_context_create();
    test_assert(ctx != NULL, "Context creation failed");

    /* Use NET cap for SPAWN - should fail */
    ak_capability_t cap;
    memset(&cap, 0, sizeof(cap));
    cap.type = AK_CAP_NET; /* Wrong type */
    memcpy(cap.run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
    cap.valid = true;

    ak_request_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.pid, ctx->pid, AK_TOKEN_ID_SIZE);
    memcpy(req.run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
    req.seq = 1;
    req.op = AK_SYS_SPAWN;
    req.cap = &cap;

    ak_response_t *res = mock_dispatch(ctx, &req);
    test_assert(res->error_code == AK_E_CAP_SCOPE, "SPAWN requires SPAWN cap");

    free(res);
    mock_shutdown();
    return 1;
}

static int test_dispatch_inference_requires_llm_cap(void)
{
    mock_init();
    ak_agent_context_t *ctx = mock_context_create();
    test_assert(ctx != NULL, "Context creation failed");

    /* Use FS cap for INFERENCE - should fail */
    ak_capability_t cap;
    memset(&cap, 0, sizeof(cap));
    cap.type = AK_CAP_FS; /* Wrong type */
    memcpy(cap.run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
    cap.valid = true;

    ak_request_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.pid, ctx->pid, AK_TOKEN_ID_SIZE);
    memcpy(req.run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
    req.seq = 1;
    req.op = AK_SYS_INFERENCE;
    req.cap = &cap;

    ak_response_t *res = mock_dispatch(ctx, &req);
    test_assert(res->error_code == AK_E_CAP_SCOPE, "INFERENCE requires LLM cap");

    free(res);
    mock_shutdown();
    return 1;
}

static int test_dispatch_any_cap_works_everywhere(void)
{
    mock_init();
    ak_agent_context_t *ctx = mock_context_create();
    test_assert(ctx != NULL, "Context creation failed");

    /* ANY cap should work for all operations */
    ak_capability_t cap;
    memset(&cap, 0, sizeof(cap));
    cap.type = AK_CAP_ANY;
    memcpy(cap.run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
    cap.valid = true;

    u16 effectful_ops[] = {AK_SYS_ALLOC, AK_SYS_WRITE, AK_SYS_DELETE,
                           AK_SYS_BATCH, AK_SYS_COMMIT, AK_SYS_RESPOND};

    for (int i = 0; i < 6; i++) {
        ak_request_t req;
        memset(&req, 0, sizeof(req));
        memcpy(req.pid, ctx->pid, AK_TOKEN_ID_SIZE);
        memcpy(req.run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
        req.seq = (u64)(i + 1);
        req.op = effectful_ops[i];
        req.cap = &cap;

        ak_response_t *res = mock_dispatch(ctx, &req);
        test_assert(res->error_code == 0, "ANY cap should work");
        free(res);
    }

    mock_shutdown();
    return 1;
}

/* ============================================================
 * TEST RUNNER
 * ============================================================ */

typedef int (*test_func_t)(void);

typedef struct {
    const char *name;
    test_func_t func;
} test_case_t;

static test_case_t test_cases[] = {
    /* Basic dispatch tests */
    {"test_dispatch_basic_read", test_dispatch_basic_read},
    {"test_dispatch_basic_query", test_dispatch_basic_query},
    {"test_dispatch_effectful_requires_cap", test_dispatch_effectful_requires_cap},
    {"test_dispatch_with_valid_cap", test_dispatch_with_valid_cap},

    /* Request validation tests */
    {"test_dispatch_pid_mismatch", test_dispatch_pid_mismatch},
    {"test_dispatch_run_id_mismatch", test_dispatch_run_id_mismatch},
    {"test_dispatch_invalid_op", test_dispatch_invalid_op},

    /* Anti-replay tests */
    {"test_dispatch_replay_detection", test_dispatch_replay_detection},
    {"test_dispatch_sequence_monotonic", test_dispatch_sequence_monotonic},
    {"test_dispatch_replay_stats", test_dispatch_replay_stats},

    /* Capability validation tests (INV-2) */
    {"test_dispatch_revoked_cap", test_dispatch_revoked_cap},
    {"test_dispatch_wrong_cap_type", test_dispatch_wrong_cap_type},
    {"test_dispatch_cap_run_id_mismatch", test_dispatch_cap_run_id_mismatch},
    {"test_dispatch_capability_stats", test_dispatch_capability_stats},

    /* Budget enforcement tests (INV-3) */
    {"test_dispatch_budget_enforcement", test_dispatch_budget_enforcement},
    {"test_dispatch_budget_stats", test_dispatch_budget_stats},

    /* Audit logging tests (INV-4) */
    {"test_dispatch_audit_before_response", test_dispatch_audit_before_response},
    {"test_dispatch_audit_logs_errors", test_dispatch_audit_logs_errors},
    {"test_dispatch_audit_all_operations", test_dispatch_audit_all_operations},

    /* Statistics tests */
    {"test_dispatch_stats_total_requests", test_dispatch_stats_total_requests},
    {"test_dispatch_stats_success_failure", test_dispatch_stats_success_failure},
    {"test_dispatch_stats_op_counts", test_dispatch_stats_op_counts},

    /* Edge case tests */
    {"test_dispatch_null_context", test_dispatch_null_context},
    {"test_dispatch_null_request", test_dispatch_null_request},
    {"test_dispatch_uninitialized", test_dispatch_uninitialized},
    {"test_dispatch_max_sequence", test_dispatch_max_sequence},

    /* Concurrent agent tests */
    {"test_dispatch_multiple_agents", test_dispatch_multiple_agents},
    {"test_dispatch_agent_isolation", test_dispatch_agent_isolation},

    /* Operation-specific capability tests */
    {"test_dispatch_call_requires_tool_cap", test_dispatch_call_requires_tool_cap},
    {"test_dispatch_spawn_requires_spawn_cap", test_dispatch_spawn_requires_spawn_cap},
    {"test_dispatch_inference_requires_llm_cap", test_dispatch_inference_requires_llm_cap},
    {"test_dispatch_any_cap_works_everywhere", test_dispatch_any_cap_works_everywhere},

    {NULL, NULL}
};

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    printf("Authority Kernel Syscall Dispatcher Tests\n");
    printf("==========================================\n\n");

    srand(12345);

    for (int i = 0; test_cases[i].name != NULL; i++) {
        RUN_TEST(test_cases[i].func);
    }

    printf("\n==========================================\n");
    printf("Results: %d/%d tests passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
