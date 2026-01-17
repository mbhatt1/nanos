/*
 * Authority Kernel - Approval Workflow Unit Tests
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Comprehensive tests for human-in-the-loop approval workflows:
 * - Request creation and lifecycle
 * - Approval/denial decisions
 * - Timeout handling
 * - Cancellation
 * - Status transitions
 * - Concurrent request handling
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

/* Test assertion macros */
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

/* ============================================================
 * APPROVAL TYPES (matching ak_approval.h)
 * ============================================================ */

#define AK_TOKEN_ID_SIZE    16

typedef enum ak_approval_status {
    AK_APPROVAL_PENDING = 0,
    AK_APPROVAL_GRANTED,
    AK_APPROVAL_DENIED,
    AK_APPROVAL_TIMEOUT,
    AK_APPROVAL_CANCELLED,
} ak_approval_status_t;

typedef struct ak_approval_request {
    uint64_t id;
    uint8_t run_id[AK_TOKEN_ID_SIZE];
    uint8_t agent_id[AK_TOKEN_ID_SIZE];
    uint16_t op;
    char *request_json;
    char *justification;
    uint64_t requested_ms;
    uint64_t timeout_ms;
    uint64_t decided_ms;
    ak_approval_status_t status;
    char reviewer_id[64];
    char *reviewer_note;
    void *on_decision;
    void *callback_data;
} ak_approval_request_t;

/* Error codes */
#define AK_E_APPROVAL_NOT_FOUND  -4600
#define AK_E_APPROVAL_EXPIRED    -4601
#define AK_E_APPROVAL_ALREADY    -4602

/* ============================================================
 * MOCK APPROVAL SYSTEM
 * ============================================================ */

#define MAX_APPROVAL_REQUESTS 100
#define DEFAULT_TIMEOUT_MS    (5 * 60 * 1000)  /* 5 minutes */

static struct {
    ak_approval_request_t *requests[MAX_APPROVAL_REQUESTS];
    int request_count;
    uint64_t next_id;
    uint64_t current_time_ms;
    uint64_t default_timeout_ms;
    int callback_count;
    bool initialized;
} mock_approval;

static void mock_approval_init(void)
{
    memset(&mock_approval, 0, sizeof(mock_approval));
    mock_approval.next_id = 1;
    mock_approval.current_time_ms = 1000000;
    mock_approval.default_timeout_ms = DEFAULT_TIMEOUT_MS;
    mock_approval.initialized = true;
}

static void mock_approval_cleanup(void)
{
    for (int i = 0; i < mock_approval.request_count; i++) {
        if (mock_approval.requests[i]) {
            free(mock_approval.requests[i]->request_json);
            free(mock_approval.requests[i]->justification);
            free(mock_approval.requests[i]->reviewer_note);
            free(mock_approval.requests[i]);
        }
    }
    memset(&mock_approval, 0, sizeof(mock_approval));
}

static ak_approval_request_t *mock_approval_create(
    uint8_t *agent_id,
    uint8_t *run_id,
    uint16_t op,
    const char *request_json,
    const char *justification)
{
    if (!mock_approval.initialized) return NULL;
    if (mock_approval.request_count >= MAX_APPROVAL_REQUESTS) return NULL;

    ak_approval_request_t *req = calloc(1, sizeof(ak_approval_request_t));
    if (!req) return NULL;

    req->id = mock_approval.next_id++;
    memcpy(req->agent_id, agent_id, AK_TOKEN_ID_SIZE);
    memcpy(req->run_id, run_id, AK_TOKEN_ID_SIZE);
    req->op = op;

    if (request_json) {
        req->request_json = strdup(request_json);
    }
    if (justification) {
        req->justification = strdup(justification);
    }

    req->requested_ms = mock_approval.current_time_ms;
    req->timeout_ms = mock_approval.default_timeout_ms;
    req->status = AK_APPROVAL_PENDING;

    mock_approval.requests[mock_approval.request_count++] = req;
    return req;
}

static ak_approval_request_t *mock_approval_find(uint64_t id)
{
    for (int i = 0; i < mock_approval.request_count; i++) {
        if (mock_approval.requests[i] && mock_approval.requests[i]->id == id) {
            return mock_approval.requests[i];
        }
    }
    return NULL;
}

static ak_approval_status_t mock_approval_check(uint64_t id)
{
    ak_approval_request_t *req = mock_approval_find(id);
    if (!req) return AK_APPROVAL_TIMEOUT;

    /* Check for timeout */
    if (req->status == AK_APPROVAL_PENDING) {
        if (mock_approval.current_time_ms > req->requested_ms + req->timeout_ms) {
            req->status = AK_APPROVAL_TIMEOUT;
            req->decided_ms = mock_approval.current_time_ms;
        }
    }

    return req->status;
}

static int mock_approval_grant(uint64_t id, const char *reviewer_id, const char *note)
{
    ak_approval_request_t *req = mock_approval_find(id);
    if (!req) return AK_E_APPROVAL_NOT_FOUND;
    if (req->status != AK_APPROVAL_PENDING) return AK_E_APPROVAL_ALREADY;

    req->status = AK_APPROVAL_GRANTED;
    req->decided_ms = mock_approval.current_time_ms;

    if (reviewer_id) {
        strncpy(req->reviewer_id, reviewer_id, sizeof(req->reviewer_id) - 1);
    }
    if (note) {
        req->reviewer_note = strdup(note);
    }

    return 0;
}

static int mock_approval_deny(uint64_t id, const char *reviewer_id, const char *note)
{
    ak_approval_request_t *req = mock_approval_find(id);
    if (!req) return AK_E_APPROVAL_NOT_FOUND;
    if (req->status != AK_APPROVAL_PENDING) return AK_E_APPROVAL_ALREADY;

    req->status = AK_APPROVAL_DENIED;
    req->decided_ms = mock_approval.current_time_ms;

    if (reviewer_id) {
        strncpy(req->reviewer_id, reviewer_id, sizeof(req->reviewer_id) - 1);
    }
    if (note) {
        req->reviewer_note = strdup(note);
    }

    return 0;
}

static int mock_approval_cancel(uint64_t id)
{
    ak_approval_request_t *req = mock_approval_find(id);
    if (!req) return AK_E_APPROVAL_NOT_FOUND;
    if (req->status != AK_APPROVAL_PENDING) return AK_E_APPROVAL_ALREADY;

    req->status = AK_APPROVAL_CANCELLED;
    req->decided_ms = mock_approval.current_time_ms;

    return 0;
}

static int mock_approval_pending_count(void)
{
    int count = 0;
    for (int i = 0; i < mock_approval.request_count; i++) {
        if (mock_approval.requests[i] &&
            mock_approval.requests[i]->status == AK_APPROVAL_PENDING) {
            count++;
        }
    }
    return count;
}

/* ============================================================
 * TEST CASES: REQUEST CREATION
 * ============================================================ */

bool test_approval_create_basic(void)
{
    mock_approval_init();

    uint8_t agent_id[AK_TOKEN_ID_SIZE] = {1, 2, 3, 4};
    uint8_t run_id[AK_TOKEN_ID_SIZE] = {5, 6, 7, 8};

    ak_approval_request_t *req = mock_approval_create(
        agent_id, run_id, 0x0400,
        "{\"tool\": \"shell_exec\"}",
        "Need to run diagnostic command"
    );

    test_assert(req != NULL);
    test_assert_eq(req->id, 1);
    test_assert_eq(req->status, AK_APPROVAL_PENDING);
    test_assert_eq(req->op, 0x0400);
    test_assert(memcmp(req->agent_id, agent_id, AK_TOKEN_ID_SIZE) == 0);
    test_assert(memcmp(req->run_id, run_id, AK_TOKEN_ID_SIZE) == 0);
    test_assert(strcmp(req->request_json, "{\"tool\": \"shell_exec\"}") == 0);
    test_assert(strcmp(req->justification, "Need to run diagnostic command") == 0);

    mock_approval_cleanup();
    return true;
}

bool test_approval_create_multiple(void)
{
    mock_approval_init();

    uint8_t ids[10][AK_TOKEN_ID_SIZE];
    for (int i = 0; i < 10; i++) {
        memset(ids[i], i, AK_TOKEN_ID_SIZE);
    }

    for (int i = 0; i < 10; i++) {
        ak_approval_request_t *req = mock_approval_create(
            ids[i], ids[i], (uint16_t)i, NULL, NULL
        );
        test_assert(req != NULL);
        test_assert_eq(req->id, (uint64_t)(i + 1));
    }

    test_assert_eq(mock_approval.request_count, 10);
    test_assert_eq(mock_approval_pending_count(), 10);

    mock_approval_cleanup();
    return true;
}

bool test_approval_create_unique_ids(void)
{
    mock_approval_init();

    uint8_t dummy[AK_TOKEN_ID_SIZE] = {0};
    uint64_t prev_id = 0;

    for (int i = 0; i < 50; i++) {
        ak_approval_request_t *req = mock_approval_create(dummy, dummy, 0, NULL, NULL);
        test_assert(req != NULL);
        test_assert(req->id > prev_id);
        prev_id = req->id;
    }

    mock_approval_cleanup();
    return true;
}

bool test_approval_create_with_null_fields(void)
{
    mock_approval_init();

    uint8_t dummy[AK_TOKEN_ID_SIZE] = {0};

    ak_approval_request_t *req = mock_approval_create(dummy, dummy, 0, NULL, NULL);
    test_assert(req != NULL);
    test_assert(req->request_json == NULL);
    test_assert(req->justification == NULL);

    mock_approval_cleanup();
    return true;
}

/* ============================================================
 * TEST CASES: APPROVAL/DENIAL DECISIONS
 * ============================================================ */

bool test_approval_grant_basic(void)
{
    mock_approval_init();

    uint8_t dummy[AK_TOKEN_ID_SIZE] = {0};
    ak_approval_request_t *req = mock_approval_create(dummy, dummy, 0, NULL, NULL);
    test_assert(req != NULL);

    int result = mock_approval_grant(req->id, "admin@example.com", "Looks good");
    test_assert_eq(result, 0);
    test_assert_eq(req->status, AK_APPROVAL_GRANTED);
    test_assert(req->decided_ms > 0);
    test_assert(strcmp(req->reviewer_id, "admin@example.com") == 0);
    test_assert(strcmp(req->reviewer_note, "Looks good") == 0);

    mock_approval_cleanup();
    return true;
}

bool test_approval_deny_basic(void)
{
    mock_approval_init();

    uint8_t dummy[AK_TOKEN_ID_SIZE] = {0};
    ak_approval_request_t *req = mock_approval_create(dummy, dummy, 0, NULL, NULL);
    test_assert(req != NULL);

    int result = mock_approval_deny(req->id, "security@example.com", "Too risky");
    test_assert_eq(result, 0);
    test_assert_eq(req->status, AK_APPROVAL_DENIED);
    test_assert(req->decided_ms > 0);
    test_assert(strcmp(req->reviewer_id, "security@example.com") == 0);
    test_assert(strcmp(req->reviewer_note, "Too risky") == 0);

    mock_approval_cleanup();
    return true;
}

bool test_approval_double_decision_fails(void)
{
    mock_approval_init();

    uint8_t dummy[AK_TOKEN_ID_SIZE] = {0};
    ak_approval_request_t *req = mock_approval_create(dummy, dummy, 0, NULL, NULL);

    /* First decision succeeds */
    int result = mock_approval_grant(req->id, "admin", NULL);
    test_assert_eq(result, 0);

    /* Second decision fails */
    result = mock_approval_deny(req->id, "admin", NULL);
    test_assert_eq(result, AK_E_APPROVAL_ALREADY);

    /* Status remains granted */
    test_assert_eq(req->status, AK_APPROVAL_GRANTED);

    mock_approval_cleanup();
    return true;
}

bool test_approval_decision_not_found(void)
{
    mock_approval_init();

    int result = mock_approval_grant(9999, "admin", NULL);
    test_assert_eq(result, AK_E_APPROVAL_NOT_FOUND);

    result = mock_approval_deny(9999, "admin", NULL);
    test_assert_eq(result, AK_E_APPROVAL_NOT_FOUND);

    mock_approval_cleanup();
    return true;
}

/* ============================================================
 * TEST CASES: TIMEOUT HANDLING
 * ============================================================ */

bool test_approval_timeout_basic(void)
{
    mock_approval_init();

    uint8_t dummy[AK_TOKEN_ID_SIZE] = {0};
    ak_approval_request_t *req = mock_approval_create(dummy, dummy, 0, NULL, NULL);
    req->timeout_ms = 1000;  /* 1 second timeout */

    /* Before timeout */
    ak_approval_status_t status = mock_approval_check(req->id);
    test_assert_eq(status, AK_APPROVAL_PENDING);

    /* After timeout */
    mock_approval.current_time_ms += 2000;
    status = mock_approval_check(req->id);
    test_assert_eq(status, AK_APPROVAL_TIMEOUT);

    mock_approval_cleanup();
    return true;
}

bool test_approval_timeout_boundary(void)
{
    mock_approval_init();

    uint8_t dummy[AK_TOKEN_ID_SIZE] = {0};
    ak_approval_request_t *req = mock_approval_create(dummy, dummy, 0, NULL, NULL);
    req->timeout_ms = 1000;

    /* Just before timeout */
    mock_approval.current_time_ms += 999;
    test_assert_eq(mock_approval_check(req->id), AK_APPROVAL_PENDING);

    /* Exactly at timeout */
    mock_approval.current_time_ms += 1;
    test_assert_eq(mock_approval_check(req->id), AK_APPROVAL_PENDING);

    /* Just after timeout */
    mock_approval.current_time_ms += 1;
    test_assert_eq(mock_approval_check(req->id), AK_APPROVAL_TIMEOUT);

    mock_approval_cleanup();
    return true;
}

bool test_approval_granted_before_timeout(void)
{
    mock_approval_init();

    uint8_t dummy[AK_TOKEN_ID_SIZE] = {0};
    ak_approval_request_t *req = mock_approval_create(dummy, dummy, 0, NULL, NULL);
    req->timeout_ms = 1000;

    /* Grant before timeout */
    mock_approval_grant(req->id, "admin", NULL);

    /* Time passes beyond original timeout */
    mock_approval.current_time_ms += 2000;

    /* Should still be granted, not timeout */
    test_assert_eq(mock_approval_check(req->id), AK_APPROVAL_GRANTED);

    mock_approval_cleanup();
    return true;
}

bool test_approval_decision_after_timeout_fails(void)
{
    mock_approval_init();

    uint8_t dummy[AK_TOKEN_ID_SIZE] = {0};
    ak_approval_request_t *req = mock_approval_create(dummy, dummy, 0, NULL, NULL);
    req->timeout_ms = 1000;

    /* Let it timeout */
    mock_approval.current_time_ms += 2000;
    mock_approval_check(req->id);  /* Triggers timeout */

    /* Try to grant after timeout */
    int result = mock_approval_grant(req->id, "admin", NULL);
    test_assert_eq(result, AK_E_APPROVAL_ALREADY);

    mock_approval_cleanup();
    return true;
}

/* ============================================================
 * TEST CASES: CANCELLATION
 * ============================================================ */

bool test_approval_cancel_pending(void)
{
    mock_approval_init();

    uint8_t dummy[AK_TOKEN_ID_SIZE] = {0};
    ak_approval_request_t *req = mock_approval_create(dummy, dummy, 0, NULL, NULL);

    int result = mock_approval_cancel(req->id);
    test_assert_eq(result, 0);
    test_assert_eq(req->status, AK_APPROVAL_CANCELLED);

    mock_approval_cleanup();
    return true;
}

bool test_approval_cancel_already_decided(void)
{
    mock_approval_init();

    uint8_t dummy[AK_TOKEN_ID_SIZE] = {0};
    ak_approval_request_t *req = mock_approval_create(dummy, dummy, 0, NULL, NULL);

    mock_approval_grant(req->id, "admin", NULL);

    int result = mock_approval_cancel(req->id);
    test_assert_eq(result, AK_E_APPROVAL_ALREADY);
    test_assert_eq(req->status, AK_APPROVAL_GRANTED);

    mock_approval_cleanup();
    return true;
}

bool test_approval_cancel_not_found(void)
{
    mock_approval_init();

    int result = mock_approval_cancel(9999);
    test_assert_eq(result, AK_E_APPROVAL_NOT_FOUND);

    mock_approval_cleanup();
    return true;
}

/* ============================================================
 * TEST CASES: STATUS TRANSITIONS
 * ============================================================ */

bool test_approval_status_transitions_grant(void)
{
    mock_approval_init();

    uint8_t dummy[AK_TOKEN_ID_SIZE] = {0};
    ak_approval_request_t *req = mock_approval_create(dummy, dummy, 0, NULL, NULL);

    test_assert_eq(req->status, AK_APPROVAL_PENDING);
    mock_approval_grant(req->id, "admin", NULL);
    test_assert_eq(req->status, AK_APPROVAL_GRANTED);

    /* No further transitions allowed */
    mock_approval_deny(req->id, "admin", NULL);
    test_assert_eq(req->status, AK_APPROVAL_GRANTED);
    mock_approval_cancel(req->id);
    test_assert_eq(req->status, AK_APPROVAL_GRANTED);

    mock_approval_cleanup();
    return true;
}

bool test_approval_status_transitions_deny(void)
{
    mock_approval_init();

    uint8_t dummy[AK_TOKEN_ID_SIZE] = {0};
    ak_approval_request_t *req = mock_approval_create(dummy, dummy, 0, NULL, NULL);

    test_assert_eq(req->status, AK_APPROVAL_PENDING);
    mock_approval_deny(req->id, "admin", NULL);
    test_assert_eq(req->status, AK_APPROVAL_DENIED);

    /* No further transitions allowed */
    mock_approval_grant(req->id, "admin", NULL);
    test_assert_eq(req->status, AK_APPROVAL_DENIED);

    mock_approval_cleanup();
    return true;
}

bool test_approval_status_transitions_timeout(void)
{
    mock_approval_init();

    uint8_t dummy[AK_TOKEN_ID_SIZE] = {0};
    ak_approval_request_t *req = mock_approval_create(dummy, dummy, 0, NULL, NULL);
    req->timeout_ms = 100;

    mock_approval.current_time_ms += 200;
    mock_approval_check(req->id);

    test_assert_eq(req->status, AK_APPROVAL_TIMEOUT);

    /* Cannot change after timeout */
    mock_approval_grant(req->id, "admin", NULL);
    test_assert_eq(req->status, AK_APPROVAL_TIMEOUT);

    mock_approval_cleanup();
    return true;
}

/* ============================================================
 * TEST CASES: PENDING COUNT
 * ============================================================ */

bool test_approval_pending_count_basic(void)
{
    mock_approval_init();

    uint8_t dummy[AK_TOKEN_ID_SIZE] = {0};

    test_assert_eq(mock_approval_pending_count(), 0);

    mock_approval_create(dummy, dummy, 0, NULL, NULL);
    test_assert_eq(mock_approval_pending_count(), 1);

    mock_approval_create(dummy, dummy, 0, NULL, NULL);
    test_assert_eq(mock_approval_pending_count(), 2);

    mock_approval_create(dummy, dummy, 0, NULL, NULL);
    test_assert_eq(mock_approval_pending_count(), 3);

    mock_approval_cleanup();
    return true;
}

bool test_approval_pending_count_after_decisions(void)
{
    mock_approval_init();

    uint8_t dummy[AK_TOKEN_ID_SIZE] = {0};

    ak_approval_request_t *req1 = mock_approval_create(dummy, dummy, 0, NULL, NULL);
    ak_approval_request_t *req2 = mock_approval_create(dummy, dummy, 0, NULL, NULL);
    ak_approval_request_t *req3 = mock_approval_create(dummy, dummy, 0, NULL, NULL);

    test_assert_eq(mock_approval_pending_count(), 3);

    mock_approval_grant(req1->id, "admin", NULL);
    test_assert_eq(mock_approval_pending_count(), 2);

    mock_approval_deny(req2->id, "admin", NULL);
    test_assert_eq(mock_approval_pending_count(), 1);

    mock_approval_cancel(req3->id);
    test_assert_eq(mock_approval_pending_count(), 0);

    mock_approval_cleanup();
    return true;
}

/* ============================================================
 * TEST CASES: MIXED SCENARIOS
 * ============================================================ */

bool test_approval_mixed_decisions(void)
{
    mock_approval_init();

    uint8_t dummy[AK_TOKEN_ID_SIZE] = {0};
    ak_approval_request_t *reqs[10];

    for (int i = 0; i < 10; i++) {
        reqs[i] = mock_approval_create(dummy, dummy, (uint16_t)i, NULL, NULL);
    }

    /* Grant some */
    mock_approval_grant(reqs[0]->id, "admin", NULL);
    mock_approval_grant(reqs[3]->id, "admin", NULL);
    mock_approval_grant(reqs[7]->id, "admin", NULL);

    /* Deny some */
    mock_approval_deny(reqs[1]->id, "admin", NULL);
    mock_approval_deny(reqs[4]->id, "admin", NULL);

    /* Cancel some */
    mock_approval_cancel(reqs[2]->id);

    /* Let some timeout */
    reqs[5]->timeout_ms = 100;
    reqs[6]->timeout_ms = 100;
    mock_approval.current_time_ms += 200;
    mock_approval_check(reqs[5]->id);
    mock_approval_check(reqs[6]->id);

    /* Verify states */
    test_assert_eq(reqs[0]->status, AK_APPROVAL_GRANTED);
    test_assert_eq(reqs[1]->status, AK_APPROVAL_DENIED);
    test_assert_eq(reqs[2]->status, AK_APPROVAL_CANCELLED);
    test_assert_eq(reqs[3]->status, AK_APPROVAL_GRANTED);
    test_assert_eq(reqs[4]->status, AK_APPROVAL_DENIED);
    test_assert_eq(reqs[5]->status, AK_APPROVAL_TIMEOUT);
    test_assert_eq(reqs[6]->status, AK_APPROVAL_TIMEOUT);
    test_assert_eq(reqs[7]->status, AK_APPROVAL_GRANTED);
    test_assert_eq(reqs[8]->status, AK_APPROVAL_PENDING);
    test_assert_eq(reqs[9]->status, AK_APPROVAL_PENDING);

    test_assert_eq(mock_approval_pending_count(), 2);

    mock_approval_cleanup();
    return true;
}

bool test_approval_high_volume(void)
{
    mock_approval_init();

    uint8_t dummy[AK_TOKEN_ID_SIZE] = {0};

    /* Create many requests */
    for (int i = 0; i < MAX_APPROVAL_REQUESTS; i++) {
        ak_approval_request_t *req = mock_approval_create(dummy, dummy, (uint16_t)i, NULL, NULL);
        test_assert(req != NULL);
    }

    test_assert_eq(mock_approval.request_count, MAX_APPROVAL_REQUESTS);
    test_assert_eq(mock_approval_pending_count(), MAX_APPROVAL_REQUESTS);

    /* Should fail when at capacity */
    ak_approval_request_t *req = mock_approval_create(dummy, dummy, 0, NULL, NULL);
    test_assert(req == NULL);

    mock_approval_cleanup();
    return true;
}

/* ============================================================
 * TEST CASES: OPERATION TYPES
 * ============================================================ */

bool test_approval_various_operations(void)
{
    mock_approval_init();

    uint8_t dummy[AK_TOKEN_ID_SIZE] = {0};
    uint16_t ops[] = {0x0400, 0x0401, 0x0402, 0x0100, 0x0200};

    for (int i = 0; i < 5; i++) {
        ak_approval_request_t *req = mock_approval_create(dummy, dummy, ops[i], NULL, NULL);
        test_assert(req != NULL);
        test_assert_eq(req->op, ops[i]);
    }

    mock_approval_cleanup();
    return true;
}

/* ============================================================
 * TEST CASES: REVIEWER INFORMATION
 * ============================================================ */

bool test_approval_reviewer_info_preserved(void)
{
    mock_approval_init();

    uint8_t dummy[AK_TOKEN_ID_SIZE] = {0};
    ak_approval_request_t *req = mock_approval_create(dummy, dummy, 0, NULL, NULL);

    mock_approval_grant(req->id, "security-team@company.com",
                        "Reviewed and approved after security assessment");

    test_assert(strcmp(req->reviewer_id, "security-team@company.com") == 0);
    test_assert(strcmp(req->reviewer_note,
                       "Reviewed and approved after security assessment") == 0);

    mock_approval_cleanup();
    return true;
}

bool test_approval_reviewer_info_optional(void)
{
    mock_approval_init();

    uint8_t dummy[AK_TOKEN_ID_SIZE] = {0};
    ak_approval_request_t *req = mock_approval_create(dummy, dummy, 0, NULL, NULL);

    mock_approval_grant(req->id, NULL, NULL);

    test_assert(req->reviewer_id[0] == '\0');
    test_assert(req->reviewer_note == NULL);

    mock_approval_cleanup();
    return true;
}

/* ============================================================
 * TEST CASES: TIMING
 * ============================================================ */

bool test_approval_timestamps_set(void)
{
    mock_approval_init();

    uint8_t dummy[AK_TOKEN_ID_SIZE] = {0};
    uint64_t create_time = mock_approval.current_time_ms;

    ak_approval_request_t *req = mock_approval_create(dummy, dummy, 0, NULL, NULL);
    test_assert_eq(req->requested_ms, create_time);
    test_assert_eq(req->decided_ms, 0);

    mock_approval.current_time_ms += 1000;
    uint64_t decide_time = mock_approval.current_time_ms;

    mock_approval_grant(req->id, "admin", NULL);
    test_assert_eq(req->decided_ms, decide_time);

    mock_approval_cleanup();
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
    /* Request creation */
    {"approval_create_basic", test_approval_create_basic},
    {"approval_create_multiple", test_approval_create_multiple},
    {"approval_create_unique_ids", test_approval_create_unique_ids},
    {"approval_create_with_null_fields", test_approval_create_with_null_fields},

    /* Approval/Denial decisions */
    {"approval_grant_basic", test_approval_grant_basic},
    {"approval_deny_basic", test_approval_deny_basic},
    {"approval_double_decision_fails", test_approval_double_decision_fails},
    {"approval_decision_not_found", test_approval_decision_not_found},

    /* Timeout handling */
    {"approval_timeout_basic", test_approval_timeout_basic},
    {"approval_timeout_boundary", test_approval_timeout_boundary},
    {"approval_granted_before_timeout", test_approval_granted_before_timeout},
    {"approval_decision_after_timeout_fails", test_approval_decision_after_timeout_fails},

    /* Cancellation */
    {"approval_cancel_pending", test_approval_cancel_pending},
    {"approval_cancel_already_decided", test_approval_cancel_already_decided},
    {"approval_cancel_not_found", test_approval_cancel_not_found},

    /* Status transitions */
    {"approval_status_transitions_grant", test_approval_status_transitions_grant},
    {"approval_status_transitions_deny", test_approval_status_transitions_deny},
    {"approval_status_transitions_timeout", test_approval_status_transitions_timeout},

    /* Pending count */
    {"approval_pending_count_basic", test_approval_pending_count_basic},
    {"approval_pending_count_after_decisions", test_approval_pending_count_after_decisions},

    /* Mixed scenarios */
    {"approval_mixed_decisions", test_approval_mixed_decisions},
    {"approval_high_volume", test_approval_high_volume},

    /* Operation types */
    {"approval_various_operations", test_approval_various_operations},

    /* Reviewer information */
    {"approval_reviewer_info_preserved", test_approval_reviewer_info_preserved},
    {"approval_reviewer_info_optional", test_approval_reviewer_info_optional},

    /* Timing */
    {"approval_timestamps_set", test_approval_timestamps_set},

    {NULL, NULL}
};

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    int passed = 0;
    int failed = 0;

    printf("=== AK Approval Workflow Tests ===\n\n");

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

    return (failed > 0) ? EXIT_FAILURE : EXIT_SUCCESS;
}
