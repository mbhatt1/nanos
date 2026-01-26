/*
 * Authority Kernel - Budget Tracking Unit Tests
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Comprehensive tests for INV-3 (Budget) enforcement:
 * - Budget initialization and limits
 * - Consumption tracking
 * - Snapshot history
 * - Breakdown tracking
 * - Critical threshold detection
 * - Burn rate calculation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

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

/* Mock heap allocator for testing */
static void *test_heap = (void *)1;

static void *test_allocate(void *h, size_t size) {
    (void)h;
    return malloc(size);
}

static void test_deallocate(void *h, void *ptr, size_t size) {
    (void)h;
    (void)size;
    free(ptr);
}

/* Mock runtime functions */
static uint64_t test_timestamp_ms = 0;

uint64_t now(int clock_id) {
    (void)clock_id;
    return test_timestamp_ms * 1000000ULL; /* Convert ms to ns */
}

void *allocate(void *h, size_t size) {
    return test_allocate(h, size);
}

void deallocate(void *h, void *ptr, size_t size) {
    test_deallocate(h, ptr, size);
}

void *runtime_memset(void *s, int c, size_t n) {
    return memset(s, c, n);
}

void *runtime_memcpy(void *dest, const void *src, size_t n) {
    return memcpy(dest, src, n);
}

int runtime_strcmp(const char *s1, const char *s2) {
    return strcmp(s1, s2);
}

int runtime_memcmp(const void *s1, const void *s2, size_t n) {
    return memcmp(s1, s2, n);
}

size_t runtime_strlen(const char *s) {
    return strlen(s);
}

/* Include budget tracking implementation */
#include "../../src/agentic/ak_budget.h"
#include "../../src/agentic/ak_budget.c"

/* ============================================================
 * TEST FUNCTIONS
 * ============================================================ */

static bool test_budget_init(void) {
    printf("  Testing budget initialization...\n");
    
    test_timestamp_ms = 1000;
    
    ak_budget_tracker_t *tracker = ak_budget_tracker_init(test_heap);
    test_assert(tracker != NULL);
    test_assert(tracker->h == test_heap);
    test_assert(tracker->start_timestamp_ms == 1000);
    test_assert(tracker->snapshot_count > 0); /* Initial snapshot taken */
    
    /* Check default limits */
    test_assert(tracker->budget.limits[AK_RESOURCE_LLM_TOKENS_IN] == AK_DEFAULT_LLM_TOKENS_IN);
    test_assert(tracker->budget.limits[AK_RESOURCE_TOOL_CALLS] == AK_DEFAULT_TOOL_CALLS);
    
    /* Check initial usage is zero */
    test_assert(tracker->budget.used[AK_RESOURCE_TOKENS] == 0);
    test_assert(tracker->budget.used[AK_RESOURCE_TOOL_CALLS] == 0);
    
    ak_budget_tracker_destroy(tracker);
    return true;
}

static bool test_budget_set_limit(void) {
    printf("  Testing budget limit setting...\n");
    
    ak_budget_tracker_t *tracker = ak_budget_tracker_init(test_heap);
    test_assert(tracker != NULL);
    
    /* Set custom limits */
    ak_budget_set_limit(tracker, AK_RESOURCE_TOKENS, 50000);
    ak_budget_set_limit(tracker, AK_RESOURCE_TOOL_CALLS, 25);
    
    test_assert_eq(tracker->budget.limits[AK_RESOURCE_TOKENS], 50000);
    test_assert_eq(tracker->budget.limits[AK_RESOURCE_TOOL_CALLS], 25);
    
    ak_budget_tracker_destroy(tracker);
    return true;
}

static bool test_budget_consume(void) {
    printf("  Testing budget consumption...\n");
    
    ak_budget_tracker_t *tracker = ak_budget_tracker_init(test_heap);
    test_assert(tracker != NULL);
    
    /* Set limits */
    ak_budget_set_limit(tracker, AK_RESOURCE_TOKENS, 1000);
    ak_budget_set_limit(tracker, AK_RESOURCE_TOOL_CALLS, 10);
    
    /* Consume within limits */
    int result = ak_budget_consume(tracker, AK_RESOURCE_TOKENS, 100);
    test_assert_eq(result, 0);
    test_assert_eq(tracker->budget.used[AK_RESOURCE_TOKENS], 100);
    
    result = ak_budget_consume(tracker, AK_RESOURCE_TOOL_CALLS, 3);
    test_assert_eq(result, 0);
    test_assert_eq(tracker->budget.used[AK_RESOURCE_TOOL_CALLS], 3);
    
    /* Consume more */
    result = ak_budget_consume(tracker, AK_RESOURCE_TOKENS, 500);
    test_assert_eq(result, 0);
    test_assert_eq(tracker->budget.used[AK_RESOURCE_TOKENS], 600);
    
    /* Attempt to exceed limit */
    result = ak_budget_consume(tracker, AK_RESOURCE_TOKENS, 500);
    test_assert_eq(result, AK_E_BUDGET_EXCEEDED);
    test_assert_eq(tracker->budget.used[AK_RESOURCE_TOKENS], 600); /* Should not change */
    
    ak_budget_tracker_destroy(tracker);
    return true;
}

static bool test_budget_snapshot(void) {
    printf("  Testing budget snapshots...\n");
    
    test_timestamp_ms = 1000;
    
    ak_budget_tracker_t *tracker = ak_budget_tracker_init(test_heap);
    test_assert(tracker != NULL);
    
    uint32_t initial_count = tracker->snapshot_count;
    
    /* Consume some budget */
    ak_budget_consume(tracker, AK_RESOURCE_LLM_TOKENS_IN, 100);
    ak_budget_consume(tracker, AK_RESOURCE_TOOL_CALLS, 5);
    
    /* Advance time and take snapshot */
    test_timestamp_ms = 2000;
    ak_budget_snapshot(tracker);
    
    test_assert(tracker->snapshot_count == initial_count + 1);
    
    /* Verify snapshot data */
    uint32_t idx = (tracker->snapshot_head + AK_BUDGET_HISTORY_SIZE - 1) % AK_BUDGET_HISTORY_SIZE;
    ak_budget_snapshot_t *snapshot = &tracker->snapshots[idx];
    
    test_assert(snapshot->timestamp_ms == 2000);
    test_assert(snapshot->tokens == 100);
    test_assert(snapshot->tool_calls == 5);
    test_assert(snapshot->wall_time_ms == 1000); /* 2000 - 1000 */
    
    ak_budget_tracker_destroy(tracker);
    return true;
}

static bool test_budget_history(void) {
    printf("  Testing budget history retrieval...\n");
    
    test_timestamp_ms = 1000;
    
    ak_budget_tracker_t *tracker = ak_budget_tracker_init(test_heap);
    test_assert(tracker != NULL);
    
    /* Create multiple snapshots */
    for (int i = 0; i < 5; i++) {
        test_timestamp_ms += 100;
        ak_budget_consume(tracker, AK_RESOURCE_TOKENS, 10);
        ak_budget_snapshot(tracker);
    }
    
    /* Retrieve history */
    ak_budget_snapshot_t snapshots[10];
    uint32_t count = ak_budget_get_history(tracker, snapshots, 10);
    
    test_assert(count >= 5); /* At least 5 snapshots (plus initial) */
    
    /* Verify chronological order */
    for (uint32_t i = 1; i < count; i++) {
        test_assert(snapshots[i].timestamp_ms >= snapshots[i-1].timestamp_ms);
    }
    
    ak_budget_tracker_destroy(tracker);
    return true;
}

static bool test_budget_breakdown(void) {
    printf("  Testing budget breakdown...\n");
    
    ak_budget_tracker_t *tracker = ak_budget_tracker_init(test_heap);
    test_assert(tracker != NULL);
    
    /* Record different operation types */
    ak_budget_record_operation(tracker, "inference", NULL, 500);
    ak_budget_record_operation(tracker, "tool_response", NULL, 200);
    ak_budget_record_operation(tracker, "tool_call", "http_get", 0);
    ak_budget_record_operation(tracker, "tool_call", "file_read", 0);
    ak_budget_record_operation(tracker, "tool_call", "http_get", 0);
    
    /* Get breakdown */
    ak_budget_breakdown_t breakdown;
    ak_budget_get_breakdown(tracker, &breakdown);
    
    test_assert_eq(breakdown.tokens_inference, 500);
    test_assert_eq(breakdown.tokens_tool_responses, 200);
    test_assert(breakdown.tool_type_count == 2); /* http_get and file_read */
    
    /* Find and verify tool counts */
    int http_get_idx = -1;
    int file_read_idx = -1;
    
    for (uint32_t i = 0; i < breakdown.tool_type_count; i++) {
        if (strcmp(breakdown.tool_names[i], "http_get") == 0) {
            http_get_idx = i;
        } else if (strcmp(breakdown.tool_names[i], "file_read") == 0) {
            file_read_idx = i;
        }
    }
    
    test_assert(http_get_idx >= 0);
    test_assert(file_read_idx >= 0);
    test_assert_eq(breakdown.tool_calls_by_type[http_get_idx], 2);
    test_assert_eq(breakdown.tool_calls_by_type[file_read_idx], 1);
    
    ak_budget_tracker_destroy(tracker);
    return true;
}

static bool test_budget_is_critical(void) {
    printf("  Testing critical budget detection...\n");
    
    ak_budget_tracker_t *tracker = ak_budget_tracker_init(test_heap);
    test_assert(tracker != NULL);
    
    /* Set limit */
    ak_budget_set_limit(tracker, AK_RESOURCE_TOKENS, 1000);
    
    /* Consume 85% - not critical */
    ak_budget_consume(tracker, AK_RESOURCE_TOKENS, 850);
    test_assert(!ak_budget_is_critical(tracker, AK_RESOURCE_TOKENS));
    
    /* Consume to 95% - critical */
    ak_budget_consume(tracker, AK_RESOURCE_TOKENS, 100);
    test_assert(ak_budget_is_critical(tracker, AK_RESOURCE_TOKENS));
    
    ak_budget_tracker_destroy(tracker);
    return true;
}

static bool test_budget_calc_rate(void) {
    printf("  Testing burn rate calculation...\n");
    
    test_timestamp_ms = 1000;
    
    ak_budget_tracker_t *tracker = ak_budget_tracker_init(test_heap);
    test_assert(tracker != NULL);
    
    /* Need at least 2 snapshots */
    test_timestamp_ms = 1000;
    ak_budget_consume(tracker, AK_RESOURCE_TOKENS, 100);
    ak_budget_snapshot(tracker);
    
    test_timestamp_ms = 2000; /* 1 second later */
    ak_budget_consume(tracker, AK_RESOURCE_TOKENS, 200);
    ak_budget_snapshot(tracker);
    
    test_timestamp_ms = 3000; /* 1 second later */
    ak_budget_consume(tracker, AK_RESOURCE_TOKENS, 300);
    ak_budget_snapshot(tracker);
    
    /* Calculate rate (should be ~300 tokens per second) */
    double rate = ak_budget_calc_rate(tracker, AK_RESOURCE_TOKENS);
    test_assert(rate > 250.0 && rate < 350.0); /* Allow some tolerance */
    
    ak_budget_tracker_destroy(tracker);
    return true;
}

static bool test_budget_get_status(void) {
    printf("  Testing budget status retrieval...\n");
    
    test_timestamp_ms = 1000;
    
    ak_budget_tracker_t *tracker = ak_budget_tracker_init(test_heap);
    test_assert(tracker != NULL);
    
    /* Set limits and consume */
    ak_budget_set_limit(tracker, AK_RESOURCE_LLM_TOKENS_IN, 500);
    ak_budget_set_limit(tracker, AK_RESOURCE_LLM_TOKENS_OUT, 500);
    ak_budget_set_limit(tracker, AK_RESOURCE_TOOL_CALLS, 50);
    
    ak_budget_consume(tracker, AK_RESOURCE_LLM_TOKENS_IN, 200);
    ak_budget_consume(tracker, AK_RESOURCE_LLM_TOKENS_OUT, 100);
    ak_budget_consume(tracker, AK_RESOURCE_TOOL_CALLS, 10);
    
    /* Get status */
    ak_budget_status_t status;
    ak_budget_get_status(tracker, &status);
    
    test_assert_eq(status.tokens_used, 300); /* 200 + 100 */
    test_assert_eq(status.tokens_limit, 1000); /* 500 + 500 */
    test_assert_eq(status.tool_calls_used, 10);
    test_assert_eq(status.tool_calls_limit, 50);
    
    test_timestamp_ms = 5000;
    ak_budget_get_status(tracker, &status);
    test_assert_eq(status.wall_time_ms_used, 4000); /* 5000 - 1000 */
    
    ak_budget_tracker_destroy(tracker);
    return true;
}

/* ============================================================
 * TEST RUNNER
 * ============================================================ */

typedef struct {
    const char *name;
    bool (*func)(void);
} test_case_t;

static test_case_t tests[] = {
    {"Budget Initialization", test_budget_init},
    {"Set Budget Limits", test_budget_set_limit},
    {"Budget Consumption", test_budget_consume},
    {"Budget Snapshots", test_budget_snapshot},
    {"Budget History", test_budget_history},
    {"Budget Breakdown", test_budget_breakdown},
    {"Critical Detection", test_budget_is_critical},
    {"Burn Rate Calculation", test_budget_calc_rate},
    {"Budget Status", test_budget_get_status},
};

int main(void) {
    printf("\n");
    printf("========================================\n");
    printf("Authority Kernel - Budget Tracking Tests\n");
    printf("========================================\n\n");
    
    int passed = 0;
    int failed = 0;
    
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        printf("[%zu/%zu] %s\n", i + 1, sizeof(tests) / sizeof(tests[0]), tests[i].name);
        
        /* Reset timestamp for each test */
        test_timestamp_ms = 0;
        
        if (tests[i].func()) {
            printf("  PASS\n\n");
            passed++;
        } else {
            printf("  FAIL\n\n");
            failed++;
        }
    }
    
    printf("========================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);
    printf("========================================\n\n");
    
    return (failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
