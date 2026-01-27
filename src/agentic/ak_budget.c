/*
 * Authority Kernel - Budget Tracking System Implementation
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * This module implements enhanced budget tracking with historical snapshots,
 * detailed breakdowns, and consumption monitoring (INV-3).
 */

#include "ak_budget.h"
#include "ak_assert.h"
#include <runtime.h>

/* Get current timestamp in milliseconds */
static u64 ak_budget_timestamp_ms(void)
{
    return now(CLOCK_ID_MONOTONIC) / MILLION; /* Convert nanoseconds to milliseconds */
}

/* Find tool index in breakdown by name */
static int ak_budget_find_tool(ak_budget_breakdown_t *breakdown, const char *tool_name)
{
    for (u32 i = 0; i < breakdown->tool_type_count; i++) {
        if (runtime_strcmp(breakdown->tool_names[i], tool_name) == 0) {
            return i;
        }
    }
    return -1;
}

/* Add tool to breakdown tracking */
static int ak_budget_add_tool(ak_budget_breakdown_t *breakdown, const char *tool_name)
{
    if (breakdown->tool_type_count >= AK_BUDGET_MAX_TOOL_TYPES) {
        return -1; /* No space for more tools */
    }
    
    u32 idx = breakdown->tool_type_count;
    runtime_memcpy(breakdown->tool_names[idx], tool_name, 
                  AK_MIN(runtime_strlen(tool_name) + 1, AK_BUDGET_TOOL_NAME_LEN));
    breakdown->tool_names[idx][AK_BUDGET_TOOL_NAME_LEN - 1] = '\0';
    breakdown->tool_calls_by_type[idx] = 0;
    breakdown->tool_type_count++;
    
    return idx;
}

ak_budget_tracker_t *ak_budget_tracker_init(heap h)
{
    AK_ASSERT_ARG(h != INVALID_ADDRESS);
    
    ak_budget_tracker_t *tracker = allocate(h, sizeof(ak_budget_tracker_t));
    if (tracker == INVALID_ADDRESS) {
        return NULL;
    }
    
    runtime_memset(tracker, 0, sizeof(ak_budget_tracker_t));
    tracker->h = h;
    tracker->start_timestamp_ms = ak_budget_timestamp_ms();
    tracker->last_update_ms = tracker->start_timestamp_ms;
    tracker->last_snapshot_ms = tracker->start_timestamp_ms;
    
    /* Initialize default limits */
    tracker->budget.limits[AK_RESOURCE_LLM_TOKENS_IN] = AK_DEFAULT_LLM_TOKENS_IN;
    tracker->budget.limits[AK_RESOURCE_LLM_TOKENS_OUT] = AK_DEFAULT_LLM_TOKENS_OUT;
    tracker->budget.limits[AK_RESOURCE_TOOL_CALLS] = AK_DEFAULT_TOOL_CALLS;
    tracker->budget.limits[AK_RESOURCE_WALL_TIME_MS] = AK_DEFAULT_WALL_TIME_MS;
    tracker->budget.limits[AK_RESOURCE_HEAP_OBJECTS] = AK_DEFAULT_HEAP_OBJECTS;
    tracker->budget.limits[AK_RESOURCE_BLOB_BYTES] = AK_DEFAULT_BLOB_BYTES;
    tracker->budget.limits[AK_RESOURCE_NET_BYTES_OUT] = AK_DEFAULT_NET_BYTES_OUT;
    
    /* Take initial snapshot */
    ak_budget_snapshot(tracker);
    
    return tracker;
}

void ak_budget_tracker_destroy(ak_budget_tracker_t *tracker)
{
    if (tracker == NULL || tracker == INVALID_ADDRESS) {
        return;
    }
    
    deallocate(tracker->h, tracker, sizeof(ak_budget_tracker_t));
}

void ak_budget_set_limit(ak_budget_tracker_t *tracker,
                        ak_resource_type_t resource,
                        u64 limit)
{
    AK_ASSERT_ARG(tracker != NULL);
    AK_ASSERT_ARG(resource < AK_RESOURCE_COUNT);
    
    tracker->budget.limits[resource] = limit;
    tracker->last_update_ms = ak_budget_timestamp_ms();
}

int ak_budget_consume(ak_budget_tracker_t *tracker,
                     ak_resource_type_t resource,
                     u64 amount)
{
    AK_ASSERT_ARG(tracker != NULL);
    AK_ASSERT_ARG(resource < AK_RESOURCE_COUNT);
    
    u64 limit = tracker->budget.limits[resource];
    u64 used = tracker->budget.used[resource];
    
    /* Check if consumption would exceed limit */
    if (limit > 0 && used + amount > limit) {
        return AK_E_BUDGET_EXCEEDED;
    }
    
    /* Update consumption */
    tracker->budget.used[resource] += amount;
    tracker->last_update_ms = ak_budget_timestamp_ms();
    
    return 0;
}

void ak_budget_record_operation(ak_budget_tracker_t *tracker,
                                const char *operation,
                                const char *detail,
                                u64 amount)
{
    AK_ASSERT_ARG(tracker != NULL);
    AK_ASSERT_ARG(operation != NULL);
    
    tracker->last_update_ms = ak_budget_timestamp_ms();
    
    /* Track operation-specific details */
    if (runtime_strcmp(operation, "inference") == 0) {
        tracker->breakdown.tokens_inference += amount;
    } else if (runtime_strcmp(operation, "tool_response") == 0) {
        tracker->breakdown.tokens_tool_responses += amount;
    } else if (runtime_strcmp(operation, "tool_call") == 0 && detail != NULL) {
        /* Track tool calls by name */
        int idx = ak_budget_find_tool(&tracker->breakdown, detail);
        if (idx < 0) {
            idx = ak_budget_add_tool(&tracker->breakdown, detail);
        }
        if (idx >= 0) {
            tracker->breakdown.tool_calls_by_type[idx]++;
        }
    }
}

void ak_budget_snapshot(ak_budget_tracker_t *tracker)
{
    AK_ASSERT_ARG(tracker != NULL);
    
    u64 now_ms = ak_budget_timestamp_ms();
    
    /* Create snapshot */
    ak_budget_snapshot_t snapshot;
    snapshot.timestamp_ms = now_ms;
    snapshot.tokens = tracker->budget.used[AK_RESOURCE_LLM_TOKENS_IN] +
                     tracker->budget.used[AK_RESOURCE_LLM_TOKENS_OUT];
    snapshot.tool_calls = tracker->budget.used[AK_RESOURCE_TOOL_CALLS];
    snapshot.wall_time_ms = now_ms - tracker->start_timestamp_ms;
    snapshot.bytes = tracker->budget.used[AK_RESOURCE_BLOB_BYTES] +
                    tracker->budget.used[AK_RESOURCE_NET_BYTES_OUT];
    
    /* Add to ring buffer */
    tracker->snapshots[tracker->snapshot_head] = snapshot;
    tracker->snapshot_head = (tracker->snapshot_head + 1) % AK_BUDGET_HISTORY_SIZE;
    
    if (tracker->snapshot_count < AK_BUDGET_HISTORY_SIZE) {
        tracker->snapshot_count++;
    }
    
    tracker->last_snapshot_ms = now_ms;
}

void ak_budget_get_status(ak_budget_tracker_t *tracker,
                         ak_budget_status_t *status)
{
    AK_ASSERT_ARG(tracker != NULL);
    AK_ASSERT_ARG(status != NULL);
    
    runtime_memset(status, 0, sizeof(ak_budget_status_t));
    
    /* Token consumption (combine input and output) */
    status->tokens_used = tracker->budget.used[AK_RESOURCE_LLM_TOKENS_IN] +
                         tracker->budget.used[AK_RESOURCE_LLM_TOKENS_OUT];
    status->tokens_limit = tracker->budget.limits[AK_RESOURCE_LLM_TOKENS_IN] +
                          tracker->budget.limits[AK_RESOURCE_LLM_TOKENS_OUT];
    
    /* Tool calls */
    status->tool_calls_used = tracker->budget.used[AK_RESOURCE_TOOL_CALLS];
    status->tool_calls_limit = tracker->budget.limits[AK_RESOURCE_TOOL_CALLS];
    
    /* Wall time */
    u64 now_ms = ak_budget_timestamp_ms();
    status->wall_time_ms_used = now_ms - tracker->start_timestamp_ms;
    status->wall_time_ms_limit = tracker->budget.limits[AK_RESOURCE_WALL_TIME_MS];
    
    /* Bytes (combine blob and network) */
    status->bytes_used = tracker->budget.used[AK_RESOURCE_BLOB_BYTES] +
                        tracker->budget.used[AK_RESOURCE_NET_BYTES_OUT];
    status->bytes_limit = tracker->budget.limits[AK_RESOURCE_BLOB_BYTES] +
                         tracker->budget.limits[AK_RESOURCE_NET_BYTES_OUT];
    
    status->last_update_ms = tracker->last_update_ms;
}

u32 ak_budget_get_history(ak_budget_tracker_t *tracker,
                         ak_budget_snapshot_t *snapshots,
                         u32 max_count)
{
    AK_ASSERT_ARG(tracker != NULL);
    AK_ASSERT_ARG(snapshots != NULL);
    
    u32 count = AK_MIN(tracker->snapshot_count, max_count);
    if (count == 0) {
        return 0;
    }
    
    /* Copy snapshots in chronological order */
    u32 start_idx;
    if (tracker->snapshot_count < AK_BUDGET_HISTORY_SIZE) {
        /* Haven't wrapped yet */
        start_idx = 0;
    } else {
        /* Wrapped - start from oldest */
        start_idx = tracker->snapshot_head;
    }
    
    for (u32 i = 0; i < count; i++) {
        u32 idx = (start_idx + i) % AK_BUDGET_HISTORY_SIZE;
        snapshots[i] = tracker->snapshots[idx];
    }
    
    return count;
}

void ak_budget_get_breakdown(ak_budget_tracker_t *tracker,
                            ak_budget_breakdown_t *breakdown)
{
    AK_ASSERT_ARG(tracker != NULL);
    AK_ASSERT_ARG(breakdown != NULL);
    
    runtime_memcpy(breakdown, &tracker->breakdown, sizeof(ak_budget_breakdown_t));
}

boolean ak_budget_is_critical(ak_budget_tracker_t *tracker,
                              ak_resource_type_t resource)
{
    AK_ASSERT_ARG(tracker != NULL);
    AK_ASSERT_ARG(resource < AK_RESOURCE_COUNT);
    
    u64 limit = tracker->budget.limits[resource];
    if (limit == 0) {
        return false; /* No limit set */
    }
    
    u64 used = tracker->budget.used[resource];
    
    /* Critical if >90% consumed */
    return (used * 100 / limit) > 90;
}

double ak_budget_calc_rate(ak_budget_tracker_t *tracker,
                           ak_resource_type_t resource)
{
    AK_ASSERT_ARG(tracker != NULL);
    AK_ASSERT_ARG(resource < AK_RESOURCE_COUNT);
    
    if (tracker->snapshot_count < 2) {
        return 0.0; /* Need at least 2 snapshots */
    }
    
    /* Get oldest and newest snapshots */
    u32 oldest_idx, newest_idx;
    if (tracker->snapshot_count < AK_BUDGET_HISTORY_SIZE) {
        oldest_idx = 0;
        newest_idx = tracker->snapshot_count - 1;
    } else {
        oldest_idx = tracker->snapshot_head;
        newest_idx = (tracker->snapshot_head + AK_BUDGET_HISTORY_SIZE - 1) % AK_BUDGET_HISTORY_SIZE;
    }
    
    ak_budget_snapshot_t *oldest = &tracker->snapshots[oldest_idx];
    ak_budget_snapshot_t *newest = &tracker->snapshots[newest_idx];
    
    /* Calculate time span in seconds */
    u64 time_span_ms = newest->timestamp_ms - oldest->timestamp_ms;
    if (time_span_ms == 0) {
        return 0.0;
    }
    
    double time_span_sec = (double)time_span_ms / 1000.0;
    
    /* Calculate consumption delta based on resource type */
    u64 delta = 0;
    switch (resource) {
        case AK_RESOURCE_TOKENS:
        case AK_RESOURCE_LLM_TOKENS_IN:
        case AK_RESOURCE_LLM_TOKENS_OUT:
            delta = newest->tokens - oldest->tokens;
            break;
        case AK_RESOURCE_TOOL_CALLS:
            delta = newest->tool_calls - oldest->tool_calls;
            break;
        case AK_RESOURCE_WALL_TIME_MS:
            delta = newest->wall_time_ms - oldest->wall_time_ms;
            break;
        default:
            delta = newest->bytes - oldest->bytes;
            break;
    }
    
    return (double)delta / time_span_sec;
}

void ak_budget_format_json(ak_budget_tracker_t *tracker, buffer output)
{
    AK_ASSERT_ARG(tracker != NULL);
    AK_ASSERT_ARG(output != NULL);
    
    ak_budget_status_t status;
    ak_budget_get_status(tracker, &status);
    
    bprintf(output, "{");
    bprintf(output, "\"tokens_used\":%lu,", status.tokens_used);
    bprintf(output, "\"tokens_limit\":%lu,", status.tokens_limit);
    bprintf(output, "\"tool_calls_used\":%lu,", status.tool_calls_used);
    bprintf(output, "\"tool_calls_limit\":%lu,", status.tool_calls_limit);
    bprintf(output, "\"wall_time_ms_used\":%lu,", status.wall_time_ms_used);
    bprintf(output, "\"wall_time_ms_limit\":%lu,", status.wall_time_ms_limit);
    bprintf(output, "\"bytes_used\":%lu,", status.bytes_used);
    bprintf(output, "\"bytes_limit\":%lu,", status.bytes_limit);
    bprintf(output, "\"last_update_ms\":%lu", status.last_update_ms);
    bprintf(output, "}");
}

void ak_budget_format_history_json(ak_budget_tracker_t *tracker,
                                   u32 count,
                                   buffer output)
{
    AK_ASSERT_ARG(tracker != NULL);
    AK_ASSERT_ARG(output != NULL);
    
    ak_budget_snapshot_t snapshots[AK_BUDGET_HISTORY_SIZE];
    u32 actual_count = ak_budget_get_history(tracker, snapshots, count);
    
    bprintf(output, "{\"snapshots\":[");
    
    for (u32 i = 0; i < actual_count; i++) {
        if (i > 0) {
            bprintf(output, ",");
        }
        bprintf(output, "{");
        bprintf(output, "\"timestamp_ms\":%lu,", snapshots[i].timestamp_ms);
        bprintf(output, "\"tokens\":%lu,", snapshots[i].tokens);
        bprintf(output, "\"tool_calls\":%lu,", snapshots[i].tool_calls);
        bprintf(output, "\"wall_time_ms\":%lu,", snapshots[i].wall_time_ms);
        bprintf(output, "\"bytes\":%lu", snapshots[i].bytes);
        bprintf(output, "}");
    }
    
    bprintf(output, "]}");
}

void ak_budget_format_breakdown_json(ak_budget_tracker_t *tracker,
                                    buffer output)
{
    AK_ASSERT_ARG(tracker != NULL);
    AK_ASSERT_ARG(output != NULL);
    
    ak_budget_breakdown_t *breakdown = &tracker->breakdown;
    
    bprintf(output, "{");
    
    /* Token breakdown */
    bprintf(output, "\"tokens_by_operation\":{");
    bprintf(output, "\"inference\":%lu,", breakdown->tokens_inference);
    bprintf(output, "\"tool_responses\":%lu", breakdown->tokens_tool_responses);
    bprintf(output, "},");
    
    /* Tool calls breakdown */
    bprintf(output, "\"tool_calls_by_name\":{");
    for (u32 i = 0; i < breakdown->tool_type_count; i++) {
        if (i > 0) {
            bprintf(output, ",");
        }
        bprintf(output, "\"%s\":%u", breakdown->tool_names[i],
               breakdown->tool_calls_by_type[i]);
    }
    bprintf(output, "},");
    
    /* Model breakdown (placeholder for future expansion) */
    bprintf(output, "\"tokens_by_model\":{}");
    
    bprintf(output, "}");
}
