/*
 * Authority Kernel - Budget Tracking System
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * This module provides enhanced budget tracking with historical snapshots,
 * detailed breakdowns, and consumption monitoring for resource management (INV-3).
 *
 * Features:
 * - Real-time budget status queries
 * - Historical consumption snapshots (ring buffer)
 * - Per-operation breakdown tracking
 * - Budget consumption rate calculation
 */

#ifndef AK_BUDGET_H
#define AK_BUDGET_H

#include "ak_types.h"
#include "ak_compat.h"

/* Configuration constants */
#define AK_BUDGET_HISTORY_SIZE 60     /* Number of historical snapshots (1 minute at 1/sec) */
#define AK_BUDGET_MAX_TOOL_TYPES 32   /* Maximum distinct tool types to track */
#define AK_BUDGET_TOOL_NAME_LEN 64    /* Maximum tool name length */

/* ============================================================
 * BUDGET SNAPSHOT STRUCTURE
 * ============================================================
 * A point-in-time snapshot of budget consumption.
 * Used for historical tracking and burn rate calculation.
 */

typedef struct ak_budget_snapshot {
    u64 timestamp_ms;           /* When this snapshot was taken */
    u64 tokens;                 /* Total tokens consumed at this time */
    u64 tool_calls;             /* Total tool calls at this time */
    u64 wall_time_ms;           /* Wall time elapsed (ms) */
    u64 bytes;                  /* Total bytes consumed */
} ak_budget_snapshot_t;

/* ============================================================
 * BUDGET BREAKDOWN STRUCTURE
 * ============================================================
 * Detailed breakdown of budget consumption by operation type.
 */

typedef struct ak_budget_breakdown {
    /* Token consumption by source */
    u64 tokens_inference;       /* Tokens consumed by LLM inference */
    u64 tokens_tool_responses;  /* Tokens in tool response processing */
    
    /* Tool call tracking */
    u32 tool_calls_by_type[AK_BUDGET_MAX_TOOL_TYPES];
    char tool_names[AK_BUDGET_MAX_TOOL_TYPES][AK_BUDGET_TOOL_NAME_LEN];
    u32 tool_type_count;        /* Number of distinct tools tracked */
} ak_budget_breakdown_t;

/* ============================================================
 * BUDGET TRACKER STRUCTURE
 * ============================================================
 * Enhanced budget tracking with historical data and breakdowns.
 */

typedef struct ak_budget_tracker {
    /* Base budget (from ak_types.h) */
    ak_budget_t budget;         /* Current limits and usage */
    
    /* Tracking metadata */
    u64 start_timestamp_ms;     /* When tracking started */
    u64 last_update_ms;         /* Last update timestamp */
    u64 last_snapshot_ms;       /* Last snapshot timestamp */
    
    /* Historical snapshots (ring buffer) */
    ak_budget_snapshot_t snapshots[AK_BUDGET_HISTORY_SIZE];
    u32 snapshot_head;          /* Ring buffer head index */
    u32 snapshot_count;         /* Number of snapshots (max AK_BUDGET_HISTORY_SIZE) */
    
    /* Detailed breakdown */
    ak_budget_breakdown_t breakdown;
    
    /* Memory management */
    heap h;
} ak_budget_tracker_t;

/* ============================================================
 * BUDGET STATUS RESULT
 * ============================================================
 * Result structure for budget status queries.
 */

typedef struct ak_budget_status {
    /* Current consumption */
    u64 tokens_used;
    u64 tokens_limit;
    u64 tool_calls_used;
    u64 tool_calls_limit;
    u64 wall_time_ms_used;
    u64 wall_time_ms_limit;
    u64 bytes_used;
    u64 bytes_limit;
    
    /* Metadata */
    u64 last_update_ms;
} ak_budget_status_t;

/* ============================================================
 * FUNCTION PROTOTYPES
 * ============================================================ */

/**
 * Initialize a budget tracker.
 *
 * @param h Heap allocator
 * @return Initialized budget tracker, or NULL on failure
 */
ak_budget_tracker_t *ak_budget_tracker_init(heap h);

/**
 * Destroy a budget tracker and free resources.
 *
 * @param tracker Budget tracker to destroy
 */
void ak_budget_tracker_destroy(ak_budget_tracker_t *tracker);

/**
 * Set budget limits from policy.
 *
 * @param tracker Budget tracker
 * @param resource Resource type
 * @param limit Limit value
 */
void ak_budget_set_limit(ak_budget_tracker_t *tracker,
                        ak_resource_type_t resource,
                        u64 limit);

/**
 * Consume budget for a resource.
 *
 * @param tracker Budget tracker
 * @param resource Resource type
 * @param amount Amount to consume
 * @return 0 on success, negative errno on budget exceeded
 */
int ak_budget_consume(ak_budget_tracker_t *tracker,
                     ak_resource_type_t resource,
                     u64 amount);

/**
 * Record detailed breakdown for specific operations.
 *
 * @param tracker Budget tracker
 * @param operation Operation type (e.g., "inference", "tool_call")
 * @param detail Detail string (e.g., tool name)
 * @param amount Amount consumed
 */
void ak_budget_record_operation(ak_budget_tracker_t *tracker,
                                const char *operation,
                                const char *detail,
                                u64 amount);

/**
 * Take a snapshot of current budget state.
 * Should be called periodically (e.g., every second).
 *
 * @param tracker Budget tracker
 */
void ak_budget_snapshot(ak_budget_tracker_t *tracker);

/**
 * Get current budget status.
 *
 * @param tracker Budget tracker
 * @param status Output status structure
 */
void ak_budget_get_status(ak_budget_tracker_t *tracker,
                         ak_budget_status_t *status);

/**
 * Get historical snapshots.
 *
 * @param tracker Budget tracker
 * @param snapshots Output array (caller-allocated)
 * @param max_count Maximum snapshots to retrieve
 * @return Actual number of snapshots returned
 */
u32 ak_budget_get_history(ak_budget_tracker_t *tracker,
                         ak_budget_snapshot_t *snapshots,
                         u32 max_count);

/**
 * Get detailed breakdown of consumption.
 *
 * @param tracker Budget tracker
 * @param breakdown Output breakdown structure
 */
void ak_budget_get_breakdown(ak_budget_tracker_t *tracker,
                            ak_budget_breakdown_t *breakdown);

/**
 * Check if budget is critically low (>90% consumed).
 *
 * @param tracker Budget tracker
 * @param resource Resource type to check
 * @return true if resource is critically low
 */
boolean ak_budget_is_critical(ak_budget_tracker_t *tracker,
                              ak_resource_type_t resource);

/**
 * Calculate consumption rate (units per second).
 *
 * @param tracker Budget tracker
 * @param resource Resource type
 * @return Consumption rate, or 0 if cannot calculate
 */
double ak_budget_calc_rate(ak_budget_tracker_t *tracker,
                           ak_resource_type_t resource);

/**
 * Format budget status as JSON.
 *
 * @param tracker Budget tracker
 * @param output Output buffer
 */
void ak_budget_format_json(ak_budget_tracker_t *tracker, buffer output);

/**
 * Format budget history as JSON.
 *
 * @param tracker Budget tracker
 * @param count Number of snapshots to include
 * @param output Output buffer
 */
void ak_budget_format_history_json(ak_budget_tracker_t *tracker,
                                   u32 count,
                                   buffer output);

/**
 * Format budget breakdown as JSON.
 *
 * @param tracker Budget tracker
 * @param output Output buffer
 */
void ak_budget_format_breakdown_json(ak_budget_tracker_t *tracker,
                                    buffer output);

#endif /* AK_BUDGET_H */
