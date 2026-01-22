/*
 * Authority Kernel - Record Mode API
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Record Mode allows the Authority Kernel to accumulate denied effects
 * for batch policy suggestions. When AK_MODE_RECORD is active:
 *   1. Denied effects are recorded but allowed to proceed
 *   2. The program runs to completion, discovering all needed effects
 *   3. A complete policy can be generated from recorded effects
 *
 * This is useful for:
 *   - Bootstrapping policies for new applications
 *   - Discovering all effects a program needs
 *   - Generating minimal-privilege policies
 */

#ifndef AK_RECORD_H
#define AK_RECORD_H

#include "ak_effects.h"

/* ============================================================
 * CONSTANTS
 * ============================================================ */

/* Hash table size for recorded effects (must be power of 2) */
#define AK_RECORD_HASH_SIZE 256

/* Maximum unique effects to record */
#define AK_RECORD_MAX_EFFECTS 4096

/* Maximum size of generated policy JSON */
#define AK_RECORD_MAX_POLICY 65536

/* ============================================================
 * RECORD STATE STRUCTURE
 * ============================================================
 * Internal state for record mode. One instance per context.
 */

typedef struct ak_record_state {
  /* Heap for allocations */
  heap h;

  /* Hash table of recorded effects (chained) */
  ak_recorded_effect_t *buckets[AK_RECORD_HASH_SIZE];

  /* Statistics */
  u32 unique_count; /* Number of unique effects recorded */
  u64 total_count;  /* Total effects seen (including duplicates) */

  /* Enabled flag */
  boolean enabled;

  /* Timestamp when recording started */
  u64 start_time_ms;

} ak_record_state_t;

/* ============================================================
 * INITIALIZATION AND LIFECYCLE
 * ============================================================ */

/*
 * ak_record_init - Initialize record mode state.
 *
 * Allocates and initializes a record state structure. Must be called
 * before using any other record functions.
 *
 * PRECONDITIONS:
 *   - h must be a valid heap
 *
 * POSTCONDITIONS:
 *   - Returns valid record state or NULL on failure
 *   - Recording is disabled by default (call ak_record_enable)
 *
 * Parameters:
 *   h - Heap for memory allocations
 *
 * Returns:
 *   Pointer to record state on success, NULL on allocation failure
 */
ak_record_state_t *ak_record_init(heap h);

/*
 * ak_record_shutdown - Free record state and all recorded effects.
 *
 * PRECONDITIONS:
 *   - state may be NULL (no-op)
 *
 * POSTCONDITIONS:
 *   - All memory is freed
 *   - state pointer is no longer valid
 *
 * Parameters:
 *   state - Record state to free (may be NULL)
 */
void ak_record_shutdown(ak_record_state_t *state);

/*
 * ak_record_enable - Enable recording.
 *
 * PRECONDITIONS:
 *   - state must be valid
 *
 * POSTCONDITIONS:
 *   - Recording is enabled
 *   - Start time is set to current time
 *
 * Parameters:
 *   state - Record state
 */
void ak_record_enable(ak_record_state_t *state);

/*
 * ak_record_disable - Disable recording.
 *
 * Stops recording new effects. Previously recorded effects are preserved.
 *
 * Parameters:
 *   state - Record state
 */
void ak_record_disable(ak_record_state_t *state);

/*
 * ak_record_is_enabled - Check if recording is enabled.
 *
 * Parameters:
 *   state - Record state (may be NULL)
 *
 * Returns:
 *   true if recording is enabled, false otherwise
 */
boolean ak_record_is_enabled(ak_record_state_t *state);

/* ============================================================
 * RECORDING EFFECTS
 * ============================================================ */

/*
 * ak_record_effect - Record a denied effect.
 *
 * Adds the effect to the record if not already present. If the effect
 * was already recorded, increments its count.
 *
 * PRECONDITIONS:
 *   - state must be valid and enabled
 *   - req must be valid effect request
 *
 * POSTCONDITIONS:
 *   - Effect is recorded (or count incremented)
 *   - unique_count may be incremented
 *   - total_count is incremented
 *
 * Parameters:
 *   state - Record state
 *   req   - Effect request to record
 *
 * Returns:
 *   0      - Success (new effect recorded)
 *   1      - Success (duplicate, count incremented)
 *   -EINVAL - Invalid parameters
 *   -ENOMEM - Memory allocation failed
 *   -ENOSPC - Maximum effects reached
 */
int ak_record_effect(ak_record_state_t *state, const ak_effect_req_t *req);

/* ============================================================
 * GENERATING SUGGESTIONS
 * ============================================================ */

/*
 * ak_record_get_suggestions - Generate complete policy from recorded effects.
 *
 * Produces a JSON policy document that would allow all recorded effects.
 * The output is formatted as a complete policy.json file.
 *
 * Output format (JSON):
 * {
 *   "version": "1.0",
 *   "generated_at": "2024-01-15T10:30:00Z",
 *   "effects_recorded": 42,
 *   "fs": {
 *     "allow": [
 *       {"path": "/app/data", "read": true},
 *       {"path": "/tmp/*", "read": true, "write": true}
 *     ]
 *   },
 *   "net": {
 *     "allow": [
 *       {"pattern": "ip:*:443", "connect": true},
 *       {"pattern": "dns:*.example.com", "resolve": true}
 *     ]
 *   },
 *   "tools": {
 *     "allow": [
 *       {"name": "http_get"},
 *       {"name": "shell_exec", "version": "1.0"}
 *     ]
 *   },
 *   "inference": {
 *     "allow": [
 *       {"model": "gpt-4"}
 *     ]
 *   }
 * }
 *
 * PRECONDITIONS:
 *   - state must be valid
 *   - out must be valid buffer with sufficient capacity
 *
 * POSTCONDITIONS:
 *   - out contains null-terminated JSON policy
 *   - Returns number of bytes written (excluding null terminator)
 *
 * Parameters:
 *   state    - Record state
 *   out      - Output buffer for JSON
 *   out_len  - Size of output buffer
 *
 * Returns:
 *   >= 0     - Number of bytes written
 *   -EINVAL  - Invalid parameters
 *   -ENOENT  - No effects recorded
 *   -ERANGE  - Buffer too small (partial output may be written)
 */
sysreturn ak_record_get_suggestions(ak_record_state_t *state, char *out,
                                    u64 out_len);

/*
 * ak_record_get_suggestions_toml - Generate TOML policy from recorded effects.
 *
 * Like ak_record_get_suggestions but outputs TOML format for ak.toml files.
 *
 * Parameters:
 *   state    - Record state
 *   out      - Output buffer for TOML
 *   out_len  - Size of output buffer
 *
 * Returns:
 *   >= 0     - Number of bytes written
 *   -EINVAL  - Invalid parameters
 *   -ENOENT  - No effects recorded
 *   -ERANGE  - Buffer too small
 */
sysreturn ak_record_get_suggestions_toml(ak_record_state_t *state, char *out,
                                         u64 out_len);

/* ============================================================
 * MANAGEMENT
 * ============================================================ */

/*
 * ak_record_clear - Clear all recorded effects.
 *
 * Removes all recorded effects and resets counters.
 *
 * POSTCONDITIONS:
 *   - All recorded effects are freed
 *   - unique_count and total_count are zero
 *   - Recording state (enabled/disabled) is preserved
 *
 * Parameters:
 *   state - Record state
 */
void ak_record_clear(ak_record_state_t *state);

/*
 * ak_record_count - Get number of unique recorded effects.
 *
 * Parameters:
 *   state - Record state (may be NULL)
 *
 * Returns:
 *   Number of unique effects, or 0 if state is NULL
 */
u32 ak_record_count(ak_record_state_t *state);

/*
 * ak_record_total_count - Get total effect count (including duplicates).
 *
 * Parameters:
 *   state - Record state (may be NULL)
 *
 * Returns:
 *   Total count, or 0 if state is NULL
 */
u64 ak_record_total_count(ak_record_state_t *state);

/* ============================================================
 * ITERATION
 * ============================================================ */

/*
 * Callback type for iterating over recorded effects.
 *
 * Parameters:
 *   effect - The recorded effect
 *   arg    - User-provided argument
 *
 * Returns:
 *   true  - Continue iteration
 *   false - Stop iteration
 */
typedef boolean (*ak_record_iter_fn)(const ak_recorded_effect_t *effect,
                                     void *arg);

/*
 * ak_record_foreach - Iterate over all recorded effects.
 *
 * Calls the provided function for each recorded effect.
 * Order is not guaranteed.
 *
 * Parameters:
 *   state - Record state
 *   fn    - Callback function
 *   arg   - User argument passed to callback
 *
 * Returns:
 *   Number of effects iterated
 */
u32 ak_record_foreach(ak_record_state_t *state, ak_record_iter_fn fn,
                      void *arg);

/* ============================================================
 * CONTEXT INTEGRATION
 * ============================================================ */

/*
 * ak_ctx_enable_record_mode - Enable record mode on a context.
 *
 * Initializes record state if needed and enables recording.
 * Also sets context mode to AK_MODE_RECORD.
 *
 * Parameters:
 *   ctx - AK context
 *   h   - Heap for allocations (or NULL to use context's heap)
 *
 * Returns:
 *   0       - Success
 *   -EINVAL - Invalid context
 *   -ENOMEM - Allocation failed
 */
int ak_ctx_enable_record_mode(ak_ctx_t *ctx, heap h);

/*
 * ak_ctx_disable_record_mode - Disable record mode on a context.
 *
 * Stops recording but preserves recorded effects for retrieval.
 * Sets context mode back to AK_MODE_SOFT.
 *
 * Parameters:
 *   ctx - AK context
 */
void ak_ctx_disable_record_mode(ak_ctx_t *ctx);

/*
 * ak_ctx_get_record_state - Get record state from context.
 *
 * Parameters:
 *   ctx - AK context (may be NULL)
 *
 * Returns:
 *   Record state, or NULL if not initialized
 */
ak_record_state_t *ak_ctx_get_record_state(ak_ctx_t *ctx);

#endif /* AK_RECORD_H */
