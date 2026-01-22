/*
 * Authority Kernel - Context Management
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * AGENT A OWNED: Per-thread context, routing modes, and boot capsule.
 *
 * This module provides the per-thread AK enforcement context that tracks:
 *   - Current routing mode (OFF/SOFT/HARD)
 *   - Boot capsule state for early boot permissions
 *   - Last denial information for AK_SYS_LAST_ERROR
 *   - Link to agent context and policy
 *   - Trace ID generation for correlation
 *
 * Thread-Local Storage (TLS):
 *   Each thread has its own ak_ctx_t accessible via ak_ctx_current().
 *   This allows concurrent threads to have independent enforcement state.
 *
 * Boot Capsule:
 *   During early boot (before policy load), the boot capsule allows
 *   essential operations. Once policy is loaded, ak_ctx_drop_boot_capsule()
 *   transitions to deny-by-default enforcement.
 *
 * Routing Modes:
 *   - AK_MODE_OFF:  Legacy minimal debug mode (no enforcement)
 *   - AK_MODE_SOFT: POSIX syscalls routed through AK, enforced (DEFAULT)
 *   - AK_MODE_HARD: Raw effectful syscalls denied, only AK API allowed
 */

#ifndef AK_CONTEXT_H
#define AK_CONTEXT_H

#include "ak_effects.h"

/* ============================================================
 * CONTEXT MODULE INITIALIZATION
 * ============================================================ */

/*
 * Initialize the context subsystem.
 *
 * Must be called once during AK initialization, before any contexts
 * are created. Sets up the TLS infrastructure and default mode.
 *
 * Parameters:
 *   h - Heap for allocations
 *
 * Returns:
 *   0 on success, negative errno on failure
 */
int ak_context_module_init(heap h);

/*
 * Shutdown the context subsystem.
 *
 * Cleans up any global state. Should be called during AK shutdown.
 */
void ak_context_module_shutdown(void);

/* ============================================================
 * CONTEXT LIFECYCLE
 * ============================================================ */

/*
 * Create a new AK enforcement context.
 *
 * Allocates and initializes a new context structure. The context is
 * NOT automatically set as the current thread's context; use
 * ak_ctx_set_current() for that.
 *
 * Parameters:
 *   h     - Heap for allocation
 *   agent - Existing agent context to link to (may be NULL for init)
 *
 * Returns:
 *   New context on success, NULL on failure
 *
 * Initial state:
 *   - mode = AK_MODE_SOFT (default deny-by-default)
 *   - boot_capsule_active = true (allows early boot operations)
 *   - last_deny cleared
 *   - trace_counter = 0
 */
ak_ctx_t *ak_ctx_create(heap h, ak_agent_context_t *agent);

/*
 * Destroy an AK enforcement context.
 *
 * Frees all resources associated with the context. If this is the
 * current thread's context, it is cleared first.
 *
 * Parameters:
 *   h   - Heap used for allocation
 *   ctx - Context to destroy
 *
 * SECURITY: Clears sensitive data (last_deny, policy pointer) before free.
 */
void ak_ctx_destroy(heap h, ak_ctx_t *ctx);

/* ============================================================
 * THREAD-LOCAL CONTEXT ACCESS
 * ============================================================ */

/*
 * Get the current thread's AK context.
 *
 * Uses thread-local storage to return the context bound to this thread.
 * Returns NULL if no context has been set for this thread.
 *
 * Returns:
 *   Current thread's context, or NULL if not set
 *
 * Thread safety: Safe to call from any thread; returns that thread's context.
 */
ak_ctx_t *ak_ctx_current(void);

/*
 * Set the current thread's AK context.
 *
 * Binds a context to the calling thread. Subsequent calls to
 * ak_ctx_current() from this thread will return this context.
 *
 * Parameters:
 *   ctx - Context to set (may be NULL to clear)
 *
 * Thread safety: Only affects the calling thread.
 */
void ak_ctx_set_current(ak_ctx_t *ctx);

/* ============================================================
 * ROUTING MODE MANAGEMENT
 * ============================================================ */

/*
 * Set the routing mode for a context.
 *
 * Changes how POSIX syscalls are handled:
 *   - AK_MODE_OFF:  No routing, syscalls execute directly (debug only)
 *   - AK_MODE_SOFT: Syscalls routed through AK for policy check
 *   - AK_MODE_HARD: Raw syscalls denied, must use AK API
 *
 * Parameters:
 *   ctx  - Context to modify
 *   mode - New routing mode
 *
 * SECURITY: Transitioning to a less restrictive mode (e.g., HARD -> SOFT)
 *           may be restricted by policy. OFF mode is only available if
 *           CONFIG_AK_ALLOW_MODE_OFF is defined.
 */
void ak_ctx_set_mode(ak_ctx_t *ctx, ak_mode_t mode);

/*
 * Get the current routing mode for a context.
 *
 * Parameters:
 *   ctx - Context to query
 *
 * Returns:
 *   Current routing mode, or AK_MODE_SOFT if ctx is NULL
 */
ak_mode_t ak_ctx_get_mode(ak_ctx_t *ctx);

/*
 * Get the default routing mode.
 *
 * Returns the mode used for new contexts and when no context is set.
 * Configurable via AK_DEFAULT_MODE build option.
 *
 * Returns:
 *   Default routing mode (typically AK_MODE_SOFT)
 */
ak_mode_t ak_ctx_default_mode(void);

/* ============================================================
 * BOOT CAPSULE MANAGEMENT
 * ============================================================ */

/*
 * Check if boot capsule is active for a context.
 *
 * The boot capsule provides elevated permissions during early boot,
 * before policy is loaded. This allows:
 *   - Reading configuration files
 *   - Loading policy from initrd
 *   - Initializing subsystems
 *
 * Once policy is loaded, ak_ctx_drop_boot_capsule() should be called
 * to transition to deny-by-default enforcement.
 *
 * Parameters:
 *   ctx - Context to check
 *
 * Returns:
 *   true if boot capsule is active, false otherwise
 *   Returns false if ctx is NULL
 */
boolean ak_ctx_boot_capsule_active(ak_ctx_t *ctx);

/*
 * Drop the boot capsule for a context.
 *
 * Transitions from boot-time elevated permissions to full deny-by-default
 * enforcement. This should be called after policy is successfully loaded.
 *
 * Parameters:
 *   ctx - Context to update
 *
 * SECURITY: This is a one-way transition. Once dropped, the boot capsule
 *           cannot be re-enabled. The boot_capsule_dropped flag is set
 *           to prevent re-activation.
 *
 * Invariant: INV-DENY is active after this call.
 */
void ak_ctx_drop_boot_capsule(ak_ctx_t *ctx);

/*
 * Check if boot capsule was ever dropped.
 *
 * Parameters:
 *   ctx - Context to check
 *
 * Returns:
 *   true if boot capsule was dropped (deny-by-default active)
 *   false if still in boot mode or ctx is NULL
 */
boolean ak_ctx_boot_capsule_was_dropped(ak_ctx_t *ctx);

/* ============================================================
 * TRACE ID GENERATION
 * ============================================================ */

/*
 * Generate a new trace ID for correlation.
 *
 * Trace IDs are monotonically increasing 64-bit values unique within
 * a context. They are used to correlate effect requests with audit
 * log entries and denial information.
 *
 * Format: (context_id << 48) | counter
 *   - High 16 bits: context identifier
 *   - Low 48 bits: monotonic counter
 *
 * Parameters:
 *   ctx - Context for which to generate trace ID
 *
 * Returns:
 *   New unique trace ID
 *   Returns 0 if ctx is NULL
 *
 * Thread safety: Uses atomic increment; safe for concurrent use.
 */
u64 ak_trace_id_generate(ak_ctx_t *ctx);

/* ============================================================
 * LAST DENIAL ACCESS
 * ============================================================ */

/*
 * Record a denial in the context.
 *
 * Called by ak_authorize_and_execute() when an effect is denied.
 * Stores the denial information for later retrieval via AK_SYS_LAST_ERROR.
 *
 * Parameters:
 *   ctx      - Context to update
 *   req      - The denied effect request
 *   decision - The denial decision
 */
void ak_ctx_record_deny(ak_ctx_t *ctx, const ak_effect_req_t *req,
                        const ak_decision_t *decision);

/*
 * Get the last denial for a context.
 *
 * Returns a pointer to the stored last denial information.
 * This is used by AK_SYS_LAST_ERROR to retrieve actionable denial info.
 *
 * Parameters:
 *   ctx - Context to query
 *
 * Returns:
 *   Pointer to last_deny structure, or NULL if ctx is NULL
 */
const ak_last_deny_t *ak_ctx_get_last_deny(ak_ctx_t *ctx);

/*
 * Clear the last denial for a context.
 *
 * Resets the last_deny structure. Called after the denial has been
 * retrieved or when starting a new operation sequence.
 *
 * Parameters:
 *   ctx - Context to clear
 */
void ak_ctx_clear_last_deny(ak_ctx_t *ctx);

/* ============================================================
 * POLICY ACCESS
 * ============================================================ */

/*
 * Set the policy for a context.
 *
 * Associates a V2 deny-by-default policy with the context.
 * The policy is used by ak_authorize_and_execute() for authorization.
 *
 * Parameters:
 *   ctx    - Context to update
 *   policy - Policy to associate (ownership transferred to context)
 *
 * SECURITY: Setting a new policy does not re-enable the boot capsule.
 */
void ak_ctx_set_policy(ak_ctx_t *ctx, struct ak_policy_v2 *policy);

/*
 * Get the policy for a context.
 *
 * Parameters:
 *   ctx - Context to query
 *
 * Returns:
 *   Associated policy, or NULL if none set or ctx is NULL
 */
struct ak_policy_v2 *ak_ctx_get_policy(ak_ctx_t *ctx);

/* ============================================================
 * CONTEXT STATISTICS
 * ============================================================ */

/*
 * Statistics for context operations.
 */
typedef struct ak_context_stats {
  u64 contexts_created;      /* Total contexts created */
  u64 contexts_destroyed;    /* Total contexts destroyed */
  u64 contexts_active;       /* Currently active contexts */
  u64 boot_capsules_dropped; /* Boot capsules dropped */
  u64 mode_changes;          /* Mode change operations */
  u64 trace_ids_generated;   /* Total trace IDs generated */
  u64 denials_recorded;      /* Denials recorded */
} ak_context_stats_t;

/*
 * Get context module statistics.
 *
 * Parameters:
 *   stats - Output structure for statistics
 */
void ak_context_get_stats(ak_context_stats_t *stats);

/* ============================================================
 * INTERNAL HELPERS (for other AK modules)
 * ============================================================ */

/*
 * Check if a context is valid.
 *
 * Validates that the context pointer is non-NULL and appears to be
 * a legitimate context structure.
 *
 * Parameters:
 *   ctx - Context to validate
 *
 * Returns:
 *   true if context appears valid, false otherwise
 */
boolean ak_ctx_is_valid(ak_ctx_t *ctx);

/*
 * Get the agent context linked to an AK context.
 *
 * Parameters:
 *   ctx - AK context
 *
 * Returns:
 *   Linked agent context, or NULL
 */
ak_agent_context_t *ak_ctx_get_agent(ak_ctx_t *ctx);

/*
 * Set the agent context linked to an AK context.
 *
 * Parameters:
 *   ctx   - AK context to update
 *   agent - Agent context to link
 */
void ak_ctx_set_agent(ak_ctx_t *ctx, ak_agent_context_t *agent);

#endif /* AK_CONTEXT_H */
