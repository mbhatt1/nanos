/*
 * Authority Kernel - Context Management Implementation
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * AGENT A OWNED: Per-thread context, routing modes, and boot capsule.
 *
 * This module implements the AK enforcement context with:
 *   - Thread-local storage for per-thread contexts
 *   - Routing mode management (OFF/SOFT/HARD)
 *   - Boot capsule for early boot permissions
 *   - Last denial tracking for actionable error messages
 *   - Monotonic trace ID generation
 *
 * Security Properties:
 *   - INV-DENY: Enforced after boot capsule drop
 *   - One-way boot capsule drop (cannot re-enable)
 *   - Sensitive data cleared on context destroy
 */

#include "ak_context.h"
#include "ak_compat.h"
#include "ak_assert.h"

/* ============================================================
 * THREAD-LOCAL STORAGE
 * ============================================================
 * Each thread has its own AK context pointer stored in TLS.
 * This allows concurrent threads to have independent enforcement state.
 */

static __thread ak_ctx_t *tls_current_ctx = NULL;

/* ============================================================
 * MODULE STATE
 * ============================================================
 * Global state for the context module.
 */

/* Module initialization flag */
static boolean context_module_initialized = false;

/* Default heap for context allocations */
static heap context_heap = NULL;

/* Default routing mode (configurable at build time) */
#ifndef AK_DEFAULT_MODE
#define AK_DEFAULT_MODE AK_MODE_SOFT
#endif

/* Context ID counter for trace ID generation */
static u64 context_id_counter = 0;

/* Module statistics */
static struct {
    u64 contexts_created;
    u64 contexts_destroyed;
    u64 contexts_active;
    u64 boot_capsules_dropped;
    u64 mode_changes;
    u64 trace_ids_generated;
    u64 denials_recorded;
} ctx_stats;

/* Magic value for context validation */
#define AK_CTX_MAGIC 0x414B4354  /* "AKCT" */

/* Internal context structure with magic for validation */
typedef struct ak_ctx_internal {
    u32 magic;                  /* Validation magic */
    ak_ctx_t ctx;               /* Public context */
    u64 context_id;             /* Unique ID for this context */
    heap alloc_heap;            /* Heap used for allocation */
} ak_ctx_internal_t;

/* ============================================================
 * INTERNAL HELPERS
 * ============================================================ */

/*
 * Get internal context structure from public context.
 */
static inline ak_ctx_internal_t *ctx_to_internal(ak_ctx_t *ctx)
{
    if (!ctx)
        return NULL;
    return container_of(ctx, ak_ctx_internal_t, ctx);
}

/*
 * Validate context magic.
 */
static inline boolean ctx_validate_magic(ak_ctx_internal_t *internal)
{
    return internal && internal->magic == AK_CTX_MAGIC;
}

/*
 * Get current timestamp in nanoseconds.
 */
static inline u64 get_timestamp_ns(void)
{
    /* Use monotonic clock for consistent timestamps */
    return nsec_from_timestamp(ak_now());
}

/* ============================================================
 * MODULE INITIALIZATION
 * ============================================================ */

int ak_context_module_init(heap h)
{
    /* Use atomic compare-and-swap to prevent race condition during init */
    if (!__sync_bool_compare_and_swap(&context_module_initialized, false, true)) {
        ak_warn("ak_context_module_init: already initialized");
        return 0;
    }

    if (!h || h == INVALID_ADDRESS) {
        ak_error("ak_context_module_init: invalid heap");
        /* Reset the flag since initialization failed */
        context_module_initialized = false;
        return -EINVAL;
    }

    context_heap = h;
    context_id_counter = 0;

    /* Clear statistics */
    ak_memzero(&ctx_stats, sizeof(ctx_stats));

    ak_debug("ak_context_module_init: initialized with default mode %d",
             AK_DEFAULT_MODE);

    return 0;
}

void ak_context_module_shutdown(void)
{
    if (!context_module_initialized) {
        return;
    }

    /* Clear TLS for current thread */
    tls_current_ctx = NULL;

    context_module_initialized = false;
    context_heap = NULL;

    ak_debug("ak_context_module_shutdown: shutdown complete, "
             "created=%llu destroyed=%llu",
             ctx_stats.contexts_created, ctx_stats.contexts_destroyed);
}

/* ============================================================
 * CONTEXT LIFECYCLE
 * ============================================================ */

ak_ctx_t *ak_ctx_create(heap h, ak_agent_context_t *agent)
{
    heap alloc_heap;
    ak_ctx_internal_t *internal;

    /* Use provided heap or module default */
    alloc_heap = h ? h : context_heap;
    if (!alloc_heap || alloc_heap == INVALID_ADDRESS) {
        ak_error("ak_ctx_create: no heap available");
        return NULL;
    }

    /* Allocate internal structure */
    internal = allocate_zero(alloc_heap, sizeof(ak_ctx_internal_t));
    if (!internal || internal == INVALID_ADDRESS) {
        ak_error("ak_ctx_create: allocation failed");
        return NULL;
    }

    /* Initialize magic and metadata */
    internal->magic = AK_CTX_MAGIC;
    internal->alloc_heap = alloc_heap;
    internal->context_id = __sync_fetch_and_add(&context_id_counter, 1);

    /* Initialize public context */
    ak_ctx_t *ctx = &internal->ctx;
    ctx->agent = agent;
    ctx->mode = AK_DEFAULT_MODE;
    ctx->boot_capsule_active = true;    /* Active until policy load */
    ctx->boot_capsule_dropped = false;
    ctx->trace_counter = 0;
    ctx->policy = NULL;
    ctx->record = NULL;

    /* Clear last_deny */
    ak_memzero(&ctx->last_deny, sizeof(ak_last_deny_t));

    /* Update statistics */
    __sync_fetch_and_add(&ctx_stats.contexts_created, 1);
    __sync_fetch_and_add(&ctx_stats.contexts_active, 1);

    ak_debug("ak_ctx_create: created context %p (id=%llu, agent=%p)",
             ctx, internal->context_id, agent);

    return ctx;
}

void ak_ctx_destroy(heap h, ak_ctx_t *ctx)
{
    ak_ctx_internal_t *internal;
    heap free_heap;

    if (!ctx)
        return;

    internal = ctx_to_internal(ctx);
    if (!ctx_validate_magic(internal)) {
        ak_error("ak_ctx_destroy: invalid context %p", ctx);
        return;
    }

    /*
     * WARNING: This only clears the TLS pointer for the CURRENT thread.
     * Other threads may still have dangling pointers to this context in
     * their TLS. Callers must ensure no other thread references this context
     * before destroying it. The magic invalidation below provides partial
     * protection against use-after-free by failing validation checks.
     */
    if (tls_current_ctx == ctx) {
        tls_current_ctx = NULL;
    }

    /* Save the heap before zeroing the structure */
    free_heap = internal->alloc_heap;

    /* Security: Clear entire internal structure including sensitive data.
     * This ensures all context data is wiped before deallocation. */
    ak_memzero(internal, sizeof(ak_ctx_internal_t));

    /* The h parameter is ignored to prevent heap mismatch bugs. */
    (void)h;  /* Suppress unused parameter warning */
    if (free_heap && free_heap != INVALID_ADDRESS) {
        deallocate(free_heap, internal, sizeof(ak_ctx_internal_t));
    }

    /* Update statistics */
    __sync_fetch_and_add(&ctx_stats.contexts_destroyed, 1);
    __sync_fetch_and_sub(&ctx_stats.contexts_active, 1);

    ak_debug("ak_ctx_destroy: destroyed context %p", ctx);
}

/* ============================================================
 * THREAD-LOCAL CONTEXT ACCESS
 * ============================================================ */

ak_ctx_t *ak_ctx_current(void)
{
    return tls_current_ctx;
}

void ak_ctx_set_current(ak_ctx_t *ctx)
{
    ak_ctx_internal_t *internal;

    /* Allow setting to NULL to clear */
    if (!ctx) {
        tls_current_ctx = NULL;
        ak_debug("ak_ctx_set_current: cleared TLS context");
        return;
    }

    /* Validate context */
    internal = ctx_to_internal(ctx);
    if (!ctx_validate_magic(internal)) {
        ak_error("ak_ctx_set_current: invalid context %p", ctx);
        return;
    }

    tls_current_ctx = ctx;
    ak_debug("ak_ctx_set_current: set TLS context to %p (id=%llu)",
             ctx, internal->context_id);
}

/* ============================================================
 * ROUTING MODE MANAGEMENT
 * ============================================================ */

void ak_ctx_set_mode(ak_ctx_t *ctx, ak_mode_t mode)
{
    ak_ctx_internal_t *internal;
    ak_mode_t old_mode;

    if (!ctx)
        return;

    internal = ctx_to_internal(ctx);
    if (!ctx_validate_magic(internal)) {
        ak_error("ak_ctx_set_mode: invalid context %p", ctx);
        return;
    }

    /* Validate mode value */
    if (mode > AK_MODE_HARD) {
        ak_error("ak_ctx_set_mode: invalid mode %d", mode);
        return;
    }

    /* Security: AK_MODE_OFF only allowed if explicitly enabled */
#ifndef CONFIG_AK_ALLOW_MODE_OFF
    if (mode == AK_MODE_OFF) {
        ak_warn("ak_ctx_set_mode: AK_MODE_OFF not allowed "
                "(CONFIG_AK_ALLOW_MODE_OFF not defined)");
        return;
    }
#endif

    old_mode = ctx->mode;
    ctx->mode = mode;

    /* Update statistics */
    if (old_mode != mode) {
        __sync_fetch_and_add(&ctx_stats.mode_changes, 1);
    }

    ak_debug("ak_ctx_set_mode: context %p mode %d -> %d",
             ctx, old_mode, mode);
}

ak_mode_t ak_ctx_get_mode(ak_ctx_t *ctx)
{
    ak_ctx_internal_t *internal;

    if (!ctx)
        return AK_DEFAULT_MODE;

    internal = ctx_to_internal(ctx);
    if (!ctx_validate_magic(internal)) {
        ak_error("ak_ctx_get_mode: invalid context %p", ctx);
        return AK_DEFAULT_MODE;
    }

    return ctx->mode;
}

ak_mode_t ak_ctx_default_mode(void)
{
    return AK_DEFAULT_MODE;
}

/* ============================================================
 * BOOT CAPSULE MANAGEMENT
 * ============================================================ */

boolean ak_ctx_boot_capsule_active(ak_ctx_t *ctx)
{
    ak_ctx_internal_t *internal;

    if (!ctx)
        return false;

    internal = ctx_to_internal(ctx);
    if (!ctx_validate_magic(internal)) {
        ak_error("ak_ctx_boot_capsule_active: invalid context %p", ctx);
        return false;
    }

    return ctx->boot_capsule_active;
}

void ak_ctx_drop_boot_capsule(ak_ctx_t *ctx)
{
    ak_ctx_internal_t *internal;

    if (!ctx)
        return;

    internal = ctx_to_internal(ctx);
    if (!ctx_validate_magic(internal)) {
        ak_error("ak_ctx_drop_boot_capsule: invalid context %p", ctx);
        return;
    }

    /* Check if already dropped */
    if (ctx->boot_capsule_dropped) {
        ak_debug("ak_ctx_drop_boot_capsule: already dropped for context %p",
                 ctx);
        return;
    }

    /* One-way transition: deactivate boot capsule */
    ctx->boot_capsule_active = false;
    ctx->boot_capsule_dropped = true;

    /* Update statistics */
    __sync_fetch_and_add(&ctx_stats.boot_capsules_dropped, 1);

    ak_debug("ak_ctx_drop_boot_capsule: context %p transitioned to "
             "deny-by-default (INV-DENY active)", ctx);
}

boolean ak_ctx_boot_capsule_was_dropped(ak_ctx_t *ctx)
{
    ak_ctx_internal_t *internal;

    if (!ctx)
        return false;

    internal = ctx_to_internal(ctx);
    if (!ctx_validate_magic(internal)) {
        return false;
    }

    return ctx->boot_capsule_dropped;
}

/* ============================================================
 * TRACE ID GENERATION
 * ============================================================ */

u64 ak_trace_id_generate(ak_ctx_t *ctx)
{
    ak_ctx_internal_t *internal;
    u64 counter;
    u64 trace_id;

    if (!ctx)
        return 0;

    internal = ctx_to_internal(ctx);
    if (!ctx_validate_magic(internal)) {
        ak_error("ak_trace_id_generate: invalid context %p", ctx);
        return 0;
    }

    /*
     * Trace ID format:
     *   Bits 63-48: Context ID (16 bits)
     *   Bits 47-0:  Monotonic counter (48 bits)
     *
     * This provides ~281 trillion unique IDs per context
     * and allows identification of which context generated the ID.
     */
    counter = __sync_fetch_and_add(&ctx->trace_counter, 1);
    trace_id = ((internal->context_id & 0xFFFF) << 48) | (counter & 0xFFFFFFFFFFFF);

    /* Update statistics */
    __sync_fetch_and_add(&ctx_stats.trace_ids_generated, 1);

    return trace_id;
}

/* ============================================================
 * LAST DENIAL MANAGEMENT
 * ============================================================ */

void ak_ctx_record_deny(ak_ctx_t *ctx,
                        const ak_effect_req_t *req,
                        const ak_decision_t *decision)
{
    ak_ctx_internal_t *internal;

    if (!ctx || !req || !decision)
        return;

    internal = ctx_to_internal(ctx);
    if (!ctx_validate_magic(internal)) {
        ak_error("ak_ctx_record_deny: invalid context %p", ctx);
        return;
    }

    /* Populate last_deny from request and decision */
    ak_last_deny_t *deny = &ctx->last_deny;

    deny->op = req->op;
    deny->trace_id = req->trace_id;
    deny->errno_equiv = decision->errno_equiv;
    deny->reason = decision->reason_code;
    deny->timestamp_ns = get_timestamp_ns();

    /* Copy bounded strings with NULL checks */
    if (req->target) {
        runtime_strncpy(deny->target, req->target, AK_MAX_TARGET - 1);
        deny->target[AK_MAX_TARGET - 1] = '\0';
    } else {
        deny->target[0] = '\0';
    }

    if (decision->missing_cap) {
        runtime_strncpy(deny->missing_cap, decision->missing_cap,
                        AK_MAX_CAPSTR - 1);
        deny->missing_cap[AK_MAX_CAPSTR - 1] = '\0';
    } else {
        deny->missing_cap[0] = '\0';
    }

    if (decision->suggested_snippet) {
        runtime_strncpy(deny->suggested_snippet, decision->suggested_snippet,
                        AK_MAX_SUGGEST - 1);
        deny->suggested_snippet[AK_MAX_SUGGEST - 1] = '\0';
    } else {
        deny->suggested_snippet[0] = '\0';
    }

    /* Update statistics */
    __sync_fetch_and_add(&ctx_stats.denials_recorded, 1);

    ak_debug("ak_ctx_record_deny: recorded denial for op=0x%x "
             "target=\"%.64s\" trace_id=%llu",
             deny->op, deny->target, deny->trace_id);
}

const ak_last_deny_t *ak_ctx_get_last_deny(ak_ctx_t *ctx)
{
    ak_ctx_internal_t *internal;

    if (!ctx)
        return NULL;

    internal = ctx_to_internal(ctx);
    if (!ctx_validate_magic(internal)) {
        ak_error("ak_ctx_get_last_deny: invalid context %p", ctx);
        return NULL;
    }

    /* Return NULL if no denial has been recorded */
    if (ctx->last_deny.timestamp_ns == 0)
        return NULL;

    return &ctx->last_deny;
}

void ak_ctx_clear_last_deny(ak_ctx_t *ctx)
{
    ak_ctx_internal_t *internal;

    if (!ctx)
        return;

    internal = ctx_to_internal(ctx);
    if (!ctx_validate_magic(internal)) {
        ak_error("ak_ctx_clear_last_deny: invalid context %p", ctx);
        return;
    }

    ak_memzero(&ctx->last_deny, sizeof(ak_last_deny_t));

    ak_debug("ak_ctx_clear_last_deny: cleared last denial for context %p",
             ctx);
}

/* ============================================================
 * POLICY ACCESS
 * ============================================================ */

void ak_ctx_set_policy(ak_ctx_t *ctx, struct ak_policy_v2 *policy)
{
    ak_ctx_internal_t *internal;

    if (!ctx)
        return;

    internal = ctx_to_internal(ctx);
    if (!ctx_validate_magic(internal)) {
        ak_error("ak_ctx_set_policy: invalid context %p", ctx);
        return;
    }

    ctx->policy = policy;

    ak_debug("ak_ctx_set_policy: context %p policy set to %p",
             ctx, policy);
}

struct ak_policy_v2 *ak_ctx_get_policy(ak_ctx_t *ctx)
{
    ak_ctx_internal_t *internal;

    if (!ctx)
        return NULL;

    internal = ctx_to_internal(ctx);
    if (!ctx_validate_magic(internal)) {
        ak_error("ak_ctx_get_policy: invalid context %p", ctx);
        return NULL;
    }

    return ctx->policy;
}

/* ============================================================
 * STATISTICS
 * ============================================================ */

void ak_context_get_stats(ak_context_stats_t *stats)
{
    if (!stats)
        return;

    /* Copy current statistics */
    stats->contexts_created = ctx_stats.contexts_created;
    stats->contexts_destroyed = ctx_stats.contexts_destroyed;
    stats->contexts_active = ctx_stats.contexts_active;
    stats->boot_capsules_dropped = ctx_stats.boot_capsules_dropped;
    stats->mode_changes = ctx_stats.mode_changes;
    stats->trace_ids_generated = ctx_stats.trace_ids_generated;
    stats->denials_recorded = ctx_stats.denials_recorded;
}

/* ============================================================
 * VALIDATION AND HELPERS
 * ============================================================ */

boolean ak_ctx_is_valid(ak_ctx_t *ctx)
{
    ak_ctx_internal_t *internal;

    if (!ctx)
        return false;

    internal = ctx_to_internal(ctx);
    return ctx_validate_magic(internal);
}

ak_agent_context_t *ak_ctx_get_agent(ak_ctx_t *ctx)
{
    ak_ctx_internal_t *internal;

    if (!ctx)
        return NULL;

    internal = ctx_to_internal(ctx);
    if (!ctx_validate_magic(internal))
        return NULL;

    return ctx->agent;
}

void ak_ctx_set_agent(ak_ctx_t *ctx, ak_agent_context_t *agent)
{
    ak_ctx_internal_t *internal;

    if (!ctx)
        return;

    internal = ctx_to_internal(ctx);
    if (!ctx_validate_magic(internal)) {
        ak_error("ak_ctx_set_agent: invalid context %p", ctx);
        return;
    }

    ctx->agent = agent;

    ak_debug("ak_ctx_set_agent: context %p agent set to %p", ctx, agent);
}
