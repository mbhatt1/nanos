/*
 * Authority Kernel - Process Model Implementation
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Implements process spawning with capability inheritance.
 *
 * SECURITY CRITICAL:
 *   - Capability delegation is monotonically attenuating
 *   - All spawns are audited
 *   - Revocation is immediate and cascading
 */

#include "ak_process.h"
#include "ak_capability.h"
#include "ak_compat.h"
#include "ak_audit.h"

/* ============================================================
 * MODULE STATE
 * ============================================================ */

static struct {
    heap h;
    boolean initialized;

    /* Process registry (hash table by PID) */
    ak_process_entry_t *entries[AK_PROCESS_MAX_ENTRIES];
    u32 entry_count;

    /* Free list for recycled entries */
    ak_process_entry_t *free_list;

    /* Fail-closed policy for processes without explicit policy */
    ak_policy_v2_t *fail_closed_policy;

    /* Statistics */
    ak_process_stats_t stats;

    /* Lock for concurrent access (simple spinlock simulation) */
    volatile boolean lock;
} ak_process_state;

/* ============================================================
 * INTERNAL HELPERS
 * ============================================================ */

/* Simple hash function for PID -> bucket */
static u32 pid_hash(u64 pid)
{
    return (u32)((pid * 2654435761ULL) % AK_PROCESS_MAX_ENTRIES);
}

/* Acquire module lock (simple spinlock for kernel) */
static void process_lock(void)
{
    while (__sync_lock_test_and_set(&ak_process_state.lock, 1)) {
        /* Spin - in real kernel, would yield */
    }
}

/* Release module lock */
static void process_unlock(void)
{
    __sync_lock_release(&ak_process_state.lock);
}

/* Allocate a new process entry */
static ak_process_entry_t *alloc_entry(void)
{
    ak_process_entry_t *entry;

    /* Try free list first */
    if (ak_process_state.free_list) {
        entry = ak_process_state.free_list;
        ak_process_state.free_list = entry->next;
        ak_memzero(entry, sizeof(*entry));
        return entry;
    }

    /* Allocate new entry */
    entry = ak_alloc_zero(ak_process_state.h, ak_process_entry_t);
    if (ak_is_invalid_address(entry))
        return NULL;

    return entry;
}

/* Return entry to free list */
static void free_entry(ak_process_entry_t *entry)
{
    if (!entry)
        return;

    /* Clear sensitive data */
    ak_memzero(entry->run_id, sizeof(entry->run_id));

    /* Add to free list */
    entry->next = ak_process_state.free_list;
    ak_process_state.free_list = entry;
}

/* Allocate delegated cap entry */
static ak_delegated_cap_t *alloc_delegated_cap(void)
{
    ak_delegated_cap_t *dcap = ak_alloc_zero(ak_process_state.h,
                                              ak_delegated_cap_t);
    if (ak_is_invalid_address(dcap))
        return NULL;
    return dcap;
}

/* Free delegated cap entry */
static void free_delegated_cap(ak_delegated_cap_t *dcap)
{
    if (!dcap)
        return;

    /* Note: We don't destroy the capability itself - it may be shared */
    deallocate(ak_process_state.h, dcap, sizeof(ak_delegated_cap_t));
}

/* Generate a new run ID */
static void generate_run_id(u8 *run_id)
{
    ak_generate_token_id(run_id);
}

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

void ak_process_init(heap h)
{
    if (ak_process_state.initialized)
        return;

    ak_process_state.h = h;

    /* Clear hash table */
    ak_memzero(ak_process_state.entries, sizeof(ak_process_state.entries));
    ak_process_state.entry_count = 0;
    ak_process_state.free_list = NULL;

    /* Create fail-closed policy */
    ak_process_state.fail_closed_policy = ak_policy_v2_bootstrap(h);

    /* Clear statistics */
    ak_memzero(&ak_process_state.stats, sizeof(ak_process_state.stats));

    ak_process_state.lock = 0;
    ak_process_state.initialized = true;

    ak_debug("ak_process: initialized");
}

void ak_process_shutdown(void)
{
    if (!ak_process_state.initialized)
        return;

    process_lock();

    /* Revoke all capabilities and clean up entries */
    for (u32 i = 0; i < AK_PROCESS_MAX_ENTRIES; i++) {
        ak_process_entry_t *entry = ak_process_state.entries[i];
        while (entry) {
            ak_process_entry_t *next = entry->next;

            /* Revoke all caps */
            ak_delegated_cap_t *dcap = entry->caps;
            while (dcap) {
                ak_delegated_cap_t *dcap_next = dcap->next;
                if (dcap->cap && !dcap->revoked) {
                    ak_revocation_add(dcap->cap->tid, "process shutdown");
                }
                free_delegated_cap(dcap);
                dcap = dcap_next;
            }

            /* Free policy if owned */
            if (entry->policy_owned && entry->policy) {
                ak_policy_v2_destroy(entry->policy);
            }

            deallocate(ak_process_state.h, entry, sizeof(ak_process_entry_t));
            entry = next;
        }
        ak_process_state.entries[i] = NULL;
    }

    /* Clean up free list */
    ak_process_entry_t *free_entry_ptr = ak_process_state.free_list;
    while (free_entry_ptr) {
        ak_process_entry_t *next = free_entry_ptr->next;
        deallocate(ak_process_state.h, free_entry_ptr, sizeof(ak_process_entry_t));
        free_entry_ptr = next;
    }
    ak_process_state.free_list = NULL;

    /* Destroy fail-closed policy */
    if (ak_process_state.fail_closed_policy) {
        ak_policy_v2_destroy(ak_process_state.fail_closed_policy);
        ak_process_state.fail_closed_policy = NULL;
    }

    ak_process_state.initialized = false;

    process_unlock();

    ak_debug("ak_process: shutdown");
}

/* ============================================================
 * PROCESS REGISTRATION
 * ============================================================ */

ak_process_entry_t *ak_process_register(
    u64 pid,
    u64 parent_pid,
    ak_policy_v2_t *policy,
    u32 flags)
{
    if (!ak_process_state.initialized)
        return NULL;

    if (pid == 0)
        return NULL;

    process_lock();

    /* Check if already registered */
    u32 bucket = pid_hash(pid);
    ak_process_entry_t *existing = ak_process_state.entries[bucket];
    while (existing) {
        if (existing->pid == pid) {
            process_unlock();
            ak_warn("ak_process: pid %lu already registered", pid);
            return NULL;
        }
        existing = existing->next;
    }

    /* Allocate entry */
    ak_process_entry_t *entry = alloc_entry();
    if (!entry) {
        process_unlock();
        ak_error("ak_process: failed to allocate entry for pid %lu", pid);
        return NULL;
    }

    /* Initialize entry */
    entry->pid = pid;
    entry->parent_pid = parent_pid;
    entry->state = AK_PROC_STATE_RUNNING;
    entry->spawn_flags = flags;
    entry->sandboxed = (flags & AK_SPAWN_FLAG_SANDBOX) != 0;
    entry->spawn_time_ms = ak_now_ms();

    /* Generate run ID */
    generate_run_id(entry->run_id);

    /* Copy parent's run_id if available */
    if (parent_pid > 0) {
        ak_process_entry_t *parent = ak_process_find(parent_pid);
        if (parent) {
            runtime_memcpy(entry->parent_run_id, parent->run_id,
                          AK_TOKEN_ID_SIZE);
        }
    }

    /* Set policy */
    if (policy) {
        entry->policy = policy;
        entry->policy_owned = false;
    } else if ((flags & AK_SPAWN_FLAG_INHERIT_POLICY) && parent_pid > 0) {
        /* Inherit parent's policy */
        ak_process_entry_t *parent = ak_process_find(parent_pid);
        if (parent && parent->policy) {
            entry->policy = parent->policy;
            entry->policy_owned = false;
        } else {
            entry->policy = ak_process_state.fail_closed_policy;
            entry->policy_owned = false;
        }
    } else {
        entry->policy = ak_process_state.fail_closed_policy;
        entry->policy_owned = false;
    }

    /* Insert into hash table */
    entry->next = ak_process_state.entries[bucket];
    ak_process_state.entries[bucket] = entry;
    ak_process_state.entry_count++;
    ak_process_state.stats.active_processes++;

    process_unlock();

    ak_debug("ak_process: registered pid=%lu parent=%lu flags=0x%x",
             pid, parent_pid, flags);

    return entry;
}

void ak_process_unregister(u64 pid, int exit_code, int exit_signal)
{
    if (!ak_process_state.initialized)
        return;

    process_lock();

    /* Find and remove entry */
    u32 bucket = pid_hash(pid);
    ak_process_entry_t *prev = NULL;
    ak_process_entry_t *entry = ak_process_state.entries[bucket];

    while (entry) {
        if (entry->pid == pid) {
            /* Found it */
            entry->state = AK_PROC_STATE_EXITED;
            entry->exit_code = exit_code;
            entry->exit_signal = exit_signal;
            entry->exit_time_ms = ak_now_ms();

            /* Revoke all delegated capabilities */
            ak_delegated_cap_t *dcap = entry->caps;
            while (dcap) {
                ak_delegated_cap_t *next = dcap->next;
                if (dcap->cap && !dcap->revoked) {
                    ak_revocation_add(dcap->cap->tid, "process exit");
                    dcap->revoked = true;
                    ak_process_state.stats.total_revocations++;
                    ak_process_state.stats.active_caps--;
                }
                free_delegated_cap(dcap);
                dcap = next;
            }
            entry->caps = NULL;
            entry->cap_count = 0;

            /* Remove from hash chain */
            if (prev) {
                prev->next = entry->next;
            } else {
                ak_process_state.entries[bucket] = entry->next;
            }

            /* Free policy if owned */
            if (entry->policy_owned && entry->policy) {
                ak_policy_v2_destroy(entry->policy);
            }

            /* Return to free list */
            free_entry(entry);
            ak_process_state.entry_count--;
            ak_process_state.stats.active_processes--;

            process_unlock();

            ak_debug("ak_process: unregistered pid=%lu exit=%d sig=%d",
                     pid, exit_code, exit_signal);
            return;
        }

        prev = entry;
        entry = entry->next;
    }

    process_unlock();
    ak_warn("ak_process: pid %lu not found for unregister", pid);
}

ak_process_entry_t *ak_process_find(u64 pid)
{
    if (!ak_process_state.initialized || pid == 0)
        return NULL;

    u32 bucket = pid_hash(pid);
    ak_process_entry_t *entry = ak_process_state.entries[bucket];

    while (entry) {
        if (entry->pid == pid)
            return entry;
        entry = entry->next;
    }

    return NULL;
}

ak_process_entry_t *ak_process_find_by_run_id(const u8 *run_id)
{
    if (!ak_process_state.initialized || !run_id)
        return NULL;

    for (u32 i = 0; i < AK_PROCESS_MAX_ENTRIES; i++) {
        ak_process_entry_t *entry = ak_process_state.entries[i];
        while (entry) {
            if (ak_token_id_equal((u8 *)run_id, entry->run_id))
                return entry;
            entry = entry->next;
        }
    }

    return NULL;
}

/* ============================================================
 * POLICY ACCESS
 * ============================================================ */

ak_policy_v2_t *ak_process_get_policy(u64 pid)
{
    ak_process_entry_t *entry = ak_process_find(pid);
    if (entry && entry->policy)
        return entry->policy;

    /* Return fail-closed policy */
    return ak_process_state.fail_closed_policy;
}

int ak_process_set_policy(u64 pid, ak_policy_v2_t *policy)
{
    if (!policy)
        return -EINVAL;

    process_lock();

    ak_process_entry_t *entry = ak_process_find(pid);
    if (!entry) {
        process_unlock();
        return -ENOENT;
    }

    /* TODO: Validate that new policy is subset of current */
    /* For now, allow any policy change */

    /* Free old policy if owned */
    if (entry->policy_owned && entry->policy) {
        ak_policy_v2_destroy(entry->policy);
    }

    entry->policy = policy;
    entry->policy_owned = false;

    process_unlock();

    ak_debug("ak_process: set policy for pid=%lu", pid);
    return 0;
}

/* ============================================================
 * CAPABILITY DELEGATION
 * ============================================================ */

int ak_process_delegate_cap(
    u64 parent_pid,
    u64 child_pid,
    ak_capability_t *cap,
    u64 ttl_ms)
{
    if (!cap)
        return -EINVAL;

    process_lock();

    /* Find parent */
    ak_process_entry_t *parent = ak_process_find(parent_pid);
    if (!parent) {
        process_unlock();
        return -ENOENT;
    }

    /* Find child */
    ak_process_entry_t *child = ak_process_find(child_pid);
    if (!child) {
        process_unlock();
        return -ENOENT;
    }

    /* Verify child is actual child of parent */
    if (child->parent_pid != parent_pid) {
        process_unlock();
        ak_warn("ak_process: delegation denied - not a child");
        return -EPERM;
    }

    /* Check cap limit */
    if (child->cap_count >= AK_PROCESS_MAX_CAPS) {
        process_unlock();
        ak_warn("ak_process: delegation denied - too many caps");
        return -ENOMEM;
    }

    /* Create delegated capability (attenuated) */
    u32 effective_ttl = ttl_ms;
    if (effective_ttl == 0) {
        effective_ttl = ak_capability_remaining_ttl(cap);
    } else {
        /* Cannot exceed parent cap's remaining TTL */
        u32 parent_remaining = ak_capability_remaining_ttl(cap);
        if (effective_ttl > parent_remaining)
            effective_ttl = parent_remaining;
    }

    /* Delegate using capability subsystem */
    ak_capability_t *child_cap = ak_capability_delegate(
        ak_process_state.h,
        cap,
        cap->type,
        (const char *)cap->resource,
        NULL,  /* Same methods */
        effective_ttl,
        cap->rate_limit,
        cap->rate_window_ms
    );

    if (!child_cap) {
        process_unlock();
        ak_warn("ak_process: delegation failed - capability subsystem error");
        return -EPERM;
    }

    /* Bind to child's run_id */
    runtime_memcpy(child_cap->run_id, child->run_id, AK_TOKEN_ID_SIZE);

    /* Create delegation record */
    ak_delegated_cap_t *dcap = alloc_delegated_cap();
    if (!dcap) {
        ak_capability_destroy(ak_process_state.h, child_cap);
        process_unlock();
        return -ENOMEM;
    }

    dcap->cap = child_cap;
    dcap->delegated_ms = ak_now_ms();
    dcap->expires_ms = (ttl_ms > 0) ? (dcap->delegated_ms + ttl_ms) : 0;
    dcap->revoked = false;

    /* Add to child's cap list */
    dcap->next = child->caps;
    child->caps = dcap;
    child->cap_count++;

    ak_process_state.stats.total_delegations++;
    ak_process_state.stats.active_caps++;

    process_unlock();

    ak_debug("ak_process: delegated cap type=%d from pid=%lu to pid=%lu ttl=%lu",
             cap->type, parent_pid, child_pid, ttl_ms);

    return 0;
}

int ak_process_revoke_cap(u64 pid, const u8 *tid)
{
    if (!tid)
        return -EINVAL;

    process_lock();

    ak_process_entry_t *entry = ak_process_find(pid);
    if (!entry) {
        process_unlock();
        return -ENOENT;
    }

    ak_delegated_cap_t *prev = NULL;
    ak_delegated_cap_t *dcap = entry->caps;

    while (dcap) {
        if (dcap->cap && ak_token_id_equal((u8 *)tid, dcap->cap->tid)) {
            /* Found it - revoke */
            if (!dcap->revoked) {
                ak_revocation_add(dcap->cap->tid, "explicit revocation");
                dcap->revoked = true;
                ak_process_state.stats.total_revocations++;
                ak_process_state.stats.active_caps--;
            }

            /* Remove from list */
            if (prev) {
                prev->next = dcap->next;
            } else {
                entry->caps = dcap->next;
            }
            entry->cap_count--;

            free_delegated_cap(dcap);

            process_unlock();

            ak_debug("ak_process: revoked cap for pid=%lu", pid);
            return 0;
        }

        prev = dcap;
        dcap = dcap->next;
    }

    process_unlock();
    return -ENOENT;
}

void ak_process_revoke_caps(u64 pid)
{
    process_lock();

    ak_process_entry_t *entry = ak_process_find(pid);
    if (!entry) {
        process_unlock();
        return;
    }

    ak_delegated_cap_t *dcap = entry->caps;
    while (dcap) {
        ak_delegated_cap_t *next = dcap->next;

        if (dcap->cap && !dcap->revoked) {
            ak_revocation_add(dcap->cap->tid, "revoke all");
            dcap->revoked = true;
            ak_process_state.stats.total_revocations++;
            ak_process_state.stats.active_caps--;
        }

        free_delegated_cap(dcap);
        dcap = next;
    }

    entry->caps = NULL;
    entry->cap_count = 0;

    process_unlock();

    ak_debug("ak_process: revoked all caps for pid=%lu", pid);
}

boolean ak_process_has_cap(u64 pid, ak_cap_type_t type, const char *resource)
{
    process_lock();

    ak_process_entry_t *entry = ak_process_find(pid);
    if (!entry) {
        process_unlock();
        return false;
    }

    ak_delegated_cap_t *dcap = entry->caps;
    while (dcap) {
        if (dcap->cap && !dcap->revoked) {
            /* Check type */
            if (dcap->cap->type != type && dcap->cap->type != AK_CAP_ANY) {
                dcap = dcap->next;
                continue;
            }

            /* Check expiration */
            if (dcap->expires_ms > 0 && ak_now_ms() >= dcap->expires_ms) {
                dcap = dcap->next;
                continue;
            }

            /* Check resource pattern */
            if (resource) {
                if (ak_pattern_match((const char *)dcap->cap->resource, resource)) {
                    process_unlock();
                    return true;
                }
            } else {
                process_unlock();
                return true;
            }
        }

        dcap = dcap->next;
    }

    process_unlock();
    return false;
}

/* ============================================================
 * SPAWN AUTHORIZATION
 * ============================================================ */

boolean ak_process_authorize_spawn(
    u64 parent_pid,
    const ak_spawn_request_t *req,
    ak_decision_t *decision)
{
    if (!req || !decision)
        return false;

    /* Initialize decision */
    ak_memzero(decision, sizeof(*decision));
    decision->allow = false;

    /* Get parent entry */
    ak_process_entry_t *parent = ak_process_find(parent_pid);
    if (!parent) {
        decision->reason_code = AK_DENY_NO_POLICY;
        decision->errno_equiv = ESRCH;
        runtime_strncpy(decision->missing_cap, "process.parent",
                       AK_MAX_CAPSTR);
        runtime_strncpy(decision->detail, "Parent process not found",
                       AK_MAX_DETAIL);
        return false;
    }

    /* Check if parent has SPAWN capability */
    if (!ak_process_has_cap(parent_pid, AK_CAP_SPAWN, req->program)) {
        /* Also check policy */
        ak_policy_v2_t *policy = parent->policy;
        if (!policy || !ak_policy_v2_check_spawn(policy, req->program)) {
            decision->reason_code = AK_DENY_NO_CAP;
            decision->errno_equiv = EPERM;
            runtime_strncpy(decision->missing_cap, "spawn",
                           AK_MAX_CAPSTR);

            /* Generate suggestion */
            char *p = decision->suggested_snippet;
            int len = 0;
            len += runtime_strlen("[spawn]\nallow = [\"");
            runtime_strncpy(p, "[spawn]\nallow = [\"", AK_MAX_SUGGEST);
            p += len;
            u64 prog_len = runtime_strlen(req->program);
            if (len + prog_len + 4 < AK_MAX_SUGGEST) {
                runtime_memcpy(p, req->program, prog_len);
                p += prog_len;
                runtime_strncpy(p, "\"]\n", AK_MAX_SUGGEST - len - prog_len);
            }

            runtime_strncpy(decision->detail,
                           "Missing spawn capability for program",
                           AK_MAX_DETAIL);
            return false;
        }
    }

    /* Check child policy subset of parent if provided */
    if (req->child_policy && parent->policy) {
        /* TODO: Implement policy subsumption check */
        /* For now, allow any child policy */
    }

    /* Check child count limit */
    if (ak_process_count_children(parent_pid) >= AK_PROCESS_MAX_CHILDREN) {
        decision->reason_code = AK_DENY_BUDGET_EXCEEDED;
        decision->errno_equiv = EAGAIN;
        runtime_strncpy(decision->missing_cap, "spawn.limit",
                       AK_MAX_CAPSTR);
        runtime_strncpy(decision->detail,
                       "Maximum child process limit reached",
                       AK_MAX_DETAIL);
        return false;
    }

    /* Authorization granted */
    decision->allow = true;
    decision->reason_code = AK_DENY_NONE;
    decision->errno_equiv = 0;

    ak_process_state.stats.spawn_success++;

    return true;
}

int ak_process_spawn(
    u64 parent_pid,
    const ak_spawn_request_t *req,
    ak_spawn_result_t *result)
{
    if (!req || !result)
        return -EINVAL;

    ak_memzero(result, sizeof(*result));

    ak_process_state.stats.total_spawns++;

    /* Authorize spawn */
    ak_decision_t decision;
    if (!ak_process_authorize_spawn(parent_pid, req, &decision)) {
        result->success = false;
        result->error_code = decision.errno_equiv;
        runtime_strncpy(result->error_msg, decision.detail,
                       sizeof(result->error_msg));
        ak_process_state.stats.spawn_denied++;
        return -decision.errno_equiv;
    }

    /*
     * NOTE: Actual fork/exec is done by the kernel.
     * This function prepares the AK state for the new process.
     * The kernel will call ak_process_register() after successful spawn.
     */

    /* For now, we don't actually spawn - just return success indicator */
    /* The caller (kernel) will do the actual fork/exec and then call register */

    result->success = true;
    /* Child PID will be set by kernel after actual spawn */

    return 0;
}

/* ============================================================
 * PROCESS HIERARCHY
 * ============================================================ */

boolean ak_process_is_descendant(u64 parent_pid, u64 child_pid)
{
    if (parent_pid == 0 || child_pid == 0)
        return false;

    if (parent_pid == child_pid)
        return false;  /* Not descendant of self */

    ak_process_entry_t *child = ak_process_find(child_pid);

    /* Walk up the tree */
    while (child) {
        if (child->parent_pid == parent_pid)
            return true;

        if (child->parent_pid == 0)
            break;  /* Reached init */

        child = ak_process_find(child->parent_pid);
    }

    return false;
}

u64 ak_process_get_parent(u64 pid)
{
    ak_process_entry_t *entry = ak_process_find(pid);
    if (entry)
        return entry->parent_pid;
    return 0;
}

u32 ak_process_count_children(u64 pid)
{
    u32 count = 0;

    for (u32 i = 0; i < AK_PROCESS_MAX_ENTRIES; i++) {
        ak_process_entry_t *entry = ak_process_state.entries[i];
        while (entry) {
            if (entry->parent_pid == pid &&
                entry->state == AK_PROC_STATE_RUNNING) {
                count++;
            }
            entry = entry->next;
        }
    }

    return count;
}

/* ============================================================
 * STATE MANAGEMENT
 * ============================================================ */

void ak_process_set_state(u64 pid, ak_process_state_t state)
{
    process_lock();

    ak_process_entry_t *entry = ak_process_find(pid);
    if (entry) {
        entry->state = state;
    }

    process_unlock();
}

ak_process_state_t ak_process_get_state(u64 pid)
{
    ak_process_entry_t *entry = ak_process_find(pid);
    if (entry)
        return entry->state;
    return AK_PROC_STATE_NONE;
}

/* ============================================================
 * CLEANUP AND MAINTENANCE
 * ============================================================ */

u32 ak_process_expire_caps(void)
{
    u32 expired = 0;
    u64 now = ak_now_ms();

    process_lock();

    for (u32 i = 0; i < AK_PROCESS_MAX_ENTRIES; i++) {
        ak_process_entry_t *entry = ak_process_state.entries[i];
        while (entry) {
            ak_delegated_cap_t *prev = NULL;
            ak_delegated_cap_t *dcap = entry->caps;

            while (dcap) {
                ak_delegated_cap_t *next = dcap->next;

                /* Check if expired */
                if (dcap->expires_ms > 0 && now >= dcap->expires_ms) {
                    if (!dcap->revoked) {
                        ak_revocation_add(dcap->cap->tid, "time limit expired");
                        dcap->revoked = true;
                        ak_process_state.stats.total_revocations++;
                        ak_process_state.stats.active_caps--;
                        expired++;
                    }

                    /* Remove from list */
                    if (prev) {
                        prev->next = next;
                    } else {
                        entry->caps = next;
                    }
                    entry->cap_count--;

                    free_delegated_cap(dcap);
                } else {
                    prev = dcap;
                }

                dcap = next;
            }

            entry = entry->next;
        }
    }

    process_unlock();

    if (expired > 0) {
        ak_debug("ak_process: expired %u capabilities", expired);
    }

    return expired;
}

u32 ak_process_cleanup_zombies(void)
{
    u32 cleaned = 0;

    process_lock();

    for (u32 i = 0; i < AK_PROCESS_MAX_ENTRIES; i++) {
        ak_process_entry_t *prev = NULL;
        ak_process_entry_t *entry = ak_process_state.entries[i];

        while (entry) {
            ak_process_entry_t *next = entry->next;

            if (entry->state == AK_PROC_STATE_EXITED) {
                /* Remove from chain */
                if (prev) {
                    prev->next = next;
                } else {
                    ak_process_state.entries[i] = next;
                }

                /* Free resources */
                if (entry->policy_owned && entry->policy) {
                    ak_policy_v2_destroy(entry->policy);
                }

                free_entry(entry);
                ak_process_state.entry_count--;
                cleaned++;
            } else {
                prev = entry;
            }

            entry = next;
        }
    }

    process_unlock();

    if (cleaned > 0) {
        ak_debug("ak_process: cleaned %u zombie entries", cleaned);
    }

    return cleaned;
}

/* ============================================================
 * STATISTICS
 * ============================================================ */

void ak_process_get_stats(ak_process_stats_t *stats)
{
    if (!stats)
        return;

    process_lock();
    runtime_memcpy(stats, &ak_process_state.stats, sizeof(*stats));
    process_unlock();
}

/* ============================================================
 * DEBUG HELPERS
 * ============================================================ */

void ak_process_debug_dump(void)
{
#if AK_DEBUG
    process_lock();

    rprintf("\n=== AK Process Registry ===\n");
    rprintf("Total entries: %u\n", ak_process_state.entry_count);
    rprintf("Active processes: %lu\n", ak_process_state.stats.active_processes);
    rprintf("Active caps: %lu\n", ak_process_state.stats.active_caps);
    rprintf("\n");

    for (u32 i = 0; i < AK_PROCESS_MAX_ENTRIES; i++) {
        ak_process_entry_t *entry = ak_process_state.entries[i];
        while (entry) {
            rprintf("PID %lu (parent=%lu, state=%d, caps=%u)\n",
                    entry->pid, entry->parent_pid, entry->state,
                    entry->cap_count);
            rprintf("  run_id: %02x%02x%02x%02x...\n",
                    entry->run_id[0], entry->run_id[1],
                    entry->run_id[2], entry->run_id[3]);
            if (entry->program[0]) {
                rprintf("  program: %s\n", entry->program);
            }

            ak_delegated_cap_t *dcap = entry->caps;
            while (dcap) {
                if (dcap->cap) {
                    rprintf("    cap type=%d revoked=%d\n",
                            dcap->cap->type, dcap->revoked);
                }
                dcap = dcap->next;
            }

            entry = entry->next;
        }
    }

    rprintf("===========================\n\n");

    process_unlock();
#endif
}
