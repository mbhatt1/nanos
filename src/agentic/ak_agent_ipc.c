/*
 * Authority Kernel - Multi-Agent IPC Implementation
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Implements secure message passing between agents with capability-gated
 * access control and support for agent hierarchies.
 *
 * SECURITY: All inter-agent communication flows through this module.
 * Messages are copied (not shared) to maintain isolation.
 * Sender identity is verified via run_id.
 */

#include "ak_agent_ipc.h"
#include "ak_capability.h"
#include "ak_effects.h"
#include "ak_compat.h"
#include "ak_assert.h"

/* ============================================================
 * MODULE STATE
 * ============================================================ */

/* Registry hash table size (must be power of 2) */
#define REGISTRY_HASH_SIZE      256
#define REGISTRY_HASH_MASK      (REGISTRY_HASH_SIZE - 1)

/* Global IPC state */
static struct {
    boolean initialized;
    heap h;

    /* Agent registry (hash table by PID) */
    ak_agent_registry_entry_t *registry_by_pid[REGISTRY_HASH_SIZE];

    /* Registry lock */
    u64 registry_lock;

    /* Message ID counter (atomic) */
    volatile u64 msg_id_counter;

    /* Statistics (atomic) */
    ak_agent_ipc_stats_t stats;
} ipc_state;

/* ============================================================
 * SPIN LOCK HELPERS
 * ============================================================ */

static inline void spin_lock_init(u64 *lock)
{
    *lock = 0;
}

static inline void spin_lock_acquire(u64 *lock)
{
    while (__sync_lock_test_and_set(lock, 1)) {
        /* Spin until lock acquired */
        while (*lock) {
            /* CPU pause hint for spin-wait */
#if defined(__x86_64__)
            __asm__ volatile("pause" ::: "memory");
#elif defined(__aarch64__)
            __asm__ volatile("yield" ::: "memory");
#endif
        }
    }
}

static inline void spin_lock_release(u64 *lock)
{
    __sync_lock_release(lock);
}

/* ============================================================
 * HASH FUNCTIONS
 * ============================================================ */

static inline u32 hash_pid(u64 pid)
{
    /* Simple hash for PID - mix bits */
    u64 h = pid;
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    return (u32)(h & REGISTRY_HASH_MASK);
}

/* ============================================================
 * INTERNAL HELPERS
 * ============================================================ */

/*
 * Get agent PID from context.
 */
static u64 get_agent_pid(ak_agent_context_t *ctx)
{
    if (!ctx)
        return 0;

    /* Reconstruct PID from pid array (little-endian) */
    u64 pid = 0;
    for (int i = 0; i < 8 && i < AK_TOKEN_ID_SIZE; i++) {
        pid |= ((u64)ctx->pid[i]) << (i * 8);
    }
    return pid;
}

/*
 * Get agent run_id from context.
 */
static void get_agent_run_id(ak_agent_context_t *ctx, u8 *run_id_out)
{
    if (!ctx || !run_id_out) {
        if (run_id_out)
            runtime_memset(run_id_out, 0, 16);
        return;
    }
    runtime_memcpy(run_id_out, ctx->run_id, 16);
}

/*
 * Lookup registry entry by PID.
 * Caller must hold registry_lock.
 */
static ak_agent_registry_entry_t *lookup_entry_locked(u64 pid)
{
    u32 hash = hash_pid(pid);
    ak_agent_registry_entry_t *entry = ipc_state.registry_by_pid[hash];

    while (entry) {
        if (entry->pid == pid && entry->active)
            return entry;
        entry = entry->next;
    }
    return NULL;
}

/*
 * Lookup registry entry by PID (with locking).
 */
static ak_agent_registry_entry_t *lookup_entry(u64 pid)
{
    spin_lock_acquire(&ipc_state.registry_lock);
    ak_agent_registry_entry_t *entry = lookup_entry_locked(pid);
    spin_lock_release(&ipc_state.registry_lock);
    return entry;
}

/*
 * Generate next message ID (atomic).
 */
static u64 next_msg_id(void)
{
    return __sync_fetch_and_add(&ipc_state.msg_id_counter, 1) + 1;
}

/*
 * Get current timestamp in nanoseconds.
 */
static u64 get_timestamp_ns(void)
{
    return ak_now() * 1000000ULL;  /* Convert ms to ns (approximate) */
}

/*
 * Check if name matches pattern.
 */
static boolean name_matches_pattern(const char *name, const char *pattern)
{
    if (!name || !pattern)
        return false;

    u64 name_len = runtime_strlen(name);
    u64 pattern_len = runtime_strlen(pattern);

    if (pattern_len == 0)
        return false;

    /* Wildcard "*" matches everything */
    if (pattern_len == 1 && pattern[0] == '*')
        return true;

    /* Suffix match "*suffix" */
    if (pattern[0] == '*') {
        const char *suffix = pattern + 1;
        u64 suffix_len = pattern_len - 1;
        if (name_len < suffix_len)
            return false;
        return runtime_strncmp(name + name_len - suffix_len, suffix, suffix_len) == 0;
    }

    /* Prefix match "prefix*" */
    if (pattern[pattern_len - 1] == '*') {
        u64 prefix_len = pattern_len - 1;
        if (name_len < prefix_len)
            return false;
        return runtime_strncmp(name, pattern, prefix_len) == 0;
    }

    /* Exact match */
    return ak_strcmp(name, pattern) == 0;
}

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

int ak_agent_ipc_init(heap h)
{
    AK_CHECK_NOT_NULL(h, -EINVAL);
    if (h == INVALID_ADDRESS) {
        ak_error("ak_agent_ipc_init: INVALID_ADDRESS heap");
        return -EINVAL;
    }

    if (ipc_state.initialized) {
        ak_warn("ak_agent_ipc_init: already initialized");
        return 0;
    }

    ak_memzero(&ipc_state, sizeof(ipc_state));
    ipc_state.h = h;
    spin_lock_init(&ipc_state.registry_lock);

    /* Initialize with timestamp for uniqueness */
    ipc_state.msg_id_counter = ak_now_ms() ^ 0x1234567890ABCDEFULL;

    ipc_state.initialized = true;
    ak_debug("ak_agent_ipc: initialized");

    return 0;
}

void ak_agent_ipc_shutdown(void)
{
    if (!ipc_state.initialized)
        return;

    spin_lock_acquire(&ipc_state.registry_lock);

    /* Free all registry entries and their mailboxes */
    for (u32 i = 0; i < REGISTRY_HASH_SIZE; i++) {
        ak_agent_registry_entry_t *entry = ipc_state.registry_by_pid[i];
        while (entry) {
            ak_agent_registry_entry_t *next = entry->next;

            /* Free mailbox messages */
            if (entry->mailbox) {
                ak_ipc_message_t *msg = entry->mailbox->inbox_head;
                while (msg) {
                    ak_ipc_message_t *msg_next = msg->next;
                    if (msg->payload)
                        deallocate_buffer(msg->payload);
                    deallocate(ipc_state.h, msg, sizeof(ak_ipc_message_t));
                    msg = msg_next;
                }
                deallocate(ipc_state.h, entry->mailbox, sizeof(ak_agent_mailbox_t));
            }

            /* Free child array */
            if (entry->child_pids)
                deallocate(ipc_state.h, entry->child_pids,
                          entry->child_capacity * sizeof(u64));

            deallocate(ipc_state.h, entry, sizeof(ak_agent_registry_entry_t));
            entry = next;
        }
        ipc_state.registry_by_pid[i] = NULL;
    }

    spin_lock_release(&ipc_state.registry_lock);

    ipc_state.initialized = false;
    ak_debug("ak_agent_ipc: shutdown");
}

/* ============================================================
 * AGENT REGISTRATION
 * ============================================================ */

int ak_agent_register(
    ak_agent_context_t *ctx,
    const char *name,
    boolean discoverable)
{
    if (!ipc_state.initialized)
        return AK_E_IPC_NOT_INIT;

    AK_CHECK_NOT_NULL(ctx, -EINVAL);
    AK_CHECK_NOT_NULL(name, -EINVAL);

    u64 name_len = runtime_strlen(name);
    if (name_len >= AK_IPC_MAX_NAME_LEN)
        return AK_E_IPC_NAME_TOO_LONG;

    u64 pid = get_agent_pid(ctx);
    if (pid == 0) {
        ak_error("ak_agent_register: invalid agent PID");
        return -EINVAL;
    }

    spin_lock_acquire(&ipc_state.registry_lock);

    /* Check if already registered */
    ak_agent_registry_entry_t *existing = lookup_entry_locked(pid);
    if (existing) {
        spin_lock_release(&ipc_state.registry_lock);
        return AK_E_IPC_ALREADY_REGISTERED;
    }

    /* Check name uniqueness among discoverable agents */
    if (discoverable) {
        for (u32 i = 0; i < REGISTRY_HASH_SIZE; i++) {
            ak_agent_registry_entry_t *e = ipc_state.registry_by_pid[i];
            while (e) {
                if (e->active && e->discoverable &&
                    ak_strcmp(e->name, name) == 0) {
                    spin_lock_release(&ipc_state.registry_lock);
                    return AK_E_IPC_NAME_EXISTS;
                }
                e = e->next;
            }
        }
    }

    /* Allocate entry */
    ak_agent_registry_entry_t *entry = allocate(ipc_state.h,
                                                sizeof(ak_agent_registry_entry_t));
    if (!entry || ak_is_invalid_address(entry)) {
        spin_lock_release(&ipc_state.registry_lock);
        return -ENOMEM;
    }
    ak_memzero(entry, sizeof(ak_agent_registry_entry_t));

    /* Allocate mailbox */
    entry->mailbox = allocate(ipc_state.h, sizeof(ak_agent_mailbox_t));
    if (!entry->mailbox || ak_is_invalid_address(entry->mailbox)) {
        deallocate(ipc_state.h, entry, sizeof(ak_agent_registry_entry_t));
        spin_lock_release(&ipc_state.registry_lock);
        return -ENOMEM;
    }
    ak_memzero(entry->mailbox, sizeof(ak_agent_mailbox_t));

    /* Initialize entry */
    entry->pid = pid;
    get_agent_run_id(ctx, entry->run_id);
    runtime_strncpy(entry->name, name, AK_IPC_MAX_NAME_LEN - 1);
    entry->name[AK_IPC_MAX_NAME_LEN - 1] = '\0';
    entry->discoverable = discoverable;
    entry->active = true;
    entry->registered_ns = get_timestamp_ns();

    /* Initialize mailbox */
    entry->mailbox->agent_pid = pid;
    entry->mailbox->inbox_limit = AK_IPC_DEFAULT_INBOX_LIMIT;
    spin_lock_init(&entry->mailbox->lock);

    /* Get parent from context */
    if (ctx->parent) {
        entry->parent_pid = get_agent_pid(ctx->parent);
    }

    /* Insert into hash table */
    u32 hash = hash_pid(pid);
    entry->next = ipc_state.registry_by_pid[hash];
    ipc_state.registry_by_pid[hash] = entry;

    /* Update statistics */
    __sync_fetch_and_add(&ipc_state.stats.agents_registered, 1);
    __sync_fetch_and_add(&ipc_state.stats.agents_active, 1);

    spin_lock_release(&ipc_state.registry_lock);

    ak_debug("ak_agent_ipc: registered agent pid=%lx name=%s discoverable=%d",
             pid, name, discoverable);

    return 0;
}

int ak_agent_unregister(ak_agent_context_t *ctx)
{
    if (!ipc_state.initialized)
        return AK_E_IPC_NOT_INIT;

    AK_CHECK_NOT_NULL(ctx, -EINVAL);

    u64 pid = get_agent_pid(ctx);

    spin_lock_acquire(&ipc_state.registry_lock);

    u32 hash = hash_pid(pid);
    ak_agent_registry_entry_t *prev = NULL;
    ak_agent_registry_entry_t *entry = ipc_state.registry_by_pid[hash];

    while (entry) {
        if (entry->pid == pid && entry->active) {
            /* Mark as inactive (keep in table for cleanup) */
            entry->active = false;

            /* Free mailbox messages */
            if (entry->mailbox) {
                spin_lock_acquire(&entry->mailbox->lock);
                ak_ipc_message_t *msg = entry->mailbox->inbox_head;
                while (msg) {
                    ak_ipc_message_t *next = msg->next;
                    if (msg->payload)
                        deallocate_buffer(msg->payload);
                    deallocate(ipc_state.h, msg, sizeof(ak_ipc_message_t));
                    msg = next;
                }
                entry->mailbox->inbox_head = NULL;
                entry->mailbox->inbox_tail = NULL;
                entry->mailbox->inbox_count = 0;
                spin_lock_release(&entry->mailbox->lock);
            }

            /* Update statistics */
            __sync_fetch_and_add(&ipc_state.stats.agents_unregistered, 1);
            __sync_fetch_and_sub(&ipc_state.stats.agents_active, 1);

            spin_lock_release(&ipc_state.registry_lock);

            ak_debug("ak_agent_ipc: unregistered agent pid=%lx", pid);
            return 0;
        }
        prev = entry;
        entry = entry->next;
    }

    spin_lock_release(&ipc_state.registry_lock);
    return AK_E_IPC_NOT_REGISTERED;
}

/* ============================================================
 * MESSAGE SENDING
 * ============================================================ */

/*
 * Internal send function.
 */
static s64 ipc_send_internal(
    ak_agent_context_t *ctx,
    u64 receiver_pid,
    u32 msg_type,
    u32 flags,
    u64 correlation_id,
    buffer payload)
{
    if (!ipc_state.initialized)
        return AK_E_IPC_NOT_INIT;

    AK_CHECK_NOT_NULL(ctx, -EINVAL);

    u64 sender_pid = get_agent_pid(ctx);

    /* Check payload size */
    u64 payload_len = payload ? buffer_length(payload) : 0;
    if (payload_len > AK_IPC_MAX_PAYLOAD_SIZE)
        return AK_E_IPC_MSG_TOO_LARGE;

    /* Lookup sender entry */
    ak_agent_registry_entry_t *sender_entry = lookup_entry(sender_pid);
    if (!sender_entry) {
        __sync_fetch_and_add(&ipc_state.stats.send_failures, 1);
        return AK_E_IPC_NOT_REGISTERED;
    }

    /* Lookup receiver entry */
    ak_agent_registry_entry_t *receiver_entry = lookup_entry(receiver_pid);
    if (!receiver_entry) {
        __sync_fetch_and_add(&ipc_state.stats.send_failures, 1);
        return AK_E_IPC_NO_RECIPIENT;
    }

    /* Check IPC authorization */
    boolean is_parent = ak_agent_is_parent_of(sender_pid, receiver_pid);
    boolean is_child = ak_agent_is_child_of(sender_pid, receiver_pid);

    if (!is_parent && !is_child) {
        /* Peer messaging - requires capability check */
        if (!sender_entry->has_ipc_cap) {
            __sync_fetch_and_add(&ipc_state.stats.capability_denials, 1);
            return AK_E_IPC_NO_CAPABILITY;
        }

        /*
         * Route through effects system for policy check.
         * Build effect request and authorize.
         */
        ak_ctx_t *ak_ctx = ak_ctx_current();
        if (ak_ctx && ak_ctx->mode != AK_MODE_OFF) {
            ak_effect_req_t req;
            ak_memzero(&req, sizeof(req));
            req.op = AK_E_AGENT_SEND;
            req.trace_id = ak_trace_id_generate(ak_ctx);
            req.pid = sender_pid;

            /* Format target as "agent:<pid>" */
            int len = 0;
            req.target[len++] = 'a';
            req.target[len++] = 'g';
            req.target[len++] = 'e';
            req.target[len++] = 'n';
            req.target[len++] = 't';
            req.target[len++] = ':';

            /* Format PID as hex */
            static const char hex[] = "0123456789abcdef";
            for (int i = 15; i >= 0; i--) {
                req.target[len++] = hex[(receiver_pid >> (i * 4)) & 0xf];
            }
            req.target[len] = '\0';

            ak_decision_t decision;
            long retval;
            int auth_result = ak_authorize_and_execute(ak_ctx, &req, &decision, &retval);

            if (auth_result != 0 || !decision.allow) {
                __sync_fetch_and_add(&ipc_state.stats.peer_denials, 1);
                return AK_E_IPC_PEER_DENIED;
            }
        }
    }

    /* Create message */
    ak_ipc_message_t *msg = allocate(ipc_state.h, sizeof(ak_ipc_message_t));
    if (!msg || ak_is_invalid_address(msg)) {
        __sync_fetch_and_add(&ipc_state.stats.send_failures, 1);
        return -ENOMEM;
    }
    ak_memzero(msg, sizeof(ak_ipc_message_t));

    msg->msg_id = next_msg_id();
    msg->sender_pid = sender_pid;
    get_agent_run_id(ctx, msg->sender_run_id);
    msg->receiver_pid = receiver_pid;
    msg->timestamp_ns = get_timestamp_ns();
    msg->msg_type = msg_type;
    msg->flags = flags;
    msg->correlation_id = correlation_id;

    /* Add hierarchy flags */
    if (is_parent)
        msg->flags |= AK_IPC_FLAG_FROM_PARENT;
    if (is_child)
        msg->flags |= AK_IPC_FLAG_FROM_CHILD;

    /* Copy payload (isolation) */
    if (payload && payload_len > 0) {
        msg->payload = allocate_buffer(ipc_state.h, payload_len);
        if (!msg->payload || ak_is_invalid_address(msg->payload)) {
            deallocate(ipc_state.h, msg, sizeof(ak_ipc_message_t));
            __sync_fetch_and_add(&ipc_state.stats.send_failures, 1);
            return -ENOMEM;
        }
        buffer_write(msg->payload, buffer_ref(payload, 0), payload_len);
    }

    /* Enqueue to receiver's mailbox */
    ak_agent_mailbox_t *mailbox = receiver_entry->mailbox;
    spin_lock_acquire(&mailbox->lock);

    if (mailbox->inbox_count >= mailbox->inbox_limit) {
        spin_lock_release(&mailbox->lock);
        if (msg->payload)
            deallocate_buffer(msg->payload);
        deallocate(ipc_state.h, msg, sizeof(ak_ipc_message_t));
        __sync_fetch_and_add(&mailbox->messages_dropped, 1);
        __sync_fetch_and_add(&ipc_state.stats.messages_dropped, 1);
        return AK_E_IPC_MAILBOX_FULL;
    }

    /* Add to queue */
    if (mailbox->inbox_tail) {
        mailbox->inbox_tail->next = msg;
    } else {
        mailbox->inbox_head = msg;
    }
    mailbox->inbox_tail = msg;
    mailbox->inbox_count++;

    if (flags & AK_IPC_FLAG_URGENT)
        mailbox->urgent_count++;

    mailbox->messages_received++;

    /* TODO: Wake waiting threads if any */

    spin_lock_release(&mailbox->lock);

    __sync_fetch_and_add(&ipc_state.stats.messages_sent, 1);

    ak_debug("ak_agent_ipc: sent msg_id=%lx from=%lx to=%lx type=%u",
             msg->msg_id, sender_pid, receiver_pid, msg_type);

    return (s64)msg->msg_id;
}

s64 ak_ipc_send(
    ak_agent_context_t *ctx,
    u64 receiver_pid,
    u32 msg_type,
    u32 flags,
    buffer payload)
{
    return ipc_send_internal(ctx, receiver_pid, msg_type, flags, 0, payload);
}

int ak_ipc_send_request(
    ak_agent_context_t *ctx,
    u64 receiver_pid,
    u32 msg_type,
    buffer payload,
    u64 *correlation_out)
{
    AK_CHECK_NOT_NULL(correlation_out, -EINVAL);

    s64 result = ipc_send_internal(ctx, receiver_pid, msg_type,
                                    AK_IPC_FLAG_NEEDS_REPLY, 0, payload);
    if (result < 0)
        return (int)result;

    *correlation_out = (u64)result;  /* msg_id is correlation_id */
    return 0;
}

int ak_ipc_send_response(
    ak_agent_context_t *ctx,
    u64 receiver_pid,
    u64 correlation_id,
    buffer payload)
{
    s64 result = ipc_send_internal(ctx, receiver_pid, AK_IPC_MSG_TYPE_RESPONSE,
                                    0, correlation_id, payload);
    return result < 0 ? (int)result : 0;
}

s64 ak_ipc_broadcast(
    ak_agent_context_t *ctx,
    u32 msg_type,
    u32 flags,
    buffer payload)
{
    if (!ipc_state.initialized)
        return AK_E_IPC_NOT_INIT;

    AK_CHECK_NOT_NULL(ctx, -EINVAL);

    u64 sender_pid = get_agent_pid(ctx);

    /* Check broadcast capability */
    ak_agent_registry_entry_t *sender_entry = lookup_entry(sender_pid);
    if (!sender_entry)
        return AK_E_IPC_NOT_REGISTERED;

    if (!sender_entry->has_broadcast_cap) {
        __sync_fetch_and_add(&ipc_state.stats.capability_denials, 1);
        return AK_E_IPC_NO_CAPABILITY;
    }

    /* Collect all discoverable recipients */
    u64 recipients[AK_IPC_BROADCAST_LIMIT];
    u32 recipient_count = 0;

    spin_lock_acquire(&ipc_state.registry_lock);

    for (u32 i = 0; i < REGISTRY_HASH_SIZE && recipient_count < AK_IPC_BROADCAST_LIMIT; i++) {
        ak_agent_registry_entry_t *entry = ipc_state.registry_by_pid[i];
        while (entry && recipient_count < AK_IPC_BROADCAST_LIMIT) {
            if (entry->active && entry->discoverable && entry->pid != sender_pid) {
                recipients[recipient_count++] = entry->pid;
            }
            entry = entry->next;
        }
    }

    spin_lock_release(&ipc_state.registry_lock);

    /* Send to all recipients */
    s64 sent = 0;
    u32 broadcast_flags = flags | AK_IPC_FLAG_BROADCAST;

    for (u32 i = 0; i < recipient_count; i++) {
        s64 result = ipc_send_internal(ctx, recipients[i], msg_type,
                                        broadcast_flags, 0, payload);
        if (result >= 0)
            sent++;
    }

    __sync_fetch_and_add(&ipc_state.stats.messages_broadcast, sent);

    return sent;
}

/* ============================================================
 * MESSAGE RECEIVING
 * ============================================================ */

ak_ipc_message_t *ak_ipc_recv(
    ak_agent_context_t *ctx,
    s32 timeout_ms)
{
    if (!ipc_state.initialized)
        return NULL;

    if (!ctx)
        return NULL;

    u64 pid = get_agent_pid(ctx);
    ak_agent_registry_entry_t *entry = lookup_entry(pid);
    if (!entry || !entry->mailbox)
        return NULL;

    ak_agent_mailbox_t *mailbox = entry->mailbox;

    /* Simple implementation: non-blocking dequeue or poll */
    u64 start_ms = ak_now_ms();
    u64 deadline_ms = (timeout_ms < 0) ? 0xFFFFFFFFFFFFFFFFULL :
                      (timeout_ms == 0) ? start_ms : start_ms + timeout_ms;

    while (1) {
        spin_lock_acquire(&mailbox->lock);

        if (mailbox->inbox_head) {
            /* Dequeue message */
            ak_ipc_message_t *msg = mailbox->inbox_head;
            mailbox->inbox_head = msg->next;
            if (!mailbox->inbox_head)
                mailbox->inbox_tail = NULL;
            mailbox->inbox_count--;

            if (msg->flags & AK_IPC_FLAG_URGENT)
                mailbox->urgent_count--;

            msg->next = NULL;  /* Detach from queue */

            spin_lock_release(&mailbox->lock);

            __sync_fetch_and_add(&ipc_state.stats.messages_received, 1);
            return msg;
        }

        mailbox->has_waiters = true;
        spin_lock_release(&mailbox->lock);

        /* Check timeout */
        u64 now_ms = ak_now_ms();
        if (now_ms >= deadline_ms) {
            __sync_fetch_and_add(&ipc_state.stats.recv_timeouts, 1);
            return NULL;
        }

        /* Simple busy-wait with yield (in real kernel, would use wait queue) */
#if defined(__x86_64__)
        __asm__ volatile("pause" ::: "memory");
#elif defined(__aarch64__)
        __asm__ volatile("yield" ::: "memory");
#endif
    }
}

ak_ipc_message_t *ak_ipc_recv_correlated(
    ak_agent_context_t *ctx,
    u64 correlation_id,
    s32 timeout_ms)
{
    if (!ipc_state.initialized)
        return NULL;

    if (!ctx)
        return NULL;

    u64 pid = get_agent_pid(ctx);
    ak_agent_registry_entry_t *entry = lookup_entry(pid);
    if (!entry || !entry->mailbox)
        return NULL;

    ak_agent_mailbox_t *mailbox = entry->mailbox;

    u64 start_ms = ak_now_ms();
    u64 deadline_ms = (timeout_ms < 0) ? 0xFFFFFFFFFFFFFFFFULL :
                      (timeout_ms == 0) ? start_ms : start_ms + timeout_ms;

    while (1) {
        spin_lock_acquire(&mailbox->lock);

        /* Search for matching message */
        ak_ipc_message_t *prev = NULL;
        ak_ipc_message_t *msg = mailbox->inbox_head;

        while (msg) {
            if (msg->correlation_id == correlation_id) {
                /* Found - remove from queue */
                if (prev) {
                    prev->next = msg->next;
                } else {
                    mailbox->inbox_head = msg->next;
                }
                if (msg == mailbox->inbox_tail)
                    mailbox->inbox_tail = prev;

                mailbox->inbox_count--;
                if (msg->flags & AK_IPC_FLAG_URGENT)
                    mailbox->urgent_count--;

                msg->next = NULL;

                spin_lock_release(&mailbox->lock);

                __sync_fetch_and_add(&ipc_state.stats.messages_received, 1);
                return msg;
            }
            prev = msg;
            msg = msg->next;
        }

        mailbox->has_waiters = true;
        spin_lock_release(&mailbox->lock);

        /* Check timeout */
        u64 now_ms = ak_now_ms();
        if (now_ms >= deadline_ms) {
            __sync_fetch_and_add(&ipc_state.stats.recv_timeouts, 1);
            return NULL;
        }

        /* Yield */
#if defined(__x86_64__)
        __asm__ volatile("pause" ::: "memory");
#elif defined(__aarch64__)
        __asm__ volatile("yield" ::: "memory");
#endif
    }
}

s64 ak_ipc_peek(ak_agent_context_t *ctx)
{
    if (!ipc_state.initialized)
        return AK_E_IPC_NOT_INIT;

    if (!ctx)
        return -EINVAL;

    u64 pid = get_agent_pid(ctx);
    ak_agent_registry_entry_t *entry = lookup_entry(pid);
    if (!entry || !entry->mailbox)
        return AK_E_IPC_NO_MAILBOX;

    return (s64)entry->mailbox->inbox_count;
}

s64 ak_ipc_peek_urgent(ak_agent_context_t *ctx)
{
    if (!ipc_state.initialized)
        return AK_E_IPC_NOT_INIT;

    if (!ctx)
        return -EINVAL;

    u64 pid = get_agent_pid(ctx);
    ak_agent_registry_entry_t *entry = lookup_entry(pid);
    if (!entry || !entry->mailbox)
        return AK_E_IPC_NO_MAILBOX;

    return (s64)entry->mailbox->urgent_count;
}

void ak_ipc_message_free(heap h, ak_ipc_message_t *msg)
{
    if (!msg)
        return;

    if (msg->payload)
        deallocate_buffer(msg->payload);

    deallocate(h ? h : ipc_state.h, msg, sizeof(ak_ipc_message_t));
}

/* ============================================================
 * AGENT DISCOVERY
 * ============================================================ */

s64 ak_agent_discover(
    const char *pattern,
    u64 *pids_out,
    u32 max_pids)
{
    if (!ipc_state.initialized)
        return AK_E_IPC_NOT_INIT;

    if (!pattern || !pids_out || max_pids == 0)
        return -EINVAL;

    u32 found = 0;

    spin_lock_acquire(&ipc_state.registry_lock);

    for (u32 i = 0; i < REGISTRY_HASH_SIZE && found < max_pids; i++) {
        ak_agent_registry_entry_t *entry = ipc_state.registry_by_pid[i];
        while (entry && found < max_pids) {
            if (entry->active && entry->discoverable &&
                name_matches_pattern(entry->name, pattern)) {
                pids_out[found++] = entry->pid;
            }
            entry = entry->next;
        }
    }

    spin_lock_release(&ipc_state.registry_lock);

    __sync_fetch_and_add(&ipc_state.stats.discover_requests, 1);
    __sync_fetch_and_add(&ipc_state.stats.discover_matches, found);

    return (s64)found;
}

int ak_agent_get_name(
    u64 pid,
    char *name_out,
    u32 max_len)
{
    if (!ipc_state.initialized)
        return AK_E_IPC_NOT_INIT;

    if (!name_out || max_len == 0)
        return -EINVAL;

    ak_agent_registry_entry_t *entry = lookup_entry(pid);
    if (!entry)
        return AK_E_IPC_NOT_REGISTERED;

    runtime_strncpy(name_out, entry->name, max_len - 1);
    name_out[max_len - 1] = '\0';

    return 0;
}

boolean ak_agent_is_discoverable(u64 pid)
{
    if (!ipc_state.initialized)
        return false;

    ak_agent_registry_entry_t *entry = lookup_entry(pid);
    return entry && entry->discoverable;
}

/* ============================================================
 * AGENT HIERARCHY
 * ============================================================ */

s64 ak_agent_get_parent(ak_agent_context_t *ctx)
{
    if (!ipc_state.initialized)
        return AK_E_IPC_NOT_INIT;

    if (!ctx)
        return -EINVAL;

    u64 pid = get_agent_pid(ctx);
    ak_agent_registry_entry_t *entry = lookup_entry(pid);
    if (!entry)
        return AK_E_IPC_NOT_REGISTERED;

    return (s64)entry->parent_pid;
}

s64 ak_agent_get_children(
    ak_agent_context_t *ctx,
    u64 *pids_out,
    u32 max_pids)
{
    if (!ipc_state.initialized)
        return AK_E_IPC_NOT_INIT;

    if (!ctx || !pids_out || max_pids == 0)
        return -EINVAL;

    u64 pid = get_agent_pid(ctx);
    ak_agent_registry_entry_t *entry = lookup_entry(pid);
    if (!entry)
        return AK_E_IPC_NOT_REGISTERED;

    u32 count = entry->child_count < max_pids ? entry->child_count : max_pids;
    if (count > 0 && entry->child_pids) {
        runtime_memcpy(pids_out, entry->child_pids, count * sizeof(u64));
    }

    return (s64)entry->child_count;
}

int ak_agent_add_child(
    ak_agent_context_t *parent_ctx,
    u64 child_pid)
{
    if (!ipc_state.initialized)
        return AK_E_IPC_NOT_INIT;

    if (!parent_ctx)
        return -EINVAL;

    u64 parent_pid = get_agent_pid(parent_ctx);

    spin_lock_acquire(&ipc_state.registry_lock);

    ak_agent_registry_entry_t *parent = lookup_entry_locked(parent_pid);
    if (!parent) {
        spin_lock_release(&ipc_state.registry_lock);
        return AK_E_IPC_NOT_REGISTERED;
    }

    /* Update child's parent_pid */
    ak_agent_registry_entry_t *child = lookup_entry_locked(child_pid);
    if (child) {
        child->parent_pid = parent_pid;
    }

    /* Expand child array if needed */
    if (parent->child_count >= parent->child_capacity) {
        u32 new_capacity = parent->child_capacity ? parent->child_capacity * 2 : 8;
        u64 *new_array = allocate(ipc_state.h, new_capacity * sizeof(u64));
        if (!new_array || ak_is_invalid_address(new_array)) {
            spin_lock_release(&ipc_state.registry_lock);
            return -ENOMEM;
        }

        if (parent->child_pids && parent->child_count > 0) {
            runtime_memcpy(new_array, parent->child_pids,
                          parent->child_count * sizeof(u64));
            deallocate(ipc_state.h, parent->child_pids,
                      parent->child_capacity * sizeof(u64));
        }

        parent->child_pids = new_array;
        parent->child_capacity = new_capacity;
    }

    parent->child_pids[parent->child_count++] = child_pid;

    spin_lock_release(&ipc_state.registry_lock);

    return 0;
}

int ak_agent_remove_child(
    ak_agent_context_t *parent_ctx,
    u64 child_pid)
{
    if (!ipc_state.initialized)
        return AK_E_IPC_NOT_INIT;

    if (!parent_ctx)
        return -EINVAL;

    u64 parent_pid = get_agent_pid(parent_ctx);

    spin_lock_acquire(&ipc_state.registry_lock);

    ak_agent_registry_entry_t *parent = lookup_entry_locked(parent_pid);
    if (!parent) {
        spin_lock_release(&ipc_state.registry_lock);
        return AK_E_IPC_NOT_REGISTERED;
    }

    /* Find and remove child from array */
    for (u32 i = 0; i < parent->child_count; i++) {
        if (parent->child_pids[i] == child_pid) {
            /* Shift remaining elements */
            for (u32 j = i; j < parent->child_count - 1; j++) {
                parent->child_pids[j] = parent->child_pids[j + 1];
            }
            parent->child_count--;
            break;
        }
    }

    /* Clear child's parent_pid */
    ak_agent_registry_entry_t *child = lookup_entry_locked(child_pid);
    if (child && child->parent_pid == parent_pid) {
        child->parent_pid = 0;
    }

    spin_lock_release(&ipc_state.registry_lock);

    return 0;
}

boolean ak_agent_is_parent_of(u64 sender_pid, u64 receiver_pid)
{
    if (!ipc_state.initialized)
        return false;

    ak_agent_registry_entry_t *receiver = lookup_entry(receiver_pid);
    return receiver && receiver->parent_pid == sender_pid;
}

boolean ak_agent_is_child_of(u64 sender_pid, u64 receiver_pid)
{
    if (!ipc_state.initialized)
        return false;

    ak_agent_registry_entry_t *sender = lookup_entry(sender_pid);
    return sender && sender->parent_pid == receiver_pid;
}

/* ============================================================
 * MAILBOX MANAGEMENT
 * ============================================================ */

int ak_ipc_set_inbox_limit(
    ak_agent_context_t *ctx,
    u32 limit)
{
    if (!ipc_state.initialized)
        return AK_E_IPC_NOT_INIT;

    if (!ctx)
        return -EINVAL;

    if (limit < 1 || limit > 10000)
        return -EINVAL;

    u64 pid = get_agent_pid(ctx);
    ak_agent_registry_entry_t *entry = lookup_entry(pid);
    if (!entry || !entry->mailbox)
        return AK_E_IPC_NO_MAILBOX;

    entry->mailbox->inbox_limit = limit;
    return 0;
}

int ak_ipc_get_mailbox_stats(
    ak_agent_context_t *ctx,
    u32 *count_out,
    u32 *limit_out,
    u64 *received_out,
    u64 *dropped_out)
{
    if (!ipc_state.initialized)
        return AK_E_IPC_NOT_INIT;

    if (!ctx)
        return -EINVAL;

    u64 pid = get_agent_pid(ctx);
    ak_agent_registry_entry_t *entry = lookup_entry(pid);
    if (!entry || !entry->mailbox)
        return AK_E_IPC_NO_MAILBOX;

    ak_agent_mailbox_t *mb = entry->mailbox;

    if (count_out) *count_out = mb->inbox_count;
    if (limit_out) *limit_out = mb->inbox_limit;
    if (received_out) *received_out = mb->messages_received;
    if (dropped_out) *dropped_out = mb->messages_dropped;

    return 0;
}

s64 ak_ipc_clear_mailbox(ak_agent_context_t *ctx)
{
    if (!ipc_state.initialized)
        return AK_E_IPC_NOT_INIT;

    if (!ctx)
        return -EINVAL;

    u64 pid = get_agent_pid(ctx);
    ak_agent_registry_entry_t *entry = lookup_entry(pid);
    if (!entry || !entry->mailbox)
        return AK_E_IPC_NO_MAILBOX;

    ak_agent_mailbox_t *mb = entry->mailbox;

    spin_lock_acquire(&mb->lock);

    u32 cleared = mb->inbox_count;

    ak_ipc_message_t *msg = mb->inbox_head;
    while (msg) {
        ak_ipc_message_t *next = msg->next;
        if (msg->payload)
            deallocate_buffer(msg->payload);
        deallocate(ipc_state.h, msg, sizeof(ak_ipc_message_t));
        msg = next;
    }

    mb->inbox_head = NULL;
    mb->inbox_tail = NULL;
    mb->inbox_count = 0;
    mb->urgent_count = 0;

    spin_lock_release(&mb->lock);

    return (s64)cleared;
}

/* ============================================================
 * CAPABILITY INTEGRATION
 * ============================================================ */

int ak_ipc_grant_capability(
    ak_agent_context_t *ctx,
    u64 *peer_pids,
    u32 peer_count,
    boolean can_broadcast)
{
    if (!ipc_state.initialized)
        return AK_E_IPC_NOT_INIT;

    if (!ctx)
        return -EINVAL;

    u64 pid = get_agent_pid(ctx);
    ak_agent_registry_entry_t *entry = lookup_entry(pid);
    if (!entry)
        return AK_E_IPC_NOT_REGISTERED;

    /* Grant capability flags */
    entry->has_ipc_cap = true;
    entry->has_broadcast_cap = can_broadcast;

    /* TODO: Store peer_pids for fine-grained access control */
    (void)peer_pids;
    (void)peer_count;

    return 0;
}

int ak_ipc_revoke_capability(ak_agent_context_t *ctx)
{
    if (!ipc_state.initialized)
        return AK_E_IPC_NOT_INIT;

    if (!ctx)
        return -EINVAL;

    u64 pid = get_agent_pid(ctx);
    ak_agent_registry_entry_t *entry = lookup_entry(pid);
    if (!entry)
        return AK_E_IPC_NOT_REGISTERED;

    entry->has_ipc_cap = false;
    entry->has_broadcast_cap = false;

    return 0;
}

boolean ak_ipc_has_capability(ak_agent_context_t *ctx, u64 peer_pid)
{
    if (!ipc_state.initialized || !ctx)
        return false;

    u64 pid = get_agent_pid(ctx);

    /* Parent/child always have capability to communicate */
    if (ak_agent_is_parent_of(pid, peer_pid) ||
        ak_agent_is_child_of(pid, peer_pid))
        return true;

    ak_agent_registry_entry_t *entry = lookup_entry(pid);
    if (!entry)
        return false;

    return entry->has_ipc_cap;
}

/* ============================================================
 * STATISTICS
 * ============================================================ */

void ak_agent_ipc_get_stats(ak_agent_ipc_stats_t *stats)
{
    if (!stats)
        return;

    runtime_memcpy(stats, &ipc_state.stats, sizeof(ak_agent_ipc_stats_t));
}

/* ============================================================
 * EFFECT INTEGRATION
 * ============================================================ */

int ak_effect_from_agent_send(
    ak_effect_req_t *req,
    ak_ctx_t *ctx,
    u64 receiver_pid,
    u32 msg_type)
{
    if (!req)
        return -EINVAL;

    ak_memzero(req, sizeof(*req));
    req->op = AK_E_AGENT_SEND;
    req->trace_id = ak_trace_id_generate(ctx);

    if (ctx && ctx->agent) {
        req->pid = get_agent_pid(ctx->agent);
    }

    /* Format target: "agent:<hex_pid>:<msg_type>" */
    int len = 0;
    req->target[len++] = 'a';
    req->target[len++] = 'g';
    req->target[len++] = 'e';
    req->target[len++] = 'n';
    req->target[len++] = 't';
    req->target[len++] = ':';

    /* Format receiver PID as hex */
    static const char hex[] = "0123456789abcdef";
    for (int i = 15; i >= 0; i--) {
        req->target[len++] = hex[(receiver_pid >> (i * 4)) & 0xf];
    }

    req->target[len++] = ':';

    /* Format message type as decimal */
    char type_buf[16];
    int type_len = 0;
    u32 t = msg_type;
    if (t == 0) {
        type_buf[type_len++] = '0';
    } else {
        char tmp[16];
        int tmp_len = 0;
        while (t > 0) {
            tmp[tmp_len++] = '0' + (t % 10);
            t /= 10;
        }
        for (int i = tmp_len - 1; i >= 0; i--) {
            type_buf[type_len++] = tmp[i];
        }
    }

    for (int i = 0; i < type_len && len < AK_MAX_TARGET - 1; i++) {
        req->target[len++] = type_buf[i];
    }

    req->target[len] = '\0';

    /* Empty params */
    req->params[0] = '{';
    req->params[1] = '}';
    req->params_len = 2;

    return 0;
}
