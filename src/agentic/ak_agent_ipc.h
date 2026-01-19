/*
 * Authority Kernel - Multi-Agent IPC
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Implements secure message passing between agents with capability-gated
 * access control. Provides mailbox-based communication with support for
 * agent hierarchies (parent/child relationships).
 *
 * SECURITY MODEL:
 *   - Messages are capability-gated (require AK_CAP_IPC)
 *   - Parent agents can always message children
 *   - Children can always message parent
 *   - Peer messaging requires explicit IPC capability
 *   - Messages are copied, not shared (isolation)
 *   - Messages include sender run_id for authentication
 *
 * INVARIANTS:
 *   INV-IPC-1: No message delivery without valid capability
 *   INV-IPC-2: Messages are isolated copies (no shared memory)
 *   INV-IPC-3: Sender identity is unforgeable (run_id verified)
 */

#ifndef AK_AGENT_IPC_H
#define AK_AGENT_IPC_H

#include "ak_types.h"

/* ============================================================
 * CONSTANTS
 * ============================================================ */

#define AK_IPC_MAX_NAME_LEN         64      /* Max agent name length */
#define AK_IPC_MAX_PAYLOAD_SIZE     (64 * 1024)  /* 64KB max message */
#define AK_IPC_DEFAULT_INBOX_LIMIT  100     /* Default max messages per mailbox */
#define AK_IPC_MAX_AGENTS           1024    /* Max registered agents */
#define AK_IPC_BROADCAST_LIMIT      100     /* Max broadcast recipients */

/* Message type constants (application-defined, but some reserved) */
#define AK_IPC_MSG_TYPE_CUSTOM      0x0000  /* Application-defined message */
#define AK_IPC_MSG_TYPE_REQUEST     0x0001  /* Request (expects response) */
#define AK_IPC_MSG_TYPE_RESPONSE    0x0002  /* Response to request */
#define AK_IPC_MSG_TYPE_NOTIFY      0x0003  /* One-way notification */
#define AK_IPC_MSG_TYPE_BROADCAST   0x0004  /* Broadcast message */
#define AK_IPC_MSG_TYPE_SHUTDOWN    0x0005  /* Shutdown notification */
#define AK_IPC_MSG_TYPE_PING        0x0006  /* Ping for presence check */
#define AK_IPC_MSG_TYPE_PONG        0x0007  /* Pong response */

/* Message flags */
#define AK_IPC_FLAG_URGENT          0x0001  /* High priority */
#define AK_IPC_FLAG_NEEDS_REPLY     0x0002  /* Sender expects reply */
#define AK_IPC_FLAG_BROADCAST       0x0004  /* Was part of broadcast */
#define AK_IPC_FLAG_FROM_PARENT     0x0008  /* From parent agent */
#define AK_IPC_FLAG_FROM_CHILD      0x0010  /* From child agent */
#define AK_IPC_FLAG_ENCRYPTED       0x0020  /* Payload is encrypted */

/* ============================================================
 * ERROR CODES
 * ============================================================ */

#define AK_E_IPC_NOT_INIT           (-4600)  /* IPC subsystem not initialized */
#define AK_E_IPC_NO_MAILBOX         (-4601)  /* Agent has no mailbox */
#define AK_E_IPC_MAILBOX_FULL       (-4602)  /* Recipient mailbox full */
#define AK_E_IPC_NO_RECIPIENT       (-4603)  /* Recipient not found */
#define AK_E_IPC_MSG_TOO_LARGE      (-4604)  /* Message exceeds limit */
#define AK_E_IPC_NOT_REGISTERED     (-4605)  /* Agent not registered */
#define AK_E_IPC_ALREADY_REGISTERED (-4606)  /* Agent already registered */
#define AK_E_IPC_NO_CAPABILITY      (-4607)  /* Missing IPC capability */
#define AK_E_IPC_NO_MESSAGES        (-4608)  /* No messages available */
#define AK_E_IPC_PEER_DENIED        (-4609)  /* Peer messaging denied */
#define AK_E_IPC_NAME_EXISTS        (-4610)  /* Agent name already exists */
#define AK_E_IPC_NAME_TOO_LONG      (-4611)  /* Agent name too long */

/* ============================================================
 * AGENT IPC MESSAGE
 * ============================================================
 * Message structure for inter-agent communication.
 * Messages are copied during send/receive for isolation.
 */

typedef struct ak_ipc_message {
    /* Message identity */
    u64 msg_id;                     /* Unique message ID */

    /* Sender identity */
    u64 sender_pid;                 /* Sender's process/agent ID */
    u8 sender_run_id[16];           /* Sender's run ID for authentication */

    /* Recipient identity */
    u64 receiver_pid;               /* Intended recipient PID */

    /* Timing */
    u64 timestamp_ns;               /* Send timestamp (nanoseconds) */

    /* Message metadata */
    u32 msg_type;                   /* Application-defined message type */
    u32 flags;                      /* Message flags */

    /* Correlation (for request/response) */
    u64 correlation_id;             /* Links response to request */

    /* Payload */
    buffer payload;                 /* Message content */

    /* Linked list for mailbox queue */
    struct ak_ipc_message *next;
} ak_ipc_message_t;

/* ============================================================
 * AGENT MAILBOX
 * ============================================================
 * Per-agent message queue with bounded capacity.
 * Thread-safe via spin lock.
 */

typedef struct ak_agent_mailbox {
    /* Owner identity */
    u64 agent_pid;                  /* Owning agent's PID */

    /* Message queue (singly linked list) */
    ak_ipc_message_t *inbox_head;   /* First message in queue */
    ak_ipc_message_t *inbox_tail;   /* Last message in queue */
    u32 inbox_count;                /* Current message count */
    u32 inbox_limit;                /* Maximum messages allowed */

    /* Urgent message tracking */
    u32 urgent_count;               /* Count of urgent messages */

    /* Statistics */
    u64 messages_received;          /* Total messages received */
    u64 messages_dropped;           /* Messages dropped (mailbox full) */

    /* Synchronization */
    u64 lock;                       /* Spin lock for thread safety */

    /* Waiting threads (for blocking receive) */
    volatile u32 waiter_count;      /* Number of threads waiting for messages */
    volatile boolean wake_pending;  /* Wake signal pending for waiters */
} ak_agent_mailbox_t;

/* ============================================================
 * AGENT REGISTRY ENTRY
 * ============================================================
 * Registry of all agents available for IPC.
 * Supports agent discovery by name.
 */

typedef struct ak_agent_registry_entry {
    /* Identity */
    u64 pid;                        /* Process/agent ID */
    u8 run_id[16];                  /* Current run ID */

    /* Naming */
    char name[AK_IPC_MAX_NAME_LEN]; /* Human-readable agent name */

    /* Mailbox reference */
    ak_agent_mailbox_t *mailbox;    /* Agent's mailbox */

    /* Hierarchy */
    u64 parent_pid;                 /* Parent agent PID (0 if root) */
    u64 *child_pids;                /* Array of child PIDs */
    u32 child_count;                /* Number of children */
    u32 child_capacity;             /* Allocated capacity for children */

    /* Discovery */
    boolean discoverable;           /* Allow other agents to find via name */

    /* State */
    boolean active;                 /* Agent is currently active */
    u64 registered_ns;              /* Registration timestamp */

    /* Capabilities granted to this agent */
    boolean has_ipc_cap;            /* Has general IPC capability */
    boolean has_broadcast_cap;      /* Can broadcast messages */

    /* Fine-grained peer access control */
    u64 *allowed_peer_pids;         /* Array of allowed peer PIDs (NULL = any) */
    u32 allowed_peer_count;         /* Number of allowed peers */
    u32 allowed_peer_capacity;      /* Allocated capacity for peer array */

    /* Hash table linkage */
    struct ak_agent_registry_entry *next;
} ak_agent_registry_entry_t;

/* ============================================================
 * AGENT IPC CONTEXT
 * ============================================================
 * Per-context IPC state, linked to ak_agent_context_t.
 */

typedef struct ak_agent_ipc_ctx {
    /* Link to agent context */
    ak_agent_context_t *agent;

    /* Registry entry for this agent */
    ak_agent_registry_entry_t *entry;

    /* Message ID counter */
    u64 next_msg_id;

    /* Capabilities */
    ak_capability_t *ipc_cap;       /* IPC capability */

    /* Heap for allocations */
    heap h;
} ak_agent_ipc_ctx_t;

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

/*
 * Initialize the agent IPC subsystem.
 *
 * PRECONDITIONS:
 *   - h must be a valid heap
 *   - Must be called once before any IPC operations
 *
 * POSTCONDITIONS:
 *   - IPC subsystem is ready for use
 *   - Agent registry is initialized
 *
 * @param h     Heap for internal allocations
 * @return      0 on success, negative error on failure
 */
int ak_agent_ipc_init(heap h);

/*
 * Shutdown the agent IPC subsystem.
 *
 * PRECONDITIONS:
 *   - ak_agent_ipc_init() was called
 *
 * POSTCONDITIONS:
 *   - All mailboxes are freed
 *   - All pending messages are freed
 *   - Registry is cleared
 */
void ak_agent_ipc_shutdown(void);

/* ============================================================
 * AGENT REGISTRATION
 * ============================================================ */

/*
 * Register an agent in the IPC registry.
 *
 * Creates a mailbox for the agent and makes it available for IPC.
 * If discoverable is true, other agents can find this agent by name.
 *
 * SECURITY: Requires valid agent context with IPC capability for
 *           discoverable agents.
 *
 * @param ctx           Agent context
 * @param name          Human-readable name (max 63 chars)
 * @param discoverable  Allow discovery by name
 * @return              0 on success, negative error on failure
 *
 * Errors:
 *   AK_E_IPC_NOT_INIT           - IPC not initialized
 *   AK_E_IPC_ALREADY_REGISTERED - Agent already registered
 *   AK_E_IPC_NAME_EXISTS        - Name already taken
 *   AK_E_IPC_NAME_TOO_LONG      - Name exceeds limit
 *   -ENOMEM                     - Allocation failed
 */
int ak_agent_register(
    ak_agent_context_t *ctx,
    const char *name,
    boolean discoverable
);

/*
 * Unregister an agent from the IPC registry.
 *
 * Frees the agent's mailbox and removes from registry.
 * Pending messages are discarded.
 *
 * @param ctx   Agent context
 * @return      0 on success, negative error on failure
 *
 * Errors:
 *   AK_E_IPC_NOT_REGISTERED - Agent not registered
 */
int ak_agent_unregister(ak_agent_context_t *ctx);

/* ============================================================
 * MESSAGE SENDING
 * ============================================================ */

/*
 * Send a message to another agent.
 *
 * The message payload is copied during send (isolation).
 * Sender identity is recorded from ctx for authentication.
 *
 * SECURITY:
 *   - Parent can message children without capability
 *   - Children can message parent without capability
 *   - Peer messaging requires IPC capability
 *
 * @param ctx           Sender's agent context
 * @param receiver_pid  Recipient's PID
 * @param msg_type      Application-defined message type
 * @param flags         Message flags
 * @param payload       Message payload (copied)
 * @return              Message ID on success, negative error on failure
 *
 * Errors:
 *   AK_E_IPC_NOT_REGISTERED - Sender not registered
 *   AK_E_IPC_NO_RECIPIENT   - Recipient not found
 *   AK_E_IPC_MAILBOX_FULL   - Recipient's mailbox is full
 *   AK_E_IPC_MSG_TOO_LARGE  - Payload exceeds limit
 *   AK_E_IPC_NO_CAPABILITY  - Missing IPC capability for peer
 *   AK_E_IPC_PEER_DENIED    - Peer messaging denied by policy
 */
s64 ak_ipc_send(
    ak_agent_context_t *ctx,
    u64 receiver_pid,
    u32 msg_type,
    u32 flags,
    buffer payload
);

/*
 * Send a request message and get correlation ID.
 *
 * Convenience wrapper that sets NEEDS_REPLY flag and returns
 * the message ID as correlation ID for matching response.
 *
 * @param ctx           Sender's agent context
 * @param receiver_pid  Recipient's PID
 * @param msg_type      Request type
 * @param payload       Request payload
 * @param correlation_out  Output: correlation ID for response matching
 * @return              0 on success, negative error on failure
 */
int ak_ipc_send_request(
    ak_agent_context_t *ctx,
    u64 receiver_pid,
    u32 msg_type,
    buffer payload,
    u64 *correlation_out
);

/*
 * Send a response to a previous request.
 *
 * Sets the correlation_id to match the original request.
 *
 * @param ctx           Sender's agent context
 * @param receiver_pid  Original requester's PID
 * @param correlation_id  ID from original request
 * @param payload       Response payload
 * @return              0 on success, negative error on failure
 */
int ak_ipc_send_response(
    ak_agent_context_t *ctx,
    u64 receiver_pid,
    u64 correlation_id,
    buffer payload
);

/*
 * Broadcast a message to all discoverable agents.
 *
 * SECURITY: Requires broadcast capability.
 * Messages are sent to all discoverable agents except sender.
 *
 * @param ctx       Sender's agent context
 * @param msg_type  Message type
 * @param flags     Message flags (BROADCAST flag auto-added)
 * @param payload   Message payload (copied to each recipient)
 * @return          Number of recipients on success, negative error on failure
 *
 * Errors:
 *   AK_E_IPC_NO_CAPABILITY - Missing broadcast capability
 */
s64 ak_ipc_broadcast(
    ak_agent_context_t *ctx,
    u32 msg_type,
    u32 flags,
    buffer payload
);

/* ============================================================
 * MESSAGE RECEIVING
 * ============================================================ */

/*
 * Receive a message (blocking with timeout).
 *
 * Waits for a message up to timeout_ms milliseconds.
 * The returned message is owned by caller and must be freed.
 *
 * @param ctx        Agent context
 * @param timeout_ms Timeout in milliseconds (0 = no wait, -1 = forever)
 * @return           Message on success, NULL on timeout/error
 *
 * Use ak_ipc_message_free() to free the returned message.
 */
ak_ipc_message_t *ak_ipc_recv(
    ak_agent_context_t *ctx,
    s32 timeout_ms
);

/*
 * Receive a message with specific correlation ID (for responses).
 *
 * Waits for a message matching the given correlation ID.
 * Useful for request/response patterns.
 *
 * @param ctx            Agent context
 * @param correlation_id Expected correlation ID
 * @param timeout_ms     Timeout in milliseconds
 * @return               Matching message or NULL on timeout
 */
ak_ipc_message_t *ak_ipc_recv_correlated(
    ak_agent_context_t *ctx,
    u64 correlation_id,
    s32 timeout_ms
);

/*
 * Peek at the mailbox without removing messages.
 *
 * Returns the number of messages waiting in the mailbox.
 *
 * @param ctx   Agent context
 * @return      Number of messages (0 if empty), negative on error
 */
s64 ak_ipc_peek(ak_agent_context_t *ctx);

/*
 * Check if any urgent messages are waiting.
 *
 * @param ctx   Agent context
 * @return      Number of urgent messages, negative on error
 */
s64 ak_ipc_peek_urgent(ak_agent_context_t *ctx);

/*
 * Free a received message.
 *
 * @param h     Heap used for allocation
 * @param msg   Message to free
 */
void ak_ipc_message_free(heap h, ak_ipc_message_t *msg);

/* ============================================================
 * AGENT DISCOVERY
 * ============================================================ */

/*
 * Discover agents by name pattern.
 *
 * Searches the registry for agents matching the pattern.
 * Only returns discoverable agents.
 *
 * Pattern syntax:
 *   "exact"      - Exact match
 *   "*suffix"    - Ends with suffix
 *   "prefix*"    - Starts with prefix
 *   "*"          - All discoverable agents
 *
 * @param pattern   Name pattern to match
 * @param pids_out  Output array for matching PIDs
 * @param max_pids  Maximum PIDs to return
 * @return          Number of matches found, negative on error
 */
s64 ak_agent_discover(
    const char *pattern,
    u64 *pids_out,
    u32 max_pids
);

/*
 * Get agent name by PID.
 *
 * @param pid       Agent PID
 * @param name_out  Output buffer for name
 * @param max_len   Buffer size
 * @return          0 on success, negative on error
 */
int ak_agent_get_name(
    u64 pid,
    char *name_out,
    u32 max_len
);

/*
 * Check if agent is discoverable.
 *
 * @param pid   Agent PID
 * @return      true if discoverable, false otherwise
 */
boolean ak_agent_is_discoverable(u64 pid);

/* ============================================================
 * AGENT HIERARCHY
 * ============================================================ */

/*
 * Get the parent agent PID.
 *
 * @param ctx   Agent context
 * @return      Parent PID (0 if root agent), negative on error
 */
s64 ak_agent_get_parent(ak_agent_context_t *ctx);

/*
 * Get child agent PIDs.
 *
 * @param ctx        Agent context
 * @param pids_out   Output array for child PIDs
 * @param max_pids   Maximum PIDs to return
 * @return           Number of children, negative on error
 */
s64 ak_agent_get_children(
    ak_agent_context_t *ctx,
    u64 *pids_out,
    u32 max_pids
);

/*
 * Register a child relationship.
 *
 * Called when a child agent is spawned.
 *
 * @param parent_ctx  Parent agent context
 * @param child_pid   Child agent PID
 * @return            0 on success, negative on error
 */
int ak_agent_add_child(
    ak_agent_context_t *parent_ctx,
    u64 child_pid
);

/*
 * Remove a child relationship.
 *
 * Called when a child agent terminates.
 *
 * @param parent_ctx  Parent agent context
 * @param child_pid   Child agent PID
 * @return            0 on success, negative on error
 */
int ak_agent_remove_child(
    ak_agent_context_t *parent_ctx,
    u64 child_pid
);

/*
 * Check if sender is parent of receiver.
 *
 * @param sender_pid    Potential parent PID
 * @param receiver_pid  Potential child PID
 * @return              true if parent relationship exists
 */
boolean ak_agent_is_parent_of(u64 sender_pid, u64 receiver_pid);

/*
 * Check if sender is child of receiver.
 *
 * @param sender_pid    Potential child PID
 * @param receiver_pid  Potential parent PID
 * @return              true if child relationship exists
 */
boolean ak_agent_is_child_of(u64 sender_pid, u64 receiver_pid);

/* ============================================================
 * MAILBOX MANAGEMENT
 * ============================================================ */

/*
 * Set mailbox capacity limit.
 *
 * @param ctx    Agent context
 * @param limit  Maximum messages (1-10000)
 * @return       0 on success, negative on error
 */
int ak_ipc_set_inbox_limit(
    ak_agent_context_t *ctx,
    u32 limit
);

/*
 * Get mailbox statistics.
 *
 * @param ctx        Agent context
 * @param count_out  Output: current message count
 * @param limit_out  Output: maximum messages
 * @param received_out Output: total messages received
 * @param dropped_out Output: messages dropped due to full mailbox
 * @return           0 on success, negative on error
 */
int ak_ipc_get_mailbox_stats(
    ak_agent_context_t *ctx,
    u32 *count_out,
    u32 *limit_out,
    u64 *received_out,
    u64 *dropped_out
);

/*
 * Clear all messages from mailbox.
 *
 * @param ctx   Agent context
 * @return      Number of messages cleared, negative on error
 */
s64 ak_ipc_clear_mailbox(ak_agent_context_t *ctx);

/* ============================================================
 * CAPABILITY INTEGRATION
 * ============================================================ */

/*
 * Grant IPC capability to an agent.
 *
 * @param ctx       Agent context to grant capability to
 * @param peer_pids Array of allowed peer PIDs (NULL for any)
 * @param peer_count Number of peer PIDs (0 for any)
 * @param can_broadcast Allow broadcast messages
 * @return          0 on success, negative on error
 */
int ak_ipc_grant_capability(
    ak_agent_context_t *ctx,
    u64 *peer_pids,
    u32 peer_count,
    boolean can_broadcast
);

/*
 * Revoke IPC capability from an agent.
 *
 * @param ctx   Agent context
 * @return      0 on success, negative on error
 */
int ak_ipc_revoke_capability(ak_agent_context_t *ctx);

/*
 * Check if agent has IPC capability for a peer.
 *
 * @param ctx       Agent context
 * @param peer_pid  Target peer PID
 * @return          true if allowed, false if denied
 */
boolean ak_ipc_has_capability(ak_agent_context_t *ctx, u64 peer_pid);

/* ============================================================
 * STATISTICS
 * ============================================================ */

typedef struct ak_agent_ipc_stats {
    /* Registration */
    u64 agents_registered;
    u64 agents_unregistered;
    u64 agents_active;

    /* Messages */
    u64 messages_sent;
    u64 messages_received;
    u64 messages_dropped;
    u64 messages_broadcast;

    /* Errors */
    u64 send_failures;
    u64 recv_timeouts;
    u64 capability_denials;
    u64 peer_denials;

    /* Discovery */
    u64 discover_requests;
    u64 discover_matches;
} ak_agent_ipc_stats_t;

/*
 * Get IPC subsystem statistics.
 *
 * @param stats Output statistics structure
 */
void ak_agent_ipc_get_stats(ak_agent_ipc_stats_t *stats);

/* ============================================================
 * EFFECT TYPE FOR INTEGRATION
 * ============================================================ */

/* Effect operation type for agent send (add to ak_effect_op enum) */
#define AK_E_AGENT_SEND     0x0403  /* Send message to another agent */

/*
 * Build effect request for agent send.
 *
 * @param req           Output effect request
 * @param ctx           AK context
 * @param receiver_pid  Target agent PID
 * @param msg_type      Message type
 * @return              0 on success, negative on error
 */
int ak_effect_from_agent_send(
    struct ak_effect_req *req,
    struct ak_ctx *ctx,
    u64 receiver_pid,
    u32 msg_type
);

#endif /* AK_AGENT_IPC_H */
