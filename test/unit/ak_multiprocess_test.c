/*
 * Authority Kernel - Multi-Process Security Boundaries Unit Tests
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Comprehensive tests for multi-agent security boundaries:
 * - Agent spawning (parent-child relationships)
 * - Inter-agent messaging (SEND/RECV operations)
 * - Agent registry management
 * - Agent lifecycle (spawn, run, crash, timeout, exit)
 * - Capability delegation between agents
 *
 * SECURITY INVARIANTS TESTED:
 *   INV-MP-1: Agent isolation (no cross-agent access)
 *   INV-MP-2: PID verification (sender identity unforgeable)
 *   INV-MP-3: Run ID binding (messages bound to current run)
 *   INV-MP-4: Capability scope limits (delegation constraints)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

/* ============================================================
 * TEST ASSERTION MACROS
 * ============================================================ */

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

#define test_assert_null(ptr) do { \
    if ((ptr) != NULL) { \
        fprintf(stderr, "FAIL: %s is not NULL at %s:%d\n", #ptr, __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

#define test_assert_not_null(ptr) do { \
    if ((ptr) == NULL) { \
        fprintf(stderr, "FAIL: %s is NULL at %s:%d\n", #ptr, __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

#define test_assert_str_eq(a, b) do { \
    if (strcmp((a), (b)) != 0) { \
        fprintf(stderr, "FAIL: %s != %s (\"%s\" != \"%s\") at %s:%d\n", \
                #a, #b, (a), (b), __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

/* ============================================================
 * CONSTANTS
 * ============================================================ */

#define AK_MAX_AGENTS           64
#define AK_TOKEN_ID_SIZE        16
#define AK_MAX_NAME_LEN         64
#define AK_MAX_PAYLOAD_SIZE     (64 * 1024)
#define AK_DEFAULT_INBOX_LIMIT  100
#define AK_MAX_CHILDREN         32
#define AK_MAX_MESSAGES         256
#define AK_MAC_SIZE             32

/* Error codes */
#define AK_E_IPC_NOT_INIT           (-4600)
#define AK_E_IPC_NO_MAILBOX         (-4601)
#define AK_E_IPC_MAILBOX_FULL       (-4602)
#define AK_E_IPC_NO_RECIPIENT       (-4603)
#define AK_E_IPC_MSG_TOO_LARGE      (-4604)
#define AK_E_IPC_NOT_REGISTERED     (-4605)
#define AK_E_IPC_ALREADY_REGISTERED (-4606)
#define AK_E_IPC_NO_CAPABILITY      (-4607)
#define AK_E_IPC_NO_MESSAGES        (-4608)
#define AK_E_IPC_PEER_DENIED        (-4609)
#define AK_E_IPC_NAME_EXISTS        (-4610)
#define AK_E_IPC_NAME_TOO_LONG      (-4611)
#define AK_E_MAX_AGENTS_EXCEEDED    (-4620)
#define AK_E_SPAWN_DENIED           (-4621)
#define AK_E_BUDGET_EXCEEDED        (-4300)
#define AK_E_CAP_INVALID            (-4101)
#define AK_E_CAP_SCOPE              (-4103)
#define AK_E_CAP_REVOKED            (-4104)

/* Message flags */
#define AK_IPC_FLAG_URGENT          0x0001
#define AK_IPC_FLAG_NEEDS_REPLY     0x0002
#define AK_IPC_FLAG_BROADCAST       0x0004
#define AK_IPC_FLAG_FROM_PARENT     0x0008
#define AK_IPC_FLAG_FROM_CHILD      0x0010

/* Message types */
#define AK_IPC_MSG_TYPE_CUSTOM      0x0000
#define AK_IPC_MSG_TYPE_REQUEST     0x0001
#define AK_IPC_MSG_TYPE_RESPONSE    0x0002
#define AK_IPC_MSG_TYPE_NOTIFY      0x0003

/* Capability types */
typedef enum ak_cap_type {
    AK_CAP_NONE     = 0,
    AK_CAP_NET      = 1,
    AK_CAP_FS       = 2,
    AK_CAP_TOOL     = 3,
    AK_CAP_SPAWN    = 5,
    AK_CAP_IPC      = 8,
    AK_CAP_ADMIN    = 255,
} ak_cap_type_t;

/* Agent lifecycle states */
typedef enum agent_state {
    AGENT_STATE_INIT = 0,
    AGENT_STATE_RUNNING,
    AGENT_STATE_EXITED,
    AGENT_STATE_CRASHED,
    AGENT_STATE_TIMEOUT,
} agent_state_t;

/* ============================================================
 * MOCK STRUCTURES
 * ============================================================ */

typedef struct mock_capability {
    ak_cap_type_t type;
    uint8_t resource[256];
    uint32_t resource_len;
    uint64_t issued_ms;
    uint32_t ttl_ms;
    uint8_t run_id[AK_TOKEN_ID_SIZE];
    uint8_t tid[AK_TOKEN_ID_SIZE];
    uint8_t mac[AK_MAC_SIZE];
    bool revoked;
    bool delegated;
    uint64_t parent_pid;  /* PID of delegating agent */
} mock_capability_t;

typedef struct mock_message {
    uint64_t msg_id;
    uint64_t sender_pid;
    uint8_t sender_run_id[AK_TOKEN_ID_SIZE];
    uint64_t receiver_pid;
    uint64_t timestamp_ms;
    uint32_t msg_type;
    uint32_t flags;
    uint64_t correlation_id;
    uint8_t payload[AK_MAX_PAYLOAD_SIZE];
    uint32_t payload_len;
    struct mock_message *next;
} mock_message_t;

typedef struct mock_mailbox {
    mock_message_t *inbox_head;
    mock_message_t *inbox_tail;
    uint32_t inbox_count;
    uint32_t inbox_limit;
    uint32_t urgent_count;
    uint64_t messages_received;
    uint64_t messages_dropped;
} mock_mailbox_t;

typedef struct mock_budget {
    uint64_t tool_calls_limit;
    uint64_t tool_calls_used;
    uint64_t tokens_limit;
    uint64_t tokens_used;
    uint64_t spawn_limit;
    uint64_t spawn_used;
} mock_budget_t;

typedef struct mock_agent {
    uint64_t pid;
    uint8_t run_id[AK_TOKEN_ID_SIZE];
    char name[AK_MAX_NAME_LEN];

    /* Hierarchy */
    uint64_t parent_pid;
    uint64_t child_pids[AK_MAX_CHILDREN];
    uint32_t child_count;

    /* State */
    agent_state_t state;
    bool discoverable;
    uint64_t registered_ms;
    uint64_t exited_ms;

    /* IPC */
    mock_mailbox_t mailbox;
    bool has_ipc_cap;
    bool has_broadcast_cap;

    /* Capabilities */
    mock_capability_t *caps[16];
    uint32_t cap_count;

    /* Budget */
    mock_budget_t budget;

    /* Active flag */
    bool active;
} mock_agent_t;

/* ============================================================
 * MOCK GLOBAL STATE
 * ============================================================ */

static struct {
    bool initialized;
    mock_agent_t agents[AK_MAX_AGENTS];
    uint32_t agent_count;
    uint64_t next_pid;
    uint64_t next_msg_id;
    uint64_t current_time_ms;

    /* Event log for testing */
    struct {
        char events[256][128];
        int event_count;
    } audit;
} mock_state;

/* ============================================================
 * MOCK HELPER FUNCTIONS
 * ============================================================ */

static void mock_init(void)
{
    memset(&mock_state, 0, sizeof(mock_state));
    mock_state.initialized = true;
    mock_state.next_pid = 1000;
    mock_state.next_msg_id = 1;
    mock_state.current_time_ms = 1000000;
}

static void mock_shutdown(void)
{
    /* Free all allocated messages */
    for (uint32_t i = 0; i < AK_MAX_AGENTS; i++) {
        mock_agent_t *agent = &mock_state.agents[i];
        if (agent->active) {
            mock_message_t *msg = agent->mailbox.inbox_head;
            while (msg) {
                mock_message_t *next = msg->next;
                free(msg);
                msg = next;
            }
            /* Free capabilities */
            for (uint32_t j = 0; j < agent->cap_count; j++) {
                free(agent->caps[j]);
            }
        }
    }
    memset(&mock_state, 0, sizeof(mock_state));
}

__attribute__((format(printf, 1, 2)))
static void mock_log_event(const char *fmt, ...)
{
    if (mock_state.audit.event_count < 256) {
        va_list args;
        va_start(args, fmt);
        vsnprintf(mock_state.audit.events[mock_state.audit.event_count],
                  128, fmt, args);
        va_end(args);
        mock_state.audit.event_count++;
    }
}

static void mock_generate_run_id(uint8_t *run_id)
{
    for (int i = 0; i < AK_TOKEN_ID_SIZE; i++) {
        run_id[i] = (uint8_t)(rand() & 0xFF);
    }
}

static mock_agent_t *mock_find_agent(uint64_t pid)
{
    for (uint32_t i = 0; i < AK_MAX_AGENTS; i++) {
        if (mock_state.agents[i].active && mock_state.agents[i].pid == pid) {
            return &mock_state.agents[i];
        }
    }
    return NULL;
}

static mock_agent_t *mock_find_agent_by_name(const char *name)
{
    for (uint32_t i = 0; i < AK_MAX_AGENTS; i++) {
        if (mock_state.agents[i].active &&
            strcmp(mock_state.agents[i].name, name) == 0) {
            return &mock_state.agents[i];
        }
    }
    return NULL;
}

/* ============================================================
 * MOCK AGENT OPERATIONS
 * ============================================================ */

static int64_t mock_agent_spawn(mock_agent_t *parent, const char *name,
                                 mock_budget_t *child_budget)
{
    if (!mock_state.initialized)
        return AK_E_IPC_NOT_INIT;

    if (!parent)
        return -1;

    /* Check spawn capability */
    bool has_spawn_cap = false;
    for (uint32_t i = 0; i < parent->cap_count; i++) {
        if (parent->caps[i] && parent->caps[i]->type == AK_CAP_SPAWN &&
            !parent->caps[i]->revoked) {
            has_spawn_cap = true;
            break;
        }
    }
    if (!has_spawn_cap)
        return AK_E_SPAWN_DENIED;

    /* Check agent limit */
    if (mock_state.agent_count >= AK_MAX_AGENTS)
        return AK_E_MAX_AGENTS_EXCEEDED;

    /* Check parent's spawn budget */
    if (parent->budget.spawn_limit > 0 &&
        parent->budget.spawn_used >= parent->budget.spawn_limit)
        return AK_E_BUDGET_EXCEEDED;

    /* Check name uniqueness */
    if (mock_find_agent_by_name(name))
        return AK_E_IPC_NAME_EXISTS;

    /* Check name length */
    if (strlen(name) >= AK_MAX_NAME_LEN)
        return AK_E_IPC_NAME_TOO_LONG;

    /* Check max children */
    if (parent->child_count >= AK_MAX_CHILDREN)
        return AK_E_MAX_AGENTS_EXCEEDED;

    /* Find free slot */
    mock_agent_t *child = NULL;
    for (uint32_t i = 0; i < AK_MAX_AGENTS; i++) {
        if (!mock_state.agents[i].active) {
            child = &mock_state.agents[i];
            break;
        }
    }
    if (!child)
        return AK_E_MAX_AGENTS_EXCEEDED;

    /* Initialize child */
    memset(child, 0, sizeof(mock_agent_t));
    child->pid = mock_state.next_pid++;
    mock_generate_run_id(child->run_id);
    strncpy(child->name, name, AK_MAX_NAME_LEN - 1);
    child->parent_pid = parent->pid;
    child->state = AGENT_STATE_RUNNING;
    child->discoverable = true;
    child->registered_ms = mock_state.current_time_ms;
    child->active = true;
    child->mailbox.inbox_limit = AK_DEFAULT_INBOX_LIMIT;

    /* Attenuate budget from parent */
    if (child_budget) {
        child->budget = *child_budget;
        /* Child budget cannot exceed parent remaining */
        if (child->budget.tool_calls_limit >
            parent->budget.tool_calls_limit - parent->budget.tool_calls_used) {
            child->budget.tool_calls_limit =
                parent->budget.tool_calls_limit - parent->budget.tool_calls_used;
        }
    }

    /* Add child to parent's list */
    parent->child_pids[parent->child_count++] = child->pid;
    parent->budget.spawn_used++;

    mock_state.agent_count++;

    mock_log_event("SPAWN: parent=%llu child=%llu name=%s",
                   parent->pid, child->pid, name);

    return (int64_t)child->pid;
}

static int mock_agent_register(mock_agent_t *agent, const char *name, bool discoverable)
{
    if (!mock_state.initialized)
        return AK_E_IPC_NOT_INIT;

    if (!agent || !name)
        return -1;

    if (strlen(name) >= AK_MAX_NAME_LEN)
        return AK_E_IPC_NAME_TOO_LONG;

    if (agent->active)
        return AK_E_IPC_ALREADY_REGISTERED;

    /* Check name uniqueness if discoverable */
    if (discoverable && mock_find_agent_by_name(name))
        return AK_E_IPC_NAME_EXISTS;

    strncpy(agent->name, name, AK_MAX_NAME_LEN - 1);
    agent->discoverable = discoverable;
    agent->registered_ms = mock_state.current_time_ms;
    agent->state = AGENT_STATE_RUNNING;
    agent->active = true;
    agent->mailbox.inbox_limit = AK_DEFAULT_INBOX_LIMIT;

    mock_state.agent_count++;

    return 0;
}

static int mock_agent_unregister(mock_agent_t *agent)
{
    if (!mock_state.initialized)
        return AK_E_IPC_NOT_INIT;

    if (!agent || !agent->active)
        return AK_E_IPC_NOT_REGISTERED;

    /* Free mailbox messages */
    mock_message_t *msg = agent->mailbox.inbox_head;
    while (msg) {
        mock_message_t *next = msg->next;
        free(msg);
        msg = next;
    }
    agent->mailbox.inbox_head = NULL;
    agent->mailbox.inbox_tail = NULL;
    agent->mailbox.inbox_count = 0;

    agent->active = false;
    agent->state = AGENT_STATE_EXITED;
    agent->exited_ms = mock_state.current_time_ms;
    mock_state.agent_count--;

    mock_log_event("EXIT: agent=%llu", agent->pid);

    return 0;
}

static bool mock_is_parent_of(uint64_t sender_pid, uint64_t receiver_pid)
{
    mock_agent_t *receiver = mock_find_agent(receiver_pid);
    return receiver && receiver->parent_pid == sender_pid;
}

static bool mock_is_child_of(uint64_t sender_pid, uint64_t receiver_pid)
{
    mock_agent_t *sender = mock_find_agent(sender_pid);
    return sender && sender->parent_pid == receiver_pid;
}

/* ============================================================
 * MOCK MESSAGE OPERATIONS
 * ============================================================ */

static int64_t mock_ipc_send(mock_agent_t *sender, uint64_t receiver_pid,
                              uint32_t msg_type, uint32_t flags,
                              const uint8_t *payload, uint32_t payload_len)
{
    if (!mock_state.initialized)
        return AK_E_IPC_NOT_INIT;

    if (!sender || !sender->active)
        return AK_E_IPC_NOT_REGISTERED;

    if (payload_len > AK_MAX_PAYLOAD_SIZE)
        return AK_E_IPC_MSG_TOO_LARGE;

    mock_agent_t *receiver = mock_find_agent(receiver_pid);
    if (!receiver || !receiver->active)
        return AK_E_IPC_NO_RECIPIENT;

    /* Check authorization */
    bool is_parent = mock_is_parent_of(sender->pid, receiver_pid);
    bool is_child = mock_is_child_of(sender->pid, receiver_pid);

    if (!is_parent && !is_child) {
        /* Peer messaging requires IPC capability */
        if (!sender->has_ipc_cap)
            return AK_E_IPC_NO_CAPABILITY;
    }

    /* Check mailbox capacity */
    if (receiver->mailbox.inbox_count >= receiver->mailbox.inbox_limit) {
        receiver->mailbox.messages_dropped++;
        return AK_E_IPC_MAILBOX_FULL;
    }

    /* Create message */
    mock_message_t *msg = calloc(1, sizeof(mock_message_t));
    if (!msg)
        return -1;

    msg->msg_id = mock_state.next_msg_id++;
    msg->sender_pid = sender->pid;
    memcpy(msg->sender_run_id, sender->run_id, AK_TOKEN_ID_SIZE);
    msg->receiver_pid = receiver_pid;
    msg->timestamp_ms = mock_state.current_time_ms;
    msg->msg_type = msg_type;
    msg->flags = flags;

    if (is_parent)
        msg->flags |= AK_IPC_FLAG_FROM_PARENT;
    if (is_child)
        msg->flags |= AK_IPC_FLAG_FROM_CHILD;

    if (payload && payload_len > 0) {
        memcpy(msg->payload, payload, payload_len);
        msg->payload_len = payload_len;
    }

    /* Enqueue */
    if (receiver->mailbox.inbox_tail) {
        receiver->mailbox.inbox_tail->next = msg;
    } else {
        receiver->mailbox.inbox_head = msg;
    }
    receiver->mailbox.inbox_tail = msg;
    receiver->mailbox.inbox_count++;
    receiver->mailbox.messages_received++;

    if (flags & AK_IPC_FLAG_URGENT)
        receiver->mailbox.urgent_count++;

    return (int64_t)msg->msg_id;
}

static mock_message_t *mock_ipc_recv(mock_agent_t *agent)
{
    if (!mock_state.initialized || !agent || !agent->active)
        return NULL;

    mock_message_t *msg = agent->mailbox.inbox_head;
    if (!msg)
        return NULL;

    /* Dequeue */
    agent->mailbox.inbox_head = msg->next;
    if (!agent->mailbox.inbox_head)
        agent->mailbox.inbox_tail = NULL;
    agent->mailbox.inbox_count--;

    if (msg->flags & AK_IPC_FLAG_URGENT)
        agent->mailbox.urgent_count--;

    msg->next = NULL;
    return msg;
}

static int mock_ipc_peek(mock_agent_t *agent)
{
    if (!mock_state.initialized || !agent || !agent->active)
        return AK_E_IPC_NO_MAILBOX;

    return (int)agent->mailbox.inbox_count;
}

/* ============================================================
 * MOCK CAPABILITY OPERATIONS
 * ============================================================ */

static mock_capability_t *mock_create_capability(mock_agent_t *agent,
                                                   ak_cap_type_t type,
                                                   const char *resource,
                                                   uint32_t ttl_ms)
{
    if (!agent || agent->cap_count >= 16)
        return NULL;

    mock_capability_t *cap = calloc(1, sizeof(mock_capability_t));
    if (!cap)
        return NULL;

    cap->type = type;
    if (resource) {
        size_t len = strlen(resource);
        if (len >= 256) len = 255;
        memcpy(cap->resource, resource, len);
        cap->resource_len = (uint32_t)len;
    }
    cap->issued_ms = mock_state.current_time_ms;
    cap->ttl_ms = ttl_ms;
    memcpy(cap->run_id, agent->run_id, AK_TOKEN_ID_SIZE);

    /* Generate token ID */
    for (int i = 0; i < AK_TOKEN_ID_SIZE; i++) {
        cap->tid[i] = (uint8_t)(rand() & 0xFF);
    }

    agent->caps[agent->cap_count++] = cap;
    return cap;
}

static int mock_delegate_capability(mock_agent_t *parent, mock_agent_t *child,
                                     mock_capability_t *cap)
{
    if (!parent || !child || !cap)
        return -1;

    if (child->cap_count >= 16)
        return AK_E_CAP_SCOPE;

    /* Verify cap belongs to parent */
    bool found = false;
    for (uint32_t i = 0; i < parent->cap_count; i++) {
        if (parent->caps[i] == cap) {
            found = true;
            break;
        }
    }
    if (!found)
        return AK_E_CAP_INVALID;

    /* Check revocation */
    if (cap->revoked)
        return AK_E_CAP_REVOKED;

    /* Create delegated copy for child */
    mock_capability_t *delegated = calloc(1, sizeof(mock_capability_t));
    if (!delegated)
        return -1;

    memcpy(delegated, cap, sizeof(mock_capability_t));
    delegated->delegated = true;
    delegated->parent_pid = parent->pid;
    memcpy(delegated->run_id, child->run_id, AK_TOKEN_ID_SIZE);

    child->caps[child->cap_count++] = delegated;

    mock_log_event("DELEGATE: cap=%d from=%llu to=%llu", cap->type, parent->pid, child->pid);

    return 0;
}

static void mock_revoke_capabilities(mock_agent_t *agent)
{
    for (uint32_t i = 0; i < agent->cap_count; i++) {
        if (agent->caps[i]) {
            agent->caps[i]->revoked = true;
        }
    }
    mock_log_event("REVOKE_ALL: agent=%llu", agent->pid);
}

/* ============================================================
 * MOCK LIFECYCLE OPERATIONS
 * ============================================================ */

static void mock_agent_crash(mock_agent_t *agent)
{
    if (!agent || !agent->active)
        return;

    /* Immediate capability revocation on crash */
    mock_revoke_capabilities(agent);

    agent->state = AGENT_STATE_CRASHED;
    agent->exited_ms = mock_state.current_time_ms;

    mock_log_event("CRASH: agent=%llu", agent->pid);

    /* Notify parent if exists */
    mock_agent_t *parent = mock_find_agent(agent->parent_pid);
    if (parent && parent->active) {
        const char *msg = "child_crashed";
        mock_ipc_send(agent, parent->pid, AK_IPC_MSG_TYPE_NOTIFY,
                      AK_IPC_FLAG_URGENT, (const uint8_t *)msg, (uint32_t)strlen(msg));
    }
}

static void mock_agent_timeout(mock_agent_t *agent)
{
    if (!agent || !agent->active)
        return;

    agent->state = AGENT_STATE_TIMEOUT;
    agent->exited_ms = mock_state.current_time_ms;

    /* Revoke capabilities on timeout */
    mock_revoke_capabilities(agent);

    mock_log_event("TIMEOUT: agent=%llu", agent->pid);
}

static void mock_agent_exit(mock_agent_t *agent, int exit_code)
{
    if (!agent || !agent->active)
        return;

    agent->state = AGENT_STATE_EXITED;
    agent->exited_ms = mock_state.current_time_ms;

    /* Revoke capabilities on exit */
    mock_revoke_capabilities(agent);

    /* Remove from parent's child list */
    mock_agent_t *parent = mock_find_agent(agent->parent_pid);
    if (parent) {
        for (uint32_t i = 0; i < parent->child_count; i++) {
            if (parent->child_pids[i] == agent->pid) {
                /* Shift remaining children */
                for (uint32_t j = i; j < parent->child_count - 1; j++) {
                    parent->child_pids[j] = parent->child_pids[j + 1];
                }
                parent->child_count--;
                break;
            }
        }
    }

    mock_log_event("EXIT: agent=%llu code=%d", agent->pid, exit_code);
}

/* ============================================================
 * TEST CASES: AGENT SPAWNING
 * ============================================================ */

bool test_spawn_child_agent(void)
{
    mock_init();

    /* Create parent with spawn capability */
    mock_agent_t *parent = &mock_state.agents[0];
    parent->pid = mock_state.next_pid++;
    mock_generate_run_id(parent->run_id);
    strncpy(parent->name, "parent", AK_MAX_NAME_LEN - 1);
    parent->active = true;
    parent->state = AGENT_STATE_RUNNING;
    parent->budget.spawn_limit = 10;
    mock_state.agent_count++;

    /* Grant spawn capability */
    mock_capability_t *spawn_cap = mock_create_capability(parent, AK_CAP_SPAWN, "*", 3600000);
    test_assert_not_null(spawn_cap);

    /* Spawn child */
    mock_budget_t child_budget = {.tool_calls_limit = 50};
    int64_t child_pid = mock_agent_spawn(parent, "child1", &child_budget);
    test_assert(child_pid > 0);

    /* Verify child created */
    mock_agent_t *child = mock_find_agent((uint64_t)child_pid);
    test_assert_not_null(child);
    test_assert_eq(child->parent_pid, parent->pid);
    test_assert_eq(child->state, AGENT_STATE_RUNNING);
    test_assert_str_eq(child->name, "child1");

    /* Verify parent has child in list */
    test_assert_eq(parent->child_count, 1);
    test_assert_eq(parent->child_pids[0], (uint64_t)child_pid);

    mock_shutdown();
    return true;
}

bool test_spawn_without_capability(void)
{
    mock_init();

    /* Create parent WITHOUT spawn capability */
    mock_agent_t *parent = &mock_state.agents[0];
    parent->pid = mock_state.next_pid++;
    mock_generate_run_id(parent->run_id);
    parent->active = true;
    parent->state = AGENT_STATE_RUNNING;
    mock_state.agent_count++;

    /* Try to spawn - should fail */
    int64_t result = mock_agent_spawn(parent, "child1", NULL);
    test_assert_eq(result, AK_E_SPAWN_DENIED);

    mock_shutdown();
    return true;
}

bool test_spawn_budget_enforcement(void)
{
    mock_init();

    mock_agent_t *parent = &mock_state.agents[0];
    parent->pid = mock_state.next_pid++;
    mock_generate_run_id(parent->run_id);
    parent->active = true;
    parent->state = AGENT_STATE_RUNNING;
    parent->budget.spawn_limit = 2;
    mock_state.agent_count++;

    mock_create_capability(parent, AK_CAP_SPAWN, "*", 3600000);

    /* Spawn first child - should succeed */
    int64_t child1 = mock_agent_spawn(parent, "child1", NULL);
    test_assert(child1 > 0);

    /* Spawn second child - should succeed */
    int64_t child2 = mock_agent_spawn(parent, "child2", NULL);
    test_assert(child2 > 0);

    /* Spawn third child - should fail (budget exceeded) */
    int64_t child3 = mock_agent_spawn(parent, "child3", NULL);
    test_assert_eq(child3, AK_E_BUDGET_EXCEEDED);

    mock_shutdown();
    return true;
}

bool test_spawn_max_agents_limit(void)
{
    mock_init();

    /*
     * Test that we hit the AK_MAX_AGENTS limit.
     * Since each parent can only have AK_MAX_CHILDREN children,
     * we need multiple parents to reach the global agent limit.
     */
    int total_spawned = 0;
    int parent_count = 0;

    /* Create enough parents to exceed AK_MAX_AGENTS */
    for (int p = 0; p < 3; p++) {  /* 3 parents can spawn up to 96 children */
        mock_agent_t *parent = &mock_state.agents[p];
        parent->pid = mock_state.next_pid++;
        mock_generate_run_id(parent->run_id);
        parent->active = true;
        parent->state = AGENT_STATE_RUNNING;
        parent->budget.spawn_limit = AK_MAX_AGENTS + 10;
        mock_state.agent_count++;
        parent_count++;

        mock_create_capability(parent, AK_CAP_SPAWN, "*", 3600000);

        /* Spawn children from this parent */
        for (int i = 0; i < AK_MAX_CHILDREN + 5; i++) {
            char name[64];
            snprintf(name, sizeof(name), "child_p%d_%d", p, i);
            int64_t result = mock_agent_spawn(parent, name, NULL);
            if (result > 0) {
                total_spawned++;
            } else {
                /* Hit either child limit or global agent limit */
                break;
            }
        }

        /* Stop if we've hit the global agent limit */
        if (mock_state.agent_count >= AK_MAX_AGENTS) break;
    }

    /* Should have spawned up to AK_MAX_AGENTS - parent_count total children */
    test_assert_eq((uint32_t)(total_spawned + parent_count), mock_state.agent_count);
    test_assert_eq(mock_state.agent_count, AK_MAX_AGENTS);

    mock_shutdown();
    return true;
}

bool test_spawn_policy_inheritance(void)
{
    mock_init();

    mock_agent_t *parent = &mock_state.agents[0];
    parent->pid = mock_state.next_pid++;
    mock_generate_run_id(parent->run_id);
    parent->active = true;
    parent->state = AGENT_STATE_RUNNING;
    parent->budget.spawn_limit = 10;
    parent->budget.tool_calls_limit = 100;
    mock_state.agent_count++;

    mock_create_capability(parent, AK_CAP_SPAWN, "*", 3600000);

    /* Spawn child with attenuated budget */
    mock_budget_t child_budget = {.tool_calls_limit = 50};
    int64_t child_pid = mock_agent_spawn(parent, "child", &child_budget);
    test_assert(child_pid > 0);

    mock_agent_t *child = mock_find_agent((uint64_t)child_pid);
    test_assert_not_null(child);

    /* Child budget should be limited */
    test_assert_eq(child->budget.tool_calls_limit, 50);

    mock_shutdown();
    return true;
}

bool test_spawn_budget_attenuation(void)
{
    mock_init();

    mock_agent_t *parent = &mock_state.agents[0];
    parent->pid = mock_state.next_pid++;
    mock_generate_run_id(parent->run_id);
    parent->active = true;
    parent->state = AGENT_STATE_RUNNING;
    parent->budget.spawn_limit = 10;
    parent->budget.tool_calls_limit = 100;
    parent->budget.tool_calls_used = 80;  /* Only 20 remaining */
    mock_state.agent_count++;

    mock_create_capability(parent, AK_CAP_SPAWN, "*", 3600000);

    /* Try to spawn child with more budget than parent has remaining */
    mock_budget_t child_budget = {.tool_calls_limit = 50};  /* Request 50 */
    int64_t child_pid = mock_agent_spawn(parent, "child", &child_budget);
    test_assert(child_pid > 0);

    mock_agent_t *child = mock_find_agent((uint64_t)child_pid);
    test_assert_not_null(child);

    /* Child budget should be attenuated to parent's remaining */
    test_assert_eq(child->budget.tool_calls_limit, 20);

    mock_shutdown();
    return true;
}

/* ============================================================
 * TEST CASES: INTER-AGENT MESSAGING
 * ============================================================ */

bool test_message_send_recv_basic(void)
{
    mock_init();

    /* Create two agents with parent-child relationship */
    mock_agent_t *parent = &mock_state.agents[0];
    parent->pid = 1000;
    mock_generate_run_id(parent->run_id);
    parent->active = true;
    parent->state = AGENT_STATE_RUNNING;
    mock_state.agent_count++;

    mock_agent_t *child = &mock_state.agents[1];
    child->pid = 1001;
    mock_generate_run_id(child->run_id);
    child->parent_pid = parent->pid;
    child->active = true;
    child->state = AGENT_STATE_RUNNING;
    child->mailbox.inbox_limit = 100;
    mock_state.agent_count++;

    parent->child_pids[0] = child->pid;
    parent->child_count = 1;

    /* Send message from parent to child */
    const char *payload = "Hello child!";
    int64_t msg_id = mock_ipc_send(parent, child->pid, AK_IPC_MSG_TYPE_NOTIFY,
                                    0, (const uint8_t *)payload, (uint32_t)strlen(payload));
    test_assert(msg_id > 0);

    /* Receive message */
    mock_message_t *msg = mock_ipc_recv(child);
    test_assert_not_null(msg);
    test_assert_eq(msg->sender_pid, parent->pid);
    test_assert_eq(msg->flags & AK_IPC_FLAG_FROM_PARENT, AK_IPC_FLAG_FROM_PARENT);
    test_assert_eq(msg->payload_len, strlen(payload));
    test_assert(memcmp(msg->payload, payload, msg->payload_len) == 0);

    free(msg);
    mock_shutdown();
    return true;
}

bool test_message_queue_ordering(void)
{
    mock_init();

    mock_agent_t *sender = &mock_state.agents[0];
    sender->pid = 1000;
    mock_generate_run_id(sender->run_id);
    sender->active = true;
    sender->has_ipc_cap = true;
    mock_state.agent_count++;

    mock_agent_t *receiver = &mock_state.agents[1];
    receiver->pid = 1001;
    mock_generate_run_id(receiver->run_id);
    receiver->active = true;
    receiver->mailbox.inbox_limit = 100;
    mock_state.agent_count++;

    /* Send multiple messages */
    for (int i = 0; i < 5; i++) {
        char payload[32];
        snprintf(payload, sizeof(payload), "msg_%d", i);
        mock_ipc_send(sender, receiver->pid, AK_IPC_MSG_TYPE_NOTIFY,
                      0, (const uint8_t *)payload, (uint32_t)strlen(payload));
    }

    /* Verify FIFO ordering */
    for (int i = 0; i < 5; i++) {
        mock_message_t *msg = mock_ipc_recv(receiver);
        test_assert_not_null(msg);

        char expected[32];
        snprintf(expected, sizeof(expected), "msg_%d", i);
        test_assert(memcmp(msg->payload, expected, strlen(expected)) == 0);

        free(msg);
    }

    mock_shutdown();
    return true;
}

bool test_message_queue_capacity(void)
{
    mock_init();

    mock_agent_t *sender = &mock_state.agents[0];
    sender->pid = 1000;
    mock_generate_run_id(sender->run_id);
    sender->active = true;
    sender->has_ipc_cap = true;
    mock_state.agent_count++;

    mock_agent_t *receiver = &mock_state.agents[1];
    receiver->pid = 1001;
    mock_generate_run_id(receiver->run_id);
    receiver->active = true;
    receiver->mailbox.inbox_limit = 5;  /* Small limit for testing */
    mock_state.agent_count++;

    /* Fill the queue */
    for (int i = 0; i < 5; i++) {
        int64_t result = mock_ipc_send(sender, receiver->pid, AK_IPC_MSG_TYPE_NOTIFY,
                                        0, (const uint8_t *)"test", 4);
        test_assert(result > 0);
    }

    /* Next send should fail */
    int64_t result = mock_ipc_send(sender, receiver->pid, AK_IPC_MSG_TYPE_NOTIFY,
                                    0, (const uint8_t *)"overflow", 8);
    test_assert_eq(result, AK_E_IPC_MAILBOX_FULL);

    /* Verify dropped message counter */
    test_assert_eq(receiver->mailbox.messages_dropped, 1);

    /* Drain queue and verify all messages received */
    for (int i = 0; i < 5; i++) {
        mock_message_t *msg = mock_ipc_recv(receiver);
        test_assert_not_null(msg);
        free(msg);
    }

    mock_shutdown();
    return true;
}

bool test_message_sender_verification(void)
{
    mock_init();

    mock_agent_t *sender = &mock_state.agents[0];
    sender->pid = 1000;
    mock_generate_run_id(sender->run_id);
    sender->active = true;
    sender->has_ipc_cap = true;
    mock_state.agent_count++;

    mock_agent_t *receiver = &mock_state.agents[1];
    receiver->pid = 1001;
    mock_generate_run_id(receiver->run_id);
    receiver->active = true;
    receiver->mailbox.inbox_limit = 100;
    mock_state.agent_count++;

    /* Send message */
    mock_ipc_send(sender, receiver->pid, AK_IPC_MSG_TYPE_NOTIFY,
                  0, (const uint8_t *)"test", 4);

    /* Receive and verify sender identity */
    mock_message_t *msg = mock_ipc_recv(receiver);
    test_assert_not_null(msg);
    test_assert_eq(msg->sender_pid, sender->pid);
    test_assert(memcmp(msg->sender_run_id, sender->run_id, AK_TOKEN_ID_SIZE) == 0);

    free(msg);
    mock_shutdown();
    return true;
}

bool test_message_peer_requires_capability(void)
{
    mock_init();

    mock_agent_t *agent1 = &mock_state.agents[0];
    agent1->pid = 1000;
    mock_generate_run_id(agent1->run_id);
    agent1->active = true;
    agent1->has_ipc_cap = false;  /* No IPC capability */
    mock_state.agent_count++;

    mock_agent_t *agent2 = &mock_state.agents[1];
    agent2->pid = 1001;
    mock_generate_run_id(agent2->run_id);
    agent2->active = true;
    agent2->mailbox.inbox_limit = 100;
    mock_state.agent_count++;

    /* Peer send should fail without capability */
    int64_t result = mock_ipc_send(agent1, agent2->pid, AK_IPC_MSG_TYPE_NOTIFY,
                                    0, (const uint8_t *)"test", 4);
    test_assert_eq(result, AK_E_IPC_NO_CAPABILITY);

    /* Grant capability */
    agent1->has_ipc_cap = true;

    /* Now should succeed */
    result = mock_ipc_send(agent1, agent2->pid, AK_IPC_MSG_TYPE_NOTIFY,
                           0, (const uint8_t *)"test", 4);
    test_assert(result > 0);

    mock_shutdown();
    return true;
}

bool test_message_parent_child_no_capability(void)
{
    mock_init();

    /* Parent-child can message without IPC capability */
    mock_agent_t *parent = &mock_state.agents[0];
    parent->pid = 1000;
    mock_generate_run_id(parent->run_id);
    parent->active = true;
    parent->has_ipc_cap = false;  /* No IPC capability */
    mock_state.agent_count++;

    mock_agent_t *child = &mock_state.agents[1];
    child->pid = 1001;
    mock_generate_run_id(child->run_id);
    child->parent_pid = parent->pid;  /* Establish relationship */
    child->active = true;
    child->has_ipc_cap = false;  /* No IPC capability */
    child->mailbox.inbox_limit = 100;
    mock_state.agent_count++;

    parent->child_pids[0] = child->pid;
    parent->child_count = 1;

    /* Parent -> Child should work */
    int64_t result = mock_ipc_send(parent, child->pid, AK_IPC_MSG_TYPE_NOTIFY,
                                    0, (const uint8_t *)"test", 4);
    test_assert(result > 0);

    /* Child -> Parent should also work */
    parent->mailbox.inbox_limit = 100;
    result = mock_ipc_send(child, parent->pid, AK_IPC_MSG_TYPE_NOTIFY,
                           0, (const uint8_t *)"reply", 5);
    test_assert(result > 0);

    mock_shutdown();
    return true;
}

bool test_message_payload_validation(void)
{
    mock_init();

    mock_agent_t *sender = &mock_state.agents[0];
    sender->pid = 1000;
    mock_generate_run_id(sender->run_id);
    sender->active = true;
    sender->has_ipc_cap = true;
    mock_state.agent_count++;

    mock_agent_t *receiver = &mock_state.agents[1];
    receiver->pid = 1001;
    mock_generate_run_id(receiver->run_id);
    receiver->active = true;
    receiver->mailbox.inbox_limit = 100;
    mock_state.agent_count++;

    /* Try to send oversized payload */
    uint8_t large_payload[AK_MAX_PAYLOAD_SIZE + 1000];
    memset(large_payload, 'A', sizeof(large_payload));

    int64_t result = mock_ipc_send(sender, receiver->pid, AK_IPC_MSG_TYPE_NOTIFY,
                                    0, large_payload, sizeof(large_payload));
    test_assert_eq(result, AK_E_IPC_MSG_TOO_LARGE);

    mock_shutdown();
    return true;
}

bool test_message_urgent_priority(void)
{
    mock_init();

    mock_agent_t *sender = &mock_state.agents[0];
    sender->pid = 1000;
    mock_generate_run_id(sender->run_id);
    sender->active = true;
    sender->has_ipc_cap = true;
    mock_state.agent_count++;

    mock_agent_t *receiver = &mock_state.agents[1];
    receiver->pid = 1001;
    mock_generate_run_id(receiver->run_id);
    receiver->active = true;
    receiver->mailbox.inbox_limit = 100;
    mock_state.agent_count++;

    /* Send normal message */
    mock_ipc_send(sender, receiver->pid, AK_IPC_MSG_TYPE_NOTIFY,
                  0, (const uint8_t *)"normal", 6);

    /* Send urgent message */
    mock_ipc_send(sender, receiver->pid, AK_IPC_MSG_TYPE_NOTIFY,
                  AK_IPC_FLAG_URGENT, (const uint8_t *)"urgent", 6);

    /* Check urgent count */
    test_assert_eq(receiver->mailbox.urgent_count, 1);
    test_assert_eq(receiver->mailbox.inbox_count, 2);

    mock_shutdown();
    return true;
}

/* ============================================================
 * TEST CASES: AGENT REGISTRY
 * ============================================================ */

bool test_registry_registration(void)
{
    mock_init();

    mock_agent_t *agent = &mock_state.agents[0];
    agent->pid = mock_state.next_pid++;
    mock_generate_run_id(agent->run_id);

    int result = mock_agent_register(agent, "test_agent", true);
    test_assert_eq(result, 0);
    test_assert(agent->active);
    test_assert_str_eq(agent->name, "test_agent");
    test_assert(agent->discoverable);

    mock_shutdown();
    return true;
}

bool test_registry_duplicate_name(void)
{
    mock_init();

    mock_agent_t *agent1 = &mock_state.agents[0];
    agent1->pid = mock_state.next_pid++;
    mock_generate_run_id(agent1->run_id);
    mock_agent_register(agent1, "duplicate", true);

    mock_agent_t *agent2 = &mock_state.agents[1];
    agent2->pid = mock_state.next_pid++;
    mock_generate_run_id(agent2->run_id);

    int result = mock_agent_register(agent2, "duplicate", true);
    test_assert_eq(result, AK_E_IPC_NAME_EXISTS);

    mock_shutdown();
    return true;
}

bool test_registry_lookup_by_pid(void)
{
    mock_init();

    mock_agent_t *agent = &mock_state.agents[0];
    agent->pid = 12345;
    mock_generate_run_id(agent->run_id);
    mock_agent_register(agent, "lookup_test", true);

    mock_agent_t *found = mock_find_agent(12345);
    test_assert_not_null(found);
    test_assert_eq(found->pid, 12345);

    /* Non-existent PID */
    found = mock_find_agent(99999);
    test_assert_null(found);

    mock_shutdown();
    return true;
}

bool test_registry_slot_reuse(void)
{
    mock_init();

    mock_agent_t *agent = &mock_state.agents[0];
    agent->pid = mock_state.next_pid++;
    mock_generate_run_id(agent->run_id);
    mock_agent_register(agent, "reuse_test", true);

    uint32_t initial_count = mock_state.agent_count;

    /* Unregister */
    mock_agent_unregister(agent);
    test_assert(!agent->active);
    test_assert_eq(mock_state.agent_count, initial_count - 1);

    /* Register new agent in same slot */
    agent->pid = mock_state.next_pid++;
    mock_generate_run_id(agent->run_id);
    int result = mock_agent_register(agent, "new_agent", true);
    test_assert_eq(result, 0);
    test_assert(agent->active);

    mock_shutdown();
    return true;
}

bool test_registry_name_too_long(void)
{
    mock_init();

    mock_agent_t *agent = &mock_state.agents[0];
    agent->pid = mock_state.next_pid++;
    mock_generate_run_id(agent->run_id);

    char long_name[AK_MAX_NAME_LEN + 10];
    memset(long_name, 'a', sizeof(long_name) - 1);
    long_name[sizeof(long_name) - 1] = '\0';

    int result = mock_agent_register(agent, long_name, true);
    test_assert_eq(result, AK_E_IPC_NAME_TOO_LONG);

    mock_shutdown();
    return true;
}

/* ============================================================
 * TEST CASES: AGENT LIFECYCLE
 * ============================================================ */

bool test_lifecycle_spawn_event(void)
{
    mock_init();
    mock_state.audit.event_count = 0;

    mock_agent_t *parent = &mock_state.agents[0];
    parent->pid = mock_state.next_pid++;
    mock_generate_run_id(parent->run_id);
    parent->active = true;
    parent->state = AGENT_STATE_RUNNING;
    parent->budget.spawn_limit = 10;
    mock_state.agent_count++;

    mock_create_capability(parent, AK_CAP_SPAWN, "*", 3600000);

    mock_agent_spawn(parent, "spawned", NULL);

    /* Check spawn event logged */
    test_assert(mock_state.audit.event_count > 0);
    test_assert(strstr(mock_state.audit.events[0], "SPAWN") != NULL);

    mock_shutdown();
    return true;
}

bool test_lifecycle_exit_revokes_caps(void)
{
    mock_init();

    mock_agent_t *agent = &mock_state.agents[0];
    agent->pid = mock_state.next_pid++;
    mock_generate_run_id(agent->run_id);
    mock_agent_register(agent, "exit_test", true);

    /* Grant capability */
    mock_capability_t *cap = mock_create_capability(agent, AK_CAP_FS, "/tmp/*", 3600000);
    test_assert_not_null(cap);
    test_assert(!cap->revoked);

    /* Exit */
    mock_agent_exit(agent, 0);

    /* Capability should be revoked */
    test_assert(cap->revoked);
    test_assert_eq(agent->state, AGENT_STATE_EXITED);

    mock_shutdown();
    return true;
}

bool test_lifecycle_crash_immediate_revoke(void)
{
    mock_init();

    mock_agent_t *agent = &mock_state.agents[0];
    agent->pid = mock_state.next_pid++;
    mock_generate_run_id(agent->run_id);
    mock_agent_register(agent, "crash_test", true);

    /* Grant multiple capabilities */
    mock_capability_t *cap1 = mock_create_capability(agent, AK_CAP_FS, "/tmp/*", 3600000);
    mock_capability_t *cap2 = mock_create_capability(agent, AK_CAP_NET, "*", 3600000);

    /* Crash */
    mock_agent_crash(agent);

    /* All capabilities immediately revoked */
    test_assert(cap1->revoked);
    test_assert(cap2->revoked);
    test_assert_eq(agent->state, AGENT_STATE_CRASHED);

    mock_shutdown();
    return true;
}

bool test_lifecycle_timeout_handling(void)
{
    mock_init();

    mock_agent_t *agent = &mock_state.agents[0];
    agent->pid = mock_state.next_pid++;
    mock_generate_run_id(agent->run_id);
    mock_agent_register(agent, "timeout_test", true);

    mock_capability_t *cap = mock_create_capability(agent, AK_CAP_TOOL, "*", 3600000);

    mock_agent_timeout(agent);

    test_assert(cap->revoked);
    test_assert_eq(agent->state, AGENT_STATE_TIMEOUT);

    mock_shutdown();
    return true;
}

bool test_lifecycle_parent_removes_child(void)
{
    mock_init();

    mock_agent_t *parent = &mock_state.agents[0];
    parent->pid = mock_state.next_pid++;
    mock_generate_run_id(parent->run_id);
    parent->active = true;
    parent->state = AGENT_STATE_RUNNING;
    parent->budget.spawn_limit = 10;
    mock_state.agent_count++;

    mock_create_capability(parent, AK_CAP_SPAWN, "*", 3600000);

    int64_t child_pid = mock_agent_spawn(parent, "child", NULL);
    test_assert(child_pid > 0);
    test_assert_eq(parent->child_count, 1);

    mock_agent_t *child = mock_find_agent((uint64_t)child_pid);
    mock_agent_exit(child, 0);

    /* Child removed from parent's list */
    test_assert_eq(parent->child_count, 0);

    mock_shutdown();
    return true;
}

/* ============================================================
 * TEST CASES: SECURITY BOUNDARIES
 * ============================================================ */

bool test_security_agent_isolation(void)
{
    mock_init();

    mock_agent_t *agent1 = &mock_state.agents[0];
    agent1->pid = 1000;
    mock_generate_run_id(agent1->run_id);
    mock_agent_register(agent1, "agent1", true);
    agent1->budget.tool_calls_limit = 100;
    agent1->budget.tool_calls_used = 50;

    mock_agent_t *agent2 = &mock_state.agents[1];
    agent2->pid = 2000;
    mock_generate_run_id(agent2->run_id);
    mock_agent_register(agent2, "agent2", true);
    agent2->budget.tool_calls_limit = 50;

    /* Agents should have independent budgets */
    test_assert_neq(agent1->budget.tool_calls_limit, agent2->budget.tool_calls_limit);
    test_assert_neq(agent1->budget.tool_calls_used, agent2->budget.tool_calls_used);

    /* Agents should have independent run IDs */
    test_assert(memcmp(agent1->run_id, agent2->run_id, AK_TOKEN_ID_SIZE) != 0);

    /* Agents should have different PIDs */
    test_assert_neq(agent1->pid, agent2->pid);

    mock_shutdown();
    return true;
}

bool test_security_run_id_binding(void)
{
    mock_init();

    mock_agent_t *sender = &mock_state.agents[0];
    sender->pid = 1000;
    mock_generate_run_id(sender->run_id);
    sender->active = true;
    sender->has_ipc_cap = true;
    mock_state.agent_count++;

    mock_agent_t *receiver = &mock_state.agents[1];
    receiver->pid = 1001;
    mock_generate_run_id(receiver->run_id);
    receiver->active = true;
    receiver->mailbox.inbox_limit = 100;
    mock_state.agent_count++;

    /* Send message */
    mock_ipc_send(sender, receiver->pid, AK_IPC_MSG_TYPE_NOTIFY,
                  0, (const uint8_t *)"test", 4);

    /* Message should be bound to sender's run ID */
    mock_message_t *msg = mock_ipc_recv(receiver);
    test_assert_not_null(msg);
    test_assert(memcmp(msg->sender_run_id, sender->run_id, AK_TOKEN_ID_SIZE) == 0);

    /* If sender gets new run, old messages are distinguishable */
    uint8_t old_run_id[AK_TOKEN_ID_SIZE];
    memcpy(old_run_id, sender->run_id, AK_TOKEN_ID_SIZE);
    mock_generate_run_id(sender->run_id);  /* New run */

    test_assert(memcmp(msg->sender_run_id, sender->run_id, AK_TOKEN_ID_SIZE) != 0);
    test_assert(memcmp(msg->sender_run_id, old_run_id, AK_TOKEN_ID_SIZE) == 0);

    free(msg);
    mock_shutdown();
    return true;
}

bool test_security_capability_scope(void)
{
    mock_init();

    mock_agent_t *parent = &mock_state.agents[0];
    parent->pid = mock_state.next_pid++;  /* Use next_pid++ to avoid collision with child */
    mock_generate_run_id(parent->run_id);
    parent->active = true;
    parent->state = AGENT_STATE_RUNNING;
    parent->budget.spawn_limit = 10;
    mock_state.agent_count++;

    mock_create_capability(parent, AK_CAP_SPAWN, "*", 3600000);
    mock_capability_t *fs_cap = mock_create_capability(parent, AK_CAP_FS, "/tmp/*", 3600000);

    int64_t child_pid = mock_agent_spawn(parent, "child", NULL);
    mock_agent_t *child = mock_find_agent((uint64_t)child_pid);
    test_assert_not_null(child);

    /* Delegate capability */
    int result = mock_delegate_capability(parent, child, fs_cap);
    test_assert_eq(result, 0);
    test_assert_eq(child->cap_count, 1);

    /* Verify delegated cap is bound to child's run ID */
    mock_capability_t *delegated = child->caps[0];
    test_assert(memcmp(delegated->run_id, child->run_id, AK_TOKEN_ID_SIZE) == 0);
    test_assert(delegated->delegated);
    test_assert_eq(delegated->parent_pid, parent->pid);

    mock_shutdown();
    return true;
}

bool test_security_capability_revoked_not_delegatable(void)
{
    mock_init();

    mock_agent_t *parent = &mock_state.agents[0];
    parent->pid = mock_state.next_pid++;
    mock_generate_run_id(parent->run_id);
    parent->active = true;
    parent->state = AGENT_STATE_RUNNING;
    parent->budget.spawn_limit = 10;
    mock_state.agent_count++;

    mock_create_capability(parent, AK_CAP_SPAWN, "*", 3600000);
    mock_capability_t *fs_cap = mock_create_capability(parent, AK_CAP_FS, "/tmp/*", 3600000);

    int64_t child_pid = mock_agent_spawn(parent, "child", NULL);
    mock_agent_t *child = mock_find_agent((uint64_t)child_pid);

    /* Revoke the capability */
    fs_cap->revoked = true;

    /* Try to delegate - should fail */
    int result = mock_delegate_capability(parent, child, fs_cap);
    test_assert_eq(result, AK_E_CAP_REVOKED);

    mock_shutdown();
    return true;
}

/* ============================================================
 * TEST CASES: MESSAGE QUEUE SECURITY
 * ============================================================ */

bool test_queue_overflow_protection(void)
{
    mock_init();

    mock_agent_t *sender = &mock_state.agents[0];
    sender->pid = 1000;
    mock_generate_run_id(sender->run_id);
    sender->active = true;
    sender->has_ipc_cap = true;
    mock_state.agent_count++;

    mock_agent_t *receiver = &mock_state.agents[1];
    receiver->pid = 1001;
    mock_generate_run_id(receiver->run_id);
    receiver->active = true;
    receiver->mailbox.inbox_limit = 3;
    mock_state.agent_count++;

    /* Fill queue */
    for (int i = 0; i < 3; i++) {
        mock_ipc_send(sender, receiver->pid, AK_IPC_MSG_TYPE_NOTIFY,
                      0, (const uint8_t *)"test", 4);
    }

    test_assert_eq(receiver->mailbox.inbox_count, 3);

    /* Overflow attempts should fail gracefully */
    for (int i = 0; i < 10; i++) {
        int64_t result = mock_ipc_send(sender, receiver->pid, AK_IPC_MSG_TYPE_NOTIFY,
                                        0, (const uint8_t *)"overflow", 8);
        test_assert_eq(result, AK_E_IPC_MAILBOX_FULL);
    }

    /* Queue should still be at limit */
    test_assert_eq(receiver->mailbox.inbox_count, 3);
    test_assert_eq(receiver->mailbox.messages_dropped, 10);

    mock_shutdown();
    return true;
}

bool test_queue_message_isolation(void)
{
    mock_init();

    mock_agent_t *sender1 = &mock_state.agents[0];
    sender1->pid = 1000;
    mock_generate_run_id(sender1->run_id);
    sender1->active = true;
    sender1->has_ipc_cap = true;
    mock_state.agent_count++;

    mock_agent_t *sender2 = &mock_state.agents[1];
    sender2->pid = 2000;
    mock_generate_run_id(sender2->run_id);
    sender2->active = true;
    sender2->has_ipc_cap = true;
    mock_state.agent_count++;

    mock_agent_t *receiver = &mock_state.agents[2];
    receiver->pid = 3000;
    mock_generate_run_id(receiver->run_id);
    receiver->active = true;
    receiver->mailbox.inbox_limit = 100;
    mock_state.agent_count++;

    /* Both senders send to same receiver */
    mock_ipc_send(sender1, receiver->pid, AK_IPC_MSG_TYPE_NOTIFY,
                  0, (const uint8_t *)"from1", 5);
    mock_ipc_send(sender2, receiver->pid, AK_IPC_MSG_TYPE_NOTIFY,
                  0, (const uint8_t *)"from2", 5);

    /* Messages should be clearly identifiable by sender */
    mock_message_t *msg1 = mock_ipc_recv(receiver);
    mock_message_t *msg2 = mock_ipc_recv(receiver);

    test_assert_not_null(msg1);
    test_assert_not_null(msg2);
    test_assert_eq(msg1->sender_pid, sender1->pid);
    test_assert_eq(msg2->sender_pid, sender2->pid);

    free(msg1);
    free(msg2);
    mock_shutdown();
    return true;
}

/* ============================================================
 * TEST CASES: RESOURCE TRACKING
 * ============================================================ */

bool test_resource_per_agent_budget(void)
{
    mock_init();

    mock_agent_t *agent = &mock_state.agents[0];
    agent->pid = mock_state.next_pid++;
    mock_generate_run_id(agent->run_id);
    mock_agent_register(agent, "budget_test", true);

    agent->budget.tool_calls_limit = 100;
    agent->budget.tool_calls_used = 0;

    /* Simulate tool usage */
    for (int i = 0; i < 50; i++) {
        agent->budget.tool_calls_used++;
    }

    test_assert_eq(agent->budget.tool_calls_used, 50);
    test_assert(agent->budget.tool_calls_used < agent->budget.tool_calls_limit);

    /* Use remaining budget */
    while (agent->budget.tool_calls_used < agent->budget.tool_calls_limit) {
        agent->budget.tool_calls_used++;
    }

    test_assert_eq(agent->budget.tool_calls_used, agent->budget.tool_calls_limit);

    mock_shutdown();
    return true;
}

bool test_resource_combined_limits(void)
{
    mock_init();

    mock_agent_t *parent = &mock_state.agents[0];
    parent->pid = mock_state.next_pid++;
    mock_generate_run_id(parent->run_id);
    parent->active = true;
    parent->state = AGENT_STATE_RUNNING;
    parent->budget.spawn_limit = 10;
    parent->budget.tool_calls_limit = 100;
    mock_state.agent_count++;

    mock_create_capability(parent, AK_CAP_SPAWN, "*", 3600000);

    /* Spawn children with budgets that sum to parent's total */
    mock_budget_t child1_budget = {.tool_calls_limit = 30};
    mock_budget_t child2_budget = {.tool_calls_limit = 30};
    mock_budget_t child3_budget = {.tool_calls_limit = 30};

    mock_agent_spawn(parent, "child1", &child1_budget);
    mock_agent_spawn(parent, "child2", &child2_budget);
    mock_agent_spawn(parent, "child3", &child3_budget);

    /* Total allocated to children should not exceed parent */
    uint64_t total_allocated = 30 + 30 + 30;
    test_assert(total_allocated <= parent->budget.tool_calls_limit);

    mock_shutdown();
    return true;
}

/* ============================================================
 * TEST CASES: EDGE CASES
 * ============================================================ */

bool test_edge_orphan_handling(void)
{
    mock_init();

    mock_agent_t *parent = &mock_state.agents[0];
    parent->pid = mock_state.next_pid++;
    mock_generate_run_id(parent->run_id);
    parent->active = true;
    parent->state = AGENT_STATE_RUNNING;
    parent->budget.spawn_limit = 10;
    mock_state.agent_count++;

    mock_create_capability(parent, AK_CAP_SPAWN, "*", 3600000);

    int64_t child_pid = mock_agent_spawn(parent, "orphan", NULL);
    mock_agent_t *child = mock_find_agent((uint64_t)child_pid);
    test_assert_not_null(child);
    test_assert_eq(child->parent_pid, parent->pid);

    /* Parent exits */
    mock_agent_exit(parent, 0);

    /* Child should still reference parent PID (orphaned) */
    test_assert_eq(child->parent_pid, parent->pid);

    /* Child should still be active */
    test_assert(child->active);
    test_assert_eq(child->state, AGENT_STATE_RUNNING);

    mock_shutdown();
    return true;
}

bool test_edge_deep_nesting(void)
{
    mock_init();

    /* Create chain: root -> level1 -> level2 -> ... */
    mock_agent_t *current = &mock_state.agents[0];
    current->pid = mock_state.next_pid++;
    mock_generate_run_id(current->run_id);
    current->active = true;
    current->state = AGENT_STATE_RUNNING;
    current->budget.spawn_limit = 100;
    mock_state.agent_count++;

    mock_create_capability(current, AK_CAP_SPAWN, "*", 3600000);

    int depth = 0;
    const int max_depth = 10;

    while (depth < max_depth) {
        char name[32];
        snprintf(name, sizeof(name), "level_%d", depth + 1);

        mock_budget_t child_budget = {.spawn_limit = 100};
        int64_t child_pid = mock_agent_spawn(current, name, &child_budget);

        if (child_pid <= 0) break;

        mock_agent_t *child = mock_find_agent((uint64_t)child_pid);
        if (!child) break;

        /* Grant spawn capability to child for next iteration */
        mock_create_capability(child, AK_CAP_SPAWN, "*", 3600000);

        current = child;
        depth++;
    }

    test_assert(depth == max_depth);

    mock_shutdown();
    return true;
}

bool test_edge_concurrent_send(void)
{
    mock_init();

    /* Multiple senders to one receiver */
    mock_agent_t *receiver = &mock_state.agents[0];
    receiver->pid = 1000;
    mock_generate_run_id(receiver->run_id);
    receiver->active = true;
    receiver->mailbox.inbox_limit = 100;
    mock_state.agent_count++;

    for (int i = 0; i < 10; i++) {
        mock_agent_t *sender = &mock_state.agents[i + 1];
        sender->pid = 2000 + (uint64_t)i;
        mock_generate_run_id(sender->run_id);
        sender->active = true;
        sender->has_ipc_cap = true;
        mock_state.agent_count++;

        char payload[32];
        snprintf(payload, sizeof(payload), "sender_%d", i);
        mock_ipc_send(sender, receiver->pid, AK_IPC_MSG_TYPE_NOTIFY,
                      0, (const uint8_t *)payload, (uint32_t)strlen(payload));
    }

    /* All messages should be received */
    test_assert_eq(receiver->mailbox.inbox_count, 10);

    /* Drain and verify all unique senders */
    uint64_t seen_senders[10] = {0};
    for (int i = 0; i < 10; i++) {
        mock_message_t *msg = mock_ipc_recv(receiver);
        test_assert_not_null(msg);

        /* Verify unique sender */
        bool duplicate = false;
        for (int j = 0; j < i; j++) {
            if (seen_senders[j] == msg->sender_pid) {
                duplicate = true;
                break;
            }
        }
        test_assert(!duplicate);
        seen_senders[i] = msg->sender_pid;

        free(msg);
    }

    mock_shutdown();
    return true;
}

bool test_edge_send_to_nonexistent(void)
{
    mock_init();

    mock_agent_t *sender = &mock_state.agents[0];
    sender->pid = 1000;
    mock_generate_run_id(sender->run_id);
    sender->active = true;
    sender->has_ipc_cap = true;
    mock_state.agent_count++;

    /* Try to send to non-existent agent */
    int64_t result = mock_ipc_send(sender, 99999, AK_IPC_MSG_TYPE_NOTIFY,
                                    0, (const uint8_t *)"test", 4);
    test_assert_eq(result, AK_E_IPC_NO_RECIPIENT);

    mock_shutdown();
    return true;
}

bool test_edge_recv_empty_queue(void)
{
    mock_init();

    mock_agent_t *agent = &mock_state.agents[0];
    agent->pid = 1000;
    mock_generate_run_id(agent->run_id);
    agent->active = true;
    agent->mailbox.inbox_limit = 100;
    mock_state.agent_count++;

    /* Try to receive from empty queue */
    mock_message_t *msg = mock_ipc_recv(agent);
    test_assert_null(msg);
    test_assert_eq(mock_ipc_peek(agent), 0);

    mock_shutdown();
    return true;
}

bool test_edge_self_message(void)
{
    mock_init();

    mock_agent_t *agent = &mock_state.agents[0];
    agent->pid = 1000;
    mock_generate_run_id(agent->run_id);
    agent->active = true;
    agent->has_ipc_cap = true;
    agent->mailbox.inbox_limit = 100;
    mock_state.agent_count++;

    /* Send message to self */
    int64_t result = mock_ipc_send(agent, agent->pid, AK_IPC_MSG_TYPE_NOTIFY,
                                    0, (const uint8_t *)"self", 4);
    test_assert(result > 0);

    /* Receive self message */
    mock_message_t *msg = mock_ipc_recv(agent);
    test_assert_not_null(msg);
    test_assert_eq(msg->sender_pid, agent->pid);

    free(msg);
    mock_shutdown();
    return true;
}

/* ============================================================
 * TEST CASES: CAPABILITY DELEGATION
 * ============================================================ */

bool test_capability_delegation_chain(void)
{
    mock_init();

    /* Create parent with spawn and FS capabilities */
    mock_agent_t *parent = &mock_state.agents[0];
    parent->pid = mock_state.next_pid++;
    mock_generate_run_id(parent->run_id);
    parent->active = true;
    parent->state = AGENT_STATE_RUNNING;
    parent->budget.spawn_limit = 10;
    mock_state.agent_count++;

    mock_create_capability(parent, AK_CAP_SPAWN, "*", 3600000);
    mock_capability_t *fs_cap = mock_create_capability(parent, AK_CAP_FS, "/data/*", 3600000);

    /* Spawn child and delegate */
    int64_t child_pid = mock_agent_spawn(parent, "child", NULL);
    mock_agent_t *child = mock_find_agent((uint64_t)child_pid);

    int result = mock_delegate_capability(parent, child, fs_cap);
    test_assert_eq(result, 0);

    /* Verify delegation */
    test_assert_eq(child->cap_count, 1);
    test_assert(child->caps[0]->delegated);
    test_assert_eq(child->caps[0]->type, AK_CAP_FS);

    mock_shutdown();
    return true;
}

bool test_capability_parent_revoke_affects_child(void)
{
    mock_init();

    mock_agent_t *parent = &mock_state.agents[0];
    parent->pid = mock_state.next_pid++;
    mock_generate_run_id(parent->run_id);
    parent->active = true;
    parent->state = AGENT_STATE_RUNNING;
    parent->budget.spawn_limit = 10;
    mock_state.agent_count++;

    mock_create_capability(parent, AK_CAP_SPAWN, "*", 3600000);
    mock_capability_t *fs_cap = mock_create_capability(parent, AK_CAP_FS, "/data/*", 3600000);

    int64_t child_pid = mock_agent_spawn(parent, "child", NULL);
    mock_agent_t *child = mock_find_agent((uint64_t)child_pid);

    mock_delegate_capability(parent, child, fs_cap);

    /* Get reference to delegated cap before revocation */
    mock_capability_t *delegated = child->caps[0];
    test_assert(!delegated->revoked);

    /* Revoke parent's capability */
    fs_cap->revoked = true;

    /* Note: In a real system, this would cascade. Here we simulate it */
    /* Cascade revocation to delegated capabilities */
    for (uint32_t i = 0; i < child->cap_count; i++) {
        if (child->caps[i]->delegated && child->caps[i]->parent_pid == parent->pid) {
            /* Check if parent cap is revoked */
            for (uint32_t j = 0; j < parent->cap_count; j++) {
                if (parent->caps[j] && parent->caps[j]->type == child->caps[i]->type) {
                    if (parent->caps[j]->revoked) {
                        child->caps[i]->revoked = true;
                    }
                }
            }
        }
    }

    test_assert(delegated->revoked);

    mock_shutdown();
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
    /* Agent spawning tests */
    {"spawn_child_agent", test_spawn_child_agent},
    {"spawn_without_capability", test_spawn_without_capability},
    {"spawn_budget_enforcement", test_spawn_budget_enforcement},
    {"spawn_max_agents_limit", test_spawn_max_agents_limit},
    {"spawn_policy_inheritance", test_spawn_policy_inheritance},
    {"spawn_budget_attenuation", test_spawn_budget_attenuation},

    /* Inter-agent messaging tests */
    {"message_send_recv_basic", test_message_send_recv_basic},
    {"message_queue_ordering", test_message_queue_ordering},
    {"message_queue_capacity", test_message_queue_capacity},
    {"message_sender_verification", test_message_sender_verification},
    {"message_peer_requires_capability", test_message_peer_requires_capability},
    {"message_parent_child_no_capability", test_message_parent_child_no_capability},
    {"message_payload_validation", test_message_payload_validation},
    {"message_urgent_priority", test_message_urgent_priority},

    /* Agent registry tests */
    {"registry_registration", test_registry_registration},
    {"registry_duplicate_name", test_registry_duplicate_name},
    {"registry_lookup_by_pid", test_registry_lookup_by_pid},
    {"registry_slot_reuse", test_registry_slot_reuse},
    {"registry_name_too_long", test_registry_name_too_long},

    /* Agent lifecycle tests */
    {"lifecycle_spawn_event", test_lifecycle_spawn_event},
    {"lifecycle_exit_revokes_caps", test_lifecycle_exit_revokes_caps},
    {"lifecycle_crash_immediate_revoke", test_lifecycle_crash_immediate_revoke},
    {"lifecycle_timeout_handling", test_lifecycle_timeout_handling},
    {"lifecycle_parent_removes_child", test_lifecycle_parent_removes_child},

    /* Security boundaries tests */
    {"security_agent_isolation", test_security_agent_isolation},
    {"security_run_id_binding", test_security_run_id_binding},
    {"security_capability_scope", test_security_capability_scope},
    {"security_capability_revoked_not_delegatable", test_security_capability_revoked_not_delegatable},

    /* Message queue security tests */
    {"queue_overflow_protection", test_queue_overflow_protection},
    {"queue_message_isolation", test_queue_message_isolation},

    /* Resource tracking tests */
    {"resource_per_agent_budget", test_resource_per_agent_budget},
    {"resource_combined_limits", test_resource_combined_limits},

    /* Edge cases tests */
    {"edge_orphan_handling", test_edge_orphan_handling},
    {"edge_deep_nesting", test_edge_deep_nesting},
    {"edge_concurrent_send", test_edge_concurrent_send},
    {"edge_send_to_nonexistent", test_edge_send_to_nonexistent},
    {"edge_recv_empty_queue", test_edge_recv_empty_queue},
    {"edge_self_message", test_edge_self_message},

    /* Capability delegation tests */
    {"capability_delegation_chain", test_capability_delegation_chain},
    {"capability_parent_revoke_affects_child", test_capability_parent_revoke_affects_child},

    {NULL, NULL}
};

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    int passed = 0;
    int failed = 0;

    srand(42);  /* Deterministic for reproducibility */

    printf("=== AK Multi-Process Security Boundaries Tests ===\n\n");

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
