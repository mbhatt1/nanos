/*
 * Authority Kernel - Process Model and Capability Propagation
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Implements process spawning with capability inheritance for the
 * Authority Kernel. This module provides:
 *   - Process registry for tracking spawned processes
 *   - Capability delegation with monotonic attenuation
 *   - Time-limited capability propagation
 *   - Automatic capability revocation on process exit
 *
 * Capability Propagation Rules:
 *   1. Child inherits parent's policy by default
 *   2. Parent can restrict child's policy (subset only)
 *   3. Capabilities can be delegated with time limits
 *   4. Child capabilities <= Parent capabilities (monotonic)
 *
 * SECURITY INVARIANTS:
 *   - No capability amplification (child cannot exceed parent)
 *   - Revocation is immediate and cascading
 *   - All spawns are audited
 */

#ifndef AK_PROCESS_H
#define AK_PROCESS_H

#include "ak_types.h"
#include "ak_effects.h"
#include "ak_policy_v2.h"

/* ============================================================
 * PROCESS REGISTRY CONSTANTS
 * ============================================================ */

#define AK_PROCESS_MAX_ENTRIES      256     /* Maximum tracked processes */
#define AK_PROCESS_MAX_CAPS         16      /* Max delegated caps per process */
#define AK_PROCESS_MAX_CHILDREN     32      /* Max children per parent */
#define AK_PROCESS_MAX_PROGRAM_LEN  256     /* Max program path length */
#define AK_PROCESS_MAX_ARGV         64      /* Max argument count */

/* ============================================================
 * PROCESS FLAGS
 * ============================================================ */

/* Spawn flags */
#define AK_SPAWN_FLAG_SANDBOX       0x0001  /* Run in sandboxed environment */
#define AK_SPAWN_FLAG_INHERIT_CAPS  0x0002  /* Inherit parent capabilities */
#define AK_SPAWN_FLAG_INHERIT_POLICY 0x0004 /* Inherit parent policy */
#define AK_SPAWN_FLAG_NO_NET        0x0008  /* Disable network access */
#define AK_SPAWN_FLAG_NO_FS_WRITE   0x0010  /* Disable filesystem writes */
#define AK_SPAWN_FLAG_EPHEMERAL     0x0020  /* Auto-revoke caps on exit */

/* Default spawn flags */
#define AK_SPAWN_FLAGS_DEFAULT      (AK_SPAWN_FLAG_INHERIT_POLICY | \
                                     AK_SPAWN_FLAG_EPHEMERAL)

/* Process states */
typedef enum ak_process_state {
    AK_PROC_STATE_NONE      = 0,    /* Unused entry */
    AK_PROC_STATE_RUNNING   = 1,    /* Process is running */
    AK_PROC_STATE_STOPPED   = 2,    /* Process is stopped (SIGSTOP) */
    AK_PROC_STATE_ZOMBIE    = 3,    /* Process exited, awaiting wait() */
    AK_PROC_STATE_EXITED    = 4,    /* Process exited and reaped */
} ak_process_state_t;

/* ============================================================
 * DELEGATED CAPABILITY ENTRY
 * ============================================================
 * Tracks capabilities delegated to a child process.
 * Supports time-limited delegation.
 */

typedef struct ak_delegated_cap {
    ak_capability_t *cap;           /* The delegated capability */
    u64 delegated_ms;               /* When it was delegated */
    u64 expires_ms;                 /* When it expires (0 = never) */
    boolean revoked;                /* Has been revoked */
    struct ak_delegated_cap *next;  /* Linked list */
} ak_delegated_cap_t;

/* ============================================================
 * PROCESS REGISTRY ENTRY
 * ============================================================
 * Tracks a spawned process and its capability state.
 */

typedef struct ak_process_entry {
    /* Identity */
    u64 pid;                        /* Process ID */
    u64 parent_pid;                 /* Parent process ID */
    u8 run_id[AK_TOKEN_ID_SIZE];   /* Run ID for capability binding */
    u8 parent_run_id[AK_TOKEN_ID_SIZE]; /* Parent's run ID */

    /* State */
    ak_process_state_t state;       /* Current state */
    u32 spawn_flags;                /* Flags used when spawning */
    int exit_code;                  /* Exit code (if exited) */
    int exit_signal;                /* Signal that caused exit (if any) */

    /* Policy */
    ak_policy_v2_t *policy;         /* Inherited or restricted policy */
    boolean policy_owned;           /* true if we allocated the policy */

    /* Capabilities */
    ak_delegated_cap_t *caps;       /* Delegated capabilities list */
    u32 cap_count;                  /* Number of delegated caps */

    /* Sandbox state */
    boolean sandboxed;              /* Running in sandbox */

    /* Program info */
    char program[AK_PROCESS_MAX_PROGRAM_LEN]; /* Program path */

    /* Timing */
    u64 spawn_time_ms;              /* When process was spawned */
    u64 exit_time_ms;               /* When process exited */

    /* Audit */
    u64 spawn_trace_id;             /* Trace ID from spawn request */

    /* Linkage */
    struct ak_process_entry *next;  /* Hash chain / free list */
} ak_process_entry_t;

/* ============================================================
 * SPAWN REQUEST STRUCTURE
 * ============================================================
 * Parameters for spawning a new process.
 */

typedef struct ak_spawn_request {
    /* Program to execute */
    const char *program;            /* Path to executable */
    const char **argv;              /* NULL-terminated argument array */
    const char **envp;              /* NULL-terminated environment (or NULL) */

    /* Flags */
    u32 flags;                      /* AK_SPAWN_FLAG_* */

    /* Policy restriction (optional) */
    ak_policy_v2_t *child_policy;   /* If NULL, inherit parent's */

    /* Capability delegation (optional) */
    ak_capability_t **delegated_caps; /* Capabilities to delegate */
    u32 delegated_cap_count;          /* Number of caps to delegate */
    u64 cap_ttl_ms;                   /* TTL for delegated caps (0 = parent's) */

    /* Resource limits (optional) */
    struct {
        u64 cpu_ns;                 /* Max CPU time */
        u64 wall_ns;                /* Max wall time */
        u64 memory_bytes;           /* Max memory */
    } limits;

} ak_spawn_request_t;

/* ============================================================
 * SPAWN RESULT STRUCTURE
 * ============================================================ */

typedef struct ak_spawn_result {
    boolean success;                /* true if spawn succeeded */
    u64 child_pid;                  /* Child process ID */
    u8 child_run_id[AK_TOKEN_ID_SIZE]; /* Child's run ID */
    int error_code;                 /* Error code on failure */
    char error_msg[128];            /* Error message on failure */
} ak_spawn_result_t;

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

/*
 * Initialize the process registry.
 *
 * Must be called before any other ak_process_* functions.
 *
 * @param h     Heap for allocations
 */
void ak_process_init(heap h);

/*
 * Shutdown the process registry.
 *
 * Revokes all capabilities and cleans up resources.
 */
void ak_process_shutdown(void);

/* ============================================================
 * PROCESS REGISTRATION
 * ============================================================ */

/*
 * Register a new process in the registry.
 *
 * Called after successful fork/exec to track the new process.
 *
 * PRECONDITIONS:
 *   - pid must be valid (> 0)
 *   - parent_pid may be 0 for init process
 *   - policy may be NULL (uses fail-closed policy)
 *
 * POSTCONDITIONS:
 *   - Process is registered and can receive delegated caps
 *   - Returns entry pointer on success
 *
 * @param pid           Process ID of new process
 * @param parent_pid    Parent process ID (0 for init)
 * @param policy        Policy for new process (may be NULL)
 * @param flags         Spawn flags used
 * @return              Process entry on success, NULL on failure
 */
ak_process_entry_t *ak_process_register(
    u64 pid,
    u64 parent_pid,
    ak_policy_v2_t *policy,
    u32 flags
);

/*
 * Unregister a process from the registry.
 *
 * Called when process exits. Revokes all delegated capabilities.
 *
 * @param pid           Process ID to unregister
 * @param exit_code     Exit code from wait()
 * @param exit_signal   Signal that caused exit (0 if normal)
 */
void ak_process_unregister(u64 pid, int exit_code, int exit_signal);

/*
 * Find a process entry by PID.
 *
 * @param pid           Process ID to find
 * @return              Process entry or NULL if not found
 */
ak_process_entry_t *ak_process_find(u64 pid);

/*
 * Find a process entry by run ID.
 *
 * @param run_id        Run ID to find
 * @return              Process entry or NULL if not found
 */
ak_process_entry_t *ak_process_find_by_run_id(const u8 *run_id);

/* ============================================================
 * POLICY ACCESS
 * ============================================================ */

/*
 * Get the effective policy for a process.
 *
 * Returns the process's policy, or the fail-closed policy if
 * no policy is set.
 *
 * @param pid           Process ID
 * @return              Policy pointer (never NULL)
 */
ak_policy_v2_t *ak_process_get_policy(u64 pid);

/*
 * Set policy for a process.
 *
 * SECURITY: New policy must be subset of current policy.
 *
 * @param pid           Process ID
 * @param policy        New policy (will be validated)
 * @return              0 on success, negative error on failure
 */
int ak_process_set_policy(u64 pid, ak_policy_v2_t *policy);

/* ============================================================
 * CAPABILITY DELEGATION
 * ============================================================ */

/*
 * Delegate a capability from parent to child.
 *
 * SECURITY INVARIANT: child_cap must be subset of parent_cap.
 * Delegation is monotonically attenuating.
 *
 * PRECONDITIONS:
 *   - parent_pid must be valid and registered
 *   - child_pid must be valid and registered
 *   - cap must be valid capability owned by parent
 *
 * POSTCONDITIONS:
 *   - Child has delegated copy of capability
 *   - Delegated cap is bound to child's run_id
 *   - Delegated cap expires when parent's does (or earlier)
 *
 * @param parent_pid    Parent process ID
 * @param child_pid     Child process ID
 * @param cap           Capability to delegate
 * @param ttl_ms        Time-to-live for delegation (0 = use cap's TTL)
 * @return              0 on success, negative error on failure
 *
 * ERRORS:
 *   -EINVAL   - Invalid PID or capability
 *   -ENOENT   - Process not found
 *   -EPERM    - Delegation would amplify (child > parent)
 *   -ENOMEM   - Allocation failed
 */
int ak_process_delegate_cap(
    u64 parent_pid,
    u64 child_pid,
    ak_capability_t *cap,
    u64 ttl_ms
);

/*
 * Revoke a specific capability from a process.
 *
 * @param pid           Process ID
 * @param tid           Token ID of capability to revoke
 * @return              0 on success, -ENOENT if not found
 */
int ak_process_revoke_cap(u64 pid, const u8 *tid);

/*
 * Revoke all capabilities for a process.
 *
 * Called automatically on process exit.
 *
 * @param pid           Process ID
 */
void ak_process_revoke_caps(u64 pid);

/*
 * Check if process has a valid capability of given type.
 *
 * @param pid           Process ID
 * @param type          Capability type to check
 * @param resource      Resource pattern to match
 * @return              true if has valid capability
 */
boolean ak_process_has_cap(u64 pid, ak_cap_type_t type, const char *resource);

/* ============================================================
 * SPAWN AUTHORIZATION
 * ============================================================ */

/*
 * Check if spawn is authorized by policy.
 *
 * Validates:
 *   - Parent has SPAWN capability
 *   - Program is in allowed list
 *   - Child policy is subset of parent
 *
 * @param parent_pid    Parent process ID
 * @param req           Spawn request
 * @param decision      Output: authorization decision
 * @return              true if authorized
 */
boolean ak_process_authorize_spawn(
    u64 parent_pid,
    const ak_spawn_request_t *req,
    ak_decision_t *decision
);

/*
 * Execute a spawn request.
 *
 * Full spawn workflow:
 *   1. Validate request
 *   2. Check authorization
 *   3. Create child process
 *   4. Register in process table
 *   5. Delegate capabilities
 *   6. Start execution
 *
 * @param parent_pid    Parent process ID
 * @param req           Spawn request
 * @param result        Output: spawn result
 * @return              0 on success, negative error on failure
 */
int ak_process_spawn(
    u64 parent_pid,
    const ak_spawn_request_t *req,
    ak_spawn_result_t *result
);

/* ============================================================
 * PROCESS HIERARCHY
 * ============================================================ */

/*
 * Check if child is descendant of parent.
 *
 * Used for capability hierarchy validation.
 *
 * @param parent_pid    Potential ancestor
 * @param child_pid     Potential descendant
 * @return              true if child is descendant of parent
 */
boolean ak_process_is_descendant(u64 parent_pid, u64 child_pid);

/*
 * Get parent PID of a process.
 *
 * @param pid           Process ID
 * @return              Parent PID, or 0 if not found/init
 */
u64 ak_process_get_parent(u64 pid);

/*
 * Count number of children for a process.
 *
 * @param pid           Process ID
 * @return              Number of child processes
 */
u32 ak_process_count_children(u64 pid);

/* ============================================================
 * STATE MANAGEMENT
 * ============================================================ */

/*
 * Update process state.
 *
 * @param pid           Process ID
 * @param state         New state
 */
void ak_process_set_state(u64 pid, ak_process_state_t state);

/*
 * Get process state.
 *
 * @param pid           Process ID
 * @return              Current state
 */
ak_process_state_t ak_process_get_state(u64 pid);

/* ============================================================
 * CLEANUP AND MAINTENANCE
 * ============================================================ */

/*
 * Expire timed-out capabilities.
 *
 * Should be called periodically to clean up expired delegations.
 *
 * @return              Number of capabilities expired
 */
u32 ak_process_expire_caps(void);

/*
 * Clean up zombie processes.
 *
 * Removes fully reaped processes from registry.
 *
 * @return              Number of zombies cleaned
 */
u32 ak_process_cleanup_zombies(void);

/* ============================================================
 * STATISTICS
 * ============================================================ */

typedef struct ak_process_stats {
    u64 total_spawns;               /* Total spawn attempts */
    u64 spawn_success;              /* Successful spawns */
    u64 spawn_denied;               /* Denied spawns */
    u64 total_delegations;          /* Total cap delegations */
    u64 total_revocations;          /* Total cap revocations */
    u32 active_processes;           /* Currently tracked processes */
    u32 active_caps;                /* Currently active delegated caps */
} ak_process_stats_t;

/*
 * Get process subsystem statistics.
 *
 * @param stats         Output: statistics structure
 */
void ak_process_get_stats(ak_process_stats_t *stats);

/* ============================================================
 * DEBUG HELPERS
 * ============================================================ */

/*
 * Dump process tree to console (debug only).
 */
void ak_process_debug_dump(void);

#endif /* AK_PROCESS_H */
