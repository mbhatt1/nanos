/*
 * Authority Kernel - Configuration Options
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Build-time configuration for the Authority Kernel.
 * These can be set via KCONFIG or command-line defines.
 */

#ifndef AK_CONFIG_H
#define AK_CONFIG_H

/* ============================================================
 * FEATURE TOGGLES
 * ============================================================ */

/* Enable Authority Kernel (master switch) */
#ifndef CONFIG_AK_ENABLED
#define CONFIG_AK_ENABLED       0
#endif

/* Enable debug logging */
#ifndef AK_DEBUG
#define AK_DEBUG                0
#endif

/* Enable extra security checks (slower but more paranoid) */
#ifndef AK_PARANOID
#define AK_PARANOID             1
#endif

/* ============================================================
 * SECURITY PARAMETERS
 * ============================================================ */

/* Key rotation interval (milliseconds) */
#ifndef AK_KEY_ROTATION_INTERVAL_MS
#define AK_KEY_ROTATION_INTERVAL_MS     (24 * 60 * 60 * 1000)   /* 24 hours */
#endif

/* Grace period for old keys (milliseconds) */
#ifndef AK_KEY_GRACE_PERIOD_MS
#define AK_KEY_GRACE_PERIOD_MS          (4 * AK_KEY_ROTATION_INTERVAL_MS)
#endif

/* Maximum capability TTL (milliseconds) */
#ifndef AK_MAX_CAP_TTL_MS
#define AK_MAX_CAP_TTL_MS               (7 * 24 * 60 * 60 * 1000)  /* 7 days */
#endif

/* Audit anchor interval (entries) */
#ifndef AK_ANCHOR_INTERVAL
#define AK_ANCHOR_INTERVAL              1000
#endif

/* ============================================================
 * RESOURCE LIMITS
 * ============================================================ */

/* Maximum heap objects per agent */
#ifndef AK_MAX_HEAP_OBJECTS
#define AK_MAX_HEAP_OBJECTS             100000
#endif

/* Maximum heap bytes per agent */
#ifndef AK_MAX_HEAP_BYTES
#define AK_MAX_HEAP_BYTES               (1024 * 1024 * 1024)    /* 1 GB */
#endif

/* Maximum IPC message size */
#ifndef AK_MAX_IPC_MESSAGE
#define AK_MAX_IPC_MESSAGE              (1024 * 1024)           /* 1 MB */
#endif

/* Maximum audit log entries to keep */
#ifndef AK_MAX_AUDIT_ENTRIES
#define AK_MAX_AUDIT_ENTRIES            1000000
#endif

/* Maximum versions to keep per object */
#ifndef AK_MAX_VERSIONS_PER_OBJECT
#define AK_MAX_VERSIONS_PER_OBJECT      100
#endif

/* ============================================================
 * TOKEN SIZES
 * ============================================================ */

/* Token ID size (bytes) */
#ifndef AK_TOKEN_ID_SIZE
#define AK_TOKEN_ID_SIZE                16
#endif

/* Hash size for SHA-256 (bytes) */
#ifndef AK_HASH_SIZE
#define AK_HASH_SIZE                    32
#endif

/* HMAC key size (bytes) */
#ifndef AK_KEY_SIZE
#define AK_KEY_SIZE                     32
#endif

/* Signature size (bytes) */
#ifndef AK_SIG_SIZE
#define AK_SIG_SIZE                     64  /* Ed25519 signature size */
#endif

/* ============================================================
 * DEFAULT BUDGETS
 * ============================================================ */

/* Default token budget */
#ifndef AK_DEFAULT_TOKEN_BUDGET
#define AK_DEFAULT_TOKEN_BUDGET         100000
#endif

/* Default API call budget */
#ifndef AK_DEFAULT_CALL_BUDGET
#define AK_DEFAULT_CALL_BUDGET          100
#endif

/* Default inference time budget (ms) */
#ifndef AK_DEFAULT_INFERENCE_BUDGET_MS
#define AK_DEFAULT_INFERENCE_BUDGET_MS  300000  /* 5 minutes */
#endif

/* Default file I/O budget (bytes) */
#ifndef AK_DEFAULT_FILE_BUDGET
#define AK_DEFAULT_FILE_BUDGET          (100 * 1024 * 1024)     /* 100 MB */
#endif

/* Default network I/O budget (bytes) */
#ifndef AK_DEFAULT_NETWORK_BUDGET
#define AK_DEFAULT_NETWORK_BUDGET       (100 * 1024 * 1024)     /* 100 MB */
#endif

/* ============================================================
 * TIMING PARAMETERS
 * ============================================================ */

/* Timeout for blocking IPC operations (ms) */
#ifndef AK_IPC_TIMEOUT_MS
#define AK_IPC_TIMEOUT_MS               30000   /* 30 seconds */
#endif

/* Timeout for capability revocation propagation (ms) */
#ifndef AK_REVOCATION_TIMEOUT_MS
#define AK_REVOCATION_TIMEOUT_MS        1000    /* 1 second */
#endif

/* Audit log flush interval (ms) */
#ifndef AK_AUDIT_FLUSH_INTERVAL_MS
#define AK_AUDIT_FLUSH_INTERVAL_MS      1000    /* 1 second */
#endif

/* ============================================================
 * OPTIONAL FEATURES
 * ============================================================ */

/* Enable WASM sandbox for tool execution */
#ifndef AK_ENABLE_WASM
#define AK_ENABLE_WASM                  1       /* Enabled by default for secure tool execution */
#endif

/* Enable remote anchor posting */
#ifndef AK_ENABLE_REMOTE_ANCHOR
#define AK_ENABLE_REMOTE_ANCHOR         0
#endif

/* Enable taint tracking */
#ifndef AK_ENABLE_TAINT
#define AK_ENABLE_TAINT                 1
#endif

/* Enable full JSON Schema validation */
#ifndef AK_ENABLE_SCHEMA_VALIDATION
#define AK_ENABLE_SCHEMA_VALIDATION     0       /* Requires JSON Schema lib */
#endif

/* ============================================================
 * POLICY SIGNATURE CONFIGURATION
 * ============================================================ */

/*
 * Allow unsigned policies (DEVELOPMENT ONLY)
 *
 * SECURITY WARNING: Setting this to 1 disables signature verification
 * for policy files. This should NEVER be enabled in production builds.
 *
 * When enabled:
 *   - Unsigned policies are accepted with a warning
 *   - A warning is logged for each unsigned policy load
 *   - This flag should only be set during development/testing
 *
 * Production builds MUST leave this at 0 (default).
 */
#ifndef AK_ALLOW_UNSIGNED_POLICIES
#define AK_ALLOW_UNSIGNED_POLICIES      0       /* Default: require signatures */
#endif

/*
 * Runtime override for unsigned policies (checked at runtime)
 *
 * Even if AK_ALLOW_UNSIGNED_POLICIES is 1, this runtime flag can
 * further restrict unsigned policy loading. Set via environment
 * or configuration at boot time.
 *
 * 0 = Follow compile-time setting
 * 1 = Always require signatures (override dev mode)
 */
#ifndef AK_REQUIRE_POLICY_SIGNATURES
#define AK_REQUIRE_POLICY_SIGNATURES    0       /* Runtime override */
#endif

/* ============================================================
 * AI-FIRST KERNEL CONFIGURATION
 * ============================================================
 * When enabled, removes unnecessary Linux syscalls:
 *   - SysV IPC (shmget, msgget, semget) - agents use AK IPC
 *   - File monitoring (inotify, fanotify) - not needed
 *   - Extended attributes (xattr) - not used
 *   - Container/namespace syscalls - unikernel model
 *
 * Keeps full Linux functionality for:
 *   - Memory management
 *   - Networking (full stack)
 *   - File operations (for binary loading, config, logs)
 *   - Threading and synchronization
 *   - Signals and time
 */
#ifndef CONFIG_SYSCALL_AGENTIC
#define CONFIG_SYSCALL_AGENTIC          1       /* AI-first syscall subset */
#endif

/* Maximum concurrent agent contexts */
#ifndef AK_MAX_AGENTS
#define AK_MAX_AGENTS                   64
#endif

/* LLM Gateway configuration */
#ifndef AK_LLM_MODE_LOCAL
#define AK_LLM_MODE_LOCAL               1       /* Local model via virtio */
#endif

#ifndef AK_LLM_MODE_EXTERNAL
#define AK_LLM_MODE_EXTERNAL            1       /* External API via HTTPS */
#endif

/* External state sync */
#ifndef AK_ENABLE_STATE_SYNC
#define AK_ENABLE_STATE_SYNC            1       /* Ephemeral VM with external state */
#endif

#ifndef AK_STATE_SYNC_INTERVAL_MS
#define AK_STATE_SYNC_INTERVAL_MS       5000    /* Sync every 5 seconds */
#endif

#endif /* AK_CONFIG_H */
