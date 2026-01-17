/*
 * Authority Kernel - Tool Registry
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Dynamic tool registration and discovery system for the Authority Kernel.
 *
 * This module provides:
 *   - Dynamic tool registration with versioning
 *   - Tool discovery and lookup with version matching
 *   - Tool invocation with authorization checks
 *   - Mock mode for testing
 *   - Tool composition (chaining tools together)
 *   - JSON Schema validation for tool arguments
 *
 * SECURITY:
 *   - All tool invocations flow through ak_authorize_and_execute()
 *   - Tool handlers cannot bypass AK policy enforcement
 *   - Mock mode is for testing only and audit-logged
 */

#ifndef AK_TOOL_REGISTRY_H
#define AK_TOOL_REGISTRY_H

#include "ak_types.h"
#include "ak_effects.h"

/* Forward declaration */
typedef struct ak_tool_def ak_tool_def_t;

/* ============================================================
 * TOOL HANDLER FUNCTION SIGNATURE
 * ============================================================
 * Tool handlers receive arguments as a buffer (JSON) and must
 * produce a result buffer. The context provides access to
 * capabilities and policy.
 */

/*
 * Tool handler function signature.
 *
 * @param ctx       AK context for authorization checks
 * @param args      Input arguments (JSON buffer)
 * @param result    Output result buffer (allocated by handler)
 * @return          0 on success, negative error code on failure
 */
typedef s64 (*ak_tool_handler_fn)(ak_ctx_t *ctx, buffer args, buffer *result);

/* ============================================================
 * TOOL DEFINITION FLAGS
 * ============================================================ */

#define AK_TOOL_FLAG_NONE           0x0000
#define AK_TOOL_FLAG_ASYNC          0x0001  /* Tool supports async execution */
#define AK_TOOL_FLAG_IDEMPOTENT     0x0002  /* Safe to retry on failure */
#define AK_TOOL_FLAG_SENSITIVE      0x0004  /* Contains/processes PII/secrets */
#define AK_TOOL_FLAG_READ_ONLY      0x0008  /* No side effects */
#define AK_TOOL_FLAG_INTERNAL       0x0010  /* Not exposed to agents */
#define AK_TOOL_FLAG_DEPRECATED     0x0020  /* Scheduled for removal */
#define AK_TOOL_FLAG_EXPERIMENTAL   0x0040  /* API may change */
#define AK_TOOL_FLAG_COMPOSABLE     0x0080  /* Can be used in composition */

/* ============================================================
 * TOOL DEFINITION STRUCTURE
 * ============================================================
 * Complete description of a registered tool including:
 *   - Identity (name, version)
 *   - Handler function and context
 *   - Input/output JSON schemas
 *   - Execution parameters (timeout, flags)
 *   - Mock mode for testing
 */

struct ak_tool_def {
    /* Identity */
    char name[64];              /* Tool name (must be unique) */
    char version[16];           /* Semantic version (e.g., "1.2.3") */
    char description[256];      /* Human-readable description */

    /* JSON Schemas for validation */
    char input_schema[1024];    /* JSON Schema for input arguments */
    char output_schema[1024];   /* JSON Schema for output result */

    /* Handler */
    ak_tool_handler_fn handler; /* Tool implementation */
    void *handler_ctx;          /* Context passed to handler */

    /* Behavior */
    u32 flags;                  /* AK_TOOL_FLAG_* */
    u64 timeout_ms;             /* Execution timeout (0 = no limit) */

    /* Mock mode for testing */
    boolean mock_enabled;       /* If true, return mock_response instead */
    buffer mock_response;       /* Pre-configured mock response */

    /* Capability requirements */
    ak_cap_type_t required_cap; /* Required capability type */
    char cap_resource[256];     /* Required resource pattern */

    /* Metrics */
    u64 invocation_count;       /* Times invoked */
    u64 success_count;          /* Successful invocations */
    u64 failure_count;          /* Failed invocations */
    u64 total_time_ns;          /* Total execution time */
    u64 registered_ms;          /* Registration timestamp */

    /* Internal linkage */
    boolean active;             /* Is tool registered */
    struct ak_tool_def *next;   /* For hash bucket chaining */
};

/* ============================================================
 * VERSION MATCHING MODES
 * ============================================================
 * Tools can be looked up with various version matching strategies:
 *   - Exact:   "1.2.3"         Only this exact version
 *   - Major:   "1.*"           Any version with major version 1
 *   - Any:     "*"             Any version (returns latest)
 *   - Semver:  "^1.2.0"        Compatible versions (>=1.2.0 <2.0.0)
 *   - Range:   ">=1.0.0"       All versions >= 1.0.0
 */

typedef enum ak_version_match {
    AK_VERSION_EXACT,           /* Exact version match required */
    AK_VERSION_MAJOR,           /* Same major version */
    AK_VERSION_ANY,             /* Any version */
    AK_VERSION_SEMVER,          /* Semver compatible (^) */
    AK_VERSION_RANGE,           /* Version range (>=, <=, etc.) */
} ak_version_match_t;

/* ============================================================
 * TOOL LIST STRUCTURE
 * ============================================================
 * Returned by ak_tool_list() for enumerating registered tools.
 */

typedef struct ak_tool_list {
    ak_tool_def_t **tools;      /* Array of tool pointers */
    u32 count;                  /* Number of tools */
    u32 capacity;               /* Array capacity */
} ak_tool_list_t;

/* ============================================================
 * COMPOSITE TOOL STRUCTURE
 * ============================================================
 * A composite tool chains multiple tools together, passing
 * the output of each tool as input to the next.
 */

#define AK_MAX_COMPOSITE_CHAIN  16

typedef struct ak_composite_tool {
    char name[64];              /* Composite tool name */
    char version[16];           /* Composite version */

    /* Chain of tools */
    struct {
        char name[64];
        char version[16];
    } chain[AK_MAX_COMPOSITE_CHAIN];
    u32 chain_length;

    /* Behavior */
    boolean stop_on_error;      /* Stop chain on first error */
    u64 total_timeout_ms;       /* Timeout for entire chain */
} ak_composite_tool_t;

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

/*
 * Initialize the tool registry.
 *
 * Must be called before any tool registration or lookup.
 * Typically called by ak_agentic_init().
 *
 * @param h     Heap for allocations
 * @return      0 on success, negative error code on failure
 */
int ak_tool_registry_init(heap h);

/*
 * Shutdown the tool registry.
 *
 * Unregisters all tools and frees resources.
 */
void ak_tool_registry_shutdown(void);

/* ============================================================
 * TOOL REGISTRATION
 * ============================================================ */

/*
 * Register a tool with the registry.
 *
 * The tool definition is copied, so the caller can free/modify
 * their copy after registration.
 *
 * @param def   Tool definition (copied)
 * @return      0 on success
 *              -EEXIST if tool with same name+version exists
 *              -EINVAL if definition is invalid
 *              -ENOSPC if registry is full
 */
int ak_tool_register(const ak_tool_def_t *def);

/*
 * Unregister a tool by name.
 *
 * Removes all versions of the named tool.
 *
 * @param name  Tool name to unregister
 * @return      0 on success, -ENOENT if not found
 */
int ak_tool_unregister(const char *name);

/*
 * Unregister a specific tool version.
 *
 * @param name      Tool name
 * @param version   Version to unregister
 * @return          0 on success, -ENOENT if not found
 */
int ak_tool_unregister_version(const char *name, const char *version);

/* ============================================================
 * TOOL LOOKUP
 * ============================================================ */

/*
 * Look up a tool by name and version.
 *
 * Version matching:
 *   - NULL or "*" matches any version (returns latest)
 *   - "1.*" matches any version with major version 1
 *   - "^1.2.0" matches semver-compatible versions
 *   - Exact string matches exact version
 *
 * @param name      Tool name
 * @param version   Version pattern (NULL for any)
 * @return          Tool definition or NULL if not found
 */
ak_tool_def_t *ak_tool_lookup(const char *name, const char *version);

/*
 * Look up a tool with explicit match mode.
 *
 * @param name      Tool name
 * @param version   Version string
 * @param mode      Version matching mode
 * @return          Tool definition or NULL if not found
 */
ak_tool_def_t *ak_tool_lookup_ex(const char *name, const char *version,
                                  ak_version_match_t mode);

/*
 * List all registered tools.
 *
 * Returns a list of all active tools. The caller must free the
 * list using ak_tool_list_free().
 *
 * @param h     Heap for allocation
 * @return      Tool list (caller frees) or NULL on error
 */
ak_tool_list_t *ak_tool_list(heap h);

/*
 * Free a tool list.
 *
 * @param h     Heap used for allocation
 * @param list  List to free
 */
void ak_tool_list_free(heap h, ak_tool_list_t *list);

/*
 * Check if a tool exists.
 *
 * @param name      Tool name
 * @param version   Version pattern (NULL for any)
 * @return          true if tool exists
 */
boolean ak_tool_exists(const char *name, const char *version);

/* ============================================================
 * TOOL INVOCATION
 * ============================================================ */

/*
 * Invoke a tool with authorization check.
 *
 * Pipeline:
 *   1. Look up tool by name/version
 *   2. Build AK_E_TOOL_CALL effect
 *   3. Route through ak_authorize_and_execute()
 *   4. If mock_enabled, return mock_response
 *   5. Validate args against input_schema (if present)
 *   6. Execute handler
 *   7. Validate result against output_schema (if present)
 *   8. Update metrics
 *
 * @param ctx       AK context for authorization
 * @param name      Tool name
 * @param version   Version pattern (NULL for any)
 * @param args      Input arguments (JSON)
 * @param result    Output buffer for result (allocated by callee)
 * @return          0 on success, negative error on failure
 */
int ak_tool_invoke(ak_ctx_t *ctx, const char *name, const char *version,
                   buffer args, buffer *result);

/*
 * Invoke a tool with explicit timeout.
 *
 * @param ctx           AK context
 * @param name          Tool name
 * @param version       Version pattern
 * @param args          Input arguments
 * @param result        Output buffer
 * @param timeout_ms    Timeout in milliseconds (0 = use tool's default)
 * @return              0 on success, negative error on failure
 */
int ak_tool_invoke_timeout(ak_ctx_t *ctx, const char *name, const char *version,
                           buffer args, buffer *result, u64 timeout_ms);

/* ============================================================
 * MOCK MODE
 * ============================================================
 * Mock mode allows tools to return pre-configured responses
 * without executing the actual handler. Useful for testing.
 */

/*
 * Enable mock mode for a tool.
 *
 * When enabled, the tool will return the mock response instead
 * of executing the handler. Mock invocations are audit-logged.
 *
 * @param name      Tool name
 * @param response  Mock response to return (copied)
 * @return          0 on success, -ENOENT if tool not found
 */
int ak_tool_set_mock(const char *name, buffer response);

/*
 * Enable mock mode with version targeting.
 *
 * @param name      Tool name
 * @param version   Specific version to mock
 * @param response  Mock response to return
 * @return          0 on success, -ENOENT if tool not found
 */
int ak_tool_set_mock_version(const char *name, const char *version,
                              buffer response);

/*
 * Disable mock mode for a tool.
 *
 * @param name  Tool name
 * @return      0 on success, -ENOENT if not found
 */
int ak_tool_clear_mock(const char *name);

/*
 * Check if mock mode is enabled for a tool.
 *
 * @param name      Tool name
 * @param version   Version (NULL for any)
 * @return          true if mock mode enabled
 */
boolean ak_tool_is_mock(const char *name, const char *version);

/* ============================================================
 * SCHEMA VALIDATION
 * ============================================================ */

/*
 * Validate arguments against a tool's input schema.
 *
 * @param tool      Tool definition
 * @param args      Arguments to validate (JSON)
 * @return          0 if valid, -EINVAL if invalid, -ENOENT if no schema
 */
int ak_tool_validate_args(const ak_tool_def_t *tool, buffer args);

/*
 * Validate result against a tool's output schema.
 *
 * @param tool      Tool definition
 * @param result    Result to validate (JSON)
 * @return          0 if valid, -EINVAL if invalid, -ENOENT if no schema
 */
int ak_tool_validate_result(const ak_tool_def_t *tool, buffer result);

/*
 * Get a tool's input schema.
 *
 * @param name      Tool name
 * @param version   Version (NULL for any)
 * @return          Input schema string or NULL if not found
 */
const char *ak_tool_get_input_schema(const char *name, const char *version);

/*
 * Get a tool's output schema.
 *
 * @param name      Tool name
 * @param version   Version (NULL for any)
 * @return          Output schema string or NULL if not found
 */
const char *ak_tool_get_output_schema(const char *name, const char *version);

/*
 * Get both schemas for a tool.
 *
 * @param name          Tool name
 * @param input_out     Output for input schema (may be NULL)
 * @param output_out    Output for output schema (may be NULL)
 * @return              0 on success, -ENOENT if tool not found
 */
int ak_tool_get_schema(const char *name, const char **input_out,
                       const char **output_out);

/* ============================================================
 * TOOL COMPOSITION
 * ============================================================
 * Composite tools chain multiple tools together. The output
 * of each tool becomes the input to the next.
 */

/*
 * Create a composite tool from a list of tools.
 *
 * The composite tool executes each tool in order, passing the
 * output of one as input to the next. If any tool fails and
 * stop_on_error is true, the chain stops.
 *
 * @param name          Composite tool name
 * @param version       Composite version
 * @param tool_names    Array of tool names
 * @param tool_versions Array of tool versions (may contain NULLs)
 * @param count         Number of tools in chain
 * @return              0 on success, negative error on failure
 */
int ak_tool_compose(const char *name, const char *version,
                    const char **tool_names, const char **tool_versions,
                    u32 count);

/*
 * Create composite tool from structure.
 *
 * @param composite     Composite tool definition
 * @return              0 on success, negative error on failure
 */
int ak_tool_compose_ex(const ak_composite_tool_t *composite);

/*
 * Get composite tool definition.
 *
 * @param name      Composite tool name
 * @return          Composite definition or NULL if not found/not composite
 */
ak_composite_tool_t *ak_tool_get_composite(const char *name);

/*
 * Check if a tool is a composite tool.
 *
 * @param name  Tool name
 * @return      true if tool is composite
 */
boolean ak_tool_is_composite(const char *name);

/* ============================================================
 * VERSION UTILITIES
 * ============================================================ */

/*
 * Parse a semantic version string.
 *
 * @param version   Version string (e.g., "1.2.3")
 * @param major     Output major version
 * @param minor     Output minor version
 * @param patch     Output patch version
 * @return          0 on success, -EINVAL if invalid
 */
int ak_version_parse(const char *version, u32 *major, u32 *minor, u32 *patch);

/*
 * Compare two versions.
 *
 * @param v1    First version string
 * @param v2    Second version string
 * @return      <0 if v1 < v2, 0 if equal, >0 if v1 > v2
 */
int ak_version_compare(const char *v1, const char *v2);

/*
 * Check if a version matches a pattern.
 *
 * @param version   Version to check
 * @param pattern   Pattern to match against
 * @param mode      Matching mode
 * @return          true if version matches pattern
 */
boolean ak_version_matches(const char *version, const char *pattern,
                           ak_version_match_t mode);

/* ============================================================
 * STATISTICS
 * ============================================================ */

typedef struct ak_tool_registry_stats {
    u64 tools_registered;       /* Total tools ever registered */
    u64 tools_active;           /* Currently active tools */
    u64 tools_unregistered;     /* Tools unregistered */
    u64 invocations_total;      /* Total invocations */
    u64 invocations_success;    /* Successful invocations */
    u64 invocations_failed;     /* Failed invocations */
    u64 invocations_denied;     /* Denied by policy */
    u64 invocations_mock;       /* Mock mode invocations */
    u64 invocations_timeout;    /* Timed out invocations */
    u64 schema_validations;     /* Schema validations performed */
    u64 schema_failures;        /* Schema validation failures */
    u64 composite_invocations;  /* Composite tool invocations */
    u64 lookups_total;          /* Total lookups */
    u64 lookups_miss;           /* Lookups that found nothing */
} ak_tool_registry_stats_t;

/*
 * Get registry statistics.
 *
 * @param stats     Output statistics structure
 */
void ak_tool_registry_get_stats(ak_tool_registry_stats_t *stats);

/*
 * Reset registry statistics.
 */
void ak_tool_registry_reset_stats(void);

/* ============================================================
 * ERROR CODES
 * ============================================================ */

#define AK_E_TOOL_NOT_FOUND         (-4750)
#define AK_E_TOOL_VERSION_MISMATCH  (-4751)
#define AK_E_TOOL_ALREADY_EXISTS    (-4752)
#define AK_E_TOOL_REGISTRY_FULL     (-4753)
#define AK_E_TOOL_INVALID_DEF       (-4754)
#define AK_E_TOOL_SCHEMA_INVALID    (-4755)
#define AK_E_TOOL_ARGS_INVALID      (-4756)
#define AK_E_TOOL_RESULT_INVALID    (-4757)
#define AK_E_TOOL_TIMEOUT           (-4758)
#define AK_E_TOOL_MOCK_ENABLED      (-4759)  /* Informational, not error */
#define AK_E_TOOL_CHAIN_ERROR       (-4760)
#define AK_E_TOOL_CHAIN_TOO_LONG    (-4761)

/* ============================================================
 * CONSTANTS
 * ============================================================ */

#define AK_TOOL_REGISTRY_MAX_TOOLS      256
#define AK_TOOL_NAME_MAX                64
#define AK_TOOL_VERSION_MAX             16
#define AK_TOOL_DESCRIPTION_MAX         256
#define AK_TOOL_SCHEMA_MAX              1024
#define AK_TOOL_DEFAULT_TIMEOUT_MS      30000

#endif /* AK_TOOL_REGISTRY_H */
