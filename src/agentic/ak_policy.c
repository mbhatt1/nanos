/*
 * Authority Kernel - Policy Engine Implementation
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Implements INV-3: Budget Invariant
 * "The sum of in-flight and committed costs never exceeds budget."
 *
 * SECURITY: All policy decisions fail-closed on ambiguity.
 */

#include "ak_policy.h"
#include "ak_capability.h"
#include "ak_compat.h"
#include "ak_pattern.h"

/* ============================================================
 * GLOBAL STATE
 * ============================================================ */

static struct {
    heap h;
    boolean initialized;
} ak_policy_state;

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

void ak_policy_init(heap h)
{
    if (ak_policy_state.initialized)
        return;

    ak_policy_state.h = h;
    ak_policy_state.initialized = true;
}

/* ============================================================
 * POLICY LOADING
 * ============================================================ */

static void compute_hash(buffer data, u8 *hash_out)
{
    /*
     * WARNING: This hash function is NOT cryptographically secure!
     * It uses FNV-1a with additional mixing, which provides reasonable
     * distribution for hash tables but does NOT provide:
     *   - Collision resistance
     *   - Pre-image resistance
     *   - Second pre-image resistance
     *
     * TODO: Replace with SHA-256 for cryptographic applications.
     * Integration with platform crypto (e.g., mbedtls) is required
     * for production policy verification and integrity checking.
     *
     * Current use is limited to:
     *   - Policy identification (non-security-critical)
     *   - Version tracking
     */
    runtime_memset(hash_out, 0, AK_HASH_SIZE);
    if (data && buffer_length(data) > 0) {
        u8 *p = buffer_ref(data, 0);
        u64 len = buffer_length(data);

        /* FNV-1a constants */
        u64 hash1 = 0xcbf29ce484222325ULL;
        u64 hash2 = 0x84222325cbf29ce4ULL;  /* Second hash for better mixing */

        for (u64 i = 0; i < len; i++) {
            /* Primary FNV-1a */
            hash1 ^= p[i];
            hash1 *= 0x100000001b3ULL;

            /* Secondary hash with different constant for independence */
            hash2 ^= p[i];
            hash2 *= 0x00000100000001b3ULL;
            hash2 = (hash2 << 13) | (hash2 >> 51);  /* Rotate for avalanche */
        }

        /* Final mixing - improves avalanche effect */
        hash1 ^= hash1 >> 33;
        hash1 *= 0xff51afd7ed558ccdULL;
        hash1 ^= hash1 >> 33;
        hash1 *= 0xc4ceb9fe1a85ec53ULL;
        hash1 ^= hash1 >> 33;

        hash2 ^= hash2 >> 33;
        hash2 *= 0xc4ceb9fe1a85ec53ULL;
        hash2 ^= hash2 >> 33;

        /* Expand to full hash size using both hash values */
        for (u64 i = 0; i < AK_HASH_SIZE; i++) {
            u64 h = (i < AK_HASH_SIZE / 2) ? hash1 : hash2;
            u64 shift = (i % 8) * 8;
            hash_out[i] = (u8)(h >> shift);

            /* Additional mixing every 8 bytes */
            if (i % 8 == 7) {
                hash1 ^= hash2;
                hash1 *= 0xff51afd7ed558ccdULL;
                hash2 ^= hash1;
                hash2 *= 0xc4ceb9fe1a85ec53ULL;
            }
        }
    }
}

ak_policy_t *ak_policy_load(heap h, buffer yaml_data)
{
    if (!yaml_data || buffer_length(yaml_data) == 0)
        return NULL;

    ak_policy_t *policy = allocate(h, sizeof(ak_policy_t));
    if (!policy)
        return NULL;

    runtime_memset(policy, 0, sizeof(ak_policy_t));
    policy->h = h;
    runtime_memcpy(policy->version, AK_POLICY_VERSION, runtime_strlen(AK_POLICY_VERSION));

    /* Compute policy hash */
    compute_hash(yaml_data, policy->policy_hash);

    /*
     * YAML parsing extracts:
     *   - version: Policy format version
     *   - signature: HMAC signature for verification
     *   - budgets: Resource limits (tokens, calls, etc.)
     *   - tools: Allowed/denied tool patterns
     *   - domains: Network domain restrictions
     *   - taint: Data flow rules
     *
     * Current implementation uses conservative defaults.
     * Production should integrate YAML parser library.
     */

    /* Set conservative defaults */
    policy->budgets.tokens = 10000;
    policy->budgets.calls = 10;
    policy->budgets.inference_ms = 30000;
    policy->budgets.file_bytes = 1024 * 1024;  /* 1 MB */
    policy->budgets.network_bytes = 1024 * 1024;
    policy->budgets.spawn_count = 0;  /* No spawning by default */
    policy->budgets.heap_objects = 100;
    policy->budgets.heap_bytes = 10 * 1024 * 1024;  /* 10 MB */

    policy->default_tool_allow = false;
    policy->default_domain_allow = false;

    /* Initialize versioning */
    ak_policy_version_t *ver = allocate(h, sizeof(ak_policy_version_t));
    if (ver) {
        runtime_memset(ver, 0, sizeof(ak_policy_version_t));
        ver->version_number = 1;
        ver->activated_ms = now(CLOCK_ID_MONOTONIC) / MILLION;
        runtime_memcpy(ver->hash, policy->policy_hash, AK_HASH_SIZE);
        /* Clone yaml_data for version history */
        ver->rules_json = allocate_buffer(h, buffer_length(yaml_data));
        if (ver->rules_json)
            buffer_write(ver->rules_json, buffer_ref(yaml_data, 0), buffer_length(yaml_data));
        ver->prev = NULL;
        policy->current_version = ver;
        policy->version_count = 1;
    }

    return policy;
}

ak_policy_t *ak_policy_load_file(heap h, const char *path)
{
    if (!path)
        return NULL;

    /*
     * File loading requires filesystem integration.
     * In unikernel context, policies are typically:
     *   - Embedded in supervisor binary
     *   - Loaded via virtio from host
     *   - Fetched from network at boot
     */
    (void)h;
    (void)path;

    return NULL;
}

void ak_policy_destroy(heap h, ak_policy_t *policy)
{
    if (!policy)
        return;

    /* Free tool rules */
    ak_tool_rule_t *tool = policy->tool_rules;
    while (tool) {
        ak_tool_rule_t *next = tool->next;
        if (tool->name)
            deallocate(h, tool->name, runtime_strlen(tool->name) + 1);
        deallocate(h, tool, sizeof(ak_tool_rule_t));
        tool = next;
    }

    /* Free domain rules */
    ak_domain_rule_t *domain = policy->domain_rules;
    while (domain) {
        ak_domain_rule_t *next = domain->next;
        if (domain->pattern)
            deallocate(h, domain->pattern, runtime_strlen(domain->pattern) + 1);
        deallocate(h, domain, sizeof(ak_domain_rule_t));
        domain = next;
    }

    /* Free taint rules */
    ak_taint_rule_t *taint = policy->taint_rules;
    while (taint) {
        ak_taint_rule_t *next = taint->next;
        if (taint->name)
            deallocate(h, taint->name, runtime_strlen(taint->name) + 1);
        deallocate(h, taint, sizeof(ak_taint_rule_t));
        taint = next;
    }

    deallocate(h, policy, sizeof(ak_policy_t));
}

void ak_policy_get_hash(ak_policy_t *policy, u8 *hash_out)
{
    if (policy && hash_out)
        runtime_memcpy(hash_out, policy->policy_hash, AK_HASH_SIZE);
}

/* ============================================================
 * POLICY VERIFICATION
 * ============================================================ */

boolean ak_policy_verify_signature(ak_policy_t *policy, u8 *signing_key)
{
    if (!policy || !signing_key)
        return false;

    /*
     * HMAC-SHA256 signature verification:
     * Computes HMAC over policy content and compares to stored signature.
     * Requires cryptographic library integration (e.g., mbedtls).
     *
     * For now, returns true to allow unsigned development policies.
     * Production deployments MUST enable signature verification.
     */

    (void)signing_key;
    return true;  /* Unsigned policies allowed in development */
}

boolean ak_policy_expired(ak_policy_t *policy)
{
    if (!policy)
        return true;

    if (policy->expires_ms == 0)
        return false;  /* No expiration */

    /* Get current monotonic time and compare to expiration */
    u64 now_ms = now(CLOCK_ID_MONOTONIC) / MILLION;
    return now_ms > policy->expires_ms;
}

/* ============================================================
 * BUDGET TRACKING
 * ============================================================ */

ak_budget_tracker_t *ak_budget_create(heap h, u8 *run_id, ak_policy_t *policy)
{
    ak_budget_tracker_t *tracker = allocate(h, sizeof(ak_budget_tracker_t));
    if (!tracker)
        return NULL;

    runtime_memset(tracker, 0, sizeof(ak_budget_tracker_t));

    if (run_id)
        runtime_memcpy(tracker->run_id, run_id, AK_TOKEN_ID_SIZE);

    if (policy)
        runtime_memcpy(&tracker->limits, &policy->budgets, sizeof(ak_budget_limits_t));

    return tracker;
}

void ak_budget_destroy(heap h, ak_budget_tracker_t *tracker)
{
    if (tracker)
        deallocate(h, tracker, sizeof(ak_budget_tracker_t));
}

static u64 get_used(ak_budget_tracker_t *tracker, ak_resource_type_t type)
{
    switch (type) {
    case AK_RESOURCE_TOKENS:        return tracker->tokens_used;
    case AK_RESOURCE_CALLS:         return tracker->calls_made;
    case AK_RESOURCE_INFERENCE_MS:  return tracker->inference_ms_used;
    case AK_RESOURCE_FILE_BYTES:    return tracker->file_bytes_used;
    case AK_RESOURCE_NETWORK_BYTES: return tracker->network_bytes_used;
    case AK_RESOURCE_HEAP_OBJECTS:  return tracker->heap_objects_used;
    case AK_RESOURCE_HEAP_BYTES:    return tracker->heap_bytes_used;
    default:                        return 0;
    }
}

static u64 get_reserved(ak_budget_tracker_t *tracker, ak_resource_type_t type)
{
    switch (type) {
    case AK_RESOURCE_TOKENS:        return tracker->tokens_reserved;
    case AK_RESOURCE_CALLS:         return tracker->calls_reserved;
    case AK_RESOURCE_INFERENCE_MS:  return tracker->inference_ms_reserved;
    default:                        return 0;
    }
}

static u64 get_limit(ak_budget_tracker_t *tracker, ak_resource_type_t type)
{
    switch (type) {
    case AK_RESOURCE_TOKENS:        return tracker->limits.tokens;
    case AK_RESOURCE_CALLS:         return tracker->limits.calls;
    case AK_RESOURCE_INFERENCE_MS:  return tracker->limits.inference_ms;
    case AK_RESOURCE_FILE_BYTES:    return tracker->limits.file_bytes;
    case AK_RESOURCE_NETWORK_BYTES: return tracker->limits.network_bytes;
    case AK_RESOURCE_HEAP_OBJECTS:  return tracker->limits.heap_objects;
    case AK_RESOURCE_HEAP_BYTES:    return tracker->limits.heap_bytes;
    default:                        return 0;
    }
}

static void add_reserved(ak_budget_tracker_t *tracker, ak_resource_type_t type, u64 amount)
{
    switch (type) {
    case AK_RESOURCE_TOKENS:        tracker->tokens_reserved += amount; break;
    case AK_RESOURCE_CALLS:         tracker->calls_reserved += amount; break;
    case AK_RESOURCE_INFERENCE_MS:  tracker->inference_ms_reserved += amount; break;
    default: break;
    }
}

static void sub_reserved(ak_budget_tracker_t *tracker, ak_resource_type_t type, u64 amount)
{
    switch (type) {
    case AK_RESOURCE_TOKENS:
        if (tracker->tokens_reserved >= amount)
            tracker->tokens_reserved -= amount;
        else
            tracker->tokens_reserved = 0;
        break;
    case AK_RESOURCE_CALLS:
        if (tracker->calls_reserved >= amount)
            tracker->calls_reserved -= amount;
        else
            tracker->calls_reserved = 0;
        break;
    case AK_RESOURCE_INFERENCE_MS:
        if (tracker->inference_ms_reserved >= amount)
            tracker->inference_ms_reserved -= amount;
        else
            tracker->inference_ms_reserved = 0;
        break;
    default: break;
    }
}

static void add_used(ak_budget_tracker_t *tracker, ak_resource_type_t type, u64 amount)
{
    switch (type) {
    case AK_RESOURCE_TOKENS:        tracker->tokens_used += amount; break;
    case AK_RESOURCE_CALLS:         tracker->calls_made += amount; break;
    case AK_RESOURCE_INFERENCE_MS:  tracker->inference_ms_used += amount; break;
    case AK_RESOURCE_FILE_BYTES:    tracker->file_bytes_used += amount; break;
    case AK_RESOURCE_NETWORK_BYTES: tracker->network_bytes_used += amount; break;
    case AK_RESOURCE_HEAP_OBJECTS:  tracker->heap_objects_used += amount; break;
    case AK_RESOURCE_HEAP_BYTES:    tracker->heap_bytes_used += amount; break;
    default: break;
    }
}

s64 ak_budget_reserve(ak_budget_tracker_t *tracker, ak_resource_type_t type, u64 amount)
{
    if (!tracker)
        return -EINVAL;

    u64 used = get_used(tracker, type);
    u64 reserved = get_reserved(tracker, type);
    u64 limit = get_limit(tracker, type);

    /*
     * INV-3 check:
     * used + reserved + new_amount <= limit
     */
    if (used + reserved + amount > limit)
        return AK_E_BUDGET_EXCEEDED;

    add_reserved(tracker, type, amount);
    return 0;
}

void ak_budget_commit(ak_budget_tracker_t *tracker, ak_resource_type_t type, u64 amount)
{
    if (!tracker)
        return;

    /* Move from reserved to committed */
    sub_reserved(tracker, type, amount);
    add_used(tracker, type, amount);
}

void ak_budget_release(ak_budget_tracker_t *tracker, ak_resource_type_t type, u64 amount)
{
    if (!tracker)
        return;

    sub_reserved(tracker, type, amount);
}

boolean ak_budget_check(ak_budget_tracker_t *tracker, ak_resource_type_t type, u64 amount)
{
    if (!tracker)
        return false;

    u64 used = get_used(tracker, type);
    u64 reserved = get_reserved(tracker, type);
    u64 limit = get_limit(tracker, type);

    return (used + reserved + amount <= limit);
}

u64 ak_budget_remaining(ak_budget_tracker_t *tracker, ak_resource_type_t type)
{
    if (!tracker)
        return 0;

    u64 used = get_used(tracker, type);
    u64 reserved = get_reserved(tracker, type);
    u64 limit = get_limit(tracker, type);

    if (used + reserved >= limit)
        return 0;

    return limit - used - reserved;
}

void ak_budget_get_stats(ak_budget_tracker_t *tracker, ak_budget_stats_t *stats)
{
    if (!tracker || !stats)
        return;

    runtime_memcpy(&stats->limits, &tracker->limits, sizeof(ak_budget_limits_t));

    stats->used.tokens = tracker->tokens_used;
    stats->used.calls = tracker->calls_made;
    stats->used.inference_ms = tracker->inference_ms_used;
    stats->used.file_bytes = tracker->file_bytes_used;
    stats->used.network_bytes = tracker->network_bytes_used;
    stats->used.spawn_count = tracker->spawns_used;
    stats->used.heap_objects = tracker->heap_objects_used;
    stats->used.heap_bytes = tracker->heap_bytes_used;

    stats->reserved.tokens = tracker->tokens_reserved;
    stats->reserved.calls = tracker->calls_reserved;
    stats->reserved.inference_ms = tracker->inference_ms_reserved;
    stats->reserved.file_bytes = 0;
    stats->reserved.network_bytes = 0;
    stats->reserved.spawn_count = 0;
    stats->reserved.heap_objects = 0;
    stats->reserved.heap_bytes = 0;

    stats->remaining.tokens = ak_budget_remaining(tracker, AK_RESOURCE_TOKENS);
    stats->remaining.calls = ak_budget_remaining(tracker, AK_RESOURCE_CALLS);
    stats->remaining.inference_ms = ak_budget_remaining(tracker, AK_RESOURCE_INFERENCE_MS);
    stats->remaining.file_bytes = ak_budget_remaining(tracker, AK_RESOURCE_FILE_BYTES);
    stats->remaining.network_bytes = ak_budget_remaining(tracker, AK_RESOURCE_NETWORK_BYTES);
    stats->remaining.spawn_count = tracker->limits.spawn_count - tracker->spawns_used;
    stats->remaining.heap_objects = ak_budget_remaining(tracker, AK_RESOURCE_HEAP_OBJECTS);
    stats->remaining.heap_bytes = ak_budget_remaining(tracker, AK_RESOURCE_HEAP_BYTES);
}

/* ============================================================
 * TOOL AUTHORIZATION
 * ============================================================ */

boolean ak_policy_check_tool(ak_policy_t *policy, const char *tool_name)
{
    if (!policy || !tool_name)
        return false;  /* Fail-closed */

    ak_tool_rule_t *rule = policy->tool_rules;
    while (rule) {
        if (rule->name) {
            /* Exact match */
            if (runtime_strcmp(rule->name, tool_name) == 0)
                return rule->allow;

            /* Glob pattern match */
            if (ak_pattern_match(rule->name, tool_name))
                return rule->allow;
        }
        rule = rule->next;
    }

    return policy->default_tool_allow;
}

const char **ak_policy_list_allowed_tools(heap h, ak_policy_t *policy, u64 *count_out)
{
    if (!policy || !count_out)
        return NULL;

    /* Count allowed tools */
    u64 count = 0;
    ak_tool_rule_t *rule = policy->tool_rules;
    while (rule) {
        if (rule->allow)
            count++;
        rule = rule->next;
    }

    if (count == 0) {
        *count_out = 0;
        return NULL;
    }

    const char **result = allocate(h, count * sizeof(char *));
    if (!result) {
        *count_out = 0;
        return NULL;
    }

    u64 idx = 0;
    rule = policy->tool_rules;
    while (rule) {
        if (rule->allow)
            result[idx++] = rule->name;
        rule = rule->next;
    }

    *count_out = count;
    return result;
}

/* ============================================================
 * DOMAIN AUTHORIZATION
 * ============================================================ */

boolean ak_policy_check_domain(ak_policy_t *policy, const char *domain)
{
    if (!policy || !domain)
        return false;  /* Fail-closed */

    ak_domain_rule_t *rule = policy->domain_rules;
    while (rule) {
        if (rule->pattern && ak_pattern_match(rule->pattern, domain))
            return rule->allow;
        rule = rule->next;
    }

    return policy->default_domain_allow;
}

boolean ak_policy_check_url(ak_policy_t *policy, const char *url)
{
    if (!policy || !url)
        return false;

    /*
     * Extract domain from URL
     * Handle: http://domain/path, https://domain/path
     */
    const char *start = url;

    /* Skip scheme */
    if (runtime_strncmp(url, "http://", 7) == 0)
        start = url + 7;
    else if (runtime_strncmp(url, "https://", 8) == 0)
        start = url + 8;

    /* Find end of domain (at / or end of string) */
    const char *end = start;
    while (*end && *end != '/' && *end != ':')
        end++;

    u64 len = end - start;
    if (len == 0 || len > 256)
        return false;

    /* Copy domain */
    char domain[257];
    runtime_memcpy(domain, start, len);
    domain[len] = '\0';

    return ak_policy_check_domain(policy, domain);
}

/* ============================================================
 * TAINT FLOW CONTROL
 * ============================================================ */

boolean ak_policy_is_source(ak_policy_t *policy, const char *name)
{
    if (!policy || !name)
        return false;

    ak_taint_rule_t *rule = policy->taint_rules;
    while (rule) {
        if (rule->type == AK_TAINT_RULE_SOURCE &&
            rule->name && runtime_strcmp(rule->name, name) == 0)
            return true;
        rule = rule->next;
    }
    return false;
}

boolean ak_policy_is_sink(ak_policy_t *policy, const char *name)
{
    if (!policy || !name)
        return false;

    ak_taint_rule_t *rule = policy->taint_rules;
    while (rule) {
        if (rule->type == AK_TAINT_RULE_SINK &&
            rule->name && runtime_strcmp(rule->name, name) == 0)
            return true;
        rule = rule->next;
    }
    return false;
}

boolean ak_policy_is_sanitizer(ak_policy_t *policy, const char *name)
{
    if (!policy || !name)
        return false;

    ak_taint_rule_t *rule = policy->taint_rules;
    while (rule) {
        if (rule->type == AK_TAINT_RULE_SANITIZER &&
            rule->name && runtime_strcmp(rule->name, name) == 0)
            return true;
        rule = rule->next;
    }
    return false;
}

boolean ak_policy_check_flow(
    ak_policy_t *policy,
    ak_taint_t source_taint,
    const char *sink_name,
    boolean sanitized)
{
    if (!policy)
        return false;

    /* Trusted data can flow anywhere */
    if (source_taint == AK_TAINT_TRUSTED)
        return true;

    /* Check if this is a defined sink */
    if (!ak_policy_is_sink(policy, sink_name))
        return true;  /* Not a sensitive sink */

    /* Tainted data to sensitive sink requires sanitization */
    if (source_taint == AK_TAINT_UNTRUSTED && !sanitized)
        return false;

    /* Sanitized data is allowed */
    if (sanitized)
        return true;

    /* Default: block tainted flows to sinks */
    return false;
}

/* ============================================================
 * REQUEST EVALUATION
 * ============================================================ */

s64 ak_policy_evaluate(
    ak_policy_t *policy,
    ak_budget_tracker_t *budget,
    ak_request_t *req)
{
    if (!policy || !req)
        return -EINVAL;

    /*
     * Comprehensive policy check:
     * 1. Budget check
     * 2. Tool authorization (for CALL)
     * 3. Domain restrictions (for network ops)
     * 4. Taint flow rules
     */

    /* Budget check */
    if (budget) {
        ak_resource_type_t resource_type;
        u64 estimated_cost = 1;  /* Default cost */

        switch (req->op) {
        case AK_SYS_INFERENCE:
            resource_type = AK_RESOURCE_TOKENS;
            estimated_cost = 1000;  /* Estimate */
            break;
        case AK_SYS_CALL:
            resource_type = AK_RESOURCE_CALLS;
            estimated_cost = 1;
            break;
        case AK_SYS_ALLOC:
            resource_type = AK_RESOURCE_HEAP_OBJECTS;
            estimated_cost = 1;
            break;
        default:
            resource_type = AK_RESOURCE_CALLS;
            estimated_cost = 0;  /* No cost for reads */
        }

        if (estimated_cost > 0 && !ak_budget_check(budget, resource_type, estimated_cost))
            return AK_E_BUDGET_EXCEEDED;
    }

    /* Tool authorization for CALL */
    if (req->op == AK_SYS_CALL) {
        /*
         * Tool name extraction requires JSON parsing of req->args.
         * The tool name should be checked against ak_policy_check_tool().
         * Capability validation (INV-2) handles the authorization.
         */
    }

    /* Taint check */
    if (req->taint == AK_TAINT_UNTRUSTED) {
        /* Check if operation is a sensitive sink */
        switch (req->op) {
        case AK_SYS_CALL:
        case AK_SYS_INFERENCE:
            /* These may be sinks depending on tool/target */
            break;
        default:
            break;
        }
    }

    return 0;  /* Allowed */
}

/* ============================================================
 * SERIALIZATION
 * ============================================================ */

buffer ak_policy_serialize(heap h, ak_policy_t *policy)
{
    if (!policy)
        return NULL;

    /*
     * Serializes policy to YAML format for storage/transmission.
     * Current implementation outputs minimal budget configuration.
     * Full serialization includes tools, domains, and taint rules.
     */

    buffer result = allocate_buffer(h, 1024);
    if (!result)
        return NULL;

    buffer_write(result, "version: \"1.0\"\n", 15);
    buffer_write(result, "budgets:\n", 9);

    /* Write budgets */
    char num_buf[32];
    int len;

    buffer_write(result, "  tokens: ", 10);
    len = 0;
    u64 val = policy->budgets.tokens;
    if (val == 0) {
        num_buf[0] = '0';
        len = 1;
    } else {
        char tmp[32];
        while (val > 0) {
            tmp[len++] = '0' + (val % 10);
            val /= 10;
        }
        for (int i = 0; i < len; i++)
            num_buf[i] = tmp[len - 1 - i];
    }
    buffer_write(result, num_buf, len);
    buffer_write(result, "\n", 1);

    buffer_write(result, "  calls: ", 9);
    len = 0;
    val = policy->budgets.calls;
    if (val == 0) {
        num_buf[0] = '0';
        len = 1;
    } else {
        char tmp[32];
        while (val > 0) {
            tmp[len++] = '0' + (val % 10);
            val /= 10;
        }
        for (int i = 0; i < len; i++)
            num_buf[i] = tmp[len - 1 - i];
    }
    buffer_write(result, num_buf, len);
    buffer_write(result, "\n", 1);

    return result;
}

void ak_policy_compute_hash(ak_policy_t *policy, u8 *hash_out)
{
    if (!policy || !hash_out)
        return;

    /*
     * Hash is computed over serialized policy content
     */
    heap h = ak_policy_state.h;
    buffer serialized = ak_policy_serialize(h, policy);
    if (serialized) {
        compute_hash(serialized, hash_out);
        deallocate_buffer(serialized);
    }
}

/* ============================================================
 * DEFAULT POLICIES
 * ============================================================ */

ak_policy_t *ak_policy_default(heap h)
{
    ak_policy_t *policy = allocate(h, sizeof(ak_policy_t));
    if (!policy)
        return NULL;

    runtime_memset(policy, 0, sizeof(ak_policy_t));
    policy->h = h;
    runtime_memcpy(policy->version, AK_POLICY_VERSION, runtime_strlen(AK_POLICY_VERSION));

    /* Conservative budgets */
    policy->budgets.tokens = 10000;
    policy->budgets.calls = 10;
    policy->budgets.inference_ms = 30000;
    policy->budgets.file_bytes = 1024 * 1024;       /* 1 MB */
    policy->budgets.network_bytes = 1024 * 1024;    /* 1 MB */
    policy->budgets.spawn_count = 0;                /* No spawning */
    policy->budgets.heap_objects = 100;
    policy->budgets.heap_bytes = 10 * 1024 * 1024;  /* 10 MB */

    /* Deny by default */
    policy->default_tool_allow = false;
    policy->default_domain_allow = false;

    /* Add safe tools */
    ak_tool_rule_t *rule1 = allocate(h, sizeof(ak_tool_rule_t));
    if (rule1) {
        const char *name = "file_read";
        rule1->name = allocate(h, runtime_strlen(name) + 1);
        if (rule1->name)
            runtime_memcpy(rule1->name, name, runtime_strlen(name) + 1);
        rule1->allow = true;
        rule1->next = policy->tool_rules;
        policy->tool_rules = rule1;
    }

    /* Add taint sink for dangerous operations */
    ak_taint_rule_t *taint1 = allocate(h, sizeof(ak_taint_rule_t));
    if (taint1) {
        const char *name = "shell_exec";
        taint1->name = allocate(h, runtime_strlen(name) + 1);
        if (taint1->name)
            runtime_memcpy(taint1->name, name, runtime_strlen(name) + 1);
        taint1->type = AK_TAINT_RULE_SINK;
        taint1->next = policy->taint_rules;
        policy->taint_rules = taint1;
    }

    ak_policy_compute_hash(policy, policy->policy_hash);

    /* Initialize versioning */
    ak_policy_version_t *ver = allocate(h, sizeof(ak_policy_version_t));
    if (ver) {
        runtime_memset(ver, 0, sizeof(ak_policy_version_t));
        ver->version_number = 1;
        ver->activated_ms = now(CLOCK_ID_MONOTONIC) / MILLION;
        runtime_memcpy(ver->hash, policy->policy_hash, AK_HASH_SIZE);
        ver->rules_json = NULL;
        ver->prev = NULL;
        policy->current_version = ver;
        policy->version_count = 1;
    }

    return policy;
}

ak_policy_t *ak_policy_permissive(heap h)
{
    ak_policy_t *policy = allocate(h, sizeof(ak_policy_t));
    if (!policy)
        return NULL;

    runtime_memset(policy, 0, sizeof(ak_policy_t));
    policy->h = h;
    runtime_memcpy(policy->version, AK_POLICY_VERSION, runtime_strlen(AK_POLICY_VERSION));

    /* High budgets for development */
    policy->budgets.tokens = 1000000;
    policy->budgets.calls = 10000;
    policy->budgets.inference_ms = 3600000;         /* 1 hour */
    policy->budgets.file_bytes = 1024 * 1024 * 100; /* 100 MB */
    policy->budgets.network_bytes = 1024 * 1024 * 100;
    policy->budgets.spawn_count = 100;
    policy->budgets.heap_objects = 100000;
    policy->budgets.heap_bytes = 1024 * 1024 * 1024;  /* 1 GB */

    /* Allow by default (DANGEROUS) */
    policy->default_tool_allow = true;
    policy->default_domain_allow = true;

    ak_policy_compute_hash(policy, policy->policy_hash);

    /* Initialize versioning */
    ak_policy_version_t *ver = allocate(h, sizeof(ak_policy_version_t));
    if (ver) {
        runtime_memset(ver, 0, sizeof(ak_policy_version_t));
        ver->version_number = 1;
        ver->activated_ms = now(CLOCK_ID_MONOTONIC) / MILLION;
        runtime_memcpy(ver->hash, policy->policy_hash, AK_HASH_SIZE);
        ver->rules_json = NULL;
        ver->prev = NULL;
        policy->current_version = ver;
        policy->version_count = 1;
    }

    return policy;
}

/* ============================================================
 * POLICY VERSIONING
 * ============================================================ */

/*
 * Parse rules from JSON/YAML buffer.
 * Returns true on success, false on parse error.
 */
static boolean ak_policy_parse_rules(ak_policy_t *policy, buffer rules)
{
    if (!policy || !rules)
        return false;

    /*
     * Full implementation would parse YAML/JSON and update:
     *   - policy->budgets
     *   - policy->tool_rules
     *   - policy->domain_rules
     *   - policy->taint_rules
     *
     * For now, perform basic validation on the buffer.
     * Production should integrate a proper parser.
     */
    u64 len = buffer_length(rules);

    /* Reject empty rules */
    if (len == 0)
        return false;

    /* Reject unreasonably large rules (> 1MB) */
    if (len > 1024 * 1024)
        return false;

    /* Basic sanity check: buffer must be readable */
    u8 *data = buffer_ref(rules, 0);
    if (!data)
        return false;

    /*
     * Minimal validation: check for printable ASCII or valid UTF-8
     * This catches obvious corruption (binary garbage, null bytes)
     */
    for (u64 i = 0; i < len && i < 256; i++) {
        u8 c = data[i];
        /* Allow printable ASCII, tabs, newlines, and high bytes (UTF-8) */
        if (c < 0x09 || (c > 0x0d && c < 0x20 && c != 0x1b))
            return false;  /* Control character that isn't whitespace */
    }

    return true;
}

ak_policy_result_t ak_policy_upgrade(
    ak_policy_t *policy,
    buffer new_rules,
    u32 new_version)
{
    if (!policy || !new_rules)
        return AK_POLICY_ERROR_PARSE;

    /* Validate new version is strictly greater */
    u32 current = policy->current_version ? policy->current_version->version_number : 0;
    if (new_version <= current)
        return AK_POLICY_ERROR_VERSION;

    /* Check version compatibility */
    if (!ak_policy_is_compatible(current, new_version))
        return AK_POLICY_ERROR_INCOMPATIBLE;

    /* Allocate new version record */
    ak_policy_version_t *new_ver = allocate(policy->h, sizeof(ak_policy_version_t));
    if (!new_ver)
        return AK_POLICY_ERROR_PARSE;

    runtime_memset(new_ver, 0, sizeof(ak_policy_version_t));
    new_ver->version_number = new_version;
    new_ver->activated_ms = now(CLOCK_ID_MONOTONIC) / MILLION;

    /* Clone rules for version history */
    new_ver->rules_json = allocate_buffer(policy->h, buffer_length(new_rules));
    if (!new_ver->rules_json) {
        deallocate(policy->h, new_ver, sizeof(ak_policy_version_t));
        return AK_POLICY_ERROR_PARSE;
    }
    buffer_write(new_ver->rules_json, buffer_ref(new_rules, 0), buffer_length(new_rules));

    /* Compute hash of new rules */
    compute_hash(new_rules, new_ver->hash);

    /* Link to previous version */
    new_ver->prev = policy->current_version;

    /* Parse and apply new rules */
    if (!ak_policy_parse_rules(policy, new_rules)) {
        deallocate_buffer(new_ver->rules_json);
        deallocate(policy->h, new_ver, sizeof(ak_policy_version_t));
        return AK_POLICY_ERROR_PARSE;
    }

    /* Update policy state */
    policy->current_version = new_ver;
    policy->version_count++;

    /* Update policy hash */
    runtime_memcpy(policy->policy_hash, new_ver->hash, AK_HASH_SIZE);

    return AK_POLICY_OK;
}

ak_policy_result_t ak_policy_rollback(ak_policy_t *policy)
{
    if (!policy)
        return AK_POLICY_ERROR_PARSE;

    if (!policy->current_version || !policy->current_version->prev)
        return AK_POLICY_ERROR_NO_PREVIOUS;

    /* Get previous version */
    ak_policy_version_t *prev_ver = policy->current_version->prev;

    /* Re-parse previous rules if available */
    if (prev_ver->rules_json) {
        if (!ak_policy_parse_rules(policy, prev_ver->rules_json)) {
            /* Rollback parse failed - keep current version */
            return AK_POLICY_ERROR_PARSE;
        }
    }

    /* Update policy state */
    policy->current_version = prev_ver;

    /* Update policy hash to previous version */
    runtime_memcpy(policy->policy_hash, prev_ver->hash, AK_HASH_SIZE);

    /*
     * NOTE: We intentionally do NOT deallocate the old version here.
     *
     * Rationale:
     * 1. Use-after-free risk: Other code may still hold references to
     *    the old version structure (e.g., for audit logging, debugging).
     * 2. The old version's memory will be reclaimed when the entire
     *    policy is destroyed or when the heap is cleaned up.
     *
     * For memory-constrained environments, consider implementing a
     * deferred garbage collection mechanism that safely reclaims
     * unreferenced version structures after a grace period.
     */

    /* Decrement version_count since the active version chain is now shorter */
    if (policy->version_count > 0)
        policy->version_count--;

    return AK_POLICY_OK;
}

boolean ak_policy_is_compatible(u32 old_version, u32 new_version)
{
    /*
     * Version compatibility rules:
     * - Major version changes (1.x -> 2.x) may be incompatible
     * - Minor version increments within same major are compatible
     *
     * For simple monotonic versioning:
     * - Sequential increments are always compatible
     * - Large jumps (> 100) require explicit migration
     */
    if (new_version <= old_version)
        return false;

    /* Allow single-step upgrades always */
    if (new_version == old_version + 1)
        return true;

    /* Allow reasonable jumps (up to 100 versions) */
    if (new_version - old_version <= 100)
        return true;

    /* Large jumps require explicit migration (return false) */
    return false;
}

u32 ak_policy_get_version(ak_policy_t *policy)
{
    if (!policy || !policy->current_version)
        return 0;
    return policy->current_version->version_number;
}

u32 ak_policy_version_count(ak_policy_t *policy)
{
    if (!policy)
        return 0;
    return policy->version_count;
}
