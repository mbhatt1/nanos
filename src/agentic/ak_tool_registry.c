/*
 * Authority Kernel - Tool Registry Implementation
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Dynamic tool registration and discovery system for the Authority Kernel.
 *
 * This module implements:
 *   - Hash-based tool registry for O(1) average lookup
 *   - Semantic versioning with multiple match modes
 *   - Tool composition for chaining operations
 *   - Mock mode for testing
 *   - Integration with AK authorization
 *
 * SECURITY:
 *   - All invocations go through ak_authorize_and_execute()
 *   - Mock invocations are audit-logged
 *   - Tool handlers run in sandboxed context
 */

#include "ak_tool_registry.h"
#include "ak_audit.h"
#include "ak_compat.h"
#include "ak_effects.h"

/* ============================================================
 * STRING UTILITIES
 * ============================================================ */

static u64 local_strlen(const char *s) {
  if (!s)
    return 0;
  u64 len = 0;
  while (s[len])
    len++;
  return len;
}

static void local_strncpy(char *dest, const char *src, u64 n) {
  if (!dest || !src || n == 0)
    return;
  u64 i;
  for (i = 0; i < n - 1 && src[i]; i++) {
    dest[i] = src[i];
  }
  dest[i] = '\0';
}

static int local_strcmp(const char *s1, const char *s2) {
  if (!s1 || !s2)
    return s1 ? 1 : (s2 ? -1 : 0);
  while (*s1 && (*s1 == *s2)) {
    s1++;
    s2++;
  }
  return (unsigned char)*s1 - (unsigned char)*s2;
}

static int local_strncmp(const char *s1, const char *s2, u64 n) {
  if (!s1 || !s2)
    return s1 ? 1 : (s2 ? -1 : 0);
  while (n > 0 && *s1 && (*s1 == *s2)) {
    s1++;
    s2++;
    n--;
  }
  if (n == 0)
    return 0;
  return (unsigned char)*s1 - (unsigned char)*s2;
}

static void local_memzero(void *ptr, u64 size) {
  u8 *p = (u8 *)ptr;
  while (size-- > 0)
    *p++ = 0;
}

static void local_memcpy(void *dest, const void *src, u64 size) {
  u8 *d = (u8 *)dest;
  const u8 *s = (const u8 *)src;
  while (size-- > 0)
    *d++ = *s++;
}

static boolean local_isdigit(char c) { return c >= '0' && c <= '9'; }

/* ============================================================
 * HASH TABLE IMPLEMENTATION
 * ============================================================
 * Simple hash table for tool lookup by name.
 */

#define TOOL_HASH_BUCKETS 64

/* Hash function for tool names */
static u32 tool_hash(const char *name) {
  u32 hash = 5381;
  while (*name) {
    hash = ((hash << 5) + hash) + (unsigned char)*name;
    name++;
  }
  return hash % TOOL_HASH_BUCKETS;
}

/* ============================================================
 * MODULE STATE
 * ============================================================ */

static struct {
  heap h;
  boolean initialized;

  /* Hash table of tools */
  ak_tool_def_t *buckets[TOOL_HASH_BUCKETS];

  /* Composite tools */
  ak_composite_tool_t *composites[AK_TOOL_REGISTRY_MAX_TOOLS];
  u32 composite_count;

  /* Statistics */
  ak_tool_registry_stats_t stats;

  /* Tool pool */
  ak_tool_def_t tool_pool[AK_TOOL_REGISTRY_MAX_TOOLS];
  u32 tool_pool_used;

  /* Current invocation context for composite tool handlers.
   * This allows composite_handler to identify which composite
   * tool is being invoked without changing the handler signature.
   * Thread safety: single-threaded kernel assumption. */
  void *current_handler_ctx;
} registry_state;

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

int ak_tool_registry_init(heap h) {
  if (registry_state.initialized)
    return 0;

  registry_state.h = h;

  /* Clear hash buckets */
  local_memzero(registry_state.buckets, sizeof(registry_state.buckets));

  /* Clear composites */
  local_memzero(registry_state.composites, sizeof(registry_state.composites));
  registry_state.composite_count = 0;

  /* Clear statistics */
  local_memzero(&registry_state.stats, sizeof(ak_tool_registry_stats_t));

  /* Clear tool pool */
  local_memzero(registry_state.tool_pool, sizeof(registry_state.tool_pool));
  registry_state.tool_pool_used = 0;

  registry_state.initialized = true;

  ak_debug("ak_tool_registry: initialized");

  return 0;
}

void ak_tool_registry_shutdown(void) {
  if (!registry_state.initialized)
    return;

  /* Clear all tools */
  for (u32 i = 0; i < TOOL_HASH_BUCKETS; i++) {
    ak_tool_def_t *tool = registry_state.buckets[i];
    while (tool) {
      ak_tool_def_t *next = tool->next;
      /* Free mock response if present */
      if (tool->mock_response && tool->mock_response != INVALID_ADDRESS) {
        deallocate_buffer(tool->mock_response);
      }
      tool->active = false;
      tool = next;
    }
    registry_state.buckets[i] = NULL;
  }

  /* Clear composites */
  for (u32 i = 0; i < registry_state.composite_count; i++) {
    if (registry_state.composites[i]) {
      deallocate(registry_state.h, registry_state.composites[i],
                 sizeof(ak_composite_tool_t));
      registry_state.composites[i] = NULL;
    }
  }
  registry_state.composite_count = 0;

  registry_state.tool_pool_used = 0;
  registry_state.initialized = false;

  ak_debug("ak_tool_registry: shutdown");
}

/* ============================================================
 * VERSION PARSING AND COMPARISON
 * ============================================================ */

int ak_version_parse(const char *version, u32 *major, u32 *minor, u32 *patch) {
  if (!version)
    return -EINVAL;

  /* Initialize outputs */
  if (major)
    *major = 0;
  if (minor)
    *minor = 0;
  if (patch)
    *patch = 0;

  /* Skip leading 'v' if present */
  if (*version == 'v' || *version == 'V')
    version++;

  /* Parse major with overflow protection (P2-5) */
  u32 val = 0;
  while (local_isdigit(*version)) {
    u32 digit = *version - '0';
    /* Check for overflow before multiplication */
    if (val > (UINT32_MAX - digit) / 10) {
      val = UINT32_MAX; /* Saturate on overflow */
      while (local_isdigit(*version))
        version++; /* Skip remaining */
      break;
    }
    val = val * 10 + digit;
    version++;
  }
  if (major)
    *major = val;

  /* Check for minor */
  if (*version != '.')
    return 0; /* Only major version */
  version++;

  /* Parse minor with overflow protection (P2-5) */
  val = 0;
  while (local_isdigit(*version)) {
    u32 digit = *version - '0';
    if (val > (UINT32_MAX - digit) / 10) {
      val = UINT32_MAX;
      while (local_isdigit(*version))
        version++;
      break;
    }
    val = val * 10 + digit;
    version++;
  }
  if (minor)
    *minor = val;

  /* Check for patch */
  if (*version != '.')
    return 0; /* Major.minor only */
  version++;

  /* Parse patch with overflow protection (P2-5) */
  val = 0;
  while (local_isdigit(*version)) {
    u32 digit = *version - '0';
    if (val > (UINT32_MAX - digit) / 10) {
      val = UINT32_MAX;
      while (local_isdigit(*version))
        version++;
      break;
    }
    val = val * 10 + digit;
    version++;
  }
  if (patch)
    *patch = val;

  return 0;
}

int ak_version_compare(const char *v1, const char *v2) {
  u32 major1, minor1, patch1;
  u32 major2, minor2, patch2;

  ak_version_parse(v1, &major1, &minor1, &patch1);
  ak_version_parse(v2, &major2, &minor2, &patch2);

  if (major1 != major2)
    return (int)major1 - (int)major2;
  if (minor1 != minor2)
    return (int)minor1 - (int)minor2;
  return (int)patch1 - (int)patch2;
}

boolean ak_version_matches(const char *version, const char *pattern,
                           ak_version_match_t mode) {
  if (!version)
    return false;

  /* NULL or "*" matches anything */
  if (!pattern || local_strcmp(pattern, "*") == 0)
    return true;

  switch (mode) {
  case AK_VERSION_EXACT:
    return local_strcmp(version, pattern) == 0;

  case AK_VERSION_MAJOR: {
    /* Pattern like "1.*" matches major version 1 */
    u32 pat_major, ver_major;
    ak_version_parse(pattern, &pat_major, NULL, NULL);
    ak_version_parse(version, &ver_major, NULL, NULL);
    return pat_major == ver_major;
  }

  case AK_VERSION_ANY:
    return true;

  case AK_VERSION_SEMVER: {
    /* Pattern like "^1.2.0" matches >=1.2.0 <2.0.0 */
    const char *pat = pattern;
    if (*pat == '^')
      pat++;

    u32 pat_major, pat_minor, pat_patch;
    u32 ver_major, ver_minor, ver_patch;

    ak_version_parse(pat, &pat_major, &pat_minor, &pat_patch);
    ak_version_parse(version, &ver_major, &ver_minor, &ver_patch);

    /* Must have same major version */
    if (ver_major != pat_major)
      return false;

    /* Version must be >= pattern */
    if (ver_minor < pat_minor)
      return false;
    if (ver_minor == pat_minor && ver_patch < pat_patch)
      return false;

    return true;
  }

  case AK_VERSION_RANGE: {
    /* Pattern like ">=1.0.0" */
    const char *pat = pattern;
    boolean gte = false, lte = false, gt = false, lt = false;

    if (pat[0] == '>' && pat[1] == '=') {
      gte = true;
      pat += 2;
    } else if (pat[0] == '<' && pat[1] == '=') {
      lte = true;
      pat += 2;
    } else if (pat[0] == '>') {
      gt = true;
      pat++;
    } else if (pat[0] == '<') {
      lt = true;
      pat++;
    } else {
      /* Exact match */
      return local_strcmp(version, pattern) == 0;
    }

    int cmp = ak_version_compare(version, pat);

    if (gte)
      return cmp >= 0;
    if (lte)
      return cmp <= 0;
    if (gt)
      return cmp > 0;
    if (lt)
      return cmp < 0;
    return false;
  }
  }

  return false;
}

/*
 * Detect version match mode from pattern.
 */
static ak_version_match_t detect_version_mode(const char *pattern) {
  if (!pattern || local_strcmp(pattern, "*") == 0)
    return AK_VERSION_ANY;

  if (pattern[0] == '^')
    return AK_VERSION_SEMVER;

  if (pattern[0] == '>' || pattern[0] == '<')
    return AK_VERSION_RANGE;

  /* Check for wildcard in pattern (e.g., "1.*") */
  u64 len = local_strlen(pattern);
  if (len >= 2 && pattern[len - 1] == '*' && pattern[len - 2] == '.')
    return AK_VERSION_MAJOR;

  return AK_VERSION_EXACT;
}

/* ============================================================
 * TOOL ALLOCATION
 * ============================================================ */

static ak_tool_def_t *allocate_tool(void) {
  if (registry_state.tool_pool_used >= AK_TOOL_REGISTRY_MAX_TOOLS)
    return NULL;

  /* Try to find an inactive slot first */
  for (u32 i = 0; i < registry_state.tool_pool_used; i++) {
    if (!registry_state.tool_pool[i].active) {
      return &registry_state.tool_pool[i];
    }
  }

  /* Use new slot */
  ak_tool_def_t *tool =
      &registry_state.tool_pool[registry_state.tool_pool_used];
  registry_state.tool_pool_used++;
  return tool;
}

/* ============================================================
 * TOOL REGISTRATION
 * ============================================================ */

int ak_tool_register(const ak_tool_def_t *def) {
  if (!registry_state.initialized)
    return -EINVAL;

  if (!def || !def->name[0] || !def->handler)
    return AK_E_TOOL_INVALID_DEF;

  /* Check for existing tool with same name+version */
  ak_tool_def_t *existing = ak_tool_lookup(def->name, def->version);
  if (existing && existing->active)
    return AK_E_TOOL_ALREADY_EXISTS;

  /* Allocate tool slot */
  ak_tool_def_t *tool = allocate_tool();
  if (!tool)
    return AK_E_TOOL_REGISTRY_FULL;

  /* Copy definition */
  local_memcpy(tool, def, sizeof(ak_tool_def_t));

  /* Set defaults for unspecified fields */
  if (tool->version[0] == '\0')
    local_strncpy(tool->version, "1.0.0", sizeof(tool->version));

  if (tool->timeout_ms == 0)
    tool->timeout_ms = AK_TOOL_DEFAULT_TIMEOUT_MS;

  /* Initialize metrics */
  tool->invocation_count = 0;
  tool->success_count = 0;
  tool->failure_count = 0;
  tool->total_time_ns = 0;
  tool->registered_ms = ak_now() / 1000000;

  /* Mark as active */
  tool->active = true;

  /* Handle mock response if provided */
  if (def->mock_enabled && def->mock_response) {
    tool->mock_response =
        allocate_buffer(registry_state.h, buffer_length(def->mock_response));
    if (tool->mock_response != INVALID_ADDRESS) {
      buffer_write(tool->mock_response, buffer_ref(def->mock_response, 0),
                   buffer_length(def->mock_response));
    }
  } else {
    tool->mock_response = NULL;
  }

  /* Insert into hash table */
  u32 bucket = tool_hash(tool->name);
  tool->next = registry_state.buckets[bucket];
  registry_state.buckets[bucket] = tool;

  /* Update statistics */
  registry_state.stats.tools_registered++;
  registry_state.stats.tools_active++;

  ak_debug("ak_tool_registry: registered '%s' v%s", tool->name, tool->version);

  return 0;
}

int ak_tool_unregister(const char *name) {
  if (!registry_state.initialized || !name)
    return -EINVAL;

  u32 bucket = tool_hash(name);
  ak_tool_def_t *prev = NULL;
  ak_tool_def_t *tool = registry_state.buckets[bucket];
  boolean found = false;

  while (tool) {
    if (local_strcmp(tool->name, name) == 0 && tool->active) {
      /* Mark inactive */
      tool->active = false;

      /* Free mock response */
      if (tool->mock_response && tool->mock_response != INVALID_ADDRESS) {
        deallocate_buffer(tool->mock_response);
        tool->mock_response = NULL;
      }

      found = true;
      registry_state.stats.tools_active--;
      registry_state.stats.tools_unregistered++;
    }

    prev = tool;
    tool = tool->next;
  }

  if (!found)
    return -ENOENT;

  ak_debug("ak_tool_registry: unregistered '%s'", name);

  return 0;
}

int ak_tool_unregister_version(const char *name, const char *version) {
  if (!registry_state.initialized || !name)
    return -EINVAL;

  ak_tool_def_t *tool = ak_tool_lookup_ex(name, version, AK_VERSION_EXACT);
  if (!tool || !tool->active)
    return -ENOENT;

  tool->active = false;

  /* Free mock response */
  if (tool->mock_response && tool->mock_response != INVALID_ADDRESS) {
    deallocate_buffer(tool->mock_response);
    tool->mock_response = NULL;
  }

  registry_state.stats.tools_active--;
  registry_state.stats.tools_unregistered++;

  ak_debug("ak_tool_registry: unregistered '%s' v%s", name, version);

  return 0;
}

/* ============================================================
 * TOOL LOOKUP
 * ============================================================ */

ak_tool_def_t *ak_tool_lookup(const char *name, const char *version) {
  ak_version_match_t mode = detect_version_mode(version);
  return ak_tool_lookup_ex(name, version, mode);
}

ak_tool_def_t *ak_tool_lookup_ex(const char *name, const char *version,
                                 ak_version_match_t mode) {
  if (!registry_state.initialized || !name) {
    registry_state.stats.lookups_total++;
    registry_state.stats.lookups_miss++;
    return NULL;
  }

  registry_state.stats.lookups_total++;

  u32 bucket = tool_hash(name);
  ak_tool_def_t *tool = registry_state.buckets[bucket];
  ak_tool_def_t *best_match = NULL;

  while (tool) {
    if (tool->active && local_strcmp(tool->name, name) == 0) {
      if (ak_version_matches(tool->version, version, mode)) {
        /* For AK_VERSION_ANY, return the latest version */
        if (mode == AK_VERSION_ANY || mode == AK_VERSION_MAJOR) {
          if (!best_match ||
              ak_version_compare(tool->version, best_match->version) > 0) {
            best_match = tool;
          }
        } else {
          return tool;
        }
      }
    }
    tool = tool->next;
  }

  if (!best_match)
    registry_state.stats.lookups_miss++;

  return best_match;
}

ak_tool_list_t *ak_tool_list(heap h) {
  if (!registry_state.initialized)
    return NULL;

  heap alloc_heap = h ? h : registry_state.h;

  ak_tool_list_t *list = allocate(alloc_heap, sizeof(ak_tool_list_t));
  if (!list)
    return NULL;

  /* Count active tools */
  u32 count = 0;
  for (u32 i = 0; i < TOOL_HASH_BUCKETS; i++) {
    ak_tool_def_t *tool = registry_state.buckets[i];
    while (tool) {
      if (tool->active)
        count++;
      tool = tool->next;
    }
  }

  list->count = 0;
  list->capacity = count;

  if (count == 0) {
    list->tools = NULL;
    return list;
  }

  list->tools = allocate(alloc_heap, count * sizeof(ak_tool_def_t *));
  if (!list->tools) {
    deallocate(alloc_heap, list, sizeof(ak_tool_list_t));
    return NULL;
  }

  /* Collect tools */
  for (u32 i = 0; i < TOOL_HASH_BUCKETS; i++) {
    ak_tool_def_t *tool = registry_state.buckets[i];
    while (tool) {
      if (tool->active && list->count < list->capacity) {
        list->tools[list->count++] = tool;
      }
      tool = tool->next;
    }
  }

  return list;
}

void ak_tool_list_free(heap h, ak_tool_list_t *list) {
  if (!list)
    return;

  heap alloc_heap = h ? h : registry_state.h;

  if (list->tools)
    deallocate(alloc_heap, list->tools,
               list->capacity * sizeof(ak_tool_def_t *));

  deallocate(alloc_heap, list, sizeof(ak_tool_list_t));
}

boolean ak_tool_exists(const char *name, const char *version) {
  ak_tool_def_t *tool = ak_tool_lookup(name, version);
  return tool != NULL && tool->active;
}

/* ============================================================
 * TOOL INVOCATION
 * ============================================================ */

int ak_tool_invoke(ak_ctx_t *ctx, const char *name, const char *version,
                   buffer args, buffer *result) {
  return ak_tool_invoke_timeout(ctx, name, version, args, result, 0);
}

int ak_tool_invoke_timeout(ak_ctx_t *ctx, const char *name, const char *version,
                           buffer args, buffer *result, u64 timeout_ms) {
  if (!registry_state.initialized)
    return -EINVAL;

  if (!ctx || !name)
    return -EINVAL;

  registry_state.stats.invocations_total++;

  /* Look up tool */
  ak_tool_def_t *tool = ak_tool_lookup(name, version);
  if (!tool) {
    registry_state.stats.invocations_failed++;
    return AK_E_TOOL_NOT_FOUND;
  }

  /* Build effect request for authorization */
  ak_effect_req_t req;
  local_memzero(&req, sizeof(ak_effect_req_t));
  req.op = AK_E_TOOL_CALL;
  req.trace_id = ak_trace_id_generate(ctx);

  /* Build target string: tool:name:version */
  int pos = 0;
  req.target[pos++] = 't';
  req.target[pos++] = 'o';
  req.target[pos++] = 'o';
  req.target[pos++] = 'l';
  req.target[pos++] = ':';
  u64 name_len = local_strlen(name);
  if (pos + name_len < AK_MAX_TARGET - 2) {
    local_memcpy(req.target + pos, name, name_len);
    pos += name_len;
  }
  req.target[pos++] = ':';
  u64 ver_len = local_strlen(tool->version);
  if (pos + ver_len < AK_MAX_TARGET - 1) {
    local_memcpy(req.target + pos, tool->version, ver_len);
    pos += ver_len;
  }
  req.target[pos] = '\0';

  /* Authorize via effects API */
  ak_decision_t decision;
  long retval = 0;

  int err = ak_authorize_and_execute(ctx, &req, &decision, &retval);

  if (err != 0 || !decision.allow) {
    registry_state.stats.invocations_denied++;

    /* Update last deny */
    ctx->last_deny.op = AK_E_TOOL_CALL;
    local_strncpy(ctx->last_deny.target, req.target, AK_MAX_TARGET);
    local_strncpy(ctx->last_deny.missing_cap, decision.missing_cap,
                  AK_MAX_CAPSTR);
    local_strncpy(ctx->last_deny.suggested_snippet, decision.suggested_snippet,
                  AK_MAX_SUGGEST);
    ctx->last_deny.trace_id = req.trace_id;
    ctx->last_deny.errno_equiv = decision.errno_equiv;
    ctx->last_deny.timestamp_ns = ak_now();
    ctx->last_deny.reason = decision.reason_code;

    ak_debug("ak_tool_registry: invoke '%s' denied", name);

    return err != 0 ? err : -EPERM;
  }

  /* Check mock mode */
  if (tool->mock_enabled && tool->mock_response) {
    registry_state.stats.invocations_mock++;
    tool->invocation_count++;

    if (result) {
      *result =
          allocate_buffer(registry_state.h, buffer_length(tool->mock_response));
      if (*result != INVALID_ADDRESS) {
        buffer_write(*result, buffer_ref(tool->mock_response, 0),
                     buffer_length(tool->mock_response));
      }
    }

    ak_debug("ak_tool_registry: mock invoke '%s'", name);

    return 0;
  }

  /* Validate arguments against schema */
  if (tool->input_schema[0] != '\0' && args) {
    err = ak_tool_validate_args(tool, args);
    if (err != 0) {
      registry_state.stats.schema_failures++;
      tool->failure_count++;
      return AK_E_TOOL_ARGS_INVALID;
    }
    registry_state.stats.schema_validations++;
  }

  /* Determine timeout */
  u64 actual_timeout = timeout_ms > 0 ? timeout_ms : tool->timeout_ms;

  /* Record start time */
  u64 start_ns = ak_now();

  /* Set handler context for composite tool lookup.
   * Saved and restored to support nested tool invocations. */
  void *saved_ctx = registry_state.current_handler_ctx;
  registry_state.current_handler_ctx = tool->handler_ctx;

  /* Execute handler */
  s64 handler_result = tool->handler(ctx, args, result);

  /* Restore previous handler context */
  registry_state.current_handler_ctx = saved_ctx;

  /* Record elapsed time */
  u64 elapsed_ns = ak_now() - start_ns;
  tool->total_time_ns += elapsed_ns;
  tool->invocation_count++;

  /* Check for timeout (approximate - handler has already completed) */
  if (actual_timeout > 0 && elapsed_ns > actual_timeout * 1000000) {
    registry_state.stats.invocations_timeout++;
    tool->failure_count++;
    return AK_E_TOOL_TIMEOUT;
  }

  if (handler_result != 0) {
    tool->failure_count++;
    registry_state.stats.invocations_failed++;
    return handler_result;
  }

  /* Validate result against schema */
  if (tool->output_schema[0] != '\0' && result && *result) {
    err = ak_tool_validate_result(tool, *result);
    if (err != 0) {
      registry_state.stats.schema_failures++;
      tool->failure_count++;
      return AK_E_TOOL_RESULT_INVALID;
    }
    registry_state.stats.schema_validations++;
  }

  tool->success_count++;
  registry_state.stats.invocations_success++;

  return 0;
}

/* ============================================================
 * MOCK MODE
 * ============================================================ */

int ak_tool_set_mock(const char *name, buffer response) {
  if (!registry_state.initialized || !name)
    return -EINVAL;

  /* Set mock on all versions */
  u32 bucket = tool_hash(name);
  ak_tool_def_t *tool = registry_state.buckets[bucket];
  boolean found = false;

  while (tool) {
    if (tool->active && local_strcmp(tool->name, name) == 0) {
      /* Free existing mock response */
      if (tool->mock_response && tool->mock_response != INVALID_ADDRESS) {
        deallocate_buffer(tool->mock_response);
      }

      /* Copy new mock response */
      if (response && buffer_length(response) > 0) {
        tool->mock_response =
            allocate_buffer(registry_state.h, buffer_length(response));
        if (tool->mock_response != INVALID_ADDRESS) {
          buffer_write(tool->mock_response, buffer_ref(response, 0),
                       buffer_length(response));
        }
        tool->mock_enabled = true;
      } else {
        tool->mock_response = NULL;
        tool->mock_enabled = false;
      }

      found = true;
    }
    tool = tool->next;
  }

  if (!found)
    return -ENOENT;

  ak_debug("ak_tool_registry: set mock for '%s'", name);

  return 0;
}

int ak_tool_set_mock_version(const char *name, const char *version,
                             buffer response) {
  if (!registry_state.initialized || !name)
    return -EINVAL;

  ak_tool_def_t *tool = ak_tool_lookup_ex(name, version, AK_VERSION_EXACT);
  if (!tool || !tool->active)
    return -ENOENT;

  /* Free existing mock response */
  if (tool->mock_response && tool->mock_response != INVALID_ADDRESS) {
    deallocate_buffer(tool->mock_response);
  }

  /* Copy new mock response */
  if (response && buffer_length(response) > 0) {
    tool->mock_response =
        allocate_buffer(registry_state.h, buffer_length(response));
    if (tool->mock_response != INVALID_ADDRESS) {
      buffer_write(tool->mock_response, buffer_ref(response, 0),
                   buffer_length(response));
    }
    tool->mock_enabled = true;
  } else {
    tool->mock_response = NULL;
    tool->mock_enabled = false;
  }

  ak_debug("ak_tool_registry: set mock for '%s' v%s", name, version);

  return 0;
}

int ak_tool_clear_mock(const char *name) {
  if (!registry_state.initialized || !name)
    return -EINVAL;

  u32 bucket = tool_hash(name);
  ak_tool_def_t *tool = registry_state.buckets[bucket];
  boolean found = false;

  while (tool) {
    if (tool->active && local_strcmp(tool->name, name) == 0) {
      tool->mock_enabled = false;
      if (tool->mock_response && tool->mock_response != INVALID_ADDRESS) {
        deallocate_buffer(tool->mock_response);
        tool->mock_response = NULL;
      }
      found = true;
    }
    tool = tool->next;
  }

  if (!found)
    return -ENOENT;

  ak_debug("ak_tool_registry: cleared mock for '%s'", name);

  return 0;
}

boolean ak_tool_is_mock(const char *name, const char *version) {
  ak_tool_def_t *tool = ak_tool_lookup(name, version);
  return tool && tool->mock_enabled;
}

/* ============================================================
 * SCHEMA VALIDATION
 * ============================================================
 * Simple JSON schema validation. In production, this would use
 * a proper JSON schema library.
 */

/*
 * Basic JSON validation (checks for well-formed JSON).
 * A full implementation would validate against the schema.
 */
static boolean is_valid_json(buffer json) {
  if (!json || buffer_length(json) == 0)
    return false;

  /* Check for basic JSON structure */
  const char *data = (const char *)buffer_ref(json, 0);
  u64 len = buffer_length(json);

  if (len == 0)
    return false;

  /* Must start with { or [ or " or digit */
  char first = data[0];
  return (first == '{' || first == '[' || first == '"' ||
          local_isdigit(first) || first == '-' ||
          local_strncmp(data, "true", 4) == 0 ||
          local_strncmp(data, "false", 5) == 0 ||
          local_strncmp(data, "null", 4) == 0);
}

int ak_tool_validate_args(const ak_tool_def_t *tool, buffer args) {
  if (!tool)
    return -EINVAL;

  if (tool->input_schema[0] == '\0')
    return 0; /* No schema to validate against */

  if (!args)
    return AK_E_TOOL_ARGS_INVALID;

  /* Basic JSON validation */
  if (!is_valid_json(args))
    return AK_E_TOOL_ARGS_INVALID;

  /* Full schema validation would go here */
  /* For P0, we just check basic JSON validity */

  return 0;
}

int ak_tool_validate_result(const ak_tool_def_t *tool, buffer result) {
  if (!tool)
    return -EINVAL;

  if (tool->output_schema[0] == '\0')
    return 0; /* No schema to validate against */

  if (!result)
    return AK_E_TOOL_RESULT_INVALID;

  /* Basic JSON validation */
  if (!is_valid_json(result))
    return AK_E_TOOL_RESULT_INVALID;

  /* Full schema validation would go here */

  return 0;
}

const char *ak_tool_get_input_schema(const char *name, const char *version) {
  ak_tool_def_t *tool = ak_tool_lookup(name, version);
  if (!tool || tool->input_schema[0] == '\0')
    return NULL;
  return tool->input_schema;
}

const char *ak_tool_get_output_schema(const char *name, const char *version) {
  ak_tool_def_t *tool = ak_tool_lookup(name, version);
  if (!tool || tool->output_schema[0] == '\0')
    return NULL;
  return tool->output_schema;
}

int ak_tool_get_schema(const char *name, const char **input_out,
                       const char **output_out) {
  ak_tool_def_t *tool = ak_tool_lookup(name, NULL);
  if (!tool)
    return -ENOENT;

  if (input_out)
    *input_out = tool->input_schema[0] ? tool->input_schema : NULL;
  if (output_out)
    *output_out = tool->output_schema[0] ? tool->output_schema : NULL;

  return 0;
}

/* ============================================================
 * TOOL COMPOSITION
 * ============================================================ */

/*
 * Composite tool handler - chains multiple tools together.
 *
 * The composite tool is identified via registry_state.current_handler_ctx,
 * which is set by ak_tool_invoke_timeout() before calling the handler.
 * This allows proper lookup without changing the handler function signature.
 */
static s64 composite_handler(ak_ctx_t *ctx, buffer args, buffer *result) {
  /* Retrieve the composite tool from the current invocation context.
   * This is set by ak_tool_invoke_timeout() before handler execution. */
  ak_composite_tool_t *comp =
      (ak_composite_tool_t *)registry_state.current_handler_ctx;

  if (!comp || comp->chain_length == 0)
    return AK_E_TOOL_CHAIN_ERROR;

  buffer current_input = args;
  buffer current_output = NULL;

  for (u32 i = 0; i < comp->chain_length; i++) {
    const char *tool_name = comp->chain[i].name;
    const char *tool_version =
        comp->chain[i].version[0] ? comp->chain[i].version : NULL;

    /* Invoke tool in chain */
    int err = ak_tool_invoke(ctx, tool_name, tool_version, current_input,
                             &current_output);

    /* Free intermediate input (except for original args) */
    if (i > 0 && current_input && current_input != INVALID_ADDRESS) {
      deallocate_buffer(current_input);
    }

    if (err != 0) {
      if (comp->stop_on_error) {
        if (current_output && current_output != INVALID_ADDRESS)
          deallocate_buffer(current_output);
        return AK_E_TOOL_CHAIN_ERROR;
      }
      /* Continue with NULL output if not stopping on error */
      current_input = NULL;
    } else {
      current_input = current_output;
      current_output = NULL;
    }
  }

  *result = current_input;
  return 0;
}

int ak_tool_compose(const char *name, const char *version,
                    const char **tool_names, const char **tool_versions,
                    u32 count) {
  if (!registry_state.initialized)
    return -EINVAL;

  if (!name || !tool_names || count == 0)
    return -EINVAL;

  if (count > AK_MAX_COMPOSITE_CHAIN)
    return AK_E_TOOL_CHAIN_TOO_LONG;

  /* Allocate composite tool */
  ak_composite_tool_t *comp =
      allocate(registry_state.h, sizeof(ak_composite_tool_t));
  if (!comp)
    return -ENOMEM;

  local_memzero(comp, sizeof(ak_composite_tool_t));

  local_strncpy(comp->name, name, sizeof(comp->name));
  local_strncpy(comp->version, version ? version : "1.0.0",
                sizeof(comp->version));
  comp->chain_length = count;
  comp->stop_on_error = true;
  comp->total_timeout_ms = AK_TOOL_DEFAULT_TIMEOUT_MS * count;

  /* Copy chain */
  for (u32 i = 0; i < count; i++) {
    if (!tool_names[i]) {
      deallocate(registry_state.h, comp, sizeof(ak_composite_tool_t));
      return -EINVAL;
    }
    local_strncpy(comp->chain[i].name, tool_names[i],
                  sizeof(comp->chain[i].name));
    if (tool_versions && tool_versions[i]) {
      local_strncpy(comp->chain[i].version, tool_versions[i],
                    sizeof(comp->chain[i].version));
    }
  }

  /* Store composite */
  if (registry_state.composite_count >= AK_TOOL_REGISTRY_MAX_TOOLS) {
    deallocate(registry_state.h, comp, sizeof(ak_composite_tool_t));
    return AK_E_TOOL_REGISTRY_FULL;
  }
  registry_state.composites[registry_state.composite_count++] = comp;

  /* Register as a regular tool */
  ak_tool_def_t def;
  local_memzero(&def, sizeof(ak_tool_def_t));

  local_strncpy(def.name, name, sizeof(def.name));
  local_strncpy(def.version, comp->version, sizeof(def.version));
  local_strncpy(def.description, "Composite tool", sizeof(def.description));
  def.handler = composite_handler;
  def.handler_ctx = comp;
  def.flags = AK_TOOL_FLAG_COMPOSABLE;
  def.timeout_ms = comp->total_timeout_ms;

  int err = ak_tool_register(&def);
  if (err != 0) {
    registry_state.composite_count--;
    deallocate(registry_state.h, comp, sizeof(ak_composite_tool_t));
    return err;
  }

  ak_debug("ak_tool_registry: composed '%s' from %u tools", name, count);

  return 0;
}

int ak_tool_compose_ex(const ak_composite_tool_t *composite) {
  if (!composite || !composite->name[0])
    return -EINVAL;

  const char *tool_names[AK_MAX_COMPOSITE_CHAIN];
  const char *tool_versions[AK_MAX_COMPOSITE_CHAIN];

  for (u32 i = 0; i < composite->chain_length; i++) {
    tool_names[i] = composite->chain[i].name;
    tool_versions[i] =
        composite->chain[i].version[0] ? composite->chain[i].version : NULL;
  }

  return ak_tool_compose(composite->name, composite->version, tool_names,
                         tool_versions, composite->chain_length);
}

ak_composite_tool_t *ak_tool_get_composite(const char *name) {
  if (!registry_state.initialized || !name)
    return NULL;

  for (u32 i = 0; i < registry_state.composite_count; i++) {
    if (registry_state.composites[i] &&
        local_strcmp(registry_state.composites[i]->name, name) == 0) {
      return registry_state.composites[i];
    }
  }

  return NULL;
}

boolean ak_tool_is_composite(const char *name) {
  return ak_tool_get_composite(name) != NULL;
}

/* ============================================================
 * STATISTICS
 * ============================================================ */

void ak_tool_registry_get_stats(ak_tool_registry_stats_t *stats) {
  if (!stats)
    return;

  local_memcpy(stats, &registry_state.stats, sizeof(ak_tool_registry_stats_t));
}

void ak_tool_registry_reset_stats(void) {
  /* Preserve active tool count */
  u64 active = registry_state.stats.tools_active;
  u64 registered = registry_state.stats.tools_registered;
  u64 unregistered = registry_state.stats.tools_unregistered;

  local_memzero(&registry_state.stats, sizeof(ak_tool_registry_stats_t));

  registry_state.stats.tools_active = active;
  registry_state.stats.tools_registered = registered;
  registry_state.stats.tools_unregistered = unregistered;
}
