/*
 * Authority Kernel - Record Mode Implementation
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Implements record mode functionality for accumulating denied effects
 * and generating batch policy suggestions.
 */

#include "ak_record.h"
#include "ak_compat.h"

/* ============================================================
 * INTERNAL HELPERS
 * ============================================================ */

/*
 * Simple hash function for effect key (op + target).
 * Uses FNV-1a variant for reasonable distribution.
 */
static u32 ak_record_hash(ak_effect_op_t op, const char *target) {
  u32 hash = 2166136261u; /* FNV offset basis */

  /* Hash the operation */
  hash ^= (u32)op;
  hash *= 16777619u; /* FNV prime */

  /* Hash the target string */
  if (target) {
    while (*target) {
      hash ^= (u8)*target++;
      hash *= 16777619u;
    }
  }

  return hash & (AK_RECORD_HASH_SIZE - 1);
}

/*
 * Find an existing recorded effect or return NULL.
 */
static ak_recorded_effect_t *ak_record_find(ak_record_state_t *state,
                                            ak_effect_op_t op,
                                            const char *target) {
  u32 bucket = ak_record_hash(op, target);
  ak_recorded_effect_t *entry = state->buckets[bucket];

  while (entry) {
    if (entry->op == op && ak_strcmp(entry->target, target) == 0) {
      return entry;
    }
    entry = entry->next;
  }

  return NULL;
}

/*
 * Get effect category name for JSON output.
 */
static const char *ak_record_category_name(ak_effect_op_t op) {
  u32 category = (op >> 8) & 0xFF;
  switch (category) {
  case 0x01:
    return "fs";
  case 0x02:
    return "net";
  case 0x03:
    return "process";
  case 0x04:
    return "agentic";
  default:
    return "unknown";
  }
}

/*
 * Get effect type name for JSON output.
 */
static const char *ak_record_effect_type_name(ak_effect_op_t op) {
  switch (op) {
  case AK_E_FS_OPEN:
    return "open";
  case AK_E_FS_UNLINK:
    return "unlink";
  case AK_E_FS_RENAME:
    return "rename";
  case AK_E_FS_MKDIR:
    return "mkdir";
  case AK_E_FS_RMDIR:
    return "rmdir";
  case AK_E_FS_STAT:
    return "stat";
  case AK_E_NET_CONNECT:
    return "connect";
  case AK_E_NET_DNS_RESOLVE:
    return "dns_resolve";
  case AK_E_NET_BIND:
    return "bind";
  case AK_E_NET_LISTEN:
    return "listen";
  case AK_E_NET_ACCEPT:
    return "accept";
  case AK_E_PROC_SPAWN:
    return "spawn";
  case AK_E_PROC_SIGNAL:
    return "signal";
  case AK_E_PROC_WAIT:
    return "wait";
  case AK_E_TOOL_CALL:
    return "tool_call";
  case AK_E_WASM_INVOKE:
    return "wasm_invoke";
  case AK_E_INFER:
    return "inference";
  default:
    return "unknown";
  }
}

/*
 * Write a JSON string with proper escaping.
 */
static int json_write_escaped_string(char *out, u32 out_len, const char *str) {
  if (!out || out_len < 3)
    return 0;

  int pos = 0;
  out[pos++] = '"';

  if (str) {
    while (*str && pos < (int)out_len - 2) {
      char c = *str++;
      switch (c) {
      case '"':
        if (pos + 2 < (int)out_len) {
          out[pos++] = '\\';
          out[pos++] = '"';
        }
        break;
      case '\\':
        if (pos + 2 < (int)out_len) {
          out[pos++] = '\\';
          out[pos++] = '\\';
        }
        break;
      case '\n':
        if (pos + 2 < (int)out_len) {
          out[pos++] = '\\';
          out[pos++] = 'n';
        }
        break;
      case '\r':
        if (pos + 2 < (int)out_len) {
          out[pos++] = '\\';
          out[pos++] = 'r';
        }
        break;
      case '\t':
        if (pos + 2 < (int)out_len) {
          out[pos++] = '\\';
          out[pos++] = 't';
        }
        break;
      default:
        if (c >= 32 && c < 127) {
          out[pos++] = c;
        }
        break;
      }
    }
  }

  out[pos++] = '"';
  return pos;
}

/*
 * Write an unsigned integer to buffer.
 */
static int json_write_uint(char *out, u32 out_len, u64 val) {
  if (!out || out_len < 2)
    return 0;

  char tmp[24];
  int tmp_len = 0;

  if (val == 0) {
    out[0] = '0';
    return 1;
  }

  while (val > 0 && tmp_len < 20) {
    tmp[tmp_len++] = '0' + (val % 10);
    val /= 10;
  }

  int pos = 0;
  for (int i = tmp_len - 1; i >= 0 && pos < (int)out_len; i--) {
    out[pos++] = tmp[i];
  }

  return pos;
}

/*
 * Generate suggested rule string for an effect.
 */
static void ak_record_generate_rule(ak_recorded_effect_t *effect,
                                    const ak_effect_req_t *req) {
  char *out = effect->suggested_rule;
  u32 max_len = sizeof(effect->suggested_rule);
  int pos = 0;

  ak_memzero(out, max_len);

  u32 category = (req->op >> 8) & 0xFF;

  switch (category) {
  case 0x01: /* Filesystem */
  {
    boolean is_write =
        (req->op == AK_E_FS_UNLINK || req->op == AK_E_FS_RENAME ||
         req->op == AK_E_FS_MKDIR || req->op == AK_E_FS_RMDIR);

    pos += runtime_strncpy(out + pos, "{\"path\":", max_len - pos) ? 8 : 0;
    pos += json_write_escaped_string(out + pos, max_len - pos, req->target);

    if (is_write) {
      pos += runtime_strncpy(out + pos, ",\"write\":true}", max_len - pos) ? 14
                                                                           : 0;
    } else {
      pos +=
          runtime_strncpy(out + pos, ",\"read\":true}", max_len - pos) ? 13 : 0;
    }
  } break;

  case 0x02: /* Network */
    if (req->op == AK_E_NET_DNS_RESOLVE) {
      /* DNS resolution */
      const char *host = req->target;
      if (runtime_strncmp(host, "dns:", 4) == 0)
        host += 4;

      pos +=
          runtime_strncpy(out + pos, "{\"pattern\":", max_len - pos) ? 11 : 0;
      pos += json_write_escaped_string(out + pos, max_len - pos, host);
      pos += runtime_strncpy(out + pos, ",\"resolve\":true}", max_len - pos)
                 ? 16
                 : 0;
    } else {
      /* Network connection */
      pos +=
          runtime_strncpy(out + pos, "{\"pattern\":", max_len - pos) ? 11 : 0;
      pos += json_write_escaped_string(out + pos, max_len - pos, req->target);

      switch (req->op) {
      case AK_E_NET_CONNECT:
        pos += runtime_strncpy(out + pos, ",\"connect\":true}", max_len - pos)
                   ? 16
                   : 0;
        break;
      case AK_E_NET_BIND:
        pos += runtime_strncpy(out + pos, ",\"bind\":true}", max_len - pos) ? 13
                                                                            : 0;
        break;
      case AK_E_NET_LISTEN:
        pos += runtime_strncpy(out + pos, ",\"listen\":true}", max_len - pos)
                   ? 15
                   : 0;
        break;
      default:
        pos += runtime_strncpy(out + pos, "}", max_len - pos) ? 1 : 0;
        break;
      }
    }
    break;

  case 0x04: /* Agentic */
    if (req->op == AK_E_TOOL_CALL) {
      /* Extract tool name from tool:<name>:<version> */
      const char *name = req->target;
      if (runtime_strncmp(name, "tool:", 5) == 0)
        name += 5;

      /* Find end of name */
      char tool_name[128];
      int name_len = 0;
      while (name[name_len] && name[name_len] != ':' && name_len < 127) {
        tool_name[name_len] = name[name_len];
        name_len++;
      }
      tool_name[name_len] = '\0';

      pos += runtime_strncpy(out + pos, "{\"name\":", max_len - pos) ? 8 : 0;
      pos += json_write_escaped_string(out + pos, max_len - pos, tool_name);
      pos += runtime_strncpy(out + pos, "}", max_len - pos) ? 1 : 0;
    } else if (req->op == AK_E_INFER) {
      /* Extract model name from model:<name>:<version> */
      const char *model = req->target;
      if (runtime_strncmp(model, "model:", 6) == 0)
        model += 6;

      char model_name[128];
      int name_len = 0;
      while (model[name_len] && model[name_len] != ':' && name_len < 127) {
        model_name[name_len] = model[name_len];
        name_len++;
      }
      model_name[name_len] = '\0';

      pos += runtime_strncpy(out + pos, "{\"model\":", max_len - pos) ? 9 : 0;
      pos += json_write_escaped_string(out + pos, max_len - pos, model_name);
      pos += runtime_strncpy(out + pos, "}", max_len - pos) ? 1 : 0;
    } else if (req->op == AK_E_WASM_INVOKE) {
      /* Extract module:function from wasm:<module>:<function> */
      pos += runtime_strncpy(out + pos, "{\"target\":", max_len - pos) ? 10 : 0;
      pos += json_write_escaped_string(out + pos, max_len - pos, req->target);
      pos += runtime_strncpy(out + pos, "}", max_len - pos) ? 1 : 0;
    } else {
      pos += runtime_strncpy(out + pos, "{\"target\":", max_len - pos) ? 10 : 0;
      pos += json_write_escaped_string(out + pos, max_len - pos, req->target);
      pos += runtime_strncpy(out + pos, "}", max_len - pos) ? 1 : 0;
    }
    break;

  default:
    pos += runtime_strncpy(out + pos, "{\"target\":", max_len - pos) ? 10 : 0;
    pos += json_write_escaped_string(out + pos, max_len - pos, req->target);
    pos += runtime_strncpy(out + pos, "}", max_len - pos) ? 1 : 0;
    break;
  }

  out[pos] = '\0';
}

/* ============================================================
 * INITIALIZATION AND LIFECYCLE
 * ============================================================ */

ak_record_state_t *ak_record_init(heap h) {
  if (!h || h == INVALID_ADDRESS)
    return NULL;

  ak_record_state_t *state = ak_alloc_zero(h, ak_record_state_t);
  if (ak_is_invalid_address(state))
    return NULL;

  state->h = h;
  state->unique_count = 0;
  state->total_count = 0;
  state->enabled = false;
  state->start_time_ms = 0;

  /* Initialize hash buckets to NULL */
  for (int i = 0; i < AK_RECORD_HASH_SIZE; i++) {
    state->buckets[i] = NULL;
  }

  ak_debug("ak_record: initialized");
  return state;
}

void ak_record_shutdown(ak_record_state_t *state) {
  if (!state)
    return;

  /* Free all recorded effects */
  ak_record_clear(state);

  /* Free the state structure */
  heap h = state->h;
  ak_memzero(state, sizeof(*state));
  deallocate(h, state, sizeof(ak_record_state_t));

  ak_debug("ak_record: shutdown");
}

void ak_record_enable(ak_record_state_t *state) {
  if (!state)
    return;

  state->enabled = true;
  state->start_time_ms = ak_now_ms();

  ak_debug("ak_record: recording enabled");
}

void ak_record_disable(ak_record_state_t *state) {
  if (!state)
    return;

  state->enabled = false;

  ak_debug("ak_record: recording disabled (recorded %u unique effects)",
           state->unique_count);
}

boolean ak_record_is_enabled(ak_record_state_t *state) {
  return state && state->enabled;
}

/* ============================================================
 * RECORDING EFFECTS
 * ============================================================ */

int ak_record_effect(ak_record_state_t *state, const ak_effect_req_t *req) {
  if (!state || !req)
    return -EINVAL;

  if (!state->enabled)
    return -EINVAL;

  /* Check if already recorded */
  ak_recorded_effect_t *existing = ak_record_find(state, req->op, req->target);
  if (existing) {
    existing->count++;
    state->total_count++;
    return 1; /* Duplicate */
  }

  /* Check capacity */
  if (state->unique_count >= AK_RECORD_MAX_EFFECTS)
    return -ENOSPC;

  /* Allocate new entry */
  ak_recorded_effect_t *entry = ak_alloc_zero(state->h, ak_recorded_effect_t);
  if (ak_is_invalid_address(entry))
    return -ENOMEM;

  /* Fill in entry */
  entry->op = req->op;
  runtime_strncpy(entry->target, req->target, AK_MAX_TARGET);
  entry->count = 1;

  /* Generate suggested rule */
  ak_record_generate_rule(entry, req);

  /* Insert into hash table */
  u32 bucket = ak_record_hash(req->op, req->target);
  entry->next = state->buckets[bucket];
  state->buckets[bucket] = entry;

  state->unique_count++;
  state->total_count++;

  ak_debug("ak_record: recorded effect %s target=%s (total=%u)",
           ak_record_effect_type_name(req->op), req->target,
           state->unique_count);

  return 0;
}

/* ============================================================
 * GENERATING SUGGESTIONS
 * ============================================================ */

sysreturn ak_record_get_suggestions(ak_record_state_t *state, char *out,
                                    u64 out_len) {
  if (!state || !out || out_len < 64)
    return -EINVAL;

  if (state->unique_count == 0)
    return -ENOENT;

  int pos = 0;
  int remaining = (int)(out_len - 1);

  /* Start JSON object */
  out[pos++] = '{';
  remaining--;

  /* Version */
  pos += runtime_strncpy(out + pos, "\"version\":\"1.0\",", remaining) ? 16 : 0;
  remaining = (int)out_len - 1 - pos;

  /* Effects recorded count */
  pos +=
      runtime_strncpy(out + pos, "\"effects_recorded\":", remaining) ? 19 : 0;
  remaining = (int)out_len - 1 - pos;
  pos += json_write_uint(out + pos, remaining, state->unique_count);
  remaining = (int)out_len - 1 - pos;

  /* Collect effects by category */
  boolean has_fs = false, has_net = false, has_agentic = false;

  for (int i = 0; i < AK_RECORD_HASH_SIZE; i++) {
    ak_recorded_effect_t *entry = state->buckets[i];
    while (entry) {
      u32 cat = (entry->op >> 8) & 0xFF;
      if (cat == 0x01)
        has_fs = true;
      else if (cat == 0x02)
        has_net = true;
      else if (cat == 0x04)
        has_agentic = true;
      entry = entry->next;
    }
  }

  /* Filesystem rules */
  if (has_fs && remaining > 50) {
    pos +=
        runtime_strncpy(out + pos, ",\"fs\":{\"allow\":[", remaining) ? 16 : 0;
    remaining = (int)out_len - 1 - pos;

    boolean first = true;
    for (int i = 0; i < AK_RECORD_HASH_SIZE && remaining > 20; i++) {
      ak_recorded_effect_t *entry = state->buckets[i];
      while (entry && remaining > 20) {
        if (((entry->op >> 8) & 0xFF) == 0x01) {
          if (!first) {
            out[pos++] = ',';
            remaining--;
          }
          first = false;

          u64 rule_len = runtime_strlen(entry->suggested_rule);
          if (pos + rule_len < out_len - 10) {
            runtime_memcpy(out + pos, entry->suggested_rule, rule_len);
            pos += rule_len;
            remaining = (int)out_len - 1 - pos;
          }
        }
        entry = entry->next;
      }
    }

    pos += runtime_strncpy(out + pos, "]}", remaining) ? 2 : 0;
    remaining = (int)out_len - 1 - pos;
  }

  /* Network rules */
  if (has_net && remaining > 50) {
    pos +=
        runtime_strncpy(out + pos, ",\"net\":{\"allow\":[", remaining) ? 17 : 0;
    remaining = (int)out_len - 1 - pos;

    boolean first = true;
    for (int i = 0; i < AK_RECORD_HASH_SIZE && remaining > 20; i++) {
      ak_recorded_effect_t *entry = state->buckets[i];
      while (entry && remaining > 20) {
        if (((entry->op >> 8) & 0xFF) == 0x02) {
          if (!first) {
            out[pos++] = ',';
            remaining--;
          }
          first = false;

          u64 rule_len = runtime_strlen(entry->suggested_rule);
          if (pos + rule_len < out_len - 10) {
            runtime_memcpy(out + pos, entry->suggested_rule, rule_len);
            pos += rule_len;
            remaining = (int)out_len - 1 - pos;
          }
        }
        entry = entry->next;
      }
    }

    pos += runtime_strncpy(out + pos, "]}", remaining) ? 2 : 0;
    remaining = (int)out_len - 1 - pos;
  }

  /* Agentic rules (tools + inference) */
  if (has_agentic && remaining > 50) {
    /* Tools */
    boolean has_tools = false, has_inference = false;
    for (int i = 0; i < AK_RECORD_HASH_SIZE; i++) {
      ak_recorded_effect_t *entry = state->buckets[i];
      while (entry) {
        if (entry->op == AK_E_TOOL_CALL || entry->op == AK_E_WASM_INVOKE)
          has_tools = true;
        if (entry->op == AK_E_INFER)
          has_inference = true;
        entry = entry->next;
      }
    }

    if (has_tools && remaining > 40) {
      pos += runtime_strncpy(out + pos, ",\"tools\":{\"allow\":[", remaining)
                 ? 19
                 : 0;
      remaining = (int)out_len - 1 - pos;

      boolean first = true;
      for (int i = 0; i < AK_RECORD_HASH_SIZE && remaining > 20; i++) {
        ak_recorded_effect_t *entry = state->buckets[i];
        while (entry && remaining > 20) {
          if (entry->op == AK_E_TOOL_CALL || entry->op == AK_E_WASM_INVOKE) {
            if (!first) {
              out[pos++] = ',';
              remaining--;
            }
            first = false;

            u64 rule_len = runtime_strlen(entry->suggested_rule);
            if (pos + rule_len < out_len - 10) {
              runtime_memcpy(out + pos, entry->suggested_rule, rule_len);
              pos += rule_len;
              remaining = (int)out_len - 1 - pos;
            }
          }
          entry = entry->next;
        }
      }

      pos += runtime_strncpy(out + pos, "]}", remaining) ? 2 : 0;
      remaining = (int)out_len - 1 - pos;
    }

    if (has_inference && remaining > 40) {
      pos +=
          runtime_strncpy(out + pos, ",\"inference\":{\"allow\":[", remaining)
              ? 23
              : 0;
      remaining = (int)out_len - 1 - pos;

      boolean first = true;
      for (int i = 0; i < AK_RECORD_HASH_SIZE && remaining > 20; i++) {
        ak_recorded_effect_t *entry = state->buckets[i];
        while (entry && remaining > 20) {
          if (entry->op == AK_E_INFER) {
            if (!first) {
              out[pos++] = ',';
              remaining--;
            }
            first = false;

            u64 rule_len = runtime_strlen(entry->suggested_rule);
            if (pos + rule_len < out_len - 10) {
              runtime_memcpy(out + pos, entry->suggested_rule, rule_len);
              pos += rule_len;
              remaining = (int)out_len - 1 - pos;
            }
          }
          entry = entry->next;
        }
      }

      pos += runtime_strncpy(out + pos, "]}", remaining) ? 2 : 0;
      remaining = (int)out_len - 1 - pos;
    }
  }

  /* Close JSON object */
  if (remaining > 0) {
    out[pos++] = '}';
  }

  out[pos] = '\0';
  return pos;
}

sysreturn ak_record_get_suggestions_toml(ak_record_state_t *state, char *out,
                                         u64 out_len) {
  if (!state || !out || out_len < 64)
    return -EINVAL;

  if (state->unique_count == 0)
    return -ENOENT;

  int pos = 0;
  int remaining = (int)(out_len - 1);

  /* Header comment */
  const char *header = "# Authority Kernel - Auto-generated Policy\n"
                       "# Generated from recorded effects\n"
                       "# Review carefully before deploying!\n\n";
  u64 header_len = runtime_strlen(header);
  if (pos + header_len < out_len) {
    runtime_memcpy(out + pos, header, header_len);
    pos += header_len;
    remaining = (int)out_len - 1 - pos;
  }

  /* Collect and output by category */

  /* Filesystem rules */
  for (int i = 0; i < AK_RECORD_HASH_SIZE && remaining > 50; i++) {
    ak_recorded_effect_t *entry = state->buckets[i];
    while (entry && remaining > 50) {
      if (((entry->op >> 8) & 0xFF) == 0x01) {
        boolean is_write =
            (entry->op == AK_E_FS_UNLINK || entry->op == AK_E_FS_RENAME ||
             entry->op == AK_E_FS_MKDIR || entry->op == AK_E_FS_RMDIR);

        pos += runtime_strncpy(out + pos, "[[fs.allow]]\n", remaining) ? 13 : 0;
        remaining = (int)out_len - 1 - pos;

        pos += runtime_strncpy(out + pos, "path = \"", remaining) ? 8 : 0;
        remaining = (int)out_len - 1 - pos;

        u64 target_len = runtime_strlen(entry->target);
        if (pos + target_len < out_len - 30) {
          runtime_memcpy(out + pos, entry->target, target_len);
          pos += target_len;
          remaining = (int)out_len - 1 - pos;
        }

        pos += runtime_strncpy(out + pos, "\"\n", remaining) ? 2 : 0;
        remaining = (int)out_len - 1 - pos;

        if (is_write) {
          pos += runtime_strncpy(out + pos, "write = true\n\n", remaining) ? 14
                                                                           : 0;
        } else {
          pos +=
              runtime_strncpy(out + pos, "read = true\n\n", remaining) ? 13 : 0;
        }
        remaining = (int)out_len - 1 - pos;
      }
      entry = entry->next;
    }
  }

  /* Network rules */
  for (int i = 0; i < AK_RECORD_HASH_SIZE && remaining > 50; i++) {
    ak_recorded_effect_t *entry = state->buckets[i];
    while (entry && remaining > 50) {
      if (((entry->op >> 8) & 0xFF) == 0x02) {
        if (entry->op == AK_E_NET_DNS_RESOLVE) {
          pos +=
              runtime_strncpy(out + pos, "[[dns.allow]]\n", remaining) ? 14 : 0;
          remaining = (int)out_len - 1 - pos;

          const char *host = entry->target;
          if (runtime_strncmp(host, "dns:", 4) == 0)
            host += 4;

          pos += runtime_strncpy(out + pos, "pattern = \"", remaining) ? 11 : 0;
          remaining = (int)out_len - 1 - pos;

          u64 host_len = runtime_strlen(host);
          if (pos + host_len < out_len - 20) {
            runtime_memcpy(out + pos, host, host_len);
            pos += host_len;
            remaining = (int)out_len - 1 - pos;
          }

          pos += runtime_strncpy(out + pos, "\"\n\n", remaining) ? 3 : 0;
          remaining = (int)out_len - 1 - pos;
        } else {
          pos +=
              runtime_strncpy(out + pos, "[[net.allow]]\n", remaining) ? 14 : 0;
          remaining = (int)out_len - 1 - pos;

          pos += runtime_strncpy(out + pos, "pattern = \"", remaining) ? 11 : 0;
          remaining = (int)out_len - 1 - pos;

          u64 target_len = runtime_strlen(entry->target);
          if (pos + target_len < out_len - 30) {
            runtime_memcpy(out + pos, entry->target, target_len);
            pos += target_len;
            remaining = (int)out_len - 1 - pos;
          }

          pos += runtime_strncpy(out + pos, "\"\n", remaining) ? 2 : 0;
          remaining = (int)out_len - 1 - pos;

          switch (entry->op) {
          case AK_E_NET_CONNECT:
            pos += runtime_strncpy(out + pos, "connect = true\n\n", remaining)
                       ? 16
                       : 0;
            break;
          case AK_E_NET_BIND:
            pos += runtime_strncpy(out + pos, "bind = true\n\n", remaining) ? 13
                                                                            : 0;
            break;
          case AK_E_NET_LISTEN:
            pos += runtime_strncpy(out + pos, "listen = true\n\n", remaining)
                       ? 15
                       : 0;
            break;
          default:
            pos += runtime_strncpy(out + pos, "\n", remaining) ? 1 : 0;
            break;
          }
          remaining = (int)out_len - 1 - pos;
        }
      }
      entry = entry->next;
    }
  }

  /* Tool rules */
  for (int i = 0; i < AK_RECORD_HASH_SIZE && remaining > 40; i++) {
    ak_recorded_effect_t *entry = state->buckets[i];
    while (entry && remaining > 40) {
      if (entry->op == AK_E_TOOL_CALL) {
        pos +=
            runtime_strncpy(out + pos, "[[tools.allow]]\n", remaining) ? 16 : 0;
        remaining = (int)out_len - 1 - pos;

        const char *name = entry->target;
        if (runtime_strncmp(name, "tool:", 5) == 0)
          name += 5;

        char tool_name[128];
        int name_len = 0;
        while (name[name_len] && name[name_len] != ':' && name_len < 127) {
          tool_name[name_len] = name[name_len];
          name_len++;
        }
        tool_name[name_len] = '\0';

        pos += runtime_strncpy(out + pos, "name = \"", remaining) ? 8 : 0;
        remaining = (int)out_len - 1 - pos;

        if (pos + name_len < out_len - 10) {
          runtime_memcpy(out + pos, tool_name, name_len);
          pos += name_len;
          remaining = (int)out_len - 1 - pos;
        }

        pos += runtime_strncpy(out + pos, "\"\n\n", remaining) ? 3 : 0;
        remaining = (int)out_len - 1 - pos;
      }
      entry = entry->next;
    }
  }

  /* Inference rules */
  for (int i = 0; i < AK_RECORD_HASH_SIZE && remaining > 40; i++) {
    ak_recorded_effect_t *entry = state->buckets[i];
    while (entry && remaining > 40) {
      if (entry->op == AK_E_INFER) {
        pos += runtime_strncpy(out + pos, "[[inference.allow]]\n", remaining)
                   ? 20
                   : 0;
        remaining = (int)out_len - 1 - pos;

        const char *model = entry->target;
        if (runtime_strncmp(model, "model:", 6) == 0)
          model += 6;

        char model_name[128];
        int name_len = 0;
        while (model[name_len] && model[name_len] != ':' && name_len < 127) {
          model_name[name_len] = model[name_len];
          name_len++;
        }
        model_name[name_len] = '\0';

        pos += runtime_strncpy(out + pos, "model = \"", remaining) ? 9 : 0;
        remaining = (int)out_len - 1 - pos;

        if (pos + name_len < out_len - 10) {
          runtime_memcpy(out + pos, model_name, name_len);
          pos += name_len;
          remaining = (int)out_len - 1 - pos;
        }

        pos += runtime_strncpy(out + pos, "\"\n\n", remaining) ? 3 : 0;
        remaining = (int)out_len - 1 - pos;
      }
      entry = entry->next;
    }
  }

  out[pos] = '\0';
  return pos;
}

/* ============================================================
 * MANAGEMENT
 * ============================================================ */

void ak_record_clear(ak_record_state_t *state) {
  if (!state)
    return;

  /* Free all entries in hash table */
  for (int i = 0; i < AK_RECORD_HASH_SIZE; i++) {
    ak_recorded_effect_t *entry = state->buckets[i];
    while (entry) {
      ak_recorded_effect_t *next = entry->next;
      deallocate(state->h, entry, sizeof(ak_recorded_effect_t));
      entry = next;
    }
    state->buckets[i] = NULL;
  }

  state->unique_count = 0;
  state->total_count = 0;

  ak_debug("ak_record: cleared all recorded effects");
}

u32 ak_record_count(ak_record_state_t *state) {
  return state ? state->unique_count : 0;
}

u64 ak_record_total_count(ak_record_state_t *state) {
  return state ? state->total_count : 0;
}

/* ============================================================
 * ITERATION
 * ============================================================ */

u32 ak_record_foreach(ak_record_state_t *state, ak_record_iter_fn fn,
                      void *arg) {
  if (!state || !fn)
    return 0;

  u32 count = 0;

  for (int i = 0; i < AK_RECORD_HASH_SIZE; i++) {
    ak_recorded_effect_t *entry = state->buckets[i];
    while (entry) {
      if (!fn(entry, arg))
        return count;
      count++;
      entry = entry->next;
    }
  }

  return count;
}

/* ============================================================
 * CONTEXT INTEGRATION
 * ============================================================ */

int ak_ctx_enable_record_mode(ak_ctx_t *ctx, heap h) {
  if (!ctx)
    return -EINVAL;

  /* Use agent heap if none provided */
  if (!h || h == INVALID_ADDRESS) {
    if (ctx->agent && ctx->agent->heap) {
      h = ctx->agent->heap;
    } else {
      return -EINVAL;
    }
  }

  /* Initialize record state if needed */
  if (!ctx->record) {
    ctx->record = ak_record_init(h);
    if (!ctx->record)
      return -ENOMEM;
  }

  /* Enable recording */
  ak_record_enable(ctx->record);

  /* Set context mode */
  ctx->mode = AK_MODE_RECORD;

  ak_debug("ak_record: record mode enabled on context");
  return 0;
}

void ak_ctx_disable_record_mode(ak_ctx_t *ctx) {
  if (!ctx)
    return;

  if (ctx->record) {
    ak_record_disable(ctx->record);
  }

  /* Revert to soft mode */
  ctx->mode = AK_MODE_SOFT;

  ak_debug("ak_record: record mode disabled on context");
}

ak_record_state_t *ak_ctx_get_record_state(ak_ctx_t *ctx) {
  return ctx ? ctx->record : NULL;
}
