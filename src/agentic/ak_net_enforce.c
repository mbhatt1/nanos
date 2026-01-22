/*
 * Authority Kernel - Network Enforcement Implementation
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Implements network access control at socket syscall layer.
 */

#include "ak_net_enforce.h"
#include "ak_capability.h"
#include "ak_sanitize.h"
#include "ak_audit.h"

/* ============================================================
 * INTERNAL STATE
 * ============================================================ */

/* Forward declaration - implemented in ak_syscall.c */
extern ak_agent_context_t *ak_get_root_context(void);

/* Network rule entry */
typedef struct ak_net_rule {
    struct ak_net_rule *next;
    ak_net_rule_type_t type;
    char host[256];         /* Host pattern */
    u16 port;               /* 0 = any port */
} ak_net_rule_t;

/* Default deny all state */
static boolean ak_net_default_deny = true;

/* Global heap for allocations */
static heap ak_net_heap = NULL;

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

void ak_net_init(heap h)
{
    ak_net_heap = h;
    ak_net_default_deny = true;
}

/* ============================================================
 * PATTERN MATCHING
 * ============================================================ */

/*
 * Match host against pattern.
 * Patterns:
 *   "*"           - Match anything
 *   "*.foo.com"   - Suffix match
 *   "foo.com"     - Exact match
 */
static boolean ak_net_host_match(const char *pattern, const char *host)
{
    if (!pattern || !host)
        return false;

    /* Wildcard matches everything */
    if (pattern[0] == '*' && pattern[1] == '\0')
        return true;

    /* Suffix match: *.example.com */
    if (pattern[0] == '*' && pattern[1] == '.') {
        const char *suffix = pattern + 1;  /* ".example.com" */
        u64 suffix_len = runtime_strlen(suffix);
        u64 host_len = runtime_strlen(host);

        if (host_len < suffix_len)
            return false;

        /* Check if host ends with suffix */
        return runtime_memcmp(host + host_len - suffix_len, suffix, suffix_len) == 0;
    }

    /* Exact match */
    return runtime_strcmp(pattern, host) == 0;
}

/*
 * Check host:port against rules.
 * Returns: true if allowed, false if denied
 */
static boolean ak_net_check_rules(ak_agent_context_t *ctx, const char *host, u16 port)
{
    if (!ctx || !ctx->network_rules)
        return !ak_net_default_deny;

    /* Iterate through rules - first match wins */
    ak_net_rule_t *rule = (ak_net_rule_t *)table_find(ctx->network_rules, 0);

    /* If no rules table or empty, check for capability */
    if (!rule) {
        /* Check for AK_CAP_NET capability */
        char endpoint[320];
        ak_net_format_endpoint(host, port, endpoint);

        /* Look for a matching network capability */
        if (ctx->root_cap && ctx->root_cap->type == AK_CAP_NET) {
            if (ak_pattern_match((const char *)ctx->root_cap->resource, endpoint))
                return true;
        }

        return !ak_net_default_deny;
    }

    /* Walk rule list */
    while (rule) {
        /* Check port match (0 = any) */
        if (rule->port != 0 && rule->port != port) {
            rule = rule->next;
            continue;
        }

        /* Check host match */
        if (ak_net_host_match(rule->host, host)) {
            return (rule->type == AK_NET_RULE_ALLOW);
        }

        rule = rule->next;
    }

    /* No rule matched - use default */
    return !ak_net_default_deny;
}

/* ============================================================
 * CONNECTION CONTROL
 * ============================================================ */

s64 ak_net_check_connect(const char *host, u16 port, boolean is_ipv6)
{
    (void)is_ipv6;  /* Currently unused */

    if (!host)
        return -EINVAL;

    /* Get current agent context */
    ak_agent_context_t *ctx = ak_get_root_context();
    if (!ctx) {
        /* No agent context - allow for non-agent processes */
        return 0;
    }

    /* Check rules */
    boolean allowed = ak_net_check_rules(ctx, host, port);

    /* Audit log the attempt */
    ak_net_audit_log("connect", host, port, allowed, 0);

    if (!allowed) {
        return -EACCES;
    }

    return 0;
}

s64 ak_net_check_bind(u16 port, boolean is_ipv6)
{
    (void)is_ipv6;

    ak_agent_context_t *ctx = ak_get_root_context();
    if (!ctx) {
        return 0;  /* Allow for non-agent processes */
    }

    /* For now, allow all binds - could restrict to specific ports */
    ak_net_audit_log("bind", "0.0.0.0", port, true, 0);
    return 0;
}

s64 ak_net_check_accept(const char *client_host, u16 client_port)
{
    ak_agent_context_t *ctx = ak_get_root_context();
    if (!ctx) {
        return 0;
    }

    /* For now, allow all accepts - could filter by client */
    ak_net_audit_log("accept", client_host, client_port, true, 0);
    return 0;
}

/* ============================================================
 * DATA FILTERING (DLP)
 * ============================================================ */

s64 ak_net_filter_send(u8 *data, u64 len, const char *dest_host, u16 dest_port)
{
    ak_agent_context_t *ctx = ak_get_root_context();
    if (!ctx) {
        return 0;  /* No filtering for non-agent processes */
    }

    /* Check budget */
    if (ctx->budget) {
        u64 used = ctx->budget->budgets.used[AK_RESOURCE_NET_BYTES_OUT];
        u64 limit = ctx->budget->budgets.limits[AK_RESOURCE_NET_BYTES_OUT];
        if (limit > 0 && used + len > limit) {
            ak_net_audit_log("send_blocked", dest_host, dest_port, false, len);
            return AK_E_BUDGET_EXCEEDED;
        }
        /* Update usage */
        ctx->budget->budgets.used[AK_RESOURCE_NET_BYTES_OUT] += len;
    }

    /* DLP: Scan for secrets */
    if (data && len > 0 && ak_net_heap) {
        /* Create buffer wrapper for scanning */
        buffer scan_buf = allocate_buffer(ak_net_heap, len);
        if (scan_buf) {
            buffer_write(scan_buf, data, len);

            /* Check for secrets */
            u32 detected = ak_dlp_detect_secrets(scan_buf, AK_DLP_PATTERN_ALL);

            if (detected) {
                /* Secrets detected - block the send */
                deallocate_buffer(scan_buf);
                ak_net_audit_log("send_dlp_block", dest_host, dest_port, false, len);
                return AK_E_DLP_BLOCK;
            }

            deallocate_buffer(scan_buf);
        }
    }

    /* Audit the send */
    ak_net_audit_log("send", dest_host, dest_port, true, len);

    return 0;
}

s64 ak_net_track_recv(u64 len, const char *src_host, u16 src_port)
{
    ak_agent_context_t *ctx = ak_get_root_context();
    if (!ctx) {
        return 0;
    }

    /* Track bytes against budget (but don't block inbound) */
    if (ctx->budget) {
        ctx->budget->budgets.used[AK_RESOURCE_NETWORK_BYTES] += len;
    }

    /* Audit the receive */
    ak_net_audit_log("recv", src_host, src_port, true, len);

    return 0;
}

/* ============================================================
 * DNS FILTERING
 * ============================================================ */

s64 ak_net_check_dns(const char *domain)
{
    if (!domain)
        return -EINVAL;

    ak_agent_context_t *ctx = ak_get_root_context();
    if (!ctx) {
        return 0;  /* Allow for non-agent processes */
    }

    /* Check if domain resolution is allowed via rules */
    /* DNS uses port 53, but we check against the domain itself */
    boolean allowed = ak_net_check_rules(ctx, domain, 0);

    ak_net_audit_log("dns", domain, 53, allowed, 0);

    if (!allowed) {
        return -EACCES;
    }

#ifdef CONFIG_AGENTIC
    /* Also check through the POSIX routing layer if available */
    extern sysreturn ak_route_dns_resolve(const char *hostname);
    sysreturn route_ret = ak_route_dns_resolve(domain);
    if (route_ret < 0) {
        return route_ret;
    }
#endif

    return 0;
}

/* ============================================================
 * RULE MANAGEMENT
 * ============================================================ */

s64 ak_net_add_rule(ak_net_rule_type_t type, const char *host, u16 port)
{
    if (!host || !ak_net_heap)
        return -EINVAL;

    ak_agent_context_t *ctx = ak_get_root_context();
    if (!ctx)
        return -EINVAL;

    /* Allocate rule */
    ak_net_rule_t *rule = allocate(ak_net_heap, sizeof(ak_net_rule_t));
    if (!rule)
        return -ENOMEM;

    rule->type = type;
    rule->port = port;
    runtime_memset(rule->host, 0, sizeof(rule->host));

    u64 len = runtime_strlen(host);
    if (len >= sizeof(rule->host))
        len = sizeof(rule->host) - 1;
    runtime_memcpy(rule->host, host, len);

    /* Initialize rules table if needed */
    if (!ctx->network_rules) {
        ctx->network_rules = allocate_table(ak_net_heap, identity_key, pointer_equal);
    }

    /* Add to front of list (table stores head pointer at key 0) */
    rule->next = (ak_net_rule_t *)table_find(ctx->network_rules, 0);
    table_set(ctx->network_rules, 0, rule);

    return 0;
}

void ak_net_clear_rules(void)
{
    ak_agent_context_t *ctx = ak_get_root_context();
    if (!ctx || !ctx->network_rules || !ak_net_heap)
        return;

    /* Free all rules */
    ak_net_rule_t *rule = (ak_net_rule_t *)table_find(ctx->network_rules, 0);
    while (rule) {
        ak_net_rule_t *next = rule->next;
        deallocate(ak_net_heap, rule, sizeof(ak_net_rule_t));
        rule = next;
    }

    table_set(ctx->network_rules, 0, NULL);
}

/* ============================================================
 * AUDIT LOGGING
 * ============================================================ */

void ak_net_audit_log(const char *event, const char *host, u16 port,
                      boolean allowed, u64 bytes)
{
    /* Build JSON audit entry */
    /* For now, just log to debug output */
    /* TODO: Integrate with ak_audit_log() */
    (void)event;
    (void)host;
    (void)port;
    (void)allowed;
    (void)bytes;
}

/* ============================================================
 * ADDRESS FORMATTING
 * ============================================================ */

void ak_net_format_ipv4(u32 ip, char *out)
{
    /* IP is in network byte order */
    u8 *bytes = (u8 *)&ip;

    /* Format as "a.b.c.d" */
    int pos = 0;
    for (int i = 0; i < 4; i++) {
        u8 b = bytes[i];
        if (b >= 100) {
            out[pos++] = '0' + (b / 100);
            b %= 100;
            out[pos++] = '0' + (b / 10);
            out[pos++] = '0' + (b % 10);
        } else if (b >= 10) {
            out[pos++] = '0' + (b / 10);
            out[pos++] = '0' + (b % 10);
        } else {
            out[pos++] = '0' + b;
        }
        if (i < 3)
            out[pos++] = '.';
    }
    out[pos] = '\0';
}

void ak_net_format_ipv6(const u8 *ip, char *out)
{
    /* Simplified IPv6 formatting - full form only */
    static const char hex[] = "0123456789abcdef";
    int pos = 0;

    for (int i = 0; i < 16; i += 2) {
        out[pos++] = hex[(ip[i] >> 4) & 0xf];
        out[pos++] = hex[ip[i] & 0xf];
        out[pos++] = hex[(ip[i+1] >> 4) & 0xf];
        out[pos++] = hex[ip[i+1] & 0xf];
        if (i < 14)
            out[pos++] = ':';
    }
    out[pos] = '\0';
}

void ak_net_format_endpoint(const char *host, u16 port, char *out)
{
    int pos = 0;

    /* Copy host */
    while (*host && pos < 300) {
        out[pos++] = *host++;
    }

    /* Add port */
    out[pos++] = ':';

    /* Format port number */
    if (port >= 10000) {
        out[pos++] = '0' + (port / 10000);
        port %= 10000;
        out[pos++] = '0' + (port / 1000);
        port %= 1000;
        out[pos++] = '0' + (port / 100);
        port %= 100;
        out[pos++] = '0' + (port / 10);
        out[pos++] = '0' + (port % 10);
    } else if (port >= 1000) {
        out[pos++] = '0' + (port / 1000);
        port %= 1000;
        out[pos++] = '0' + (port / 100);
        port %= 100;
        out[pos++] = '0' + (port / 10);
        out[pos++] = '0' + (port % 10);
    } else if (port >= 100) {
        out[pos++] = '0' + (port / 100);
        port %= 100;
        out[pos++] = '0' + (port / 10);
        out[pos++] = '0' + (port % 10);
    } else if (port >= 10) {
        out[pos++] = '0' + (port / 10);
        out[pos++] = '0' + (port % 10);
    } else {
        out[pos++] = '0' + port;
    }

    out[pos] = '\0';
}
