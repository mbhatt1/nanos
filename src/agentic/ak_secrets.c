/*
 * Authority Kernel - Secrets Resolution Implementation
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Provides secure secret resolution for WASM tools.
 */

#include "ak_secrets.h"
#include "ak_compat.h"
#include "ak_pattern.h"

/* ============================================================
 * STATE
 * ============================================================ */

static struct {
    heap h;
    ak_secret_backend_t backend;
    const char *file_path;
    int virtio_fd;
    table secrets;              /* name -> buffer (preloaded secrets) */
    boolean initialized;
    const char *last_error;
} secrets_state;

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

void ak_secrets_init(heap h, ak_secrets_config_t *config)
{
    secrets_state.h = h;
    secrets_state.backend = config ? config->backend : AK_SECRET_BACKEND_ENV;
    secrets_state.file_path = config && config->file_path ?
                              config->file_path : "/run/secrets";
    secrets_state.virtio_fd = config ? config->virtio_fd : -1;
    secrets_state.secrets = allocate_table(h, key_from_pointer, pointer_equal);
    secrets_state.initialized = true;
    secrets_state.last_error = 0;

    /* If config provides preloaded secrets table, copy references */
    if (config && config->env_secrets) {
        table_foreach(config->env_secrets, k, v) {
            table_set(secrets_state.secrets, k, v);
        }
    }
}

void ak_secrets_preload(const char *name, const char *value, u64 value_len)
{
    if (!secrets_state.initialized)
        return;

    /* Create buffer for the value */
    buffer v = allocate_buffer(secrets_state.h, value_len);
    if (v && v != INVALID_ADDRESS) {
        buffer_write(v, value, value_len);

        /* Create key (copy of name) */
        u64 name_len = runtime_strlen(name);
        buffer k = allocate_buffer(secrets_state.h, name_len + 1);
        if (k && k != INVALID_ADDRESS) {
            buffer_write(k, name, name_len);
            push_u8(k, '\0');
            table_set(secrets_state.secrets, k, v);
        }
    }
}

/* ============================================================
 * BACKEND IMPLEMENTATIONS
 * ============================================================ */

static buffer resolve_from_preloaded(const char *ref, u64 ref_len)
{
    /* Linear search through preloaded secrets */
    table_foreach(secrets_state.secrets, k, v) {
        buffer key = k;
        if (buffer_length(key) >= ref_len) {
            const char *key_str = buffer_ref(key, 0);
            if (runtime_strncmp(key_str, ref, ref_len) == 0 &&
                (buffer_length(key) == ref_len ||
                 byte(key, ref_len) == '\0')) {
                return (buffer)v;
            }
        }
    }
    return 0;
}

static buffer resolve_from_env(heap h, const char *ref, u64 ref_len)
{
    /* First check preloaded secrets */
    buffer result = 0;
    buffer preloaded = resolve_from_preloaded(ref, ref_len);
    if (preloaded) {
        /* Clone the buffer for the caller */
        result = allocate_buffer(h, buffer_length(preloaded));
        if (result && result != INVALID_ADDRESS) {
            buffer_write(result, buffer_ref(preloaded, 0), buffer_length(preloaded));
        }
        return result;
    }

    /*
     * In kernel context, environment variables come from:
     * 1. Kernel command line (parsed during boot)
     * 2. Configuration manifest
     *
     * For production, secrets should be preloaded during initialization
     * from the appropriate source.
     */
    secrets_state.last_error = "secret not found in environment";
    return 0;
}

static buffer resolve_from_file(heap h, const char *ref, u64 ref_len)
{
    /*
     * Resolve secret from /run/secrets/<ref> path.
     *
     * Current implementation: Falls back to preloaded secrets since filesystem
     * access requires Nanos fs APIs that may not be available at secret
     * resolution time (especially during early boot).
     *
     * Preloaded secrets are populated via ak_secret_preload() during init,
     * allowing policies to reference file:// URIs without actual file I/O.
     */
    buffer result = 0;
    buffer preloaded = resolve_from_preloaded(ref, ref_len);
    if (preloaded) {
        result = allocate_buffer(h, buffer_length(preloaded));
        if (result && result != INVALID_ADDRESS) {
            buffer_write(result, buffer_ref(preloaded, 0), buffer_length(preloaded));
        }
        return result;
    }

    /*
     * Future: Direct file-based secret reading.
     * This would require integration with Nanos filesystem APIs:
     * 1. Build path: /run/secrets/<ref>
     * 2. Open file (fs_open)
     * 3. Read contents (fs_read)
     * 4. Close file
     * 5. Return buffer
     *
     * Until filesystem integration is complete, secrets must be preloaded.
     */
    secrets_state.last_error = "secret file not found";
    return 0;
}

static buffer resolve_from_virtio(heap h, const char *ref, u64 ref_len)
{
    /*
     * Request secret from host via virtio-serial.
     *
     * Protocol:
     * 1. Send: { "op": "get_secret", "name": "<ref>" }
     * 2. Recv: { "value": "<base64-encoded-secret>" } or { "error": "..." }
     * 3. Decode and return
     *
     * This requires the virtio-serial driver to be implemented.
     */
    if (secrets_state.virtio_fd < 0) {
        secrets_state.last_error = "virtio secret backend not configured";
        return 0;
    }

    /* Check preloaded as fallback */
    buffer result = 0;
    buffer preloaded = resolve_from_preloaded(ref, ref_len);
    if (preloaded) {
        result = allocate_buffer(h, buffer_length(preloaded));
        if (result && result != INVALID_ADDRESS) {
            buffer_write(result, buffer_ref(preloaded, 0), buffer_length(preloaded));
        }
        return result;
    }

    secrets_state.last_error = "virtio secret resolution not implemented";
    return 0;
}

/* ============================================================
 * PUBLIC API
 * ============================================================ */

buffer ak_secret_resolve(heap h, const char *ref, u64 ref_len,
                         ak_capability_t *cap)
{
    if (!secrets_state.initialized) {
        secrets_state.last_error = "secrets subsystem not initialized";
        return 0;
    }

    if (!ref || ref_len == 0) {
        secrets_state.last_error = "invalid secret reference";
        return 0;
    }

    /* Validate capability if provided */
    if (cap && !ak_secret_check_cap(cap, ref, ref_len)) {
        secrets_state.last_error = "capability does not grant secret access";
        return 0;
    }

    /* Resolve based on backend */
    switch (secrets_state.backend) {
    case AK_SECRET_BACKEND_ENV:
        return resolve_from_env(h, ref, ref_len);
    case AK_SECRET_BACKEND_FILE:
        return resolve_from_file(h, ref, ref_len);
    case AK_SECRET_BACKEND_VIRTIO:
        return resolve_from_virtio(h, ref, ref_len);
    default:
        secrets_state.last_error = "unknown secret backend";
        return 0;
    }
}

boolean ak_secret_check_cap(ak_capability_t *cap, const char *ref, u64 ref_len)
{
    if (!cap)
        return false;

    if (cap->type != AK_CAP_SECRETS)
        return false;

    /* Check resource pattern matches ref */
    /* Pattern "API_*" matches "API_KEY", "API_SECRET", etc. */
    /* Pattern "*" matches everything (dangerous but valid) */

    /* Build null-terminated string for pattern matching */
    char ref_buf[257];
    u64 copy_len = ref_len < 256 ? ref_len : 256;
    runtime_memcpy(ref_buf, ref, copy_len);
    ref_buf[copy_len] = '\0';

    return ak_pattern_match((const char *)cap->resource, ref_buf);
}

void ak_secret_clear(buffer b)
{
    if (!b)
        return;

    /* Secure clear - use volatile to prevent optimization */
    volatile u8 *p = buffer_ref(b, 0);
    u64 len = buffer_length(b);
    while (len--) {
        *p++ = 0;
    }
}

const char *ak_secrets_last_error(void)
{
    return secrets_state.last_error;
}
