/*
 * Authority Kernel - Secrets Resolution
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Provides secure secret resolution for WASM tools.
 * Secrets are never exposed to agent code directly - only
 * injected into authorized tool executions.
 *
 * SECURITY: All secret access requires AK_CAP_SECRETS capability.
 */

#ifndef AK_SECRETS_H
#define AK_SECRETS_H

#include "ak_types.h"
#include "ak_capability.h"

/* ============================================================
 * SECRET BACKEND TYPES
 * ============================================================ */

typedef enum ak_secret_backend {
    AK_SECRET_BACKEND_ENV,      /* Environment variables (AK_SECRET_<name>) */
    AK_SECRET_BACKEND_FILE,     /* File-based (/run/secrets/<name>) */
    AK_SECRET_BACKEND_VIRTIO,   /* virtio-serial to host secret manager */
} ak_secret_backend_t;

/* ============================================================
 * CONFIGURATION
 * ============================================================ */

typedef struct ak_secrets_config {
    ak_secret_backend_t backend;
    const char *file_path;      /* For FILE backend (default: /run/secrets) */
    int virtio_fd;              /* For VIRTIO backend */
    table env_secrets;          /* Preloaded secrets from environment */
} ak_secrets_config_t;

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

/* Initialize secrets subsystem with configuration */
void ak_secrets_init(heap h, ak_secrets_config_t *config);

/* Preload a secret (used during boot from environment/config) */
void ak_secrets_preload(const char *name, const char *value, u64 value_len);

/* ============================================================
 * SECRET RESOLUTION
 * ============================================================ */

/*
 * Resolve a secret reference to its value.
 *
 * SECURITY: Requires valid AK_CAP_SECRETS capability.
 * The capability's resource pattern must match the secret name.
 *
 * @param h         Heap for allocation
 * @param ref       Secret reference name (e.g., "OPENAI_API_KEY")
 * @param ref_len   Length of reference
 * @param cap       Capability authorizing access (may be NULL for internal use)
 * @return          Buffer containing secret value, or NULL on error
 */
buffer ak_secret_resolve(heap h, const char *ref, u64 ref_len,
                         ak_capability_t *cap);

/*
 * Check if capability grants access to a secret.
 *
 * @param cap       Capability to check
 * @param ref       Secret reference name
 * @param ref_len   Length of reference
 * @return          true if access is granted
 */
boolean ak_secret_check_cap(ak_capability_t *cap, const char *ref, u64 ref_len);

/* ============================================================
 * SECURITY UTILITIES
 * ============================================================ */

/* Securely clear a secret buffer (prevents compiler optimization) */
void ak_secret_clear(buffer b);

/* Get error message for last resolution failure */
const char *ak_secrets_last_error(void);

#endif /* AK_SECRETS_H */
