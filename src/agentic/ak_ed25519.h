/*
 * Authority Kernel - Ed25519 Signature Verification
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Provides Ed25519 signature verification for WASM module signing.
 * Based on TweetNaCl (public domain) - minimal, auditable implementation.
 *
 * SECURITY: Only verification is implemented - no signing in kernel.
 * Private keys should never be in the kernel.
 */

#ifndef AK_ED25519_H
#define AK_ED25519_H

#include "ak_types.h"

/* ============================================================
 * CONSTANTS
 * ============================================================ */

#define AK_ED25519_PUBLIC_KEY_SIZE  32
#define AK_ED25519_SIGNATURE_SIZE   64
#define AK_ED25519_MAX_TRUSTED_KEYS 16

/* ============================================================
 * SIGNATURE VERIFICATION
 * ============================================================ */

/*
 * Verify Ed25519 signature.
 *
 * @param message      Message that was signed
 * @param message_len  Length of message
 * @param signature    64-byte signature
 * @param public_key   32-byte public key
 * @return             true if signature is valid
 */
boolean ak_ed25519_verify(const u8 *message, u64 message_len,
                          const u8 *signature,
                          const u8 *public_key);

/* ============================================================
 * TRUSTED KEY MANAGEMENT
 * ============================================================ */

/*
 * Add a trusted public key for WASM module verification.
 *
 * Keys are typically loaded at boot from configuration.
 *
 * @param public_key   32-byte Ed25519 public key
 * @param name         Human-readable name for the key
 * @return             true if key was added
 */
boolean ak_ed25519_add_trusted_key(const u8 *public_key, const char *name);

/*
 * Check if a public key is in the trusted set.
 *
 * @param public_key   32-byte public key to check
 * @return             true if key is trusted
 */
boolean ak_ed25519_is_trusted(const u8 *public_key);

/*
 * Remove a trusted key (for key rotation).
 *
 * @param public_key   32-byte public key to remove
 * @return             true if key was found and removed
 */
boolean ak_ed25519_remove_trusted_key(const u8 *public_key);

/*
 * Get count of trusted keys.
 */
u32 ak_ed25519_trusted_key_count(void);

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

/* Initialize Ed25519 subsystem */
void ak_ed25519_init(heap h);

#endif /* AK_ED25519_H */
