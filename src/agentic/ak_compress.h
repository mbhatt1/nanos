/*
 * Authority Kernel - Compression
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Provides LZ4 compression for state sync and audit logs.
 * LZ4 is chosen for its excellent speed/ratio tradeoff.
 *
 * Based on LZ4 by Yann Collet (BSD license).
 */

#ifndef AK_COMPRESS_H
#define AK_COMPRESS_H

#include "ak_types.h"

/* ============================================================
 * COMPRESSION
 * ============================================================ */

/*
 * Compress data using LZ4.
 *
 * Output format:
 *   [4 bytes: original size, little-endian]
 *   [compressed data...]
 *
 * @param h       Heap for allocation
 * @param input   Data to compress
 * @return        Compressed data, or NULL on failure
 */
buffer ak_compress_lz4(heap h, buffer input);

/*
 * Decompress LZ4 data.
 *
 * @param h               Heap for allocation
 * @param compressed      Compressed data (with size header)
 * @return                Decompressed data, or NULL on failure
 */
buffer ak_decompress_lz4(heap h, buffer compressed);

/*
 * Decompress LZ4 data with known original size.
 *
 * Use when original size is known from external source.
 *
 * @param h               Heap for allocation
 * @param compressed      Compressed data (without size header)
 * @param original_size   Expected decompressed size
 * @return                Decompressed data, or NULL on failure
 */
buffer ak_decompress_lz4_sized(heap h, buffer compressed, u64 original_size);

/* ============================================================
 * UTILITIES
 * ============================================================ */

/*
 * Calculate maximum compressed size for given input.
 *
 * Use to pre-allocate output buffer.
 *
 * @param input_size    Size of uncompressed data
 * @return              Maximum possible compressed size
 */
u64 ak_compress_bound(u64 input_size);

/*
 * Check if compression is worthwhile for given size.
 *
 * Very small inputs may expand when compressed.
 *
 * @param input_size    Size of data to compress
 * @return              true if compression is recommended
 */
boolean ak_compress_worthwhile(u64 input_size);

/* Minimum size to consider compression (smaller may expand) */
#define AK_COMPRESS_MIN_SIZE    64

/* Maximum decompression size (256MB) - protects against decompression bombs */
#define AK_DECOMPRESS_MAX_SIZE  (256ULL * 1024 * 1024)

/* Maximum compression ratio allowed (1024:1) - protects against malicious data */
#define AK_COMPRESS_MAX_RATIO   1024

/* Maximum size that can be stored in 32-bit header */
#define AK_COMPRESS_MAX_INPUT   0xFFFFFFFFULL

#endif /* AK_COMPRESS_H */
