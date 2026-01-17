/*
 * Authority Kernel - LZ4 Compression Implementation
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * LZ4 compression/decompression for kernel use.
 * Based on LZ4 by Yann Collet (BSD license).
 *
 * This is a simplified implementation optimized for correctness
 * and minimal dependencies rather than maximum speed.
 */

#include "ak_compress.h"
#include "ak_compat.h"

/* ============================================================
 * LZ4 CONSTANTS
 * ============================================================ */

#define LZ4_HASHLOG             12
#define LZ4_HASHTABLESIZE       (1 << LZ4_HASHLOG)
#define LZ4_MINMATCH            4
#define LZ4_MFLIMIT             12
#define LZ4_LASTLITERALS        5
#define LZ4_MAX_INPUT_SIZE      0x7E000000

/* ============================================================
 * INTERNAL HELPERS
 * ============================================================ */

static u32 lz4_hash(u32 sequence)
{
    return (sequence * 2654435761U) >> (32 - LZ4_HASHLOG);
}

static u32 read32(const u8 *p)
{
    return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
}

static void write32(u8 *p, u32 v)
{
    p[0] = v & 0xff;
    p[1] = (v >> 8) & 0xff;
    p[2] = (v >> 16) & 0xff;
    p[3] = (v >> 24) & 0xff;
}

static u64 count_match(const u8 *p1, const u8 *p2, const u8 *limit)
{
    const u8 *start = p1;
    while (p1 < limit - 7) {
        u64 diff = read32(p1) ^ read32(p2);
        diff |= ((u64)read32(p1 + 4) ^ (u64)read32(p2 + 4)) << 32;
        if (diff) {
            /* Find first different byte */
            int pos = 0;
            while (pos < 8 && p1[pos] == p2[pos])
                pos++;
            return (p1 - start) + pos;
        }
        p1 += 8;
        p2 += 8;
    }
    while (p1 < limit && *p1 == *p2) {
        p1++;
        p2++;
    }
    return p1 - start;
}

/* ============================================================
 * COMPRESSION
 * ============================================================ */

buffer ak_compress_lz4(heap h, buffer input)
{
    if (!input)
        return 0;

    u64 src_len = buffer_length(input);
    if (src_len == 0) {
        /* Empty input -> just the size header */
        buffer out = allocate_buffer(h, 4);
        if (out == INVALID_ADDRESS)
            return 0;
        u8 hdr[4] = {0, 0, 0, 0};
        buffer_write(out, hdr, 4);
        return out;
    }

    if (src_len > LZ4_MAX_INPUT_SIZE)
        return 0;

    /* Check for integer truncation - header only supports 32-bit sizes */
    if (src_len > AK_COMPRESS_MAX_INPUT)
        return 0;

    u64 max_dst = ak_compress_bound(src_len);
    buffer output = allocate_buffer(h, max_dst + 4);
    if (output == INVALID_ADDRESS)
        return 0;

    /* Write original size header (little-endian) */
    u8 size_hdr[4];
    write32(size_hdr, (u32)src_len);  /* Safe: checked src_len <= UINT32_MAX above */
    buffer_write(output, size_hdr, 4);

    const u8 *src = buffer_ref(input, 0);
    const u8 *src_end = src + src_len;
    const u8 *match_limit = src_end - LZ4_LASTLITERALS;
    const u8 *mflimit = src_end - LZ4_MFLIMIT;

    /* Hash table for finding matches */
    u32 hash_table[LZ4_HASHTABLESIZE];
    runtime_memset((u8 *)hash_table, 0, sizeof(hash_table));

    const u8 *anchor = src;
    const u8 *ip = src;

    /* First byte - bounds check: need at least 4 bytes for read32 */
    if (src_len >= LZ4_MINMATCH && ip + 4 <= src_end) {
        hash_table[lz4_hash(read32(ip))] = 0;
        ip++;
    }

    /* Main loop */
    while (ip < mflimit) {
        /* Bounds check: ensure we can safely read 4 bytes for hash */
        if (ip + 4 > src_end)
            break;

        /* Find match */
        u32 h = lz4_hash(read32(ip));
        u32 ref_idx = hash_table[h];
        hash_table[h] = ip - src;

        const u8 *ref = src + ref_idx;

        /* Bounds check: ensure ref is valid and we can read from it */
        if (ref + 4 > src_end)
            ref_idx = 0;  /* Invalidate match if ref would read past buffer */

        /* Check if match is valid */
        if (ref_idx > 0 &&
            ip - ref < 65535 &&
            ref + 4 <= src_end &&  /* Additional bounds check for read32(ref) */
            read32(ref) == read32(ip)) {

            /* Found match - write literals */
            u64 lit_len = ip - anchor;
            u64 match_len = LZ4_MINMATCH + count_match(ip + LZ4_MINMATCH,
                                                        ref + LZ4_MINMATCH,
                                                        match_limit);

            /* Encode token */
            u8 token = ((lit_len >= 15 ? 15 : lit_len) << 4) |
                       (match_len - LZ4_MINMATCH >= 15 ? 15 : match_len - LZ4_MINMATCH);
            push_u8(output, token);

            /* Encode literal length overflow */
            if (lit_len >= 15) {
                u64 l = lit_len - 15;
                while (l >= 255) {
                    push_u8(output, 255);
                    l -= 255;
                }
                push_u8(output, (u8)l);
            }

            /* Copy literals */
            if (lit_len > 0)
                buffer_write(output, anchor, lit_len);

            /* Encode offset (little-endian) */
            u16 offset = ip - ref;
            push_u8(output, offset & 0xff);
            push_u8(output, (offset >> 8) & 0xff);

            /* Encode match length overflow */
            if (match_len - LZ4_MINMATCH >= 15) {
                u64 l = match_len - LZ4_MINMATCH - 15;
                while (l >= 255) {
                    push_u8(output, 255);
                    l -= 255;
                }
                push_u8(output, (u8)l);
            }

            ip += match_len;
            anchor = ip;

            /* Update hash for positions in match - with bounds check */
            if (ip < mflimit && ip - 2 >= src && ip + 2 <= src_end) {
                hash_table[lz4_hash(read32(ip - 2))] = (ip - 2) - src;
            }
        } else {
            ip++;
        }
    }

    /* Encode remaining literals */
    u64 lit_len = src_end - anchor;
    u8 token = (lit_len >= 15 ? 15 : lit_len) << 4;
    push_u8(output, token);

    if (lit_len >= 15) {
        u64 l = lit_len - 15;
        while (l >= 255) {
            push_u8(output, 255);
            l -= 255;
        }
        push_u8(output, (u8)l);
    }

    if (lit_len > 0)
        buffer_write(output, anchor, lit_len);

    return output;
}

/* ============================================================
 * DECOMPRESSION
 * ============================================================ */

buffer ak_decompress_lz4(heap h, buffer compressed)
{
    if (!compressed || buffer_length(compressed) < 4)
        return 0;

    /* Read original size from header */
    const u8 *data = buffer_ref(compressed, 0);
    u32 original_size = read32(data);

    if (original_size == 0) {
        return allocate_buffer(h, 0);
    }

    /* Decompression bomb protection: check max size limit (256MB) */
    if (original_size > AK_DECOMPRESS_MAX_SIZE)
        return 0;

    /* Ratio check: compressed data (minus 4-byte header) vs decompressed */
    u64 compressed_len = buffer_length(compressed) - 4;
    if (compressed_len > 0 && (u64)original_size / compressed_len > AK_COMPRESS_MAX_RATIO)
        return 0;

    /* Create view of compressed data without header */
    buffer compressed_data = allocate_buffer(h, buffer_length(compressed) - 4);
    if (compressed_data == INVALID_ADDRESS)
        return 0;

    buffer_write(compressed_data, data + 4, buffer_length(compressed) - 4);

    buffer result = ak_decompress_lz4_sized(h, compressed_data, original_size);

    deallocate_buffer(compressed_data);
    return result;
}

buffer ak_decompress_lz4_sized(heap h, buffer compressed, u64 original_size)
{
    if (!compressed)
        return 0;

    if (original_size == 0)
        return allocate_buffer(h, 0);

    /* Decompression bomb protection: check max size limit (256MB) */
    if (original_size > AK_DECOMPRESS_MAX_SIZE)
        return 0;

    /* Ratio check: verify compression ratio is reasonable (max 1024:1) */
    u64 compressed_len = buffer_length(compressed);
    if (compressed_len > 0 && original_size / compressed_len > AK_COMPRESS_MAX_RATIO)
        return 0;

    buffer output = allocate_buffer(h, original_size);
    if (output == INVALID_ADDRESS)
        return 0;

    const u8 *src = buffer_ref(compressed, 0);
    u64 src_len = buffer_length(compressed);
    const u8 *src_end = src + src_len;

    u8 *dst = buffer_ref(output, 0);
    u8 *dst_end = dst + original_size;
    u8 *op = dst;

    while (src < src_end && op < dst_end) {
        /* Read token */
        u8 token = *src++;
        u64 lit_len = token >> 4;
        u64 match_len = (token & 0x0F) + LZ4_MINMATCH;

        /* Read literal length overflow */
        if (lit_len == 15) {
            u8 s;
            do {
                if (src >= src_end)
                    goto error;
                s = *src++;
                /* Overflow check: prevent wrap-around */
                if (lit_len > UINT64_MAX - s)
                    goto error;
                lit_len += s;
            } while (s == 255);
        }

        /* Copy literals */
        if (lit_len > 0) {
            if (src + lit_len > src_end || op + lit_len > dst_end)
                goto error;
            runtime_memcpy(op, src, lit_len);
            src += lit_len;
            op += lit_len;
        }

        /* Check if we're done (last literals have no match) */
        if (src >= src_end)
            break;

        /* Read offset */
        if (src + 2 > src_end)
            goto error;
        u16 offset = src[0] | (src[1] << 8);
        src += 2;

        if (offset == 0 || offset > (u64)(op - dst))
            goto error;

        const u8 *match = op - offset;

        /* Read match length overflow */
        if ((token & 0x0F) == 15) {
            u8 s;
            do {
                if (src >= src_end)
                    goto error;
                s = *src++;
                /* Overflow check: prevent wrap-around */
                if (match_len > UINT64_MAX - s)
                    goto error;
                match_len += s;
            } while (s == 255);
        }

        /* Copy match */
        if (op + match_len > dst_end)
            goto error;

        /* Handle overlapping copies */
        if (offset < match_len) {
            while (match_len--) {
                *op++ = *match++;
            }
        } else {
            runtime_memcpy(op, match, match_len);
            op += match_len;
        }
    }

    /* Verify we got expected output */
    if ((u64)(op - dst) != original_size)
        goto error;

    buffer_produce(output, original_size);
    return output;

error:
    deallocate_buffer(output);
    return 0;
}

/* ============================================================
 * UTILITIES
 * ============================================================ */

u64 ak_compress_bound(u64 input_size)
{
    /* LZ4 worst case: input_size + (input_size / 255) + 16 */
    u64 extra = input_size / 255;
    /* Overflow check: saturate to UINT64_MAX on overflow */
    if (input_size > UINT64_MAX - extra)
        return UINT64_MAX;
    u64 sum = input_size + extra;
    if (sum > UINT64_MAX - 16)
        return UINT64_MAX;
    return sum + 16;
}

boolean ak_compress_worthwhile(u64 input_size)
{
    return input_size >= AK_COMPRESS_MIN_SIZE;
}
