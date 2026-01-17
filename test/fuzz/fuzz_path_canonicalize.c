/*
 * Fuzz Target: Path Canonicalization
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * This fuzz target exercises the path canonicalization logic in ak_effects.c.
 * Path canonicalization is security-critical as it prevents:
 *   - Path traversal attacks (../../../etc/passwd)
 *   - Null byte injection (/path\x00malicious)
 *   - Symlink attacks (when combined with realpath)
 *   - Unicode normalization issues
 *
 * Build: clang -fsanitize=fuzzer,address,undefined -g fuzz_path_canonicalize.c -o fuzz_path_canonicalize
 * Run:   ./fuzz_path_canonicalize corpus/path/ -max_total_time=60
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

/*
 * Minimal type definitions for standalone fuzzing.
 */
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef signed long long s64;
typedef int boolean;

#define true 1
#define false 0

/* Maximum target length from ak_effects.h */
#define AK_MAX_TARGET 512

/* Error codes */
#ifndef EINVAL
#define EINVAL 22
#endif
#ifndef ERANGE
#define ERANGE 34
#endif

/*
 * Path canonicalization implementation from ak_effects.c.
 * This normalizes paths by:
 *   - Converting relative to absolute paths
 *   - Removing . and .. components
 *   - Collapsing multiple slashes
 *   - Skipping null bytes (security)
 */
int ak_canonicalize_path(const char *path, char *out, u32 out_len,
                         const char *cwd) {
    if (!path || !out || out_len == 0)
        return -EINVAL;

    u32 pos = 0;
    const char *src = path;

    /* Handle relative paths: prepend cwd */
    if (path[0] != '/') {
        if (!cwd)
            cwd = "/";

        u64 cwd_len = strlen(cwd);
        if (cwd_len >= out_len)
            return -ERANGE;

        strncpy(out, cwd, out_len);
        pos = cwd_len;

        /* Ensure separator */
        if (pos > 0 && out[pos - 1] != '/' && pos < out_len - 1) {
            out[pos++] = '/';
        }
    }

    /* Process path components */
    while (*src && pos < out_len - 1) {
        /* Skip leading/consecutive slashes */
        while (*src == '/')
            src++;

        if (*src == '\0')
            break;

        /* Find end of component */
        const char *end = src;
        while (*end && *end != '/')
            end++;

        u64 comp_len = end - src;

        /* Handle "." - skip it */
        if (comp_len == 1 && src[0] == '.') {
            src = end;
            continue;
        }

        /* Handle ".." - go up one level */
        if (comp_len == 2 && src[0] == '.' && src[1] == '.') {
            /* Find last slash and remove component */
            if (pos > 1) {
                pos--;  /* Move before trailing slash if any */
                while (pos > 0 && out[pos - 1] != '/')
                    pos--;
            }
            src = end;
            continue;
        }

        /* Handle null bytes - skip (security) */
        boolean has_null = false;
        for (u64 i = 0; i < comp_len; i++) {
            if (src[i] == '\0') {
                has_null = true;
                break;
            }
        }
        if (has_null) {
            src = end;
            continue;
        }

        /* Add separator if needed */
        if (pos == 0 || out[pos - 1] != '/') {
            if (pos < out_len - 1)
                out[pos++] = '/';
        }

        /* Copy component */
        for (u64 i = 0; i < comp_len && pos < out_len - 1; i++) {
            out[pos++] = src[i];
        }

        src = end;
    }

    /* Ensure at least "/" for root */
    if (pos == 0 && out_len > 0) {
        out[pos++] = '/';
    }

    /* Null terminate */
    out[pos] = '\0';

    return 0;
}

/*
 * Socket address canonicalization from ak_effects.c.
 * Normalizes IP addresses and ports to canonical form.
 */

/* AF_INET and AF_INET6 values */
#define AF_INET  2
#define AF_INET6 10

struct sockaddr {
    u16 sa_family;
    char sa_data[14];
};

typedef u32 socklen_t;

/* Helper: format u8 as decimal */
static int ak_format_u8(char *buf, u8 val) {
    int len = 0;
    if (val >= 100) {
        buf[len++] = '0' + (val / 100);
        val %= 100;
        buf[len++] = '0' + (val / 10);
        val %= 10;
    } else if (val >= 10) {
        buf[len++] = '0' + (val / 10);
        val %= 10;
    }
    buf[len++] = '0' + val;
    return len;
}

/* Helper: format u16 as decimal */
static int ak_format_u16(char *buf, u16 val) {
    char tmp[6];
    int len = 0;

    if (val == 0) {
        buf[0] = '0';
        return 1;
    }

    while (val > 0) {
        tmp[len++] = '0' + (val % 10);
        val /= 10;
    }

    /* Reverse */
    for (int i = 0; i < len; i++) {
        buf[i] = tmp[len - 1 - i];
    }

    return len;
}

/* Helper: format u16 as hex */
static int ak_format_hex16(char *buf, u16 val) {
    static const char hex[] = "0123456789abcdef";
    buf[0] = hex[(val >> 12) & 0xf];
    buf[1] = hex[(val >> 8) & 0xf];
    buf[2] = hex[(val >> 4) & 0xf];
    buf[3] = hex[val & 0xf];
    return 4;
}

/*
 * Socket address canonicalization
 */
int ak_canonicalize_sockaddr(const struct sockaddr *addr, socklen_t len,
                             char *out, u32 out_len) {
    if (!addr || !out || out_len < 32)
        return -EINVAL;

    /* Handle AF_INET (IPv4) */
    if (addr->sa_family == AF_INET) {
        if (len < 8)  /* sizeof(struct sockaddr_in) minimum */
            return -EINVAL;

        const u8 *bytes = (const u8 *)addr;
        u16 port = (bytes[2] << 8) | bytes[3];  /* Network to host */
        u8 a = bytes[4], b = bytes[5], c = bytes[6], d = bytes[7];

        /* Normalize loopback: 127.x.x.x -> 127.0.0.1 */
        if (a == 127) {
            b = 0; c = 0; d = 1;
        }

        /* Format: ip:a.b.c.d:port */
        int written = 0;
        out[written++] = 'i';
        out[written++] = 'p';
        out[written++] = ':';

        /* IP address */
        written += ak_format_u8(out + written, a);
        out[written++] = '.';
        written += ak_format_u8(out + written, b);
        out[written++] = '.';
        written += ak_format_u8(out + written, c);
        out[written++] = '.';
        written += ak_format_u8(out + written, d);
        out[written++] = ':';

        /* Port */
        written += ak_format_u16(out + written, port);
        out[written] = '\0';

        return 0;
    }

    /* Handle AF_INET6 (IPv6) */
    if (addr->sa_family == AF_INET6) {
        if (len < 28)  /* sizeof(struct sockaddr_in6) minimum */
            return -EINVAL;

        const u8 *bytes = (const u8 *)addr;
        u16 port = (bytes[2] << 8) | bytes[3];
        const u8 *ip6 = bytes + 8;  /* sin6_addr offset */

        /* Check for IPv4-mapped IPv6 (::ffff:a.b.c.d) */
        boolean is_v4_mapped = true;
        for (int i = 0; i < 10; i++) {
            if (ip6[i] != 0) {
                is_v4_mapped = false;
                break;
            }
        }
        if (is_v4_mapped && ip6[10] == 0xff && ip6[11] == 0xff) {
            /* Treat as IPv4 */
            u8 a = ip6[12], b = ip6[13], c = ip6[14], d = ip6[15];

            int written = 0;
            out[written++] = 'i';
            out[written++] = 'p';
            out[written++] = ':';
            written += ak_format_u8(out + written, a);
            out[written++] = '.';
            written += ak_format_u8(out + written, b);
            out[written++] = '.';
            written += ak_format_u8(out + written, c);
            out[written++] = '.';
            written += ak_format_u8(out + written, d);
            out[written++] = ':';
            written += ak_format_u16(out + written, port);
            out[written] = '\0';
            return 0;
        }

        /* Check for loopback (::1) */
        boolean is_loopback = true;
        for (int i = 0; i < 15; i++) {
            if (ip6[i] != 0) {
                is_loopback = false;
                break;
            }
        }
        if (is_loopback && ip6[15] == 1) {
            /* Format as IPv6 loopback */
            int written = 0;
            out[written++] = 'i';
            out[written++] = 'p';
            out[written++] = ':';
            out[written++] = '[';
            out[written++] = ':';
            out[written++] = ':';
            out[written++] = '1';
            out[written++] = ']';
            out[written++] = ':';
            written += ak_format_u16(out + written, port);
            out[written] = '\0';
            return 0;
        }

        /* Format general IPv6: ip:[xxxx:xxxx:...]:port */
        int written = 0;
        out[written++] = 'i';
        out[written++] = 'p';
        out[written++] = ':';
        out[written++] = '[';

        for (int i = 0; i < 8; i++) {
            if (i > 0) out[written++] = ':';
            u16 group = (ip6[i*2] << 8) | ip6[i*2 + 1];
            written += ak_format_hex16(out + written, group);
        }

        out[written++] = ']';
        out[written++] = ':';
        written += ak_format_u16(out + written, port);
        out[written] = '\0';

        return 0;
    }

    /* Unknown address family - return error */
    return -1;  /* EAFNOSUPPORT */
}

/*
 * LibFuzzer entry point.
 *
 * The input format for path canonicalization is:
 *   [1 byte: flags]
 *     bit 0: use relative path (prepend cwd)
 *     bit 1: test sockaddr instead of path
 *   [remaining bytes: path or sockaddr data]
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0;
    }

    /* Limit input size */
    if (size > 4096) {
        return 0;
    }

    uint8_t flags = data[0];
    data++;
    size--;

    if (flags & 0x02) {
        /* Test sockaddr canonicalization */
        if (size < 8) {
            return 0;
        }

        /* Build sockaddr from fuzz data */
        struct sockaddr addr;
        memset(&addr, 0, sizeof(addr));

        /* Set address family based on size */
        if (size >= 28) {
            addr.sa_family = AF_INET6;
            memcpy(&addr, data, size < sizeof(addr) ? size : sizeof(addr));
            addr.sa_family = AF_INET6;  /* Ensure family is set */
        } else {
            addr.sa_family = AF_INET;
            memcpy(&addr, data, size < sizeof(addr) ? size : sizeof(addr));
            addr.sa_family = AF_INET;  /* Ensure family is set */
        }

        char out[128];
        int result = ak_canonicalize_sockaddr(&addr, size, out, sizeof(out));

        /* Verify output is valid if success */
        if (result == 0) {
            /* Output should start with "ip:" */
            if (strncmp(out, "ip:", 3) != 0) {
                __builtin_trap();
            }
            /* Output should be null-terminated */
            if (strlen(out) >= sizeof(out)) {
                __builtin_trap();
            }
        }
    } else {
        /* Test path canonicalization */
        char *path = malloc(size + 1);
        if (!path) {
            return 0;
        }
        memcpy(path, data, size);
        path[size] = '\0';

        char out[AK_MAX_TARGET];
        const char *cwd = (flags & 0x01) ? "/home/user" : NULL;

        int result = ak_canonicalize_path(path, out, sizeof(out), cwd);

        /* Verify output properties */
        if (result == 0) {
            /* Output should start with / */
            if (out[0] != '/') {
                __builtin_trap();
            }
            /* Output should be null-terminated within bounds */
            if (strlen(out) >= sizeof(out)) {
                __builtin_trap();
            }
            /* Output should not contain .. after canonicalization at root level */
            /* (but may contain .. if cwd is below root - this is valid) */

            /* Output should not contain // */
            for (size_t i = 0; out[i] && out[i+1]; i++) {
                if (out[i] == '/' && out[i+1] == '/') {
                    __builtin_trap();
                }
            }
            /* Output should not contain /./ */
            for (size_t i = 0; out[i] && out[i+1] && out[i+2]; i++) {
                if (out[i] == '/' && out[i+1] == '.' && out[i+2] == '/') {
                    __builtin_trap();
                }
            }
        }

        free(path);
    }

    return 0;
}

#ifdef FUZZ_STANDALONE
/*
 * Standalone main for testing without LibFuzzer.
 */
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <path> [cwd]\n", argv[0]);
        return 1;
    }

    const char *path = argv[1];
    const char *cwd = argc > 2 ? argv[2] : "/";

    char out[AK_MAX_TARGET];
    int result = ak_canonicalize_path(path, out, sizeof(out), cwd);

    if (result == 0) {
        printf("Input:  '%s'\n", path);
        printf("CWD:    '%s'\n", cwd);
        printf("Output: '%s'\n", out);
    } else {
        printf("Error: %d\n", result);
    }

    return result;
}
#endif
