# BUG-005: Stack Buffer Overflow in fuzz_path_canonicalize sockaddr Test

## Summary
Fuzz testing discovers a stack-buffer-overflow when testing sockaddr canonicalization with IPv6 addresses.

## Severity
**Low** - Affects fuzz test harness only, not production code.

## Environment
- OS: Ubuntu 22.04 (GitHub Actions runner)
- Compiler: clang with AddressSanitizer
- Test: `test/fuzz/fuzz_path_canonicalize.c`

## Reproduction
```bash
cd test/fuzz
make clean
make CC=clang
./fuzz_path_canonicalize corpus/path/ -max_total_time=60
```

## Error Output
```
AddressSanitizer: stack-buffer-overflow on address 0x7ffef20080f0
READ of size 1 at 0x7ffef20080f0 thread T0
    #0 0x55b49a305e7f in ak_canonicalize_sockaddr fuzz_path_canonicalize.c:336:26

[32, 48) 'addr' (line 382) <== Memory access at offset 48 overflows this variable
```

## Root Cause Analysis
The fuzz harness allocated a `struct sockaddr` which is only 16 bytes:

```c
struct sockaddr addr;
memset(&addr, 0, sizeof(addr));
```

However, for IPv6 addresses, the code needs 28 bytes (size of `struct sockaddr_in6`). The harness was:
1. Setting AF_INET6 when input size >= 28
2. Copying only `sizeof(addr)` (16 bytes) into the buffer
3. Passing `size` (>= 28) as the length to `ak_canonicalize_sockaddr`
4. The function then tried to read bytes 8-23 for the IPv6 address, reading past buffer end

## Impact
- Fuzz tests crash in CI
- Does not affect production code (the bug is in the test harness)

## Fix Applied
Use a 32-byte buffer that can accommodate both IPv4 and IPv6 addresses:

```c
uint8_t addr_buf[32];
memset(addr_buf, 0, sizeof(addr_buf));

size_t copy_len = size < sizeof(addr_buf) ? size : sizeof(addr_buf);
memcpy(addr_buf, data, copy_len);

struct sockaddr *addr = (struct sockaddr *)addr_buf;
```

Pass the actual copied length instead of the input size.

## References
- CI Run: https://github.com/mbhatt1/authority/actions/runs/21267546014
- File: `test/fuzz/fuzz_path_canonicalize.c:336`
- Fix commit: 8ffdf3f3

## Status
**Fixed** - Buffer size increased to accommodate IPv6 addresses.
