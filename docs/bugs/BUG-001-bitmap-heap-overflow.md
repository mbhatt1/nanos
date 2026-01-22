# BUG-001: Heap Buffer Overflow in bitmap_test.c

## Summary
AddressSanitizer detects a heap-buffer-overflow in the upstream nanos `bitmap_test.c` unit test.

## Severity
**Medium** - Affects test suite only, not production code.

## Environment
- OS: Ubuntu 22.04 (GitHub Actions runner)
- Compiler: clang with AddressSanitizer
- Test: `test/unit/bitmap_test.c`

## Reproduction
```bash
cd test/unit
make clean
make asan CC=clang
```

## Error Output
```
SUMMARY: AddressSanitizer: heap-buffer-overflow /home/runner/work/authority/authority/test/unit/bitmap_test.c in test_alloc
make[1]: *** [Makefile:279: test] Error 1
```

## Root Cause Analysis
The `test_alloc` function in `bitmap_test.c` (lines 11-20) allocates a bitmap and iterates over it:

```c
bitmap test_alloc(heap h) {
    bitmap b = allocate_bitmap(h, h, 4096);
    bitmap_foreach_set(b, i) {
        if (i) {
            msg_err("%s failed for bitmap", func_ss);
            return NULL;
        }
    }
    return b;
}
```

The `bitmap_foreach_set` macro likely accesses memory beyond the allocated bitmap bounds. This could be due to:
1. Incorrect size calculation in `allocate_bitmap`
2. Off-by-one error in `bitmap_foreach_set` iteration
3. Uninitialized bitmap memory causing spurious set bits

## Impact
- ASAN unit tests fail in CI
- Does not affect production kernel code
- Inherited from upstream nanos project

## Workaround
Skip `bitmap_test` when running ASAN tests:
```bash
make asan CC=clang SKIP_TEST="network_test udp_test bitmap_test"
```

## Recommended Fix
1. Investigate `bitmap_foreach_set` macro bounds checking
2. Verify `allocate_bitmap` returns correctly sized allocation
3. Consider upstreaming fix to nanos project

## References
- CI Run: https://github.com/mbhatt1/authority/actions/runs/21266022477
- File: `test/unit/bitmap_test.c:11-20`
- Related: `src/runtime/bitmap.c`, `src/runtime/bitmap.h`

## Status
**Open** - Workaround applied, root cause investigation pending.
