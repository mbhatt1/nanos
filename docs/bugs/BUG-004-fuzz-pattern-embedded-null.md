# BUG-004: Pattern Match Fuzzer Crash on Embedded Null Bytes

## Summary
Fuzz testing triggers `__builtin_trap()` in fuzz_pattern_match.c when inputs contain embedded null bytes.

## Severity
**Low** - Affects fuzz test harness only, not production code.

## Environment
- OS: Ubuntu 22.04 (GitHub Actions runner)
- Compiler: clang with LibFuzzer
- Test: `test/fuzz/fuzz_pattern_match.c`

## Reproduction
```bash
cd test/fuzz
make clean
make CC=clang
./fuzz_pattern_match corpus/pattern/ -max_total_time=60
```

## Error Output
```
==2809== ERROR: libFuzzer: deadly signal
artifact_prefix='./'; Test unit written to ./crash-c806863794adb11f263168f0ec440235046475d2
```

## Root Cause Analysis
The fuzz harness compared results from two different pattern matching APIs:
1. `ak_pattern_match(pattern, string)` - uses `strlen()` to get length
2. `ak_pattern_match_n(pattern, sep, string, size - 1 - sep)` - uses explicit buffer length

When the fuzzer generates inputs with embedded null bytes, `strlen()` stops at the first null while the explicit length includes bytes after the null. This causes different matching results, triggering the consistency check `__builtin_trap()`.

## Impact
- Fuzz tests fail in CI
- False positive crash detection
- Does not affect actual pattern matching logic

## Fix Applied
Calculate actual string lengths using `strlen()` for both API calls to ensure consistent behavior:

```c
size_t actual_pattern_len = strlen(pattern);
size_t actual_string_len = strlen(string);

boolean result1 = ak_pattern_match(pattern, string);
boolean result2 = ak_pattern_match_n(pattern, actual_pattern_len,
                                      string, actual_string_len);
```

Also added null check to `local_strlen` for defensive programming.

## References
- CI Run: https://github.com/mbhatt1/authority/actions/runs/21266022477
- File: `test/fuzz/fuzz_pattern_match.c`
- Fix commit: 2283d4cd

## Status
**Fixed** - Embedded null handling corrected in fuzz_pattern_match.c.
