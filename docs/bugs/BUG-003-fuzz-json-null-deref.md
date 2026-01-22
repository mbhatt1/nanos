# BUG-003: Null Pointer Dereference in fuzz_json_parser.c

## Summary
Fuzz testing discovers a null pointer dereference in the JSON parser fuzzing harness at line 73.

## Severity
**Medium** - Affects fuzz test harness, indicates potential issue in JSON parsing logic.

## Environment
- OS: Ubuntu 22.04 (GitHub Actions runner)
- Compiler: clang with UndefinedBehaviorSanitizer (part of fuzzer build)
- Test: `test/fuzz/fuzz_json_parser.c`

## Reproduction
```bash
cd test/fuzz
make clean
make CC=clang
./fuzz_json_parser corpus/json/ -max_total_time=120
```

## Error Output
```
fuzz_json_parser.c:73:24: runtime error: load of null pointer of type 'const u8' (aka 'const unsigned char')
artifact_prefix='./'; Test unit written to ./crash-5474248ec9237191e08fe672d54fd348db33d07b
```

## Root Cause Analysis
Line 73 in `fuzz_json_parser.c` is in the `skip_ws` function:

```c
static const u8 *skip_ws(const u8 *p, const u8 *end) {
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
        p++;
    return p;
}
```

The issue occurs when `p` is NULL. The comparison `p < end` may evaluate to true (if `end` is also NULL or a small value), but then `*p` causes a null pointer dereference.

## Impact
- Fuzz tests fail in CI
- Indicates JSON parser may not handle edge cases properly
- Crash file preserved for reproduction

## Fix Required
Add null pointer check before dereferencing:

```c
static const u8 *skip_ws(const u8 *p, const u8 *end) {
    if (!p || !end)
        return p;
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
        p++;
    return p;
}
```

## Crash Reproduction File
The fuzzer saved the crashing input to:
`./crash-5474248ec9237191e08fe672d54fd348db33d07b`

This file can be used to reproduce and debug the issue:
```bash
./fuzz_json_parser ./crash-5474248ec9237191e08fe672d54fd348db33d07b
```

## References
- CI Run: https://github.com/mbhatt1/authority/actions/runs/21266022477
- File: `test/fuzz/fuzz_json_parser.c:73`
- Related: JSON parsing in Authority Kernel policy handling

## Status
**Open** - Fix required in fuzz harness and potentially in core JSON parser.
