# Authority Kernel Fuzz Testing

This directory contains fuzz targets for testing parser/decoder boundaries in the Authority Kernel.

## Overview

Fuzzing is critical for security-sensitive code like the Authority Kernel, where input parsing bugs could lead to:
- Policy bypass vulnerabilities
- Path traversal attacks
- Denial of service
- Memory corruption

## Fuzz Targets

### 1. `fuzz_json_parser.c`

Tests the JSON policy parser (`ak_policy_v2.c`) with:
- Malformed JSON
- Truncated input
- Deeply nested structures
- Large arrays/strings
- Special characters and escape sequences

### 2. `fuzz_pattern_match.c`

Tests the glob pattern matcher (`ak_pattern.c`) with:
- Pathological patterns (e.g., many `*` characters)
- Unicode and special characters
- Edge cases like empty patterns
- ReDoS-style attack patterns

### 3. `fuzz_path_canonicalize.c`

Tests path canonicalization (`ak_effects.c`) with:
- Path traversal attempts (`../../../etc/passwd`)
- Null byte injection
- Double slashes
- Mixed `.` and `..` components
- Very long paths

## Building

```bash
# Build all fuzz targets
make

# Build specific target
make fuzz_json_parser

# Build standalone debug versions (no fuzzer)
make standalone
```

Requirements:
- clang with libFuzzer support
- AddressSanitizer and UndefinedBehaviorSanitizer

## Running

### Quick Start

```bash
# Run all fuzzers for 60 seconds each
../tools/run-fuzz.sh

# Run specific fuzzer for 5 minutes
../tools/run-fuzz.sh -t 300 json

# Run with 4 parallel jobs
../tools/run-fuzz.sh -j 4 all
```

### Direct Execution

```bash
# Run JSON fuzzer
./fuzz_json_parser corpus/json/ -max_total_time=60

# Run with multiple jobs
./fuzz_json_parser corpus/json/ -jobs=4 -workers=4

# Run with specific seed
./fuzz_json_parser corpus/json/ -seed=12345
```

### Coverage-Guided Fuzzing

```bash
# Run with coverage and generate HTML report
../tools/run-fuzz.sh -c all
```

## Corpus Management

### Initial Seeds

The `corpus/` directory contains seed inputs organized by target:
- `corpus/json/` - JSON policy examples
- `corpus/pattern/` - Pattern matching test cases
- `corpus/path/` - Path canonicalization inputs

### Generating Corpus

```bash
make corpus
```

### Minimizing Corpus

```bash
# After fuzzing, minimize the corpus
make minimize
```

## Interpreting Results

### Crash Files

If a crash is found, a file like `crash-<hash>` is created. To reproduce:

```bash
./fuzz_json_parser crash-abc123
```

### Leak Files

Memory leaks are recorded in `leak-<hash>` files.

### Timeout Files

Inputs causing timeouts are saved as `timeout-<hash>`.

## Integration with CI

Add to your CI pipeline:

```yaml
fuzz_test:
  script:
    - cd test/fuzz
    - make
    - make corpus
    - ./fuzz_json_parser corpus/json/ -max_total_time=30
    - ./fuzz_pattern_match corpus/pattern/ -max_total_time=30
    - ./fuzz_path_canonicalize corpus/path/ -max_total_time=30
  artifacts:
    paths:
      - test/fuzz/crash-*
      - test/fuzz/leak-*
    when: on_failure
```

## Security Considerations

The fuzz targets are designed to catch:

1. **Memory Safety Issues**
   - Buffer overflows
   - Use-after-free
   - Uninitialized memory reads

2. **Logic Bugs**
   - Incorrect parsing
   - Pattern matching bypasses
   - Path traversal vulnerabilities

3. **Resource Exhaustion**
   - Exponential backtracking (ReDoS)
   - Excessive memory allocation
   - Infinite loops

## Adding New Fuzz Targets

1. Create `fuzz_<target>.c` implementing `LLVMFuzzerTestOneInput`
2. Add target to `Makefile`
3. Create seed corpus in `corpus/<target>/`
4. Update this README
