# Bug Checklist - Security Audit Findings

## Agents A10+A11 (Security Hardeners) - Security Vulnerability Report

**Date:** 2026-01-16
**Target Files:** ak_posix_route.c, ak_effects.c, ak_nanos.c, ak_policy_v2.c, ak_wasm_host.c

---

## Summary

| Severity | Count | Description |
|----------|-------|-------------|
| S0 (Critical) | 2 | User/kernel boundary, Integer overflow |
| S1 (High) | 4 | Path traversal edge cases, TOCTOU, Input validation |
| S2 (Medium) | 3 | Missing bounds checks, escape sequence handling |

---

## S0 - Security Critical Findings

### S0-1: Missing User-Space Pointer Validation in ak_nanos.c

**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_nanos.c`
**Lines:** 118-139, 186-187

**Description:**
The syscall handler copies data from user-space pointers without proper validation that the memory is actually mapped and accessible. The comment says "SECURITY: This copy validates the pointer" but `runtime_memcpy` does NOT validate user pointers - it just copies blindly.

**Vulnerable Code:**
```c
u8 *req_buf = (u8 *)arg0;
u64 req_len = arg1;
// ...
/* Copy from user space */
/* SECURITY: This copy validates the pointer */
runtime_memcpy(buffer_ref(req_data, 0), req_buf, req_len);  // NO VALIDATION!
```

**Impact:**
- Kernel memory disclosure (read from kernel addresses)
- Kernel memory corruption (write to kernel addresses)
- Privilege escalation

**Fix:**
```c
/* Validate user-space pointer before copy */
if (!validate_user_memory(req_buf, req_len, false))  // read access
    return -EFAULT;
if (!validate_user_memory(res_buf, res_max, true))   // write access
    return -EFAULT;

/* Now safe to copy */
if (!copy_from_user(buffer_ref(req_data, 0), req_buf, req_len))
    return -EFAULT;
```

**Negative Test:**
```c
void test_invalid_user_pointer(void) {
    // Should return -EFAULT, not crash
    assert(ak_syscall_handler(AK_SYS_READ, 0xFFFF800000000000, 100,
                              valid_buf, 256, 0, 0) == -EFAULT);
    assert(ak_syscall_handler(AK_SYS_READ, NULL, 100,
                              valid_buf, 256, 0, 0) == -EINVAL);
}
```

---

### S0-2: Integer Overflow in parse_number() - ak_policy_v2.c

**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_policy_v2.c`
**Lines:** 204-211

**Description:**
The `parse_number` function does not check for integer overflow when parsing numbers. A malicious policy JSON could provide extremely large numbers that overflow u64.

**Vulnerable Code:**
```c
static const u8 *parse_number(const u8 *p, const u8 *end, u64 *out)
{
    *out = 0;
    while (p < end && *p >= '0' && *p <= '9') {
        *out = (*out * 10) + (*p - '0');  // NO OVERFLOW CHECK!
        p++;
    }
    return p;
}
```

**Impact:**
- Budget limits can wrap around (e.g., max_tokens wrapping to 0)
- Denial of service or policy bypass

**Fix:**
```c
static const u8 *parse_number(const u8 *p, const u8 *end, u64 *out)
{
    *out = 0;
    while (p < end && *p >= '0' && *p <= '9') {
        u64 digit = *p - '0';
        /* Check for overflow before multiplication */
        if (*out > (UINT64_MAX - digit) / 10) {
            *out = UINT64_MAX;  /* Saturate instead of wrap */
            /* Skip remaining digits */
            while (p < end && *p >= '0' && *p <= '9') p++;
            return p;
        }
        *out = (*out * 10) + digit;
        p++;
    }
    return p;
}
```

**Negative Test:**
```c
void test_number_overflow(void) {
    const char *huge_num = "99999999999999999999999999999999";
    u64 result;
    parse_number((const u8*)huge_num, (const u8*)huge_num + strlen(huge_num), &result);
    assert(result == UINT64_MAX);  // Should saturate, not wrap
}
```

---

## S1 - High Severity Findings

### S1-1: Path Traversal - ".." Handling Allows Escape Above CWD

**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_effects.c`
**Lines:** 238-248

**Description:**
The `ak_canonicalize_path` function handles ".." by going up one directory level, but it can escape above the intended root when the path starts with `../` components. The code only prevents going above position 0, but a relative path like `../../../../etc/passwd` with cwd `/tmp/sandbox` can escape.

**Vulnerable Code:**
```c
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
```

**Impact:**
- Relative path `../../../etc/passwd` with cwd `/var/tmp` canonicalizes to `/etc/passwd`
- This allows escaping intended sandbox directories

**Fix:**
```c
/* Handle ".." - go up one level, but never above initial cwd */
if (comp_len == 2 && src[0] == '.' && src[1] == '.') {
    /* Track minimum position (initial cwd length) to prevent escape */
    u32 min_pos = cwd ? runtime_strlen(cwd) : 1;
    if (pos > min_pos) {
        pos--;
        while (pos > min_pos && out[pos - 1] != '/')
            pos--;
    }
    src = end;
    continue;
}
```

**Negative Test:**
```c
void test_path_traversal_escape(void) {
    char out[512];
    ak_canonicalize_path("../../../etc/passwd", out, sizeof(out), "/var/sandbox");
    // Should NOT result in /etc/passwd - should stay within /var/sandbox
    assert(strncmp(out, "/var/sandbox", 12) == 0 || strcmp(out, "/") == 0);
}
```

---

### S1-2: TOCTOU in ak_wasm_host.c Path Validation

**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_wasm_host.c`
**Lines:** 260-284

**Description:**
File paths are validated via capability check but then the path string is used later for actual filesystem access. Between validation and use, the path buffer could theoretically change (if in shared memory).

**Vulnerable Code:**
```c
s64 ak_host_fs_read(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result)
{
    // ... parse path ...
    runtime_memcpy(path_buf, path, path_len);  // Copy path
    path_buf[path_len] = 0;

    s64 cap_result = validate_host_cap(ctx, AK_CAP_FS, path_buf, "read");  // Validate
    if (cap_result != 0)
        return cap_result;

    // TIME WINDOW - path_buf validated but actual read happens later
    // If this were async or path_buf in shared memory, could be modified

    // Actual filesystem read would happen here using path_buf
}
```

**Impact:**
- In current implementation: Low (path_buf is stack-local)
- If refactored to async or shared buffers: High (path substitution attack)

**Fix:**
```c
/* Copy path to guaranteed-local buffer and never reference original */
char path_buf_local[512];
// ... copy to path_buf_local ...

/* Validate using the local copy */
s64 cap_result = validate_host_cap(ctx, AK_CAP_FS, path_buf_local, "read");
if (cap_result != 0)
    return cap_result;

/* Use SAME local copy for actual operation - no window for substitution */
/* Also: Consider passing path_buf_local by value to filesystem layer */
```

---

### S1-3: Missing Response Buffer Size Validation in ak_nanos.c

**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_nanos.c`
**Lines:** 181-187

**Description:**
The response copy to user space truncates if the response is larger than res_max, but it doesn't indicate to the caller that truncation occurred. This could lead to partial JSON being processed.

**Vulnerable Code:**
```c
if (res_json) {
    u64 copy_len = buffer_length(res_json);
    if (copy_len > res_max)
        copy_len = res_max;  // Silent truncation!

    /* Copy to user space */
    runtime_memcpy(res_buf, buffer_ref(res_json, 0), copy_len);
```

**Impact:**
- Truncated JSON may be parsed incorrectly by caller
- Security decisions based on partial response data

**Fix:**
```c
if (res_json) {
    u64 actual_len = buffer_length(res_json);
    if (actual_len > res_max) {
        /* Response too large - return error with required size */
        deallocate_buffer(res_json);
        ak_response_destroy(ctx->heap, res);
        return -ERANGE;  // Or return actual_len as negative to indicate required size
    }

    if (!copy_to_user(res_buf, buffer_ref(res_json, 0), actual_len))
        return -EFAULT;
```

---

### S1-4: Incomplete Escape Sequence Handling in parse_string()

**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_policy_v2.c`
**Lines:** 181-201

**Description:**
The JSON string parser only handles `\"` and `\\` escape sequences. It ignores other escapes like `\n`, `\r`, `\t`, `\uXXXX`. Malformed escape sequences could lead to parsing inconsistencies.

**Vulnerable Code:**
```c
if (*p == '\\' && p + 1 < end) {
    p++;
    if (*p == '"' || *p == '\\') {
        if (i < max_len - 1) out[i++] = *p;
    }
    // Other escapes like \n, \t, \uXXXX are SILENTLY DROPPED
}
```

**Impact:**
- Policy patterns containing escape sequences will be mangled
- `"\u002e\u002e"` (Unicode for "..") might bypass path filters if later processed

**Fix:**
```c
if (*p == '\\' && p + 1 < end) {
    p++;
    char escaped = 0;
    switch (*p) {
        case '"':  escaped = '"';  break;
        case '\\': escaped = '\\'; break;
        case 'n':  escaped = '\n'; break;
        case 'r':  escaped = '\r'; break;
        case 't':  escaped = '\t'; break;
        case '/':  escaped = '/';  break;
        case 'u':  /* Reject unicode escapes in security-critical paths */
            return NULL;  /* Parse error - unicode not supported */
        default:   /* Unknown escape - reject for security */
            return NULL;
    }
    if (i < max_len - 1) out[i++] = escaped;
}
```

---

## S2 - Medium Severity Findings

### S2-1: No Maximum Nesting Depth Check in skip_value()

**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_policy_v2.c`
**Lines:** 227-258

**Description:**
The `skip_value` function uses a local depth counter but has no maximum limit. Deeply nested JSON could cause stack exhaustion.

**Vulnerable Code:**
```c
} else if (*p == '{') {
    int depth = 1;
    p++;
    while (p < end && depth > 0) {
        if (*p == '{') depth++;  // No maximum check!
```

**Fix:**
```c
#define MAX_JSON_DEPTH 32

} else if (*p == '{') {
    int depth = 1;
    p++;
    while (p < end && depth > 0) {
        if (*p == '{') {
            depth++;
            if (depth > MAX_JSON_DEPTH) return NULL;  // Reject too-deep nesting
        }
```

---

### S2-2: Potential Off-by-One in local_strncpy

**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_policy_v2.c`
**Lines:** 88-96

**Description:**
The function is correct, but callers may misuse it by passing `sizeof(buffer)` without accounting for the null terminator already being handled.

**Code:**
```c
static void local_strncpy(char *dest, const char *src, u64 n)
{
    if (!dest || !src || n == 0) return;
    u64 i;
    for (i = 0; i < n - 1 && src[i]; i++) {
        dest[i] = src[i];
    }
    dest[i] = '\0';
}
```

**Recommendation:** Add comment and/or assert that n > 0 is required.

---

### S2-3: Missing NULL Check Before local_strncmp in skip_value

**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_policy_v2.c`
**Lines:** 263-268

**Description:**
The code calls `local_strncmp((const char *)p, "true", 4)` without verifying that there are at least 4 bytes remaining before `end`. If `end - p < 4`, this could read past the buffer.

**Vulnerable Code:**
```c
} else if (local_strncmp((const char *)p, "true", 4) == 0) {
    return p + 4;  // What if end - p < 4?
}
```

**Fix:**
```c
} else if ((end - p >= 4) && local_strncmp((const char *)p, "true", 4) == 0) {
    return p + 4;
} else if ((end - p >= 5) && local_strncmp((const char *)p, "false", 5) == 0) {
    return p + 5;
} else if ((end - p >= 4) && local_strncmp((const char *)p, "null", 4) == 0) {
    return p + 4;
}
```

---

## Additional Recommendations

### 1. Symlink Resolution
The path canonicalization does not resolve symlinks. A path like `/tmp/link` where `link -> ../etc/passwd` would pass canonicalization but access `/etc/passwd`.

**Recommendation:** Add symlink resolution or explicitly document that callers must use O_NOFOLLOW.

### 2. Path Length Limits
Various functions use `AK_MAX_TARGET` (512) but some intermediate buffers are smaller. Consider centralizing path length constants.

### 3. Capability Token Fixed Size
In ak_nanos.c line 154: `u64 cap_len = 256;` - hardcoded capability token size could cause issues if token format changes.

**Recommendation:** Define `AK_CAP_TOKEN_SIZE` constant.

---

## Test Coverage Needed

1. **Path Traversal Tests:**
   - `../../../etc/passwd`
   - `/./foo/../bar/../../baz`
   - Paths with null bytes: `/foo\0bar`
   - Very long paths (> 512 chars)

2. **JSON Parsing Tests:**
   - Deeply nested objects (> 32 levels)
   - Very long strings
   - Invalid escape sequences
   - Integer overflow values

3. **Boundary Tests:**
   - Zero-length buffers
   - NULL pointers for all parameters
   - Maximum size allocations

---

## Status

- [x] ak_posix_route.c - Audited
- [x] ak_effects.c - Audited
- [x] ak_nanos.c - Audited
- [x] ak_policy_v2.c - Audited
- [x] ak_wasm_host.c - Audited
- [x] Fixes implemented (2026-01-16)
  - [x] S0-1: ak_nanos.c - User-space pointer validation FIXED
  - [x] S0-2: ak_policy_v2.c - Integer overflow check FIXED
  - [x] S1-1: ak_effects.c - Path traversal escape prevention FIXED
  - [x] S1-4: ak_policy_v2.c - JSON escape handling FIXED
  - [x] S2-1: ak_policy_v2.c - MAX_JSON_DEPTH check FIXED
  - [x] S2-3: ak_policy_v2.c - Buffer length checks FIXED
- [ ] Negative tests added
- [ ] Code review completed

---

*Generated by Agents A10+A11 (Security Hardeners) - Bug Extermination Org*

---

## Agent A2 (Sanitizer Engineer) - Sanitizer Infrastructure

**Date:** 2026-01-16

### Sanitizer Build Targets

The following sanitizer targets have been added to `test/unit/Makefile`:

| Target | Sanitizer | Description |
|--------|-----------|-------------|
| `make asan` | AddressSanitizer + UBSan | Detects buffer overflows, use-after-free, memory leaks, undefined behavior |
| `make tsan` | ThreadSanitizer | Detects data races and deadlocks |
| `make msan` | MemorySanitizer | Detects uninitialized memory reads (Linux only) |

### Usage

```bash
# Build and run with AddressSanitizer + UBSan
make -C test/unit CC=clang asan

# Build and run with ThreadSanitizer
make -C test/unit CC=clang tsan

# Build and run with MemorySanitizer (Linux only)
make -C test/unit CC=clang msan

# Use the convenience script
./tools/run-sanitizers.sh --asan
./tools/run-sanitizers.sh --all
```

### Convenience Script

A helper script has been created at `tools/run-sanitizers.sh` that:
- Builds with the specified sanitizer(s)
- Runs all tests
- Reports any sanitizer errors
- Exits non-zero on failure

### Known Build Issues

1. **closure_templates.h not found during sanitizer builds**
   - **Status**: Documented
   - **Description**: The sanitizer builds may fail with "closure_templates.h not found" error when the OBJDIR include path is not properly propagated through recursive make.
   - **Workaround**: Ensure a clean build (`make clean`) before running sanitizer targets.

### Sanitizer Findings

_Pending full sanitizer run. Build issues are being resolved._

### Test Programs Covered

The following test programs are included in sanitizer testing:

- ak_effects_test
- ak_negative_test
- ak_pattern_test
- ak_policy_test
- bitmap_test
- buffer_test
- closure_test
- id_heap_test
- memops_test
- objcache_test
- pageheap_test
- parser_test
- pqueue_test
- queue_test
- random_test
- range_test
- rbtree_test
- table_test
- tuple_test
- vector_test

**Skipped tests** (require network):
- network_test
- udp_test

### Recommendations

1. **Run sanitizers in CI**: Add sanitizer tests to the CI pipeline to catch issues early.

2. **Fix warnings before running sanitizers**: The codebase has some warnings that need to be addressed. The sanitizer builds disable strict warnings to focus on runtime issues.

3. **Regular sanitizer testing**: Run sanitizer tests periodically, especially after significant changes to memory management or concurrency code.

4. **Platform considerations**:
   - ASan and UBSan work on both Linux and macOS
   - TSan works on both Linux and macOS
   - MSan requires Linux with an instrumented libc

---

*Generated by Agent A2 (Sanitizer Engineer) - Bug Extermination Org*

---

## Agent A1 (Build Hardener) - Strict Warning Configuration

**Date:** 2026-01-16
**Target Files:** test/unit/Makefile, test/integration/Makefile

### Strict Warning Flags Added

The following warning flags have been added to the test build system:

```
-Wall -Wextra -Werror -Wshadow -Wconversion -Wsign-conversion
-Wformat=2 -Wundef -Wpointer-arith -Wstrict-prototypes -Wvla
```

### Warning Suppressions (Waivers)

#### W1: Runtime Header Warnings Suppressed via -isystem

**Justification:** The test code includes headers from the nanos runtime (`src/runtime/`, `src/aarch64/`, etc.) which have their own coding style and conventions. These headers produce warnings such as:

- `-Wgnu-pointer-arith`: Void pointer arithmetic (GNU extension used intentionally)
- `-Wshadow`: Variable shadowing in macros (macro design choice)
- `-Wsign-conversion`: Signed/unsigned conversions in low-level code
- `-Wunused-parameter`: Unused parameters in callback signatures

**Approach:** Use `-isystem` instead of `-I` for runtime include directories. This treats them as system headers and suppresses warnings, while strict warnings remain active for test source files.

**Risk:** Low. Runtime code is covered by the main build system's warnings. This waiver only affects warning reporting during test compilation.

### Warnings Fixed in Test Files

1. **ak_effects_test.c:**
   - Line 157: Cast pointer difference to `size_t`
   - Line 261: Cast `rand()` return to unsigned before combining
   - Line 273: Handle `snprintf` return value properly
   - Line 456: Cast pointer difference to `size_t`
   - Line 889: Mark unused `argc`/`argv` with `(void)`

2. **ak_pattern_test.c:**
   - Line 117: Cast character arithmetic to `u32`
   - Line 147: Cast pointer difference to `size_t`
   - Line 407: Mark unused `argc`/`argv` with `(void)`

3. **ak_policy_test.c:**
   - Line 121: Cast pointer difference to `size_t`
   - Line 136: Mark unused `error` parameter with `(void)`
   - Line 946-947: Mark unused `argc`/`argv` with `(void)`

### Build Verification Script

Run `tools/build-strict.sh` to verify all test code compiles cleanly with strict warnings:

```bash
./tools/build-strict.sh
```

This script:
- Cleans and rebuilds unit tests with strict flags
- Runs the unit tests
- Cleans and rebuilds integration tests with strict flags
- Runs the integration tests
- Reports pass/fail status for each stage

---

*Generated by Agent A1 (Build Hardener) - Bug Extermination Org*
