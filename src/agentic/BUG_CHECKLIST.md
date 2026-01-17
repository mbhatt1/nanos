# Bug Checklist - Integer Overflow and Truncation Bugs

## Agent A6: Integer/Overflow Hunter

This document tracks integer overflow, truncation, and related arithmetic bugs found in the Authority Kernel codebase.

---

## BUG-A6-001: Potential Integer Overflow in LZ4 Literal Length Accumulation

**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_lz4.c`
**Lines:** 297-306, 332-341
**Severity:** HIGH
**Type:** Integer Overflow

### Description
In `ak_decompress_lz4_sized()`, the literal length and match length are accumulated in a loop without overflow checking. The `lit_len` and `match_len` variables are `u64`, which can overflow if a malicious compressed stream contains many 255-byte length continuation bytes.

### Vulnerable Code
```c
/* Line 297-306: Literal length overflow */
if (lit_len == 15) {
    u8 s;
    do {
        if (src >= src_end)
            goto error;
        s = *src++;
        lit_len += s;  // BUG: No overflow check
    } while (s == 255);
}

/* Line 332-341: Match length overflow */
if ((token & 0x0F) == 15) {
    u8 s;
    do {
        if (src >= src_end)
            goto error;
        s = *src++;
        match_len += s;  // BUG: No overflow check
    } while (s == 255);
}
```

### Impact
An attacker could craft a malicious LZ4 stream that causes `lit_len` or `match_len` to overflow, wrapping around to a small value. This could then pass the bounds checks (`src + lit_len > src_end`) incorrectly.

### Fix
Add overflow checks before accumulating length values:
```c
if (lit_len == 15) {
    u8 s;
    do {
        if (src >= src_end)
            goto error;
        s = *src++;
        if (lit_len > UINT64_MAX - s)  // Overflow check
            goto error;
        lit_len += s;
    } while (s == 255);
}
```

### Status
- [x] Fixed
- [ ] Test case added

---

## BUG-A6-002: Missing Overflow Check in ak_compress_bound()

**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_lz4.c`
**Lines:** 374-378
**Severity:** MEDIUM
**Type:** Integer Overflow in Multiplication/Addition

### Description
The `ak_compress_bound()` function computes `input_size + (input_size / 255) + 16` without checking for overflow. For very large input sizes near `UINT64_MAX`, this can overflow.

### Vulnerable Code
```c
u64 ak_compress_bound(u64 input_size)
{
    /* LZ4 worst case: input_size + (input_size / 255) + 16 */
    return input_size + (input_size / 255) + 16;  // BUG: Can overflow
}
```

### Impact
If `input_size` is close to `UINT64_MAX`, the result overflows and returns a much smaller value, leading to buffer under-allocation in callers.

### Fix
```c
u64 ak_compress_bound(u64 input_size)
{
    u64 extra = input_size / 255;
    if (input_size > UINT64_MAX - extra - 16)
        return UINT64_MAX;  // Saturate on overflow
    return input_size + extra + 16;
}
```

### Status
- [x] Fixed
- [ ] Test case added

---

## BUG-A6-003: Potential Overflow in Audit Entry Hash Computation

**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_audit.c`
**Lines:** 148
**Severity:** MEDIUM
**Type:** Integer Overflow in Addition

### Description
In `ak_audit_compute_entry_hash()`, `total_len` is computed as `AK_HASH_SIZE + buffer_length(canonical)` without overflow checking. If `buffer_length(canonical)` returns a very large value (near `UINT32_MAX - AK_HASH_SIZE`), this could overflow.

### Vulnerable Code
```c
void ak_audit_compute_entry_hash(...)
{
    buffer canonical = ak_log_entry_canonicalize(ak_log.h, entry);

    /* hash = SHA256(prev_hash || canonical) */
    u32 total_len = AK_HASH_SIZE + buffer_length(canonical);  // BUG: No overflow check
    u8 *combined = allocate(ak_log.h, total_len);
```

### Impact
Overflow could cause under-allocation of `combined` buffer, leading to heap buffer overflow during subsequent memcpy operations.

### Fix
Use `u64` for the computation and add overflow check:
```c
u64 canon_len = buffer_length(canonical);
if (canon_len > UINT32_MAX - AK_HASH_SIZE) {
    deallocate_buffer(canonical);
    return;  // Error handling
}
u64 total_len = AK_HASH_SIZE + canon_len;
```

### Status
- [x] Fixed
- [ ] Test case added

---

## BUG-A6-004: Unchecked Multiplication in ak_heap_list_by_type() and ak_heap_list_by_run()

**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_heap.c`
**Lines:** 467, 511, 573
**Severity:** HIGH
**Type:** Integer Overflow in Multiplication

### Description
Multiple functions allocate arrays using `count * sizeof(T)` without checking for overflow. If `count` is large enough, this multiplication can overflow, resulting in a small allocation followed by out-of-bounds writes.

### Vulnerable Code
```c
/* Line 467: ak_heap_list_by_type() */
u64 *result = allocate(h, count * sizeof(u64));  // BUG: Can overflow

/* Line 511: ak_heap_list_by_run() */
u64 *result = allocate(h, count * sizeof(u64));  // BUG: Can overflow

/* Line 573: ak_heap_list_versions() */
u64 *result = allocate(h, hist->count * sizeof(u64));  // BUG: Can overflow
```

### Impact
An attacker who can control the number of objects in the heap could trigger an overflow, causing heap corruption when the array is populated.

### Fix
Add overflow checks before allocation:
```c
#define SAFE_MULT(a, b, result) ((b) != 0 && (a) > SIZE_MAX / (b))

if (SAFE_MULT(count, sizeof(u64), result)) {
    *count_out = 0;
    return NULL;
}
u64 *result = allocate(h, count * sizeof(u64));
```

### Status
- [x] Fixed
- [ ] Test case added

---

## BUG-A6-005: Unchecked Multiplication in ak_audit_query()

**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_audit.c`
**Lines:** 338
**Severity:** HIGH
**Type:** Integer Overflow in Multiplication

### Description
In `ak_audit_query()`, the result array is allocated using `sizeof(ak_log_entry_t *) * count` without overflow checking.

### Vulnerable Code
```c
/* Allocate result array */
ak_log_entry_t **results = allocate(h, sizeof(ak_log_entry_t *) * count);  // BUG
```

### Impact
If `count` is very large (controlled by the query range), this multiplication can overflow, leading to a small allocation and subsequent heap overflow.

### Fix
```c
if (count > SIZE_MAX / sizeof(ak_log_entry_t *)) {
    spin_unlock(&ak_log.lock);
    *count_out = 0;
    return NULL;
}
ak_log_entry_t **results = allocate(h, sizeof(ak_log_entry_t *) * count);
```

### Status
- [x] Fixed
- [ ] Test case added

---

## BUG-A6-006: Unchecked Multiplication in Sanitizer Functions

**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_sanitize.c`
**Lines:** 27, 73, 155, 202
**Severity:** HIGH
**Type:** Integer Overflow in Multiplication

### Description
All sanitizer functions compute worst-case buffer sizes using multiplication without overflow checks:

### Vulnerable Code
```c
/* Line 27: ak_sanitize_html() */
buffer out = allocate_buffer(h, len * 6);  // BUG: Can overflow

/* Line 73: ak_sanitize_sql() */
buffer out = allocate_buffer(h, len * 2);  // BUG: Can overflow

/* Line 155: ak_sanitize_url() */
buffer out = allocate_buffer(h, len * 3);  // BUG: Can overflow

/* Line 202: ak_sanitize_cmd() */
buffer out = allocate_buffer(h, len + quote_count * 3 + 2);  // BUG: Multiple overflows possible
```

### Impact
Input strings with `len` near `UINT64_MAX / 6` (or other divisors) will cause the multiplication to overflow, resulting in a tiny buffer allocation. The subsequent loop will then write past the buffer boundary.

### Fix
Add overflow checks:
```c
/* For ak_sanitize_html() */
if (len > SIZE_MAX / 6) {
    return 0;  // Input too large
}
buffer out = allocate_buffer(h, len * 6);
```

### Status
- [x] Fixed
- [ ] Test case added

---

## BUG-A6-007: Unchecked Multiplication in State Merkle Root Computation

**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_state.c`
**Lines:** 117, 132, 328, 347, 588, 600
**Severity:** HIGH
**Type:** Integer Overflow in Multiplication

### Description
Multiple locations compute `count * AK_HASH_SIZE` without overflow checking.

### Vulnerable Code
```c
/* Line 117: compute_merkle_root() */
u32 max_level_size = count * AK_HASH_SIZE;  // BUG: Can overflow

/* Line 328: ak_state_verify_integrity() */
u8 *hashes = allocate(ak_state.h, count * AK_HASH_SIZE);  // BUG

/* Line 588: ak_state_emit_anchor() */
u8 *hashes = allocate(ak_state.h, count * AK_HASH_SIZE);  // BUG
```

### Impact
If `count` is large enough that `count * AK_HASH_SIZE` overflows, the allocation will be too small, leading to buffer overflow when populating the hash array.

### Fix
```c
if (count > SIZE_MAX / AK_HASH_SIZE) {
    // Handle error
}
u32 max_level_size = count * AK_HASH_SIZE;
```

### Status
- [x] Fixed
- [ ] Test case added

---

## BUG-A6-008: Potential Integer Truncation in Ed25519 Verify

**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_ed25519.c`
**Lines:** 502
**Severity:** LOW
**Type:** Potential Integer Overflow in Addition

### Description
In `ak_ed25519_verify()`, the allocation size is computed as `message_len + 64` without overflow checking.

### Vulnerable Code
```c
u8 *sm = allocate(ed25519_state.h, message_len + 64);  // BUG: No overflow check
```

### Impact
If `message_len` is close to `UINT64_MAX - 64`, this addition overflows, causing a small allocation followed by buffer overflow in the subsequent memcpy operations.

### Fix
```c
if (message_len > SIZE_MAX - 64) {
    return false;
}
u8 *sm = allocate(ed25519_state.h, message_len + 64);
```

### Status
- [x] Fixed
- [ ] Test case added

---

## BUG-A6-009: Unchecked Anchor Array Growth

**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_audit.c`
**Lines:** 460-461
**Severity:** MEDIUM
**Type:** Integer Overflow in Multiplication

### Description
When growing the anchor array, `new_cap * sizeof(ak_anchor_t)` is computed without overflow checking.

### Vulnerable Code
```c
if (ak_log.anchor_count >= ak_log.anchor_capacity) {
    u32 new_cap = ak_log.anchor_capacity * 2;  // BUG: Can overflow
    ak_anchor_t *new_anchors = allocate(ak_log.h, sizeof(ak_anchor_t) * new_cap);  // BUG
```

### Impact
If `anchor_capacity` is large enough that doubling it overflows, or if `sizeof(ak_anchor_t) * new_cap` overflows, the allocation will be too small.

### Fix
```c
if (ak_log.anchor_capacity > UINT32_MAX / 2) {
    spin_unlock(&ak_log.lock);
    return AK_E_LOG_FULL;
}
u32 new_cap = ak_log.anchor_capacity * 2;
if (new_cap > SIZE_MAX / sizeof(ak_anchor_t)) {
    spin_unlock(&ak_log.lock);
    return AK_E_LOG_FULL;
}
```

### Status
- [x] Fixed
- [ ] Test case added

---

## BUG-A6-010: Subtraction Underflow in ak_heap_write()

**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_heap.c`
**Lines:** 378
**Severity:** LOW
**Type:** Potential Underflow (mitigated by language)

### Description
The bytes_used calculation could theoretically underflow, but since u64 underflow wraps around, this would result in a very large value rather than a crash.

### Vulnerable Code
```c
ak_heap_state.bytes_used = ak_heap_state.bytes_used - old_len + new_len;
```

### Impact
If `old_len > bytes_used` (which shouldn't happen in normal operation but could occur due to corruption), the subtraction would underflow. This is a logic bug rather than a security issue.

### Fix
Add defensive check:
```c
if (ak_heap_state.bytes_used >= old_len) {
    ak_heap_state.bytes_used = ak_heap_state.bytes_used - old_len + new_len;
} else {
    ak_heap_state.bytes_used = new_len;  // Recovery from corruption
}
```

### Status
- [x] Fixed
- [ ] Test case added

---

## Summary

| Bug ID | File | Severity | Type | Fixed |
|--------|------|----------|------|-------|
| A6-001 | ak_lz4.c | HIGH | Overflow in length accumulation | [x] |
| A6-002 | ak_lz4.c | MEDIUM | Overflow in compress_bound | [x] |
| A6-003 | ak_audit.c | MEDIUM | Overflow in hash computation | [x] |
| A6-004 | ak_heap.c | HIGH | Unchecked multiplication | [x] |
| A6-005 | ak_audit.c | HIGH | Unchecked multiplication | [x] |
| A6-006 | ak_sanitize.c | HIGH | Unchecked multiplication | [x] |
| A6-007 | ak_state.c | HIGH | Unchecked multiplication | [x] |
| A6-008 | ak_ed25519.c | LOW | Overflow in addition | [x] |
| A6-009 | ak_audit.c | MEDIUM | Unchecked array growth | [x] |
| A6-010 | ak_heap.c | LOW | Potential underflow | [x] |

**Total Bugs Found:** 10
**High Severity:** 5 (all fixed)
**Medium Severity:** 3 (all fixed)
**Low Severity:** 2 (all fixed)

---

## Recommended Helper Macros

Add these to `ak_compat.h` for safe arithmetic:

```c
/* Safe multiplication with overflow check */
#define AK_SAFE_MUL(a, b, result) \
    (((b) != 0 && (a) > SIZE_MAX / (b)) ? 0 : ((result) = (a) * (b), 1))

/* Safe addition with overflow check */
#define AK_SAFE_ADD(a, b, result) \
    (((a) > SIZE_MAX - (b)) ? 0 : ((result) = (a) + (b), 1))

/* Check if multiplication would overflow */
#define AK_MUL_WOULD_OVERFLOW(a, b) \
    ((b) != 0 && (a) > SIZE_MAX / (b))

/* Check if addition would overflow */
#define AK_ADD_WOULD_OVERFLOW(a, b) \
    ((a) > SIZE_MAX - (b))
```

---

# Agent A9: Error/Leak Hunter Report

**Date:** 2026-01-16
**Target Files:**
- ak_syscall.c (1441 lines)
- ak_wasm.c (832 lines)
- ak_wasm_host.c (564 lines)
- ak_agentic.c (1012 lines)
- ak_inference.c (1009 lines)

---

## A9 Summary

| Severity | Count |
|----------|-------|
| Critical | 5 |
| High     | 11 |
| Medium   | 9 |
| Low      | 6 |
| **Total**| **31** |

---

## Critical Issues

### BUG-A9-001: Resource Leak in ak_handle_spawn on result buffer allocation failure
**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_syscall.c`
**Lines:** 924-926
**Severity:** Critical
**Type:** Resource Leak

```c
/* Build result with child ID */
buffer result = allocate_buffer(ctx->heap, 128);
if (!result)
    return ak_response_error(ctx->heap, req, -ENOMEM);
```

**Problem:** When the result buffer allocation fails, the already-created child context is leaked. The child was added to the agent registry (line 911-914) and its budget/seq_tracker were created but never cleaned up.

**Fix Pattern:**
```c
buffer result = allocate_buffer(ctx->heap, 128);
if (!result) {
    ak_agent_registry_remove(child->pid);  /* Remove from registry */
    ak_context_destroy(ctx->heap, child);  /* Cleanup child context */
    return ak_response_error(ctx->heap, req, -ENOMEM);
}
```

### Status
- [ ] Fixed
- [ ] Test case added

---

### BUG-A9-002: Resource Leak in ak_handle_send when result buffer allocation fails
**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_syscall.c`
**Lines:** 1021-1023
**Severity:** Critical
**Type:** Resource Leak

```c
buffer result = allocate_buffer(ctx->heap, 32);
if (!result)
    return ak_response_error(ctx->heap, req, -ENOMEM);
```

**Problem:** When result buffer allocation fails, the message (`msg`) has already been allocated (line 991) and enqueued into the inbox (lines 1012-1019). The message payload was also allocated (line 1003). Both are leaked.

**Fix Pattern:**
```c
buffer result = allocate_buffer(ctx->heap, 32);
if (!result) {
    /* Dequeue the message we just added */
    if (inbox->tail == msg) inbox->tail = NULL;
    if (inbox->head == msg) inbox->head = NULL;
    inbox->count--;
    if (msg->payload) deallocate_buffer(msg->payload);
    deallocate(ctx->heap, msg, sizeof(ak_message_t));
    return ak_response_error(ctx->heap, req, -ENOMEM);
}
```

### Status
- [ ] Fixed
- [ ] Test case added

---

### BUG-A9-003: Missing NULL check for msg->payload allocation
**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_syscall.c`
**Lines:** 1003-1009
**Severity:** Critical
**Type:** Missing Error Check

```c
if (req->args) {
    msg->payload = allocate_buffer(ctx->heap, buffer_length(req->args));
    if (msg->payload) {
        buffer_write(msg->payload, buffer_ref(req->args, 0), buffer_length(req->args));
    }
}
```

**Problem:** If `allocate_buffer` fails (returns NULL or INVALID_ADDRESS), the code continues silently with msg->payload = NULL/INVALID_ADDRESS. This means the message will be enqueued with potentially corrupted payload state.

**Fix Pattern:**
```c
if (req->args) {
    msg->payload = allocate_buffer(ctx->heap, buffer_length(req->args));
    if (!msg->payload || msg->payload == INVALID_ADDRESS) {
        deallocate(ctx->heap, msg, sizeof(ak_message_t));
        return ak_response_error(ctx->heap, req, -ENOMEM);
    }
    buffer_write(msg->payload, buffer_ref(req->args, 0), buffer_length(req->args));
}
```

### Status
- [ ] Fixed
- [ ] Test case added

---

### BUG-A9-004: Missing INVALID_ADDRESS check in ak_context_create
**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_syscall.c`
**Lines:** 191-194
**Severity:** Critical
**Type:** Missing Error Check

```c
ak_agent_context_t *ctx = allocate(h, sizeof(ak_agent_context_t));
if (!ctx)
    return NULL;
```

**Problem:** The allocate() function may return INVALID_ADDRESS instead of NULL on failure (depending on the heap implementation). The code only checks for NULL.

**Fix Pattern:**
```c
ak_agent_context_t *ctx = allocate(h, sizeof(ak_agent_context_t));
if (!ctx || ctx == INVALID_ADDRESS)
    return NULL;
```

### Status
- [ ] Fixed
- [ ] Test case added

---

### BUG-A9-005: Budget/SeqTracker creation not checked in ak_context_create
**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_syscall.c`
**Lines:** 209-212
**Severity:** Critical
**Type:** Missing Error Check / Resource Leak

```c
/* Create budget tracker */
ctx->budget = ak_budget_create(h, ctx->run_id, ctx->policy);

/* Create sequence tracker */
ctx->seq_tracker = ak_seq_tracker_create(h, ctx->pid, ctx->run_id);
```

**Problem:** Neither `ak_budget_create` nor `ak_seq_tracker_create` return values are checked. If budget creation fails, the context is partially initialized. If seq_tracker creation fails after budget succeeded, we leak the budget.

**Fix Pattern:**
```c
ctx->budget = ak_budget_create(h, ctx->run_id, ctx->policy);
if (!ctx->budget) {
    deallocate(h, ctx, sizeof(ak_agent_context_t));
    return NULL;
}

ctx->seq_tracker = ak_seq_tracker_create(h, ctx->pid, ctx->run_id);
if (!ctx->seq_tracker) {
    ak_budget_destroy(h, ctx->budget);
    deallocate(h, ctx, sizeof(ak_agent_context_t));
    return NULL;
}
```

### Status
- [ ] Fixed
- [ ] Test case added

---

## High Severity Issues

### BUG-A9-006: Resource leak in ak_handle_tool_call WASM path
**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_agentic.c`
**Lines:** 537-567
**Severity:** High
**Type:** Resource Leak

**Problem:** The response from `ak_wasm_execute_tool` is never freed. The response object and its result buffer are leaked.

### Status
- [ ] Fixed
- [ ] Test case added

---

### BUG-A9-007: Memory leak in ak_handle_wasm_invoke
**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_agentic.c`
**Lines:** 706-742
**Severity:** High
**Type:** Resource Leak

**Problem:** When `args_buf` allocation returns INVALID_ADDRESS, the code proceeds without error.

### Status
- [ ] Fixed
- [ ] Test case added

---

### BUG-A9-008: Missing INVALID_ADDRESS check for virtio buffers
**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_inference.c`
**Lines:** 218-219
**Severity:** High
**Type:** Missing Error Check

**Problem:** Neither allocation is checked. If either fails, the module continues with INVALID_ADDRESS pointers.

### Status
- [ ] Fixed
- [ ] Test case added

---

### BUG-A9-009: Response leaked in ak_local_inference_request
**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_inference.c`
**Lines:** 457-467
**Severity:** High
**Type:** Resource Leak

**Problem:** Confusing ownership semantics between pre-allocated response and virtio response.

### Status
- [ ] Fixed
- [ ] Test case added

---

### BUG-A9-010: Missing cleanup in ak_handle_infer prompt_buf path
**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_agentic.c`
**Lines:** 947-985
**Severity:** High
**Type:** Incomplete Cleanup

**Problem:** Cleanup may not be reached in all error paths.

### Status
- [ ] Fixed
- [ ] Test case added

---

### BUG-A9-011: WASM module bytecode inconsistent error check
**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_wasm.c`
**Lines:** 186-188
**Severity:** High
**Type:** Inconsistent Error Check

**Problem:** Checks INVALID_ADDRESS but not NULL for module allocation.

### Status
- [ ] Fixed
- [ ] Test case added

---

### BUG-A9-012: Missing error check for export_names string allocation
**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_wasm.c`
**Lines:** 348-351
**Severity:** High
**Type:** Missing Error Check

**Problem:** Code assumes all export_names were successfully allocated during module creation.

### Status
- [ ] Fixed
- [ ] Test case added

---

### BUG-A9-013: ak_tool_register missing tool deallocation on failure
**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_wasm.c`
**Lines:** 412-417
**Severity:** High
**Type:** Resource Leak

**Problem:** No cleanup of allocated tool if later operations fail.

### Status
- [ ] Fixed
- [ ] Test case added

---

### BUG-A9-014: ak_wasm_exec_create missing NULL check
**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_wasm.c`
**Lines:** 546-548
**Severity:** High
**Type:** Missing Error Check

**Problem:** Only checks INVALID_ADDRESS, not NULL.

### Status
- [ ] Fixed
- [ ] Test case added

---

### BUG-A9-015: Missing result check in ak_wasm_execute_tool
**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_wasm.c`
**Lines:** 790-791
**Severity:** High
**Type:** Missing Error Check

**Problem:** ctx->output set to 0 before checking if ak_response_success succeeded.

### Status
- [ ] Fixed
- [ ] Test case added

---

### BUG-A9-016: ak_response_success ownership semantics
**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_syscall.c`
**Lines:** 1162-1167
**Severity:** High
**Type:** Ownership Semantics

**Problem:** On NULL return, passed result buffer has been freed. Callers may double-free.

### Status
- [ ] Documentation added
- [ ] Callers audited

---

## Medium Severity Issues

### BUG-A9-017: ak_context_new_run missing error checks
**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_syscall.c` Lines: 255-262

### BUG-A9-018: ak_grant_capability cap leak when delegated_caps is NULL
**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_syscall.c` Lines: 1293-1305

### BUG-A9-019: ak_wasm_exec_suspend resume_data cleanup
**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_wasm.c` Lines: 609-621

### BUG-A9-020: create_json_result buffer check inconsistent
**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_wasm_host.c` Lines: 127-129

### BUG-A9-021: ak_parse_api_response content buffer ownership ambiguity
**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_inference.c` Lines: 680-694

### BUG-A9-022: format_openai_request missing NULL checks
**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_inference.c` Lines: 504-506

### BUG-A9-023: json_escape_string no bounds checking
**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_inference.c` Lines: 170-186

### BUG-A9-024: ak_inference_embed response leak on routing
**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_inference.c` Lines: 921-931

### BUG-A9-025: Missing immediate NULL check in ak_handle_inference
**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_inference.c` Lines: 978

---

## Low Severity Issues

### BUG-A9-026: Unused variable warning potential
**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_wasm_host.c` Lines: 381-383

### BUG-A9-027: ak_host_random uses weak random
**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_wasm_host.c` Lines: 554-558

### BUG-A9-028: ak_syscall_handler static context never freed
**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_syscall.c` Lines: 1350-1358

### BUG-A9-029: ak_dispatch_raw cleanup asymmetric
**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_syscall.c` Lines: 434-438

### BUG-A9-030: ak_wasm_module_unload inconsistent with create
**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_wasm.c` Lines: 336-366

### BUG-A9-031: Potential integer overflow in buffer size calculation
**File:** `/Users/mbhatt/authority/nanos/src/agentic/ak_inference.c` Lines: 496-502

---

## A9 Recommended Fixes Priority

### Immediate (Critical):
1. BUG-A9-001: Fix ak_handle_spawn leak
2. BUG-A9-002: Fix ak_handle_send leak
3. BUG-A9-003: Fix msg->payload allocation check
4. BUG-A9-004: Add INVALID_ADDRESS check in ak_context_create
5. BUG-A9-005: Add budget/seq_tracker creation checks

### Short-term (High):
6-16: Fix all high severity issues

### Medium-term:
17-25: Address medium severity issues

### Long-term:
26-31: Address low severity issues

---

## A9 Testing Recommendations

For each fix, add test cases that:
1. Force allocation failures at each allocation point
2. Verify no memory leaks with valgrind/ASan
3. Test partial initialization scenarios
4. Verify error codes are correctly propagated

---

## Combined Summary (A6 + A9)

| Agent | High/Critical | Medium | Low | Total |
|-------|---------------|--------|-----|-------|
| A6 (Integer/Overflow) | 5 | 3 | 2 | 10 |
| A9 (Error/Leak) | 16 | 9 | 6 | 31 |
| **Combined** | **21** | **12** | **8** | **41** |
