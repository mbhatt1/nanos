# Budget Tracking: Token Calculation Explained

## Overview

Authority Kernel tracks token consumption across different resource types to enforce budget limits. This document explains how tokens are calculated, tracked, and reported in the system.

---

## Token Calculation Methods

### 1. Real Kernel Mode (Production)

When running with the actual Authority Kernel, tokens are calculated through kernel syscalls:

```c
// In ak_budget.c
int ak_budget_consume(ak_budget_tracker_t *tracker,
                     ak_resource_type_t resource,
                     u64 amount)
{
    // Check if consumption would exceed limit
    if (limit > 0 && used + amount > limit) {
        return AK_E_BUDGET_EXCEEDED;
    }
    
    // Update consumption
    tracker->budget.used[resource] += amount;
    return 0;
}
```

**Token Tracking Flow:**

1. **LLM Inference** → `AK_SYS_INFERENCE` syscall
   - Kernel intercepts inference request
   - Forwards to LLM provider
   - Provider returns actual token counts in response metadata
   - Kernel records: `AK_RESOURCE_LLM_TOKENS_IN` (prompt) + `AK_RESOURCE_LLM_TOKENS_OUT` (completion)

2. **Tool Execution** → `AK_SYS_TOOL_CALL` syscall
   - Increments `AK_RESOURCE_TOOL_CALLS`
   - Records operation in breakdown tracker
   - Response tokens counted separately

3. **Combined Tracking**:
   ```c
   // Total tokens = input tokens + output tokens
   status->tokens_used = tracker->budget.used[AK_RESOURCE_LLM_TOKENS_IN] +
                        tracker->budget.used[AK_RESOURCE_LLM_TOKENS_OUT];
   ```

---

### 2. Simulation Mode (Testing/Development)

When running without the kernel (simulation mode), tokens are estimated:

```python
# In examples/09_langchain_budget_demo.py
def inference(self, request_data: bytes) -> bytes:
    tokens_used = 150  # Fixed estimate per inference
    self.budget.record_inference(tokens_used)
    # ...
```

**Simulation Token Estimates:**
- **Inference call**: ~150 tokens (fixed)
- **Tool call**: ~50 tokens (fixed)
- **Combined**: Sum of all operations

**Purpose**: Allows development and testing without:
- Building the kernel
- Connecting to real LLM APIs
- Incurring API costs

---

### 3. Real API Mode (Gemini Example)

When using real LLM APIs (e.g., Gemini), tokens come from API response:

```python
# In examples/10_langchain_gemini_budget.py
response = self.client.models.generate_content(
    model=self.model_name,
    contents=user_msg
)

# Get actual token counts from API metadata
if hasattr(response, 'usage_metadata'):
    prompt_tokens = response.usage_metadata.prompt_token_count
    completion_tokens = response.usage_metadata.candidates_token_count
    total_tokens = response.usage_metadata.total_token_count
else:
    # Fallback estimation if metadata not available
    prompt_tokens = len(user_msg.split()) * 1.3
    completion_tokens = len(response_text.split()) * 1.3
    total_tokens = int(prompt_tokens + completion_tokens)

self.budget.record_inference(total_tokens)
```

**Token Sources (Priority Order):**

1. **API Metadata** (Most Accurate)
   - `prompt_token_count` - Exact prompt tokens
   - `candidates_token_count` - Exact completion tokens
   - `total_token_count` - Total (prompt + completion)

2. **Word-Based Estimation** (Fallback)
   - English: ~1.3 tokens per word
   - Code: ~1.5 tokens per word
   - Mixed: ~1.4 tokens per word

3. **Character-Based Estimation** (Last Resort)
   - ~4 characters per token average
   - `tokens = len(text) / 4`

---

## Token Types and Resources

### Resource Type Mapping

```c
// From ak_types.h
typedef enum {
    AK_RESOURCE_LLM_TOKENS_IN,      // Prompt tokens
    AK_RESOURCE_LLM_TOKENS_OUT,     // Completion tokens
    AK_RESOURCE_TOOL_CALLS,         // Tool execution count
    AK_RESOURCE_WALL_TIME_MS,       // Elapsed time
    AK_RESOURCE_HEAP_BYTES,         // Memory usage
    AK_RESOURCE_NETWORK_BYTES,      // Network I/O
    AK_RESOURCE_FILE_BYTES,         // File I/O
    AK_RESOURCE_BLOB_BYTES,         // Blob storage
    AK_RESOURCE_COUNT
} ak_resource_type_t;
```

### Combined Metrics

**Total Tokens:**
```c
tokens_used = tokens_in + tokens_out
```

**Total Bytes:**
```c
bytes_used = heap_bytes + network_bytes + file_bytes + blob_bytes
```

---

## Breakdown Tracking

The system tracks token consumption by operation type:

```c
// In ak_budget.c
void ak_budget_record_operation(ak_budget_tracker_t *tracker,
                                const char *operation,
                                const char *detail,
                                u64 amount)
{
    if (runtime_strcmp(operation, "inference") == 0) {
        tracker->breakdown.tokens_inference += amount;
    } else if (runtime_strcmp(operation, "tool_response") == 0) {
        tracker->breakdown.tokens_tool_responses += amount;
    } else if (runtime_strcmp(operation, "tool_call") == 0) {
        // Track per-tool statistics
        int idx = ak_budget_find_tool(&tracker->breakdown, detail);
        if (idx >= 0) {
            tracker->breakdown.tool_calls_by_type[idx]++;
        }
    }
}
```

**Operation Types:**

1. **inference** - Direct LLM inference calls
2. **tool_response** - Tokens in tool results
3. **tool_call** - Tool execution metadata
4. **ipc** - Inter-process communication
5. **other** - Miscellaneous operations

---

## Historical Tracking

Tokens are recorded in time-series snapshots:

```c
// Take snapshot every N seconds or on significant events
void ak_budget_snapshot(ak_budget_tracker_t *tracker)
{
    snapshot.timestamp_ms = now_ms;
    snapshot.tokens = used_tokens_in + used_tokens_out;
    snapshot.tool_calls = used_tool_calls;
    snapshot.wall_time_ms = now_ms - start_time;
    
    // Store in ring buffer (60 snapshots by default)
    tracker->snapshots[tracker->snapshot_head] = snapshot;
    tracker->snapshot_head = (tracker->snapshot_head + 1) % 60;
}
```

**Snapshot Storage:**
- Ring buffer: 60 snapshots (configurable)
- Each snapshot: timestamp + resource usage
- Automatic overflow: oldest replaced by newest

---

## Burn Rate Calculation

Token consumption rate is calculated from historical data:

```python
def estimate_remaining_runtime(self) -> Optional[timedelta]:
    if len(self.snapshots) < 2:
        return None
    
    elapsed = (datetime.now() - self.start_time).total_seconds()
    token_rate = self.status.tokens_used / elapsed  # tokens per second
    
    if token_rate < 0.1:
        return timedelta(hours=999)  # Effectively unlimited
    
    remaining_tokens = self.status.tokens_remaining
    remaining_seconds = remaining_tokens / token_rate
    return timedelta(seconds=int(remaining_seconds))
```

**Formula:**
```
burn_rate = total_tokens_used / elapsed_time_seconds
remaining_time = tokens_remaining / burn_rate
```

---

## Example Token Flows

### Example 1: Simple Inference

```
User: "What is 2+2?"

1. Request sent to LLM
   - Prompt tokens: ~10
   - System tokens: ~20
   - Total input: 30

2. LLM responds: "The answer is 4."
   - Completion tokens: ~10

3. Budget updated:
   - AK_RESOURCE_LLM_TOKENS_IN += 30
   - AK_RESOURCE_LLM_TOKENS_OUT += 10
   - Total: 40 tokens
```

### Example 2: Tool Use

```
User: "Calculate 25 * 4"

1. Initial inference
   - Prompt: 20 tokens
   - Decision to use tool: 30 tokens
   - Subtotal: 50 tokens

2. Tool execution
   - AK_RESOURCE_TOOL_CALLS += 1
   - Tool result: "100"
   - Result encoding: 5 tokens

3. Final response generation
   - Prompt + tool result: 40 tokens
   - Final answer: 20 tokens
   - Subtotal: 60 tokens

4. Total: 115 tokens (50 + 5 + 60)
```

### Example 3: Multi-turn Conversation

```
Turn 1: "What is the weather?"
  - Request: 30 tokens
  - Response: 50 tokens
  - Running total: 80 tokens

Turn 2: "And tomorrow?"
  - Context (previous turn): 80 tokens
  - New request: 20 tokens
  - Response: 40 tokens
  - Running total: 220 tokens (80 + 20 + 40 + previous 80)

Note: Context grows with each turn!
```

---

## Token Estimation Accuracy

### Accuracy by Method

| Method | Accuracy | Use Case |
|--------|----------|----------|
| Real Kernel + Real API | 100% | Production |
| Real API (Gemini, OpenAI) | 95-99% | Development/Testing |
| Word-based estimation | 70-85% | Simulation |
| Fixed estimates | 50-70% | Quick demos |

### Improving Estimation Accuracy

1. **Use Real APIs in Testing**
   - Set up API keys
   - Test with actual models
   - Validate token counts

2. **Calibrate Estimates**
   ```python
   # Measure actual usage
   test_prompt = "Sample text"
   actual = api_call(test_prompt).tokens
   estimated = len(test_prompt.split()) * 1.3
   
   # Calculate correction factor
   factor = actual / estimated
   
   # Apply to future estimates
   future_estimate = len(new_text.split()) * 1.3 * factor
   ```

3. **Model-Specific Factors**
   - GPT-4: ~1.3 tokens/word
   - GPT-3.5: ~1.2 tokens/word
   - Gemini: ~1.4 tokens/word
   - Code models: ~1.5 tokens/word

---

## Budget Enforcement

### Check Before Consumption

```c
// In ak_budget.c
int ak_budget_consume(ak_budget_tracker_t *tracker,
                     ak_resource_type_t resource,
                     u64 amount)
{
    u64 limit = tracker->budget.limits[resource];
    u64 used = tracker->budget.used[resource];
    
    // Deny if would exceed limit
    if (limit > 0 && used + amount > limit) {
        return AK_E_BUDGET_EXCEEDED;
    }
    
    // Allow and record consumption
    tracker->budget.used[resource] += amount;
    return 0;
}
```

### Critical Threshold Detection

```python
# In Python SDK
@property
def is_any_critical(self) -> bool:
    return any([
        self.tokens_percent >= 90,      # 90% of token budget
        self.tool_calls_percent >= 90,  # 90% of tool calls
        self.wall_time_percent >= 90    # 90% of time budget
    ])
```

---

## Summary

**Token Calculation Hierarchy:**

1. **Best**: Real kernel + Real API → Exact counts from provider
2. **Good**: Real API only → Accurate counts from metadata
3. **Acceptable**: Word-based estimation → ~80% accuracy
4. **Demo**: Fixed estimates → Predictable but inaccurate

**Key Points:**

- Tokens are tracked per-resource (input, output, tool calls)
- Historical snapshots enable burn rate calculation
- Breakdown tracking identifies high-consumption operations
- Real APIs provide the most accurate token counts
- Simulation mode uses fixed estimates for testing

**For Production:**
- Always use real kernel with real API integration
- Monitor actual consumption vs estimates
- Set appropriate buffer in limits (e.g., 80% of max)
- Use breakdown data to optimize token usage
