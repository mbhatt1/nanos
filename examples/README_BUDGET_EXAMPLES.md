# Budget Tracking Examples

This directory contains production-grade budget tracking examples using real API token counts.

## Primary Example

### 01_budget_tracking_unified.py
**Universal Budget Tracking (All LLM Providers)**

Production-grade token tracking that works with ANY LLM provider:
- **OpenAI** (GPT-4, GPT-3.5, etc.)
- **Anthropic** (Claude 3.5, etc.)
- **Google Gemini** (Gemini 2.0, etc.)
- Auto-detects available provider
- 100% accurate token counting
- NO estimation fallbacks
- Adapter pattern for easy extensibility

```bash
# Setup - Install provider SDK (any one)
pip install openai          # For OpenAI
pip install anthropic        # For Anthropic  
pip install google-genai     # For Gemini

# Set API key (any one)
export OPENAI_API_KEY=your_key
export ANTHROPIC_API_KEY=your_key
export GEMINI_API_KEY=your_key

# Run (auto-detects provider)
python3 examples/01_budget_tracking_unified.py
```

**Features:**
- Works with OpenAI, Anthropic, Gemini - any supported provider
- Auto-detects available API from environment
- Adapter pattern for easy extensibility
- Extracts real token counts from API response metadata
- Explicit error handling if metadata unavailable
- Detailed breakdown: prompt tokens vs completion tokens
- Token usage optimization analysis
- Budget limit enforcement with critical warnings

**Demonstrations:**
1. Basic usage with auto-detected provider
2. Budget limit enforcement (intentionally low limit)
3. Token optimization comparison (verbose vs concise prompts)

**Adapter Pattern:**
```python
from authority_nanos.llm_adapters import get_adapter

# Auto-detect provider from environment
adapter = get_adapter()

# Or specify preferred provider
adapter = get_adapter(provider='OpenAI')

# Generate with token tracking
response = adapter.generate("What is 2+2?")

# Access standardized token usage
print(f"Provider: {response.usage.provider}")
print(f"Prompt tokens: {response.usage.prompt_tokens}")
print(f"Completion tokens: {response.usage.completion_tokens}")
print(f"Total: {response.usage.total_tokens}")
```

**Why API-Only:**
- Production billing requires 100% accuracy
- Estimation leads to cost tracking errors
- Fail-fast reveals API issues immediately
- Provider abstraction simplifies multi-provider support

**Recommended for:**
- Production deployments
- Cost accounting and billing
- Budget enforcement systems
- Token usage optimization
- Multi-provider environments

**Provider-Specific Setup:**

**OpenAI:**
```bash
# Get key from: https://platform.openai.com/api-keys
pip install openai
export OPENAI_API_KEY=sk-...
```

**Anthropic:**
```bash
# Get key from: https://console.anthropic.com/
pip install anthropic
export ANTHROPIC_API_KEY=sk-ant-...
```

**Gemini:**
```bash
# Get key from: https://makersuite.google.com/app/apikey
pip install google-genai
export GEMINI_API_KEY=AIza...
```

---

## Budget Tracking API

### Core Classes

#### `BudgetTracker`
Main interface for budget tracking:

```python
from authority_nanos import AuthorityKernel

with AuthorityKernel() as ak:
    # Get current status
    status = ak.budget.get_status()
    print(f"Tokens: {status.tokens_used} / {status.tokens_limit}")
    
    # Get history
    history = ak.budget.get_history(count=60)
    
    # Get breakdown
    breakdown = ak.budget.get_breakdown()
    
    # Estimate remaining time
    remaining = ak.budget.estimate_remaining_runtime()
    
    # Print formatted status
    ak.budget.print_status(detailed=True)
```

#### `BudgetStatus`
Current budget state:
- `tokens_used`, `tokens_limit`, `tokens_percent`, `tokens_remaining`
- `tool_calls_used`, `tool_calls_limit`, `tool_calls_percent`
- `wall_time_used`, `wall_time_limit`, `wall_time_percent`
- `bytes_used`, `bytes_limit`, `bytes_percent`
- `is_any_critical` - True if any resource > 90%

#### `BudgetSnapshot`
Historical point-in-time data:
- `timestamp` - When snapshot was taken
- `tokens` - Total tokens at that time
- `tool_calls` - Total tool calls
- `wall_time_ms` - Elapsed time in milliseconds

#### `BudgetBreakdown`
Detailed consumption analysis:
- `tokens_by_operation` - Dict of operation type → token count
- `tool_calls_by_name` - Dict of tool name → call count
- `top_token_consumers(n)` - Top N token-consuming operations
- `top_tools(n)` - Top N most-called tools

---

## Common Patterns

### 1. Basic Monitoring

```python
with AuthorityKernel() as ak:
    # Do work...
    
    # Check status
    status = ak.budget.get_status()
    if status.is_any_critical:
        print("WARNING: Budget critical!")
```

### 2. Continuous Monitoring

```python
def monitor_loop(ak, interval=1.0):
    while True:
        status = ak.budget.get_status(force_refresh=True)
        if status.tokens_percent > 90:
            alert("Token budget critical!")
        time.sleep(interval)
```

### 3. Budget Alerts

```python
class BudgetMonitor:
    def __init__(self, kernel, warn=75, critical=90):
        self.kernel = kernel
        self.warn_threshold = warn
        self.critical_threshold = critical
    
    def check(self):
        status = self.kernel.budget.get_status()
        if status.tokens_percent >= self.critical_threshold:
            return "CRITICAL"
        elif status.tokens_percent >= self.warn_threshold:
            return "WARNING"
        return "OK"
```

### 4. Historical Analysis

```python
# Get last hour of snapshots
history = ak.budget.get_history(count=60)

# Calculate burn rate
if len(history) >= 2:
    first, last = history[0], history[-1]
    elapsed_sec = (last.timestamp - first.timestamp).total_seconds()
    token_rate = (last.tokens - first.tokens) / elapsed_sec
    print(f"Burn rate: {token_rate:.1f} tokens/sec")
```

### 5. Detailed Reporting

```python
breakdown = ak.budget.get_breakdown()

print("Top Token Consumers:")
for operation, tokens in breakdown.top_token_consumers(5):
    print(f"  {operation}: {tokens:,} tokens")

print("\nTop Tools:")
for tool, calls in breakdown.top_tools(5):
    print(f"  {tool}: {calls} calls")
```

---

## Environment Setup

### For Real Kernel Mode (Production)
1. Build Authority Kernel:
   ```bash
   cd src/agentic
   make
   ```

2. Set library path:
   ```bash
   export LD_LIBRARY_PATH=/path/to/libak:$LD_LIBRARY_PATH
   ```

3. Run with real kernel

### For API-Only Example (Recommended)
1. Get API key: https://makersuite.google.com/app/apikey

2. Install SDK:
   ```bash
   pip install google-genai
   ```

3. Set environment variable:
   ```bash
   export GEMINI_API_KEY=your_key_here
   ```

4. Or create `.env` file:
   ```
   GEMINI_API_KEY=your_key_here
   ```

---

## Token Accuracy

### Real API Mode (Example 11) - 100% Accurate

Tokens are extracted directly from LLM API response metadata:

```python
# Call API
response = client.models.generate_content(model=model_name, contents=prompt)

# Extract REAL token counts
metadata = response.usage_metadata
prompt_tokens = metadata.prompt_token_count      # 100% accurate
completion_tokens = metadata.candidates_token_count  # 100% accurate
total_tokens = metadata.total_token_count        # 100% accurate

# NO estimation - fail if metadata unavailable
if not hasattr(response, 'usage_metadata'):
    raise RuntimeError("Cannot track tokens accurately without API metadata")
```

**These are the exact tokens that the provider counts and bills for.**

### Supported Providers

| Provider | Models | Token Extraction | Accuracy |
|----------|--------|------------------|----------|
| **OpenAI** | GPT-4, GPT-3.5, etc. | `response.usage.*` | 100% |
| **Anthropic** | Claude 3.5, etc. | `response.usage.*` | 100% |
| **Gemini** | Gemini 2.0, etc. | `response.usage_metadata.*` | 100% |

All providers extract REAL token counts from API metadata with NO estimation fallbacks.

### Accuracy Guarantee

| Method | Accuracy | Source | Use Case |
|--------|----------|--------|----------|
| **Unified Adapter (Example 01)** | **100%** | API response metadata | Production, any provider |
| **Real Kernel + API** | **100%** | API via kernel syscalls | Production with full kernel |

---

## Integration with Your Code

### Minimal Integration

```python
from authority_nanos import AuthorityKernel

with AuthorityKernel() as ak:
    # Your agent code here
    
    # Check budget periodically
    if ak.budget.get_status().is_any_critical:
        print("Budget critical - stopping")
        break
```

### Full Integration

```python
from authority_nanos import AuthorityKernel

class MyAgent:
    def __init__(self):
        self.kernel = AuthorityKernel()
        self.kernel.init()
    
    def run(self):
        while True:
            # Do work
            self.process_task()
            
            # Monitor budget
            status = self.kernel.budget.get_status()
            if status.is_any_critical:
                self.handle_budget_critical()
                break
            
            # Log progress
            if self.should_log():
                self.kernel.budget.print_status()
    
    def handle_budget_critical(self):
        print("Budget exhausted!")
        breakdown = self.kernel.budget.get_breakdown()
        print("Top consumers:")
        for op, tokens in breakdown.top_token_consumers(3):
            print(f"  {op}: {tokens:,} tokens")
```

---

## Troubleshooting

### "libak not found"
- Build the kernel first: `cd src/agentic && make`
- Set library path: `export LD_LIBRARY_PATH=/path/to/libak:$LD_LIBRARY_PATH`

### "Gemini API error"
- Check API key is valid
- Ensure `google-genai` is installed
- Check internet connection
- Verify API quota

### "API response missing usage_metadata"
- This is intentional fail-fast behavior
- API didn't provide token counts
- Check API version compatibility
- Verify API is not rate-limited

### "No budget data"
- Budget tracking starts after first operation
- Call `ak.budget.get_status()` to force update

---

## Token Optimization

Example 01 includes a token optimization demo comparing:

```python
# Verbose prompt: 420 tokens
"Please explain to me in detail what the result of multiplying 5 by 5 is..."

# Concise prompt: 16 tokens
"What is 5*5?"

# System prompt: 15 tokens
"Calculate: 5*5"
```

**Optimization strategies:**
- Use concise prompts to reduce input tokens
- Request brief responses to reduce completion tokens
- Monitor breakdown to identify high-consumption operations
- All measurements are 100% accurate from API

---

## Development/Testing Examples

The following examples (08-10) are available for development and testing purposes only. They use simulation or estimation and are NOT suitable for production:

- `08_budget_tracking.py` - Simulation mode, fixed token estimates
- `09_langchain_budget_demo.py` - Simulated LangChain agent
- `10_langchain_gemini_budget.py` - Has estimation fallbacks

**For production, use example 01 only.**

---

## Next Steps

1. Set up your API key
2. Run example 01 to see real token tracking
3. Integrate budget tracking into your agents
4. Set appropriate budget limits in policy files
5. Monitor and optimize token usage

For more information, see:
- Main README: `../README.md`
- Python SDK docs: `../sdk/python/README.md`
- Token calculation details: `../docs/budget-token-calculation.md`
- Policy examples: `../policies/`
