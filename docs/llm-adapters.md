# LLM Adapters for Budget Tracking

The Authority Nanos SDK provides a unified adapter pattern for token tracking across all major LLM providers.

## Supported Providers

| Provider | Model Examples | Token Extraction |
|----------|---------------|------------------|
| **OpenAI** | gpt-4, gpt-3.5-turbo | `response.usage.prompt_tokens`, `completion_tokens` |
| **Anthropic** | claude-3-5-sonnet | `response.usage.input_tokens`, `output_tokens` |
| **Google Gemini** | gemini-2.0-flash-exp | `response.usage_metadata.prompt_token_count` |

## Quick Start

### Auto-Detection

```python
from authority_nanos.llm_adapters import get_adapter

# Auto-detect from environment variables
adapter = get_adapter()

# Use it
response = adapter.generate("What is 2+2?")
print(f"Tokens used: {response.usage.total_tokens}")
print(f"Response: {response.content}")
```

### Specific Provider

```python
from authority_nanos.llm_adapters import get_adapter

# Prefer specific provider
adapter = get_adapter(provider='OpenAI')

response = adapter.generate("What is 2+2?")
```

### Direct Creation

```python
from authority_nanos.llm_adapters import OpenAIAdapter, AnthropicAdapter, GeminiAdapter

# OpenAI
adapter = OpenAIAdapter(api_key="sk-...", model="gpt-4")

# Anthropic
adapter = AnthropicAdapter(api_key="sk-ant-...", model="claude-3-5-sonnet-20241022")

# Gemini
adapter = GeminiAdapter(api_key="AIza...", model="gemini-2.0-flash-exp")

response = adapter.generate("Hello!")
```

## Adapter Interface

All adapters implement the same interface:

```python
class LLMAdapter(ABC):
    def generate(self, prompt: str, **kwargs) -> LLMResponse:
        """Generate completion with token tracking."""
        pass
    
    def is_available(self) -> bool:
        """Check if provider SDK is installed."""
        pass
    
    @classmethod
    def from_env(cls, model: Optional[str] = None) -> Optional['LLMAdapter']:
        """Create adapter from environment variables."""
        pass
```

## Response Format

All adapters return a standardized `LLMResponse`:

```python
@dataclass
class LLMResponse:
    content: str              # The generated text
    usage: TokenUsage         # Token usage details
    raw_response: Any         # Original API response
```

## Token Usage

Token usage is standardized across all providers:

```python
@dataclass
class TokenUsage:
    prompt_tokens: int        # Input tokens
    completion_tokens: int    # Output tokens
    total_tokens: int         # Total (prompt + completion)
    model: str                # Model name
    provider: str             # Provider name
```

## Adding a New Provider

To add support for a new LLM provider:

### 1. Create Adapter Class

```python
from authority_nanos.llm_adapters import LLMAdapter, TokenUsage, LLMResponse

class NewProviderAdapter(LLMAdapter):
    """Adapter for NewProvider API."""
    
    def __init__(self, api_key: str, model: str = "default-model"):
        super().__init__(api_key, model)
        # Initialize provider client
        from newprovider import Client
        self.client = Client(api_key=api_key)
    
    def generate(self, prompt: str, **kwargs) -> LLMResponse:
        """Generate with NewProvider API."""
        response = self.client.complete(
            model=self.model,
            prompt=prompt,
            **kwargs
        )
        
        # Extract token counts - FAIL if not available
        if not hasattr(response, 'token_info'):
            raise RuntimeError("API response missing token information")
        
        # Map to standard TokenUsage
        usage = TokenUsage(
            prompt_tokens=response.token_info.input_tokens,
            completion_tokens=response.token_info.output_tokens,
            total_tokens=response.token_info.total_tokens,
            model=self.model,
            provider='NewProvider'
        )
        
        return LLMResponse(
            content=response.text,
            usage=usage,
            raw_response=response
        )
    
    def is_available(self) -> bool:
        """Check if SDK is installed."""
        try:
            import newprovider
            return True
        except ImportError:
            return False
    
    @classmethod
    def from_env(cls, model: Optional[str] = None) -> Optional['NewProviderAdapter']:
        """Create from environment variable."""
        api_key = os.getenv('NEWPROVIDER_API_KEY')
        if api_key:
            return cls(api_key, model or "default-model")
        return None
```

### 2. Register in Factory

```python
# In llm_adapters.py, add to AdapterFactory.ADAPTERS list
class AdapterFactory:
    ADAPTERS = [
        OpenAIAdapter,
        AnthropicAdapter,
        GeminiAdapter,
        NewProviderAdapter,  # Add your adapter
    ]
```

### 3. Test

```python
from authority_nanos.llm_adapters import get_adapter

# Set environment variable
os.environ['NEWPROVIDER_API_KEY'] = 'your_key'

# Should auto-detect
adapter = get_adapter()
assert adapter.provider_name == 'NewProvider'

# Test generation
response = adapter.generate("Test prompt")
assert response.usage.total_tokens > 0
```

## Token Extraction Examples

### OpenAI

```python
response = client.chat.completions.create(...)

# Token extraction
prompt_tokens = response.usage.prompt_tokens
completion_tokens = response.usage.completion_tokens
total_tokens = response.usage.total_tokens
```

### Anthropic

```python
response = client.messages.create(...)

# Token extraction
prompt_tokens = response.usage.input_tokens
completion_tokens = response.usage.output_tokens
total_tokens = input_tokens + output_tokens
```

### Gemini

```python
response = client.models.generate_content(...)

# Token extraction
metadata = response.usage_metadata
prompt_tokens = metadata.prompt_token_count
completion_tokens = metadata.candidates_token_count
total_tokens = metadata.total_token_count
```

## Error Handling

All adapters follow a fail-fast approach:

```python
def generate(self, prompt: str, **kwargs) -> LLMResponse:
    response = self.client.generate(...)
    
    # Fail if no token metadata
    if not hasattr(response, 'usage'):
        raise RuntimeError(
            f"{self.provider_name} API response missing usage data. "
            f"Cannot track tokens accurately."
        )
    
    # Continue with extraction...
```

This ensures:
- 100% accurate token counts (no estimation)
- Immediate detection of API issues
- Clear error messages for debugging

## Environment Variables

| Provider | Environment Variable | Default Model |
|----------|---------------------|---------------|
| OpenAI | `OPENAI_API_KEY` | `gpt-4` |
| Anthropic | `ANTHROPIC_API_KEY` | `claude-3-5-sonnet-20241022` |
| Gemini | `GEMINI_API_KEY` | `gemini-2.0-flash-exp` |

## Best Practices

1. **Always use real API metadata** - Never fall back to estimation
2. **Fail fast** - Raise RuntimeError if metadata unavailable
3. **Validate token counts** - Ensure `total = prompt + completion`
4. **Preserve raw response** - Include in LLMResponse for debugging
5. **Test thoroughly** - Verify token extraction with real API calls

## Integration with Budget Tracking

```python
from authority_nanos.llm_adapters import get_adapter

class BudgetTracker:
    def __init__(self, token_limit: int = 100000):
        self.adapter = get_adapter()  # Auto-detect
        self.tokens_used = 0
        self.tokens_limit = token_limit
    
    def generate(self, prompt: str) -> str:
        # Check budget
        if self.tokens_used >= self.tokens_limit:
            raise RuntimeError("Budget exhausted")
        
        # Generate with token tracking
        response = self.adapter.generate(prompt)
        
        # Update budget
        self.tokens_used += response.usage.total_tokens
        
        return response.content
```

## See Also

- Example 01: Universal budget tracking with all providers
- `sdk/python/authority_nanos/llm_adapters.py`: Full implementation
- `examples/README_BUDGET_EXAMPLES.md`: Usage examples
