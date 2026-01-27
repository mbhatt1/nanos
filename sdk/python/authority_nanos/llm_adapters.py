"""
LLM API Adapters for Budget Tracking

Provides unified interface for token tracking across different LLM providers.
Supports: OpenAI, Anthropic, Google Gemini, and custom providers.

All adapters extract REAL token counts from API responses with NO estimation.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Any, Optional, List
import os


@dataclass
class TokenUsage:
    """Standardized token usage across all providers."""
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    model: str
    provider: str
    
    def __post_init__(self):
        """Validate token counts."""
        if self.total_tokens != self.prompt_tokens + self.completion_tokens:
            raise ValueError(
                f"Token count mismatch: {self.total_tokens} != "
                f"{self.prompt_tokens} + {self.completion_tokens}"
            )


@dataclass
class LLMResponse:
    """Standardized response across all providers."""
    content: str
    usage: TokenUsage
    raw_response: Any = None


class LLMAdapter(ABC):
    """Base adapter interface for LLM providers."""
    
    def __init__(self, api_key: str, model: str):
        self.api_key = api_key
        self.model = model
        self.provider_name = self.__class__.__name__.replace('Adapter', '')
    
    @abstractmethod
    def generate(self, prompt: str, **kwargs) -> LLMResponse:
        """
        Generate completion with token tracking.
        
        Args:
            prompt: User prompt
            **kwargs: Provider-specific options
            
        Returns:
            LLMResponse with content and token usage
            
        Raises:
            RuntimeError: If API doesn't provide token metadata
        """
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """Check if provider SDK is installed."""
        pass
    
    @classmethod
    def from_env(cls, model: Optional[str] = None) -> Optional['LLMAdapter']:
        """Create adapter from environment variables."""
        return None


class OpenAIAdapter(LLMAdapter):
    """OpenAI API adapter (GPT-4, GPT-3.5, etc.)."""
    
    def __init__(self, api_key: str, model: str = "gpt-4"):
        super().__init__(api_key, model)
        from openai import OpenAI
        self.client = OpenAI(api_key=api_key)
    
    def generate(self, prompt: str, **kwargs) -> LLMResponse:
        """Generate with OpenAI API."""
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            **kwargs
        )
        
        # Extract token usage
        if not hasattr(response, 'usage') or response.usage is None:
            raise RuntimeError(
                "OpenAI API response missing usage data. "
                "Cannot track tokens accurately."
            )
        
        usage = TokenUsage(
            prompt_tokens=response.usage.prompt_tokens,
            completion_tokens=response.usage.completion_tokens,
            total_tokens=response.usage.total_tokens,
            model=self.model,
            provider='OpenAI'
        )
        
        return LLMResponse(
            content=response.choices[0].message.content,
            usage=usage,
            raw_response=response
        )
    
    def is_available(self) -> bool:
        try:
            import openai
            return True
        except ImportError:
            return False
    
    @classmethod
    def from_env(cls, model: Optional[str] = None) -> Optional['OpenAIAdapter']:
        api_key = os.getenv('OPENAI_API_KEY')
        if api_key:
            return cls(api_key, model or "gpt-4")
        return None


class AnthropicAdapter(LLMAdapter):
    """Anthropic API adapter (Claude)."""
    
    def __init__(self, api_key: str, model: str = "claude-3-5-sonnet-20241022"):
        super().__init__(api_key, model)
        from anthropic import Anthropic
        self.client = Anthropic(api_key=api_key)
    
    def generate(self, prompt: str, **kwargs) -> LLMResponse:
        """Generate with Anthropic API."""
        max_tokens = kwargs.pop('max_tokens', 1024)
        
        response = self.client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
            **kwargs
        )
        
        # Extract token usage
        if not hasattr(response, 'usage') or response.usage is None:
            raise RuntimeError(
                "Anthropic API response missing usage data. "
                "Cannot track tokens accurately."
            )
        
        usage = TokenUsage(
            prompt_tokens=response.usage.input_tokens,
            completion_tokens=response.usage.output_tokens,
            total_tokens=response.usage.input_tokens + response.usage.output_tokens,
            model=self.model,
            provider='Anthropic'
        )
        
        return LLMResponse(
            content=response.content[0].text,
            usage=usage,
            raw_response=response
        )
    
    def is_available(self) -> bool:
        try:
            import anthropic
            return True
        except ImportError:
            return False
    
    @classmethod
    def from_env(cls, model: Optional[str] = None) -> Optional['AnthropicAdapter']:
        api_key = os.getenv('ANTHROPIC_API_KEY')
        if api_key:
            return cls(api_key, model or "claude-3-5-sonnet-20241022")
        return None


class GeminiAdapter(LLMAdapter):
    """Google Gemini API adapter."""
    
    def __init__(self, api_key: str, model: str = "gemini-2.0-flash-exp"):
        super().__init__(api_key, model)
        from google import genai
        self.client = genai.Client(api_key=api_key)
    
    def generate(self, prompt: str, **kwargs) -> LLMResponse:
        """Generate with Gemini API."""
        response = self.client.models.generate_content(
            model=self.model,
            contents=prompt,
            **kwargs
        )
        
        # Extract token usage
        if not hasattr(response, 'usage_metadata'):
            raise RuntimeError(
                "Gemini API response missing usage_metadata. "
                "Cannot track tokens accurately."
            )
        
        metadata = response.usage_metadata
        usage = TokenUsage(
            prompt_tokens=metadata.prompt_token_count,
            completion_tokens=metadata.candidates_token_count,
            total_tokens=metadata.total_token_count,
            model=self.model,
            provider='Gemini'
        )
        
        return LLMResponse(
            content=response.text,
            usage=usage,
            raw_response=response
        )
    
    def is_available(self) -> bool:
        try:
            from google import genai
            return True
        except ImportError:
            return False
    
    @classmethod
    def from_env(cls, model: Optional[str] = None) -> Optional['GeminiAdapter']:
        api_key = os.getenv('GEMINI_API_KEY')
        if api_key:
            return cls(api_key, model or "gemini-2.0-flash-exp")
        return None


class AdapterFactory:
    """Factory for auto-detecting and creating LLM adapters."""
    
    # Registry of available adapters
    ADAPTERS = [
        OpenAIAdapter,
        AnthropicAdapter,
        GeminiAdapter,
    ]
    
    @classmethod
    def create_from_env(cls, preferred_provider: Optional[str] = None) -> Optional[LLMAdapter]:
        """
        Auto-detect and create adapter from environment variables.
        
        Args:
            preferred_provider: Provider name ('OpenAI', 'Anthropic', 'Gemini')
                               If None, auto-detects first available
        
        Returns:
            LLMAdapter instance or None if no API key found
        """
        if preferred_provider:
            for adapter_cls in cls.ADAPTERS:
                if adapter_cls.__name__.replace('Adapter', '').lower() == preferred_provider.lower():
                    adapter = adapter_cls.from_env()
                    if adapter and adapter.is_available():
                        return adapter
                    raise RuntimeError(
                        f"{preferred_provider} selected but API key not found or SDK not installed"
                    )
        
        # Auto-detect
        for adapter_cls in cls.ADAPTERS:
            adapter = adapter_cls.from_env()
            if adapter and adapter.is_available():
                return adapter
        
        return None
    
    @classmethod
    def list_available(cls) -> List[str]:
        """List providers with available API keys and SDKs."""
        available = []
        for adapter_cls in cls.ADAPTERS:
            adapter = adapter_cls.from_env()
            if adapter and adapter.is_available():
                available.append(adapter.provider_name)
        return available
    
    @classmethod
    def create(cls, provider: str, api_key: str, model: Optional[str] = None) -> LLMAdapter:
        """
        Create adapter for specific provider.
        
        Args:
            provider: Provider name ('OpenAI', 'Anthropic', 'Gemini')
            api_key: API key
            model: Model name (uses provider default if None)
        
        Returns:
            LLMAdapter instance
        """
        for adapter_cls in cls.ADAPTERS:
            if adapter_cls.__name__.replace('Adapter', '').lower() == provider.lower():
                if not adapter_cls(api_key, model or "temp").is_available():
                    raise RuntimeError(f"{provider} SDK not installed")
                return adapter_cls.from_env(model) or adapter_cls(api_key, model or "default")
        
        raise ValueError(f"Unknown provider: {provider}")


# Convenience functions
def get_adapter(provider: Optional[str] = None) -> Optional[LLMAdapter]:
    """
    Get LLM adapter from environment.
    
    Args:
        provider: Optional provider name to prefer
        
    Returns:
        LLMAdapter instance or None
    """
    return AdapterFactory.create_from_env(provider)


def list_available_providers() -> List[str]:
    """List providers with available API keys."""
    return AdapterFactory.list_available()
