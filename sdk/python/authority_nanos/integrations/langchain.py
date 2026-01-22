"""
LangChain Integration for Authority Kernel.

This module provides LangChain-compatible classes that route all LLM
operations through the Authority Kernel for policy-controlled access.

Key Classes:
- AuthorityLLM: LangChain-compatible LLM that uses Authority Kernel
- LLMResponse: Response object from AuthorityLLM

Example Usage:

    from authority_nanos import AuthorityKernel
    from authority_nanos.integrations.langchain import AuthorityLLM

    # Basic usage with simulation
    with AuthorityKernel(simulate=True) as ak:
        llm = AuthorityLLM(ak, model="gpt-4")

        # Simple string prompt
        response = llm.invoke("What is the capital of France?")
        print(response.content)

        # With message objects (LangChain style)
        from langchain_core.messages import HumanMessage, SystemMessage
        response = llm.invoke([
            SystemMessage(content="You are a helpful assistant."),
            HumanMessage(content="What is 2 + 2?")
        ])
        print(response.content)

    # With real kernel
    with AuthorityKernel() as ak:  # Real kernel
        llm = AuthorityLLM(ak, model="gpt-4")
        response = llm.invoke("Hello!")

Features:
- Routes all LLM calls through Authority Kernel
- Automatic audit logging of requests and responses
- Works with LangChain message types (HumanMessage, AIMessage, etc.)
- Graceful degradation when LangChain is not installed
- Compatible with both simulation and real kernel modes
"""

import json
import logging
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)


class LLMResponse:
    """
    Response from Authority-wrapped LLM.

    Attributes:
        content: The text content of the response
        raw: The raw response dict from the kernel
        model: The model that generated the response
        usage: Token usage information (if available)

    Example:
        response = llm.invoke("Hello")
        print(response.content)  # "Hello! How can I help?"
        print(response.usage)    # {"prompt_tokens": 1, "completion_tokens": 5}
    """

    def __init__(self, content: str, raw: dict = None, model: str = ""):
        """
        Initialize LLM response.

        Args:
            content: The text content of the response
            raw: Raw response dictionary from kernel
            model: Model identifier
        """
        self.content = content
        self.raw = raw or {}
        self.model = model
        self.usage = self.raw.get("usage", {})

    def __str__(self):
        return self.content

    def __repr__(self):
        return f"LLMResponse(content='{self.content[:50]}...', model='{self.model}')"

    @property
    def role(self) -> str:
        """Get the role (always 'assistant' for LLM responses)."""
        return "assistant"


class AuthorityLLM:
    """
    LangChain-compatible LLM that routes calls through Authority Kernel.

    This class provides a drop-in replacement for LangChain LLMs that:
    1. Routes all inference requests through Authority Kernel
    2. Checks authorization before making LLM calls
    3. Logs all interactions to the audit log
    4. Works in both simulation and real kernel modes

    Attributes:
        kernel: The AuthorityKernel instance
        model: Model identifier (e.g., "gpt-4", "claude-3")
        temperature: Sampling temperature (0.0 - 1.0)
        max_tokens: Maximum tokens to generate

    Example:
        from authority_nanos import AuthorityKernel
        from authority_nanos.integrations.langchain import AuthorityLLM

        with AuthorityKernel(simulate=True) as ak:
            llm = AuthorityLLM(ak, model="gpt-4", temperature=0.7)

            # Simple invocation
            response = llm.invoke("What is machine learning?")
            print(response.content)

            # With chat history
            response = llm.invoke([
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "What is 2 + 2?"}
            ])

            # Check if response was simulated
            if response.raw.get("simulated"):
                print("This was a simulated response")
    """

    def __init__(
        self,
        kernel: "AuthorityKernel",
        model: str = "gpt-4",
        temperature: float = 0.7,
        max_tokens: int = 500,
        **kwargs
    ):
        """
        Initialize Authority-wrapped LLM.

        Args:
            kernel: AuthorityKernel instance (simulated or real)
            model: Model identifier (e.g., "gpt-4", "claude-3", "gpt-3.5-turbo")
            temperature: Sampling temperature (0.0 - 1.0, default 0.7)
            max_tokens: Maximum tokens to generate (default 500)
            **kwargs: Additional arguments (ignored, for compatibility)
        """
        self.kernel = kernel
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self._extra_kwargs = kwargs

        logger.debug(f"AuthorityLLM initialized: model={model}, temp={temperature}")

    def invoke(self, messages: Any) -> LLMResponse:
        """
        Invoke the LLM with the given messages.

        This method accepts multiple input formats:
        - String: Treated as a single user message
        - List of dicts: Standard OpenAI message format
        - List of LangChain message objects: HumanMessage, AIMessage, etc.

        Args:
            messages: Input prompt or messages in various formats

        Returns:
            LLMResponse with the model's response

        Raises:
            AuthorityKernelError: If kernel operation fails

        Example:
            # String input
            response = llm.invoke("Hello!")

            # Dict list input
            response = llm.invoke([
                {"role": "user", "content": "Hello!"}
            ])

            # LangChain message objects
            from langchain_core.messages import HumanMessage
            response = llm.invoke([HumanMessage(content="Hello!")])
        """
        # Convert input to standard message format
        formatted_messages = self._format_messages(messages)

        # Log the request to audit
        self.kernel.audit_log("llm_request", {
            "model": self.model,
            "message_count": len(formatted_messages),
            "max_tokens": self.max_tokens,
            "temperature": self.temperature
        })

        logger.debug(f"Sending {len(formatted_messages)} messages to {self.model}")

        # Build and send inference request through kernel
        request = json.dumps({
            "model": self.model,
            "messages": formatted_messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens
        }).encode()

        response = self.kernel.inference(request)
        result = json.loads(response.decode('utf-8'))

        # Extract content from response
        content = self._extract_content(result)

        # Log the response
        self.kernel.audit_log("llm_response", {
            "model": self.model,
            "content_length": len(content),
            "simulated": result.get("simulated", False)
        })

        logger.debug(f"Received response: {len(content)} chars")

        return LLMResponse(content=content, raw=result, model=self.model)

    def _format_messages(self, messages: Any) -> List[Dict[str, str]]:
        """
        Convert various message formats to standard OpenAI format.

        Args:
            messages: Input in any supported format

        Returns:
            List of message dicts with 'role' and 'content' keys
        """
        if isinstance(messages, str):
            return [{"role": "user", "content": messages}]

        if not isinstance(messages, list):
            return [{"role": "user", "content": str(messages)}]

        formatted = []
        for msg in messages:
            if isinstance(msg, dict):
                # Already in dict format
                formatted.append({
                    "role": msg.get("role", "user"),
                    "content": msg.get("content", "")
                })
            elif hasattr(msg, 'content'):
                # LangChain message object
                role = self._get_message_role(msg)
                formatted.append({
                    "role": role,
                    "content": str(msg.content)
                })
            else:
                # Unknown format, convert to string
                formatted.append({
                    "role": "user",
                    "content": str(msg)
                })

        return formatted

    def _get_message_role(self, msg: Any) -> str:
        """
        Determine the role from a LangChain message object.

        Args:
            msg: LangChain message object

        Returns:
            Role string: 'user', 'assistant', or 'system'
        """
        # Check type attribute
        if hasattr(msg, 'type'):
            type_str = str(msg.type).lower()
            if 'human' in type_str or 'user' in type_str:
                return 'user'
            elif 'ai' in type_str or 'assistant' in type_str:
                return 'assistant'
            elif 'system' in type_str:
                return 'system'

        # Check role attribute
        if hasattr(msg, 'role'):
            role_str = str(msg.role).lower()
            if 'human' in role_str or 'user' in role_str:
                return 'user'
            elif 'ai' in role_str or 'assistant' in role_str:
                return 'assistant'
            elif 'system' in role_str:
                return 'system'

        # Check class name
        class_name = msg.__class__.__name__.lower()
        if 'human' in class_name or 'user' in class_name:
            return 'user'
        elif 'ai' in class_name or 'assistant' in class_name:
            return 'assistant'
        elif 'system' in class_name:
            return 'system'

        # Default to user
        return 'user'

    def _extract_content(self, result: dict) -> str:
        """
        Extract content from LLM response.

        Args:
            result: Raw response dictionary

        Returns:
            Extracted text content
        """
        # OpenAI format
        if "choices" in result and result["choices"]:
            choice = result["choices"][0]
            if "message" in choice:
                return choice["message"].get("content", "")
            elif "text" in choice:
                return choice["text"]

        # Anthropic format
        if "content" in result:
            content = result["content"]
            if isinstance(content, list) and content:
                return content[0].get("text", "")
            return str(content)

        # Simple format
        if "text" in result:
            return result["text"]

        return ""

    def __repr__(self):
        return f"AuthorityLLM(model='{self.model}', temp={self.temperature})"


# ============================================================================
# OPTIONAL: LangChain BaseLLM Integration
# ============================================================================

# Try to import LangChain for proper integration
try:
    from langchain_core.language_models.llms import BaseLLM
    from langchain_core.callbacks.manager import CallbackManagerForLLMRun
    from langchain_core.outputs import Generation, LLMResult
    from pydantic import Field

    class AuthorityLangChainLLM(BaseLLM):
        """
        Full LangChain BaseLLM implementation for Authority Kernel.

        This class provides complete LangChain integration including:
        - Streaming support
        - Callback integration
        - Batch processing

        Only available when langchain is installed.

        Example:
            from authority_nanos import AuthorityKernel
            from authority_nanos.integrations.langchain import AuthorityLangChainLLM

            with AuthorityKernel(simulate=True) as ak:
                llm = AuthorityLangChainLLM(kernel=ak, model="gpt-4")

                # Use as standard LangChain LLM
                result = llm.invoke("Hello!")

                # With chains
                from langchain.chains import LLMChain
                chain = LLMChain(llm=llm, prompt=my_prompt)
        """

        kernel: Any = Field(description="AuthorityKernel instance")
        model: str = Field(default="gpt-4")
        temperature: float = Field(default=0.7)
        max_tokens: int = Field(default=500)

        @property
        def _llm_type(self) -> str:
            return "authority_kernel"

        def _call(
            self,
            prompt: str,
            stop: Optional[List[str]] = None,
            run_manager: Optional[CallbackManagerForLLMRun] = None,
            **kwargs
        ) -> str:
            """Execute LLM call through Authority Kernel."""
            # Build request
            request = json.dumps({
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": self.temperature,
                "max_tokens": self.max_tokens,
                "stop": stop
            }).encode()

            # Call through kernel
            response = self.kernel.inference(request)
            result = json.loads(response.decode('utf-8'))

            # Extract content
            content = ""
            if "choices" in result and result["choices"]:
                content = result["choices"][0].get("message", {}).get("content", "")

            return content

        @property
        def _identifying_params(self) -> Dict[str, Any]:
            return {
                "model": self.model,
                "temperature": self.temperature,
                "max_tokens": self.max_tokens
            }

    # Export the LangChain-native class
    __all__ = ["AuthorityLLM", "LLMResponse", "AuthorityLangChainLLM"]

except ImportError:
    # LangChain not installed, only basic integration available
    AuthorityLangChainLLM = None
    __all__ = ["AuthorityLLM", "LLMResponse"]

    logger.debug("LangChain not installed, using basic AuthorityLLM only")
