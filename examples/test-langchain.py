#!/usr/bin/env python3
"""
Authority Kernel - LangChain Integration Test

This example demonstrates LangChain running with Authority Kernel authorization.
Supports both simulation mode (default) and real kernel mode.

Simulation Mode (default):
  python examples/test-langchain.py
  python examples/test-langchain.py --sim

Real Kernel Mode (requires kernel running):
  python examples/test-langchain.py --real
  minops run examples/test-langchain.py --allow-llm -c examples/llm-config.json

The config file should contain your API key:
  {"Env": {"OPENAI_API_KEY": "sk-..."}}
"""

import argparse
import json
import os
import sys

# Authority Nanos SDK - always available
from authority_nanos import AuthorityKernel, AuthorityKernelError

# ============================================================================
# MOCK LANGCHAIN CLASSES (for simulation mode without langchain installed)
# ============================================================================

class MockHumanMessage:
    """Mock HumanMessage for simulation mode."""
    def __init__(self, content: str):
        self.content = content
        self.role = "human"


class MockAIMessage:
    """Mock AIMessage for simulation mode."""
    def __init__(self, content: str):
        self.content = content
        self.role = "assistant"


class MockChatOpenAI:
    """Mock ChatOpenAI LLM that uses Authority Kernel simulator."""

    def __init__(self, kernel: AuthorityKernel, model: str = "gpt-3.5-turbo",
                 temperature: float = 0, max_tokens: int = 100):
        self.kernel = kernel
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens

    def invoke(self, messages):
        """Invoke the LLM through Authority Kernel."""
        # Convert messages to standard format
        formatted_messages = []
        for msg in messages:
            if hasattr(msg, 'content'):
                role = getattr(msg, 'role', 'user')
                if 'human' in role.lower() or 'user' in role.lower():
                    role = 'user'
                formatted_messages.append({
                    "role": role,
                    "content": msg.content
                })
            elif isinstance(msg, dict):
                formatted_messages.append(msg)

        # Build inference request
        request = json.dumps({
            "model": self.model,
            "messages": formatted_messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens
        }).encode()

        # Call through Authority Kernel
        response = self.kernel.inference(request)
        result = json.loads(response.decode('utf-8'))

        # Extract content from response
        content = ""
        if "choices" in result and result["choices"]:
            content = result["choices"][0].get("message", {}).get("content", "")
        elif "content" in result:
            content = result["content"]

        return MockAIMessage(content=content)


# ============================================================================
# TRY TO IMPORT REAL LANGCHAIN (graceful degradation)
# ============================================================================

LANGCHAIN_AVAILABLE = False
HumanMessage = MockHumanMessage
ChatOpenAI = None

try:
    from langchain_core.messages import HumanMessage as RealHumanMessage
    HumanMessage = RealHumanMessage
    LANGCHAIN_AVAILABLE = True
except ImportError:
    pass

try:
    from langchain_openai import ChatOpenAI as RealChatOpenAI
    if LANGCHAIN_AVAILABLE:
        ChatOpenAI = RealChatOpenAI
except ImportError:
    pass


# ============================================================================
# TEST FUNCTIONS
# ============================================================================

def test_imports(simulate: bool):
    """Test that required packages are available."""
    print("Testing imports...")

    results = []

    # Authority Nanos SDK - always required
    print("  [OK] authority_nanos")
    results.append(True)

    if simulate:
        print("  [OK] Using mock LangChain (simulation mode)")
        return True

    # Real mode requires actual packages
    try:
        import requests
        print("  [OK] requests")
        results.append(True)
    except ImportError as e:
        print(f"  [FAIL] requests: {e}")
        results.append(False)

    try:
        import httpx
        print("  [OK] httpx")
        results.append(True)
    except ImportError as e:
        print(f"  [FAIL] httpx: {e}")
        results.append(False)

    try:
        import pydantic
        print("  [OK] pydantic")
        results.append(True)
    except ImportError as e:
        print(f"  [FAIL] pydantic: {e}")
        results.append(False)

    try:
        import openai
        print("  [OK] openai")
        results.append(True)
    except ImportError as e:
        print(f"  [FAIL] openai: {e}")
        results.append(False)

    try:
        from langchain_core.messages import HumanMessage
        print("  [OK] langchain_core")
        results.append(True)
    except ImportError as e:
        print(f"  [FAIL] langchain_core: {e}")
        results.append(False)

    try:
        from langchain_openai import ChatOpenAI
        print("  [OK] langchain_openai")
        results.append(True)
    except ImportError as e:
        print(f"  [FAIL] langchain_openai: {e}")
        results.append(False)

    print()
    return all(results)


def test_ssl_certs():
    """Test that SSL certificates are available."""
    print("Testing SSL certificates...")

    cert_paths = [
        os.environ.get("SSL_CERT_FILE", "/etc/ssl/cert.pem"),
        os.environ.get("SSL_CERT_DIR", "/etc/ssl/certs"),
        os.environ.get("REQUESTS_CA_BUNDLE", "/etc/ssl/cert.pem"),
    ]

    for path in cert_paths:
        if os.path.exists(path):
            print(f"  [OK] {path}")
        else:
            print(f"  [MISSING] {path}")

    print()
    return True


def test_authority_kernel(simulate: bool):
    """Test Authority Kernel connectivity."""
    print("Testing Authority Kernel...")

    mode = "simulation" if simulate else "real"
    print(f"  Mode: {mode}")

    try:
        with AuthorityKernel(simulate=simulate) as ak:
            # Basic alloc/read test
            handle = ak.alloc("test", b'{"status": "ok"}')
            data = ak.read(handle)
            print(f"  [OK] Kernel operations working")

            # Test authorization
            authorized = ak.authorize("read", "/tmp/test.txt")
            print(f"  [OK] Authorization check: {'allowed' if authorized else 'denied'}")

            return True
    except Exception as e:
        print(f"  [FAIL] Kernel error: {e}")
        return False


def test_langchain_simulation(ak: AuthorityKernel):
    """Test LangChain with simulated kernel."""
    print("\nTesting LangChain with Simulated LLM...")

    try:
        # Create mock LLM using Authority Kernel
        llm = MockChatOpenAI(kernel=ak, model="gpt-4", max_tokens=100)

        print("  [+] Created MockChatOpenAI with Authority Kernel")

        # Test simple message
        print("  [+] Sending test message...")
        response = llm.invoke([
            MockHumanMessage(content="What is 2 + 2?")
        ])

        print(f"  [OK] Response: {response.content}")
        return True

    except Exception as e:
        print(f"  [FAIL] {e}")
        import traceback
        traceback.print_exc()
        return False


def test_network_connectivity():
    """Test basic HTTPS connectivity to OpenAI."""
    print("\nTesting network connectivity...")

    try:
        import requests
    except ImportError:
        print("  [SKIP] requests not installed")
        return True

    try:
        # Just test we can reach the API (will fail auth, but that's OK)
        response = requests.get(
            "https://api.openai.com/v1/models",
            headers={"Authorization": "Bearer test"},
            timeout=10
        )
        # 401 means we reached the server (auth failed, but network works)
        if response.status_code == 401:
            print("  [OK] Reached api.openai.com (auth expected to fail)")
            return True
        else:
            print(f"  [OK] Reached api.openai.com (status: {response.status_code})")
            return True
    except Exception as e:
        print(f"  [FAIL] Connection error: {e}")
        print("  Make sure you're running with --allow-llm flag")
        return False


def test_langchain_openai(simulate: bool):
    """Test LangChain with OpenAI."""
    print("\nTesting LangChain with OpenAI...")

    if simulate:
        print("  [SKIP] Skipping real OpenAI test in simulation mode")
        return True

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("  [SKIP] OPENAI_API_KEY not set")
        print("  To test, create a config file with:")
        print('    {"Env": {"OPENAI_API_KEY": "sk-..."}}')
        return True

    if api_key == "sk-test" or api_key.startswith("sk-test"):
        print("  [SKIP] Using test API key, skipping actual API call")
        return True

    if ChatOpenAI is None:
        print("  [SKIP] langchain_openai not installed")
        return True

    try:
        print("  Creating ChatOpenAI instance...")
        llm = ChatOpenAI(
            model="gpt-3.5-turbo",
            temperature=0,
            max_tokens=50
        )

        print("  Sending test message...")
        response = llm.invoke([
            HumanMessage(content="Say 'Hello from Authority Kernel!' and nothing else.")
        ])

        print(f"  [OK] Response: {response.content}")
        return True

    except Exception as e:
        print(f"  [FAIL] {e}")
        return False


def test_langchain_anthropic(simulate: bool):
    """Test LangChain with Anthropic."""
    print("\nTesting LangChain with Anthropic...")

    if simulate:
        print("  [SKIP] Skipping real Anthropic test in simulation mode")
        return True

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("  [SKIP] ANTHROPIC_API_KEY not set")
        return True

    try:
        from langchain_anthropic import ChatAnthropic

        print("  Creating ChatAnthropic instance...")
        llm = ChatAnthropic(
            model="claude-3-haiku-20240307",
            temperature=0,
            max_tokens=50
        )

        print("  Sending test message...")
        response = llm.invoke([
            HumanMessage(content="Say 'Hello from Authority Kernel!' and nothing else.")
        ])

        print(f"  [OK] Response: {response.content}")
        return True

    except ImportError:
        print("  [SKIP] langchain_anthropic not installed")
        return True
    except Exception as e:
        print(f"  [FAIL] {e}")
        return False


def main():
    """Main entry point."""
    # Parse arguments
    parser = argparse.ArgumentParser(
        description="Authority Kernel - LangChain Integration Test"
    )
    parser.add_argument("--sim", action="store_true", default=True,
                        help="Run in simulation mode (default)")
    parser.add_argument("--real", action="store_true",
                        help="Run with real kernel and LLM APIs")
    args = parser.parse_args()

    # Determine mode
    simulate = not args.real
    mode = "SIMULATION" if simulate else "REAL"

    print("=" * 60)
    print(f"Authority Kernel - LangChain Integration Test ({mode} MODE)")
    print("=" * 60)
    print()

    # Show environment
    print("Environment:")
    print(f"  Python: {sys.version.split()[0]}")
    print(f"  Mode: {mode}")
    print(f"  LangChain Available: {LANGCHAIN_AVAILABLE}")
    if not simulate:
        print(f"  SSL_CERT_FILE: {os.environ.get('SSL_CERT_FILE', '(not set)')}")
        print(f"  OPENAI_API_KEY: {'set' if os.environ.get('OPENAI_API_KEY') else 'not set'}")
        print(f"  ANTHROPIC_API_KEY: {'set' if os.environ.get('ANTHROPIC_API_KEY') else 'not set'}")
    print()

    results = []

    # Run tests
    results.append(("Imports", test_imports(simulate)))

    if not simulate:
        results.append(("SSL Certs", test_ssl_certs()))

    results.append(("Authority Kernel", test_authority_kernel(simulate)))

    if simulate:
        # Simulation mode - use mock LLM
        try:
            with AuthorityKernel(simulate=True) as ak:
                results.append(("LangChain+Simulation", test_langchain_simulation(ak)))
        except Exception as e:
            results.append(("LangChain+Simulation", False))
            print(f"  [FAIL] {e}")
    else:
        # Real mode - test network and real APIs
        results.append(("Network", test_network_connectivity()))
        results.append(("LangChain+OpenAI", test_langchain_openai(simulate)))
        results.append(("LangChain+Anthropic", test_langchain_anthropic(simulate)))

    # Summary
    print("\n" + "=" * 60)
    print("Summary:")
    print("=" * 60)

    all_passed = True
    for name, passed in results:
        status = "PASS" if passed else "FAIL"
        print(f"  {name}: {status}")
        if not passed:
            all_passed = False

    print()
    if all_passed:
        if simulate:
            print("All tests passed! LangChain simulation working.")
            print("Run with --real to test actual LLM APIs.")
        else:
            print("All tests passed! LangChain is working with Authority Kernel.")
    else:
        print("Some tests failed. Check the output above for details.")

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
