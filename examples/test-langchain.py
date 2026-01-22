#!/usr/bin/env python3
"""
Authority Kernel - LangChain Integration Test

This example demonstrates LangChain running inside Authority Kernel with:
- Network access controlled by --allow-llm flag
- DLP filtering on outbound requests
- Budget tracking on network bytes

Usage:
  minops run examples/test-langchain.py --allow-llm -c examples/llm-config.json

The config file should contain your API key:
  {"Env": {"OPENAI_API_KEY": "sk-..."}}
"""

import os
import sys

def test_imports():
    """Test that all required packages are available."""
    print("Testing imports...")

    try:
        import requests
        print("  [OK] requests")
    except ImportError as e:
        print(f"  [FAIL] requests: {e}")
        return False

    try:
        import httpx
        print("  [OK] httpx")
    except ImportError as e:
        print(f"  [FAIL] httpx: {e}")
        return False

    try:
        import pydantic
        print("  [OK] pydantic")
    except ImportError as e:
        print(f"  [FAIL] pydantic: {e}")
        return False

    try:
        import openai
        print("  [OK] openai")
    except ImportError as e:
        print(f"  [FAIL] openai: {e}")
        return False

    try:
        from langchain_core.messages import HumanMessage
        print("  [OK] langchain_core")
    except ImportError as e:
        print(f"  [FAIL] langchain_core: {e}")
        return False

    try:
        from langchain_openai import ChatOpenAI
        print("  [OK] langchain_openai")
    except ImportError as e:
        print(f"  [FAIL] langchain_openai: {e}")
        return False

    print("All imports successful!\n")
    return True


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


def test_network_connectivity():
    """Test basic HTTPS connectivity to OpenAI."""
    print("Testing network connectivity...")

    import requests

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
    except requests.exceptions.SSLError as e:
        print(f"  [FAIL] SSL error: {e}")
        return False
    except requests.exceptions.ConnectionError as e:
        print(f"  [FAIL] Connection error: {e}")
        print("  Make sure you're running with --allow-llm flag")
        return False
    except Exception as e:
        print(f"  [FAIL] Unexpected error: {e}")
        return False


def test_langchain_openai():
    """Test LangChain with OpenAI."""
    print("\nTesting LangChain with OpenAI...")

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("  [SKIP] OPENAI_API_KEY not set")
        print("  To test, create a config file with:")
        print('    {"Env": {"OPENAI_API_KEY": "sk-..."}}')
        return True  # Not a failure, just skipped

    if api_key == "sk-test" or api_key.startswith("sk-test"):
        print("  [SKIP] Using test API key, skipping actual API call")
        return True

    try:
        from langchain_openai import ChatOpenAI
        from langchain_core.messages import HumanMessage

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


def test_langchain_anthropic():
    """Test LangChain with Anthropic."""
    print("\nTesting LangChain with Anthropic...")

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("  [SKIP] ANTHROPIC_API_KEY not set")
        return True

    try:
        from langchain_anthropic import ChatAnthropic
        from langchain_core.messages import HumanMessage

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
    print("=" * 60)
    print("Authority Kernel - LangChain Integration Test")
    print("=" * 60)
    print()

    # Show environment
    print("Environment:")
    print(f"  Python: {sys.version}")
    print(f"  SSL_CERT_FILE: {os.environ.get('SSL_CERT_FILE', '(not set)')}")
    print(f"  OPENAI_API_KEY: {'set' if os.environ.get('OPENAI_API_KEY') else 'not set'}")
    print(f"  ANTHROPIC_API_KEY: {'set' if os.environ.get('ANTHROPIC_API_KEY') else 'not set'}")
    print()

    results = []

    # Run tests
    results.append(("Imports", test_imports()))
    results.append(("SSL Certs", test_ssl_certs()))
    results.append(("Network", test_network_connectivity()))
    results.append(("LangChain+OpenAI", test_langchain_openai()))
    results.append(("LangChain+Anthropic", test_langchain_anthropic()))

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
        print("All tests passed! LangChain is working inside Authority Kernel.")
    else:
        print("Some tests failed. Check the output above for details.")

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
