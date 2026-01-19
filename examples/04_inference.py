#!/usr/bin/env python3
"""
Example 4: LLM Inference

Demonstrates sending inference requests to an LLM through the Authority Kernel's
policy-controlled gateway.
"""

import sys
import json
from pathlib import Path

# Add SDK to path
sys.path.insert(0, str(Path(__file__).parent.parent / "sdk/python"))

from authority_nanos import AuthorityKernel, AuthorityKernelError


def main():
    """LLM inference example."""
    try:
        # libak.so location is determined by LIBAK_PATH env var or SDK defaults
        with AuthorityKernel() as ak:
            print("✅ Connected to Authority Kernel")

            # Send inference request
            inference_request = json.dumps({
                "model": "gpt-4",
                "messages": [
                    {
                        "role": "user",
                        "content": "What is 2 + 2?"
                    }
                ],
                "temperature": 0.7,
                "max_tokens": 100
            }).encode()

            try:
                response = ak.inference(inference_request)
                result = json.loads(response.decode('utf-8'))
                print(f"✅ Inference request processed")
                print(f"✅ Response: {json.dumps(result, indent=2)}")
            except Exception as e:
                print(f"ℹ️  Inference (expected if LLM not configured): {e}")

    except AuthorityKernelError as e:
        print(f"❌ Kernel error: {e}")
        return 1
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
