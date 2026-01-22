#!/usr/bin/env python3
"""
Example 4: LLM Inference

Demonstrates sending inference requests to an LLM through the Authority Kernel's
policy-controlled gateway.

By default, runs in simulation mode (no kernel required).
Use --real or --kernel to run against the actual Authority Kernel.

In simulation mode, inference requests return a simulated response that
echoes part of the prompt. Real inference requires LLM configuration.
"""

import argparse
import json
import sys

from authority_nanos import AuthorityKernel, AuthorityKernelError


def main():
    """LLM inference example."""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="LLM inference example")
    parser.add_argument("--real", "--kernel", action="store_true",
                        help="Use real kernel instead of simulation")
    args = parser.parse_args()

    # Determine mode
    simulate = not args.real
    mode = "SIMULATION" if simulate else "REAL KERNEL"
    print(f"=== LLM Inference Example ({mode} mode) ===\n")

    try:
        with AuthorityKernel(simulate=simulate) as ak:
            print("[+] Connected to Authority Kernel")

            # Send inference request
            print("\n--- Sending Inference Request ---")
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
                print(f"[+] Inference request processed")
                print(f"[+] Response:")
                print(json.dumps(result, indent=2))

                if result.get("simulated"):
                    print("\n[i] Note: This is a simulated response")
                    print("[i] Real inference requires LLM configuration")

            except Exception as e:
                print(f"[i] Inference (expected if LLM not configured): {e}")

            # Try another inference with different format
            print("\n--- Second Inference Request ---")
            inference_request2 = json.dumps({
                "model": "claude-3",
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a helpful assistant."
                    },
                    {
                        "role": "user",
                        "content": "Explain Authority Kernel in one sentence."
                    }
                ],
                "max_tokens": 50
            }).encode()

            try:
                response = ak.inference(inference_request2)
                result = json.loads(response.decode('utf-8'))
                print(f"[+] Second inference processed")

                # Extract and display the assistant's message
                if "choices" in result:
                    message = result["choices"][0].get("message", {}).get("content", "")
                    print(f"[+] Assistant: {message}")

            except Exception as e:
                print(f"[i] Inference (expected if LLM not configured): {e}")

            print("\n[+] Inference examples completed!")

    except AuthorityKernelError as e:
        print(f"[-] Kernel error: {e}")
        return 1
    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
