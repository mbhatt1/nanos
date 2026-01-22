#!/usr/bin/env python3
"""
Example 6: LangChain Agent with Authority Kernel

Demonstrates a complete LangChain agent integration with Authority Kernel
for policy-controlled LLM access and authorization.

By default, runs in simulation mode (no kernel or LangChain required).
Use --real or --kernel to run against the actual Authority Kernel with real LLM.

Key Features:
- Policy-controlled LLM inference through Authority Kernel
- Authorization checks before tool execution
- Audit logging of all agent actions
- Works without LangChain installed (simulation mode)

Usage:
  python examples/06_langchain_agent.py            # Simulation mode
  python examples/06_langchain_agent.py --real     # Real mode (requires LLM API key)
"""

import argparse
import json
import sys
from typing import Any, Dict, List, Optional

from authority_nanos import AuthorityKernel, AuthorityKernelError


# ============================================================================
# AUTHORITY-WRAPPED LLM FOR LANGCHAIN
# ============================================================================

class AuthorityLLM:
    """
    LangChain-compatible LLM that routes all calls through Authority Kernel.

    This class provides a mock LangChain LLM interface that:
    1. Routes all inference requests through Authority Kernel
    2. Checks authorization before making LLM calls
    3. Logs all interactions to the audit log
    4. Works in both simulation and real kernel modes

    Example:
        with AuthorityKernel(simulate=True) as ak:
            llm = AuthorityLLM(ak, model="gpt-4")
            response = llm.invoke("What is the capital of France?")
            print(response.content)
    """

    def __init__(self, kernel: AuthorityKernel, model: str = "gpt-4",
                 temperature: float = 0.7, max_tokens: int = 500):
        """
        Initialize Authority-wrapped LLM.

        Args:
            kernel: AuthorityKernel instance (simulated or real)
            model: Model identifier (e.g., "gpt-4", "claude-3")
            temperature: Sampling temperature (0.0 - 1.0)
            max_tokens: Maximum tokens to generate
        """
        self.kernel = kernel
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens

    def invoke(self, messages: Any) -> "LLMResponse":
        """
        Invoke the LLM with the given messages.

        Args:
            messages: Either a string prompt or list of message dicts/objects

        Returns:
            LLMResponse with the model's response
        """
        # Convert input to standard message format
        if isinstance(messages, str):
            formatted_messages = [{"role": "user", "content": messages}]
        elif isinstance(messages, list):
            formatted_messages = []
            for msg in messages:
                if isinstance(msg, dict):
                    formatted_messages.append(msg)
                elif hasattr(msg, 'content'):
                    role = getattr(msg, 'role', 'user')
                    if 'human' in str(role).lower():
                        role = 'user'
                    elif 'ai' in str(role).lower() or 'assistant' in str(role).lower():
                        role = 'assistant'
                    formatted_messages.append({
                        "role": role,
                        "content": msg.content
                    })
        else:
            formatted_messages = [{"role": "user", "content": str(messages)}]

        # Log the request to audit
        self.kernel.audit_log("llm_request", {
            "model": self.model,
            "message_count": len(formatted_messages),
            "max_tokens": self.max_tokens
        })

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
        content = ""
        if "choices" in result and result["choices"]:
            content = result["choices"][0].get("message", {}).get("content", "")
        elif "content" in result:
            content = result["content"]

        # Log the response
        self.kernel.audit_log("llm_response", {
            "model": self.model,
            "content_length": len(content),
            "simulated": result.get("simulated", False)
        })

        return LLMResponse(content=content, raw=result)


class LLMResponse:
    """Response from Authority-wrapped LLM."""

    def __init__(self, content: str, raw: dict = None):
        self.content = content
        self.raw = raw or {}

    def __str__(self):
        return self.content


# ============================================================================
# AUTHORITY TOOL WRAPPER
# ============================================================================

class AuthorityTool:
    """
    Tool that executes through Authority Kernel with policy checks.

    Example:
        calculator = AuthorityTool(
            kernel=ak,
            name="calculator",
            description="Performs basic math",
            func=lambda x: eval(x)  # Simplified example
        )
    """

    def __init__(self, kernel: AuthorityKernel, name: str,
                 description: str, func: callable):
        self.kernel = kernel
        self.name = name
        self.description = description
        self._func = func

    def run(self, input_str: str) -> str:
        """Execute the tool with authorization check."""
        # Check authorization
        if not self.kernel.authorize("tool", self.name):
            return f"Error: Tool '{self.name}' not authorized by policy"

        # Log tool execution
        self.kernel.audit_log("tool_execute", {
            "tool": self.name,
            "input_preview": input_str[:100] if len(input_str) > 100 else input_str
        })

        try:
            result = self._func(input_str)
            return str(result)
        except Exception as e:
            return f"Error executing tool: {e}"


# ============================================================================
# SIMPLE AGENT IMPLEMENTATION
# ============================================================================

class SimpleAgent:
    """
    Simple agent that uses Authority Kernel for LLM and tool execution.

    This demonstrates the pattern for building agents with Authority Kernel:
    1. LLM calls go through AuthorityLLM
    2. Tool executions go through AuthorityTool
    3. All actions are logged to audit

    Example:
        with AuthorityKernel(simulate=True) as ak:
            agent = SimpleAgent(ak)
            result = agent.run("What is 2 + 2?")
    """

    def __init__(self, kernel: AuthorityKernel, model: str = "gpt-4"):
        self.kernel = kernel
        self.llm = AuthorityLLM(kernel, model=model)
        self.tools: List[AuthorityTool] = []
        self.memory: List[Dict] = []

    def add_tool(self, name: str, description: str, func: callable):
        """Add a tool to the agent."""
        tool = AuthorityTool(self.kernel, name, description, func)
        self.tools.append(tool)

    def run(self, task: str, verbose: bool = True) -> str:
        """
        Run the agent on a task.

        Args:
            task: The task/question to process
            verbose: Print progress information

        Returns:
            The agent's final response
        """
        if verbose:
            print(f"\n[Agent] Starting task: {task}")

        # Log task start
        self.kernel.audit_log("agent_task_start", {"task": task})

        # Build system prompt
        tool_descriptions = "\n".join([
            f"- {t.name}: {t.description}" for t in self.tools
        ])

        system_prompt = f"""You are a helpful AI assistant with access to these tools:
{tool_descriptions if self.tools else "(No tools available)"}

Answer the user's question. If you need to use a tool, respond with:
TOOL: tool_name
INPUT: tool_input

Otherwise, provide your answer directly."""

        # Send to LLM
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": task}
        ]

        response = self.llm.invoke(messages)

        if verbose:
            print(f"[Agent] LLM response: {response.content[:100]}...")

        # Check if agent wants to use a tool
        response_text = response.content
        if "TOOL:" in response_text:
            # Parse tool request
            lines = response_text.split("\n")
            tool_name = None
            tool_input = None

            for line in lines:
                if line.startswith("TOOL:"):
                    tool_name = line.replace("TOOL:", "").strip()
                elif line.startswith("INPUT:"):
                    tool_input = line.replace("INPUT:", "").strip()

            if tool_name and tool_input:
                # Find and execute tool
                tool = next((t for t in self.tools if t.name == tool_name), None)
                if tool:
                    if verbose:
                        print(f"[Agent] Using tool: {tool_name}")
                    tool_result = tool.run(tool_input)
                    if verbose:
                        print(f"[Agent] Tool result: {tool_result}")

                    # Get final response with tool result
                    messages.append({"role": "assistant", "content": response_text})
                    messages.append({"role": "user", "content": f"Tool result: {tool_result}"})

                    final_response = self.llm.invoke(messages)
                    response_text = final_response.content

        # Log task completion
        self.kernel.audit_log("agent_task_complete", {
            "task": task,
            "response_length": len(response_text)
        })

        if verbose:
            print(f"[Agent] Final response: {response_text}")

        return response_text


# ============================================================================
# MAIN EXAMPLE
# ============================================================================

def run_langchain_agent_example(simulate: bool = True):
    """Run the LangChain agent example."""
    mode = "SIMULATION" if simulate else "REAL KERNEL"
    print(f"\n=== LangChain Agent Example ({mode} mode) ===\n")

    try:
        with AuthorityKernel(simulate=simulate) as ak:
            print("[+] Connected to Authority Kernel")
            print(f"[+] Simulated: {ak.is_simulated()}")

            # Create agent
            print("\n--- Creating Agent ---")
            agent = SimpleAgent(ak, model="gpt-4")

            # Add some tools
            def calculator(expr: str) -> str:
                """Simple calculator - evaluate math expressions."""
                try:
                    # Only allow simple math for safety
                    allowed = set("0123456789+-*/.() ")
                    if not all(c in allowed for c in expr):
                        return "Error: Invalid characters in expression"
                    return str(eval(expr))
                except Exception as e:
                    return f"Error: {e}"

            def get_time(input_str: str) -> str:
                """Get current time."""
                from datetime import datetime
                return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            agent.add_tool("calculator", "Performs basic math operations", calculator)
            agent.add_tool("get_time", "Gets the current date and time", get_time)

            print("[+] Agent created with tools: calculator, get_time")

            # Run some tasks
            print("\n--- Running Agent Tasks ---")

            # Task 1: Simple question
            print("\n[Task 1] Simple question")
            result1 = agent.run("What is the capital of France?")

            # Task 2: Math question (might use calculator)
            print("\n[Task 2] Math question")
            result2 = agent.run("What is 15 * 7?")

            # Task 3: Time question
            print("\n[Task 3] Time question")
            result3 = agent.run("What time is it now?")

            # Show audit log
            print("\n--- Audit Log Summary ---")
            logs = ak.audit_logs()
            print(f"[+] Total audit entries: {len(logs)}")

            # Show last few entries
            for log_entry in logs[-5:]:
                try:
                    entry = json.loads(log_entry.decode('utf-8'))
                    print(f"  - {entry.get('event')}: {list(entry.keys())}")
                except:
                    pass

            print("\n[+] LangChain agent example completed!")
            return True

    except AuthorityKernelError as e:
        print(f"[-] Kernel error: {e}")
        return False
    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="LangChain Agent with Authority Kernel"
    )
    parser.add_argument("--real", "--kernel", action="store_true",
                        help="Use real kernel instead of simulation")
    args = parser.parse_args()

    simulate = not args.real

    success = run_langchain_agent_example(simulate)

    if simulate:
        print("\n[i] Running in simulation mode. Use --real for actual kernel.")

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
