#!/usr/bin/env python3
"""
{{PROJECT_NAME}} - LangChain Authority Nanos Agent

An AI agent using LangChain with Authority Kernel for secure execution.

Created: {{DATE}}
"""

import json
import os
from typing import Optional

from authority_nanos import AuthorityKernel, TypedHeap

# LangChain imports
try:
    from langchain_openai import ChatOpenAI
    from langchain.agents import AgentExecutor, create_react_agent
    from langchain.tools import Tool
    from langchain.prompts import PromptTemplate
except ImportError:
    print("Error: LangChain not installed. Run: pip install -r requirements.txt")
    raise


class SecureStateManager:
    """Manages agent state using Authority Kernel's typed heap."""

    def __init__(self, kernel: AuthorityKernel):
        self.heap = TypedHeap(kernel)
        self.handles = {}

    def save_state(self, key: str, value: dict) -> int:
        """Save state to the secure heap."""
        data = json.dumps(value).encode()
        if key in self.handles:
            # Update existing
            patch = json.dumps([{"op": "replace", "path": "/data", "value": value}]).encode()
            return self.heap.write(self.handles[key], patch)
        else:
            # Create new
            handle = self.heap.alloc(f"state:{key}", json.dumps({"data": value}).encode())
            self.handles[key] = handle
            return handle.get("version", 1)

    def load_state(self, key: str) -> Optional[dict]:
        """Load state from the secure heap."""
        if key not in self.handles:
            return None
        data = self.heap.read(self.handles[key])
        return json.loads(data.decode()).get("data")

    def delete_state(self, key: str) -> bool:
        """Delete state from the secure heap."""
        if key not in self.handles:
            return False
        self.heap.delete(self.handles[key])
        del self.handles[key]
        return True


def create_authority_tools(state_manager: SecureStateManager) -> list:
    """Create LangChain tools that use Authority Kernel."""

    def save_memory(input_str: str) -> str:
        """Save information to secure memory."""
        try:
            data = json.loads(input_str)
            key = data.get("key", "default")
            value = data.get("value", {})
            version = state_manager.save_state(key, value)
            return f"Saved to key '{key}' (version {version})"
        except json.JSONDecodeError:
            # Treat as simple key-value
            state_manager.save_state("memory", {"content": input_str})
            return "Saved to memory"

    def load_memory(key: str) -> str:
        """Load information from secure memory."""
        data = state_manager.load_state(key.strip())
        if data is None:
            return f"No data found for key '{key}'"
        return json.dumps(data)

    def clear_memory(key: str) -> str:
        """Clear information from secure memory."""
        if state_manager.delete_state(key.strip()):
            return f"Cleared key '{key}'"
        return f"Key '{key}' not found"

    return [
        Tool(
            name="save_memory",
            func=save_memory,
            description="Save information to secure memory. Input should be JSON with 'key' and 'value' fields, or plain text to save to default memory."
        ),
        Tool(
            name="load_memory",
            func=load_memory,
            description="Load information from secure memory. Input should be the key name."
        ),
        Tool(
            name="clear_memory",
            func=clear_memory,
            description="Clear information from secure memory. Input should be the key name."
        ),
    ]


def create_agent(state_manager: SecureStateManager, model_name: str = "gpt-4"):
    """Create a LangChain ReAct agent with Authority tools."""

    # Get API key from environment
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("OPENAI_API_KEY environment variable not set")

    # Create LLM
    llm = ChatOpenAI(model=model_name, temperature=0)

    # Create tools
    tools = create_authority_tools(state_manager)

    # Create prompt
    prompt = PromptTemplate.from_template("""You are an AI assistant running in a secure Authority Kernel environment.
You have access to secure memory tools that store data in the kernel's typed heap.

Available tools:
{tools}

Tool names: {tool_names}

Use the following format:

Question: the input question you must answer
Thought: you should always think about what to do
Action: the action to take, should be one of [{tool_names}]
Action Input: the input to the action
Observation: the result of the action
... (this Thought/Action/Action Input/Observation can repeat N times)
Thought: I now know the final answer
Final Answer: the final answer to the original input question

Begin!

Question: {input}
Thought: {agent_scratchpad}""")

    # Create agent
    agent = create_react_agent(llm, tools, prompt)
    return AgentExecutor(agent=agent, tools=tools, verbose=True, handle_parsing_errors=True)


def main():
    """Main entry point for the agent."""
    print("=" * 60)
    print(f"  {{PROJECT_NAME}} - LangChain Agent")
    print("  Running with Authority Kernel")
    print("=" * 60)
    print()

    # Initialize Authority Kernel
    kernel = AuthorityKernel()
    state_manager = SecureStateManager(kernel)

    print("[1] Initializing agent...")

    try:
        agent_executor = create_agent(state_manager)
    except ValueError as e:
        print(f"    Error: {e}")
        print("\n    Set your OpenAI API key:")
        print("    export OPENAI_API_KEY='your-key-here'")
        return

    print("    Agent initialized successfully!")

    # Interactive loop
    print("\n[2] Starting interactive session...")
    print("    Type 'quit' to exit\n")

    while True:
        try:
            user_input = input("You: ").strip()
            if user_input.lower() in ('quit', 'exit', 'q'):
                break
            if not user_input:
                continue

            result = agent_executor.invoke({"input": user_input})
            print(f"\nAgent: {result.get('output', 'No response')}\n")

        except KeyboardInterrupt:
            print("\n")
            break
        except Exception as e:
            print(f"\nError: {e}\n")

    print("\n" + "=" * 60)
    print("  Session ended")
    print("=" * 60)


if __name__ == "__main__":
    main()
