#!/usr/bin/env python3
"""
{{PROJECT_NAME}} - CrewAI Multi-Agent System

A multi-agent system using CrewAI with Authority Kernel for secure execution.

Created: {{DATE}}
"""

import json
import os
from typing import Optional

from authority_nanos import AuthorityKernel, TypedHeap

# CrewAI imports
try:
    from crewai import Agent, Task, Crew, Process
    from crewai.tools import tool
    from langchain_openai import ChatOpenAI
except ImportError:
    print("Error: CrewAI not installed. Run: pip install -r requirements.txt")
    raise


class SharedMemory:
    """Shared memory for multi-agent coordination using Authority Kernel."""

    def __init__(self, kernel: AuthorityKernel):
        self.heap = TypedHeap(kernel)
        self.handles = {}

    def write(self, key: str, value: dict, agent_id: str = "system") -> int:
        """Write to shared memory with agent attribution."""
        wrapped = {
            "data": value,
            "written_by": agent_id,
            "timestamp": str(__import__("datetime").datetime.now())
        }
        data = json.dumps(wrapped).encode()

        if key in self.handles:
            patch = json.dumps([{"op": "replace", "path": "/", "value": wrapped}]).encode()
            return self.heap.write(self.handles[key], patch)
        else:
            handle = self.heap.alloc(f"shared:{key}", data)
            self.handles[key] = handle
            return handle.get("version", 1)

    def read(self, key: str) -> Optional[dict]:
        """Read from shared memory."""
        if key not in self.handles:
            return None
        data = self.heap.read(self.handles[key])
        wrapped = json.loads(data.decode())
        return wrapped.get("data")

    def list_keys(self) -> list:
        """List all keys in shared memory."""
        return list(self.handles.keys())

    def delete(self, key: str) -> bool:
        """Delete from shared memory."""
        if key not in self.handles:
            return False
        self.heap.delete(self.handles[key])
        del self.handles[key]
        return True


# Global shared memory instance (initialized in main)
shared_memory: Optional[SharedMemory] = None


@tool
def save_to_shared_memory(key: str, value: str) -> str:
    """Save data to shared memory that other agents can access."""
    global shared_memory
    if shared_memory is None:
        return "Error: Shared memory not initialized"
    try:
        data = json.loads(value) if value.startswith("{") else {"content": value}
        version = shared_memory.write(key, data)
        return f"Saved to '{key}' (version {version})"
    except Exception as e:
        return f"Error saving: {e}"


@tool
def read_from_shared_memory(key: str) -> str:
    """Read data from shared memory."""
    global shared_memory
    if shared_memory is None:
        return "Error: Shared memory not initialized"
    data = shared_memory.read(key)
    if data is None:
        return f"Key '{key}' not found"
    return json.dumps(data)


@tool
def list_shared_memory() -> str:
    """List all keys in shared memory."""
    global shared_memory
    if shared_memory is None:
        return "Error: Shared memory not initialized"
    keys = shared_memory.list_keys()
    if not keys:
        return "Shared memory is empty"
    return f"Keys: {', '.join(keys)}"


def create_research_agent(llm) -> Agent:
    """Create a research agent."""
    return Agent(
        role="Research Analyst",
        goal="Research and gather information on given topics",
        backstory="""You are an expert research analyst skilled at gathering
        and synthesizing information. You store your findings in shared memory
        for other agents to use.""",
        tools=[save_to_shared_memory, read_from_shared_memory, list_shared_memory],
        llm=llm,
        verbose=True
    )


def create_writer_agent(llm) -> Agent:
    """Create a writer agent."""
    return Agent(
        role="Content Writer",
        goal="Create well-written content based on research",
        backstory="""You are a skilled content writer who transforms research
        into clear, engaging content. You read from shared memory to access
        research findings.""",
        tools=[save_to_shared_memory, read_from_shared_memory, list_shared_memory],
        llm=llm,
        verbose=True
    )


def create_reviewer_agent(llm) -> Agent:
    """Create a reviewer agent."""
    return Agent(
        role="Quality Reviewer",
        goal="Review and improve content quality",
        backstory="""You are a meticulous reviewer who ensures content quality
        and accuracy. You read drafts from shared memory and provide feedback.""",
        tools=[save_to_shared_memory, read_from_shared_memory, list_shared_memory],
        llm=llm,
        verbose=True
    )


def create_crew(topic: str, llm) -> Crew:
    """Create a research and writing crew."""

    # Create agents
    researcher = create_research_agent(llm)
    writer = create_writer_agent(llm)
    reviewer = create_reviewer_agent(llm)

    # Create tasks
    research_task = Task(
        description=f"""Research the topic: {topic}

        Gather key information and save your findings to shared memory
        under the key 'research_findings'.""",
        expected_output="Research summary saved to shared memory",
        agent=researcher
    )

    writing_task = Task(
        description="""Read the research findings from shared memory and
        write a comprehensive article. Save the draft to shared memory
        under the key 'article_draft'.""",
        expected_output="Article draft saved to shared memory",
        agent=writer
    )

    review_task = Task(
        description="""Read the article draft from shared memory, review it
        for quality and accuracy, and provide the final improved version.
        Save the final version under 'final_article'.""",
        expected_output="Final reviewed article",
        agent=reviewer
    )

    # Create crew
    return Crew(
        agents=[researcher, writer, reviewer],
        tasks=[research_task, writing_task, review_task],
        process=Process.sequential,
        verbose=True
    )


def main():
    """Main entry point for the multi-agent system."""
    global shared_memory

    print("=" * 60)
    print(f"  {{PROJECT_NAME}} - CrewAI Multi-Agent System")
    print("  Running with Authority Kernel")
    print("=" * 60)
    print()

    # Initialize Authority Kernel and shared memory
    print("[1] Initializing Authority Kernel...")
    kernel = AuthorityKernel()
    shared_memory = SharedMemory(kernel)
    print("    Kernel and shared memory initialized")

    # Check for API key
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("\n    Error: OPENAI_API_KEY not set")
        print("    Run: export OPENAI_API_KEY='your-key-here'")
        return

    # Initialize LLM
    print("\n[2] Initializing LLM...")
    llm = ChatOpenAI(model="gpt-4", temperature=0.7)
    print("    LLM initialized")

    # Get topic from user
    print("\n[3] Enter a topic for the crew to research and write about:")
    topic = input("Topic: ").strip()
    if not topic:
        topic = "The future of AI agents in secure computing environments"
        print(f"    Using default topic: {topic}")

    # Create and run crew
    print("\n[4] Creating agent crew...")
    crew = create_crew(topic, llm)
    print("    Crew created with 3 agents: Researcher, Writer, Reviewer")

    print("\n[5] Starting crew execution...")
    print("-" * 60)

    try:
        result = crew.kickoff()
        print("-" * 60)
        print("\n[6] Crew execution completed!")
        print("\nFinal Result:")
        print(result)

        # Show what's in shared memory
        print("\n[7] Shared Memory Contents:")
        for key in shared_memory.list_keys():
            data = shared_memory.read(key)
            print(f"\n  [{key}]:")
            if isinstance(data, dict) and "content" in data:
                print(f"    {data['content'][:200]}...")
            else:
                print(f"    {str(data)[:200]}...")

    except Exception as e:
        print(f"\nError during execution: {e}")

    print("\n" + "=" * 60)
    print("  Multi-agent session ended")
    print("=" * 60)


if __name__ == "__main__":
    main()
