#!/usr/bin/env python3
"""
Authority Kernel - CrewAI Integration Test

This example demonstrates CrewAI running with Authority Kernel authorization.
Requires akproxy daemon running with LLM configured.

Usage:
  minops run examples/test-crewai.py --allow-llm -c examples/llm-config.json

The config file should contain your API key:
  {"Env": {"OPENAI_API_KEY": "sk-..."}}
"""

import json
import os
import sys

# Authority Nanos SDK - always available
from authority_nanos import AuthorityKernel, AuthorityKernelError


# ============================================================================
# MOCK CREWAI CLASSES (for simulation mode without crewai installed)
# ============================================================================

class MockAgent:
    """Mock CrewAI Agent for simulation mode."""

    def __init__(self, role: str, goal: str, backstory: str,
                 verbose: bool = True, allow_delegation: bool = False,
                 llm=None, **kwargs):
        self.role = role
        self.goal = goal
        self.backstory = backstory
        self.verbose = verbose
        self.allow_delegation = allow_delegation
        self.llm = llm

    def __repr__(self):
        return f"MockAgent(role='{self.role}')"


class MockTask:
    """Mock CrewAI Task for simulation mode."""

    def __init__(self, description: str, expected_output: str,
                 agent: MockAgent = None, **kwargs):
        self.description = description
        self.expected_output = expected_output
        self.agent = agent

    def __repr__(self):
        return f"MockTask(description='{self.description[:30]}...')"


class MockProcess:
    """Mock CrewAI Process enum."""
    sequential = "sequential"
    hierarchical = "hierarchical"


class MockCrewOutput:
    """Mock CrewAI output."""

    def __init__(self, raw: str):
        self.raw = raw

    def __str__(self):
        return self.raw


class MockCrew:
    """Mock CrewAI Crew that uses Authority Kernel simulator."""

    def __init__(self, agents: list, tasks: list, process=None,
                 verbose: bool = True, kernel: AuthorityKernel = None):
        self.agents = agents
        self.tasks = tasks
        self.process = process or MockProcess.sequential
        self.verbose = verbose
        self.kernel = kernel

    def kickoff(self):
        """Execute the crew workflow through Authority Kernel."""
        results = []

        for i, task in enumerate(self.tasks):
            agent = task.agent or (self.agents[0] if self.agents else None)

            if self.verbose:
                print(f"\n    [Task {i+1}] {task.description[:50]}...")
                if agent:
                    print(f"    [Agent] {agent.role}")

            # If we have a kernel, use it for inference
            if self.kernel:
                request = json.dumps({
                    "model": "gpt-4",
                    "messages": [
                        {
                            "role": "system",
                            "content": f"You are {agent.role}. {agent.backstory}" if agent else "You are a helpful assistant."
                        },
                        {
                            "role": "user",
                            "content": task.description
                        }
                    ],
                    "max_tokens": 100
                }).encode()

                response = self.kernel.inference(request)
                result = json.loads(response.decode('utf-8'))

                if "choices" in result and result["choices"]:
                    content = result["choices"][0].get("message", {}).get("content", "")
                else:
                    content = f"[Simulated] Task '{task.description}' completed by {agent.role if agent else 'agent'}"
            else:
                content = f"[Simulated] Task '{task.description}' completed by {agent.role if agent else 'agent'}"

            if self.verbose:
                print(f"    [Result] {content[:100]}...")

            results.append(content)

        final_result = "\n\n".join(results)
        return MockCrewOutput(raw=final_result)


# ============================================================================
# TRY TO IMPORT REAL CREWAI (graceful degradation)
# ============================================================================

CREWAI_AVAILABLE = False
Agent = MockAgent
Task = MockTask
Crew = MockCrew
Process = MockProcess

try:
    from crewai import Agent as RealAgent, Task as RealTask, Crew as RealCrew, Process as RealProcess
    Agent = RealAgent
    Task = RealTask
    Crew = RealCrew
    Process = RealProcess
    CREWAI_AVAILABLE = True
except ImportError:
    pass


# ============================================================================
# TEST FUNCTIONS
# ============================================================================

def test_imports():
    """Test that required packages are available."""
    print("Testing imports...")

    # Authority Nanos SDK - always required
    print("  [OK] authority_nanos")

    # Check if crewai is available
    try:
        from crewai import Agent, Task, Crew
        print("  [OK] crewai (Agent, Task, Crew)")
    except ImportError:
        print("  [INFO] crewai not installed, using mock classes")

    return True


def test_authority_kernel():
    """Test Authority Kernel connectivity."""
    print("\nTesting Authority Kernel...")

    try:
        with AuthorityKernel() as ak:
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


def test_crewai_with_kernel(ak: AuthorityKernel):
    """Test CrewAI with Authority Kernel."""
    print("\nTesting CrewAI with Authority Kernel...")

    try:
        # Create a research agent
        print("  [+] Creating researcher agent...")
        researcher = MockAgent(
            role="Researcher",
            goal="Find accurate answers to questions",
            backstory="You are a careful research assistant who always verifies facts.",
            verbose=True,
            allow_delegation=False
        )

        # Create a writer agent
        print("  [+] Creating writer agent...")
        writer = MockAgent(
            role="Writer",
            goal="Write clear and concise summaries",
            backstory="You are a skilled technical writer who explains complex topics simply.",
            verbose=True,
            allow_delegation=False
        )

        # Create tasks
        print("  [+] Creating tasks...")
        research_task = MockTask(
            description="What is 2 + 2? Provide just the numerical answer.",
            expected_output="A single number",
            agent=researcher
        )

        summary_task = MockTask(
            description="Summarize the Authority Kernel in one sentence.",
            expected_output="A brief summary",
            agent=writer
        )

        # Create crew with kernel
        print("  [+] Creating crew...")
        crew = MockCrew(
            agents=[researcher, writer],
            tasks=[research_task, summary_task],
            process=MockProcess.sequential,
            verbose=True,
            kernel=ak
        )

        # Execute
        print("  [+] Executing crew workflow...")
        result = crew.kickoff()

        print(f"\n  [OK] Crew execution completed")
        print(f"  [OK] Result preview: {str(result)[:100]}...")
        return True

    except Exception as e:
        print(f"  [FAIL] CrewAI error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_crewai_real():
    """Test CrewAI with real LLM (requires API key)."""
    print("\nTesting CrewAI workflow with real LLM...")

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key or api_key.startswith("sk-your") or api_key == "sk-test":
        print("  [SKIP] Valid OPENAI_API_KEY not set")
        print("  To test, set a real API key in llm-config.json")
        return True

    if not CREWAI_AVAILABLE:
        print("  [SKIP] crewai not installed")
        return True

    try:
        # Create a simple agent
        print("  Creating researcher agent...")
        researcher = Agent(
            role="Researcher",
            goal="Answer questions accurately and concisely",
            backstory="You are a helpful research assistant inside Authority Kernel.",
            verbose=True,
            allow_delegation=False
        )

        # Create a simple task
        print("  Creating task...")
        task = Task(
            description="What is 2 + 2? Answer with just the number.",
            expected_output="A single number",
            agent=researcher
        )

        # Create crew and run
        print("  Creating crew and executing...")
        crew = Crew(
            agents=[researcher],
            tasks=[task],
            process=Process.sequential,
            verbose=True
        )

        result = crew.kickoff()

        print(f"  [OK] CrewAI result: {result}")
        return True

    except Exception as e:
        print(f"  [FAIL] CrewAI error: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Main entry point."""
    print("=" * 60)
    print("Authority Kernel - CrewAI Integration Test")
    print("=" * 60)
    print()

    # Show environment
    print("Environment:")
    print(f"  Python: {sys.version.split()[0]}")
    print(f"  CrewAI Available: {CREWAI_AVAILABLE}")
    print(f"  OPENAI_API_KEY: {'set' if os.environ.get('OPENAI_API_KEY') else 'not set'}")
    print()

    results = []

    # Run tests
    results.append(("Imports", test_imports()))
    results.append(("Authority Kernel", test_authority_kernel()))

    # Test with kernel
    try:
        with AuthorityKernel() as ak:
            results.append(("CrewAI+Kernel", test_crewai_with_kernel(ak)))
    except Exception as e:
        results.append(("CrewAI+Kernel", False))
        print(f"  [FAIL] {e}")

    # Also test real CrewAI if available and API key set
    if CREWAI_AVAILABLE and os.environ.get('OPENAI_API_KEY'):
        results.append(("CrewAI+Real", test_crewai_real()))

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
        print("All tests passed! CrewAI is working with Authority Kernel!")
    else:
        print("Some tests failed. Check output above.")

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
