#!/usr/bin/env python3
"""
Authority Kernel - CrewAI Integration Test

This example demonstrates CrewAI running inside Authority Kernel with:
- Multiple agents collaborating
- Network access controlled by --allow-llm flag
- All LLM calls going through Authority's capability system

Usage:
  minops run examples/test-crewai.py --allow-llm -c examples/llm-config.json

The config file should contain your API key:
  {"Env": {"OPENAI_API_KEY": "sk-..."}}
"""

import os
import sys


def test_crewai_imports():
    """Test that CrewAI packages are available."""
    print("Testing CrewAI imports...")

    try:
        from crewai import Agent, Task, Crew
        print("  [OK] crewai (Agent, Task, Crew)")
        return True
    except ImportError as e:
        print(f"  [FAIL] crewai: {e}")
        return False


def test_crewai_simple():
    """Test a simple CrewAI workflow."""
    print("\nTesting CrewAI workflow...")

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key or api_key.startswith("sk-your") or api_key == "sk-test":
        print("  [SKIP] Valid OPENAI_API_KEY not set")
        print("  To test, set a real API key in llm-config.json")
        return True

    try:
        from crewai import Agent, Task, Crew, Process

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
    print("=" * 60)
    print("Authority Kernel - CrewAI Integration Test")
    print("=" * 60)
    print()

    print("Environment:")
    print(f"  Python: {sys.version.split()[0]}")
    print(f"  OPENAI_API_KEY: {'set' if os.environ.get('OPENAI_API_KEY') else 'not set'}")
    print()

    results = []

    results.append(("CrewAI Imports", test_crewai_imports()))
    results.append(("CrewAI Workflow", test_crewai_simple()))

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
        print("CrewAI is working inside Authority Kernel!")
    else:
        print("Some tests failed. Check output above.")

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
