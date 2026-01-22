#!/usr/bin/env python3
"""
Example 7: CrewAI Multi-Agent with Authority Kernel

Demonstrates a complete CrewAI multi-agent system with Authority Kernel
for policy-controlled collaboration and authorization.

By default, runs in simulation mode (no kernel or CrewAI required).
Use --real or --kernel to run against the actual Authority Kernel with real LLM.

Key Features:
- Multiple agents collaborating through Authority Kernel
- Policy-controlled LLM inference for each agent
- Authorization checks for inter-agent communication
- Audit logging of all agent actions
- Works without CrewAI installed (simulation mode)

Usage:
  python examples/07_crewai_agent.py            # Simulation mode
  python examples/07_crewai_agent.py --real     # Real mode (requires LLM API key)
"""

import argparse
import json
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Callable

from authority_nanos import AuthorityKernel, AuthorityKernelError


# ============================================================================
# AUTHORITY-AWARE AGENT CLASSES
# ============================================================================

@dataclass
class AgentConfig:
    """Configuration for an Authority-aware agent."""
    role: str
    goal: str
    backstory: str
    tools: List[str] = None
    allow_delegation: bool = False
    verbose: bool = True


class AuthorityAgent:
    """
    CrewAI-compatible agent that routes all actions through Authority Kernel.

    This agent implementation:
    1. Routes all LLM calls through Authority Kernel's inference API
    2. Checks authorization before inter-agent communication
    3. Logs all actions to the audit log
    4. Works in both simulation and real kernel modes

    Example:
        with AuthorityKernel(simulate=True) as ak:
            researcher = AuthorityAgent(
                kernel=ak,
                role="Researcher",
                goal="Find accurate information",
                backstory="Expert research assistant"
            )
            result = researcher.execute("What is machine learning?")
    """

    def __init__(self, kernel: AuthorityKernel, role: str, goal: str,
                 backstory: str, tools: List[str] = None,
                 allow_delegation: bool = False, verbose: bool = True,
                 model: str = "gpt-4"):
        """
        Initialize an Authority-aware agent.

        Args:
            kernel: AuthorityKernel instance
            role: Agent's role (e.g., "Researcher", "Writer")
            goal: Agent's primary goal
            backstory: Background context for the agent
            tools: List of tool names the agent can use
            allow_delegation: Whether agent can delegate to others
            verbose: Print progress information
            model: LLM model to use
        """
        self.kernel = kernel
        self.role = role
        self.goal = goal
        self.backstory = backstory
        self.tools = tools or []
        self.allow_delegation = allow_delegation
        self.verbose = verbose
        self.model = model
        self.memory: List[Dict] = []

    def execute(self, task: str, context: str = "") -> str:
        """
        Execute a task.

        Args:
            task: The task description to execute
            context: Additional context from previous agents

        Returns:
            The agent's response
        """
        # Log task start
        self.kernel.audit_log("agent_execute", {
            "agent": self.role,
            "task_preview": task[:100]
        })

        if self.verbose:
            print(f"\n  [{self.role}] Starting task...")

        # Build the prompt
        system_content = f"""You are {self.role}.
Goal: {self.goal}
Background: {self.backstory}

Available tools: {', '.join(self.tools) if self.tools else 'None'}

Respond to the task professionally and concisely."""

        user_content = task
        if context:
            user_content = f"Context from previous work:\n{context}\n\nTask: {task}"

        # Send inference request through kernel
        request = json.dumps({
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_content},
                {"role": "user", "content": user_content}
            ],
            "temperature": 0.7,
            "max_tokens": 500
        }).encode()

        response = self.kernel.inference(request)
        result = json.loads(response.decode('utf-8'))

        # Extract content
        content = ""
        if "choices" in result and result["choices"]:
            content = result["choices"][0].get("message", {}).get("content", "")
        elif "content" in result:
            content = result["content"]

        # Store in memory
        self.memory.append({
            "task": task,
            "response": content
        })

        if self.verbose:
            print(f"  [{self.role}] Completed: {content[:80]}...")

        # Log completion
        self.kernel.audit_log("agent_complete", {
            "agent": self.role,
            "response_length": len(content)
        })

        return content

    def __repr__(self):
        return f"AuthorityAgent(role='{self.role}')"


# ============================================================================
# AUTHORITY-AWARE TASK
# ============================================================================

class AuthorityTask:
    """
    Task that executes within Authority Kernel constraints.

    Example:
        task = AuthorityTask(
            description="Research quantum computing",
            expected_output="A summary of key concepts",
            agent=researcher
        )
    """

    def __init__(self, description: str, expected_output: str,
                 agent: AuthorityAgent = None, context: str = ""):
        self.description = description
        self.expected_output = expected_output
        self.agent = agent
        self.context = context
        self.output: Optional[str] = None

    def execute(self, context: str = "") -> str:
        """Execute the task with the assigned agent."""
        if not self.agent:
            raise ValueError("Task has no assigned agent")

        full_context = f"{self.context}\n{context}".strip() if context else self.context
        self.output = self.agent.execute(self.description, full_context)
        return self.output

    def __repr__(self):
        return f"AuthorityTask(description='{self.description[:30]}...')"


# ============================================================================
# AUTHORITY-AWARE CREW
# ============================================================================

class AuthorityCrew:
    """
    Multi-agent crew that coordinates through Authority Kernel.

    This crew implementation:
    1. Coordinates multiple agents with policy-controlled communication
    2. Executes tasks sequentially or hierarchically
    3. Passes context between agents as they work
    4. Logs all crew activities to audit

    Example:
        with AuthorityKernel(simulate=True) as ak:
            researcher = AuthorityAgent(ak, "Researcher", ...)
            writer = AuthorityAgent(ak, "Writer", ...)

            crew = AuthorityCrew(
                kernel=ak,
                agents=[researcher, writer],
                tasks=[research_task, writing_task],
                process="sequential"
            )

            result = crew.kickoff()
    """

    def __init__(self, kernel: AuthorityKernel, agents: List[AuthorityAgent],
                 tasks: List[AuthorityTask], process: str = "sequential",
                 verbose: bool = True):
        """
        Initialize Authority-aware crew.

        Args:
            kernel: AuthorityKernel instance
            agents: List of agents in the crew
            tasks: List of tasks to execute
            process: Execution process ("sequential" or "hierarchical")
            verbose: Print progress information
        """
        self.kernel = kernel
        self.agents = agents
        self.tasks = tasks
        self.process = process
        self.verbose = verbose

    def kickoff(self) -> "CrewOutput":
        """
        Start the crew execution.

        Returns:
            CrewOutput with combined results from all tasks
        """
        # Log crew start
        self.kernel.audit_log("crew_kickoff", {
            "agent_count": len(self.agents),
            "task_count": len(self.tasks),
            "process": self.process
        })

        if self.verbose:
            print(f"\n[Crew] Starting with {len(self.agents)} agents, {len(self.tasks)} tasks")
            print(f"[Crew] Process: {self.process}")

        results = []
        accumulated_context = ""

        for i, task in enumerate(self.tasks):
            if self.verbose:
                print(f"\n[Crew] === Task {i+1}/{len(self.tasks)} ===")
                print(f"[Crew] Description: {task.description[:50]}...")
                if task.agent:
                    print(f"[Crew] Assigned to: {task.agent.role}")

            # Check authorization for task execution
            if not self.kernel.authorize("crew_task", f"task_{i}"):
                if self.verbose:
                    print(f"[Crew] Task {i+1} denied by policy")
                continue

            # Execute task with accumulated context
            try:
                output = task.execute(context=accumulated_context)
                results.append(output)
                # Add to context for next task
                accumulated_context += f"\n\nFrom {task.agent.role if task.agent else 'agent'}:\n{output}"

            except Exception as e:
                if self.verbose:
                    print(f"[Crew] Task {i+1} failed: {e}")
                results.append(f"Error: {e}")

        # Combine results
        final_output = "\n\n---\n\n".join(results)

        # Log completion
        self.kernel.audit_log("crew_complete", {
            "tasks_completed": len(results),
            "total_output_length": len(final_output)
        })

        if self.verbose:
            print(f"\n[Crew] === Execution Complete ===")
            print(f"[Crew] Tasks completed: {len(results)}/{len(self.tasks)}")

        return CrewOutput(raw=final_output, tasks_output=results)


class CrewOutput:
    """Output from crew execution."""

    def __init__(self, raw: str, tasks_output: List[str] = None):
        self.raw = raw
        self.tasks_output = tasks_output or []

    def __str__(self):
        return self.raw


# ============================================================================
# MAIN EXAMPLE
# ============================================================================

def run_crewai_example(simulate: bool = True):
    """Run the CrewAI multi-agent example."""
    mode = "SIMULATION" if simulate else "REAL KERNEL"
    print(f"\n=== CrewAI Multi-Agent Example ({mode} mode) ===\n")

    try:
        with AuthorityKernel(simulate=simulate) as ak:
            print("[+] Connected to Authority Kernel")
            print(f"[+] Simulated: {ak.is_simulated()}")

            # Create agents
            print("\n--- Creating Agent Team ---")

            researcher = AuthorityAgent(
                kernel=ak,
                role="Research Analyst",
                goal="Gather accurate information on technical topics",
                backstory="You are an expert researcher with deep knowledge of technology. "
                         "You always verify facts and provide detailed analysis.",
                tools=["web_search", "document_reader"],
                verbose=True
            )
            print(f"[+] Created: {researcher}")

            writer = AuthorityAgent(
                kernel=ak,
                role="Technical Writer",
                goal="Create clear, engaging technical content",
                backstory="You are a skilled technical writer who transforms complex topics "
                         "into accessible content. You focus on clarity and accuracy.",
                tools=["text_editor"],
                verbose=True
            )
            print(f"[+] Created: {writer}")

            reviewer = AuthorityAgent(
                kernel=ak,
                role="Quality Reviewer",
                goal="Ensure content accuracy and quality",
                backstory="You are a meticulous editor who checks for errors, "
                         "improves clarity, and ensures high-quality output.",
                tools=["grammar_checker"],
                verbose=True
            )
            print(f"[+] Created: {reviewer}")

            # Create tasks
            print("\n--- Creating Tasks ---")

            research_task = AuthorityTask(
                description="Research the Authority Kernel concept: what it is, how it provides "
                           "security for AI agents, and its key features. Provide 3-5 key points.",
                expected_output="A list of key facts about Authority Kernel",
                agent=researcher
            )
            print(f"[+] Created: {research_task}")

            writing_task = AuthorityTask(
                description="Based on the research, write a brief 2-3 paragraph summary "
                           "explaining Authority Kernel for a technical audience.",
                expected_output="A clear technical summary",
                agent=writer
            )
            print(f"[+] Created: {writing_task}")

            review_task = AuthorityTask(
                description="Review the summary for accuracy and clarity. "
                           "Provide the final approved version with any corrections.",
                expected_output="Final reviewed and approved content",
                agent=reviewer
            )
            print(f"[+] Created: {review_task}")

            # Create and run crew
            print("\n--- Executing Crew Workflow ---")

            crew = AuthorityCrew(
                kernel=ak,
                agents=[researcher, writer, reviewer],
                tasks=[research_task, writing_task, review_task],
                process="sequential",
                verbose=True
            )

            result = crew.kickoff()

            # Show final output
            print("\n--- Final Output ---")
            print(result.raw[:500])
            if len(result.raw) > 500:
                print(f"... ({len(result.raw)} total characters)")

            # Show audit summary
            print("\n--- Audit Log Summary ---")
            logs = ak.audit_logs()
            print(f"[+] Total audit entries: {len(logs)}")

            # Count by event type
            event_counts: Dict[str, int] = {}
            for log_entry in logs:
                try:
                    entry = json.loads(log_entry.decode('utf-8'))
                    event = entry.get('event', 'unknown')
                    event_counts[event] = event_counts.get(event, 0) + 1
                except:
                    pass

            print("[+] Events by type:")
            for event, count in sorted(event_counts.items()):
                print(f"    - {event}: {count}")

            print("\n[+] CrewAI multi-agent example completed!")
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
        description="CrewAI Multi-Agent with Authority Kernel"
    )
    parser.add_argument("--real", "--kernel", action="store_true",
                        help="Use real kernel instead of simulation")
    args = parser.parse_args()

    simulate = not args.real

    success = run_crewai_example(simulate)

    if simulate:
        print("\n[i] Running in simulation mode. Use --real for actual kernel.")

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
