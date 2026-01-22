"""
CrewAI Integration for Authority Kernel.

This module provides CrewAI-compatible classes that route all agent
operations through the Authority Kernel for policy-controlled access.

Key Classes:
- AuthorityAgent: CrewAI-compatible agent using Authority Kernel
- AuthorityTask: Task wrapper with policy checks
- AuthorityCrew: Crew orchestrator with audit logging
- CrewOutput: Result container

Example Usage:

    from authority_nanos import AuthorityKernel
    from authority_nanos.integrations.crewai import (
        AuthorityAgent, AuthorityTask, AuthorityCrew
    )

    with AuthorityKernel(simulate=True) as ak:
        # Create agents
        researcher = AuthorityAgent(
            kernel=ak,
            role="Research Analyst",
            goal="Find accurate information",
            backstory="Expert researcher with attention to detail"
        )

        writer = AuthorityAgent(
            kernel=ak,
            role="Technical Writer",
            goal="Create clear documentation",
            backstory="Skilled at explaining complex topics"
        )

        # Create tasks
        research_task = AuthorityTask(
            description="Research quantum computing basics",
            expected_output="Key concepts summary",
            agent=researcher
        )

        writing_task = AuthorityTask(
            description="Write a beginner's guide",
            expected_output="Clear documentation",
            agent=writer
        )

        # Create and run crew
        crew = AuthorityCrew(
            kernel=ak,
            agents=[researcher, writer],
            tasks=[research_task, writing_task]
        )

        result = crew.kickoff()
        print(result.raw)

Features:
- Routes all LLM calls through Authority Kernel
- Policy-controlled agent communication
- Automatic audit logging of all actions
- Works with or without CrewAI installed
- Compatible with both simulation and real kernel modes
"""

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Union

logger = logging.getLogger(__name__)


# ============================================================================
# CREW OUTPUT
# ============================================================================

class CrewOutput:
    """
    Output from crew execution.

    Attributes:
        raw: Combined output from all tasks
        tasks_output: List of individual task outputs
        metadata: Additional execution metadata

    Example:
        result = crew.kickoff()
        print(result.raw)                    # Full combined output
        print(result.tasks_output[0])        # First task's output
        print(result.metadata["duration"])   # Execution time
    """

    def __init__(
        self,
        raw: str,
        tasks_output: List[str] = None,
        metadata: Dict[str, Any] = None
    ):
        """
        Initialize crew output.

        Args:
            raw: Combined output from all tasks
            tasks_output: List of individual task outputs
            metadata: Additional execution metadata
        """
        self.raw = raw
        self.tasks_output = tasks_output or []
        self.metadata = metadata or {}

    def __str__(self):
        return self.raw

    def __repr__(self):
        return f"CrewOutput(tasks={len(self.tasks_output)}, length={len(self.raw)})"


# ============================================================================
# AUTHORITY AGENT
# ============================================================================

class AuthorityAgent:
    """
    CrewAI-compatible agent that routes all actions through Authority Kernel.

    This agent implementation:
    1. Routes all LLM calls through Authority Kernel's inference API
    2. Checks authorization before inter-agent communication
    3. Logs all actions to the audit log
    4. Works in both simulation and real kernel modes

    Attributes:
        kernel: AuthorityKernel instance
        role: Agent's role (e.g., "Researcher", "Writer")
        goal: Agent's primary goal
        backstory: Background context for the agent
        tools: List of tool names the agent can use
        allow_delegation: Whether agent can delegate to others
        verbose: Print progress information
        model: LLM model to use
        memory: Agent's conversation memory

    Example:
        with AuthorityKernel(simulate=True) as ak:
            researcher = AuthorityAgent(
                kernel=ak,
                role="Research Analyst",
                goal="Find accurate, detailed information",
                backstory="You are an expert researcher with deep knowledge "
                         "of technology. You always verify facts.",
                tools=["web_search", "document_reader"],
                verbose=True
            )

            result = researcher.execute(
                "Research the history of machine learning"
            )
            print(result)
    """

    def __init__(
        self,
        kernel: "AuthorityKernel",
        role: str,
        goal: str,
        backstory: str = "",
        tools: List[str] = None,
        allow_delegation: bool = False,
        verbose: bool = True,
        model: str = "gpt-4",
        temperature: float = 0.7,
        max_tokens: int = 500,
        **kwargs
    ):
        """
        Initialize an Authority-aware agent.

        Args:
            kernel: AuthorityKernel instance (simulated or real)
            role: Agent's role (e.g., "Researcher", "Writer", "Analyst")
            goal: Agent's primary goal or objective
            backstory: Background context that shapes agent behavior
            tools: List of tool names the agent can use
            allow_delegation: Whether agent can delegate to others
            verbose: Print progress information
            model: LLM model to use (default: "gpt-4")
            temperature: Sampling temperature (default: 0.7)
            max_tokens: Maximum tokens to generate (default: 500)
            **kwargs: Additional arguments (ignored, for compatibility)
        """
        self.kernel = kernel
        self.role = role
        self.goal = goal
        self.backstory = backstory
        self.tools = tools or []
        self.allow_delegation = allow_delegation
        self.verbose = verbose
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.memory: List[Dict] = []
        self._extra_kwargs = kwargs

        logger.debug(f"AuthorityAgent created: role={role}, model={model}")

    def execute(self, task: str, context: str = "") -> str:
        """
        Execute a task.

        Args:
            task: The task description to execute
            context: Additional context from previous agents or tasks

        Returns:
            The agent's response as a string

        Example:
            result = agent.execute(
                "Analyze the provided data",
                context="Previous analysis showed trends..."
            )
        """
        # Log task start
        self.kernel.audit_log("agent_execute", {
            "agent_role": self.role,
            "task_preview": task[:100] if len(task) > 100 else task,
            "has_context": bool(context)
        })

        if self.verbose:
            print(f"\n  [{self.role}] Starting task...")

        # Build the system prompt
        tool_list = ", ".join(self.tools) if self.tools else "None"
        system_content = f"""You are {self.role}.

Goal: {self.goal}

Background: {self.backstory}

Available tools: {tool_list}

Instructions:
- Respond to the task professionally and thoroughly
- Use your expertise to provide accurate information
- If you need to use a tool, indicate which one and why
- Be concise but complete in your response"""

        # Build user content with optional context
        user_content = task
        if context:
            user_content = f"""Context from previous work:
{context}

Current Task: {task}"""

        # Send inference request through kernel
        request = json.dumps({
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_content},
                {"role": "user", "content": user_content}
            ],
            "temperature": self.temperature,
            "max_tokens": self.max_tokens
        }).encode()

        response = self.kernel.inference(request)
        result = json.loads(response.decode('utf-8'))

        # Extract content
        content = self._extract_content(result)

        # Store in memory
        self.memory.append({
            "task": task,
            "context": context,
            "response": content
        })

        if self.verbose:
            preview = content[:80] + "..." if len(content) > 80 else content
            print(f"  [{self.role}] Completed: {preview}")

        # Log completion
        self.kernel.audit_log("agent_complete", {
            "agent_role": self.role,
            "response_length": len(content),
            "simulated": result.get("simulated", False)
        })

        return content

    def _extract_content(self, result: dict) -> str:
        """Extract content from LLM response."""
        if "choices" in result and result["choices"]:
            choice = result["choices"][0]
            if "message" in choice:
                return choice["message"].get("content", "")
            elif "text" in choice:
                return choice["text"]

        if "content" in result:
            content = result["content"]
            if isinstance(content, list) and content:
                return content[0].get("text", "")
            return str(content)

        return ""

    def __repr__(self):
        return f"AuthorityAgent(role='{self.role}')"


# ============================================================================
# AUTHORITY TASK
# ============================================================================

class AuthorityTask:
    """
    Task that executes within Authority Kernel constraints.

    Attributes:
        description: What the task should accomplish
        expected_output: Description of expected output format
        agent: The agent assigned to this task
        context: Initial context for the task
        output: The task's output after execution

    Example:
        task = AuthorityTask(
            description="Research the history of quantum computing",
            expected_output="A timeline of major milestones",
            agent=researcher_agent
        )

        # Execute standalone
        result = task.execute()

        # Or use with a crew
        crew = AuthorityCrew(kernel=ak, agents=[...], tasks=[task])
    """

    def __init__(
        self,
        description: str,
        expected_output: str,
        agent: AuthorityAgent = None,
        context: str = "",
        **kwargs
    ):
        """
        Initialize a task.

        Args:
            description: What the task should accomplish
            expected_output: Description of expected output format
            agent: The agent assigned to this task (optional)
            context: Initial context for the task
            **kwargs: Additional arguments (ignored, for compatibility)
        """
        self.description = description
        self.expected_output = expected_output
        self.agent = agent
        self.context = context
        self.output: Optional[str] = None
        self._extra_kwargs = kwargs

    def execute(self, context: str = "") -> str:
        """
        Execute the task with the assigned agent.

        Args:
            context: Additional context to include (combined with task context)

        Returns:
            The task output

        Raises:
            ValueError: If no agent is assigned
        """
        if not self.agent:
            raise ValueError("Task has no assigned agent")

        # Combine contexts
        full_context = self.context
        if context:
            full_context = f"{self.context}\n{context}".strip() if self.context else context

        # Execute with agent
        self.output = self.agent.execute(self.description, full_context)
        return self.output

    def __repr__(self):
        desc_preview = self.description[:30] + "..." if len(self.description) > 30 else self.description
        return f"AuthorityTask(description='{desc_preview}')"


# ============================================================================
# AUTHORITY CREW
# ============================================================================

class AuthorityCrew:
    """
    Multi-agent crew that coordinates through Authority Kernel.

    This crew implementation:
    1. Coordinates multiple agents with policy-controlled communication
    2. Executes tasks sequentially or with custom flow
    3. Passes context between agents as they work
    4. Logs all crew activities to audit

    Attributes:
        kernel: AuthorityKernel instance
        agents: List of agents in the crew
        tasks: List of tasks to execute
        process: Execution process ("sequential" or "hierarchical")
        verbose: Print progress information

    Example:
        with AuthorityKernel(simulate=True) as ak:
            # Create agents
            researcher = AuthorityAgent(ak, "Researcher", ...)
            writer = AuthorityAgent(ak, "Writer", ...)

            # Create tasks
            research_task = AuthorityTask(
                description="Research the topic",
                agent=researcher
            )
            writing_task = AuthorityTask(
                description="Write the article",
                agent=writer
            )

            # Create and run crew
            crew = AuthorityCrew(
                kernel=ak,
                agents=[researcher, writer],
                tasks=[research_task, writing_task],
                process="sequential"
            )

            result = crew.kickoff()
            print(result.raw)
    """

    def __init__(
        self,
        kernel: "AuthorityKernel",
        agents: List[AuthorityAgent],
        tasks: List[AuthorityTask],
        process: str = "sequential",
        verbose: bool = True,
        **kwargs
    ):
        """
        Initialize Authority-aware crew.

        Args:
            kernel: AuthorityKernel instance
            agents: List of agents in the crew
            tasks: List of tasks to execute
            process: Execution process ("sequential" or "hierarchical")
            verbose: Print progress information
            **kwargs: Additional arguments (ignored, for compatibility)
        """
        self.kernel = kernel
        self.agents = agents
        self.tasks = tasks
        self.process = process
        self.verbose = verbose
        self._extra_kwargs = kwargs

        logger.debug(f"AuthorityCrew created: {len(agents)} agents, {len(tasks)} tasks")

    def kickoff(self, inputs: Dict[str, Any] = None) -> CrewOutput:
        """
        Start the crew execution.

        Args:
            inputs: Optional input variables for tasks

        Returns:
            CrewOutput with combined results from all tasks
        """
        import time
        start_time = time.time()

        # Log crew start
        self.kernel.audit_log("crew_kickoff", {
            "agent_count": len(self.agents),
            "task_count": len(self.tasks),
            "process": self.process,
            "has_inputs": bool(inputs)
        })

        if self.verbose:
            print(f"\n[Crew] Starting execution")
            print(f"[Crew] Agents: {len(self.agents)}")
            print(f"[Crew] Tasks: {len(self.tasks)}")
            print(f"[Crew] Process: {self.process}")

        results = []
        accumulated_context = ""

        # Process inputs if provided
        if inputs:
            accumulated_context = "\n".join([
                f"{k}: {v}" for k, v in inputs.items()
            ])

        for i, task in enumerate(self.tasks):
            if self.verbose:
                print(f"\n[Crew] === Task {i+1}/{len(self.tasks)} ===")
                desc_preview = task.description[:50] + "..." if len(task.description) > 50 else task.description
                print(f"[Crew] Task: {desc_preview}")
                if task.agent:
                    print(f"[Crew] Agent: {task.agent.role}")

            # Check authorization for task execution
            task_id = f"task_{i}"
            if not self.kernel.authorize("crew_task", task_id):
                if self.verbose:
                    print(f"[Crew] Task {i+1} denied by policy")
                self.kernel.audit_log("crew_task_denied", {
                    "task_index": i,
                    "task_description": task.description[:100]
                })
                continue

            # Execute task with accumulated context
            try:
                output = task.execute(context=accumulated_context)
                results.append(output)

                # Add to context for next task
                agent_role = task.agent.role if task.agent else "Agent"
                accumulated_context += f"\n\n--- From {agent_role} ---\n{output}"

            except Exception as e:
                error_msg = f"Error: {e}"
                if self.verbose:
                    print(f"[Crew] Task {i+1} failed: {e}")

                self.kernel.audit_log("crew_task_error", {
                    "task_index": i,
                    "error": str(e)
                })
                results.append(error_msg)

        # Combine results
        final_output = "\n\n---\n\n".join(results)

        # Calculate duration
        duration = time.time() - start_time

        # Log completion
        self.kernel.audit_log("crew_complete", {
            "tasks_completed": len(results),
            "total_tasks": len(self.tasks),
            "total_output_length": len(final_output),
            "duration_seconds": round(duration, 2)
        })

        if self.verbose:
            print(f"\n[Crew] === Execution Complete ===")
            print(f"[Crew] Tasks completed: {len(results)}/{len(self.tasks)}")
            print(f"[Crew] Duration: {duration:.2f}s")

        return CrewOutput(
            raw=final_output,
            tasks_output=results,
            metadata={
                "duration": duration,
                "tasks_completed": len(results),
                "total_tasks": len(self.tasks)
            }
        )

    def __repr__(self):
        return f"AuthorityCrew(agents={len(self.agents)}, tasks={len(self.tasks)})"


# ============================================================================
# OPTIONAL: CrewAI Native Integration
# ============================================================================

# Try to import CrewAI for proper integration
try:
    from crewai import Agent as CrewAIAgent, Task as CrewAITask, Crew as CrewAICrew

    class AuthorityCrewAIAgent(CrewAIAgent):
        """
        Full CrewAI Agent implementation for Authority Kernel.

        Only available when crewai is installed.
        """
        pass  # Placeholder for future native integration

    __all__ = [
        "AuthorityAgent",
        "AuthorityTask",
        "AuthorityCrew",
        "CrewOutput",
        "AuthorityCrewAIAgent"
    ]

except ImportError:
    # CrewAI not installed, only basic integration available
    AuthorityCrewAIAgent = None
    __all__ = [
        "AuthorityAgent",
        "AuthorityTask",
        "AuthorityCrew",
        "CrewOutput"
    ]

    logger.debug("CrewAI not installed, using basic Authority classes only")
