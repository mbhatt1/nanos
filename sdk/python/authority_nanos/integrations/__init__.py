"""
Authority Nanos Integrations Package.

This package provides integration adapters for popular AI frameworks:

- **LangChain**: AuthorityLLM wrapper for LangChain applications
- **CrewAI**: AuthorityAgent wrapper for CrewAI multi-agent systems

All integrations route their LLM calls and tool executions through
the Authority Kernel for policy-controlled access and audit logging.

Basic Usage:

    from authority_nanos import AuthorityKernel
    from authority_nanos.integrations import AuthorityLLM, AuthorityAgent

    # LangChain integration
    with AuthorityKernel(simulate=True) as ak:
        llm = AuthorityLLM(ak, model="gpt-4")
        response = llm.invoke("What is the capital of France?")

    # CrewAI integration
    with AuthorityKernel(simulate=True) as ak:
        agent = AuthorityAgent(
            kernel=ak,
            role="Researcher",
            goal="Find accurate information"
        )
        result = agent.execute("Research quantum computing")

These integrations work in both simulation mode (for testing without
real LLM APIs) and real mode (with actual Authority Kernel).
"""

from authority_nanos.integrations.langchain import (
    AuthorityLLM,
    LLMResponse,
)

from authority_nanos.integrations.crewai import (
    AuthorityAgent,
    AuthorityTask,
    AuthorityCrew,
    CrewOutput,
)

__all__ = [
    # LangChain integration
    "AuthorityLLM",
    "LLMResponse",
    # CrewAI integration
    "AuthorityAgent",
    "AuthorityTask",
    "AuthorityCrew",
    "CrewOutput",
]
