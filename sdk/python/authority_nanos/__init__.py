"""
Authority Nanos Python SDK.

Low-level and high-level bindings for the Authority Kernel (libak).

This package provides comprehensive Python support for Authority Kernel operations:

- Typed heap management (alloc, read, write, delete)
- Tool execution in WASM sandbox
- LLM inference
- Policy-controlled file I/O
- Policy-controlled HTTP requests
- Authorization and capability management
- Audit logging
- **LangChain integration** (via authority_nanos.integrations)
- **CrewAI integration** (via authority_nanos.integrations)

Typical usage with real kernel:

    from authority_nanos import AuthorityKernel
    import json

    with AuthorityKernel() as ak:
        # Allocate a counter object
        handle = ak.alloc("counter", b'{"value": 0}')

        # Read it back
        data = ak.read(handle)
        counter = json.loads(data.decode('utf-8'))

        # Update with JSON Patch
        patch = b'[{"op": "replace", "path": "/value", "value": 42}]'
        new_version = ak.write(handle, patch)

        # Check authorization
        if ak.authorize("read", "/etc/config.json"):
            config = ak.file_read("/etc/config.json")

Simulation mode (no kernel required):

    from authority_nanos import AuthorityKernel
    import json

    # Use simulate=True to run without a real kernel
    with AuthorityKernel(simulate=True) as ak:
        # All operations work with in-memory simulation
        handle = ak.alloc("counter", b'{"value": 0}')
        data = ak.read(handle)

        # Configure policy for testing
        ak.deny_operation("write")  # Deny all writes
        ak.deny_target("/secret/*")  # Deny access to secrets

        # Check if in simulation mode
        if ak.is_simulated():
            print("Running in simulation mode")

Or use SimulatedKernel directly for more control:

    from authority_nanos import SimulatedKernel

    with SimulatedKernel() as ak:
        handle = ak.alloc("counter", b'{"value": 0}')
        # Simulation-specific methods available directly
        ak.deny_operation("read")
        ak.deny_target("/etc/passwd")

LangChain Integration:

    from authority_nanos import AuthorityKernel
    from authority_nanos.integrations import AuthorityLLM

    with AuthorityKernel(simulate=True) as ak:
        llm = AuthorityLLM(ak, model="gpt-4")
        response = llm.invoke("What is the capital of France?")
        print(response.content)

CrewAI Integration:

    from authority_nanos import AuthorityKernel
    from authority_nanos.integrations import AuthorityAgent, AuthorityTask, AuthorityCrew

    with AuthorityKernel(simulate=True) as ak:
        researcher = AuthorityAgent(
            kernel=ak,
            role="Researcher",
            goal="Find information",
            backstory="Expert research assistant"
        )

        task = AuthorityTask(
            description="Research machine learning",
            expected_output="Summary of key concepts",
            agent=researcher
        )

        crew = AuthorityCrew(
            kernel=ak,
            agents=[researcher],
            tasks=[task]
        )

        result = crew.kickoff()
        print(result.raw)

For more details, see the documentation at https://authority-systems.github.io/nanos/python
"""

from authority_nanos.core import (
    # Core classes
    AuthorityKernel,
    SimulatedKernel,
    LibakLoader,
    # Data structures
    Handle,
    ToolCall,
    InferenceRequest,
    EffectRequest,
    EffectResponse,
    Capability,
    DenialInfo,
    AuthorizationDetails,
    # Enums
    Syscall,
    ErrorCode,
    # Exceptions
    AuthorityKernelError,
    OperationDeniedError,
    CapabilityError,
    InvalidArgumentError,
    NotFoundError,
    BufferOverflowError,
    TimeoutError,
    OutOfMemoryError,
    LibakError,
)

# Exception base classes (canonical location)
from authority_nanos.exceptions import BudgetExceededError

# Policy tools
from authority_nanos.policy import (
    PolicyWizard,
    PolicyValidator,
    PolicyExplainer,
    PolicyMerger,
    MergeMode,
    ValidationResult,
    ValidationSeverity,
    # Convenience functions
    validate_policy_file,
    explain_policy_file,
    merge_policy_files,
    run_policy_wizard,
)

# Integrations (lazy import to avoid dependency issues)
# Users can import directly: from authority_nanos.integrations import AuthorityLLM
# Or access via: authority_nanos.integrations.AuthorityLLM
try:
    from authority_nanos import integrations
except ImportError:
    integrations = None

# Read version from version.txt to ensure consistency with packaging
import os

_version_file = os.path.join(os.path.dirname(__file__), "version.txt")
try:
    with open(_version_file, "r") as f:
        __version__ = f.read().strip()
except (IOError, OSError):
    # Fallback if version.txt is missing (e.g., in development)
    __version__ = "0.1.0"

__author__ = "Authority Systems"
__license__ = "Apache License 2.0"

__all__ = [
    # Version info
    "__version__",
    "__author__",
    "__license__",
    # Core classes
    "AuthorityKernel",
    "SimulatedKernel",
    "LibakLoader",
    # Data structures
    "Handle",
    "ToolCall",
    "InferenceRequest",
    "EffectRequest",
    "EffectResponse",
    "Capability",
    "DenialInfo",
    "AuthorizationDetails",
    # Enums
    "Syscall",
    "ErrorCode",
    # Exceptions
    "AuthorityKernelError",
    "OperationDeniedError",
    "CapabilityError",
    "InvalidArgumentError",
    "NotFoundError",
    "BufferOverflowError",
    "TimeoutError",
    "OutOfMemoryError",
    "LibakError",
    "BudgetExceededError",
    # Policy tools
    "PolicyWizard",
    "PolicyValidator",
    "PolicyExplainer",
    "PolicyMerger",
    "MergeMode",
    "ValidationResult",
    "ValidationSeverity",
    "validate_policy_file",
    "explain_policy_file",
    "merge_policy_files",
    "run_policy_wizard",
    # Integrations module (for: from authority_nanos import integrations)
    "integrations",
]
