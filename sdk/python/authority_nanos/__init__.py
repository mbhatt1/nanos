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

Typical usage:

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

For more details, see the documentation at https://authority-systems.github.io/nanos/python
"""

from authority_nanos.core import (
    # Core classes
    AuthorityKernel,
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
]
