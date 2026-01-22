"""
Core Authority Kernel syscall wrappers for Python.

This module provides low-level ctypes bindings to libak, the Authority Kernel C library.
It implements the foundation for all Authority Kernel operations including:

- Typed heap operations (alloc, read, write, delete)
- Tool execution in WASM sandbox
- LLM inference
- Authorization and policy checks
- File I/O with policy enforcement
- HTTP requests with policy enforcement
- Audit logging

Production-ready with comprehensive error handling, resource management, and validation.

Simulation Mode:
    When simulate=True, the SDK provides a fully functional in-memory simulation
    of the Authority Kernel. This is useful for:
    - Testing and development without building the kernel
    - Quick prototyping and experimentation
    - CI/CD pipelines where kernel isn't available
    - Learning the API without infrastructure setup
"""

import ctypes
import json
import logging
import os
import platform
import time
from ctypes import (
    CDLL, POINTER, Structure, c_char, c_char_p, c_uint8, c_uint16, c_uint32,
    c_uint64, c_int64, c_bool, c_void_p, byref, create_string_buffer, sizeof, cast
)
from pathlib import Path
from typing import Optional, Dict, Tuple, Any, Union, List
from dataclasses import dataclass, field
from enum import IntEnum

logger = logging.getLogger(__name__)

# Import binary locator functions
try:
    from authority_nanos._libak_loader import find_libak, find_kernel_image, LibakNotFoundError
except ImportError:
    # Fallback if module not available
    find_libak = None
    find_kernel_image = None
    LibakNotFoundError = None


# ============================================================================
# SYSCALL NUMBERS (1024-1100)
# ============================================================================

class Syscall(IntEnum):
    """Authority Kernel syscall numbers."""
    READ = 1024
    ALLOC = 1025
    WRITE = 1026
    DELETE = 1027
    QUERY = 1028
    BATCH = 1029
    COMMIT = 1030
    CALL = 1031
    SPAWN = 1032
    SEND = 1033
    RECV = 1034
    RESPOND = 1035
    ASSERT = 1036
    INFERENCE = 1037


# ============================================================================
# ERROR CODES
# ============================================================================

class ErrorCode(IntEnum):
    """Authority Kernel error codes."""
    OK = 0
    DENIED = -1              # Operation denied by policy
    CAP_INVALID = -2         # Invalid capability
    CAP_EXPIRED = -3         # Capability expired
    CAP_REVOKED = -4         # Capability revoked
    BUDGET = -5              # Budget exceeded
    NOMEM = -6               # Out of memory
    INVAL = -7               # Invalid argument
    NOENT = -8               # Not found
    OVERFLOW = -9            # Buffer overflow
    TIMEOUT = -10            # Operation timeout


# ============================================================================
# EXCEPTION HIERARCHY
# ============================================================================

class AuthorityKernelError(Exception):
    """Base exception for Authority Kernel errors."""
    def __init__(self, code: int, message: str = "", context: str = ""):
        self.code = code
        self.message = message
        self.context = context
        super().__init__(f"[{code}] {message}" + (f" ({context})" if context else ""))


class OperationDeniedError(AuthorityKernelError):
    """Operation was denied by security policy."""
    pass


class CapabilityError(AuthorityKernelError):
    """Capability token error (invalid, expired, or revoked)."""
    pass


class BudgetExceededError(AuthorityKernelError):
    """Operation exceeded available budget."""
    pass


class InvalidArgumentError(AuthorityKernelError):
    """Invalid argument provided to syscall."""
    pass


class NotFoundError(AuthorityKernelError):
    """Requested resource not found."""
    pass


class BufferOverflowError(AuthorityKernelError):
    """Buffer overflow in syscall."""
    pass


class TimeoutError(AuthorityKernelError):
    """Operation timed out."""
    pass


class OutOfMemoryError(AuthorityKernelError):
    """Out of memory."""
    pass


class LibakError(AuthorityKernelError):
    """Generic libak error."""
    pass


# ============================================================================
# CTYPES STRUCTURE DEFINITIONS (Match libak.h exactly)
# ============================================================================

class Handle(Structure):
    """Typed object handle in Authority Kernel typed heap.

    Attributes:
        id: 64-bit object ID (unique identifier)
        version: 32-bit version number (for compare-and-swap semantics)
    """
    _fields_ = [
        ("id", c_uint64),
        ("version", c_uint32),
    ]

    def __repr__(self) -> str:
        return f"Handle(id={self.id}, version={self.version})"


class ToolCall(Structure):
    """Tool call request for WASM sandbox execution.

    Attributes:
        tool_name: Tool identifier (max 63 chars)
        args_json: Arguments as JSON (max 2047 bytes)
        args_len: Actual argument length
    """
    _fields_ = [
        ("tool_name", c_char * 64),
        ("args_json", c_uint8 * 2048),
        ("args_len", c_uint32),
    ]


class InferenceRequest(Structure):
    """LLM inference request.

    Attributes:
        model: Model identifier (max 63 chars)
        prompt: Prompt or messages as JSON (max 4095 bytes)
        prompt_len: Actual prompt length
        max_tokens: Maximum tokens to generate
    """
    _fields_ = [
        ("model", c_char * 64),
        ("prompt", c_uint8 * 4096),
        ("prompt_len", c_uint32),
        ("max_tokens", c_uint32),
    ]


class EffectRequest(Structure):
    """Effect request for Authority Kernel operations.

    Attributes:
        op: Effect operation code (syscall number)
        target: Canonical target (path, URL, etc) (max 511 chars)
        params: Effect-specific parameters (max 1023 bytes)
        params_len: Parameter length
        trace_id: Trace ID for correlation and debugging
    """
    _fields_ = [
        ("op", c_uint16),
        ("target", c_char * 512),
        ("params", c_uint8 * 1024),
        ("params_len", c_uint32),
        ("trace_id", c_uint64),
    ]


class EffectResponse(Structure):
    """Effect response from Authority Kernel.

    Attributes:
        err: Error code (0 for success, negative for errors)
        result: Response data (max 1023 bytes)
        result_len: Actual response length
    """
    _fields_ = [
        ("err", c_int64),
        ("result", c_uint8 * 1024),
        ("result_len", c_uint32),
    ]


class Capability(Structure):
    """Capability token for authorization.

    Attributes:
        token: HMAC-signed capability token (max 255 bytes)
        token_len: Actual token length
        ttl_ms: Time-to-live in milliseconds
    """
    _fields_ = [
        ("token", c_uint8 * 256),
        ("token_len", c_uint32),
        ("ttl_ms", c_uint32),
    ]


# ============================================================================
# LIBAK LOADER
# ============================================================================

class LibakLoader:
    """Loads and manages libak.so shared library.

    Handles loading libak from standard system locations and gracefully
    manages missing libraries with helpful error messages.

    Attributes:
        DEFAULT_PATHS: Standard locations to search for libak.so
    """

    DEFAULT_PATHS = [
        "/lib/libak.so",
        "/usr/lib/libak.so",
        "/usr/local/lib/libak.so",
        "/lib64/libak.so",
        "/usr/lib64/libak.so",
        "/opt/authority/lib/libak.so",
        "libak.so",  # System library path
    ]

    _instance: Optional[CDLL] = None
    _lock: bool = False

    @classmethod
    def load(cls, libak_path: Optional[str] = None) -> CDLL:
        """Load libak.so library with caching and fallback logic.

        Tries to load libak from the following locations in order:
        1. Explicit path (if provided)
        2. Bundled binaries in wheel (via find_libak from _libak_loader)
        3. System library paths (standard locations)

        Args:
            libak_path: Explicit path to libak.so, or None to search defaults

        Returns:
            Loaded CDLL instance

        Raises:
            LibakError: If library cannot be loaded from any location
        """
        if cls._instance is not None:
            return cls._instance

        if cls._lock:
            raise LibakError(-1, "LibakLoader.load() is not reentrant")

        cls._lock = True
        try:
            paths_to_try = []

            # 1. Explicit path
            if libak_path:
                paths_to_try.append(libak_path)

            # 2. Try bundled binary via _libak_loader module
            if find_libak is not None:
                try:
                    bundled_path = find_libak()
                    if bundled_path:
                        paths_to_try.insert(0, bundled_path)
                        logger.debug(f"Found bundled libak: {bundled_path}")
                except Exception as e:
                    logger.debug(f"Error finding bundled libak: {e}")

            # 3. System library paths (DEFAULT_PATHS)
            paths_to_try.extend(cls.DEFAULT_PATHS)

            # Remove duplicates while preserving order
            seen = set()
            unique_paths = []
            for path in paths_to_try:
                if path and path not in seen:
                    unique_paths.append(path)
                    seen.add(path)

            for path in unique_paths:
                try:
                    logger.debug(f"Attempting to load libak from: {path}")
                    lib = CDLL(path)
                    logger.info(f"Successfully loaded libak from: {path}")
                    cls._instance = lib
                    return lib
                except OSError as e:
                    logger.debug(f"Failed to load libak from {path}: {e}")
                    continue

            # Provide helpful error message
            available_paths = "\n  ".join(unique_paths)
            raise LibakError(
                -1,
                f"Could not load libak.so from any standard location",
                f"Tried: {available_paths}\n"
                f"Make sure libak is installed and in the system library path, "
                f"or specify libak_path parameter"
            )
        finally:
            cls._lock = False

    @classmethod
    def unload(cls) -> None:
        """Unload cached libak instance."""
        cls._instance = None


# ============================================================================
# DENIAL INFO
# ============================================================================

@dataclass
class DenialInfo:
    """Information about a policy denial.

    Attributes:
        reason: Human-readable denial reason
        capability_required: Required capability name
        operation: Denied operation
        target: Denied target resource
        suggestion: Helpful suggestion for user
    """
    reason: str
    capability_required: Optional[str] = None
    operation: Optional[str] = None
    target: Optional[str] = None
    suggestion: Optional[str] = None

    @classmethod
    def from_json(cls, json_bytes: bytes) -> "DenialInfo":
        """Parse denial info from JSON response.

        Args:
            json_bytes: JSON response bytes

        Returns:
            DenialInfo instance
        """
        try:
            data = json.loads(json_bytes.decode('utf-8'))
            return cls(
                reason=data.get("reason", "Unknown denial"),
                capability_required=data.get("capability_required"),
                operation=data.get("operation"),
                target=data.get("target"),
                suggestion=data.get("suggestion"),
            )
        except (json.JSONDecodeError, UnicodeDecodeError):
            return cls(reason="Failed to parse denial information")


# ============================================================================
# AUTHORIZATION DETAILS
# ============================================================================

@dataclass
class AuthorizationDetails:
    """Details about authorization requirement for an operation.

    Attributes:
        operation: Operation code
        target: Target resource
        authorized: Whether operation is authorized
        capability_name: Required capability name
        ttl_ms: Capability TTL in milliseconds
        reason: Explanation
    """
    operation: int
    target: str
    authorized: bool
    capability_name: Optional[str] = None
    ttl_ms: Optional[int] = None
    reason: Optional[str] = None

    @classmethod
    def from_json(cls, json_bytes: bytes, operation: int, target: str) -> "AuthorizationDetails":
        """Parse authorization details from JSON response.

        Args:
            json_bytes: JSON response bytes
            operation: Operation code
            target: Target resource

        Returns:
            AuthorizationDetails instance
        """
        try:
            data = json.loads(json_bytes.decode('utf-8'))
            return cls(
                operation=operation,
                target=target,
                authorized=data.get("authorized", False),
                capability_name=data.get("capability_name"),
                ttl_ms=data.get("ttl_ms"),
                reason=data.get("reason"),
            )
        except (json.JSONDecodeError, UnicodeDecodeError):
            return cls(
                operation=operation,
                target=target,
                authorized=False,
                reason="Failed to parse authorization details"
            )


# ============================================================================
# SIMULATED KERNEL (In-Memory Implementation)
# ============================================================================

@dataclass
class SimulatedObject:
    """An object in the simulated heap."""
    type_name: str
    data: bytes
    version: int = 0
    deleted: bool = False
    created_at: float = field(default_factory=time.time)


class SimulatedKernel:
    """In-memory simulation of Authority Kernel for testing and development.

    Provides a fully functional mock implementation that behaves like the real
    kernel but runs entirely in Python. Useful for:
    - Testing without building the kernel
    - Development and prototyping
    - CI/CD pipelines
    - Learning the API

    All operations are simulated with realistic behavior:
    - Heap operations: Full alloc/read/write/delete with versioning
    - Authorization: Configurable allow/deny policies
    - Audit logging: In-memory audit trail
    - Tool calls: Simulated tool execution
    """

    def __init__(self, debug: bool = False):
        """Initialize simulated kernel.

        Args:
            debug: Enable debug logging
        """
        self.debug = debug
        self._heap: Dict[int, SimulatedObject] = {}
        self._next_id = 1
        self._audit_log: List[dict] = []
        self._initialized = False
        self._last_denial: Optional[DenialInfo] = None
        # Default: allow all operations
        self._denied_operations: set = set()
        self._denied_targets: set = set()

    def init(self) -> None:
        """Initialize simulated kernel."""
        self._initialized = True
        self._log_audit("init", {"status": "success"})
        logger.info("Simulated Authority Kernel initialized")

    def shutdown(self) -> None:
        """Shutdown simulated kernel."""
        self._initialized = False
        self._log_audit("shutdown", {"status": "success"})
        logger.info("Simulated Authority Kernel shut down")

    def alloc(self, type_name: str, initial_value: bytes = b"") -> Handle:
        """Allocate object in simulated heap."""
        if not isinstance(initial_value, bytes):
            raise InvalidArgumentError(-7, "initial_value must be bytes")

        if len(initial_value) > 1024:
            raise BufferOverflowError(-9, f"initial_value exceeds 1024 bytes")

        obj_id = self._next_id
        self._next_id += 1

        self._heap[obj_id] = SimulatedObject(
            type_name=type_name,
            data=initial_value,
            version=0
        )

        handle = Handle()
        handle.id = obj_id
        handle.version = 0

        self._log_audit("alloc", {
            "type": type_name,
            "handle_id": obj_id,
            "size": len(initial_value)
        })

        logger.debug(f"[SIM] Allocated {type_name}: handle={obj_id}")
        return handle

    def read(self, handle: Handle) -> bytes:
        """Read object from simulated heap."""
        obj = self._heap.get(handle.id)
        if obj is None or obj.deleted:
            raise NotFoundError(-8, f"Object {handle.id} not found")

        self._log_audit("read", {"handle_id": handle.id})
        logger.debug(f"[SIM] Read handle={handle.id}: {len(obj.data)} bytes")
        return obj.data

    def write(self, handle: Handle, patch: bytes, expected_version: int = 0) -> int:
        """Update object in simulated heap with JSON Patch."""
        if not isinstance(patch, bytes):
            raise InvalidArgumentError(-7, "patch must be bytes")

        obj = self._heap.get(handle.id)
        if obj is None or obj.deleted:
            raise NotFoundError(-8, f"Object {handle.id} not found")

        # CAS check if expected_version > 0
        if expected_version > 0 and obj.version != expected_version:
            raise InvalidArgumentError(-7, f"Version mismatch: expected {expected_version}, got {obj.version}")

        # Apply JSON Patch
        try:
            current_data = json.loads(obj.data.decode('utf-8')) if obj.data else {}
            patch_ops = json.loads(patch.decode('utf-8'))

            for op in patch_ops:
                if op["op"] == "replace":
                    path = op["path"].strip("/").split("/")
                    target = current_data
                    for part in path[:-1]:
                        if part.isdigit():
                            target = target[int(part)]
                        else:
                            target = target[part]
                    key = path[-1]
                    if key.isdigit():
                        target[int(key)] = op["value"]
                    else:
                        target[key] = op["value"]
                elif op["op"] == "add":
                    path = op["path"].strip("/").split("/")
                    target = current_data
                    for part in path[:-1]:
                        if part.isdigit():
                            target = target[int(part)]
                        else:
                            target = target[part]
                    key = path[-1]
                    if key.isdigit():
                        target.insert(int(key), op["value"])
                    else:
                        target[key] = op["value"]
                elif op["op"] == "remove":
                    path = op["path"].strip("/").split("/")
                    target = current_data
                    for part in path[:-1]:
                        if part.isdigit():
                            target = target[int(part)]
                        else:
                            target = target[part]
                    key = path[-1]
                    if key.isdigit():
                        del target[int(key)]
                    else:
                        del target[key]

            obj.data = json.dumps(current_data).encode('utf-8')
        except (json.JSONDecodeError, KeyError, IndexError) as e:
            raise InvalidArgumentError(-7, f"Patch error: {e}")

        obj.version += 1
        new_version = obj.version

        self._log_audit("write", {
            "handle_id": handle.id,
            "new_version": new_version
        })

        logger.debug(f"[SIM] Write handle={handle.id}: version={new_version}")
        return new_version

    def delete(self, handle: Handle) -> None:
        """Delete object from simulated heap (soft delete)."""
        obj = self._heap.get(handle.id)
        if obj is None:
            raise NotFoundError(-8, f"Object {handle.id} not found")

        obj.deleted = True

        self._log_audit("delete", {"handle_id": handle.id})
        logger.debug(f"[SIM] Deleted handle={handle.id}")

    def authorize(self, operation: str, target: str) -> bool:
        """Check authorization in simulation (default: allow all)."""
        # Check if operation or target is explicitly denied
        if operation in self._denied_operations:
            self._last_denial = DenialInfo(
                reason=f"Operation '{operation}' denied by simulation policy",
                operation=operation,
                target=target
            )
            self._log_audit("authorize_denied", {
                "operation": operation,
                "target": target
            })
            return False

        if target in self._denied_targets:
            self._last_denial = DenialInfo(
                reason=f"Target '{target}' denied by simulation policy",
                operation=operation,
                target=target
            )
            self._log_audit("authorize_denied", {
                "operation": operation,
                "target": target
            })
            return False

        self._log_audit("authorize_granted", {
            "operation": operation,
            "target": target
        })
        return True

    def tool_call(self, tool_name: str, args: Union[dict, bytes]) -> bytes:
        """Simulate tool execution."""
        if isinstance(args, dict):
            args_json = json.dumps(args).encode('utf-8')
        else:
            args_json = args

        self._log_audit("tool_call", {
            "tool": tool_name,
            "args_size": len(args_json)
        })

        # Simulate some basic tools
        try:
            args_dict = json.loads(args_json.decode('utf-8'))
        except:
            args_dict = {}

        if tool_name == "add":
            a = args_dict.get("a", 0)
            b = args_dict.get("b", 0)
            return json.dumps({"result": a + b}).encode('utf-8')
        elif tool_name == "concat":
            str1 = args_dict.get("str1", "")
            str2 = args_dict.get("str2", "")
            return json.dumps({"result": str1 + str2}).encode('utf-8')
        else:
            # Return success for unknown tools in simulation
            return json.dumps({
                "status": "simulated",
                "tool": tool_name,
                "message": f"Tool '{tool_name}' executed in simulation mode"
            }).encode('utf-8')

    def inference(self, request: Union[bytes, str], prompt: str = None, max_tokens: int = 1000) -> bytes:
        """Simulate LLM inference."""
        if isinstance(request, bytes):
            try:
                req_data = json.loads(request.decode('utf-8'))
            except:
                req_data = {}
        else:
            req_data = {"model": request, "prompt": prompt}

        model = req_data.get("model", "simulated")
        prompt_text = req_data.get("prompt", req_data.get("messages", [{}])[-1].get("content", ""))

        self._log_audit("inference", {
            "model": model,
            "prompt_length": len(str(prompt_text))
        })

        # Return simulated response
        response = {
            "model": model,
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": f"[SIMULATED] This is a simulated response to: '{prompt_text[:50]}...'"
                },
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": len(str(prompt_text).split()),
                "completion_tokens": 20,
                "total_tokens": len(str(prompt_text).split()) + 20
            },
            "simulated": True
        }
        return json.dumps(response).encode('utf-8')

    def file_read(self, path: str, max_size: int = 10 * 1024 * 1024) -> bytes:
        """Simulate file read (actually reads file if it exists)."""
        if not self.authorize("read", path):
            raise OperationDeniedError(-1, f"Policy denies file read: {path}")

        self._log_audit("file_read", {"path": path})

        # In simulation, try to actually read the file
        try:
            with open(path, "rb") as f:
                return f.read(max_size)
        except FileNotFoundError:
            raise NotFoundError(-8, f"File not found: {path}")
        except OSError as e:
            raise LibakError(-1, f"File read error: {e}")

    def file_write(self, path: str, data: bytes) -> None:
        """Simulate file write (actually writes file)."""
        if not self.authorize("write", path):
            raise OperationDeniedError(-1, f"Policy denies file write: {path}")

        self._log_audit("file_write", {"path": path, "size": len(data)})

        # In simulation, try to actually write the file
        try:
            with open(path, "wb") as f:
                f.write(data)
        except OSError as e:
            raise LibakError(-1, f"File write error: {e}")

    def audit_log(self, event_type: str, details: dict = None) -> None:
        """Log an audit event."""
        self._log_audit(event_type, details or {})

    def audit_logs(self) -> List[bytes]:
        """Get all audit logs."""
        return [json.dumps(entry).encode('utf-8') for entry in self._audit_log]

    def audit_query(self, query: Union[bytes, dict] = None, **kwargs) -> List[bytes]:
        """Query audit logs."""
        if query:
            if isinstance(query, bytes):
                query = json.loads(query.decode('utf-8'))
        else:
            query = kwargs

        event_type = query.get("event_type")
        limit = query.get("limit", 100)

        results = []
        for entry in reversed(self._audit_log):
            if event_type and entry.get("event") != event_type:
                continue
            results.append(json.dumps(entry).encode('utf-8'))
            if len(results) >= limit:
                break

        return results

    def get_last_denial(self) -> Optional[DenialInfo]:
        """Get last denial info."""
        return self._last_denial

    def _log_audit(self, event: str, details: dict) -> None:
        """Internal: log audit event."""
        entry = {
            "timestamp": time.time(),
            "event": event,
            "actor": "simulation",
            **details
        }
        self._audit_log.append(entry)

    # Simulation-specific methods
    def deny_operation(self, operation: str) -> None:
        """Add operation to deny list."""
        self._denied_operations.add(operation)

    def deny_target(self, target: str) -> None:
        """Add target to deny list."""
        self._denied_targets.add(target)

    def allow_all(self) -> None:
        """Reset to allow all operations."""
        self._denied_operations.clear()
        self._denied_targets.clear()


# ============================================================================
# AUTHORITY KERNEL CONTEXT MANAGER
# ============================================================================

class AuthorityKernel:
    """Context manager for Authority Kernel operations.

    Provides low-level syscall wrappers and high-level convenience methods
    for interacting with the Authority Kernel through libak.

    Usage (real kernel):
        with AuthorityKernel() as ak:
            handle = ak.alloc("counter", b'{"value": 0}')
            data = ak.read(handle)

    Usage (simulation mode - default for examples):
        with AuthorityKernel(simulate=True) as ak:
            handle = ak.alloc("counter", b'{"value": 0}')
            data = ak.read(handle)

    Args:
        simulate: If True, use in-memory simulation instead of real kernel.
                  This allows testing without building/running the kernel.
        libak_path: Explicit path to libak.so (ignored in simulate mode)
        debug: Enable debug logging

    Raises:
        LibakError: If libak.so cannot be loaded (only in non-simulate mode)
    """

    # Default maximum sizes for operations
    MAX_ALLOC_SIZE = 1024 * 1024  # 1 MB
    MAX_READ_SIZE = 1024 * 1024   # 1 MB
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
    MAX_HTTP_RESPONSE = 10 * 1024 * 1024  # 10 MB

    def __init__(self, libak_path: Optional[str] = None, debug: bool = False,
                 simulate: bool = False):
        """Initialize Authority Kernel context.

        Args:
            libak_path: Explicit path to libak.so, or None to search defaults
            debug: Enable debug logging
            simulate: Use in-memory simulation instead of real kernel

        Raises:
            LibakError: If libak.so cannot be loaded (only if simulate=False)
        """
        self.debug = debug
        self.simulate = simulate
        self._initialized = False
        self._last_denial: Optional[DenialInfo] = None

        if simulate:
            # Use simulated kernel
            self._sim = SimulatedKernel(debug=debug)
            self.libak = None
            logger.info("Authority Kernel running in SIMULATION mode")
        else:
            # Use real kernel
            self._sim = None
            self.libak = LibakLoader.load(libak_path)
            # Setup function signatures
            self._setup_function_signatures()

    def __enter__(self) -> "AuthorityKernel":
        """Enter context manager."""
        self.init()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit context manager."""
        self.shutdown()

    def _setup_function_signatures(self) -> None:
        """Setup ctypes function signatures for libak functions."""
        # ak_syscall(uint64_t sysnum, uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4)
        self.libak.ak_syscall.argtypes = [c_uint64, c_uint64, c_uint64, c_uint64, c_uint64, c_uint64]
        self.libak.ak_syscall.restype = c_int64

        # ak_init()
        self.libak.ak_init.argtypes = []
        self.libak.ak_init.restype = c_int64

        # ak_shutdown()
        self.libak.ak_shutdown.argtypes = []
        self.libak.ak_shutdown.restype = None

        # ak_alloc(const char *type_name, const uint8_t *initial_value, size_t value_len, ak_handle_t *out_handle)
        self.libak.ak_alloc.argtypes = [c_char_p, POINTER(c_uint8), c_uint64, POINTER(Handle)]
        self.libak.ak_alloc.restype = c_int64

        # ak_read(ak_handle_t handle, uint8_t *out_value, size_t max_len, size_t *out_len)
        self.libak.ak_read.argtypes = [Handle, POINTER(c_uint8), c_uint64, POINTER(c_uint64)]
        self.libak.ak_read.restype = c_int64

        # ak_write(ak_handle_t handle, const uint8_t *patch, size_t patch_len, uint32_t expected_version, uint32_t *out_new_version)
        self.libak.ak_write.argtypes = [Handle, POINTER(c_uint8), c_uint64, c_uint32, POINTER(c_uint32)]
        self.libak.ak_write.restype = c_int64

        # ak_delete(ak_handle_t handle)
        self.libak.ak_delete.argtypes = [Handle]
        self.libak.ak_delete.restype = c_int64

        # ak_call_tool(const ak_tool_call_t *tool_call, uint8_t *out_result, size_t max_len, size_t *out_len)
        self.libak.ak_call_tool.argtypes = [POINTER(ToolCall), POINTER(c_uint8), c_uint64, POINTER(c_uint64)]
        self.libak.ak_call_tool.restype = c_int64

        # ak_authorize(uint16_t effect_op, const char *target)
        self.libak.ak_authorize.argtypes = [c_uint16, c_char_p]
        self.libak.ak_authorize.restype = c_int64

        # ak_file_read(const char *path, uint8_t *out_data, size_t max_len, size_t *out_len)
        self.libak.ak_file_read.argtypes = [c_char_p, POINTER(c_uint8), c_uint64, POINTER(c_uint64)]
        self.libak.ak_file_read.restype = c_int64

        # ak_audit_log(const char *event_type, const uint8_t *details, size_t details_len)
        self.libak.ak_audit_log.argtypes = [c_char_p, POINTER(c_uint8), c_uint64]
        self.libak.ak_audit_log.restype = c_int64

        # ak_get_last_denial(uint8_t *out_reason, size_t max_len)
        self.libak.ak_get_last_denial.argtypes = [POINTER(c_uint8), c_uint64]
        self.libak.ak_get_last_denial.restype = c_int64

        # ak_strerror(ak_err_t err)
        self.libak.ak_strerror.argtypes = [c_int64]
        self.libak.ak_strerror.restype = c_char_p

        # ak_is_fatal(ak_err_t err)
        self.libak.ak_is_fatal.argtypes = [c_int64]
        self.libak.ak_is_fatal.restype = c_bool

    def init(self) -> None:
        """Initialize Authority Kernel.

        Should be called once at startup. Called automatically when
        entering context manager.

        Raises:
            AuthorityKernelError: If initialization fails
        """
        if self._initialized:
            logger.debug("Authority Kernel already initialized")
            return

        if self.simulate:
            self._sim.init()
            self._initialized = True
            return

        err = self.libak.ak_init()
        self._check_error(err, "ak_init")
        self._initialized = True
        logger.info("Authority Kernel initialized")

    def shutdown(self) -> None:
        """Cleanup Authority Kernel resources.

        Called automatically when exiting context manager.
        """
        if not self._initialized:
            return

        if self.simulate:
            self._sim.shutdown()
            self._initialized = False
            return

        try:
            self.libak.ak_shutdown()
            self._initialized = False
            logger.info("Authority Kernel shut down")
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")

    # ========================================================================
    # SYSCALL WRAPPER (Low-level)
    # ========================================================================

    def syscall(self, sysnum: int, arg0: int = 0, arg1: int = 0,
                arg2: int = 0, arg3: int = 0, arg4: int = 0) -> int:
        """Make raw syscall to Authority Kernel.

        Args:
            sysnum: Syscall number (1024-1100)
            arg0: First argument
            arg1: Second argument
            arg2: Third argument
            arg3: Fourth argument
            arg4: Fifth argument

        Returns:
            Raw syscall result

        Raises:
            AuthorityKernelError: If syscall fails
        """
        if not self._initialized:
            raise LibakError(-1, "Authority Kernel not initialized")

        result = self.libak.ak_syscall(
            c_uint64(sysnum), c_uint64(arg0), c_uint64(arg1),
            c_uint64(arg2), c_uint64(arg3), c_uint64(arg4)
        )

        self._check_error(result, f"syscall({sysnum})")
        return result

    # ========================================================================
    # TYPED HEAP OPERATIONS
    # ========================================================================

    def alloc(self, type_name: str, initial_value: bytes = b"") -> Handle:
        """Allocate new object in typed heap.

        Args:
            type_name: Object type identifier
            initial_value: JSON initial value as bytes

        Returns:
            Handle to allocated object

        Raises:
            AuthorityKernelError: If allocation fails
            BufferOverflowError: If initial_value too large

        Example:
            handle = ak.alloc("counter", b'{"value": 0}')
        """
        # Delegate to simulator in simulation mode
        if self.simulate:
            return self._sim.alloc(type_name, initial_value)

        if not isinstance(initial_value, bytes):
            raise InvalidArgumentError(-7, "initial_value must be bytes")

        if len(initial_value) > 1024:
            raise BufferOverflowError(
                -9,
                f"initial_value exceeds maximum size of 1024 bytes (got {len(initial_value)} bytes)"
            )

        # Prepare arguments for ak_alloc
        type_name_c = type_name.encode('utf-8')
        value_buf = (c_uint8 * len(initial_value))(*initial_value) if initial_value else None
        value_len = len(initial_value)
        out_handle = Handle()

        # Call ak_alloc
        err = self.libak.ak_alloc(
            type_name_c,
            value_buf,
            c_uint64(value_len),
            byref(out_handle)
        )

        self._check_error(err, "alloc")

        logger.debug(f"Allocated object: {out_handle}")
        return out_handle

    def read(self, handle: Handle) -> bytes:
        """Read object from typed heap.

        Args:
            handle: Object handle

        Returns:
            Object value as bytes (typically JSON)

        Raises:
            AuthorityKernelError: If read fails
            NotFoundError: If object not found

        Example:
            data = ak.read(handle)
            obj = json.loads(data.decode('utf-8'))
        """
        # Delegate to simulator in simulation mode
        if self.simulate:
            return self._sim.read(handle)

        # Prepare output buffer
        max_len = 4096
        out_value = (c_uint8 * max_len)()
        out_len = c_uint64(0)

        # Call ak_read
        err = self.libak.ak_read(
            handle,
            out_value,
            c_uint64(max_len),
            byref(out_len)
        )

        self._check_error(err, "read")

        if out_len.value > 0:
            result = bytes(out_value[:out_len.value])
            logger.debug(f"Read {out_len.value} bytes from {handle}")
            return result

        return b""

    def write(self, handle: Handle, patch: bytes,
              expected_version: int = 0) -> int:
        """Update object with compare-and-swap semantics.

        Args:
            handle: Object handle
            patch: JSON Patch (RFC 6902) as bytes
            expected_version: Expected version for CAS (0 = no CAS check)

        Returns:
            New version number after update

        Raises:
            AuthorityKernelError: If write fails or CAS mismatch
            BufferOverflowError: If patch too large

        Example:
            patch = b'[{"op": "replace", "path": "/value", "value": 42}]'
            new_version = ak.write(handle, patch)
        """
        # Delegate to simulator in simulation mode
        if self.simulate:
            return self._sim.write(handle, patch, expected_version)

        if not isinstance(patch, bytes):
            raise InvalidArgumentError(-7, "patch must be bytes")

        if len(patch) > 2000:
            raise BufferOverflowError(-9, f"patch exceeds 2000 bytes")

        # Prepare arguments for ak_write
        patch_buf = (c_uint8 * len(patch))(*patch)
        out_new_version = c_uint32(0)

        # Call ak_write
        err = self.libak.ak_write(
            handle,
            patch_buf,
            c_uint64(len(patch)),
            c_uint32(expected_version),
            byref(out_new_version)
        )

        self._check_error(err, "write")

        new_version = out_new_version.value
        logger.debug(f"Write successful, new version: {new_version}")
        return new_version

    def delete(self, handle: Handle) -> None:
        """Delete (soft delete) an object.

        Args:
            handle: Object handle

        Raises:
            AuthorityKernelError: If deletion fails

        Example:
            ak.delete(handle)
        """
        # Delegate to simulator in simulation mode
        if self.simulate:
            return self._sim.delete(handle)

        # Call ak_delete
        err = self.libak.ak_delete(handle)

        self._check_error(err, "delete")
        logger.debug(f"Deleted object: {handle}")

    # ========================================================================
    # TOOL EXECUTION
    # ========================================================================

    def tool_call(self, tool_name: str, args: Union[dict, bytes]) -> bytes:
        """Execute a tool in the WASM sandbox.

        Args:
            tool_name: Name of the tool to execute
            args: Tool arguments as dictionary or JSON bytes

        Returns:
            Tool result as bytes

        Raises:
            AuthorityKernelError: If tool execution fails
        """
        # Delegate to simulator in simulation mode
        if self.simulate:
            return self._sim.tool_call(tool_name, args)

        # Prepare tool call structure
        tool_call_struct = ToolCall()
        tool_name_bytes = tool_name.encode('utf-8')[:63]
        # Use direct assignment for c_char array (which supports bytes assignment)
        tool_call_struct.tool_name = tool_name_bytes

        # Convert args to JSON bytes if needed
        if isinstance(args, dict):
            args_json = json.dumps(args).encode('utf-8')
        else:
            args_json = args

        if len(args_json) > 2047:
            raise BufferOverflowError(-9, "Tool arguments too large")

        # Copy args_json using ctypes.memmove for c_uint8 array
        ctypes.memmove(tool_call_struct.args_json, args_json, len(args_json))
        tool_call_struct.args_len = len(args_json)

        # Call ak_call_tool
        max_result = 4096
        out_result = (c_uint8 * max_result)()
        out_len = c_uint64(0)

        err = self.libak.ak_call_tool(
            byref(tool_call_struct),
            out_result,
            c_uint64(max_result),
            byref(out_len)
        )

        self._check_error(err, "tool_call")

        return bytes(out_result[:out_len.value])

    # ========================================================================
    # LLM INFERENCE
    # ========================================================================

    def inference(self, request: Union[bytes, str], prompt: str = None, max_tokens: int = 1000) -> bytes:
        """Request LLM inference.

        Args:
            request: Either:
                - bytes: JSON-encoded inference request (preferred)
                - str: Model name (legacy, requires prompt argument)
            prompt: Prompt text (only if request is model name)
            max_tokens: Maximum tokens to generate (only if request is model name)

        Returns:
            Model response as bytes (JSON)

        Raises:
            AuthorityKernelError: If inference fails

        Example (new API):
            request = json.dumps({"model": "gpt-4", "messages": [...]}).encode()
            response = ak.inference(request)

        Example (legacy API):
            response = ak.inference("gpt-4", "What is 2+2?", max_tokens=100)
        """
        # Delegate to simulator in simulation mode
        if self.simulate:
            return self._sim.inference(request, prompt, max_tokens)

        # Handle bytes input (new API)
        if isinstance(request, bytes):
            request_json = request
        elif prompt is not None:
            # Legacy API: model, prompt, max_tokens
            model = request
            request_json = json.dumps({
                "model": model,
                "prompt": prompt,
                "max_tokens": max_tokens
            }).encode('utf-8')
        else:
            raise InvalidArgumentError(-7, "inference() requires either bytes request or (model, prompt) arguments")

        # Build inference request structure
        req = InferenceRequest()

        # Parse model from JSON for structure
        try:
            req_data = json.loads(request_json.decode('utf-8'))
            model_name = req_data.get("model", "")[:63]
        except:
            model_name = ""

        model_bytes = model_name.encode('utf-8')
        # Use direct assignment for c_char array
        req.model = model_bytes

        # Store full request JSON in prompt field using memmove
        if len(request_json) > 4095:
            request_json = request_json[:4095]
        ctypes.memmove(req.prompt, request_json, len(request_json))
        req.prompt_len = len(request_json)
        req.max_tokens = req_data.get("max_tokens", 1000) if isinstance(request, bytes) else max_tokens

        # Call via syscall (inference not in libak C API yet)
        max_response = 8192
        out_response = (c_uint8 * max_response)()

        # Use raw syscall for inference
        err = self.libak.ak_syscall(
            Syscall.INFERENCE,
            0,  # root context
            cast(byref(req), c_void_p).value or 0,
            sizeof(req),
            cast(out_response, c_void_p).value or 0,
            max_response
        )

        if err < 0:
            self._check_error(err, "inference")

        result_bytes = bytes(out_response[:err if err > 0 else 0])
        return result_bytes

    # ========================================================================
    # AUDIT LOGGING
    # ========================================================================

    def audit_log(self, event_type: str, details: dict = None) -> None:
        """Log an audit event.

        Args:
            event_type: Event type identifier
            details: Optional event details as dictionary
        """
        # Delegate to simulator in simulation mode
        if self.simulate:
            return self._sim.audit_log(event_type, details)

        event_bytes = event_type.encode('utf-8')
        details_bytes = json.dumps(details).encode('utf-8') if details else None
        details_buf = (c_uint8 * len(details_bytes))(*details_bytes) if details_bytes else None
        details_len = len(details_bytes) if details_bytes else 0

        err = self.libak.ak_audit_log(
            event_bytes,
            details_buf,
            c_uint64(details_len)
        )

        self._check_error(err, "audit_log")

    def audit_logs(self) -> list:
        """Retrieve audit logs.

        Returns:
            List of audit log entries
        """
        # Delegate to simulator in simulation mode
        if self.simulate:
            return self._sim.audit_logs()

        # Audit logs query not implemented in kernel
        return []

    def audit_query(self, query: Union[bytes, dict] = None, **kwargs) -> list:
        """Query audit logs with filters.

        Args:
            query: Either:
                - bytes: JSON-encoded query
                - dict: Query parameters
            **kwargs: Filter criteria (legacy, if query not provided)

        Returns:
            Filtered audit log entries

        Example:
            query = json.dumps({"event_type": "alloc", "limit": 10}).encode()
            results = ak.audit_query(query)
        """
        # Delegate to simulator in simulation mode
        if self.simulate:
            return self._sim.audit_query(query, **kwargs)

        # Audit query not implemented in kernel yet
        # Just return empty list for now
        return []

    # ========================================================================
    # AUTHORIZATION
    # ========================================================================

    def authorize(self, operation: str, target: str) -> bool:
        """Check if operation is authorized by policy.

        Args:
            operation: Operation name/code
            target: Target resource (path, URL, etc)

        Returns:
            True if authorized, False otherwise

        Raises:
            AuthorityKernelError: On fatal errors

        Example:
            if ak.authorize("read", "/etc/passwd"):
                data = ak.file_read("/etc/passwd")
        """
        # Delegate to simulator in simulation mode
        if self.simulate:
            return self._sim.authorize(operation, target)

        try:
            # Map operation names to syscall numbers
            op_map = {
                "read": Syscall.READ,
                "write": Syscall.WRITE,
                "alloc": Syscall.ALLOC,
                "delete": Syscall.DELETE,
                "http.get": Syscall.CALL,
                "http.post": Syscall.CALL,
            }
            op_num = op_map.get(operation, int(operation) if operation.isdigit() else 0)

            err = self.libak.ak_authorize(
                c_uint16(op_num),
                target.encode('utf-8')
            )
            return err == 0
        except Exception as e:
            logger.error(f"Authorization check failed: {e}")
            return False

    def authorize_details(self, operation: str, target: str) -> AuthorizationDetails:
        """Get authorization details for an operation.

        Args:
            operation: Operation name/code
            target: Target resource (path, URL, etc)

        Returns:
            AuthorizationDetails with capability info

        Raises:
            AuthorityKernelError: If query fails

        Example:
            details = ak.authorize_details("write", "/tmp/file.txt")
            if not details.authorized:
                print(f"Need: {details.capability_name}")
        """
        operation_int = int(operation) if operation.isdigit() else 0

        req = EffectRequest()
        req.op = Syscall.QUERY
        req.trace_id = 0

        # Format: auth:op:target
        query_str = f"auth:{operation_int}:{target}"
        query_bytes = query_str.encode('utf-8')[:511]
        req.target = query_bytes
        req.params_len = 0

        resp = EffectResponse()
        err = self.libak.ak_syscall(
            Syscall.QUERY,
            cast(byref(req), c_void_p).value or 0,
            cast(byref(resp), c_void_p).value or 0,
            0, 0, 0
        )

        if err != 0:
            logger.warning(f"Authorization query failed: {self._strerror(err)}")
            return AuthorizationDetails(
                operation=operation_int,
                target=target,
                authorized=False,
                reason=self._strerror(err)
            )

        # Parse response JSON
        if resp.result_len > 0:
            resp_bytes = bytes(resp.result[:resp.result_len])
            return AuthorizationDetails.from_json(resp_bytes, operation_int, target)

        return AuthorizationDetails(
            operation=operation_int,
            target=target,
            authorized=False
        )

    # ========================================================================
    # FILE I/O
    # ========================================================================

    def file_read(self, path: str, max_size: int = MAX_FILE_SIZE) -> bytes:
        """Read a file through policy-controlled filesystem.

        Args:
            path: File path
            max_size: Maximum bytes to read (default 10MB)

        Returns:
            File contents as bytes

        Raises:
            AuthorityKernelError: If read fails
            OperationDeniedError: If policy denies access
            NotFoundError: If file not found

        Example:
            data = ak.file_read("/etc/config.json")
            config = json.loads(data.decode('utf-8'))
        """
        if not self.authorize("read", path):
            self._update_denial_info()
            raise OperationDeniedError(
                -1,
                f"Policy denies file read: {path}",
                str(self._last_denial) if self._last_denial else ""
            )

        # Use POSIX read - routes through policy
        try:
            with open(path, "rb") as f:
                data = f.read(max_size)
            logger.debug(f"Read {len(data)} bytes from {path}")
            return data
        except FileNotFoundError:
            raise NotFoundError(-8, f"File not found: {path}")
        except OSError as e:
            raise LibakError(-1, f"File read error: {e}", path)

    def file_write(self, path: str, data: bytes) -> None:
        """Write a file through policy-controlled filesystem.

        Args:
            path: File path
            data: Data to write as bytes

        Raises:
            AuthorityKernelError: If write fails
            OperationDeniedError: If policy denies access

        Example:
            ak.file_write("/tmp/output.json", b'{"status": "ok"}')
        """
        if not self.authorize("write", path):
            self._update_denial_info()
            raise OperationDeniedError(
                -1,
                f"Policy denies file write: {path}",
                str(self._last_denial) if self._last_denial else ""
            )

        try:
            with open(path, "wb") as f:
                n = f.write(data)

            if n != len(data):
                raise BufferOverflowError(
                    -9,
                    f"Incomplete write: wrote {n}/{len(data)} bytes"
                )

            logger.debug(f"Wrote {len(data)} bytes to {path}")
        except OSError as e:
            raise LibakError(-1, f"File write error: {e}", path)

    # ========================================================================
    # HTTP REQUESTS
    # ========================================================================

    def http_request(self, method: str, url: str, body: Optional[bytes] = None,
                     max_response: int = MAX_HTTP_RESPONSE) -> bytes:
        """Make HTTP request through policy-controlled network.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc)
            url: Request URL
            body: Request body as bytes (optional)
            max_response: Maximum response size (default 10MB)

        Returns:
            Response data as bytes

        Raises:
            AuthorityKernelError: If request fails
            OperationDeniedError: If policy denies access
            TimeoutError: If request times out

        Example:
            response = ak.http_request("POST", "https://api.example.com/data",
                                     b'{"key": "value"}')
        """
        if not self.authorize("http", url):
            self._update_denial_info()
            raise OperationDeniedError(
                -1,
                f"Policy denies HTTP request: {method} {url}",
                str(self._last_denial) if self._last_denial else ""
            )

        # Build tool call for HTTP
        tool_call = ToolCall()
        tool_name = b"http"
        tool_call.tool_name = tool_name

        # Build JSON args: {"method": "...", "url": "...", "body": "..."}
        args_dict = {
            "method": method,
            "url": url,
        }
        if body is not None:
            try:
                args_dict["body"] = body.decode('utf-8')
            except UnicodeDecodeError:
                args_dict["body"] = "base64:" + __import__('base64').b64encode(body).decode('utf-8')

        args_json = json.dumps(args_dict).encode('utf-8')
        if len(args_json) > 2048:
            raise BufferOverflowError(-9, "HTTP request JSON exceeds 2048 bytes")

        for i, byte in enumerate(args_json):
            tool_call.args_json[i] = byte
        tool_call.args_len = len(args_json)

        # Execute tool call
        result_buf = (c_uint8 * max_response)()
        result_len = c_uint64(0)

        req = EffectRequest()
        req.op = Syscall.CALL
        req.trace_id = 0
        req.target = tool_name
        ctypes.memmove(req.params, tool_call.args_json, tool_call.args_len)
        req.params_len = tool_call.args_len

        resp = EffectResponse()
        err = self.libak.ak_syscall(
            Syscall.CALL,
            cast(byref(req), c_void_p).value or 0,
            cast(byref(resp), c_void_p).value or 0,
            0, 0, 0
        )

        self._check_error(err, "http_request")

        if resp.result_len > 0:
            result = bytes(resp.result[:resp.result_len])
            logger.debug(f"HTTP {method} {url}: {resp.result_len} bytes")
            return result

        return b""

    # ========================================================================
    # ERROR HANDLING
    # ========================================================================

    def get_last_denial(self) -> Optional[DenialInfo]:
        """Get information about last policy denial.

        Returns:
            DenialInfo with reason and suggestion, or None if no recent denial

        Example:
            denial = ak.get_last_denial()
            if denial:
                print(f"Denied: {denial.reason}")
                print(f"Suggestion: {denial.suggestion}")
        """
        # Delegate to simulator in simulation mode
        if self.simulate:
            return self._sim.get_last_denial()

        self._update_denial_info()
        return self._last_denial

    def _update_denial_info(self) -> None:
        """Fetch and update last denial information."""
        # Skip in simulation mode
        if self.simulate:
            return

        try:
            max_len = 2048
            resp_buf = (c_uint8 * max_len)()
            err = self.libak.ak_get_last_denial(resp_buf, max_len)

            if err == 0:
                # Find actual length of response
                resp_len = 0
                for i in range(max_len):
                    if resp_buf[i] == 0:
                        resp_len = i
                        break

                if resp_len > 0:
                    resp_bytes = bytes(resp_buf[:resp_len])
                    self._last_denial = DenialInfo.from_json(resp_bytes)
                    logger.debug(f"Last denial: {self._last_denial}")
        except Exception as e:
            logger.warning(f"Failed to fetch denial info: {e}")

    def _strerror(self, err_code: int) -> str:
        """Get human-readable error message.

        Args:
            err_code: Error code from syscall

        Returns:
            Error description string
        """
        try:
            msg_ptr = self.libak.ak_strerror(err_code)
            if msg_ptr:
                return msg_ptr.decode('utf-8')
        except Exception as e:
            logger.debug(f"Error getting error message: {e}")

        return f"Error {err_code}"

    def _is_fatal(self, err_code: int) -> bool:
        """Check if error is fatal (unrecoverable).

        Args:
            err_code: Error code from syscall

        Returns:
            True if fatal, False if retryable
        """
        try:
            return self.libak.ak_is_fatal(err_code)
        except Exception:
            return False

    def _check_error(self, err_code: int, context: str = "") -> None:
        """Check error code and raise appropriate exception.

        Args:
            err_code: Error code from syscall
            context: Context for error message

        Raises:
            AuthorityKernelError: If err_code indicates error
        """
        if err_code == 0:
            return

        error_msg = self._strerror(err_code)

        if err_code == ErrorCode.DENIED:
            self._update_denial_info()
            raise OperationDeniedError(
                err_code,
                f"{context}: {error_msg}",
                str(self._last_denial) if self._last_denial else ""
            )
        elif err_code == ErrorCode.CAP_INVALID:
            raise CapabilityError(err_code, f"{context}: Invalid capability")
        elif err_code == ErrorCode.CAP_EXPIRED:
            raise CapabilityError(err_code, f"{context}: Capability expired")
        elif err_code == ErrorCode.CAP_REVOKED:
            raise CapabilityError(err_code, f"{context}: Capability revoked")
        elif err_code == ErrorCode.BUDGET:
            raise BudgetExceededError(err_code, f"{context}: Budget exceeded")
        elif err_code == ErrorCode.INVAL:
            raise InvalidArgumentError(err_code, f"{context}: Invalid argument")
        elif err_code == ErrorCode.NOENT:
            raise NotFoundError(err_code, f"{context}: Not found")
        elif err_code == ErrorCode.OVERFLOW:
            raise BufferOverflowError(err_code, f"{context}: Buffer overflow")
        elif err_code == ErrorCode.TIMEOUT:
            raise TimeoutError(err_code, f"{context}: Operation timeout")
        elif err_code == ErrorCode.NOMEM:
            raise OutOfMemoryError(err_code, f"{context}: Out of memory")
        else:
            raise LibakError(err_code, f"{context}: {error_msg}")

    # ========================================================================
    # SIMULATION-SPECIFIC METHODS
    # ========================================================================

    def deny_operation(self, operation: str) -> None:
        """Add operation to deny list (simulation mode only).

        Args:
            operation: Operation to deny

        Raises:
            RuntimeError: If not in simulation mode
        """
        if not self.simulate:
            raise RuntimeError("deny_operation() only available in simulation mode")
        self._sim.deny_operation(operation)

    def deny_target(self, target: str) -> None:
        """Add target to deny list (simulation mode only).

        Args:
            target: Target resource to deny

        Raises:
            RuntimeError: If not in simulation mode
        """
        if not self.simulate:
            raise RuntimeError("deny_target() only available in simulation mode")
        self._sim.deny_target(target)

    def allow_all(self) -> None:
        """Reset to allow all operations (simulation mode only).

        Raises:
            RuntimeError: If not in simulation mode
        """
        if not self.simulate:
            raise RuntimeError("allow_all() only available in simulation mode")
        self._sim.allow_all()

    def is_simulated(self) -> bool:
        """Check if running in simulation mode.

        Returns:
            True if in simulation mode, False if using real kernel
        """
        return self.simulate


# ============================================================================
# MODULE INITIALIZATION
# ============================================================================

__all__ = [
    # Classes
    "AuthorityKernel",
    "SimulatedKernel",
    "LibakLoader",
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
    "BudgetExceededError",
    "InvalidArgumentError",
    "NotFoundError",
    "BufferOverflowError",
    "TimeoutError",
    "OutOfMemoryError",
    "LibakError",
]

logger.debug("Authority Kernel core module loaded")
