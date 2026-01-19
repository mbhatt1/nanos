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
"""

import ctypes
import json
import logging
import os
import platform
from ctypes import (
    CDLL, POINTER, Structure, c_char, c_char_p, c_uint8, c_uint16, c_uint32,
    c_uint64, c_int64, c_bool, c_void_p, byref, create_string_buffer, sizeof, cast
)
from pathlib import Path
from typing import Optional, Dict, Tuple, Any, Union, List
from dataclasses import dataclass
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
# AUTHORITY KERNEL CONTEXT MANAGER
# ============================================================================

class AuthorityKernel:
    """Context manager for Authority Kernel operations.

    Provides low-level syscall wrappers and high-level convenience methods
    for interacting with the Authority Kernel through libak.

    Usage:
        with AuthorityKernel() as ak:
            handle = ak.alloc("counter", b'{"value": 0}')
            data = ak.read(handle)
            ak.write(handle, b'[{"op": "replace", "path": "/value", "value": 1}]')

    Raises:
        LibakError: If libak.so cannot be loaded
    """

    # Default maximum sizes for operations
    MAX_ALLOC_SIZE = 1024 * 1024  # 1 MB
    MAX_READ_SIZE = 1024 * 1024   # 1 MB
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
    MAX_HTTP_RESPONSE = 10 * 1024 * 1024  # 10 MB

    def __init__(self, libak_path: Optional[str] = None, debug: bool = False):
        """Initialize Authority Kernel context.

        Args:
            libak_path: Explicit path to libak.so, or None to search defaults
            debug: Enable debug logging

        Raises:
            LibakError: If libak.so cannot be loaded
        """
        self.libak = LibakLoader.load(libak_path)
        self.debug = debug
        self._initialized = False
        self._last_denial: Optional[DenialInfo] = None

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
        if not isinstance(initial_value, bytes):
            raise InvalidArgumentError(-7, "initial_value must be bytes")

        if len(initial_value) > 1024:
            raise BufferOverflowError(
                -9,
                f"initial_value exceeds maximum size of 1024 bytes (got {len(initial_value)} bytes)"
            )

        req = EffectRequest()
        req.op = Syscall.ALLOC
        req.trace_id = 0

        # Pack type name into target
        type_name_bytes = type_name.encode('utf-8')[:511]
        req.target = type_name_bytes

        # Pack initial value into params
        if initial_value:
            for i, byte in enumerate(initial_value):
                req.params[i] = byte
        req.params_len = len(initial_value)

        # Make syscall
        resp = EffectResponse()
        err = self.libak.ak_syscall(
            Syscall.ALLOC,
            cast(byref(req), c_void_p).value or 0,
            cast(byref(resp), c_void_p).value or 0,
            0, 0, 0
        )

        self._check_error(err, "alloc")

        # Parse handle from response
        if resp.result_len >= sizeof(Handle):
            handle = Handle()
            ctypes.memmove(byref(handle), resp.result, sizeof(Handle))
            logger.debug(f"Allocated object: {handle}")
            return handle

        raise LibakError(-6, "Invalid response from alloc syscall")

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
        req = EffectRequest()
        req.op = Syscall.READ
        req.trace_id = 0

        # Pack handle into params
        ctypes.memmove(req.params, byref(handle), sizeof(Handle))
        req.params_len = sizeof(Handle)

        resp = EffectResponse()
        err = self.libak.ak_syscall(
            Syscall.READ,
            cast(byref(req), c_void_p).value or 0,
            cast(byref(resp), c_void_p).value or 0,
            0, 0, 0
        )

        self._check_error(err, "read")

        if resp.result_len > 0:
            result = bytes(resp.result[:resp.result_len])
            logger.debug(f"Read {resp.result_len} bytes from {handle}")
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
        if not isinstance(patch, bytes):
            raise InvalidArgumentError(-7, "patch must be bytes")

        max_patch_size = 1024 - sizeof(Handle) - 4
        if len(patch) > max_patch_size:
            raise BufferOverflowError(
                -9,
                f"patch exceeds {max_patch_size} bytes"
            )

        req = EffectRequest()
        req.op = Syscall.WRITE
        req.trace_id = 0

        # Pack handle, version, and patch into params
        offset = 0
        ctypes.memmove(req.params, byref(handle), sizeof(Handle))
        offset += sizeof(Handle)

        version_bytes = expected_version.to_bytes(4, 'little')
        ctypes.memmove(
            byref(req.params, offset),
            version_bytes,
            4
        )
        offset += 4

        if patch:
            ctypes.memmove(byref(req.params, offset), patch, len(patch))

        req.params_len = offset + len(patch)

        resp = EffectResponse()
        err = self.libak.ak_syscall(
            Syscall.WRITE,
            cast(byref(req), c_void_p).value or 0,
            cast(byref(resp), c_void_p).value or 0,
            0, 0, 0
        )

        self._check_error(err, "write")

        # Extract new version from response
        if resp.result_len >= 4:
            new_version = int.from_bytes(bytes(resp.result[:4]), 'little')
            logger.debug(f"Write successful, new version: {new_version}")
            return new_version

        raise LibakError(-6, "Invalid response from write syscall")

    def delete(self, handle: Handle) -> None:
        """Delete (soft delete) an object.

        Args:
            handle: Object handle

        Raises:
            AuthorityKernelError: If deletion fails

        Example:
            ak.delete(handle)
        """
        req = EffectRequest()
        req.op = Syscall.DELETE
        req.trace_id = 0

        ctypes.memmove(req.params, byref(handle), sizeof(Handle))
        req.params_len = sizeof(Handle)

        resp = EffectResponse()
        err = self.libak.ak_syscall(
            Syscall.DELETE,
            cast(byref(req), c_void_p).value or 0,
            cast(byref(resp), c_void_p).value or 0,
            0, 0, 0
        )

        self._check_error(err, "delete")
        logger.debug(f"Deleted object: {handle}")

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
        try:
            details = self.authorize_details(operation, target)
            return details.authorized
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
        self._update_denial_info()
        return self._last_denial

    def _update_denial_info(self) -> None:
        """Fetch and update last denial information."""
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


# ============================================================================
# MODULE INITIALIZATION
# ============================================================================

__all__ = [
    # Classes
    "AuthorityKernel",
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
