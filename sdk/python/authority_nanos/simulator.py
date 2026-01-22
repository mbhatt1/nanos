"""
Advanced Simulated Authority Kernel for testing and development.

This module provides an advanced SimulatedKernel class with more sophisticated
features than the basic SimulatedKernel in core.py. Use this module when you need:

- Regex-based allow/deny patterns for fine-grained policy control
- Custom mock LLM responses keyed by prompt patterns
- Custom mock tool response handlers
- Simulated file system
- Comprehensive JSON Patch implementation (add, remove, replace, move, copy, test)

For basic simulation, use AuthorityKernel(simulate=True) from the main SDK.
For advanced testing scenarios, use SimulatedKernel from this module.

Key features:
- In-memory typed heap (dict of handles to values)
- Regex-based policy checking (allow by default, can add deny patterns)
- Fake audit log entries with timestamps and trace IDs
- Mock LLM responses with pattern matching
- Mock tool responses with custom handlers
- Simulated file system for isolated testing

Basic Usage (recommended):
    from authority_nanos import AuthorityKernel

    # Use simulate=True to run without libak
    with AuthorityKernel(simulate=True) as ak:
        handle = ak.alloc("counter", b'{"value": 0}')
        data = ak.read(handle)

Advanced Usage (this module):
    from authority_nanos.simulator import SimulatedKernel

    with SimulatedKernel(
        deny_patterns=[r".*secret.*"],
        simulated_files={"/config.json": b'{"key": "value"}'},
    ) as ak:
        handle = ak.alloc("counter", b'{"value": 0}')
        # Fine-grained policy control with regex
        ak.add_deny_pattern(r"write:/etc/.*")
"""

import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

logger = logging.getLogger(__name__)


# ============================================================================
# SIMULATED HANDLE
# ============================================================================

@dataclass
class SimulatedHandle:
    """Simulated handle for typed heap objects.

    Mimics the real Handle structure from core.py but as a Python dataclass.

    Attributes:
        id: Unique object identifier
        version: Version number (increments on each write)
    """
    id: int
    version: int = 1

    def __repr__(self) -> str:
        return f"Handle(id={self.id}, version={self.version})"


# ============================================================================
# HEAP OBJECT
# ============================================================================

@dataclass
class HeapObject:
    """Object stored in the simulated typed heap.

    Attributes:
        type_name: Type identifier for the object
        value: Current value as bytes (JSON)
        version: Current version number
        created_at: Creation timestamp
        updated_at: Last update timestamp
        deleted: Soft delete flag
    """
    type_name: str
    value: bytes
    version: int = 1
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    deleted: bool = False


# ============================================================================
# AUDIT LOG ENTRY
# ============================================================================

@dataclass
class AuditLogEntry:
    """Entry in the simulated audit log.

    Attributes:
        timestamp: ISO timestamp when event occurred
        event_type: Type of event (alloc, read, write, delete, etc.)
        details: Event-specific details as dict
        trace_id: Correlation ID for request tracing
    """
    timestamp: str
    event_type: str
    details: Dict[str, Any]
    trace_id: str = field(default_factory=lambda: str(uuid.uuid4()))


# ============================================================================
# DENIAL INFO
# ============================================================================

@dataclass
class SimulatedDenialInfo:
    """Information about a simulated policy denial.

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


# ============================================================================
# AUTHORIZATION DETAILS
# ============================================================================

@dataclass
class SimulatedAuthorizationDetails:
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


# ============================================================================
# MOCK LLM RESPONSES
# ============================================================================

DEFAULT_MOCK_LLM_RESPONSES = {
    "gpt-4": {
        "default": {
            "id": "chatcmpl-sim-001",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": "gpt-4-simulated",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "This is a simulated response from the mock LLM. "
                               "In a real deployment, this would be an actual LLM response."
                },
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 25,
                "total_tokens": 35
            }
        },
        "2 + 2": {
            "id": "chatcmpl-sim-math-001",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": "gpt-4-simulated",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "2 + 2 = 4"
                },
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 5,
                "completion_tokens": 5,
                "total_tokens": 10
            }
        }
    },
    "claude-3": {
        "default": {
            "id": "msg-sim-001",
            "type": "message",
            "role": "assistant",
            "content": [{
                "type": "text",
                "text": "This is a simulated Claude response."
            }],
            "model": "claude-3-simulated",
            "stop_reason": "end_turn",
            "usage": {
                "input_tokens": 10,
                "output_tokens": 15
            }
        }
    }
}


# ============================================================================
# MOCK TOOL RESPONSES
# ============================================================================

DEFAULT_MOCK_TOOL_RESPONSES = {
    "add": lambda args: json.dumps({"result": args.get("a", 0) + args.get("b", 0)}),
    "concat": lambda args: json.dumps({"result": args.get("str1", "") + args.get("str2", "")}),
    "multiply": lambda args: json.dumps({"result": args.get("a", 0) * args.get("b", 0)}),
    "echo": lambda args: json.dumps({"result": args.get("message", "")}),
    "http": lambda args: json.dumps({
        "status": 200,
        "body": f"Mock response for {args.get('method', 'GET')} {args.get('url', '')}"
    }),
}


# ============================================================================
# SIMULATED KERNEL
# ============================================================================

class SimulatedKernel:
    """Simulated Authority Kernel for testing and development.

    Provides mock implementations of all AuthorityKernel methods using
    in-memory data structures. Useful for:
    - Running examples without a real kernel
    - Unit testing
    - Development and prototyping

    Attributes:
        typed_heap: Dict mapping handle IDs to HeapObject instances
        audit_log: List of AuditLogEntry instances
        deny_patterns: Set of regex patterns for operations to deny
        allow_patterns: Set of regex patterns for operations to allow (overrides deny)
        mock_llm_responses: Dict of model -> prompt_pattern -> response
        mock_tool_responses: Dict of tool_name -> response generator function
        debug: Enable debug logging

    Example:
        with SimulatedKernel() as ak:
            # Allocate an object
            handle = ak.alloc("counter", b'{"value": 0}')

            # Read it back
            data = ak.read(handle)

            # Modify with JSON Patch
            patch = b'[{"op": "replace", "path": "/value", "value": 42}]'
            ak.write(handle, patch)

            # Add a deny pattern
            ak.add_deny_pattern(r".*secret.*")

            # This will now be denied
            if not ak.authorize("read", "/path/to/secret"):
                print("Denied by policy")
    """

    # Maximum sizes (matching core.py)
    MAX_ALLOC_SIZE = 1024 * 1024  # 1 MB
    MAX_READ_SIZE = 1024 * 1024   # 1 MB
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
    MAX_HTTP_RESPONSE = 10 * 1024 * 1024  # 10 MB

    def __init__(
        self,
        debug: bool = False,
        deny_patterns: Optional[List[str]] = None,
        allow_patterns: Optional[List[str]] = None,
        mock_llm_responses: Optional[Dict[str, Any]] = None,
        mock_tool_responses: Optional[Dict[str, Callable]] = None,
        simulated_files: Optional[Dict[str, bytes]] = None,
    ):
        """Initialize the simulated kernel.

        Args:
            debug: Enable debug logging
            deny_patterns: List of regex patterns for operations to deny
            allow_patterns: List of regex patterns that override deny (always allow)
            mock_llm_responses: Custom mock LLM responses (model -> prompt_pattern -> response)
            mock_tool_responses: Custom mock tool responses (tool_name -> callable)
            simulated_files: Dict of path -> content for simulated file system
        """
        self.debug = debug
        self._initialized = False

        # Typed heap: id -> HeapObject
        self.typed_heap: Dict[int, HeapObject] = {}
        self._next_handle_id = 1

        # Audit log
        self.audit_log: List[AuditLogEntry] = []

        # Policy patterns
        self.deny_patterns: Set[str] = set(deny_patterns or [])
        self.allow_patterns: Set[str] = set(allow_patterns or [])

        # Mock responses
        self.mock_llm_responses = mock_llm_responses or DEFAULT_MOCK_LLM_RESPONSES.copy()
        self.mock_tool_responses = mock_tool_responses or DEFAULT_MOCK_TOOL_RESPONSES.copy()

        # Simulated file system
        self.simulated_files: Dict[str, bytes] = simulated_files or {
            "/etc/config.json": b'{"setting": "value", "debug": false}',
            "/tmp/test.txt": b"Test file content",
        }

        # Last denial info
        self._last_denial: Optional[SimulatedDenialInfo] = None

        logger.debug("SimulatedKernel created")

    def __enter__(self) -> "SimulatedKernel":
        """Enter context manager."""
        self.init()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit context manager."""
        self.shutdown()

    def init(self) -> None:
        """Initialize the simulated kernel.

        Called automatically when entering context manager.
        """
        if self._initialized:
            logger.debug("SimulatedKernel already initialized")
            return

        self._initialized = True
        self._log_audit("init", {"simulator": True})
        logger.info("SimulatedKernel initialized")

    def shutdown(self) -> None:
        """Shutdown the simulated kernel.

        Called automatically when exiting context manager.
        """
        if not self._initialized:
            return

        self._log_audit("shutdown", {"objects_in_heap": len(self.typed_heap)})
        self._initialized = False
        logger.info("SimulatedKernel shut down")

    # ========================================================================
    # POLICY CONFIGURATION
    # ========================================================================

    def add_deny_pattern(self, pattern: str) -> None:
        """Add a regex pattern that will cause authorize() to return False.

        Args:
            pattern: Regex pattern to match against "operation:target"

        Example:
            ak.add_deny_pattern(r".*secret.*")  # Deny anything with "secret"
            ak.add_deny_pattern(r"write:/etc/.*")  # Deny writes to /etc/
        """
        self.deny_patterns.add(pattern)
        logger.debug(f"Added deny pattern: {pattern}")

    def remove_deny_pattern(self, pattern: str) -> None:
        """Remove a deny pattern.

        Args:
            pattern: Pattern to remove
        """
        self.deny_patterns.discard(pattern)
        logger.debug(f"Removed deny pattern: {pattern}")

    def add_allow_pattern(self, pattern: str) -> None:
        """Add a regex pattern that will always be allowed (overrides deny).

        Args:
            pattern: Regex pattern to match against "operation:target"

        Example:
            ak.add_allow_pattern(r"read:/tmp/.*")  # Always allow reads from /tmp
        """
        self.allow_patterns.add(pattern)
        logger.debug(f"Added allow pattern: {pattern}")

    def remove_allow_pattern(self, pattern: str) -> None:
        """Remove an allow pattern.

        Args:
            pattern: Pattern to remove
        """
        self.allow_patterns.discard(pattern)
        logger.debug(f"Removed allow pattern: {pattern}")

    def clear_patterns(self) -> None:
        """Clear all deny and allow patterns."""
        self.deny_patterns.clear()
        self.allow_patterns.clear()
        logger.debug("Cleared all policy patterns")

    # ========================================================================
    # TYPED HEAP OPERATIONS
    # ========================================================================

    def alloc(self, type_name: str, initial_value: bytes = b"") -> SimulatedHandle:
        """Allocate a new object in the simulated typed heap.

        Args:
            type_name: Type identifier for the object
            initial_value: Initial JSON value as bytes

        Returns:
            Handle to the allocated object

        Raises:
            ValueError: If initial_value exceeds maximum size

        Example:
            handle = ak.alloc("counter", b'{"value": 0}')
        """
        self._ensure_initialized()

        if not isinstance(initial_value, bytes):
            raise ValueError("initial_value must be bytes")

        if len(initial_value) > 1024:
            raise ValueError(f"initial_value exceeds maximum size of 1024 bytes (got {len(initial_value)} bytes)")

        # Validate JSON if provided
        if initial_value:
            try:
                json.loads(initial_value.decode('utf-8'))
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                logger.warning(f"initial_value is not valid JSON: {e}")

        # Create handle and object
        handle_id = self._next_handle_id
        self._next_handle_id += 1

        obj = HeapObject(
            type_name=type_name,
            value=initial_value,
            version=1,
        )
        self.typed_heap[handle_id] = obj

        handle = SimulatedHandle(id=handle_id, version=1)

        self._log_audit("alloc", {
            "handle_id": handle_id,
            "type_name": type_name,
            "value_len": len(initial_value),
        })

        logger.debug(f"Allocated object: {handle}")
        return handle

    def read(self, handle: SimulatedHandle) -> bytes:
        """Read an object from the simulated typed heap.

        Args:
            handle: Object handle

        Returns:
            Object value as bytes

        Raises:
            KeyError: If object not found
            ValueError: If object has been deleted

        Example:
            data = ak.read(handle)
            obj = json.loads(data.decode('utf-8'))
        """
        self._ensure_initialized()

        obj = self._get_object(handle.id)
        if obj.deleted:
            raise ValueError(f"Object {handle.id} has been deleted")

        self._log_audit("read", {
            "handle_id": handle.id,
            "type_name": obj.type_name,
            "value_len": len(obj.value),
        })

        logger.debug(f"Read {len(obj.value)} bytes from handle {handle.id}")
        return obj.value

    def write(self, handle: SimulatedHandle, patch: bytes, expected_version: int = 0) -> int:
        """Update an object with JSON Patch.

        Args:
            handle: Object handle
            patch: JSON Patch (RFC 6902) as bytes
            expected_version: Expected version for CAS (0 = no check)

        Returns:
            New version number

        Raises:
            KeyError: If object not found
            ValueError: If CAS check fails or object deleted

        Example:
            patch = b'[{"op": "replace", "path": "/value", "value": 42}]'
            new_version = ak.write(handle, patch)
        """
        self._ensure_initialized()

        if not isinstance(patch, bytes):
            raise ValueError("patch must be bytes")

        if len(patch) > 2000:
            raise ValueError("patch exceeds 2000 bytes")

        obj = self._get_object(handle.id)
        if obj.deleted:
            raise ValueError(f"Object {handle.id} has been deleted")

        # CAS check
        if expected_version != 0 and obj.version != expected_version:
            raise ValueError(
                f"Version mismatch: expected {expected_version}, got {obj.version}"
            )

        # Parse and apply JSON Patch
        try:
            patch_ops = json.loads(patch.decode('utf-8'))
            current_value = json.loads(obj.value.decode('utf-8')) if obj.value else {}
            new_value = self._apply_json_patch(current_value, patch_ops)
            obj.value = json.dumps(new_value).encode('utf-8')
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise ValueError(f"Invalid JSON in patch or value: {e}")

        # Update version
        obj.version += 1
        obj.updated_at = time.time()

        self._log_audit("write", {
            "handle_id": handle.id,
            "type_name": obj.type_name,
            "new_version": obj.version,
            "patch_len": len(patch),
        })

        logger.debug(f"Write to handle {handle.id}, new version: {obj.version}")
        return obj.version

    def delete(self, handle: SimulatedHandle) -> None:
        """Soft delete an object.

        Args:
            handle: Object handle

        Raises:
            KeyError: If object not found

        Example:
            ak.delete(handle)
        """
        self._ensure_initialized()

        obj = self._get_object(handle.id)
        obj.deleted = True
        obj.updated_at = time.time()

        self._log_audit("delete", {
            "handle_id": handle.id,
            "type_name": obj.type_name,
        })

        logger.debug(f"Deleted handle {handle.id}")

    # ========================================================================
    # TOOL EXECUTION
    # ========================================================================

    def tool_call(self, tool_name: str, args: Union[dict, bytes]) -> bytes:
        """Execute a simulated tool.

        Args:
            tool_name: Name of the tool
            args: Tool arguments as dict or JSON bytes

        Returns:
            Tool result as bytes

        Example:
            result = ak.tool_call("add", {"a": 5, "b": 3})
            # Returns: b'{"result": 8}'
        """
        self._ensure_initialized()

        # Parse args
        if isinstance(args, bytes):
            try:
                args_dict = json.loads(args.decode('utf-8'))
            except (json.JSONDecodeError, UnicodeDecodeError):
                args_dict = {}
        else:
            args_dict = args

        self._log_audit("tool_call", {
            "tool_name": tool_name,
            "args": args_dict,
        })

        # Look up mock response
        if tool_name in self.mock_tool_responses:
            handler = self.mock_tool_responses[tool_name]
            if callable(handler):
                result = handler(args_dict)
                if isinstance(result, str):
                    result = result.encode('utf-8')
                return result
            else:
                # Static response
                if isinstance(handler, bytes):
                    return handler
                return json.dumps(handler).encode('utf-8')

        # Default: return echo of args
        return json.dumps({
            "tool": tool_name,
            "args": args_dict,
            "simulated": True,
            "message": f"Mock response for tool '{tool_name}'"
        }).encode('utf-8')

    # ========================================================================
    # LLM INFERENCE
    # ========================================================================

    def inference(self, request: Union[bytes, str], prompt: str = None, max_tokens: int = 1000) -> bytes:
        """Request simulated LLM inference.

        Args:
            request: Either bytes (JSON request) or str (model name for legacy API)
            prompt: Prompt text (only if request is model name)
            max_tokens: Maximum tokens (only if request is model name)

        Returns:
            Mock LLM response as bytes (JSON)

        Example:
            request = json.dumps({"model": "gpt-4", "messages": [...]}).encode()
            response = ak.inference(request)
        """
        self._ensure_initialized()

        # Parse request
        if isinstance(request, bytes):
            try:
                req_data = json.loads(request.decode('utf-8'))
            except (json.JSONDecodeError, UnicodeDecodeError):
                req_data = {}
            model = req_data.get("model", "gpt-4")
            prompt_text = ""
            if "messages" in req_data:
                # Extract prompt from messages
                for msg in req_data.get("messages", []):
                    if msg.get("role") == "user":
                        prompt_text = msg.get("content", "")
                        break
            elif "prompt" in req_data:
                prompt_text = req_data.get("prompt", "")
        else:
            # Legacy API
            model = request
            prompt_text = prompt or ""

        self._log_audit("inference", {
            "model": model,
            "prompt_preview": prompt_text[:100] if prompt_text else "",
            "max_tokens": max_tokens,
        })

        # Find matching mock response
        model_responses = self.mock_llm_responses.get(model, {})
        if not model_responses:
            # Try partial match
            for model_key in self.mock_llm_responses:
                if model_key in model or model in model_key:
                    model_responses = self.mock_llm_responses[model_key]
                    break

        # Look for prompt-specific response
        response = None
        for pattern, resp in model_responses.items():
            if pattern == "default":
                continue
            if pattern.lower() in prompt_text.lower():
                response = resp
                break

        if response is None:
            response = model_responses.get("default", {
                "id": f"sim-{uuid.uuid4().hex[:8]}",
                "model": f"{model}-simulated",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": f"Simulated response for model '{model}'"
                    },
                    "finish_reason": "stop"
                }]
            })

        return json.dumps(response).encode('utf-8')

    # ========================================================================
    # AUTHORIZATION
    # ========================================================================

    def authorize(self, operation: str, target: str) -> bool:
        """Check if operation is authorized by simulated policy.

        Args:
            operation: Operation name (read, write, http.get, etc.)
            target: Target resource (path, URL, etc.)

        Returns:
            True if authorized, False if denied

        Example:
            if ak.authorize("read", "/etc/passwd"):
                data = ak.file_read("/etc/passwd")
        """
        self._ensure_initialized()

        check_string = f"{operation}:{target}"

        # Check allow patterns first (override deny)
        for pattern in self.allow_patterns:
            try:
                if re.search(pattern, check_string):
                    logger.debug(f"Authorized by allow pattern: {pattern}")
                    self._log_audit("authorize", {
                        "operation": operation,
                        "target": target,
                        "authorized": True,
                        "matched_pattern": pattern,
                    })
                    return True
            except re.error:
                pass

        # Check deny patterns
        for pattern in self.deny_patterns:
            try:
                if re.search(pattern, check_string):
                    logger.debug(f"Denied by pattern: {pattern}")
                    self._last_denial = SimulatedDenialInfo(
                        reason=f"Denied by policy pattern: {pattern}",
                        operation=operation,
                        target=target,
                        suggestion="Check your policy configuration or add an allow pattern",
                    )
                    self._log_audit("authorize", {
                        "operation": operation,
                        "target": target,
                        "authorized": False,
                        "matched_pattern": pattern,
                    })
                    return False
            except re.error:
                pass

        # Default: allow
        self._log_audit("authorize", {
            "operation": operation,
            "target": target,
            "authorized": True,
        })
        return True

    def authorize_details(self, operation: str, target: str) -> SimulatedAuthorizationDetails:
        """Get authorization details for an operation.

        Args:
            operation: Operation name
            target: Target resource

        Returns:
            SimulatedAuthorizationDetails with capability info

        Example:
            details = ak.authorize_details("write", "/tmp/file.txt")
            if not details.authorized:
                print(f"Denied: {details.reason}")
        """
        self._ensure_initialized()

        authorized = self.authorize(operation, target)
        operation_int = int(operation) if operation.isdigit() else 0

        if authorized:
            return SimulatedAuthorizationDetails(
                operation=operation_int,
                target=target,
                authorized=True,
                capability_name=f"cap:{operation}",
                ttl_ms=3600000,  # 1 hour
                reason="Allowed by simulator policy",
            )
        else:
            return SimulatedAuthorizationDetails(
                operation=operation_int,
                target=target,
                authorized=False,
                capability_name=f"cap:{operation}",
                reason=self._last_denial.reason if self._last_denial else "Denied by policy",
            )

    # ========================================================================
    # FILE I/O
    # ========================================================================

    def file_read(self, path: str, max_size: int = None) -> bytes:
        """Read a file from the simulated file system.

        Args:
            path: File path
            max_size: Maximum bytes to read

        Returns:
            File contents as bytes

        Raises:
            PermissionError: If policy denies access
            FileNotFoundError: If file not found

        Example:
            data = ak.file_read("/etc/config.json")
        """
        self._ensure_initialized()
        max_size = max_size or self.MAX_FILE_SIZE

        if not self.authorize("read", path):
            raise PermissionError(f"Policy denies file read: {path}")

        self._log_audit("file_read", {"path": path})

        # Check simulated files first
        if path in self.simulated_files:
            data = self.simulated_files[path]
            return data[:max_size]

        # Fall back to real file system (for development convenience)
        try:
            with open(path, "rb") as f:
                return f.read(max_size)
        except FileNotFoundError:
            raise FileNotFoundError(f"File not found: {path}")

    def file_write(self, path: str, data: bytes) -> None:
        """Write a file to the simulated file system.

        Args:
            path: File path
            data: Data to write

        Raises:
            PermissionError: If policy denies access

        Example:
            ak.file_write("/tmp/output.json", b'{"status": "ok"}')
        """
        self._ensure_initialized()

        if not self.authorize("write", path):
            raise PermissionError(f"Policy denies file write: {path}")

        self._log_audit("file_write", {"path": path, "size": len(data)})

        # Store in simulated files
        self.simulated_files[path] = data
        logger.debug(f"Wrote {len(data)} bytes to simulated file: {path}")

    # ========================================================================
    # HTTP REQUESTS
    # ========================================================================

    def http_request(self, method: str, url: str, body: Optional[bytes] = None,
                     max_response: int = None) -> bytes:
        """Make a simulated HTTP request.

        Args:
            method: HTTP method (GET, POST, etc.)
            url: Request URL
            body: Request body
            max_response: Maximum response size

        Returns:
            Mock response as bytes

        Raises:
            PermissionError: If policy denies access

        Example:
            response = ak.http_request("GET", "https://api.example.com/data")
        """
        self._ensure_initialized()

        if not self.authorize("http", url):
            raise PermissionError(f"Policy denies HTTP request: {method} {url}")

        self._log_audit("http_request", {
            "method": method,
            "url": url,
            "body_size": len(body) if body else 0,
        })

        # Return mock response
        response = {
            "status": 200,
            "headers": {
                "Content-Type": "application/json",
                "X-Simulated": "true",
            },
            "body": f"Mock {method} response for {url}",
        }
        return json.dumps(response).encode('utf-8')

    # ========================================================================
    # AUDIT LOGGING
    # ========================================================================

    def audit_log(self, event_type: str, details: dict = None) -> None:
        """Log a custom audit event.

        Args:
            event_type: Event type identifier
            details: Event details as dictionary

        Example:
            ak.audit_log("custom_event", {"action": "test"})
        """
        self._ensure_initialized()
        self._log_audit(event_type, details or {})

    def audit_logs(self) -> List[bytes]:
        """Retrieve all audit logs.

        Returns:
            List of audit log entries as JSON bytes

        Example:
            logs = ak.audit_logs()
            for log in logs:
                entry = json.loads(log.decode())
                print(entry)
        """
        self._ensure_initialized()
        return [
            json.dumps({
                "timestamp": entry.timestamp,
                "event": entry.event_type,
                "details": entry.details,
                "trace_id": entry.trace_id,
            }).encode('utf-8')
            for entry in self.audit_log
        ]

    def audit_query(self, query: Union[bytes, dict] = None, **kwargs) -> List[bytes]:
        """Query audit logs with filters.

        Args:
            query: Query as JSON bytes or dict
            **kwargs: Filter criteria

        Returns:
            Filtered audit log entries as JSON bytes

        Example:
            results = ak.audit_query({"event_type": "alloc", "limit": 10})
        """
        self._ensure_initialized()

        # Parse query
        if isinstance(query, bytes):
            try:
                filters = json.loads(query.decode('utf-8'))
            except (json.JSONDecodeError, UnicodeDecodeError):
                filters = {}
        elif isinstance(query, dict):
            filters = query
        else:
            filters = kwargs

        event_type = filters.get("event_type")
        limit = filters.get("limit", 100)

        # Filter logs
        results = []
        for entry in self.audit_log:
            if event_type and entry.event_type != event_type:
                continue
            results.append(json.dumps({
                "timestamp": entry.timestamp,
                "event": entry.event_type,
                "details": entry.details,
                "trace_id": entry.trace_id,
            }).encode('utf-8'))
            if len(results) >= limit:
                break

        return results

    # ========================================================================
    # ERROR HANDLING
    # ========================================================================

    def get_last_denial(self) -> Optional[SimulatedDenialInfo]:
        """Get information about the last policy denial.

        Returns:
            SimulatedDenialInfo or None if no recent denial

        Example:
            denial = ak.get_last_denial()
            if denial:
                print(f"Denied: {denial.reason}")
        """
        return self._last_denial

    # ========================================================================
    # SYSCALL (Low-level compatibility)
    # ========================================================================

    def syscall(self, sysnum: int, arg0: int = 0, arg1: int = 0,
                arg2: int = 0, arg3: int = 0, arg4: int = 0) -> int:
        """Make a simulated syscall.

        This is a compatibility method that logs the syscall but returns 0.

        Args:
            sysnum: Syscall number
            arg0-arg4: Syscall arguments

        Returns:
            0 (success)
        """
        self._ensure_initialized()

        self._log_audit("syscall", {
            "sysnum": sysnum,
            "args": [arg0, arg1, arg2, arg3, arg4],
        })

        return 0

    # ========================================================================
    # INTERNAL HELPERS
    # ========================================================================

    def _ensure_initialized(self) -> None:
        """Ensure kernel is initialized."""
        if not self._initialized:
            raise RuntimeError("SimulatedKernel not initialized. Use 'with' statement or call init().")

    def _get_object(self, handle_id: int) -> HeapObject:
        """Get object from heap by handle ID.

        Args:
            handle_id: Handle ID

        Returns:
            HeapObject

        Raises:
            KeyError: If not found
        """
        if handle_id not in self.typed_heap:
            raise KeyError(f"Object not found: handle_id={handle_id}")
        return self.typed_heap[handle_id]

    def _log_audit(self, event_type: str, details: Dict[str, Any]) -> None:
        """Add entry to audit log.

        Args:
            event_type: Event type
            details: Event details
        """
        entry = AuditLogEntry(
            timestamp=datetime.utcnow().isoformat() + "Z",
            event_type=event_type,
            details=details,
        )
        self.audit_log.append(entry)
        logger.debug(f"Audit: {event_type} - {details}")

    def _apply_json_patch(self, document: Any, patch: List[Dict]) -> Any:
        """Apply JSON Patch operations to a document.

        Implements a subset of RFC 6902:
        - add: Add a value
        - remove: Remove a value
        - replace: Replace a value
        - test: Test a value (for assertions)

        Args:
            document: Original document
            patch: List of patch operations

        Returns:
            Modified document

        Raises:
            ValueError: If patch operation fails
        """
        result = document

        for op in patch:
            operation = op.get("op")
            path = op.get("path", "")
            value = op.get("value")

            # Parse path into parts
            parts = [p for p in path.split("/") if p]

            if operation == "add":
                result = self._patch_set(result, parts, value)
            elif operation == "remove":
                result = self._patch_remove(result, parts)
            elif operation == "replace":
                result = self._patch_set(result, parts, value)
            elif operation == "test":
                current = self._patch_get(result, parts)
                if current != value:
                    raise ValueError(f"Test failed: {path} is {current}, expected {value}")
            elif operation == "move":
                from_path = op.get("from", "")
                from_parts = [p for p in from_path.split("/") if p]
                val = self._patch_get(result, from_parts)
                result = self._patch_remove(result, from_parts)
                result = self._patch_set(result, parts, val)
            elif operation == "copy":
                from_path = op.get("from", "")
                from_parts = [p for p in from_path.split("/") if p]
                val = self._patch_get(result, from_parts)
                result = self._patch_set(result, parts, val)
            else:
                raise ValueError(f"Unknown patch operation: {operation}")

        return result

    def _patch_get(self, document: Any, parts: List[str]) -> Any:
        """Get value at path."""
        current = document
        for part in parts:
            if isinstance(current, dict):
                current = current[part]
            elif isinstance(current, list):
                current = current[int(part)]
            else:
                raise ValueError(f"Cannot navigate to {part}")
        return current

    def _patch_set(self, document: Any, parts: List[str], value: Any) -> Any:
        """Set value at path."""
        if not parts:
            return value

        current = document
        for i, part in enumerate(parts[:-1]):
            if isinstance(current, dict):
                if part not in current:
                    current[part] = {}
                current = current[part]
            elif isinstance(current, list):
                current = current[int(part)]
            else:
                raise ValueError(f"Cannot navigate to {part}")

        last_part = parts[-1]
        if isinstance(current, dict):
            current[last_part] = value
        elif isinstance(current, list):
            idx = int(last_part)
            if last_part == "-":
                current.append(value)
            elif idx < len(current):
                current[idx] = value
            else:
                current.append(value)

        return document

    def _patch_remove(self, document: Any, parts: List[str]) -> Any:
        """Remove value at path."""
        if not parts:
            return None

        current = document
        for part in parts[:-1]:
            if isinstance(current, dict):
                current = current[part]
            elif isinstance(current, list):
                current = current[int(part)]

        last_part = parts[-1]
        if isinstance(current, dict):
            del current[last_part]
        elif isinstance(current, list):
            del current[int(last_part)]

        return document


# ============================================================================
# MODULE EXPORTS
# ============================================================================

__all__ = [
    "SimulatedKernel",
    "SimulatedHandle",
    "SimulatedDenialInfo",
    "SimulatedAuthorizationDetails",
    "HeapObject",
    "AuditLogEntry",
]

logger.debug("Simulator module loaded")
