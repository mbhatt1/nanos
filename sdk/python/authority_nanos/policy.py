#!/usr/bin/env python3
"""
Authority Nanos Policy Tools.

This module provides tools for creating, validating, explaining, and merging
Authority Nanos policy files. It includes:

- PolicyWizard: Interactive policy generator with pre-built profiles
- PolicyValidator: Validate policy syntax and structure
- PolicyExplainer: Explain policies in plain English
- PolicyMerger: Merge multiple policies with conflict resolution
"""

import json
import re
import sys
from copy import deepcopy
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union


# ============================================================================
# Policy Schema and Constants
# ============================================================================

POLICY_VERSION = "1.0"

# Valid top-level sections in a policy
VALID_SECTIONS = {
    "version", "fs", "net", "tools", "wasm", "infer", "budgets", "profiles"
}

# Valid fs subsections
VALID_FS_SUBSECTIONS = {"read", "write"}

# Valid net subsections
VALID_NET_SUBSECTIONS = {"dns", "connect", "bind", "listen"}

# Valid tools subsections
VALID_TOOLS_SUBSECTIONS = {"allow", "deny"}

# Valid wasm subsections
VALID_WASM_SUBSECTIONS = {"modules", "hostcalls"}

# Valid infer subsections
VALID_INFER_SUBSECTIONS = {"models", "max_tokens"}

# Valid budget keys
VALID_BUDGET_KEYS = {
    "tool_calls", "tokens", "wall_time_ms", "cpu_ns", "bytes",
    "heap_objects", "heap_bytes"
}

# Built-in profiles
BUILTIN_PROFILES = {"tier1-musl", "tier2-glibc"}


# ============================================================================
# Pre-built Policy Profiles
# ============================================================================

PROFILE_WEB_APP = {
    "version": "1.0",
    "fs": {
        "read": ["/app/**", "/lib/**", "/usr/lib/**", "/etc/ssl/**"],
        "write": ["/app/logs/**", "/tmp/**"]
    },
    "net": {
        "dns": ["*"],
        "connect": ["dns:*:443", "dns:*:80"],
        "bind": ["ip:0.0.0.0:8080"],
        "listen": ["ip:0.0.0.0:8080"]
    },
    "budgets": {
        "wall_time_ms": 300000,
        "bytes": 104857600
    },
    "profiles": ["tier1-musl"]
}

PROFILE_AI_AGENT = {
    "version": "1.0",
    "fs": {
        "read": ["/app/**", "/etc/ssl/**"],
        "write": ["/app/workspace/**", "/tmp/**"]
    },
    "net": {
        "dns": [],
        "connect": []
    },
    "tools": {
        "allow": ["http_get", "http_post", "file_read", "file_write"],
        "deny": ["shell_exec"]
    },
    "infer": {
        "models": [],
        "max_tokens": 100000
    },
    "budgets": {
        "tool_calls": 100,
        "tokens": 100000,
        "wall_time_ms": 300000
    },
    "profiles": ["tier1-musl"]
}

PROFILE_DATABASE_CLIENT = {
    "version": "1.0",
    "fs": {
        "read": ["/app/**", "/etc/ssl/**", "/lib/**"],
        "write": ["/tmp/**"]
    },
    "net": {
        "dns": [],
        "connect": []
    },
    "budgets": {
        "wall_time_ms": 60000,
        "bytes": 10485760
    },
    "profiles": ["tier1-musl"]
}

PROFILE_MINIMAL = {
    "version": "1.0",
    "fs": {
        "read": ["/app/**"],
        "write": []
    },
    "budgets": {
        "wall_time_ms": 30000
    },
    "profiles": ["tier1-musl"]
}


# ============================================================================
# Data Classes
# ============================================================================

class ValidationSeverity(Enum):
    """Severity levels for validation messages."""
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass
class ValidationMessage:
    """A validation message with severity and context."""
    severity: ValidationSeverity
    message: str
    path: str = ""
    suggestion: str = ""

    def __str__(self) -> str:
        prefix = {
            ValidationSeverity.ERROR: "[ERROR]",
            ValidationSeverity.WARNING: "[WARN]",
            ValidationSeverity.INFO: "[INFO]"
        }[self.severity]

        result = f"{prefix} {self.message}"
        if self.path:
            result = f"{prefix} {self.path}: {self.message}"
        if self.suggestion:
            result += f"\n        Suggestion: {self.suggestion}"
        return result


@dataclass
class ValidationResult:
    """Result of policy validation."""
    valid: bool
    messages: List[ValidationMessage] = field(default_factory=list)

    def add_error(self, message: str, path: str = "", suggestion: str = "") -> None:
        """Add an error message."""
        self.messages.append(ValidationMessage(
            ValidationSeverity.ERROR, message, path, suggestion
        ))
        self.valid = False

    def add_warning(self, message: str, path: str = "", suggestion: str = "") -> None:
        """Add a warning message."""
        self.messages.append(ValidationMessage(
            ValidationSeverity.WARNING, message, path, suggestion
        ))

    def add_info(self, message: str, path: str = "", suggestion: str = "") -> None:
        """Add an info message."""
        self.messages.append(ValidationMessage(
            ValidationSeverity.INFO, message, path, suggestion
        ))

    @property
    def errors(self) -> List[ValidationMessage]:
        """Get all error messages."""
        return [m for m in self.messages if m.severity == ValidationSeverity.ERROR]

    @property
    def warnings(self) -> List[ValidationMessage]:
        """Get all warning messages."""
        return [m for m in self.messages if m.severity == ValidationSeverity.WARNING]

    def __str__(self) -> str:
        lines = []
        for msg in self.messages:
            lines.append(str(msg))
        return "\n".join(lines)


class MergeMode(Enum):
    """Merge modes for combining policies."""
    UNION = "union"           # Combine all rules (most permissive)
    INTERSECTION = "intersection"  # Keep only common rules (most restrictive)


# ============================================================================
# PolicyValidator Class
# ============================================================================

class PolicyValidator:
    """
    Validate Authority Nanos policy files.

    Performs:
    - JSON/TOML syntax validation
    - Schema validation
    - Pattern validation
    - Security warnings for overly permissive rules

    Example:
        validator = PolicyValidator()
        result = validator.validate_file("policy.json")
        if not result.valid:
            print("Validation errors:")
            for msg in result.errors:
                print(f"  - {msg}")
    """

    def __init__(self):
        """Initialize the validator."""
        pass

    def validate_file(self, path: Union[str, Path]) -> ValidationResult:
        """
        Validate a policy file.

        Args:
            path: Path to the policy file (JSON or TOML)

        Returns:
            ValidationResult with any errors, warnings, or info messages
        """
        path = Path(path)
        result = ValidationResult(valid=True)

        if not path.exists():
            result.add_error(f"File not found: {path}")
            return result

        suffix = path.suffix.lower()

        try:
            if suffix == ".json":
                with open(path, "r") as f:
                    data = json.load(f)
            elif suffix == ".toml":
                try:
                    import tomllib
                except ImportError:
                    try:
                        import tomli as tomllib
                    except ImportError:
                        result.add_error(
                            "TOML parser not available",
                            suggestion="Install tomli: pip install tomli"
                        )
                        return result

                with open(path, "rb") as f:
                    data = tomllib.load(f)
            else:
                result.add_error(
                    f"Unknown file format: {suffix}",
                    suggestion="Use .json or .toml file extension"
                )
                return result

        except json.JSONDecodeError as e:
            result.add_error(f"JSON parse error: {e}")
            return result
        except Exception as e:
            result.add_error(f"Parse error: {e}")
            return result

        return self.validate(data)

    def validate(self, policy: Dict[str, Any]) -> ValidationResult:
        """
        Validate a policy dictionary.

        Args:
            policy: Policy dictionary to validate

        Returns:
            ValidationResult with any errors, warnings, or info messages
        """
        result = ValidationResult(valid=True)

        if not isinstance(policy, dict):
            result.add_error("Policy must be a JSON object/dictionary")
            return result

        # Check version
        self._validate_version(policy, result)

        # Check for unknown sections
        for key in policy.keys():
            if key not in VALID_SECTIONS:
                result.add_warning(
                    f"Unknown section: {key}",
                    path=key,
                    suggestion=f"Valid sections: {', '.join(sorted(VALID_SECTIONS))}"
                )

        # Validate each section
        if "fs" in policy:
            self._validate_fs(policy["fs"], result)

        if "net" in policy:
            self._validate_net(policy["net"], result)

        if "tools" in policy:
            self._validate_tools(policy["tools"], result)

        if "wasm" in policy:
            self._validate_wasm(policy["wasm"], result)

        if "infer" in policy:
            self._validate_infer(policy["infer"], result)

        if "budgets" in policy:
            self._validate_budgets(policy["budgets"], result)

        if "profiles" in policy:
            self._validate_profiles(policy["profiles"], result)

        return result

    def _validate_version(self, policy: Dict[str, Any], result: ValidationResult) -> None:
        """Validate the version field."""
        if "version" not in policy:
            result.add_error(
                "Missing required field: version",
                path="version",
                suggestion="Add: \"version\": \"1.0\""
            )
        elif policy["version"] != POLICY_VERSION:
            result.add_warning(
                f"Unknown version: {policy['version']}",
                path="version",
                suggestion=f"Expected version: {POLICY_VERSION}"
            )

    def _validate_fs(self, fs: Any, result: ValidationResult) -> None:
        """Validate the fs section."""
        if not isinstance(fs, dict):
            result.add_error("fs must be an object", path="fs")
            return

        for key in fs.keys():
            if key not in VALID_FS_SUBSECTIONS:
                result.add_warning(
                    f"Unknown fs subsection: {key}",
                    path=f"fs.{key}",
                    suggestion=f"Valid subsections: {', '.join(VALID_FS_SUBSECTIONS)}"
                )

        for key in ["read", "write"]:
            if key in fs:
                self._validate_path_patterns(fs[key], f"fs.{key}", result)

    def _validate_net(self, net: Any, result: ValidationResult) -> None:
        """Validate the net section."""
        if not isinstance(net, dict):
            result.add_error("net must be an object", path="net")
            return

        for key in net.keys():
            if key not in VALID_NET_SUBSECTIONS:
                result.add_warning(
                    f"Unknown net subsection: {key}",
                    path=f"net.{key}",
                    suggestion=f"Valid subsections: {', '.join(VALID_NET_SUBSECTIONS)}"
                )

        # Validate DNS patterns
        if "dns" in net:
            self._validate_dns_patterns(net["dns"], result)

        # Validate connect patterns
        if "connect" in net:
            self._validate_connect_patterns(net["connect"], result)

        # Validate bind/listen patterns
        for key in ["bind", "listen"]:
            if key in net:
                self._validate_bind_patterns(net[key], f"net.{key}", result)

    def _validate_tools(self, tools: Any, result: ValidationResult) -> None:
        """Validate the tools section."""
        if not isinstance(tools, dict):
            result.add_error("tools must be an object", path="tools")
            return

        for key in tools.keys():
            if key not in VALID_TOOLS_SUBSECTIONS:
                result.add_warning(
                    f"Unknown tools subsection: {key}",
                    path=f"tools.{key}",
                    suggestion=f"Valid subsections: {', '.join(VALID_TOOLS_SUBSECTIONS)}"
                )

        for key in ["allow", "deny"]:
            if key in tools:
                if not isinstance(tools[key], list):
                    result.add_error(f"tools.{key} must be an array", path=f"tools.{key}")
                else:
                    for i, pattern in enumerate(tools[key]):
                        if not isinstance(pattern, str):
                            result.add_error(
                                f"Tool pattern must be a string",
                                path=f"tools.{key}[{i}]"
                            )
                        elif pattern == "*" and key == "allow":
                            result.add_warning(
                                "Wildcard tool allow is dangerous",
                                path=f"tools.{key}[{i}]",
                                suggestion="Be specific about which tools to allow"
                            )

    def _validate_wasm(self, wasm: Any, result: ValidationResult) -> None:
        """Validate the wasm section."""
        if not isinstance(wasm, dict):
            result.add_error("wasm must be an object", path="wasm")
            return

        for key in wasm.keys():
            if key not in VALID_WASM_SUBSECTIONS:
                result.add_warning(
                    f"Unknown wasm subsection: {key}",
                    path=f"wasm.{key}",
                    suggestion=f"Valid subsections: {', '.join(VALID_WASM_SUBSECTIONS)}"
                )

        for key in ["modules", "hostcalls"]:
            if key in wasm:
                if not isinstance(wasm[key], list):
                    result.add_error(f"wasm.{key} must be an array", path=f"wasm.{key}")
                else:
                    for i, pattern in enumerate(wasm[key]):
                        if not isinstance(pattern, str):
                            result.add_error(
                                f"WASM pattern must be a string",
                                path=f"wasm.{key}[{i}]"
                            )

    def _validate_infer(self, infer: Any, result: ValidationResult) -> None:
        """Validate the infer section."""
        if not isinstance(infer, dict):
            result.add_error("infer must be an object", path="infer")
            return

        for key in infer.keys():
            if key not in VALID_INFER_SUBSECTIONS:
                result.add_warning(
                    f"Unknown infer subsection: {key}",
                    path=f"infer.{key}",
                    suggestion=f"Valid subsections: {', '.join(VALID_INFER_SUBSECTIONS)}"
                )

        if "models" in infer:
            if not isinstance(infer["models"], list):
                result.add_error("infer.models must be an array", path="infer.models")
            else:
                for i, model in enumerate(infer["models"]):
                    if not isinstance(model, str):
                        result.add_error(
                            "Model pattern must be a string",
                            path=f"infer.models[{i}]"
                        )
                    elif model == "*":
                        result.add_warning(
                            "Wildcard model access is dangerous",
                            path=f"infer.models[{i}]",
                            suggestion="Be specific about which models to allow"
                        )

        if "max_tokens" in infer:
            if not isinstance(infer["max_tokens"], int):
                result.add_error(
                    "max_tokens must be an integer",
                    path="infer.max_tokens"
                )
            elif infer["max_tokens"] <= 0:
                result.add_error(
                    "max_tokens must be positive",
                    path="infer.max_tokens"
                )

    def _validate_budgets(self, budgets: Any, result: ValidationResult) -> None:
        """Validate the budgets section."""
        if not isinstance(budgets, dict):
            result.add_error("budgets must be an object", path="budgets")
            return

        for key in budgets.keys():
            if key not in VALID_BUDGET_KEYS:
                result.add_warning(
                    f"Unknown budget key: {key}",
                    path=f"budgets.{key}",
                    suggestion=f"Valid keys: {', '.join(sorted(VALID_BUDGET_KEYS))}"
                )

        for key, value in budgets.items():
            if key in VALID_BUDGET_KEYS:
                if not isinstance(value, int):
                    result.add_error(
                        f"Budget {key} must be an integer",
                        path=f"budgets.{key}"
                    )
                elif value <= 0:
                    result.add_error(
                        f"Budget {key} must be positive",
                        path=f"budgets.{key}"
                    )

    def _validate_profiles(self, profiles: Any, result: ValidationResult) -> None:
        """Validate the profiles section."""
        if not isinstance(profiles, list):
            result.add_error("profiles must be an array", path="profiles")
            return

        for i, profile in enumerate(profiles):
            if not isinstance(profile, str):
                result.add_error(
                    "Profile must be a string",
                    path=f"profiles[{i}]"
                )
            elif profile not in BUILTIN_PROFILES:
                result.add_info(
                    f"Non-standard profile: {profile}",
                    path=f"profiles[{i}]",
                    suggestion=f"Built-in profiles: {', '.join(sorted(BUILTIN_PROFILES))}"
                )

    def _validate_path_patterns(
        self, patterns: Any, path: str, result: ValidationResult
    ) -> None:
        """Validate filesystem path patterns."""
        if not isinstance(patterns, list):
            result.add_error(f"{path} must be an array", path=path)
            return

        for i, pattern in enumerate(patterns):
            if not isinstance(pattern, str):
                result.add_error(
                    "Path pattern must be a string",
                    path=f"{path}[{i}]"
                )
            elif pattern == "*" or pattern == "**":
                result.add_warning(
                    "Wildcard path access is dangerous",
                    path=f"{path}[{i}]",
                    suggestion="Be specific about which paths to allow"
                )
            elif not pattern.startswith("/") and not pattern.startswith("*"):
                result.add_warning(
                    "Path pattern should start with /",
                    path=f"{path}[{i}]",
                    suggestion=f"Use: /{pattern}"
                )

    def _validate_dns_patterns(self, patterns: Any, result: ValidationResult) -> None:
        """Validate DNS patterns."""
        if not isinstance(patterns, list):
            result.add_error("net.dns must be an array", path="net.dns")
            return

        for i, pattern in enumerate(patterns):
            if not isinstance(pattern, str):
                result.add_error(
                    "DNS pattern must be a string",
                    path=f"net.dns[{i}]"
                )
            elif pattern == "*":
                result.add_warning(
                    "Wildcard DNS access allows resolution of any domain",
                    path=f"net.dns[{i}]",
                    suggestion="Be specific about which domains to allow"
                )

    def _validate_connect_patterns(
        self, patterns: Any, result: ValidationResult
    ) -> None:
        """Validate network connect patterns."""
        if not isinstance(patterns, list):
            result.add_error("net.connect must be an array", path="net.connect")
            return

        connect_pattern = re.compile(
            r"^(dns|ip):([^:]+):(\d+|\*)$"
        )

        for i, pattern in enumerate(patterns):
            if not isinstance(pattern, str):
                result.add_error(
                    "Connect pattern must be a string",
                    path=f"net.connect[{i}]"
                )
            elif not connect_pattern.match(pattern):
                result.add_error(
                    f"Invalid connect pattern format: {pattern}",
                    path=f"net.connect[{i}]",
                    suggestion="Use format: dns:hostname:port or ip:address:port"
                )
            elif pattern.startswith("dns:*:") or pattern == "dns:*:*":
                result.add_warning(
                    "Wildcard DNS connect allows connection to any host",
                    path=f"net.connect[{i}]",
                    suggestion="Be specific about which hosts to allow"
                )

    def _validate_bind_patterns(
        self, patterns: Any, path: str, result: ValidationResult
    ) -> None:
        """Validate network bind/listen patterns."""
        if not isinstance(patterns, list):
            result.add_error(f"{path} must be an array", path=path)
            return

        bind_pattern = re.compile(
            r"^ip:([^:]+):(\d+|\*)$"
        )

        for i, pattern in enumerate(patterns):
            if not isinstance(pattern, str):
                result.add_error(
                    "Bind pattern must be a string",
                    path=f"{path}[{i}]"
                )
            elif not bind_pattern.match(pattern):
                result.add_error(
                    f"Invalid bind pattern format: {pattern}",
                    path=f"{path}[{i}]",
                    suggestion="Use format: ip:address:port"
                )


# ============================================================================
# PolicyExplainer Class
# ============================================================================

class PolicyExplainer:
    """
    Explain Authority Nanos policies in plain English.

    Parses a policy and generates human-readable explanations of:
    - What's allowed and denied
    - Effective permissions
    - Security implications

    Example:
        explainer = PolicyExplainer()
        explanation = explainer.explain_file("policy.json")
        print(explanation)
    """

    def __init__(self):
        """Initialize the explainer."""
        pass

    def explain_file(self, path: Union[str, Path]) -> str:
        """
        Explain a policy file.

        Args:
            path: Path to the policy file

        Returns:
            Human-readable explanation string
        """
        path = Path(path)

        if not path.exists():
            return f"Error: File not found: {path}"

        suffix = path.suffix.lower()

        try:
            if suffix == ".json":
                with open(path, "r") as f:
                    data = json.load(f)
            elif suffix == ".toml":
                try:
                    import tomllib
                except ImportError:
                    import tomli as tomllib

                with open(path, "rb") as f:
                    data = tomllib.load(f)
            else:
                return f"Error: Unknown file format: {suffix}"

        except Exception as e:
            return f"Error parsing policy: {e}"

        return self.explain(data)

    def explain(self, policy: Dict[str, Any]) -> str:
        """
        Explain a policy dictionary.

        Args:
            policy: Policy dictionary to explain

        Returns:
            Human-readable explanation string
        """
        lines = []
        lines.append("=" * 60)
        lines.append("Policy Explanation")
        lines.append("=" * 60)
        lines.append("")

        # Version
        version = policy.get("version", "unknown")
        lines.append(f"Policy Version: {version}")
        lines.append("")

        # Filesystem
        if "fs" in policy:
            lines.extend(self._explain_fs(policy["fs"]))

        # Network
        if "net" in policy:
            lines.extend(self._explain_net(policy["net"]))

        # Tools
        if "tools" in policy:
            lines.extend(self._explain_tools(policy["tools"]))

        # WASM
        if "wasm" in policy:
            lines.extend(self._explain_wasm(policy["wasm"]))

        # Inference
        if "infer" in policy:
            lines.extend(self._explain_infer(policy["infer"]))

        # Budgets
        if "budgets" in policy:
            lines.extend(self._explain_budgets(policy["budgets"]))

        # Profiles
        if "profiles" in policy:
            lines.extend(self._explain_profiles(policy["profiles"]))

        lines.append("=" * 60)

        return "\n".join(lines)

    def _explain_fs(self, fs: Dict[str, Any]) -> List[str]:
        """Explain filesystem rules."""
        lines = ["FILESYSTEM ACCESS", "-" * 40]

        read_paths = fs.get("read", [])
        write_paths = fs.get("write", [])

        if read_paths:
            lines.append("")
            lines.append("ALLOWED to READ:")
            for path in read_paths:
                if path.endswith("/**"):
                    lines.append(f"  - {path[:-3]} (and all subdirectories)")
                elif path.endswith("/*"):
                    lines.append(f"  - Files in {path[:-2]} (not recursive)")
                else:
                    lines.append(f"  - {path}")
        else:
            lines.append("")
            lines.append("READ ACCESS: None (no files can be read)")

        if write_paths:
            lines.append("")
            lines.append("ALLOWED to WRITE:")
            for path in write_paths:
                if path.endswith("/**"):
                    lines.append(f"  - {path[:-3]} (and all subdirectories)")
                elif path.endswith("/*"):
                    lines.append(f"  - Files in {path[:-2]} (not recursive)")
                else:
                    lines.append(f"  - {path}")
        else:
            lines.append("")
            lines.append("WRITE ACCESS: None (read-only)")

        lines.append("")
        return lines

    def _explain_net(self, net: Dict[str, Any]) -> List[str]:
        """Explain network rules."""
        lines = ["NETWORK ACCESS", "-" * 40]

        dns = net.get("dns", [])
        connect = net.get("connect", [])
        bind = net.get("bind", [])
        listen = net.get("listen", [])

        if dns:
            lines.append("")
            lines.append("DNS RESOLUTION ALLOWED:")
            for domain in dns:
                if domain == "*":
                    lines.append("  - ANY domain (WARNING: very permissive)")
                elif domain.startswith("*."):
                    lines.append(f"  - Any subdomain of {domain[2:]}")
                else:
                    lines.append(f"  - {domain}")
        else:
            lines.append("")
            lines.append("DNS RESOLUTION: None (no DNS lookups)")

        if connect:
            lines.append("")
            lines.append("OUTBOUND CONNECTIONS ALLOWED:")
            for pattern in connect:
                lines.append(f"  - {self._explain_connect_pattern(pattern)}")
        else:
            lines.append("")
            lines.append("OUTBOUND CONNECTIONS: None")

        if bind:
            lines.append("")
            lines.append("CAN BIND TO:")
            for pattern in bind:
                lines.append(f"  - {self._explain_bind_pattern(pattern)}")

        if listen:
            lines.append("")
            lines.append("CAN LISTEN ON:")
            for pattern in listen:
                lines.append(f"  - {self._explain_bind_pattern(pattern)}")

        if not bind and not listen:
            lines.append("")
            lines.append("SERVER FUNCTIONALITY: Disabled (no bind/listen)")

        lines.append("")
        return lines

    def _explain_connect_pattern(self, pattern: str) -> str:
        """Explain a single connect pattern."""
        if pattern.startswith("dns:"):
            parts = pattern[4:].rsplit(":", 1)
            host = parts[0]
            port = parts[1] if len(parts) > 1 else "*"

            if host == "*":
                host_desc = "any host"
            elif host.startswith("*."):
                host_desc = f"any subdomain of {host[2:]}"
            else:
                host_desc = host

            if port == "*":
                return f"{host_desc} on any port"
            elif port == "443":
                return f"{host_desc} on HTTPS (port 443)"
            elif port == "80":
                return f"{host_desc} on HTTP (port 80)"
            else:
                return f"{host_desc} on port {port}"

        elif pattern.startswith("ip:"):
            parts = pattern[3:].rsplit(":", 1)
            ip = parts[0]
            port = parts[1] if len(parts) > 1 else "*"

            if "/" in ip:
                ip_desc = f"IP range {ip}"
            else:
                ip_desc = f"IP {ip}"

            if port == "*":
                return f"{ip_desc} on any port"
            else:
                return f"{ip_desc} on port {port}"

        return pattern

    def _explain_bind_pattern(self, pattern: str) -> str:
        """Explain a single bind/listen pattern."""
        if pattern.startswith("ip:"):
            parts = pattern[3:].rsplit(":", 1)
            ip = parts[0]
            port = parts[1] if len(parts) > 1 else "*"

            if ip == "0.0.0.0":
                ip_desc = "all interfaces (IPv4)"
            elif ip == "[::]":
                ip_desc = "all interfaces (IPv6)"
            elif ip == "127.0.0.1":
                ip_desc = "localhost only"
            else:
                ip_desc = f"interface {ip}"

            if port == "*":
                return f"{ip_desc}, any port"
            else:
                return f"{ip_desc}, port {port}"

        return pattern

    def _explain_tools(self, tools: Dict[str, Any]) -> List[str]:
        """Explain tool rules."""
        lines = ["TOOL EXECUTION", "-" * 40]

        allow = tools.get("allow", [])
        deny = tools.get("deny", [])

        if allow:
            lines.append("")
            lines.append("TOOLS ALLOWED:")
            for tool in allow:
                if tool == "*":
                    lines.append("  - ALL tools (WARNING: very permissive)")
                elif tool.endswith("_*"):
                    lines.append(f"  - Any tool starting with {tool[:-1]}")
                else:
                    lines.append(f"  - {tool}")
        else:
            lines.append("")
            lines.append("TOOLS ALLOWED: None explicitly")

        if deny:
            lines.append("")
            lines.append("TOOLS DENIED (always blocked):")
            for tool in deny:
                lines.append(f"  - {tool}")

        lines.append("")
        return lines

    def _explain_wasm(self, wasm: Dict[str, Any]) -> List[str]:
        """Explain WASM rules."""
        lines = ["WASM MODULES", "-" * 40]

        modules = wasm.get("modules", [])
        hostcalls = wasm.get("hostcalls", [])

        if modules:
            lines.append("")
            lines.append("WASM MODULES ALLOWED:")
            for module in modules:
                if module.endswith("_*"):
                    lines.append(f"  - Any module starting with {module[:-1]}")
                else:
                    lines.append(f"  - {module}")
        else:
            lines.append("")
            lines.append("WASM MODULES: None (WASM disabled)")

        if hostcalls:
            lines.append("")
            lines.append("HOST CALLS ALLOWED:")
            for hostcall in hostcalls:
                lines.append(f"  - {hostcall}")

        lines.append("")
        return lines

    def _explain_infer(self, infer: Dict[str, Any]) -> List[str]:
        """Explain inference rules."""
        lines = ["LLM INFERENCE", "-" * 40]

        models = infer.get("models", [])
        max_tokens = infer.get("max_tokens")

        if models:
            lines.append("")
            lines.append("LLM MODELS ALLOWED:")
            for model in models:
                if model == "*":
                    lines.append("  - ANY model (WARNING: very permissive)")
                elif model.endswith("-*"):
                    lines.append(f"  - Any model starting with {model[:-1]}")
                else:
                    lines.append(f"  - {model}")
        else:
            lines.append("")
            lines.append("LLM ACCESS: Disabled (no models allowed)")

        if max_tokens:
            lines.append("")
            lines.append(f"TOKEN LIMIT: {max_tokens:,} tokens per request")

        lines.append("")
        return lines

    def _explain_budgets(self, budgets: Dict[str, Any]) -> List[str]:
        """Explain budget limits."""
        lines = ["RESOURCE BUDGETS", "-" * 40]
        lines.append("")

        budget_descriptions = {
            "tool_calls": ("Tool Calls", "maximum tool invocations"),
            "tokens": ("LLM Tokens", "input + output tokens"),
            "wall_time_ms": ("Wall Time", "milliseconds of execution time"),
            "cpu_ns": ("CPU Time", "nanoseconds of CPU time"),
            "bytes": ("I/O Bytes", "bytes of I/O"),
            "heap_objects": ("Heap Objects", "maximum objects in heap"),
            "heap_bytes": ("Heap Memory", "bytes of heap memory"),
        }

        for key, (name, desc) in budget_descriptions.items():
            if key in budgets:
                value = budgets[key]
                if key == "wall_time_ms":
                    formatted = f"{value:,}ms ({value/1000:.1f}s)"
                elif key == "cpu_ns":
                    formatted = f"{value:,}ns ({value/1e9:.1f}s)"
                elif key in ("bytes", "heap_bytes"):
                    if value >= 1024 * 1024 * 1024:
                        formatted = f"{value:,} ({value / (1024**3):.1f} GB)"
                    elif value >= 1024 * 1024:
                        formatted = f"{value:,} ({value / (1024**2):.1f} MB)"
                    elif value >= 1024:
                        formatted = f"{value:,} ({value / 1024:.1f} KB)"
                    else:
                        formatted = f"{value:,}"
                else:
                    formatted = f"{value:,}"

                lines.append(f"  {name}: {formatted}")

        lines.append("")
        return lines

    def _explain_profiles(self, profiles: List[str]) -> List[str]:
        """Explain included profiles."""
        lines = ["INCLUDED PROFILES", "-" * 40]
        lines.append("")

        profile_descriptions = {
            "tier1-musl": "Minimal profile for static/musl-linked binaries",
            "tier2-glibc": "Extended profile for dynamic/glibc-linked binaries",
        }

        for profile in profiles:
            desc = profile_descriptions.get(profile, "Custom profile")
            lines.append(f"  - {profile}: {desc}")

        lines.append("")
        return lines


# ============================================================================
# PolicyMerger Class
# ============================================================================

class PolicyMerger:
    """
    Merge multiple Authority Nanos policies.

    Supports two merge modes:
    - UNION: Combine all rules (most permissive result)
    - INTERSECTION: Keep only common rules (most restrictive result)

    Example:
        merger = PolicyMerger()
        merged = merger.merge_files(["policy1.json", "policy2.json"])
        merged_strict = merger.merge_files(
            ["policy1.json", "policy2.json"],
            mode=MergeMode.INTERSECTION
        )
    """

    def __init__(self):
        """Initialize the merger."""
        pass

    def merge_files(
        self,
        paths: List[Union[str, Path]],
        mode: MergeMode = MergeMode.UNION
    ) -> Tuple[Dict[str, Any], List[str]]:
        """
        Merge multiple policy files.

        Args:
            paths: List of paths to policy files
            mode: Merge mode (UNION or INTERSECTION)

        Returns:
            Tuple of (merged policy dict, list of conflict messages)
        """
        policies = []
        conflicts = []

        for path in paths:
            path = Path(path)

            if not path.exists():
                conflicts.append(f"File not found: {path}")
                continue

            suffix = path.suffix.lower()

            try:
                if suffix == ".json":
                    with open(path, "r") as f:
                        data = json.load(f)
                elif suffix == ".toml":
                    try:
                        import tomllib
                    except ImportError:
                        import tomli as tomllib

                    with open(path, "rb") as f:
                        data = tomllib.load(f)
                else:
                    conflicts.append(f"Unknown format: {path}")
                    continue

                policies.append(data)
            except Exception as e:
                conflicts.append(f"Error parsing {path}: {e}")

        if not policies:
            return {}, conflicts

        merged, merge_conflicts = self.merge(policies, mode)
        conflicts.extend(merge_conflicts)

        return merged, conflicts

    def merge(
        self,
        policies: List[Dict[str, Any]],
        mode: MergeMode = MergeMode.UNION
    ) -> Tuple[Dict[str, Any], List[str]]:
        """
        Merge multiple policy dictionaries.

        Args:
            policies: List of policy dictionaries
            mode: Merge mode (UNION or INTERSECTION)

        Returns:
            Tuple of (merged policy dict, list of conflict messages)
        """
        if not policies:
            return {}, []

        if len(policies) == 1:
            return deepcopy(policies[0]), []

        conflicts = []
        merged = {"version": POLICY_VERSION}

        # Merge filesystem rules
        merged["fs"] = self._merge_fs(policies, mode, conflicts)

        # Merge network rules
        merged["net"] = self._merge_net(policies, mode, conflicts)

        # Merge tool rules
        merged["tools"] = self._merge_tools(policies, mode, conflicts)

        # Merge WASM rules
        merged["wasm"] = self._merge_wasm(policies, mode, conflicts)

        # Merge inference rules
        merged["infer"] = self._merge_infer(policies, mode, conflicts)

        # Merge budgets
        merged["budgets"] = self._merge_budgets(policies, mode, conflicts)

        # Merge profiles
        merged["profiles"] = self._merge_profiles(policies, mode)

        # Clean up empty sections
        merged = {k: v for k, v in merged.items() if v}

        return merged, conflicts

    def _merge_string_lists(
        self,
        lists: List[List[str]],
        mode: MergeMode
    ) -> List[str]:
        """Merge lists of strings based on mode."""
        if not lists:
            return []

        if mode == MergeMode.UNION:
            result = set()
            for lst in lists:
                result.update(lst)
            return sorted(result)
        else:  # INTERSECTION
            result = set(lists[0])
            for lst in lists[1:]:
                result &= set(lst)
            return sorted(result)

    def _merge_fs(
        self,
        policies: List[Dict[str, Any]],
        mode: MergeMode,
        conflicts: List[str]
    ) -> Dict[str, Any]:
        """Merge filesystem sections."""
        result = {}

        for key in ["read", "write"]:
            lists = [
                p.get("fs", {}).get(key, [])
                for p in policies
            ]
            lists = [lst for lst in lists if lst]

            if lists:
                result[key] = self._merge_string_lists(lists, mode)

        return result

    def _merge_net(
        self,
        policies: List[Dict[str, Any]],
        mode: MergeMode,
        conflicts: List[str]
    ) -> Dict[str, Any]:
        """Merge network sections."""
        result = {}

        for key in ["dns", "connect", "bind", "listen"]:
            lists = [
                p.get("net", {}).get(key, [])
                for p in policies
            ]
            lists = [lst for lst in lists if lst]

            if lists:
                result[key] = self._merge_string_lists(lists, mode)

        return result

    def _merge_tools(
        self,
        policies: List[Dict[str, Any]],
        mode: MergeMode,
        conflicts: List[str]
    ) -> Dict[str, Any]:
        """Merge tools sections."""
        result = {}

        # For tools, deny always takes precedence
        allow_lists = [
            p.get("tools", {}).get("allow", [])
            for p in policies
        ]
        allow_lists = [lst for lst in allow_lists if lst]

        deny_lists = [
            p.get("tools", {}).get("deny", [])
            for p in policies
        ]
        deny_lists = [lst for lst in deny_lists if lst]

        if allow_lists:
            result["allow"] = self._merge_string_lists(allow_lists, mode)

        # For deny, always use union (most restrictive)
        if deny_lists:
            deny_set = set()
            for lst in deny_lists:
                deny_set.update(lst)
            result["deny"] = sorted(deny_set)

        return result

    def _merge_wasm(
        self,
        policies: List[Dict[str, Any]],
        mode: MergeMode,
        conflicts: List[str]
    ) -> Dict[str, Any]:
        """Merge WASM sections."""
        result = {}

        for key in ["modules", "hostcalls"]:
            lists = [
                p.get("wasm", {}).get(key, [])
                for p in policies
            ]
            lists = [lst for lst in lists if lst]

            if lists:
                result[key] = self._merge_string_lists(lists, mode)

        return result

    def _merge_infer(
        self,
        policies: List[Dict[str, Any]],
        mode: MergeMode,
        conflicts: List[str]
    ) -> Dict[str, Any]:
        """Merge inference sections."""
        result = {}

        # Merge model lists
        model_lists = [
            p.get("infer", {}).get("models", [])
            for p in policies
        ]
        model_lists = [lst for lst in model_lists if lst]

        if model_lists:
            result["models"] = self._merge_string_lists(model_lists, mode)

        # Merge max_tokens
        max_tokens_values = [
            p.get("infer", {}).get("max_tokens")
            for p in policies
            if p.get("infer", {}).get("max_tokens") is not None
        ]

        if max_tokens_values:
            if mode == MergeMode.UNION:
                result["max_tokens"] = max(max_tokens_values)
            else:
                result["max_tokens"] = min(max_tokens_values)

            if len(set(max_tokens_values)) > 1:
                conflicts.append(
                    f"Conflicting max_tokens values: {max_tokens_values}, "
                    f"using {'max' if mode == MergeMode.UNION else 'min'}: "
                    f"{result['max_tokens']}"
                )

        return result

    def _merge_budgets(
        self,
        policies: List[Dict[str, Any]],
        mode: MergeMode,
        conflicts: List[str]
    ) -> Dict[str, Any]:
        """Merge budget sections."""
        result = {}

        for key in VALID_BUDGET_KEYS:
            values = [
                p.get("budgets", {}).get(key)
                for p in policies
                if p.get("budgets", {}).get(key) is not None
            ]

            if values:
                if mode == MergeMode.UNION:
                    result[key] = max(values)
                else:
                    result[key] = min(values)

                if len(set(values)) > 1:
                    conflicts.append(
                        f"Conflicting budget {key}: {values}, "
                        f"using {'max' if mode == MergeMode.UNION else 'min'}: "
                        f"{result[key]}"
                    )

        return result

    def _merge_profiles(
        self,
        policies: List[Dict[str, Any]],
        mode: MergeMode
    ) -> List[str]:
        """Merge profile lists."""
        profile_lists = [
            p.get("profiles", [])
            for p in policies
        ]
        profile_lists = [lst for lst in profile_lists if lst]

        if not profile_lists:
            return []

        return self._merge_string_lists(profile_lists, mode)


# ============================================================================
# PolicyWizard Class
# ============================================================================

class PolicyWizard:
    """
    Interactive wizard for creating Authority Nanos policies.

    Guides users through creating policies with simple prompts.
    Supports pre-built profiles for common use cases.

    Example:
        wizard = PolicyWizard()
        policy = wizard.run()
        wizard.save(policy, "policy.json")
    """

    def __init__(self, input_func=None, output_func=None):
        """
        Initialize the wizard.

        Args:
            input_func: Function for reading input (default: input())
            output_func: Function for printing output (default: print())
        """
        self._input = input_func or input
        self._print = output_func or print

    def run(self) -> Dict[str, Any]:
        """
        Run the interactive wizard.

        Returns:
            Generated policy dictionary
        """
        self._print_header()

        # Select application type
        app_type = self._select_app_type()

        # Start with base profile
        if app_type == "web-app":
            policy = deepcopy(PROFILE_WEB_APP)
        elif app_type == "ai-agent":
            policy = deepcopy(PROFILE_AI_AGENT)
        elif app_type == "database-client":
            policy = deepcopy(PROFILE_DATABASE_CLIENT)
        elif app_type == "minimal":
            policy = deepcopy(PROFILE_MINIMAL)
        else:
            policy = {"version": "1.0", "profiles": ["tier1-musl"]}

        # Customize based on app type
        if app_type == "ai-agent":
            policy = self._customize_ai_agent(policy)
        elif app_type == "database-client":
            policy = self._customize_database_client(policy)
        elif app_type == "web-app":
            policy = self._customize_web_app(policy)
        elif app_type == "custom":
            policy = self._customize_custom(policy)

        # Final customizations
        policy = self._final_customizations(policy)

        self._print("")
        self._print("=" * 60)
        self._print("Policy generation complete!")
        self._print("=" * 60)

        return policy

    def _print_header(self) -> None:
        """Print the wizard header."""
        self._print("")
        self._print("Authority Nanos Policy Wizard")
        self._print("=" * 60)
        self._print("")
        self._print("This wizard will help you create a security policy for your")
        self._print("application running on Authority Nanos.")
        self._print("")

    def _prompt(self, message: str, default: str = "") -> str:
        """
        Prompt user for input.

        Args:
            message: Prompt message
            default: Default value if empty input

        Returns:
            User input or default value
        """
        if default:
            prompt = f"{message} [{default}]: "
        else:
            prompt = f"{message}: "

        result = self._input(prompt).strip()
        return result if result else default

    def _prompt_choice(
        self,
        message: str,
        choices: List[Tuple[str, str]],
        default: int = 1
    ) -> str:
        """
        Prompt user to select from choices.

        Args:
            message: Prompt message
            choices: List of (value, description) tuples
            default: Default choice number (1-indexed)

        Returns:
            Selected value
        """
        self._print(message)
        for i, (value, desc) in enumerate(choices, 1):
            self._print(f"  {i}) {desc}")
        self._print("")

        while True:
            result = self._prompt(">", str(default))
            try:
                idx = int(result) - 1
                if 0 <= idx < len(choices):
                    return choices[idx][0]
            except ValueError:
                pass
            self._print(f"Please enter a number between 1 and {len(choices)}")

    def _prompt_yes_no(self, message: str, default: bool = True) -> bool:
        """
        Prompt for yes/no answer.

        Args:
            message: Prompt message
            default: Default value

        Returns:
            Boolean answer
        """
        default_str = "Y/n" if default else "y/N"
        result = self._prompt(f"{message} ({default_str})", "")

        if not result:
            return default

        return result.lower() in ("y", "yes", "true", "1")

    def _prompt_list(self, message: str, hint: str = "") -> List[str]:
        """
        Prompt for a comma-separated list.

        Args:
            message: Prompt message
            hint: Hint text

        Returns:
            List of values
        """
        if hint:
            self._print(hint)
        result = self._prompt(message, "")

        if not result:
            return []

        items = [item.strip() for item in result.split(",")]
        return [item for item in items if item]

    def _select_app_type(self) -> str:
        """Select application type."""
        return self._prompt_choice(
            "What type of application are you building?",
            [
                ("web-app", "Web application"),
                ("ai-agent", "AI agent"),
                ("database-client", "Database client"),
                ("minimal", "Minimal (strict security)"),
                ("custom", "Custom"),
            ]
        )

    def _customize_ai_agent(self, policy: Dict[str, Any]) -> Dict[str, Any]:
        """Customize policy for AI agent."""
        self._print("")
        self._print("-" * 40)
        self._print("AI Agent Configuration")
        self._print("-" * 40)
        self._print("")

        # LLM provider
        llm_choice = self._prompt_choice(
            "Does your agent need LLM access?",
            [
                ("openai", "Yes - OpenAI"),
                ("anthropic", "Yes - Anthropic"),
                ("both", "Yes - Both OpenAI and Anthropic"),
                ("ollama", "Yes - Local (Ollama)"),
                ("none", "No"),
            ]
        )

        if llm_choice == "openai":
            policy["net"]["dns"] = ["api.openai.com"]
            policy["net"]["connect"] = ["dns:api.openai.com:443"]
            policy["infer"]["models"] = ["gpt-4", "gpt-4-turbo", "gpt-3.5-turbo"]
        elif llm_choice == "anthropic":
            policy["net"]["dns"] = ["api.anthropic.com"]
            policy["net"]["connect"] = ["dns:api.anthropic.com:443"]
            policy["infer"]["models"] = ["claude-3-opus", "claude-3-sonnet", "claude-*"]
        elif llm_choice == "both":
            policy["net"]["dns"] = ["api.openai.com", "api.anthropic.com"]
            policy["net"]["connect"] = [
                "dns:api.openai.com:443",
                "dns:api.anthropic.com:443"
            ]
            policy["infer"]["models"] = ["gpt-4", "gpt-4-turbo", "claude-*"]
        elif llm_choice == "ollama":
            policy["net"]["dns"] = []
            policy["net"]["connect"] = ["ip:127.0.0.1:11434"]
            policy["infer"]["models"] = ["*"]
        else:
            if "infer" in policy:
                del policy["infer"]

        # Token budget
        if "infer" in policy:
            self._print("")
            tokens = self._prompt(
                "Maximum tokens per request",
                str(policy.get("infer", {}).get("max_tokens", 100000))
            )
            try:
                policy["infer"]["max_tokens"] = int(tokens)
            except ValueError:
                pass

        return policy

    def _customize_database_client(self, policy: Dict[str, Any]) -> Dict[str, Any]:
        """Customize policy for database client."""
        self._print("")
        self._print("-" * 40)
        self._print("Database Configuration")
        self._print("-" * 40)
        self._print("")

        # Database type
        db_choice = self._prompt_choice(
            "What database will you connect to?",
            [
                ("postgres", "PostgreSQL (port 5432)"),
                ("mysql", "MySQL (port 3306)"),
                ("redis", "Redis (port 6379)"),
                ("mongodb", "MongoDB (port 27017)"),
                ("custom", "Custom"),
            ]
        )

        port_map = {
            "postgres": "5432",
            "mysql": "3306",
            "redis": "6379",
            "mongodb": "27017",
        }

        if db_choice == "custom":
            host = self._prompt("Database hostname", "db.internal")
            port = self._prompt("Database port", "5432")
        else:
            host = self._prompt("Database hostname", "db.internal")
            port = port_map[db_choice]

        policy["net"]["dns"] = [host]
        policy["net"]["connect"] = [f"dns:{host}:{port}"]

        return policy

    def _customize_web_app(self, policy: Dict[str, Any]) -> Dict[str, Any]:
        """Customize policy for web application."""
        self._print("")
        self._print("-" * 40)
        self._print("Web Application Configuration")
        self._print("-" * 40)
        self._print("")

        # Listen port
        port = self._prompt("What port should your app listen on?", "8080")
        policy["net"]["bind"] = [f"ip:0.0.0.0:{port}"]
        policy["net"]["listen"] = [f"ip:0.0.0.0:{port}"]

        # Restrict outbound?
        self._print("")
        restrict = self._prompt_yes_no(
            "Restrict outbound connections to specific domains?"
        )

        if restrict:
            self._print("")
            domains = self._prompt_list(
                "Enter allowed domains (comma-separated)",
                "(Example: api.example.com, *.googleapis.com)"
            )

            if domains:
                policy["net"]["dns"] = domains
                policy["net"]["connect"] = [
                    f"dns:{domain}:443" for domain in domains
                ]

        return policy

    def _customize_custom(self, policy: Dict[str, Any]) -> Dict[str, Any]:
        """Build a custom policy from scratch."""
        self._print("")
        self._print("-" * 40)
        self._print("Custom Policy Configuration")
        self._print("-" * 40)

        # Filesystem
        self._print("")
        self._print("FILESYSTEM ACCESS")

        read_paths = self._prompt_list(
            "What files does your app need to read? (comma-separated, or * for all)",
            "(Example: /app/**, /etc/ssl/**, /lib/**)"
        )
        if read_paths:
            policy["fs"] = policy.get("fs", {})
            policy["fs"]["read"] = read_paths

        write_paths = self._prompt_list(
            "What files does your app need to write? (comma-separated)",
            "(Example: /tmp/**, /app/data/**)"
        )
        if write_paths:
            policy["fs"] = policy.get("fs", {})
            policy["fs"]["write"] = write_paths

        # Network
        self._print("")
        self._print("NETWORK ACCESS")

        needs_network = self._prompt_yes_no("Does your app need network access?")

        if needs_network:
            dns_domains = self._prompt_list(
                "What domains can be resolved? (comma-separated, or * for all)",
                "(Example: api.github.com, *.googleapis.com)"
            )
            if dns_domains:
                policy["net"] = policy.get("net", {})
                policy["net"]["dns"] = dns_domains

            connect_patterns = self._prompt_list(
                "What can your app connect to? (comma-separated)",
                "(Example: dns:api.github.com:443, ip:10.0.0.0/8:5432)"
            )
            if connect_patterns:
                policy["net"] = policy.get("net", {})
                policy["net"]["connect"] = connect_patterns

            needs_listen = self._prompt_yes_no("Does your app need to listen for connections?", False)
            if needs_listen:
                port = self._prompt("What port?", "8080")
                policy["net"]["bind"] = [f"ip:0.0.0.0:{port}"]
                policy["net"]["listen"] = [f"ip:0.0.0.0:{port}"]

        # Tools
        self._print("")
        self._print("TOOL ACCESS")

        needs_tools = self._prompt_yes_no("Does your app use tools/functions?", False)

        if needs_tools:
            allowed_tools = self._prompt_list(
                "What tools are allowed? (comma-separated)",
                "(Example: http_get, http_post, file_read)"
            )
            denied_tools = self._prompt_list(
                "What tools are always denied? (comma-separated)",
                "(Example: shell_exec, file_delete)"
            )

            if allowed_tools or denied_tools:
                policy["tools"] = {}
                if allowed_tools:
                    policy["tools"]["allow"] = allowed_tools
                if denied_tools:
                    policy["tools"]["deny"] = denied_tools

        # LLM
        self._print("")
        self._print("LLM INFERENCE")

        needs_llm = self._prompt_yes_no("Does your app need LLM inference?", False)

        if needs_llm:
            models = self._prompt_list(
                "What models are allowed? (comma-separated)",
                "(Example: gpt-4, claude-*, llama-*)"
            )
            if models:
                policy["infer"] = {"models": models}

                max_tokens = self._prompt("Maximum tokens per request", "100000")
                try:
                    policy["infer"]["max_tokens"] = int(max_tokens)
                except ValueError:
                    policy["infer"]["max_tokens"] = 100000

        return policy

    def _final_customizations(self, policy: Dict[str, Any]) -> Dict[str, Any]:
        """Apply final customizations."""
        self._print("")
        self._print("-" * 40)
        self._print("Resource Budgets")
        self._print("-" * 40)
        self._print("")

        customize_budgets = self._prompt_yes_no(
            "Customize resource budgets?",
            False
        )

        if customize_budgets:
            budgets = policy.get("budgets", {})

            # Wall time
            wall_time = self._prompt(
                "Maximum execution time (ms)",
                str(budgets.get("wall_time_ms", 300000))
            )
            try:
                budgets["wall_time_ms"] = int(wall_time)
            except ValueError:
                pass

            # Tool calls
            if "tools" in policy:
                tool_calls = self._prompt(
                    "Maximum tool calls",
                    str(budgets.get("tool_calls", 100))
                )
                try:
                    budgets["tool_calls"] = int(tool_calls)
                except ValueError:
                    pass

            # Tokens
            if "infer" in policy:
                tokens = self._prompt(
                    "Maximum LLM tokens",
                    str(budgets.get("tokens", 100000))
                )
                try:
                    budgets["tokens"] = int(tokens)
                except ValueError:
                    pass

            policy["budgets"] = budgets

        return policy

    def save(
        self,
        policy: Dict[str, Any],
        path: Union[str, Path],
        format: str = "json"
    ) -> None:
        """
        Save policy to file.

        Args:
            policy: Policy dictionary
            path: Output path
            format: Output format ("json" or "toml")
        """
        path = Path(path)

        if format == "json" or path.suffix.lower() == ".json":
            with open(path, "w") as f:
                json.dump(policy, f, indent=2)
        elif format == "toml" or path.suffix.lower() == ".toml":
            # Convert to TOML
            try:
                import tomli_w
                with open(path, "wb") as f:
                    tomli_w.dump(policy, f)
            except ImportError:
                # Fall back to manual TOML generation
                with open(path, "w") as f:
                    f.write(self._to_toml(policy))
        else:
            # Default to JSON
            with open(path, "w") as f:
                json.dump(policy, f, indent=2)

    def _to_toml(self, policy: Dict[str, Any], prefix: str = "") -> str:
        """Convert policy to TOML string (simple implementation)."""
        lines = []

        # Handle version first
        if "version" in policy and not prefix:
            lines.append(f'version = "{policy["version"]}"')
            lines.append("")

        for key, value in policy.items():
            if key == "version" and not prefix:
                continue

            full_key = f"{prefix}.{key}" if prefix else key

            if isinstance(value, dict):
                lines.append(f"[{full_key}]")
                for k, v in value.items():
                    if isinstance(v, list):
                        lines.append(f"{k} = {json.dumps(v)}")
                    elif isinstance(v, int):
                        lines.append(f"{k} = {v}")
                    elif isinstance(v, str):
                        lines.append(f'{k} = "{v}"')
                lines.append("")
            elif isinstance(value, list):
                lines.append(f"{key} = {json.dumps(value)}")

        return "\n".join(lines)


# ============================================================================
# Convenience Functions
# ============================================================================

def validate_policy_file(path: Union[str, Path]) -> ValidationResult:
    """
    Validate a policy file.

    Args:
        path: Path to the policy file

    Returns:
        ValidationResult
    """
    return PolicyValidator().validate_file(path)


def explain_policy_file(path: Union[str, Path]) -> str:
    """
    Explain a policy file in plain English.

    Args:
        path: Path to the policy file

    Returns:
        Human-readable explanation
    """
    return PolicyExplainer().explain_file(path)


def merge_policy_files(
    paths: List[Union[str, Path]],
    mode: MergeMode = MergeMode.UNION
) -> Tuple[Dict[str, Any], List[str]]:
    """
    Merge multiple policy files.

    Args:
        paths: List of policy file paths
        mode: Merge mode

    Returns:
        Tuple of (merged policy, conflict messages)
    """
    return PolicyMerger().merge_files(paths, mode)


def run_policy_wizard() -> Dict[str, Any]:
    """
    Run the interactive policy wizard.

    Returns:
        Generated policy dictionary
    """
    return PolicyWizard().run()


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == "__main__":
    # Simple test of the module
    print("Authority Nanos Policy Tools")
    print("=" * 40)
    print()
    print("Available classes:")
    print("  - PolicyWizard: Interactive policy creation")
    print("  - PolicyValidator: Validate policy files")
    print("  - PolicyExplainer: Explain policies in plain English")
    print("  - PolicyMerger: Merge multiple policies")
    print()
    print("Usage:")
    print("  from authority_nanos.policy import PolicyWizard")
    print("  wizard = PolicyWizard()")
    print("  policy = wizard.run()")
