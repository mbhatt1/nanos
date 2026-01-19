"""
Exception hierarchy for the Authority Nanos SDK.

This module defines all exception types used by the Authority Nanos Python SDK,
providing a structured way to handle errors from the libak authorization kernel.
"""

from typing import Optional, Dict, Any

# Error code constants
ERROR_CODE_UNKNOWN = "AK_ERR_UNKNOWN"
ERROR_CODE_INVALID_INPUT = "AK_ERR_INVALID_INPUT"
ERROR_CODE_AUTHORIZATION_DENIED = "AK_ERR_AUTHORIZATION_DENIED"
ERROR_CODE_BUDGET_EXCEEDED = "AK_ERR_BUDGET_EXCEEDED"
ERROR_CODE_INTERNAL_ERROR = "AK_ERR_INTERNAL_ERROR"
ERROR_CODE_POLICY_VIOLATION = "AK_ERR_POLICY_VIOLATION"
ERROR_CODE_NOT_FOUND = "AK_ERR_NOT_FOUND"
ERROR_CODE_TIMEOUT = "AK_ERR_TIMEOUT"


class AKError(Exception):
    """
    Base exception class for all Authority Kernel errors.

    This exception is the parent class for all errors that may be raised
    by the Authority Nanos SDK. It provides a structured way to access
    error information including error codes and context.

    Attributes:
        code: The error code identifying the type of error
        message: Human-readable error description
        context: Additional context information about the error
        suggestion: A suggested remediation action for the error
    """

    def __init__(
        self,
        message: str,
        code: str = ERROR_CODE_UNKNOWN,
        context: Optional[Dict[str, Any]] = None,
        suggestion: Optional[str] = None,
    ) -> None:
        """
        Initialize an AKError instance.

        Args:
            message: A human-readable description of the error
            code: An error code identifying the type of error
            context: Additional context information relevant to the error
            suggestion: A suggested action to resolve the error
        """
        super().__init__(message)
        self.code = code
        self.message = message
        self.context = context or {}
        self.suggestion = suggestion

    def __str__(self) -> str:
        """Return a formatted string representation of the error."""
        result = f"[{self.code}] {self.message}"
        if self.suggestion:
            result += f"\nSuggestion: {self.suggestion}"
        return result

    def __repr__(self) -> str:
        """Return a detailed string representation for debugging."""
        return (
            f"{self.__class__.__name__}(code={self.code!r}, message={self.message!r}, "
            f"context={self.context!r}, suggestion={self.suggestion!r})"
        )


class AKDenialError(AKError):
    """
    Raised when an authorization request is denied.

    This exception is raised when the Authority Kernel denies access
    based on the configured authorization policies.

    Attributes:
        principal: The principal requesting access
        resource: The resource being accessed
        action: The action being performed
    """

    def __init__(
        self,
        message: str,
        principal: Optional[str] = None,
        resource: Optional[str] = None,
        action: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        suggestion: Optional[str] = None,
    ) -> None:
        """
        Initialize an AKDenialError instance.

        Args:
            message: A human-readable description of the denial
            principal: The principal that was denied access
            resource: The resource that was being accessed
            action: The action that was being performed
            context: Additional context information
            suggestion: A suggested action to resolve the error
        """
        default_suggestion = suggestion or (
            "Check that the principal has the required permissions. "
            "Contact your security administrator if you believe this is an error."
        )
        super().__init__(
            message,
            code=ERROR_CODE_AUTHORIZATION_DENIED,
            context=context or {},
            suggestion=default_suggestion,
        )
        self.principal = principal
        self.resource = resource
        self.action = action

        if principal or resource or action:
            self.context["principal"] = principal
            self.context["resource"] = resource
            self.context["action"] = action


class BudgetExceededError(AKError):
    """
    Base exception raised when budget is exceeded.

    This is a common base class for all budget exceeded errors,
    allowing isinstance() checks to work consistently regardless of
    whether the error comes from the core or decorators module.
    """

    def __init__(
        self,
        message: str,
        budget_type: Optional[str] = None,
        limit: Optional[int] = None,
        used: Optional[int] = None,
        context: Optional[Dict[str, Any]] = None,
        suggestion: Optional[str] = None,
    ) -> None:
        """
        Initialize a BudgetExceededError instance.

        Args:
            message: A human-readable description of the budget exceeded condition
            budget_type: The type of budget that was exceeded (e.g., "tokens", "wall_time")
            limit: The budget limit
            used: The amount of budget used
            context: Additional context information
            suggestion: A suggested action to resolve the error
        """
        default_suggestion = suggestion or (
            "Try reducing the complexity of the operation or breaking it into smaller requests."
        )
        ctx = context or {}
        if budget_type:
            ctx["budget_type"] = budget_type
        if limit is not None:
            ctx["limit"] = limit
        if used is not None:
            ctx["used"] = used

        super().__init__(
            message,
            code=ERROR_CODE_BUDGET_EXCEEDED,
            context=ctx,
            suggestion=default_suggestion,
        )


class AKBudgetError(BudgetExceededError):
    """
    Raised when authorization budget is exceeded (legacy alias).

    This exception is an alias for BudgetExceededError to maintain backward
    compatibility with code that imports from core module directly.

    New code should use BudgetExceededError from exceptions module instead.
    """

    pass  # Inherits all implementation from BudgetExceededError


class AKAuthorizationError(AKError):
    """
    Raised when there are authorization-related errors.

    This exception is raised for authorization-related errors that are not
    simple denials, such as invalid authorization checks or configuration errors.
    """

    def __init__(
        self,
        message: str,
        context: Optional[Dict[str, Any]] = None,
        suggestion: Optional[str] = None,
    ) -> None:
        """
        Initialize an AKAuthorizationError instance.

        Args:
            message: A human-readable description of the authorization error
            context: Additional context information
            suggestion: A suggested action to resolve the error
        """
        default_suggestion = suggestion or (
            "Check that your authorization policies are correctly configured."
        )
        super().__init__(
            message,
            code=ERROR_CODE_POLICY_VIOLATION,
            context=context or {},
            suggestion=default_suggestion,
        )


class AKInvalidInputError(AKError):
    """
    Raised when invalid input is provided to the Authority Kernel.

    This exception is raised when the SDK receives invalid parameters
    or malformed requests.
    """

    def __init__(
        self,
        message: str,
        parameter: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        suggestion: Optional[str] = None,
    ) -> None:
        """
        Initialize an AKInvalidInputError instance.

        Args:
            message: A human-readable description of the invalid input
            parameter: The name of the invalid parameter, if applicable
            context: Additional context information
            suggestion: A suggested action to resolve the error
        """
        ctx = context or {}
        if parameter:
            ctx["parameter"] = parameter

        default_suggestion = suggestion or f"Check the format and values of your input parameters."
        super().__init__(
            message,
            code=ERROR_CODE_INVALID_INPUT,
            context=ctx,
            suggestion=default_suggestion,
        )


class AKInternalError(AKError):
    """
    Raised when an internal error occurs in the Authority Kernel.

    This exception indicates an unexpected error in the kernel that is
    not covered by other exception types. This usually warrants investigation
    and may indicate a bug or misconfiguration.
    """

    def __init__(
        self,
        message: str,
        context: Optional[Dict[str, Any]] = None,
        suggestion: Optional[str] = None,
    ) -> None:
        """
        Initialize an AKInternalError instance.

        Args:
            message: A human-readable description of the internal error
            context: Additional context information
            suggestion: A suggested action to resolve the error
        """
        default_suggestion = suggestion or (
            "Please report this error with the context information to the support team."
        )
        super().__init__(
            message,
            code=ERROR_CODE_INTERNAL_ERROR,
            context=context or {},
            suggestion=default_suggestion,
        )


class AKNotFoundError(AKError):
    """
    Raised when a requested resource is not found.

    This exception is raised when the Authority Kernel cannot find
    a requested policy, principal, or other resource.
    """

    def __init__(
        self,
        message: str,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        suggestion: Optional[str] = None,
    ) -> None:
        """
        Initialize an AKNotFoundError instance.

        Args:
            message: A human-readable description of the not found error
            resource_type: The type of resource that was not found
            resource_id: The ID of the resource that was not found
            context: Additional context information
            suggestion: A suggested action to resolve the error
        """
        ctx = context or {}
        if resource_type:
            ctx["resource_type"] = resource_type
        if resource_id:
            ctx["resource_id"] = resource_id

        default_suggestion = suggestion or "Verify that the resource ID is correct and the resource exists."
        super().__init__(
            message,
            code=ERROR_CODE_NOT_FOUND,
            context=ctx,
            suggestion=default_suggestion,
        )


class AKTimeoutError(AKError):
    """
    Raised when an operation times out.

    This exception is raised when an authorization operation takes longer
    than the configured timeout period.
    """

    def __init__(
        self,
        message: str,
        timeout_seconds: Optional[float] = None,
        context: Optional[Dict[str, Any]] = None,
        suggestion: Optional[str] = None,
    ) -> None:
        """
        Initialize an AKTimeoutError instance.

        Args:
            message: A human-readable description of the timeout
            timeout_seconds: The timeout duration in seconds
            context: Additional context information
            suggestion: A suggested action to resolve the error
        """
        ctx = context or {}
        if timeout_seconds is not None:
            ctx["timeout_seconds"] = timeout_seconds

        default_suggestion = suggestion or (
            "Try increasing the timeout duration or simplifying the authorization query."
        )
        super().__init__(
            message,
            code=ERROR_CODE_TIMEOUT,
            context=ctx,
            suggestion=default_suggestion,
        )


# Mapping of error codes to exception classes for creating exceptions from kernel responses
ERROR_CODE_MAP: Dict[str, type] = {
    ERROR_CODE_AUTHORIZATION_DENIED: AKDenialError,
    ERROR_CODE_BUDGET_EXCEEDED: AKBudgetError,
    ERROR_CODE_INVALID_INPUT: AKInvalidInputError,
    ERROR_CODE_POLICY_VIOLATION: AKAuthorizationError,
    ERROR_CODE_NOT_FOUND: AKNotFoundError,
    ERROR_CODE_TIMEOUT: AKTimeoutError,
    ERROR_CODE_INTERNAL_ERROR: AKInternalError,
}


def create_error_from_code(
    code: str,
    message: str,
    context: Optional[Dict[str, Any]] = None,
) -> AKError:
    """
    Create an appropriate exception instance from an error code.

    This factory function maps error codes from the Authority Kernel
    to the appropriate Python exception class.

    Args:
        code: The error code from the kernel
        message: The error message
        context: Additional context information

    Returns:
        An instance of the appropriate AKError subclass
    """
    exception_class = ERROR_CODE_MAP.get(code, AKError)
    if exception_class == AKError:
        return AKError(message, code=code, context=context)
    return exception_class(message, context=context)
