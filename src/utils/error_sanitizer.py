"""
Error message sanitization utilities for TailOpsMCP security.
"""

import traceback
from typing import Any, Dict, Optional
import re


def sanitize_error_message(error: Exception, include_details: bool = False) -> str:
    """
    Sanitize error messages to prevent sensitive data exposure.

    Args:
        error: The exception to sanitize
        include_details: Whether to include safe error details (for internal logs)

    Returns:
        Sanitized error message safe for external exposure
    """
    # For external users, always return generic messages
    if not include_details:
        return "An internal error occurred. Please try again later."

    # For internal logging, include details but sanitize sensitive data
    error_msg = str(error)

    # Remove potential sensitive patterns
    # File paths (might contain user data)
    error_msg = re.sub(r"/[^/\s]+/[^/\s]+/", "/[REDACTED_PATH]/", error_msg)

    # API keys, tokens, passwords (common patterns)
    error_msg = re.sub(
        r'([a-zA-Z_-]+=\s*)["\']?([a-zA-Z0-9+/]{20,})["\']?',
        r"\1[REDACTED_TOKEN]",
        error_msg,
    )

    # Database connection strings
    error_msg = re.sub(
        r"(mongodb://|postgres://|mysql://)[^\s]+",
        r"\1[REDACTED_CONNECTION]",
        error_msg,
    )

    # Email addresses
    error_msg = re.sub(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "[REDACTED_EMAIL]",
        error_msg,
    )

    # IP addresses (optional, uncomment if needed)
    # error_msg = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[REDACTED_IP]', error_msg)

    return error_msg


def create_safe_error_response(
    error: Exception, request_id: Optional[str] = None, include_type: bool = False
) -> Dict[str, Any]:
    """
    Create a safe error response for API endpoints.

    Args:
        error: The exception that occurred
        request_id: Optional request ID for tracking
        include_type: Whether to include error type (internal only)

    Returns:
        Dictionary safe for JSON response to users
    """
    response = {
        "success": False,
        "error": "An internal error occurred. Please try again later.",
        "request_id": request_id,
    }

    # Only add request_id if provided
    if request_id is None:
        response.pop("request_id")

    # Option to include error type for internal debugging
    if include_type:
        response["error_type"] = type(error).__name__

    return response


def sanitize_stack_trace(trace: str) -> str:
    """
    Sanitize stack traces by removing sensitive information while preserving debugging value.

    Args:
        trace: Raw stack trace string

    Returns:
        Sanitized stack trace safe for internal logging
    """
    # Remove sensitive file paths
    trace = re.sub(r"/home/[^/\s]+/", "/[USER_HOME]/", trace)
    trace = re.sub(r"/Users/[^/\s]+/", "/[USER_HOME]/", trace)

    # Remove potential sensitive parameters from function calls
    trace = re.sub(r'password\s*=\s*["\'][^"\']+["\']', 'password="[REDACTED]"', trace)
    trace = re.sub(r'token\s*=\s*["\'][^"\']+["\']', 'token="[REDACTED]"', trace)
    trace = re.sub(r'api_key\s*=\s*["\'][^"\']+["\']', 'api_key="[REDACTED]"', trace)
    trace = re.sub(r'secret\s*=\s*["\'][^"\']+["\']', 'secret="[REDACTED]"', trace)

    return trace
