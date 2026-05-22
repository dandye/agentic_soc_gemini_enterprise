#!/usr/bin/env python3
"""
Environment Variable Validation Utility

This module provides validation for environment variables to detect when users
have copied .env.example without updating placeholder values.
"""

import os
import re
from typing import NamedTuple


class ValidationError(NamedTuple):
    """Represents an environment variable validation error."""

    variable: str
    current_value: str
    error_type: str  # "missing" or "placeholder"
    suggestion: str


# Placeholder patterns from .env.example
# Maps environment variable names to their placeholder values/patterns
PLACEHOLDER_PATTERNS = {
    "GCP_PROJECT_ID": ["your-project-id"],
    "GCP_PROJECT_NUMBER": ["123456789012"],
    "GCP_STAGING_BUCKET": ["gs://your-staging-bucket"],
    "CHRONICLE_PROJECT_ID": ["your-gcp-project-id", "your-project-id"],
    "CHRONICLE_CUSTOMER_ID": ["your-customer-uuid"],
    "CHRONICLE_SERVICE_ACCOUNT_PATH": ["/path/to/service-account.json"],
    "SOAR_URL": ["https://your-instance.siemplify-soar.com:443"],
    "SOAR_API_KEY": ["your-soar-api-key"],
    "GTI_API_KEY": ["your-virustotal-api-key"],
    "RAG_CORPUS_ID": [
        "projects/your-project-id/locations/us-central1/ragCorpora/1234567890"
    ],
    "AGENTSPACE_APP_ID": ["your-app-id"],
    "AGENTSPACE_AGENT_ID": ["your-agent-id"],
}

# Additional pattern-based checks for values that contain placeholders
PLACEHOLDER_REGEX_PATTERNS = [
    (r"your-[a-z-]+", "placeholder pattern 'your-...'"),
    (r"/path/to/", "placeholder path '/path/to/...'"),
    (r"123456789012", "example project number"),
]


def is_placeholder_value(var_name: str, value: str) -> tuple[bool, str | None]:
    """
    Check if a value is a placeholder from .env.example.

    Args:
        var_name: Name of the environment variable
        value: Current value of the variable

    Returns:
        Tuple of (is_placeholder, reason)
        - is_placeholder: True if value appears to be a placeholder
        - reason: Description of why it's considered a placeholder, or None
    """
    if not value:
        return False, None

    # Check exact matches for known placeholders
    if var_name in PLACEHOLDER_PATTERNS:
        for placeholder in PLACEHOLDER_PATTERNS[var_name]:
            if value == placeholder:
                return True, f"matches .env.example placeholder: '{placeholder}'"

    # Check if value contains common placeholder patterns
    for pattern, description in PLACEHOLDER_REGEX_PATTERNS:
        if re.search(pattern, value):
            return True, f"contains {description}"

    return False, None


def validate_env_vars(
    required_vars: list[str], env_vars: dict[str, str] | None = None
) -> tuple[bool, list[ValidationError]]:
    """
    Validate required environment variables.

    Checks for both missing variables and placeholder values from .env.example.

    Args:
        required_vars: List of required environment variable names
        env_vars: Optional dict of env vars to check (defaults to os.environ)

    Returns:
        Tuple of (is_valid, errors)
        - is_valid: True if all validations pass
        - errors: List of ValidationError objects for any issues found
    """
    if env_vars is None:
        env_vars = dict(os.environ)

    errors = []

    for var in required_vars:
        value = env_vars.get(var)

        # Check if missing
        if not value:
            errors.append(
                ValidationError(
                    variable=var,
                    current_value="",
                    error_type="missing",
                    suggestion=f"Set {var} in your .env file",
                )
            )
            continue

        # Check if it's a placeholder value
        is_placeholder, reason = is_placeholder_value(var, value)
        if is_placeholder:
            errors.append(
                ValidationError(
                    variable=var,
                    current_value=value,
                    error_type="placeholder",
                    suggestion=f"Replace placeholder value with actual {var}",
                )
            )

    is_valid = len(errors) == 0
    return is_valid, errors


def format_validation_errors(errors: list[ValidationError]) -> str:
    """
    Format validation errors into a user-friendly error message.

    Args:
        errors: List of ValidationError objects

    Returns:
        Formatted error message string
    """
    if not errors:
        return ""

    lines = [
        "Environment variable validation failed:\n",
    ]

    # Group by error type
    missing = [e for e in errors if e.error_type == "missing"]
    placeholders = [e for e in errors if e.error_type == "placeholder"]

    if missing:
        lines.append("Missing required variables:")
        for error in missing:
            lines.append(f"  - {error.variable}")
        lines.append("")

    if placeholders:
        lines.append(
            "Variables contain placeholder values from .env.example (must be updated):"
        )
        for error in placeholders:
            # Truncate long values for readability
            value_display = error.current_value
            if len(value_display) > 50:
                value_display = value_display[:47] + "..."
            lines.append(f"  - {error.variable}: '{value_display}'")
        lines.append("")

    lines.extend(
        [
            "Action required:",
            "1. Copy .env.example to .env (if you haven't already)",
            "2. Edit .env and replace ALL placeholder values with your actual configuration",
            "3. Refer to .env.example comments for guidance on each variable",
        ]
    )

    return "\n".join(lines)


def validate_file_path_exists(var_name: str, file_path: str) -> ValidationError | None:
    """
    Validate that a file path exists and is not a placeholder.

    Args:
        var_name: Name of the environment variable
        file_path: Path to validate

    Returns:
        ValidationError if path is invalid, None otherwise
    """
    # First check if it's a placeholder
    is_placeholder, reason = is_placeholder_value(var_name, file_path)
    if is_placeholder:
        return ValidationError(
            variable=var_name,
            current_value=file_path,
            error_type="placeholder",
            suggestion=f"Replace with actual path to your {var_name.lower().replace('_', ' ')}",
        )

    # Then check if file exists
    if not os.path.exists(file_path):
        return ValidationError(
            variable=var_name,
            current_value=file_path,
            error_type="missing",
            suggestion=f"File does not exist: {file_path}",
        )

    return None
