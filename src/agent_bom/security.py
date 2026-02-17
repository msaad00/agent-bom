"""Security validation and hardening utilities."""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Allowed executables for MCP servers (security allowlist)
ALLOWED_COMMANDS = {
    "npx",
    "uvx",
    "python",
    "python3",
    "node",
    "deno",
    "bun",
    "npm",
    "uv",
}

# Dangerous environment variables that should never be set
DANGEROUS_ENV_VARS = {
    "LD_PRELOAD",
    "DYLD_INSERT_LIBRARIES",
    "PYTHONPATH",  # Can be used for code injection
    "NODE_OPTIONS",  # Can inject malicious code
}

# Shell metacharacters that indicate potential injection
SHELL_METACHARACTERS = {";", "|", "&", "$", "`", "<", ">", "\n", "\r"}

# Patterns for sensitive data (for redaction)
SENSITIVE_PATTERNS = [
    r"token",
    r"password",
    r"secret",
    r"api[_-]?key",
    r"auth",
    r"credential",
    r"bearer",
    r"jwt",
]


class SecurityError(Exception):
    """Raised when a security validation fails."""
    pass


def validate_command(command: str) -> None:
    """
    Validate that a command is in the allowed list.

    Args:
        command: The command to validate

    Raises:
        SecurityError: If command is not allowed
    """
    if command not in ALLOWED_COMMANDS:
        raise SecurityError(
            f"Command '{command}' is not in the allowed list. "
            f"Allowed commands: {', '.join(sorted(ALLOWED_COMMANDS))}"
        )
    logger.debug(f"Command '{command}' validated successfully")


def validate_arguments(args: list[str]) -> None:
    """
    Validate command arguments for shell metacharacters.

    Args:
        args: List of command arguments

    Raises:
        SecurityError: If dangerous characters found
    """
    for arg in args:
        for char in SHELL_METACHARACTERS:
            if char in arg:
                raise SecurityError(
                    f"Dangerous character '{char}' found in argument: {arg}"
                )
    logger.debug(f"Validated {len(args)} argument(s) successfully")


def validate_environment(env: dict[str, str]) -> None:
    """
    Validate environment variables for dangerous settings.

    Args:
        env: Dictionary of environment variables

    Raises:
        SecurityError: If dangerous environment variable found
    """
    for var in env:
        if var in DANGEROUS_ENV_VARS:
            raise SecurityError(
                f"Dangerous environment variable '{var}' not allowed"
            )
    logger.debug(f"Validated {len(env)} environment variable(s)")


def validate_path(path: str | Path, must_exist: bool = False) -> Path:
    """
    Validate and normalize a file path.

    Args:
        path: Path to validate
        must_exist: If True, path must exist

    Returns:
        Validated and normalized Path object

    Raises:
        SecurityError: If path is invalid or contains path traversal
    """
    path = Path(path)

    # Resolve to absolute path (prevents path traversal)
    try:
        resolved = path.resolve()
    except (OSError, RuntimeError) as e:
        raise SecurityError(f"Invalid path '{path}': {e}")

    # Check for path traversal attempts
    if ".." in path.parts:
        logger.warning(f"Path traversal attempt detected: {path}")
        raise SecurityError(f"Path traversal not allowed: {path}")

    # Check if path must exist
    if must_exist and not resolved.exists():
        raise SecurityError(f"Path does not exist: {resolved}")

    logger.debug(f"Validated path: {resolved}")
    return resolved


def sanitize_env_vars(env: dict[str, Any]) -> dict[str, str]:
    """
    Sanitize environment variables by redacting sensitive values.

    Args:
        env: Dictionary of environment variables

    Returns:
        Dictionary with sensitive values redacted
    """
    sanitized = {}
    for key, value in env.items():
        # Check if key matches sensitive pattern
        is_sensitive = any(
            re.search(pattern, key.lower())
            for pattern in SENSITIVE_PATTERNS
        )

        if is_sensitive:
            sanitized[key] = "***REDACTED***"
        else:
            sanitized[key] = str(value)

    return sanitized


def validate_file_size(path: Path, max_size_bytes: int = 10 * 1024 * 1024) -> None:
    """
    Validate that a file is not too large (DoS prevention).

    Args:
        path: Path to file
        max_size_bytes: Maximum allowed file size (default 10MB)

    Raises:
        SecurityError: If file is too large
    """
    try:
        size = os.path.getsize(path)
        if size > max_size_bytes:
            raise SecurityError(
                f"File too large: {size} bytes (max: {max_size_bytes} bytes)"
            )
        logger.debug(f"File size OK: {size} bytes")
    except OSError as e:
        raise SecurityError(f"Cannot check file size: {e}")


def validate_json_file(path: Path) -> dict:
    """
    Safely load and validate a JSON file.

    Args:
        path: Path to JSON file

    Returns:
        Parsed JSON data

    Raises:
        SecurityError: If file is invalid or too large
    """
    import json

    # Validate path
    path = validate_path(path, must_exist=True)

    # Check file size (DoS prevention)
    validate_file_size(path)

    # Load JSON safely (json.load is safe, doesn't execute code)
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        logger.debug(f"Successfully loaded JSON from {path}")
        return data
    except json.JSONDecodeError as e:
        raise SecurityError(f"Invalid JSON in {path}: {e}")
    except (OSError, UnicodeDecodeError) as e:
        raise SecurityError(f"Cannot read file {path}: {e}")


def validate_url(url: str) -> None:
    """
    Validate a URL for safety.

    Args:
        url: URL to validate

    Raises:
        SecurityError: If URL is invalid or uses insecure protocol
    """
    from urllib.parse import urlparse

    try:
        parsed = urlparse(url)
    except Exception as e:
        raise SecurityError(f"Invalid URL '{url}': {e}")

    # Only allow HTTPS (not HTTP or other protocols)
    if parsed.scheme not in ('https',):
        raise SecurityError(
            f"Only HTTPS URLs are allowed, got: {parsed.scheme}"
        )

    # Validate domain is not localhost or internal IP
    if parsed.hostname in ('localhost', '127.0.0.1', '0.0.0.0', '::1'):  # nosec B104 - checking FOR these values to reject them, not binding to them
        raise SecurityError(
            f"Cannot connect to localhost/internal IPs: {parsed.hostname}"
        )

    logger.debug(f"URL validated: {url}")


def validate_package_name(name: str, ecosystem: str) -> None:
    """
    Validate package name follows ecosystem conventions.

    Args:
        name: Package name
        ecosystem: Package ecosystem (npm, pypi, go, cargo)

    Raises:
        SecurityError: If package name is invalid
    """
    if not name or not isinstance(name, str):
        raise SecurityError(f"Invalid package name: {name}")

    # Ecosystem-specific validation
    if ecosystem == "npm":
        # npm: lowercase, alphanumeric, hyphens, underscores, @ for scoped
        if not re.match(r'^(@[a-z0-9-_]+/)?[a-z0-9-_]+$', name.lower()):
            raise SecurityError(f"Invalid npm package name: {name}")

    elif ecosystem == "pypi":
        # PyPI: alphanumeric, hyphens, underscores, dots
        if not re.match(r'^[a-zA-Z0-9-_.]+$', name):
            raise SecurityError(f"Invalid PyPI package name: {name}")

    elif ecosystem == "go":
        # Go: domain/path format
        if not re.match(r'^[a-zA-Z0-9-_.\/]+$', name):
            raise SecurityError(f"Invalid Go package name: {name}")

    elif ecosystem == "cargo":
        # Rust: alphanumeric, hyphens, underscores
        if not re.match(r'^[a-zA-Z0-9-_]+$', name):
            raise SecurityError(f"Invalid Cargo package name: {name}")

    logger.debug(f"Package name validated: {name} ({ecosystem})")


def create_safe_subprocess_env() -> dict[str, str]:
    """
    Create a minimal, safe environment for subprocess execution.

    Returns:
        Dictionary with minimal safe environment variables
    """
    # Only include essential environment variables
    safe_env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),  # nosec B108 - safe fallback for subprocess when HOME not set
        "LANG": os.environ.get("LANG", "en_US.UTF-8"),
    }

    # Add npm/node specific vars if present
    if "NPM_CONFIG_REGISTRY" in os.environ:
        safe_env["NPM_CONFIG_REGISTRY"] = os.environ["NPM_CONFIG_REGISTRY"]

    return safe_env


def validate_mcp_server_config(server_config: dict) -> None:
    """
    Validate an MCP server configuration for security issues.

    Args:
        server_config: MCP server configuration dictionary

    Raises:
        SecurityError: If configuration has security issues
    """
    # Validate command (remote/URL-based servers don't require a local command)
    command = server_config.get("command", "")
    has_url = bool(server_config.get("url"))
    if not has_url:
        validate_command(command)

    # Validate arguments
    args = server_config.get("args", [])
    if not isinstance(args, list):
        raise SecurityError("Server args must be a list")
    validate_arguments(args)

    # Validate environment variables
    env = server_config.get("env", {})
    if not isinstance(env, dict):
        raise SecurityError("Server env must be a dictionary")
    validate_environment(env)

    logger.info(f"MCP server config validated: {command or server_config.get('url', 'unknown')}")


# Export all validation functions
__all__ = [
    "SecurityError",
    "validate_command",
    "validate_arguments",
    "validate_environment",
    "validate_path",
    "sanitize_env_vars",
    "validate_file_size",
    "validate_json_file",
    "validate_url",
    "validate_package_name",
    "create_safe_subprocess_env",
    "validate_mcp_server_config",
]
