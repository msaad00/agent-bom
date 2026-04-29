"""Security validation and hardening utilities."""

from __future__ import annotations

import base64
import binascii
import logging
import math
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

logger = logging.getLogger(__name__)
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")

# Allowed executables for MCP servers (security allowlist).
# Includes package managers, runtimes, and container tools commonly used
# to launch MCP servers. Adding a binary here means discovery won't block
# the server — it does NOT mean the binary is safe to run untrusted.
ALLOWED_COMMANDS = {
    # JavaScript/TypeScript runtimes & package managers
    "npx",
    "npm",
    "node",
    "deno",
    "bun",
    "tsx",
    # Python runtimes & package managers
    "python",
    "python3",
    "uvx",
    "uv",
    "pipx",
    # Go
    "go",
    # Java/JVM
    "java",
    "mvn",
    "gradle",
    # .NET
    "dotnet",
    # Ruby
    "ruby",
    "bundle",
    # Rust
    "cargo",
    # Container tools (MCP servers often run in containers)
    "docker",
    "podman",
    # Common MCP server launchers
    "mcp",
    "mcp-server",
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


def sanitize_log_label(value: object, max_len: int = 500) -> str:
    """Return a single-line, ANSI-free label for logs and terminal output."""
    text = ANSI_ESCAPE_RE.sub("", str(value))
    text = text.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    text = "".join(ch for ch in text if ch >= " " and ch != "\x7f")
    return re.sub(r" {2,}", " ", text).strip()[:max_len]


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
        raise SecurityError(f"Command '{command}' is not in the allowed list. Allowed commands: {', '.join(sorted(ALLOWED_COMMANDS))}")
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
                raise SecurityError(f"Dangerous character '{char}' found in argument: {arg}")
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
            raise SecurityError(f"Dangerous environment variable '{var}' not allowed")
    logger.debug(f"Validated {len(env)} environment variable(s)")


def validate_path(
    path: str | Path,
    must_exist: bool = False,
    restrict_to_home: bool = False,
) -> Path:
    """
    Validate and normalize a file path.

    Args:
        path: Path to validate
        must_exist: If True, path must exist
        restrict_to_home: If True, path must resolve inside the user's home directory

    Returns:
        Validated and normalized Path object

    Raises:
        SecurityError: If path is invalid or contains path traversal
    """
    path = Path(path).expanduser()

    # Resolve to absolute path (prevents path traversal)
    try:
        resolved = path.resolve()
    except (OSError, RuntimeError) as e:
        raise SecurityError(f"Invalid path '{path}': {e}")

    # Restrict to home directory (used by MCP server for user-provided paths)
    if restrict_to_home and not resolved.is_relative_to(Path.home()):
        raise SecurityError(f"Path resolves outside home directory: {path}")

    # Check for path traversal attempts (on unresolved path)
    if ".." in path.parts:
        logger.warning(f"Path traversal attempt detected: {path}")
        raise SecurityError(f"Path traversal not allowed: {path}")

    # Check if path must exist
    if must_exist and not resolved.exists():
        raise SecurityError(f"Path does not exist: {resolved}")

    logger.debug(f"Validated path: {resolved}")
    return resolved


_VALUE_CREDENTIAL_PATTERNS = [
    re.compile(r"(?:sk|pk|rk)[-_](?:live|test|prod)[-_]\w{10,}", re.I),  # Stripe/service keys
    re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,}"),  # GitHub tokens
    re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}"),  # AWS access key IDs
    re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),  # Private keys
    re.compile(r"eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}"),  # JWTs
    re.compile(r"xox[bpsar]-[A-Za-z0-9-]{10,}"),  # Slack tokens
    re.compile(r"\w+://[^:]+:[^@]+@"),  # Connection strings with embedded credentials
]

# Base64 alphabet (standard + URL-safe)
_B64_RE = re.compile(r"^[A-Za-z0-9+/\-_]+=*$")

# Minimum length to bother trying base64 decode (encodes ≥20 bytes)
_B64_MIN_LEN = 28

# Shannon entropy threshold — secrets typically score >3.8 bits/char;
# readable English scores ~4.0 but with spaces; env var values without
# spaces that score >4.5 over a long string are almost certainly secrets.
# Shorter strings (24-39 chars) require higher entropy to reduce false positives.
_HIGH_ENTROPY_THRESHOLD = 4.5
_HIGH_ENTROPY_MIN_LEN = 24
_HIGH_ENTROPY_SHORT_THRESHOLD = 5.0  # stricter for shorter strings (24-39 chars)


def _shannon_entropy(s: str) -> float:
    """Return Shannon entropy (bits per character) of a string."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _is_obfuscated_credential(value: str) -> bool:
    """Return True if value looks like a base64-encoded or high-entropy secret.

    Two detection strategies:
    1. Base64 decode: if the value decodes to valid UTF-8 text that itself
       matches a key name or value credential pattern, flag it.
    2. High-entropy: strings (≥24 chars) with no whitespace and high Shannon
       entropy are extremely likely to be opaque secrets (keys, tokens,
       passwords).  Short strings (24-39 chars) require entropy >5.0 to reduce
       false positives; longer strings (≥40 chars) use the standard 4.5
       threshold.  Pure random bytes score ~6.0; base64-encoded secrets
       score ~5.8; UUIDs score ~3.8.
    """
    stripped = value.strip()

    # Strategy 1: base64 decode and re-check
    if len(stripped) >= _B64_MIN_LEN and _B64_RE.match(stripped):
        try:
            decoded = base64.b64decode(stripped + "==").decode("utf-8", errors="strict")
            decoded_lower = decoded.lower()
            # Decoded text contains a sensitive keyword
            if any(re.search(p, decoded_lower) for p in SENSITIVE_PATTERNS):
                return True
            # Decoded text matches a known credential value pattern
            if any(p.search(decoded) for p in _VALUE_CREDENTIAL_PATTERNS):
                return True
        except (ValueError, UnicodeDecodeError, binascii.Error):
            pass  # Not valid base64 — fall through to entropy check

    # Strategy 2: high Shannon entropy on a compact, non-URL string
    # Short strings (24-39 chars) use a stricter threshold to avoid false positives
    str_len = len(stripped)
    if str_len >= _HIGH_ENTROPY_MIN_LEN and " " not in stripped and "://" not in stripped:
        entropy = _shannon_entropy(stripped)
        threshold = _HIGH_ENTROPY_SHORT_THRESHOLD if str_len < 40 else _HIGH_ENTROPY_THRESHOLD
        if entropy > threshold:
            return True

    return False


def sanitize_env_vars(env: dict[str, Any]) -> dict[str, str]:
    """
    Sanitize environment variables by redacting sensitive values.

    Checks both key names (via SENSITIVE_PATTERNS) and values (via
    _VALUE_CREDENTIAL_PATTERNS) to catch hardcoded credentials in
    custom-named variables.

    Args:
        env: Dictionary of environment variables

    Returns:
        Dictionary with sensitive values redacted
    """
    sanitized = {}
    for key, value in env.items():
        # Check if key matches sensitive pattern
        is_sensitive = any(re.search(pattern, key.lower()) for pattern in SENSITIVE_PATTERNS)

        if is_sensitive:
            sanitized[key] = "***REDACTED***"
        else:
            str_value = str(value)
            # Scan values for plaintext credential patterns (catches custom-named vars)
            if any(p.search(str_value) for p in _VALUE_CREDENTIAL_PATTERNS):
                sanitized[key] = "***REDACTED***"
            # Detect obfuscated secrets: base64-encoded values and high-entropy strings
            elif _is_obfuscated_credential(str_value):
                sanitized[key] = "***REDACTED***"
            else:
                sanitized[key] = str_value

    return sanitized


def sanitize_url(value: str | None) -> str | None:
    """Strip credentials, query strings, and fragments from display/export URLs."""
    if value is None:
        return None
    try:
        parsed = urlsplit(value)
    except ValueError:
        return "<redacted-url>"
    if not parsed.scheme or not parsed.netloc:
        return value
    host = parsed.hostname or parsed.netloc.rsplit("@", 1)[-1]
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return urlunsplit((parsed.scheme, host, parsed.path, "", ""))


def sanitize_text(value: object, max_len: int = 1000) -> str:
    """Redact credential-shaped substrings and credential-bearing URLs in text."""
    text = sanitize_log_label(value, max_len=max_len)
    text = re.sub(r"https?://[^\s\"'<>]+", lambda match: str(sanitize_url(match.group(0)) or ""), text)
    for pattern in _VALUE_CREDENTIAL_PATTERNS:
        text = pattern.sub("<redacted>", text)
    return text[:max_len]


def _looks_sensitive_value(value: str) -> bool:
    return sanitize_env_vars({"ARG": value}).get("ARG") == "***REDACTED***"


def sanitize_command_args(args: list[Any] | tuple[Any, ...]) -> list[str]:
    """Redact secret-bearing command arguments while preserving launch shape."""
    sanitized: list[str] = []
    redact_next = False
    for raw_arg in args:
        arg = str(raw_arg)
        if redact_next:
            sanitized.append("<redacted>")
            redact_next = False
            continue

        if "=" in arg:
            key, _sep, raw_value = arg.partition("=")
            if any(re.search(pattern, key.lower()) for pattern in SENSITIVE_PATTERNS):
                sanitized.append(f"{key}=<redacted>")
                continue
            if "://" in raw_value:
                sanitized.append(f"{key}={sanitize_url(raw_value)}")
                continue
            if _looks_sensitive_value(raw_value):
                sanitized.append(f"{key}=<redacted>")
                continue

        if "://" in arg:
            sanitized.append(str(sanitize_url(arg) or ""))
            continue

        if _looks_sensitive_value(arg):
            sanitized.append("<redacted>")
            continue

        if arg.startswith("-") and any(re.search(pattern, arg.lower()) for pattern in SENSITIVE_PATTERNS):
            sanitized.append(arg)
            redact_next = True
            continue

        sanitized.append(arg)
    return sanitized


def sanitize_launch_command(command: object, args: list[Any] | tuple[Any, ...] | None = None, *, max_args: int | None = None) -> str:
    """Return a safe command label for display/export surfaces."""
    safe_command = sanitize_text(command, max_len=200)
    raw_args = list(args or [])
    if max_args is not None:
        raw_args = raw_args[:max_args]
    safe_args = sanitize_command_args(raw_args)
    return " ".join([part for part in [safe_command, *safe_args] if part]).strip()


def sanitize_security_warnings(values: list[Any] | tuple[Any, ...]) -> list[str]:
    """Redact warning text before persistence or UI/API export."""
    return [sanitize_text(value) for value in values if str(value or "").strip()]


def _key_looks_sensitive(key: object) -> bool:
    return any(re.search(pattern, str(key).lower()) for pattern in SENSITIVE_PATTERNS)


def _key_looks_like_url(key: object) -> bool:
    key_text = str(key).lower()
    return key_text in {"url", "uri", "endpoint", "webhook"} or key_text.endswith(("_url", "_uri", "_endpoint", "_webhook"))


def _key_looks_like_path(key: object) -> bool:
    key_text = str(key).lower()
    path_terms = ("path", "file", "dir", "directory", "cwd", "workspace", "config_path", "source_path")
    return any(term in key_text for term in path_terms)


def _looks_like_path_value(value: str) -> bool:
    if not value or "://" in value:
        return False
    return value.startswith("/") or value.startswith("~/") or bool(re.match(r"^[A-Za-z]:[\\/]", value))


_CLOUD_IDENTITY_KEYS = {
    "account_id",
    "arn",
    "cloud_principal",
    "endpoint_id",
    "location",
    "principal_arn",
    "project_id",
    "region",
    "resource_group",
    "resource_id",
    "resource_name",
    "service",
    "subscription_id",
    "tenant_id",
}


def _key_looks_like_cloud_identity(key: object) -> bool:
    key_text = str(key or "").strip().lower().replace("-", "_")
    return key_text in _CLOUD_IDENTITY_KEYS or key_text.endswith("_arn") or key_text.endswith("_resource_id")


def sanitize_path_label(value: object) -> str:
    """Return a non-revealing label for local filesystem paths."""
    text = sanitize_log_label(value, max_len=1000)
    basename = re.split(r"[\\/]+", text.rstrip("/\\"))[-1] if text else ""
    basename = sanitize_text(basename or "path", max_len=80)
    if not basename or _key_looks_sensitive(basename) or _looks_sensitive_value(basename):
        basename = "path"
    return f"<path:{basename}>"


def sanitize_sensitive_payload(value: object, *, key: object | None = None, max_str_len: int = 1000, depth: int = 0) -> object:
    """Recursively redact sensitive runtime/audit payloads before persistence/export."""
    if depth >= 8:
        return "[truncated]"
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        if key is not None and _key_looks_sensitive(key):
            return "***REDACTED***"
        if key is not None and _key_looks_like_url(key):
            return sanitize_url(value)
        if key is not None and _key_looks_like_cloud_identity(key):
            if _looks_sensitive_value(value):
                return "***REDACTED***"
            return sanitize_text(value, max_len=max_str_len)
        if "://" in value:
            return sanitize_text(value, max_len=max_str_len)
        if key is not None and _key_looks_like_path(key) and _looks_like_path_value(value):
            return sanitize_path_label(value)
        if _looks_like_path_value(value):
            return sanitize_path_label(value)
        if _looks_sensitive_value(value):
            return "***REDACTED***"
        return sanitize_text(value, max_len=max_str_len)
    if isinstance(value, dict):
        sanitized: dict[str, object] = {}
        for raw_key, raw_value in value.items():
            clean_key = sanitize_text(raw_key, max_len=200)
            sanitized[clean_key] = sanitize_sensitive_payload(raw_value, key=clean_key, max_str_len=max_str_len, depth=depth + 1)
        return sanitized
    if isinstance(value, list | tuple | set):
        return [sanitize_sensitive_payload(item, key=key, max_str_len=max_str_len, depth=depth + 1) for item in list(value)]
    return sanitize_text(value, max_len=max_str_len)


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
            raise SecurityError(f"File too large: {size} bytes (max: {max_size_bytes} bytes)")
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
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        logger.debug(f"Successfully loaded JSON from {path}")
        return data
    except json.JSONDecodeError as e:
        raise SecurityError(f"Invalid JSON in {path}: {e}")
    except (OSError, UnicodeDecodeError) as e:
        raise SecurityError(f"Cannot read file {path}: {e}")


def validate_url(url: str, *, allowed_schemes: tuple[str, ...] = ("https",), allow_private: bool = False) -> None:
    """
    Validate a URL for safety, including DNS rebinding protection.

    Resolves hostnames to IPs and validates the resolved addresses against
    private/loopback/reserved/link-local ranges to prevent DNS rebinding
    attacks where a hostname initially resolves to a public IP but later
    resolves to an internal one.

    Args:
        url: URL to validate

    Raises:
        SecurityError: If URL is invalid or uses insecure protocol
    """
    import ipaddress
    import socket
    from urllib.parse import urlparse

    try:
        parsed = urlparse(url)
    except Exception as e:
        raise SecurityError(f"Invalid URL '{url}': {e}")

    allow_private = allow_private or os.environ.get("AGENT_BOM_ALLOW_PRIVATE_EGRESS_URLS", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }

    if parsed.scheme not in allowed_schemes:
        if allowed_schemes == ("https",):
            raise SecurityError(f"URL must use HTTPS; got: {parsed.scheme}")
        expected = ", ".join(f"{scheme}://" for scheme in allowed_schemes)
        raise SecurityError(f"URL must use one of {expected}; got: {parsed.scheme}")

    # Validate domain is not localhost or internal IP
    hostname = parsed.hostname or ""
    if not hostname:
        raise SecurityError("URL must include a hostname")
    if hostname in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):  # nosec B104 - checking FOR these values to reject them, not binding to them
        if not allow_private:
            raise SecurityError(f"Cannot connect to localhost/internal IPs: {hostname}")
        logger.warning("Private egress URL allowed by operator override")
        return

    # Block cloud metadata endpoints (AWS/GCP/Azure)
    if hostname in ("169.254.169.254", "metadata.google.internal"):
        raise SecurityError(f"Cannot connect to cloud metadata endpoint: {hostname}")

    # Check if hostname is already an IP literal
    try:
        addr = ipaddress.ip_address(hostname)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            if not allow_private:
                raise SecurityError(f"Cannot connect to private/reserved IP: {hostname}")
            logger.warning("Private egress URL allowed by operator override")
            return
    except ValueError:
        pass  # hostname is a domain name — resolve below

    # DNS rebinding protection: resolve hostname and validate all resolved IPs
    try:
        addrinfos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror:
        raise SecurityError(f"Cannot resolve hostname: {hostname}")

    for family, _type, _proto, _canonname, sockaddr in addrinfos:
        resolved_ip = sockaddr[0]
        try:
            addr = ipaddress.ip_address(resolved_ip)
            if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
                if not allow_private:
                    raise SecurityError(f"Hostname '{hostname}' resolves to private/reserved IP: {resolved_ip}")
                logger.warning("Private egress URL allowed by operator override")
                return
        except ValueError:
            continue

    # Static log — no user-controlled values to prevent both cleartext
    # credential logging and log injection (CodeQL py/clear-text-logging,
    # py/log-injection).
    logger.debug("URL validated successfully")


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
        if not re.match(r"^(@[a-z0-9-_]+/)?[a-z0-9-_]+$", name.lower()):
            raise SecurityError(f"Invalid npm package name: {name}")

    elif ecosystem == "pypi":
        # PyPI: alphanumeric, hyphens, underscores, dots
        if not re.match(r"^[a-zA-Z0-9-_.]+$", name):
            raise SecurityError(f"Invalid PyPI package name: {name}")

    elif ecosystem == "go":
        # Go: domain/path format
        if not re.match(r"^[a-zA-Z0-9-_.\/]+$", name):
            raise SecurityError(f"Invalid Go package name: {name}")

    elif ecosystem == "cargo":
        # Rust: alphanumeric, hyphens, underscores
        if not re.match(r"^[a-zA-Z0-9-_]+$", name):
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
    has_url = bool(server_config.get("url") or server_config.get("uri"))
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

    logger.info("MCP server config validated: %s", sanitize_text(command or server_config.get("url", "unknown")))


# Docker/OCI image reference pattern — must start with alphanum, no shell metacharacters
_IMAGE_REF_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._\-/:@]+$")


def validate_image_ref(ref: str) -> str:
    """Validate a Docker/OCI image reference.

    Rejects references starting with ``-`` (argument injection) and those
    containing shell metacharacters.

    Returns:
        The validated reference string.

    Raises:
        SecurityError: If the reference is invalid.
    """
    if not ref or not _IMAGE_REF_RE.match(ref):
        raise SecurityError(f"Invalid image reference: {ref!r}")
    return ref


def sanitize_error(exc: Exception | str, generic: bool = False) -> str:
    """Return a safe error message suitable for API consumers.

    Strips sensitive data (file paths, URLs) from exception messages while
    preserving safe, actionable text.  Set ``generic=True`` to always return
    a fixed non-diagnostic string regardless of the exception content.
    """
    if generic:
        return "An internal error occurred. Please contact support."

    msg = str(exc)
    # Strip URLs first (before path regex matches the path portion)
    msg = re.sub(r"https?://[^\s\"']+", "<url>", msg)
    # Strip absolute file paths
    msg = re.sub(r"(/[^\s:\"']+)+", "<path>", msg)
    return msg[:200] if len(msg) > 200 else msg


# Export all validation functions
__all__ = [
    "SecurityError",
    "validate_command",
    "validate_arguments",
    "validate_environment",
    "validate_path",
    "sanitize_env_vars",
    "sanitize_command_args",
    "sanitize_launch_command",
    "sanitize_security_warnings",
    "sanitize_sensitive_payload",
    "sanitize_path_label",
    "sanitize_text",
    "sanitize_url",
    "validate_file_size",
    "validate_json_file",
    "validate_url",
    "validate_package_name",
    "create_safe_subprocess_env",
    "validate_mcp_server_config",
    "validate_image_ref",
    "sanitize_error",
]
