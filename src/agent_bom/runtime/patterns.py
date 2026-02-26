"""Security patterns for runtime MCP traffic monitoring.

Regex patterns for detecting credential leaks, dangerous arguments,
and suspicious tool call sequences in MCP traffic.
"""

from __future__ import annotations

import re

# ─── Credential patterns in tool responses ───────────────────────────────────

# Each pattern: (name, compiled regex)
CREDENTIAL_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS Secret Key", re.compile(r"(?:aws_secret_access_key|secret_?key)\s*[=:]\s*[A-Za-z0-9/+=]{40}", re.IGNORECASE)),
    ("GitHub Token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}")),
    ("GitLab Token", re.compile(r"glpat-[A-Za-z0-9\-_]{20,}")),
    ("OpenAI API Key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("Anthropic API Key", re.compile(r"sk-ant-[A-Za-z0-9\-_]{20,}")),
    ("Slack Token", re.compile(r"xox[bporas]-[A-Za-z0-9\-]{10,}")),
    ("Stripe Key", re.compile(r"[sr]k_(live|test)_[A-Za-z0-9]{20,}")),
    ("Generic Bearer Token", re.compile(r"Bearer\s+[A-Za-z0-9\-_.~+/]+=*", re.IGNORECASE)),
    ("Generic API Key", re.compile(r"(?:api[_-]?key|apikey|access[_-]?token)\s*[=:]\s*['\"]?[A-Za-z0-9\-_.]{20,}", re.IGNORECASE)),
    ("Private Key Block", re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----")),
    ("Connection String", re.compile(r"(?:mongodb|postgres|mysql|redis)://[^\s]{10,}", re.IGNORECASE)),
]


# ─── Dangerous argument patterns ──────────────────────────────────────────────

# Patterns that indicate shell injection, path traversal, or credential exfiltration
DANGEROUS_ARG_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("Shell metacharacter", re.compile(r"[;&|`$]|\$\(|>\s*/|<\s*/")),
    ("Path traversal", re.compile(r"\.\./|\.\.\\|%2e%2e")),
    ("Command injection", re.compile(r"\b(?:curl|wget|nc|ncat|bash|sh|python|perl|ruby)\s", re.IGNORECASE)),
    ("Environment variable access", re.compile(r"\$(?:HOME|PATH|USER|AWS_|ANTHROPIC_|OPENAI_|GITHUB_)", re.IGNORECASE)),
    ("Credential-like value", re.compile(r"(?:password|secret|token|key)\s*[=:]\s*\S{8,}", re.IGNORECASE)),
    ("Base64 encoded payload", re.compile(r"(?:^|[^A-Za-z0-9])(?:[A-Za-z0-9+/]{40,}={0,2})(?:$|[^A-Za-z0-9])")),
    ("Hex encoded payload", re.compile(r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){9,}")),
]


# ─── Suspicious tool call sequences ──────────────────────────────────────────

# (sequence_name, [tool_name_patterns], description)
# If tools matching these patterns are called in order within a window,
# it may indicate exfiltration or lateral movement.
SUSPICIOUS_SEQUENCES: list[tuple[str, list[str], str]] = [
    (
        "data_exfiltration",
        ["read", "http|fetch|request|curl|post"],
        "Read followed by network request — potential data exfiltration",
    ),
    (
        "credential_harvest",
        ["read|list|get", "write|create|send|post"],
        "Read/list followed by write/send — potential credential harvesting",
    ),
    (
        "privilege_escalation",
        ["exec|run|shell|command", "write|create|chmod"],
        "Command execution followed by file write — potential privilege escalation",
    ),
    (
        "reconnaissance",
        ["list|search|find|glob", "list|search|find|glob", "read"],
        "Multiple list/search operations followed by read — reconnaissance pattern",
    ),
]
