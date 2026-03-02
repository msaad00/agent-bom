"""Inline content scanning for MCP runtime proxy.

Scans JSON-RPC message payloads for security threats:
  - Prompt injection / jailbreak patterns
  - PII detection (email, SSN, credit card, phone, internal IP)
  - Secrets / credential exposure (API keys, tokens, private keys)
  - Payload vulnerabilities (SQLi, SSRF, path traversal, command injection, XSS)

Reuses existing pattern libraries from ``parsers.prompt_scanner`` and
``runtime.detectors`` — zero regex duplication.  Designed to plug into
``proxy.relay_client_to_server`` and ``proxy.relay_server_to_client``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Reuse existing pattern libraries
# ---------------------------------------------------------------------------
from agent_bom.parsers.prompt_scanner import (
    _INJECTION_PATTERNS,
    _SECRET_PATTERNS,
    _SENSITIVE_DATA_PATTERNS,
    _UNSAFE_INSTRUCTION_PATTERNS,
)

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class ScanResult:
    """A single detection from inline content scanning."""

    scanner: str  # "injection" | "pii" | "secrets" | "payload_vuln"
    rule_id: str  # e.g. "role_override", "ssn", "aws_key", "sqli"
    severity: str  # "critical" | "high" | "medium" | "low"
    confidence: str  # "high" | "medium" | "low"
    excerpt: str  # redacted match preview
    blocked: bool


@dataclass
class ScanConfig:
    """Configuration for inline proxy scanning."""

    enabled: bool = False
    mode: str = "audit"  # "audit" | "enforce"
    scanners: list[str] = field(default_factory=lambda: ["injection", "pii", "secrets", "payload_vuln"])
    pii_action: str = "redact"  # "redact" | "block"


# ---------------------------------------------------------------------------
# PII patterns (new — not in prompt_scanner.py)
# ---------------------------------------------------------------------------

_PII_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (
        re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
        "email",
        "medium",
    ),
    (
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "ssn",
        "high",
    ),
    (
        re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"),
        "credit_card",
        "high",
    ),
    (
        re.compile(r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        "phone",
        "medium",
    ),
    (
        re.compile(r"\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b"),
        "internal_ip",
        "medium",
    ),
]

# ---------------------------------------------------------------------------
# Payload vulnerability patterns (WAF-style — new)
# ---------------------------------------------------------------------------

_PAYLOAD_VULN_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (
        re.compile(r"(?i)(?:union\s+select|or\s+1\s*=\s*1|drop\s+table|;\s*delete\s|'\s*or\s*')"),
        "sqli",
        "high",
    ),
    (
        re.compile(r"(?i)(?:file://|gopher://|dict://|169\.254\.169\.254|::1)"),
        "ssrf",
        "high",
    ),
    (
        re.compile(r"(?:\.\./|\.\.\\|%2e%2e[/\\])"),
        "path_traversal",
        "high",
    ),
    (
        re.compile(r"(?:[;|&`$]\s*(?:cat|ls|id|whoami|curl|wget|nc|bash|sh)\b)"),
        "command_injection",
        "critical",
    ),
    (
        re.compile(r"(?i)(?:<script|javascript:|on(?:error|load|click)\s*=)"),
        "xss",
        "medium",
    ),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _redact_excerpt(match_text: str, max_len: int = 12) -> str:
    """Return a safely redacted preview of a match."""
    if len(match_text) <= 4:
        return "***"
    return match_text[:max_len] + "***"


def _scan_patterns(
    text: str,
    patterns: list[tuple[re.Pattern, str, str]],
    scanner_name: str,
    blocked: bool,
) -> list[ScanResult]:
    """Run a list of (regex, rule_id, severity) patterns against text."""
    results: list[ScanResult] = []
    for regex, rule_id, severity in patterns:
        m = regex.search(text)
        if m:
            results.append(
                ScanResult(
                    scanner=scanner_name,
                    rule_id=rule_id,
                    severity=severity,
                    confidence="high",
                    excerpt=_redact_excerpt(m.group(0)),
                    blocked=blocked,
                )
            )
    return results


def _scan_prompt_scanner_patterns(
    text: str,
    patterns: list[tuple[re.Pattern, str]],
    scanner_name: str,
    severity: str,
    blocked: bool,
) -> list[ScanResult]:
    """Adapter for prompt_scanner patterns which are (regex, description) tuples."""
    results: list[ScanResult] = []
    for regex, description in patterns:
        m = regex.search(text)
        if m:
            # Derive rule_id from description
            rule_id = description.lower().replace(" ", "_").replace(":", "")[:40]
            results.append(
                ScanResult(
                    scanner=scanner_name,
                    rule_id=rule_id,
                    severity=severity,
                    confidence="high",
                    excerpt=_redact_excerpt(m.group(0)),
                    blocked=blocked,
                )
            )
    return results


# ---------------------------------------------------------------------------
# Scanner entry points
# ---------------------------------------------------------------------------


def scan_content(text: str, config: ScanConfig) -> list[ScanResult]:
    """Run all enabled scanners against a text string.

    Returns a list of ScanResult findings. In enforce mode, findings
    have ``blocked=True`` (except PII when ``pii_action=redact``).
    """
    if not config.enabled or not text:
        return []

    is_enforce = config.mode == "enforce"
    results: list[ScanResult] = []

    # Injection scanning
    if "injection" in config.scanners:
        results.extend(_scan_prompt_scanner_patterns(text, _INJECTION_PATTERNS, "injection", "high", is_enforce))
        results.extend(
            _scan_prompt_scanner_patterns(
                text,
                _UNSAFE_INSTRUCTION_PATTERNS,
                "injection",
                "high",
                is_enforce,
            )
        )

    # PII scanning
    if "pii" in config.scanners:
        pii_blocked = is_enforce and config.pii_action == "block"
        results.extend(_scan_patterns(text, _PII_PATTERNS, "pii", pii_blocked))

    # Secrets scanning
    if "secrets" in config.scanners:
        results.extend(
            _scan_prompt_scanner_patterns(
                text,
                _SECRET_PATTERNS,
                "secrets",
                "critical",
                is_enforce,
            )
        )
        results.extend(
            _scan_prompt_scanner_patterns(
                text,
                _SENSITIVE_DATA_PATTERNS,
                "secrets",
                "medium",
                is_enforce,
            )
        )

    # Payload vulnerability scanning
    if "payload_vuln" in config.scanners:
        results.extend(_scan_patterns(text, _PAYLOAD_VULN_PATTERNS, "payload_vuln", is_enforce))

    return results


def scan_tool_call(tool_name: str, arguments: dict, config: ScanConfig) -> list[ScanResult]:
    """Scan tool call arguments for security threats.

    Serializes each argument value to string and runs ``scan_content``.
    """
    if not config.enabled or not arguments:
        return []

    results: list[ScanResult] = []
    for _key, value in arguments.items():
        text = json.dumps(value) if not isinstance(value, str) else value
        results.extend(scan_content(text, config))
    return results


def scan_tool_response(response_text: str, config: ScanConfig) -> list[ScanResult]:
    """Scan tool response content for security threats.

    Typically run on the JSON-serialized ``result`` field of a JSON-RPC
    response from the MCP server.
    """
    return scan_content(response_text, config)


# ---------------------------------------------------------------------------
# PII redaction
# ---------------------------------------------------------------------------


def redact_pii(text: str) -> str:
    """Replace PII matches with ``[REDACTED:<type>]`` placeholders."""
    for regex, pii_type, _severity in _PII_PATTERNS:
        text = regex.sub(f"[REDACTED:{pii_type}]", text)
    return text


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------


def load_scan_config(policy: dict) -> ScanConfig:
    """Extract inline scanning configuration from a proxy policy dict.

    Expected key::

        {
            "inline_scanning": {
                "enabled": true,
                "mode": "enforce",
                "scanners": ["injection", "pii", "secrets", "payload_vuln"],
                "pii_action": "redact"
            }
        }
    """
    section = policy.get("inline_scanning", {})
    if not section:
        return ScanConfig()

    return ScanConfig(
        enabled=bool(section.get("enabled", False)),
        mode=str(section.get("mode", "audit")),
        scanners=list(section.get("scanners", ["injection", "pii", "secrets", "payload_vuln"])),
        pii_action=str(section.get("pii_action", "redact")),
    )
