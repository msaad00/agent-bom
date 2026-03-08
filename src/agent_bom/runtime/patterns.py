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


# ─── Response content inspection patterns ────────────────────────────────────

# HTML/CSS cloaking patterns used to hide malicious instructions from users
# while keeping them visible to the LLM (Unit42 research)
RESPONSE_CLOAKING_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("CSS display:none", re.compile(r"display\s*:\s*none", re.IGNORECASE)),
    ("CSS visibility:hidden", re.compile(r"visibility\s*:\s*hidden", re.IGNORECASE)),
    ("CSS opacity:0", re.compile(r"opacity\s*:\s*0(?:[;\s\"]|$)", re.IGNORECASE)),
    ("CSS position offscreen", re.compile(r"position\s*:\s*absolute[^}]*(?:left|top)\s*:\s*-\d{4,}px", re.IGNORECASE)),
    ("CSS font-size:0", re.compile(r"font-size\s*:\s*0(?:px|em|rem|%)?[;\s\"]", re.IGNORECASE)),
    ("CSS color transparent", re.compile(r"color\s*:\s*(?:transparent|rgba\s*\([^)]*,\s*0\s*\))", re.IGNORECASE)),
    ("HTML hidden attribute", re.compile(r"<[^>]+\bhidden\b[^>]*>", re.IGNORECASE)),
    ("HTML aria-hidden", re.compile(r'aria-hidden\s*=\s*["\']true["\']', re.IGNORECASE)),
]

# SVG payload patterns — embedded scripts or foreign content
RESPONSE_SVG_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("SVG script tag", re.compile(r"<script[^>]*>", re.IGNORECASE)),
    ("SVG foreignObject", re.compile(r"<foreignObject[^>]*>", re.IGNORECASE)),
    ("SVG onload handler", re.compile(r"\bon(?:load|error|click|mouseover)\s*=", re.IGNORECASE)),
    ("SVG xlink:href javascript", re.compile(r'xlink:href\s*=\s*["\']javascript:', re.IGNORECASE)),
    ("SVG use href data URI", re.compile(r'href\s*=\s*["\']data:', re.IGNORECASE)),
]

# Zero-width and invisible Unicode characters used to hide instructions
RESPONSE_INVISIBLE_CHARS: list[tuple[str, re.Pattern]] = [
    ("Zero-width space cluster", re.compile(r"[\u200b\u200c\u200d\ufeff]{3,}")),
    ("Zero-width joiner sequence", re.compile(r"(?:\u200d.){4,}")),
    ("Homoglyph substitution", re.compile(r"[\u0410-\u044f](?=[a-zA-Z])|(?<=[a-zA-Z])[\u0410-\u044f]")),  # Cyrillic mixed with Latin
    ("Right-to-left override", re.compile(r"[\u202e\u2066\u2067\u2068\u202a\u202b]")),
    ("Tag characters", re.compile(r"[\U000e0001-\U000e007f]{3,}")),
]

# Base64 encoded content in responses (potential exfiltration staging)
RESPONSE_BASE64_PATTERN = re.compile(r"(?:^|[^A-Za-z0-9+/])([A-Za-z0-9+/]{60,}={0,2})(?:$|[^A-Za-z0-9+/])")


# ─── Prompt injection patterns in tool responses ──────────────────────────────

# Patterns that indicate a tool response (e.g. from a vector DB retrieval or
# RAG context fetch) is attempting to inject instructions into the LLM.
# Used by ResponseInspector to detect cache poisoning and cross-agent injection.
RESPONSE_INJECTION_PATTERNS: list[tuple[str, re.Pattern]] = [
    # Role / persona overrides
    (
        "Role override",
        re.compile(
            r"\b(?:ignore|disregard|forget|override)\b.{0,40}\b(?:instructions?|system\s+prompt|previous|above|rules?|constraints?)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "System prompt injection",
        re.compile(
            r"<(?:system|assistant|user|im_start|im_end)[>\s]",
            re.IGNORECASE,
        ),
    ),
    (
        "Jailbreak trigger",
        re.compile(
            r"\b(?:DAN|jailbreak|do\s+anything\s+now|developer\s+mode|god\s+mode|unrestricted\s+mode|sudo\s+mode)\b",
            re.IGNORECASE,
        ),
    ),
    # Instruction injection
    (
        "Instruction injection",
        re.compile(
            r"\b(?:new\s+instruction|additional\s+instruction|important\s+instruction|secret\s+instruction|hidden\s+instruction)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "Task hijack",
        re.compile(
            r"\b(?:instead(?:\s+of)?|actually|your\s+real\s+task|your\s+actual\s+(?:goal|purpose|job)|from\s+now\s+on)\b.{0,60}\b(?:you\s+(?:must|should|will|are\s+to)|please|task)\b",
            re.IGNORECASE,
        ),
    ),
    # Exfiltration instructions embedded in content
    (
        "Exfil instruction",
        re.compile(
            r"\b(?:send|post|forward|transmit|upload|exfiltrate)\b.{0,60}\b(?:this\s+(?:conversation|context|data|prompt)|user\s+data|api\s+key|token|secret)\b",
            re.IGNORECASE,
        ),
    ),
    # Prompt delimiter attacks
    (
        "Prompt delimiter attack",
        re.compile(
            r"(?:###\s*(?:SYSTEM|INSTRUCTION|CONTEXT)|---\s*(?:SYSTEM|NEW\s+PROMPT)|={3,}\s*(?:SYSTEM|INSTRUCTION))",
            re.IGNORECASE,
        ),
    ),
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
