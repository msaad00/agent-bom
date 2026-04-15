"""Shared prompt and guardrail signal helpers for AST analyzers."""

from __future__ import annotations

import re

_GUARDRAIL_CALL_PATTERNS = re.compile(
    r"\b(?:content_filter|safety_check|moderate|moderation|validate_input|"
    r"validate_output|check_toxicity|check_bias|filter_response|sanitize|"
    r"guard|guardrail|rate_limit|throttle|pii_detect|anonymize|redact)\b",
    re.IGNORECASE,
)

_PROMPT_RISK_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("credential_in_prompt", re.compile(r"(?:api[_-]?key|password|secret|token)\s*[=:]\s*\S+", re.IGNORECASE)),
    ("unrestricted_access", re.compile(r"\b(?:full\s+access|no\s+restrictions?|unrestricted|admin\s+privileges?)\b", re.IGNORECASE)),
    ("code_execution", re.compile(r"\b(?:execute|run|eval|exec)\s+(?:any|all|arbitrary)\s+(?:code|command|script)\b", re.IGNORECASE)),
    ("data_exfil_instruction", re.compile(r"\b(?:send|forward|transmit|upload)\s+(?:data|results|output|findings)\s+to\b", re.IGNORECASE)),
    ("no_safety", re.compile(r"\b(?:bypass|skip|ignore|disable)\s+(?:safety|security|guardrail|filter|moderation)\b", re.IGNORECASE)),
]


def check_prompt_risks(text: str) -> list[str]:
    """Check a prompt for security risk patterns."""
    flags = []
    for flag_name, pattern in _PROMPT_RISK_PATTERNS:
        if pattern.search(text):
            flags.append(flag_name)
    return flags


def classify_prompt_type(var_name: str) -> str:
    """Classify prompt type from variable/parameter name."""
    name = var_name.lower()
    if "system" in name:
        return "system_prompt"
    if "instruct" in name:
        return "instructions"
    if "template" in name:
        return "template"
    if "prefix" in name or "preamble" in name:
        return "prefix"
    if "backstory" in name or "persona" in name or "role" in name:
        return "persona"
    return "prompt"
