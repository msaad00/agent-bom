"""Single-line rendering of untrusted values for log messages."""

from __future__ import annotations

from agent_bom.security import sanitize_text


def sanitize_log_value(value: object, max_len: int = 200) -> str:
    """Redact an untrusted value and keep it on one log line."""
    return sanitize_text(value, max_len=max_len).replace("\r", " ").replace("\n", " ")
