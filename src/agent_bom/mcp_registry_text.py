"""Shared text normalization for the bundled MCP registry."""

from __future__ import annotations

MCP_REGISTRY_DESCRIPTION_MAX_CHARS = 100


def normalize_registry_description(value: object, *, max_chars: int = MCP_REGISTRY_DESCRIPTION_MAX_CHARS) -> str:
    """Return a single-line, bounded registry description.

    MCP registry feeds are user-controlled and vary widely in length. Keeping
    descriptions short protects release metadata, UI cards, and downstream MCP
    catalog consumers from oversized generated text.
    """
    text = " ".join(str(value or "").split())
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 1].rstrip() + "…"
