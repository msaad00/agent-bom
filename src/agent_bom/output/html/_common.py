"""Shared low-level helpers and colour constants for the HTML report."""
from __future__ import annotations

_SEV_COLOR = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#6b7280",
    "none": "#16a34a",
    "unknown": "#9ca3af",
}

# Max packages shown per server before collapsing
_PKG_PREVIEW = 15

# Client-side pagination: rows shown per page for large findings tables.
_PAGE_SIZE = 50


def _sev_badge(sev: str) -> str:
    color = _SEV_COLOR.get(sev.lower(), "#6b7280")
    return (
        f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;'
        f'font-size:.72rem;font-weight:700;letter-spacing:.04em">{sev.upper()}</span>'
    )


def _esc(s: object) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
