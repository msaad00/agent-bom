"""Shared product lane labels for terminal output.

The UI and docs present agent-bom as a small set of product lanes rather
than a pile of commands. The CLI should use the same language in compact
mode so the first-run experience feels like one product.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LaneToken:
    """Terminal-safe label + Rich style for a product lane."""

    label: str
    style: str


LANE_TOKENS: dict[str, LaneToken] = {
    "discover": LaneToken(label="DISCOVER", style="blue"),
    "scan": LaneToken(label="SCAN", style="red"),
    "analyze": LaneToken(label="ANALYZE", style="yellow"),
    "protect": LaneToken(label="PROTECT", style="magenta"),
    "govern": LaneToken(label="GOVERN", style="green"),
}


def lane_token(name: str) -> LaneToken:
    """Return a lane token, defaulting to a neutral uppercase label."""

    key = name.strip().lower()
    return LANE_TOKENS.get(key, LaneToken(label=key.upper() or "AGENT-BOM", style="cyan"))


def lane_title(name: str, title: str) -> str:
    """Render a compact lane-prefixed section title."""

    token = lane_token(name)
    return f"[{token.style}]{token.label}[/{token.style}] [dim]|[/dim] [bold]{title}[/bold]"


__all__ = ["LANE_TOKENS", "LaneToken", "lane_title", "lane_token"]
