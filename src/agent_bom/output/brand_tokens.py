"""Shared product brand tokens for terminal + lane labels.

Product name is always ``agent-bom``. The mark is BOM-with-agent-O (logo only).
See ``docs/VISUAL_LANGUAGE.md``.
"""

from __future__ import annotations

from dataclasses import dataclass

PRODUCT_NAME = "agent-bom"
TAGLINE_SHORT = "BOM for humans & agents"
TAGLINE_CHAIN = "agent → MCP server → packages → CVEs → blast radius"
DOCS_URL = "https://github.com/msaad00/agent-bom"

# Terminal mark: BOM with agent face in the O (antenna + eyes).
_MARK_UNICODE = (
    "  ┌───────────┐",
    "  │ B  ◉  M  │",
    "  └───────────┘",
)
_MARK_ASCII = (
    "  +-----------+",
    "  | B  .o.  M |",
    "  +-----------+",
)


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


def _stdout_supports(text: str) -> bool:
    import sys

    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        text.encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def cli_mark_lines(*, force_ascii: bool = False) -> tuple[str, ...]:
    """Return the BOM-with-agent-O mark as terminal lines."""

    if force_ascii or not _stdout_supports("\n".join(_MARK_UNICODE)):
        return _MARK_ASCII
    return _MARK_UNICODE


def cli_banner_plain(*, version: str | None = None, force_ascii: bool = False) -> str:
    """Plain-text lockup for ``BANNER`` / non-Rich callers."""

    lines = list(cli_mark_lines(force_ascii=force_ascii))
    ver = f"  v{version}" if version else ""
    lines.append(f"  {PRODUCT_NAME}{ver}")
    lines.append(f"  {TAGLINE_SHORT}")
    return "\n" + "\n".join(lines) + "\n"


def print_cli_startup_banner(console: object, *, version: str) -> None:
    """Render the no-args CLI splash with mark, wordmark, tagline, and quick start."""

    mark = cli_mark_lines()
    # ``console`` is a Rich Console; typed as object to avoid a hard import cycle.
    print_ = getattr(console, "print")
    print_()
    for line in mark:
        print_(f"[bold cyan]{line}[/bold cyan]")
    print_()
    print_(f"    [bold]{PRODUCT_NAME}[/bold] [dim]·[/dim] [dim]v{version}[/dim]")
    print_(f"    [dim]{TAGLINE_SHORT}[/dim]")
    print_()
    print_("    Open security scanner for AI infrastructure.")
    print_(f"    [dim]{TAGLINE_CHAIN}[/dim]")
    print_()
    print_("    [bold]Quick start[/bold]")
    print_(f"    [cyan]▶[/cyan] [bold]{PRODUCT_NAME} scan[/bold]                 discover + scan local agents and MCP servers")
    print_(f"    [cyan]▶[/cyan] [bold]{PRODUCT_NAME} samples first-run[/bold]   write an inspectable sample AI stack")
    print_(f"    [cyan]▶[/cyan] [bold]{PRODUCT_NAME} -h[/bold]                  full command catalog (grouped)")
    print_()
    print_(f"    [dim]Docs:[/dim]  [link={DOCS_URL}]{DOCS_URL}[/link]")
    print_()


__all__ = [
    "DOCS_URL",
    "LANE_TOKENS",
    "PRODUCT_NAME",
    "TAGLINE_CHAIN",
    "TAGLINE_SHORT",
    "LaneToken",
    "cli_banner_plain",
    "cli_mark_lines",
    "lane_title",
    "lane_token",
    "print_cli_startup_banner",
]
