"""Shared product brand tokens for terminal + lane labels.

Product name is always ``agent-bom``. The mark is BOM with an agent HUD in the O.
See ``docs/VISUAL_LANGUAGE.md``.
"""

from __future__ import annotations

from dataclasses import dataclass

PRODUCT_NAME = "agent-bom"
# Capability line for meta/prose — not shown under the nav lockup.
POSITIONING_SHORT = "Open security scanner for AI infrastructure"
# Longer meta line for OpenAPI / HTML <title> chrome (matches VISUAL_LANGUAGE).
POSITIONING_META = (
    "Open security scanner and self-hosted control plane for AI, MCP, and cloud infrastructure"
)
TAGLINE_CHAIN = "agent → MCP server → packages → CVEs → blast radius"
DOCS_URL = "https://github.com/msaad00/agent-bom"
REPORT_TITLE = f"{PRODUCT_NAME} scan report"

# Minimal dark mark for API /docs favicon when package data is unavailable.
MARK_SVG_DARK = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" role="img" aria-label="agent-bom mark">
  <defs>
    <linearGradient id="abm" x1="8" y1="6" x2="56" y2="58" gradientUnits="userSpaceOnUse">
      <stop offset="0%" stop-color="#34d399"/>
      <stop offset="100%" stop-color="#06b6d4"/>
    </linearGradient>
  </defs>
  <rect x="3.5" y="3.5" width="57" height="57" rx="15" fill="#0c1210" stroke="url(#abm)" stroke-width="2"/>
  <circle cx="32" cy="30.2" r="12" fill="#0f1a17" stroke="url(#abm)" stroke-width="2.4"/>
  <path d="M32 18.4V13.5" stroke="url(#abm)" stroke-width="2.2" stroke-linecap="round"/>
  <circle cx="32" cy="11.9" r="2.1" fill="url(#abm)"/>
  <circle cx="28" cy="28.9" r="2.7" fill="#34d399"/>
  <circle cx="36" cy="28.9" r="2.7" fill="#22d3ee"/>
  <path d="M28.3 35.4h7.4" stroke="url(#abm)" stroke-width="1.9" stroke-linecap="round"/>
</svg>
"""

# Terminal mark: BOM with agent HUD in the O (visor + antenna cue).
_MARK_UNICODE = (
    "  ┌───────────┐",
    "  │ B [=o=] M │",
    "  └───────────┘",
)
_MARK_ASCII = (
    "  +-----------+",
    "  | B [=o=] M |",
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
    lines.append(f"  {POSITIONING_SHORT}")
    return "\n" + "\n".join(lines) + "\n"


def print_cli_startup_banner(console: object, *, version: str) -> None:
    """Render the no-args CLI splash with mark, wordmark, and quick start."""

    mark = cli_mark_lines()
    # ``console`` is a Rich Console; typed as object to avoid a hard import cycle.
    print_ = getattr(console, "print")
    print_()
    for line in mark:
        print_(f"[bold cyan]{line}[/bold cyan]")
    print_()
    print_(f"    [bold]{PRODUCT_NAME}[/bold] [dim]·[/dim] [dim]v{version}[/dim]")
    print_(f"    [dim]{POSITIONING_SHORT}[/dim]")
    print_()
    print_(f"    [dim]{TAGLINE_CHAIN}[/dim]")
    print_()
    print_("    [bold]Quick start[/bold]")
    print_(f"    [cyan]▶[/cyan] [bold]{PRODUCT_NAME} scan[/bold]                 discover + scan local agents and MCP servers")
    print_(f"    [cyan]▶[/cyan] [bold]{PRODUCT_NAME} samples first-run[/bold]   write an inspectable sample AI stack")
    print_(f"    [cyan]▶[/cyan] [bold]{PRODUCT_NAME} -h[/bold]                  full command catalog (grouped)")
    print_()
    print_(f"    [dim]Docs:[/dim]  [link={DOCS_URL}]{DOCS_URL}[/link]")
    print_()


def emit_cli_runtime_summary(
    title: str,
    rows: list[tuple[str, str]],
    *,
    err: bool = False,
    force_ascii: bool = False,
) -> None:
    """Print the BOM mark + product title + aligned key/value rows for serve/gateway."""

    import click

    click.echo("", err=err)
    for line in cli_mark_lines(force_ascii=force_ascii):
        click.echo(line, err=err)
    click.echo(f"  {title}", err=err)
    for label, value in rows:
        click.echo(f"  {label:<11} {value}", err=err)
    click.echo("  Press Ctrl+C to stop.\n", err=err)


__all__ = [
    "DOCS_URL",
    "LANE_TOKENS",
    "MARK_SVG_DARK",
    "POSITIONING_META",
    "POSITIONING_SHORT",
    "PRODUCT_NAME",
    "REPORT_TITLE",
    "TAGLINE_CHAIN",
    "LaneToken",
    "cli_banner_plain",
    "cli_mark_lines",
    "emit_cli_runtime_summary",
    "lane_title",
    "lane_token",
    "print_cli_startup_banner",
]
