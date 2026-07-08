"""Shared terminal layout for scan, cloud, connect, and interactive CLI paths.

Keeps provider-agnostic output consistent: lane-labelled sections, collapsed
warnings, verdict-first summaries, and a single footer with next-step commands.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import TYPE_CHECKING, Iterator

from rich.panel import Panel
from rich.rule import Rule

from agent_bom.output.brand_tokens import lane_title
from agent_bom.output.compact import _compact_detail

if TYPE_CHECKING:
    from rich.console import Console

    from agent_bom.cli.agents._context import ScanContext
    from agent_bom.models import AIBOMReport


def ctx_quiet(ctx: ScanContext) -> bool:
    """True when console output should be suppressed (``-q`` / pipe mode)."""
    con = getattr(ctx, "con", None)
    return bool(getattr(ctx, "quiet", False) or getattr(con, "quiet", False))


def ctx_verbose(ctx: ScanContext) -> bool:
    """True when the operator asked for expanded terminal detail."""
    return bool(getattr(ctx, "verbose", False))


@contextmanager
def stage_status(con: Console, message: str, *, enabled: bool) -> Iterator[None]:
    """Rich status spinner when enabled; no-op otherwise."""
    if not enabled:
        yield
        return
    with con.status(message, spinner="dots"):
        yield


def print_lane_header(con: Console, lane: str, title: str) -> None:
    """Open a lane-labelled section (DISCOVER | SCAN | GOVERN …)."""
    con.print()
    con.print(f"  {lane_title(lane, title)}")


def print_section_divider(con: Console, label: str = "") -> None:
    """Visual separator between major report blocks."""
    con.print()
    con.print(Rule(label, style="dim") if label else Rule(style="dim"))


def print_collapsed_warnings(
    con: Console,
    warnings: list[str] | tuple[str, ...],
    *,
    verbose: bool,
    max_visible: int = 2,
    prefix: str = "!",
) -> None:
    """Print warnings; collapse long lists unless *verbose*."""
    clean = [str(w).strip() for w in warnings if str(w or "").strip()]
    if not clean:
        return
    if verbose:
        for warning in clean:
            con.print(f"  [yellow]{prefix}[/yellow] {_compact_detail(warning, 120)}")
        return
    for warning in clean[:max_visible]:
        con.print(f"  [yellow]{prefix}[/yellow] {_compact_detail(warning, 100)}")
    remaining = len(clean) - min(len(clean), max_visible)
    if remaining > 0:
        con.print(f"  [dim]… {remaining} more warning(s) — use --verbose to expand[/dim]")


def print_provider_discovery_result(
    con: Console,
    provider: str,
    *,
    agent_count: int,
    package_count: int,
    warnings: list[str] | tuple[str, ...],
    verbose: bool,
) -> None:
    """One-line provider discovery summary plus collapsed warnings."""
    label = provider.upper()
    if agent_count:
        con.print(f"  [green]✓[/green] {label} · {agent_count} agent(s) · {package_count} package(s)")
    else:
        con.print(f"  [dim]—[/dim] {label} · no AI agents found")
    print_collapsed_warnings(con, warnings, verbose=verbose)


def print_benchmark_line(
    con: Console,
    label: str,
    *,
    total: int,
    passed: int,
    failed: int,
    pass_rate: float,
    scope: str = "",
    errored: int = 0,
) -> None:
    """Compact one-line benchmark result."""
    scope_bit = f" · {scope}" if scope else ""
    errored_bit = f" · {errored} errored" if errored else ""
    con.print(
        f"  [green]✓[/green] {label} · {total} checks{scope_bit} · {passed} passed · {failed} failed{errored_bit} ({pass_rate:.0f}% pass)"
    )


def print_scan_next_steps(con: Console, report: AIBOMReport, *, quiet: bool = False) -> None:
    """Footer with graph / report / drill-down commands."""
    if quiet:
        return

    steps: list[str] = []
    if getattr(report, "total_agents", 0):
        steps.append("agent-bom graph")
    if getattr(report, "total_vulnerabilities", 0) or getattr(report, "critical_vulns", None):
        steps.append("agent-bom report -f html -o agent-bom-report.html")
    else:
        steps.append("agent-bom report -f html -o agent-bom-report.html")

    cis_attrs = (
        "cis_benchmark_data",
        "azure_cis_benchmark_data",
        "gcp_cis_benchmark_data",
        "snowflake_cis_benchmark_data",
    )
    if any(getattr(report, attr, None) for attr in cis_attrs):
        steps.append("agent-bom cloud scan --verbose --show-passed   # full CIS plan")

    print_section_divider(con, "Next")
    for step in steps:
        con.print(f"  [cyan]→[/cyan] {step}")


def render_connect_card(con: Console, *, title: str, role_summary: str, body: str, next_command: str) -> None:
    """Readable connect/onboarding card for every cloud source."""
    con.print()
    con.print(
        Panel(
            body,
            title=f"[bold]Connect {title}[/bold]",
            subtitle=f"[dim]{role_summary}[/dim]",
            border_style="cyan",
            padding=(1, 2),
        )
    )
    con.print(f"  [bold]Next[/bold]  [cyan]{next_command}[/cyan]")
    con.print()


__all__ = [
    "ctx_quiet",
    "ctx_verbose",
    "print_benchmark_line",
    "print_collapsed_warnings",
    "print_lane_header",
    "print_provider_discovery_result",
    "print_scan_next_steps",
    "print_section_divider",
    "render_connect_card",
    "stage_status",
]
