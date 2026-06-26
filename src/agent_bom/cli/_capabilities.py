"""`agent-bom capabilities` — the nothing-silent capability view.

Renders the declarative registry in :mod:`agent_bom.capabilities`: every gated
feature, its current state (enabled / available-to-unlock / degraded), *why*,
and the exact one-line unlock path. A silent coverage gap is, for a security
tool, false safety — so this view exists to make every gate self-explanatory.

Print contract:
  * never prints a secret value — only the presence/absence of a variable name,
  * deterministic for a fixed environment,
  * groups output as a coverage story and ends with a one-line summary.
"""

from __future__ import annotations

import click
from rich.console import Console

from agent_bom.capabilities import (
    GROUP_ORDER,
    GROUP_TITLES,
    Capability,
    CapabilityStatus,
    State,
    coverage_line,
    resolved_capabilities,
)

_STATE_ICON: dict[State, str] = {
    State.ON: "[green]✓[/green]",
    State.OFF: "[dim]○[/dim]",
    State.DEGRADED: "[yellow]◐[/yellow]",
    State.UNKNOWN: "[red]?[/red]",
}
_STATE_LABEL: dict[State, str] = {
    State.ON: "[green]ENABLED[/green]",
    State.OFF: "[dim]OFF[/dim]",
    State.DEGRADED: "[yellow]DEGRADED[/yellow]",
    State.UNKNOWN: "[red]UNKNOWN[/red]",
}


def _render_capability(console: Console, cap: Capability, status: CapabilityStatus) -> None:
    icon = _STATE_ICON[status.state]
    label = _STATE_LABEL[status.state]
    console.print(f"    {icon}  [bold]{cap.name}[/bold]  {label}")
    console.print(f"       [dim]{cap.does}[/dim]")
    console.print(f"       why: {status.detail}")
    if status.state is not State.ON:
        console.print(f"       [cyan]unlock:[/cyan] {cap.unlock}")
    console.print()


def render_capabilities(console: Console) -> None:
    """Render the full grouped capability view to ``console``.

    Reused by ``capabilities`` and by ``doctor`` so both surfaces stay identical.
    """
    resolved = resolved_capabilities()
    by_group: dict[str, list[tuple[Capability, CapabilityStatus]]] = {}
    for cap, status in resolved:
        by_group.setdefault(cap.group, []).append((cap, status))

    console.print()
    console.print("  [bold]agent-bom capabilities[/bold] [dim]— nothing silent[/dim]")
    console.print("  [dim]Every gated feature, its state, why, and how to unlock it.[/dim]")
    console.print()

    for group in GROUP_ORDER:
        items = by_group.get(group)
        if not items:
            continue
        console.print(f"  [bold]{GROUP_TITLES[group]}[/bold]")
        for cap, status in items:
            _render_capability(console, cap, status)

    console.print(f"  {coverage_line()}")
    console.print()


@click.command("capabilities")
def capabilities_cmd() -> None:
    """Show every gated capability: state, why, and how to unlock.

    \b
    States:  ENABLED   unlock condition met, the capability runs
             OFF       available but not unlocked (the unlock line says how)
             DEGRADED  active with reduced coverage or a caveat
             UNKNOWN   a probe could not evaluate (surfaced, never silent)

    \b
    No secret values are ever printed — only whether a variable is set.
    """
    render_capabilities(Console())
