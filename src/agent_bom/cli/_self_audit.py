"""``agent-bom self-audit`` — agent-bom audits its OWN deployment posture.

Points the honesty model at the running control plane itself: reads (never
writes) the security-relevant configuration and reports an honest per-check
posture — hardened, misconfigured, weakened-but-acknowledged, or unknown.
Human table by default; ``--agent-mode`` emits the stable JSON envelope for
headless/CI callers, so operator + agent get surface parity with the
``GET /v1/self-posture`` API.
"""

from __future__ import annotations

from typing import cast

import click
from rich.console import Console

_STATUS_ICON = {
    "pass": "[green]✓[/green]",
    "fail": "[red]✗[/red]",
    "warn": "[yellow]⚠[/yellow]",
    "unknown": "[dim]○[/dim]",
}

_OVERALL_LINE = {
    "hardened": ("[green]", "Self-posture: hardened — no weakened settings detected."),
    "action_advised": ("[yellow]", "Self-posture: action advised — weakened settings detected."),
    "needs_review": ("[yellow]", "Self-posture: needs review — some checks could not be determined."),
    "at_risk": ("[red]", "Self-posture: at risk — one or more checks failed for this deployment mode."),
}


@click.command("self-audit")
def self_audit_cmd() -> None:
    """Audit THIS agent-bom deployment's own security + governance posture.

    \b
    Read-only checks:  API authentication, database tenant isolation (RLS),
                       audit-log integrity signing, secret sealing, and the
                       dependency attack surface. Honest pass/fail/warn/unknown
                       — unknown is explicit, never an assumed pass. Run
                       `agent-bom scan --self-scan` for the dependency CVE
                       posture.
    """
    from agent_bom.self_posture import self_posture

    report = self_posture()

    from agent_bom.cli._agent_mode import agent_mode_requested

    if agent_mode_requested():
        from agent_bom.cli._agent_mode import emit_command_envelope

        emit_command_envelope(
            command="self-audit",
            data=report,
            summary={
                "overall_status": report["overall_status"],
                "hardened": report["hardened"],
                "counts": report["counts"],
            },
        )
        return

    console = Console()
    console.print()
    console.print("  [bold]agent-bom self-audit[/bold]  [dim](this instance's own posture)[/dim]")
    console.print(f"  [dim]deployment: {report['deployment_env']}[/dim]")
    console.print()

    checks = cast(list[dict[str, str]], report["checks"])
    categories: list[str] = []
    for check in checks:
        if check["category"] not in categories:
            categories.append(check["category"])

    for category in categories:
        console.print(f"  [bold]{category.replace('_', ' ').title()}[/bold]")
        for check in checks:
            if check["category"] != category:
                continue
            icon = _STATUS_ICON.get(check["status"], "[dim]○[/dim]")
            console.print(f"    {icon}  {check['title']}")
            console.print(f"        [dim]{check['detail']}[/dim]")
            if check["status"] in {"fail", "warn"} and check["remediation"]:
                console.print(f"        [dim]→ {check['remediation']}[/dim]")
        console.print()

    color, message = _OVERALL_LINE.get(cast(str, report["overall_status"]), ("[dim]", "Self-posture computed."))
    console.print(f"  {color}{message}[/]")
    counts = cast(dict[str, int], report["counts"])
    console.print(f"  [dim]{counts['pass']} pass · {counts['fail']} fail · {counts['warn']} warn · {counts['unknown']} unknown[/dim]")
    console.print()
