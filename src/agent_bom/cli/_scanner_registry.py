"""Scanner driver registry CLI surfaces."""

from __future__ import annotations

import json

import click
from rich.table import Table

from agent_bom.cli._common import _make_console
from agent_bom.scanners.registry import list_registered_scanners, scanner_registry_summary, scanner_registry_warnings


@click.command("scanners")
@click.option("--include-planned/--active-only", default=True, help="Include planned scanner-driver slots.")
@click.option("-f", "--format", "output_format", type=click.Choice(["console", "json"]), default="console", show_default=True)
def scanners_cmd(include_planned: bool, output_format: str) -> None:
    """List scanner drivers, capabilities, and failure semantics."""

    drivers = list_registered_scanners(include_planned=include_planned)
    summary = scanner_registry_summary()
    warnings = scanner_registry_warnings()

    if output_format == "json":
        click.echo(
            json.dumps(
                {
                    "drivers": [driver.to_dict() for driver in drivers],
                    "summary": summary,
                    "warnings": warnings,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return

    console = _make_console()
    table = Table(title="Scanner Driver Registry", show_lines=False)
    table.add_column("Driver", style="bold cyan", no_wrap=True)
    table.add_column("State", no_wrap=True)
    table.add_column("Phase", no_wrap=True)
    table.add_column("Failure", no_wrap=True)
    table.add_column("Inputs")
    table.add_column("Findings")
    table.add_column("Summary")

    for driver in drivers:
        table.add_row(
            driver.name,
            driver.execution_state.value,
            driver.phase.value,
            driver.failure_mode.value,
            ", ".join(driver.input_types) or "-",
            ", ".join(driver.finding_types) or "-",
            driver.summary,
        )

    console.print(table)
    console.print(
        f"[dim]total={summary['total']} active={summary['active']} passive={summary['passive']} planned={summary['planned']}[/dim]"
    )
    for warning in warnings:
        console.print(f"[yellow]warning:[/yellow] {warning}")
