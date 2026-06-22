"""Ingest command group — operator-provided evidence into the unified graph.

Reference-only ingest of evidence that already exists outside agent-bom. The
first surface is hardware/firmware attestation evidence (#1891): vendor
hardware/firmware SBOMs, signed firmware attestations, and BMC/BIOS/CMDB
inventory exports. agent-bom does not probe devices — it maps the supplied
evidence onto the graph so hosts, firmware, GPUs, and firmware/GPU-driver
advisories become first-class, traversable nodes.

Usage::

    agent-bom ingest hardware evidence.json                 # graph JSON to stdout
    agent-bom ingest hardware evidence.json -f table        # human summary
    agent-bom ingest hardware evidence.json -o graph.json   # write to a file
    agent-bom ingest hardware evidence.json --capture-serials  # retain raw serials
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Optional

import click

from agent_bom.cli._grouped_help import SuggestingGroup

if TYPE_CHECKING:
    from agent_bom.graph import UnifiedGraph

_DEFAULT_TENANT = "default"


@click.group("ingest", cls=SuggestingGroup)
def ingest_group() -> None:
    """Ingest operator-provided evidence into the unified graph (reference-only).

    \b
    Subcommands:
      hardware   Ingest hardware/firmware attestation evidence (host/GPU/firmware)
    """


@click.command("hardware")
@click.argument("evidence_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--tenant", default=_DEFAULT_TENANT, show_default=True, help="Tenant to scope the graph to.")
@click.option(
    "--capture-serials",
    is_flag=True,
    default=False,
    help="Retain raw device/GPU serials. Off by default — serials are hashed to a fingerprint.",
)
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["json", "table"]),
    default="json",
    show_default=True,
    help="json streams the graph export; table prints a human summary.",
)
@click.option("-o", "--output", "output_path", type=click.Path(dir_okay=False, path_type=Path), default=None)
def hardware_cmd(
    evidence_file: Path,
    tenant: str,
    capture_serials: bool,
    output_format: str,
    output_path: Optional[Path],
) -> None:
    """Map a hardware/firmware evidence file onto the unified graph.

    EVIDENCE_FILE is a JSON document conforming to the
    ``agent-bom.hardware-evidence/v1`` contract. This is evidence ingest, not a
    firmware scan: nothing is probed on any device.
    """
    from agent_bom.hardware_evidence import HardwareEvidenceError, build_hardware_graph

    try:
        evidence = json.loads(evidence_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise click.ClickException(f"could not read evidence file: {exc}") from exc

    try:
        graph = build_hardware_graph(evidence, capture_serials=capture_serials, tenant_id=tenant)
    except HardwareEvidenceError as exc:
        raise click.ClickException(str(exc)) from exc

    if output_format == "json":
        payload = json.dumps(graph.to_dict(), indent=2, sort_keys=True)
        if output_path:
            output_path.write_text(payload, encoding="utf-8")
            click.echo(f"Graph exported ({len(graph.nodes)} nodes, {len(graph.edges)} edges) → {output_path}")
        else:
            click.echo(payload)
        return

    _render_table(graph, capture_serials=capture_serials)


def _render_table(graph: UnifiedGraph, *, capture_serials: bool) -> None:
    from rich.console import Console
    from rich.table import Table

    from agent_bom.graph import EntityType
    from agent_bom.hardware_evidence import (
        RESOURCE_KIND_FIRMWARE,
        RESOURCE_KIND_GPU,
        RESOURCE_KIND_HOST,
    )

    nodes = list(graph.nodes.values())
    hosts = [n for n in nodes if n.attributes.get("resource_kind") == RESOURCE_KIND_HOST]
    firmware = [n for n in nodes if n.attributes.get("resource_kind") == RESOURCE_KIND_FIRMWARE]
    gpus = [n for n in nodes if n.attributes.get("resource_kind") == RESOURCE_KIND_GPU]
    advisories = [n for n in nodes if n.entity_type == EntityType.VULNERABILITY]

    con = Console()
    redaction = "raw serials retained" if capture_serials else "serials hashed"
    con.print(
        f"\n  [bold]Hardware/firmware evidence[/bold] [dim]· {len(hosts)} host(s) · "
        f"{len(firmware)} firmware · {len(gpus)} GPU(s) · {len(advisories)} advisory/ies · {redaction}[/dim]"
    )

    host_table = Table(title="Hosts", title_justify="left", title_style="bold")
    host_table.add_column("Host")
    host_table.add_column("Vendor / model")
    host_table.add_column("BIOS")
    host_table.add_column("Attestation")
    for host in hosts:
        a = host.attributes
        vendor_model = " ".join(p for p in (a.get("vendor", ""), a.get("model", "")) if p) or "—"
        host_table.add_row(
            host.label,
            vendor_model,
            a.get("bios_version", "—") or "—",
            ", ".join(host.compliance_tags) or "—",
        )
    if hosts:
        con.print(host_table)

    if advisories:
        adv_table = Table(title="Advisories", title_justify="left", title_style="bold")
        adv_table.add_column("ID")
        adv_table.add_column("Severity")
        adv_table.add_column("Affects")
        adv_table.add_column("Fixed in")
        for adv in advisories:
            adv_table.add_row(
                adv.label,
                adv.severity or "unknown",
                str(adv.attributes.get("affects", "host")),
                adv.attributes.get("fixed_version", "—") or "—",
            )
        con.print(adv_table)
    con.print()


ingest_group.add_command(hardware_cmd, "hardware")
