"""Local warehouse-export mapping; never execute SQL or access provider credentials."""

from __future__ import annotations

import json
import os
from pathlib import Path

import click

_MAX_BYTES = 16 * 1024 * 1024


def _load(path: Path) -> dict:
    with path.open("rb") as stream:
        content = stream.read(_MAX_BYTES + 1)
    if len(content) > _MAX_BYTES:
        raise ValueError("Warehouse input exceeds the 16 MiB limit")
    value = json.loads(content)
    if not isinstance(value, dict):
        raise ValueError("Warehouse input must be an object")
    return value


@click.command("warehouse")
@click.argument("rows_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--mapping", "mapping_file", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--tenant", required=True, help="Explicit local graph tenant scope; does not grant control-plane access.")
@click.option("-o", "--output", "output_file", required=True, type=click.Path(dir_okay=False, path_type=Path))
def warehouse_cmd(rows_file: Path, mapping_file: Path, tenant: str, output_file: Path) -> None:
    """Map exported warehouse rows to a versioned graph JSON artifact.

    Both inputs are local JSON. Source observations remain recorded evidence;
    the import does not establish collection coverage or successful access.
    """
    from agent_bom.graph.warehouse_evidence import build_warehouse_graph

    try:
        graph = build_warehouse_graph(_load(rows_file), _load(mapping_file), tenant_id=tenant)
        payload = json.dumps(graph.to_dict(), indent=2, sort_keys=True, allow_nan=False) + "\n"
    except (OSError, ValueError, TypeError, RecursionError):
        raise click.ClickException("Invalid warehouse evidence or mapping; check the documented schema and limits.") from None
    try:
        # Exclusive creation preserves existing evidence if a command is repeated.
        with os.fdopen(os.open(output_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", encoding="utf-8") as stream:
            stream.write(payload)
    except OSError:
        raise click.ClickException("Cannot create output; choose a new writable artifact path.") from None
    click.echo(f"Exported {len(graph.nodes)} entities and {len(graph.edges)} recorded relationships. Collection coverage remains unknown.")
