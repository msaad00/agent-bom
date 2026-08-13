"""CLI queries for ranked attack paths and exposure paths.

Thin surface over ``GET /v1/graph/attack-paths`` and
``GET /v1/graph/exposure-paths`` — the same ranked-path computation the REST API
and the MCP ``blast_radius`` / ``exposure_paths`` tools consume. No path logic is
reimplemented here; the CLI only renders the queue with a lead summary and dense
rows (the cloud-CLI readability pattern).
"""

from __future__ import annotations

from collections.abc import Mapping

import click

from agent_bom.cli._findings_group import (
    _common_api_options,
    _emit_json,
    _make_client,
    _run_request,
    _string,
)


def _node_label(value: object) -> str:
    if isinstance(value, Mapping):
        return _string(value.get("label") or value.get("id"))
    return _string(value)


def _risk(value: object) -> str:
    if isinstance(value, (int, float)):
        return f"{float(value):.0f}"
    return _string(value)


def _print_attack_paths(payload: Mapping[str, object], *, offset: int) -> None:
    rows = payload.get("attack_paths")
    if not isinstance(rows, list):
        rows = []
    pagination = payload.get("pagination") if isinstance(payload.get("pagination"), Mapping) else {}
    total = pagination.get("total") if isinstance(pagination, Mapping) else None
    scan_id = _string(payload.get("scan_id")) or "-"
    total_text = _string(total) if isinstance(total, int) else str(len(rows))
    click.echo(f"{len(rows)} of {total_text} attack paths (scan {scan_id})")
    click.echo("#\trisk\tsource\ttarget\thops\ttechniques\tsummary")
    for index, item in enumerate(rows):
        if not isinstance(item, dict):
            continue
        hops = item.get("hops")
        techniques = item.get("mitre_technique_ids")
        click.echo(
            "\t".join(
                [
                    _string(offset + index + 1),
                    _risk(item.get("composite_risk")),
                    _node_label(item.get("source")),
                    _node_label(item.get("target")),
                    _string(len(hops)) if isinstance(hops, list) else "0",
                    ",".join(str(t) for t in techniques) if isinstance(techniques, list) else "",
                    _string(item.get("summary")),
                ]
            )
        )


def _print_exposure_paths(payload: Mapping[str, object]) -> None:
    rows = payload.get("paths")
    if not isinstance(rows, list):
        rows = []
    total = payload.get("total")
    scan_id = _string(payload.get("scan_id")) or "-"
    total_text = _string(total) if isinstance(total, int) else str(len(rows))
    click.echo(f"{len(rows)} of {total_text} exposure paths (scan {scan_id})")
    message = payload.get("message")
    if not rows and isinstance(message, str) and message:
        click.echo(f"note: {message}")
    click.echo("rank\trisk\tseverity\tsource\ttarget\thops\tsummary")
    for index, item in enumerate(rows):
        if not isinstance(item, dict):
            continue
        hops = item.get("hops")
        click.echo(
            "\t".join(
                [
                    _string(item.get("rank")) or _string(index + 1),
                    _risk(item.get("riskScore")),
                    _string(item.get("severity")),
                    _node_label(item.get("source")),
                    _node_label(item.get("target")),
                    _string(len(hops)) if isinstance(hops, list) else "0",
                    _string(item.get("summary") or item.get("label")),
                ]
            )
        )


@click.group(name="graph-paths")
def graph_paths_cmd() -> None:
    """Query ranked attack paths and exposure paths from the correlated graph."""


@graph_paths_cmd.command("attack")
@click.option("--scan-id", "scan_id", help="Scan snapshot to query (defaults to the latest for the tenant).")
@click.option("--limit", default=20, show_default=True, type=click.IntRange(min=1, max=1000), help="Maximum attack paths.")
@click.option("--offset", default=0, show_default=True, type=click.IntRange(min=0), help="Pagination offset.")
@click.option("--format", "output_format", type=click.Choice(["table", "json"]), default="table", show_default=True)
@_common_api_options
def attack_paths_cmd(
    api_url: str | None,
    api_key: str | None,
    bearer_token: str | None,
    tenant_id: str | None,
    scan_id: str | None,
    limit: int,
    offset: int,
    output_format: str,
) -> None:
    """List ranked attack paths (fix-first triage queue) for a scan."""

    client = _make_client(api_url, api_key, bearer_token, tenant_id)
    payload = _run_request(client, lambda api: api.attack_paths(scan_id=scan_id, offset=offset, limit=limit))
    if output_format == "json":
        _emit_json(payload)
    else:
        _print_attack_paths(payload, offset=offset)


@graph_paths_cmd.command("exposure")
@click.option("--scan-id", "scan_id", help="Scan snapshot to query (defaults to the latest for the tenant).")
@click.option("--limit", default=20, show_default=True, type=click.IntRange(min=1, max=100), help="Maximum exposure paths.")
@click.option("--min-risk", "min_risk", default=0.0, show_default=True, type=click.FloatRange(min=0, max=100), help="Minimum risk score.")
@click.option("--format", "output_format", type=click.Choice(["table", "json"]), default="table", show_default=True)
@_common_api_options
def exposure_paths_cmd(
    api_url: str | None,
    api_key: str | None,
    bearer_token: str | None,
    tenant_id: str | None,
    scan_id: str | None,
    limit: int,
    min_risk: float,
    output_format: str,
) -> None:
    """List ranked exposure paths (MCP-compatible ExposurePath queue) for a scan."""

    client = _make_client(api_url, api_key, bearer_token, tenant_id)
    payload = _run_request(client, lambda api: api.exposure_paths(scan_id=scan_id, limit=limit, min_risk=min_risk))
    if output_format == "json":
        _emit_json(payload)
    else:
        _print_exposure_paths(payload)


__all__ = ["graph_paths_cmd"]
