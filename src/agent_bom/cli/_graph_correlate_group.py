"""CLI parity for immutable graph correlation runs."""

from __future__ import annotations

import time
import uuid
from collections.abc import Mapping

import click

from agent_bom.cli._findings_group import _common_api_options, _emit_json, _make_client, _run_request, _string
from agent_bom.client import AgentBomClient, JsonObject


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _sequence(value: object) -> list[object]:
    return list(value) if isinstance(value, list) else []


def _summary(run: Mapping[str, object]) -> list[str]:
    inputs = [item for item in _sequence(run.get("input_manifest")) if isinstance(item, Mapping)]
    freshness = "stale_allowed" if any(item.get("freshness") == "stale_allowed" for item in inputs) else "fresh"
    result = _mapping(run.get("result_manifest"))
    merge = _mapping(result.get("correlation_merge"))
    output = _mapping(result.get("output"))
    analysis = _mapping(result.get("analysis"))
    bounds = _mapping(result.get("analysis_bounds"))
    limitations = _sequence(analysis.get("limitations"))
    if not limitations:
        limitations = [name for name, value in bounds.items() if isinstance(value, Mapping) and value.get("truncated")]
    attack_paths = output.get("attack_path_count", analysis.get("attack_path_count", 0))
    exposure_paths = output.get("exposure_path_count", analysis.get("exposure_path_count", 0))
    receipt_verification = _mapping(run.get("receipt_verification"))
    return [
        _string(run.get("correlation_id")),
        _string(run.get("status")),
        str(len(inputs)),
        freshness,
        _string(receipt_verification.get("status") or "unknown"),
        _string(merge.get("conflict_count") or 0),
        _string(run.get("output_scan_id") or "-"),
        _string(attack_paths or 0),
        _string(exposure_paths or 0),
        ",".join(_string(item) for item in limitations) or "none",
    ]


def _print_runs(runs: list[Mapping[str, object]]) -> None:
    click.echo(
        "correlation_id\tstatus\tsources\tfreshness\treceipt_integrity\tconflicts\toutput_snapshot\tattack_paths\texposure_paths\tlimitations"
    )
    for run in runs:
        click.echo("\t".join(_summary(run)))


@click.group(name="graph-correlate")
def graph_correlate_cmd() -> None:
    """Correlate immutable scan snapshots into one evidence graph."""


@graph_correlate_cmd.command("create")
@click.option("--name", required=True, help="Human-readable correlation run name.")
@click.option("--scan-id", "scan_ids", multiple=True, required=True, help="Source snapshot id; repeat 2-32 times.")
@click.option("--max-age-hours", type=click.IntRange(1, 8760), required=True)
@click.option("--allow-stale", is_flag=True, help="Admit stale evidence while preserving its stale label.")
@click.option("--idempotency-key", default=None, help="Retry key; generated and returned by the API when omitted.")
@click.option("--wait", is_flag=True, help="Poll until the run completes or fails.")
@click.option("--wait-timeout", type=click.FloatRange(min=0.1, max=600.0), default=30.0, show_default=True)
@click.option("--format", "output_format", type=click.Choice(["table", "json"]), default="table", show_default=True)
@_common_api_options
def create_correlation_cmd(
    api_url: str | None,
    api_key: str | None,
    bearer_token: str | None,
    tenant_id: str | None,
    name: str,
    scan_ids: tuple[str, ...],
    max_age_hours: int,
    allow_stale: bool,
    idempotency_key: str | None,
    wait: bool,
    wait_timeout: float,
    output_format: str,
) -> None:
    """Create a correlation from 2-32 exact source snapshot ids."""

    if len(scan_ids) < 2 or len(set(scan_ids)) != len(scan_ids):
        raise click.UsageError("Provide between 2 and 32 distinct --scan-id values.")
    resolved_key = idempotency_key or str(uuid.uuid4())
    client = _make_client(api_url, api_key, bearer_token, tenant_id)

    def _request(api: AgentBomClient) -> JsonObject:
        run = api.create_graph_correlation(
            name=name,
            scan_ids=list(scan_ids),
            max_age_hours=max_age_hours,
            allow_stale=allow_stale,
            idempotency_key=resolved_key,
        )
        if not wait:
            return run
        correlation_id = _string(run.get("correlation_id"))
        deadline = time.monotonic() + wait_timeout
        while run.get("status") not in {"complete", "failed"}:
            if time.monotonic() >= deadline:
                raise click.ClickException(f"Timed out waiting for correlation {correlation_id}.")
            run = api.graph_correlation(correlation_id)
            if run.get("status") not in {"complete", "failed"}:
                time.sleep(0.25)
        return run

    payload = _run_request(client, _request)
    if output_format == "json":
        _emit_json(payload)
    else:
        _print_runs([payload])
    if payload.get("status") == "failed":
        raise click.ClickException(f"Correlation failed: {_string(payload.get('failure_code')) or 'unknown_failure'}")


@graph_correlate_cmd.command("status")
@click.argument("correlation_id")
@click.option("--format", "output_format", type=click.Choice(["table", "json"]), default="table", show_default=True)
@_common_api_options
def correlation_status_cmd(
    api_url: str | None,
    api_key: str | None,
    bearer_token: str | None,
    tenant_id: str | None,
    correlation_id: str,
    output_format: str,
) -> None:
    """Read one correlation run and its source receipts."""

    client = _make_client(api_url, api_key, bearer_token, tenant_id)
    payload = _run_request(client, lambda api: api.graph_correlation(correlation_id))
    if output_format == "json":
        _emit_json(payload)
    else:
        _print_runs([payload])


@graph_correlate_cmd.command("list")
@click.option("--limit", type=click.IntRange(1, 100), default=50, show_default=True)
@click.option("--format", "output_format", type=click.Choice(["table", "json"]), default="table", show_default=True)
@_common_api_options
def correlation_list_cmd(
    api_url: str | None,
    api_key: str | None,
    bearer_token: str | None,
    tenant_id: str | None,
    limit: int,
    output_format: str,
) -> None:
    """List recent correlation runs for the authenticated tenant."""

    client = _make_client(api_url, api_key, bearer_token, tenant_id)
    payload = _run_request(client, lambda api: api.list_graph_correlations(limit=limit))
    if output_format == "json":
        _emit_json(payload)
        return
    items = [item for item in _sequence(payload.get("items")) if isinstance(item, Mapping)]
    _print_runs(items)


__all__ = ["graph_correlate_cmd"]
