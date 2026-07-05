"""CLI commands for findings and triage workflows."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import click

from agent_bom.client import AgentBomApiError, AgentBomClient, JsonObject


def _make_client(api_url: str | None, api_key: str | None, bearer_token: str | None, tenant_id: str | None) -> AgentBomClient:
    base_url = api_url or os.getenv("AGENT_BOM_API_URL") or "http://127.0.0.1:8422"
    resolved_api_key = api_key or os.getenv("AGENT_BOM_API_KEY")
    resolved_bearer_token = bearer_token or os.getenv("AGENT_BOM_API_TOKEN")
    resolved_tenant_id = tenant_id or os.getenv("AGENT_BOM_TENANT_ID")
    return AgentBomClient(
        base_url=base_url,
        api_key=resolved_api_key,
        bearer_token=resolved_bearer_token,
        tenant_id=resolved_tenant_id,
    )


def _common_api_options(fn: Any) -> Any:
    fn = click.option("--tenant", "tenant_id", envvar="AGENT_BOM_TENANT_ID", help="Tenant id for the request.")(fn)
    fn = click.option("--bearer-token", envvar="AGENT_BOM_API_TOKEN", help="Bearer token for the API.")(fn)
    fn = click.option("--api-key", envvar="AGENT_BOM_API_KEY", help="API key for the API.")(fn)
    fn = click.option("--api-url", envvar="AGENT_BOM_API_URL", help="agent-bom API base URL.")(fn)
    return fn


def _emit_json(payload: JsonObject, *, output: Path | None = None) -> None:
    rendered = json.dumps(payload, indent=2, sort_keys=True)
    if output is not None:
        output.write_text(rendered + "\n", encoding="utf-8")
        click.echo(f"Wrote {output}")
        return
    click.echo(rendered)


def _string(value: object) -> str:
    if value is None:
        return ""
    return str(value)


def _finding_id(row: Mapping[str, object]) -> str:
    for key in ("finding_id", "id", "vulnerability_id", "cve", "advisory_id"):
        value = row.get(key)
        if value:
            return str(value)
    return "-"


def _package_name(row: Mapping[str, object]) -> str:
    value = row.get("package") or row.get("package_name") or row.get("component")
    if isinstance(value, dict):
        return _string(value.get("name") or value.get("purl"))
    return _string(value)


def _print_findings_table(payload: JsonObject) -> None:
    rows = payload.get("findings")
    if not isinstance(rows, list):
        rows = []
    click.echo("id\tseverity\tstatus\tpackage\tfirst_seen\tlast_seen\ttitle")
    for item in rows:
        if not isinstance(item, dict):
            continue
        click.echo(
            "\t".join(
                [
                    _finding_id(item),
                    _string(item.get("severity")),
                    _string(item.get("status")),
                    _package_name(item),
                    _string(item.get("first_seen")),
                    _string(item.get("last_seen")),
                    _string(item.get("title") or item.get("summary") or item.get("message")),
                ]
            )
        )


def _print_triage_table(payload: JsonObject) -> None:
    rows = payload.get("triage")
    if not isinstance(rows, list):
        rows = []
    click.echo("id\tvulnerability\tpackage\tstate\tdecision\tassignee")
    for item in rows:
        if not isinstance(item, dict):
            continue
        click.echo(
            "\t".join(
                [
                    _string(item.get("id") or item.get("triage_id")),
                    _string(item.get("vulnerability_id")),
                    _string(item.get("package")),
                    _string(item.get("queue_state")),
                    _string(item.get("decision")),
                    _string(item.get("assignee")),
                ]
            )
        )


def _run_request(client: AgentBomClient, callback: Any) -> JsonObject:
    try:
        return callback(client)
    except AgentBomApiError as exc:
        raise click.ClickException(f"API request failed with {exc.status_code}: {exc.body[:500]}") from exc
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        client.close()


@click.group(name="findings")
def findings_cmd() -> None:
    """Inspect and triage normalized findings from the control plane."""


@findings_cmd.command("push")
@click.argument("input_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--source", default="external_scan", show_default=True, help="Source label stored on ingested findings.")
@click.option("--reconcile", "reconcile_absent", is_flag=True, help="Mark findings absent from this batch as resolved.")
@click.option("--observed-at", help="ISO-8601 observation timestamp for the batch.")
@click.option("--idempotency-key", help="Optional Idempotency-Key header for safe retries.")
@click.option("--format", "output_format", type=click.Choice(["json"]), default="json", show_default=True)
@_common_api_options
def push_findings_cmd(
    api_url: str | None,
    api_key: str | None,
    bearer_token: str | None,
    tenant_id: str | None,
    input_path: Path,
    source: str,
    reconcile_absent: bool,
    observed_at: str | None,
    idempotency_key: str | None,
    output_format: str,
) -> None:
    """Push normalized findings or external scanner JSON to the control plane."""

    from agent_bom.findings_push import load_push_findings_file

    findings = load_push_findings_file(input_path, source=source)
    client = _make_client(api_url, api_key, bearer_token, tenant_id)
    payload = _run_request(
        client,
        lambda api: api.ingest_findings(
            findings,
            source=source,
            observed_at=observed_at,
            reconcile_absent=reconcile_absent,
            idempotency_key=idempotency_key,
        ),
    )
    if output_format == "json":
        _emit_json(payload)


@findings_cmd.command("list")
@click.option("--severity", help="Filter findings by severity.")
@click.option("--sort", default="effective_reach", show_default=True, help="Sort field used by the API.")
@click.option("--limit", default=500, show_default=True, type=click.IntRange(min=1, max=1000), help="Maximum rows to return.")
@click.option("--offset", default=0, show_default=True, type=click.IntRange(min=0), help="Rows to skip.")
@click.option("--format", "output_format", type=click.Choice(["table", "json"]), default="table", show_default=True)
@_common_api_options
def list_findings_cmd(
    api_url: str | None,
    api_key: str | None,
    bearer_token: str | None,
    tenant_id: str | None,
    severity: str | None,
    sort: str,
    limit: int,
    offset: int,
    output_format: str,
) -> None:
    """List findings with the same filters as the REST API."""

    client = _make_client(api_url, api_key, bearer_token, tenant_id)
    payload = _run_request(client, lambda api: api.list_findings(severity=severity, sort=sort, limit=limit, offset=offset))
    if output_format == "json":
        _emit_json(payload)
    else:
        _print_findings_table(payload)


@findings_cmd.group("triage")
def triage_group() -> None:
    """Manage finding triage decisions and OpenVEX export."""


@triage_group.command("list")
@click.option("--queue-state", help="Filter by triage queue state.")
@click.option("--decision", help="Filter by triage decision.")
@click.option("--limit", default=1000, show_default=True, type=click.IntRange(min=1, max=1000), help="Maximum rows to return.")
@click.option("--offset", default=0, show_default=True, type=click.IntRange(min=0), help="Rows to skip.")
@click.option("--format", "output_format", type=click.Choice(["table", "json"]), default="table", show_default=True)
@_common_api_options
def list_triage_cmd(
    api_url: str | None,
    api_key: str | None,
    bearer_token: str | None,
    tenant_id: str | None,
    queue_state: str | None,
    decision: str | None,
    limit: int,
    offset: int,
    output_format: str,
) -> None:
    """List finding triage queue items."""

    client = _make_client(api_url, api_key, bearer_token, tenant_id)
    payload = _run_request(
        client,
        lambda api: api.list_finding_triage(queue_state=queue_state, decision=decision, limit=limit, offset=offset),
    )
    if output_format == "json":
        _emit_json(payload)
    else:
        _print_triage_table(payload)


@triage_group.command("create")
@click.argument("vulnerability_id")
@click.option("--package", "package_name", default="*", show_default=True, help="Affected package or product.")
@click.option("--server-name", default="", help="MCP server or asset scope for the item.")
@click.option("--assignee", default="", help="User or team assigned to review the item.")
@click.option("--queue-state", default="open", show_default=True, help="Initial queue state.")
@click.option("--decision", default="under_investigation", show_default=True, help="Initial decision.")
@click.option("--justification", help="OpenVEX justification when applicable.")
@click.option("--reason", "decision_reason", default="", help="Human-readable decision reason.")
@click.option("--expires-at", default="", help="Optional ISO-8601 expiry timestamp.")
@click.option("--format", "output_format", type=click.Choice(["json"]), default="json", show_default=True)
@_common_api_options
def create_triage_cmd(
    api_url: str | None,
    api_key: str | None,
    bearer_token: str | None,
    tenant_id: str | None,
    vulnerability_id: str,
    package_name: str,
    server_name: str,
    assignee: str,
    queue_state: str,
    decision: str,
    justification: str | None,
    decision_reason: str,
    expires_at: str,
    output_format: str,
) -> None:
    """Create a finding triage queue item."""

    client = _make_client(api_url, api_key, bearer_token, tenant_id)
    payload = _run_request(
        client,
        lambda api: api.create_finding_triage(
            vulnerability_id,
            package=package_name,
            server_name=server_name,
            assignee=assignee,
            queue_state=queue_state,
            decision=decision,
            justification=justification,
            decision_reason=decision_reason,
            expires_at=expires_at,
        ),
    )
    if output_format == "json":
        _emit_json(payload)


@triage_group.command("decide")
@click.argument("triage_id")
@click.option("--decision", required=True, help="Final triage decision.")
@click.option("--justification", help="OpenVEX justification when applicable.")
@click.option("--reason", "decision_reason", default="", help="Human-readable decision reason.")
@click.option("--assignee", help="Reviewer recorded on the decision.")
@click.option("--expires-at", help="Optional ISO-8601 expiry timestamp.")
@click.option("--format", "output_format", type=click.Choice(["json"]), default="json", show_default=True)
@_common_api_options
def decide_triage_cmd(
    api_url: str | None,
    api_key: str | None,
    bearer_token: str | None,
    tenant_id: str | None,
    triage_id: str,
    decision: str,
    justification: str | None,
    decision_reason: str,
    assignee: str | None,
    expires_at: str | None,
    output_format: str,
) -> None:
    """Record a decision for a finding triage queue item."""

    client = _make_client(api_url, api_key, bearer_token, tenant_id)
    payload = _run_request(
        client,
        lambda api: api.update_finding_triage_decision(
            triage_id,
            decision=decision,
            justification=justification,
            decision_reason=decision_reason,
            assignee=assignee,
            expires_at=expires_at,
        ),
    )
    if output_format == "json":
        _emit_json(payload)


@triage_group.command("export-vex")
@click.option("-o", "--output", type=click.Path(dir_okay=False, path_type=Path), help="Write the signed OpenVEX envelope to a file.")
@click.option("--format", "output_format", type=click.Choice(["json"]), default="json", show_default=True)
@_common_api_options
def export_triage_vex_cmd(
    api_url: str | None,
    api_key: str | None,
    bearer_token: str | None,
    tenant_id: str | None,
    output: Path | None,
    output_format: str,
) -> None:
    """Export signed OpenVEX for eligible not_affected decisions."""

    client = _make_client(api_url, api_key, bearer_token, tenant_id)
    payload = _run_request(client, lambda api: api.export_finding_triage_vex())
    if output_format == "json":
        _emit_json(payload, output=output)


__all__ = ["findings_cmd"]
