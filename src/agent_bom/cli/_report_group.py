"""Report command group — history, diff, analytics, and dashboard helpers.

Usage::

    agent-bom report history             # list saved scan reports
    agent-bom report diff <a> <b>        # diff two scan reports or SBOMs
    agent-bom report rescan              # re-scan to verify remediation
    agent-bom report compliance-narrative report.json
    agent-bom report query "SELECT ..."  # query the local scan analytics store
    agent-bom report storage              # inspect local mirror size and retention
    agent-bom report prune                # plan or apply bounded whole-run pruning
    agent-bom report analytics           # query vulnerability trends
    agent-bom serve                      # launch bundled API + Next.js dashboard
    agent-bom report dashboard           # legacy Streamlit compatibility dashboard
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click

from agent_bom.cli._grouped_help import SuggestingGroup


@click.group("report", cls=SuggestingGroup, invoke_without_command=True)
@click.pass_context
def report_group(ctx: click.Context) -> None:
    """Reports — history, diff, analytics, and dashboard helpers.

    \b
    Subcommands:
      history     List saved scan reports
      diff        Diff two scan reports or CycloneDX/SPDX SBOMs
      rescan      Re-scan vulnerable packages to verify remediation
      compliance-narrative  Generate auditor-facing compliance narrative from a saved scan report
      pipeline-events  Export scan pipeline DAG events as JSONL
      query       Run read-only SQL against the local scan analytics store
      storage     Inspect local scan mirror size, rows, and retention caps
      prune       Plan or apply whole-run pruning; optionally compact SQLite
      analytics   Query vulnerability trends (ClickHouse)
      dashboard   Launch legacy Streamlit compatibility dashboard; use `agent-bom serve` for the bundled Next.js UI
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@click.command("pipeline-events")
@click.argument("scan_job_json", type=click.Path(exists=True, dir_okay=False, readable=True))
@click.option("-o", "--output", "output_path", type=click.Path(dir_okay=False), help="Write JSONL artifact to this file")
def pipeline_events_cmd(scan_job_json: str, output_path: str | None) -> None:
    """Export structured scan pipeline progress as dashboard-ready JSONL."""
    from agent_bom.api.models import ScanJob
    from agent_bom.api.pipeline import pipeline_dag_events_jsonl

    path = Path(scan_job_json)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        job = ScanJob.model_validate(payload)
    except Exception as exc:  # noqa: BLE001
        raise click.ClickException(f"Could not read ScanJob JSON from {path}: {exc}") from exc

    jsonl = pipeline_dag_events_jsonl(job)
    if output_path:
        output = Path(output_path)
        output.write_text(f"{jsonl}\n" if jsonl else "", encoding="utf-8")
        click.echo(f"Wrote {output}")
        return
    if jsonl:
        click.echo(jsonl)


@click.command("query")
@click.argument("sql")
@click.option(
    "--db",
    "db_path",
    type=click.Path(dir_okay=False, path_type=Path),
    help="Local analytics database path. Defaults to AGENT_BOM_LOCAL_ANALYTICS_DB or ~/.agent-bom/local-analytics.sqlite.",
)
@click.option("--format", "output_format", type=click.Choice(["table", "json"]), default="table", show_default=True)
def local_query_cmd(sql: str, db_path: Path | None, output_format: str) -> None:
    """Run read-only SQL against the local scan analytics store."""
    from agent_bom.db.local_analytics import LocalAnalyticsStore, local_analytics_path

    resolved_db = db_path or local_analytics_path()
    store = LocalAnalyticsStore(resolved_db)
    try:
        rows = store.query(sql)
    except Exception as exc:  # noqa: BLE001
        raise click.ClickException(f"Could not query local analytics store: {exc}") from exc

    if output_format == "json":
        click.echo(json.dumps({"db_path": str(resolved_db), "count": len(rows), "rows": rows}, indent=2))
        return

    _echo_rows_as_table(rows)


def _analytics_db_option(function):
    return click.option(
        "--db",
        "db_path",
        type=click.Path(dir_okay=False, path_type=Path),
        help="Local analytics database path. Defaults to AGENT_BOM_LOCAL_ANALYTICS_DB or ~/.agent-bom/local-analytics.sqlite.",
    )(function)


@click.command("storage")
@_analytics_db_option
@click.option("--format", "output_format", type=click.Choice(["table", "json"]), default="table", show_default=True)
def local_storage_cmd(db_path: Path | None, output_format: str) -> None:
    """Inspect local scan mirror size, row counts, and configured caps."""
    from agent_bom.db.local_analytics import LocalAnalyticsStore, local_analytics_path

    resolved_db = db_path or local_analytics_path()
    stats = LocalAnalyticsStore(resolved_db).storage_stats()
    if output_format == "json":
        click.echo(json.dumps(stats, indent=2))
        return
    rows = [
        {"metric": "database bytes", "current": stats["bytes"], "limit": ""},
        {"metric": "scan runs", "current": stats["scan_runs"], "limit": stats["limits"]["scan_runs"]},
        {"metric": "findings", "current": stats["findings"], "limit": stats["limits"]["findings"]},
        {"metric": "packages", "current": stats["packages"], "limit": stats["limits"]["packages"]},
    ]
    click.echo(f"Local analytics: {stats['db_path']}")
    _echo_rows_as_table(rows)
    if stats["over_limit"]:
        click.echo("Retention limit exceeded; run `agent-bom report prune` to preview cleanup.")


@click.command("prune")
@_analytics_db_option
@click.option("--max-runs", type=click.IntRange(min=0), default=None, help="Override the retained scan-run cap.")
@click.option("--max-packages", type=click.IntRange(min=0), default=None, help="Override the retained package-row cap.")
@click.option("--max-findings", type=click.IntRange(min=0), default=None, help="Override the retained finding-row cap.")
@click.option("--apply", "apply_changes", is_flag=True, help="Apply the previewed whole-run deletions.")
@click.option("--compact", is_flag=True, help="Run SQLite VACUUM after applying deletions; may require temporary disk space.")
@click.option("--format", "output_format", type=click.Choice(["table", "json"]), default="table", show_default=True)
def local_prune_cmd(
    db_path: Path | None,
    max_runs: int | None,
    max_packages: int | None,
    max_findings: int | None,
    apply_changes: bool,
    compact: bool,
    output_format: str,
) -> None:
    """Preview local mirror pruning; pass --apply to delete whole old runs."""
    from agent_bom.db.local_analytics import LocalAnalyticsStore, local_analytics_path

    if compact and not apply_changes:
        raise click.UsageError("--compact requires --apply")
    resolved_db = db_path or local_analytics_path()
    result = LocalAnalyticsStore(resolved_db).prune(
        max_runs=max_runs,
        max_packages=max_packages,
        max_findings=max_findings,
        apply=apply_changes,
        compact=compact,
    )
    if output_format == "json":
        click.echo(json.dumps(result, indent=2))
        return
    action = "Applied" if apply_changes else "Dry run"
    click.echo(f"{action}: {result['deleted_runs']} old scan run(s) selected from {result['db_path']}")
    click.echo(f"Storage: {result['bytes_before']} -> {result['bytes_after']} bytes")
    if not apply_changes and result["deleted_runs"]:
        click.echo("Re-run with --apply to delete the selected runs.")


def _echo_rows_as_table(rows: list[dict[str, Any]]) -> None:
    if not rows:
        click.echo("No rows.")
        return

    columns = list(rows[0].keys())
    widths = {column: max(len(column), *(len(_stringify(row.get(column))) for row in rows)) for column in columns}
    header = "  ".join(column.ljust(widths[column]) for column in columns)
    divider = "  ".join("-" * widths[column] for column in columns)
    click.echo(header)
    click.echo(divider)
    for row in rows:
        click.echo("  ".join(_stringify(row.get(column)).ljust(widths[column]) for column in columns))


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    return str(value)
