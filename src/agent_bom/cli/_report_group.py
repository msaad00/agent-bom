"""Report command group — history, diff, analytics, and dashboard helpers.

Usage::

    agent-bom report history             # list saved scan reports
    agent-bom report diff <a> <b>        # diff two scan reports or SBOMs
    agent-bom report rescan              # re-scan to verify remediation
    agent-bom report compliance-narrative report.json
    agent-bom report analytics           # query vulnerability trends
    agent-bom serve                      # launch bundled API + Next.js dashboard
    agent-bom report dashboard           # legacy Streamlit compatibility dashboard
"""

from __future__ import annotations

import json
from pathlib import Path

import click


@click.group("report", invoke_without_command=True)
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
