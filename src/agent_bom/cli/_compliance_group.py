"""CLI command that RUNS a framework compliance evaluation (the CI-gate wedge).

Thin surface over ``GET /v1/compliance/{framework}``; the evaluator, control
logic, and ``no_data`` honesty guard all live in
``agent_bom.api.routes.compliance``. The CLI only renders the posture and maps
it to a process exit code so it can gate CI, mirroring ``agent-bom check``'s
``--exit-zero`` escape hatch.
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


def _print_posture(payload: Mapping[str, object]) -> None:
    framework = _string(payload.get("framework")) or "-"
    status = (_string(payload.get("status")) or "unknown").upper()
    score = payload.get("score")
    evaluated = payload.get("evaluated_controls")
    total = payload.get("total_controls")
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    score_text = f"{score}%" if isinstance(score, (int, float)) and status != "NO_DATA" else "—"
    click.echo(f"{framework}: {status}  score {score_text}  ({_string(evaluated)}/{_string(total)} controls evaluated)")
    if isinstance(summary, Mapping):
        click.echo(
            f"pass\twarning\tfail\n{_string(summary.get('pass'))}\t{_string(summary.get('warning'))}\t{_string(summary.get('fail'))}"
        )
    if status == "NO_DATA":
        click.echo("note: no completed scan evaluated this framework — posture is unknown, not a pass.")


@click.group(name="compliance")
def compliance_cmd() -> None:
    """Run framework compliance evaluations from the control plane."""


@compliance_cmd.command("eval")
@click.option("--framework", required=True, help="Framework slug to evaluate (e.g. soc2, cis, nist, owasp-llm, aisvs).")
@click.option(
    "--exit-zero",
    is_flag=True,
    help="Report posture without failing the process when the framework fails (CI escape hatch).",
)
@click.option("--format", "output_format", type=click.Choice(["table", "json"]), default="table", show_default=True)
@_common_api_options
def compliance_eval_cmd(
    api_url: str | None,
    api_key: str | None,
    bearer_token: str | None,
    tenant_id: str | None,
    framework: str,
    exit_zero: bool,
    output_format: str,
) -> None:
    """Evaluate a framework's pass/fail posture; exit non-zero on failure unless --exit-zero."""

    client = _make_client(api_url, api_key, bearer_token, tenant_id)
    payload = _run_request(client, lambda api: api.compliance_framework(framework))
    if output_format == "json":
        _emit_json(payload)
    else:
        _print_posture(payload)

    if _string(payload.get("status")) == "fail" and not exit_zero:
        raise SystemExit(1)


__all__ = ["compliance_cmd"]
