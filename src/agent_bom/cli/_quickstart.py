"""Quickstart lane for first-run onboarding."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import TypedDict, cast

import click

from agent_bom.samples import write_first_run_sample

QUICKSTART_SCAN_TIMEOUT_SECONDS = 300
DURABLE_LOCAL_CONTROL_PLANE_DB = Path.home() / ".agent-bom" / "control-plane.db"


class _GraphReceipt(TypedDict):
    scan_id: str
    nodes: int
    edges: int


@click.command("quickstart")
@click.option("--dry-run", is_flag=True, help="Print the onboarding plan without writing files or starting services.")
@click.option(
    "--offline",
    is_flag=True,
    help="Avoid network calls; with --run, inventory and graph the sample without package-CVE lookup.",
)
@click.option(
    "--sample-dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path("agent-bom-first-run"),
    show_default=True,
    help="Directory used for the bundled sample stack.",
)
@click.option("--write-sample", is_flag=True, help="Write the bundled sample stack before printing next steps.")
@click.option("--force", is_flag=True, help="Overwrite files when used with --write-sample or --run.")
@click.option(
    "--run",
    "execute",
    is_flag=True,
    help="Execute the onboarding: write the sample stack, run a graph-persisting scan, and seed a baseline gateway policy.",
)
@click.option(
    "--gateway-policy/--no-gateway-policy",
    default=True,
    show_default=True,
    help="With --run, render the secure-by-default gateway baseline policy.",
)
@click.option(
    "--gateway-mode",
    type=click.Choice(["audit", "enforce"], case_sensitive=False),
    default="audit",
    show_default=True,
    help="Enforcement mode for the seeded gateway baseline policy (audit warns before enforcing).",
)
@click.option("--port", type=int, default=8422, show_default=True, help="Port suggested for the local API/UI handoff.")
def quickstart_cmd(
    dry_run: bool,
    offline: bool,
    sample_dir: Path,
    write_sample: bool,
    force: bool,
    execute: bool,
    gateway_policy: bool,
    gateway_mode: str,
    port: int,
) -> None:
    """Print — or with --run, execute — a local first-run onboarding path."""
    if dry_run and write_sample:
        raise click.UsageError("--dry-run cannot be combined with --write-sample.")
    if dry_run and execute:
        raise click.UsageError("--dry-run cannot be combined with --run.")

    if execute:
        _run_quickstart(
            sample_dir=sample_dir,
            offline=offline,
            force=force,
            gateway_policy=gateway_policy,
            gateway_mode=gateway_mode,
            port=port,
        )
        return

    if write_sample:
        try:
            written = write_first_run_sample(sample_dir, force=force)
        except FileExistsError as exc:
            raise click.ClickException(str(exc)) from exc
        click.echo(f"Wrote {len(written)} sample files to {sample_dir}")
        click.echo("")

    scan_command = _sample_scan_command(sample_dir, offline=offline)

    click.echo("agent-bom quickstart")
    click.echo("")
    click.echo("Local scan:")
    click.echo("  agent-bom scan --demo --offline")
    click.echo("")
    click.echo("Sample data:")
    if dry_run:
        click.echo(f"  agent-bom quickstart --write-sample --sample-dir {sample_dir}")
    else:
        click.echo(f"  agent-bom samples first-run --target {sample_dir}")
    click.echo(f"  {scan_command}")
    click.echo("")
    click.echo("Local API/UI:")
    click.echo("  pip install 'agent-bom[ui]'")
    click.echo(
        f"  AGENT_BOM_NO_AUTH_ROLE=analyst agent-bom serve --persist ~/.agent-bom/control-plane.db"
        f" --host 127.0.0.1 --port {port} --allow-insecure-no-auth"
    )
    click.echo("  # the explicit local analyst role permits scans in this loopback-only workflow;")
    click.echo("  # on a shared host use --api-key <key> or configure OIDC authentication instead.")
    click.echo(f"  API docs: http://127.0.0.1:{port}/docs")
    click.echo(f"  UI:       http://127.0.0.1:{port}/")
    click.echo("")
    click.echo("One command:")
    click.echo("  agent-bom quickstart --run        # writes sample, scans, seeds gateway policy")
    click.echo("")
    click.echo("Everything in this lane can run locally. Use 'agent-bom[all]' for all first-run extras; MLflow remains separate.")


def _run_quickstart(
    *,
    sample_dir: Path,
    offline: bool,
    force: bool,
    gateway_policy: bool,
    gateway_mode: str,
    port: int,
) -> None:
    """Execute the onboarding end to end so the local cockpit is populated on first run."""
    inventory_path = sample_dir / "inventory.json"

    # 1. Sample stack -------------------------------------------------------
    if inventory_path.exists() and not force:
        click.echo(f"[1/3] Using existing sample stack at {sample_dir} (pass --force to rewrite)")
    else:
        try:
            written = write_first_run_sample(sample_dir, force=force)
        except FileExistsError as exc:
            raise click.ClickException(str(exc)) from exc
        click.echo(f"[1/3] Wrote {len(written)} sample files to {sample_dir}")

    # 2. Graph-persisting scan ---------------------------------------------
    executable = _resolve_agent_bom()
    if executable is None:
        raise click.ClickException(
            "Could not locate the 'agent-bom' executable to run the scan. "
            f"Run it manually: {_sample_scan_command(sample_dir, offline=offline)}"
        )
    # --context-graph triggers persistence of the unified graph. Resolve both
    # database paths before launching the child process so the readback and the
    # printed control-plane command use the exact same configuration.
    scan_env = os.environ.copy()
    control_plane_db, graph_db = _resolve_quickstart_databases(scan_env)
    scan_env["AGENT_BOM_DB"] = str(control_plane_db)
    scan_env["AGENT_BOM_GRAPH_DB"] = str(graph_db)
    report_path = sample_dir / "agent-bom-report.json"
    scan_args = [
        executable,
        "agents",
        "--inventory",
        str(inventory_path),
        "-p",
        str(sample_dir),
        "--context-graph",
        # The sample is intentionally vulnerable. A severity verdict is still
        # useful completed evidence and must not abort policy/UI onboarding;
        # --exit-zero does not suppress incomplete, malicious, or policy exits.
        "--exit-zero",
        "-o",
        str(report_path),
    ]
    if offline:
        # A fresh install has no local vulnerability database. Keep the
        # one-command onboarding deterministic and honest: inventory packages,
        # analyze/persist the graph, and leave package-CVE proof to the bundled
        # `scan --demo --offline` lane printed by the quickstart.
        scan_args.extend(["--offline", "--no-scan"])
        click.echo("[2/3] Offline first-run skips package-CVE lookup; run `agent-bom scan --demo --offline` for bundled CVE proof.")
    else:
        scan_args.append("--enrich")
    click.echo(f"[2/3] Scanning sample stack: {' '.join(scan_args[1:])}")
    scan_started_at = datetime.now(timezone.utc)
    result = subprocess.run(  # noqa: S603 - args built from validated inputs
        scan_args,
        check=False,
        env=scan_env,
        timeout=QUICKSTART_SCAN_TIMEOUT_SECONDS,
    )
    if result.returncode != 0:
        raise click.ClickException(f"Scan exited with status {result.returncode}. The cockpit graph may be incomplete.")
    graph_receipt = _verify_persisted_graph(
        report_path=report_path,
        graph_db=graph_db,
        scan_started_at=scan_started_at,
    )
    click.echo(
        f"      Verified persisted graph: {graph_receipt['nodes']} nodes, "
        f"{graph_receipt['edges']} edges (scan {graph_receipt['scan_id'][:8]}…)"
    )

    # 3. Secure-by-default gateway policy ----------------------------------
    policy_path: Path | None = None
    if gateway_policy:
        policy_path = sample_dir / "gateway-baseline-policy.json"
        _write_gateway_baseline(policy_path, mode=gateway_mode)
        click.echo(f"[3/3] Seeded gateway baseline policy ({gateway_mode}) at {policy_path}")
    else:
        click.echo("[3/3] Skipped gateway baseline policy (--no-gateway-policy)")

    # Handoff ---------------------------------------------------------------
    click.echo("")
    click.echo("Onboarding complete. The security graph was read back from the configured local database.")
    click.echo("")
    click.echo("Open the cockpit:")
    click.echo(f"  {_control_plane_command(control_plane_db=control_plane_db, graph_db=graph_db, port=port)}")
    click.echo("  # the explicit local analyst role permits scans in this loopback-only workflow;")
    click.echo("  # on a shared host use --api-key <key> or configure OIDC authentication instead.")
    click.echo(f"  Security graph: http://127.0.0.1:{port}/security-graph")
    click.echo(f"  Dashboard:      http://127.0.0.1:{port}/")
    if policy_path is not None:
        click.echo("")
        click.echo(f"Run the gateway baseline ({gateway_mode.lower()}):")
        click.echo(
            f"  agent-bom gateway serve --policy {shlex.quote(str(policy_path))} "
            f"--from-control-plane http://127.0.0.1:{port} --bind 127.0.0.1:8090"
        )


def _resolve_quickstart_databases(environment: dict[str, str]) -> tuple[Path, Path]:
    """Resolve the child scan and printed control-plane database paths."""

    control_plane_db = _durable_sqlite_path(environment.get("AGENT_BOM_DB") or str(DURABLE_LOCAL_CONTROL_PLANE_DB))
    graph_db = _durable_sqlite_path(environment.get("AGENT_BOM_GRAPH_DB") or str(control_plane_db))
    return control_plane_db, graph_db


def _durable_sqlite_path(value: str) -> Path:
    """Normalize one restart-safe local SQLite path for the quickstart."""

    raw = value.strip()
    if raw == ":memory:" or "://" in raw:
        raise click.ClickException(
            "agent-bom quickstart --run requires a durable local SQLite path in AGENT_BOM_DB and AGENT_BOM_GRAPH_DB."
        )
    return Path(raw).expanduser().resolve()


def _verify_persisted_graph(
    *,
    report_path: Path,
    graph_db: Path,
    scan_started_at: datetime,
) -> _GraphReceipt:
    """Read back the exact scan snapshot before claiming onboarding success."""

    try:
        payload = json.loads(report_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise click.ClickException("Persisted graph could not be verified because the scan report is unavailable.") from exc

    scan_run = payload.get("scan_run")
    scan_id = str(payload.get("scan_id") or (scan_run.get("scan_id") if isinstance(scan_run, dict) else "") or "")
    outcome = str(scan_run.get("outcome") or "") if isinstance(scan_run, dict) else ""
    if not scan_id or outcome != "complete" or not graph_db.is_file():
        raise click.ClickException("Persisted graph could not be verified in the configured graph database.")

    try:
        from agent_bom.cli._tenant import resolve_cli_tenant_id
        from agent_bom.db.graph_store import load_graph, open_graph_db

        with open_graph_db(graph_db) as connection:
            graph = load_graph(connection, tenant_id=resolve_cli_tenant_id(), scan_id=scan_id)
        created_at = datetime.fromisoformat(graph.created_at.replace("Z", "+00:00"))
    except Exception as exc:  # noqa: BLE001 - every storage/read/schema failure means verification failed
        raise click.ClickException("Persisted graph could not be verified in the configured graph database.") from exc

    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    if graph.scan_id != scan_id or not graph.nodes or not graph.edges or created_at < scan_started_at:
        raise click.ClickException("Persisted graph could not be verified in the configured graph database.")
    return {"scan_id": scan_id, "nodes": len(graph.nodes), "edges": len(graph.edges)}


def _control_plane_command(*, control_plane_db: Path, graph_db: Path, port: int) -> str:
    """Render a shell-safe command that opens the database just verified."""

    environment = []
    if graph_db != control_plane_db:
        environment.append(f"AGENT_BOM_GRAPH_DB={shlex.quote(str(graph_db))}")
    environment.append("AGENT_BOM_NO_AUTH_ROLE=analyst")
    persisted = (
        "~/.agent-bom/control-plane.db"
        if control_plane_db == DURABLE_LOCAL_CONTROL_PLANE_DB.expanduser().resolve()
        else shlex.quote(str(control_plane_db))
    )
    return f"{' '.join(environment)} agent-bom serve --persist {persisted} --host 127.0.0.1 --port {port} --allow-insecure-no-auth"


def _write_gateway_baseline(output_path: Path, *, mode: str) -> None:
    """Render the bundled secure-by-default gateway baseline policy to ``output_path``."""
    from agent_bom.gateway_policy_templates import (
        GatewayBaselineMode,
        render_gateway_baseline_policy,
    )

    rendered = render_gateway_baseline_policy(
        mode=cast(GatewayBaselineMode, mode.lower()),
        output_format="proxy",
        tenant_id="default",
    )
    output_path.write_text(json.dumps(rendered, indent=2) + "\n")


def _resolve_agent_bom() -> str | None:
    """Resolve the ``agent-bom`` console script, preferring the active interpreter's bin."""
    candidate = Path(sys.executable).with_name("agent-bom")
    if candidate.exists():
        return str(candidate)
    return shutil.which("agent-bom")


def _sample_scan_command(sample_dir: Path, *, offline: bool) -> str:
    command = f"agent-bom scan --inventory {sample_dir / 'inventory.json'} -p {sample_dir}"
    if offline:
        return f"{command} --offline"
    return f"{command} --enrich"
