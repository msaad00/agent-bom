"""Quickstart lane for first-run onboarding."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import cast

import click

from agent_bom.samples import write_first_run_sample


@click.command("quickstart")
@click.option("--dry-run", is_flag=True, help="Print the onboarding plan without writing files or starting services.")
@click.option("--offline", is_flag=True, help="Show commands that avoid network enrichment and remote advisory calls.")
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
    click.echo("  agent-bom agents --demo --offline")
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
    click.echo(f"  agent-bom serve --host 127.0.0.1 --port {port}")
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
    # --context-graph triggers persistence of the unified graph to the local
    # control-plane store (~/.agent-bom/db/graph.db) that `agent-bom serve` reads,
    # so the security-graph cockpit is populated on first run.
    scan_args = [executable, "agents", "--inventory", str(inventory_path), "-p", str(sample_dir), "--context-graph"]
    scan_args.append("--offline" if offline else "--enrich")
    click.echo(f"[2/3] Scanning sample stack: {' '.join(scan_args[1:])}")
    result = subprocess.run(scan_args, check=False)  # noqa: S603 - args built from validated inputs
    if result.returncode != 0:
        raise click.ClickException(f"Scan exited with status {result.returncode}. The cockpit graph may be incomplete.")

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
    click.echo("Onboarding complete. The security graph is now populated locally.")
    click.echo("")
    click.echo("Open the cockpit:")
    click.echo(f"  agent-bom serve --host 127.0.0.1 --port {port}")
    click.echo(f"  Security graph: http://127.0.0.1:{port}/security-graph")
    click.echo(f"  Dashboard:      http://127.0.0.1:{port}/")
    if policy_path is not None:
        click.echo("")
        click.echo("Enforce the gateway baseline:")
        click.echo(f"  agent-bom gateway serve --policy {policy_path} --upstreams upstreams.yaml")


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
    command = f"agent-bom agents --inventory {sample_dir / 'inventory.json'} -p {sample_dir}"
    if offline:
        return f"{command} --offline"
    return f"{command} --enrich"
