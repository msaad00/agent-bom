"""Quickstart lane for first-run onboarding."""

from __future__ import annotations

from pathlib import Path

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
@click.option("--force", is_flag=True, help="Overwrite files when used with --write-sample.")
def quickstart_cmd(dry_run: bool, offline: bool, sample_dir: Path, write_sample: bool, force: bool) -> None:
    """Print a local onboarding path for scan, API/UI, and sample data."""
    if dry_run and write_sample:
        raise click.UsageError("--dry-run cannot be combined with --write-sample.")

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
    click.echo("  agent-bom serve --host 127.0.0.1 --port 8422")
    click.echo("  API docs: http://127.0.0.1:8422/docs")
    click.echo("  UI:       http://127.0.0.1:8422/")
    click.echo("")
    click.echo("Everything in this lane can run locally. Use 'agent-bom[all]' for all first-run extras; MLflow remains separate.")


def _sample_scan_command(sample_dir: Path, *, offline: bool) -> str:
    command = f"agent-bom agents --inventory {sample_dir / 'inventory.json'} -p {sample_dir}"
    if offline:
        return f"{command} --offline"
    return f"{command} --enrich"
