"""Sample project helpers for first-run onboarding."""

from __future__ import annotations

from pathlib import Path

import click

from agent_bom.samples import write_first_run_sample


@click.group(name="samples")
def samples_group() -> None:
    """Create bundled sample inputs for demos and first-run scans."""


@samples_group.command("first-run")
@click.option(
    "--output",
    "-o",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path("agent-bom-first-run"),
    show_default=True,
    help="Directory to write the sample project into.",
)
@click.option("--force", is_flag=True, help="Overwrite files in an existing sample directory.")
def first_run_sample(output: Path, force: bool) -> None:
    """Write an inspectable AI stack sample project."""
    try:
        written = write_first_run_sample(output, force=force)
    except FileExistsError as exc:
        raise click.ClickException(str(exc)) from exc

    click.echo(f"Wrote {len(written)} files to {output}")
    click.echo("")
    click.echo("Next:")
    click.echo(f"  agent-bom agents --inventory {output / 'inventory.json'} -p {output} --enrich")
