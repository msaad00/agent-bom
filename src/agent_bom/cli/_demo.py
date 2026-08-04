"""Offline enterprise-demo story commands."""

from __future__ import annotations

from pathlib import Path

import click

from agent_bom.cli._grouped_help import SuggestingGroup
from agent_bom.demo_estate.presentation import EnterpriseDemoStory, build_enterprise_demo_story


def _render_story(story: EnterpriseDemoStory) -> str:
    primary = story.primary_correlation
    sources = " → ".join(source.value.replace("_", " ") for source in primary.sources)
    asset_path = "\n    → ".join(primary.asset_path)
    partial = [
        f"{row.source.value} ({row.failure_code})"
        for row in story.collection_health
        if row.status.value == "partial"
    ]
    return "\n".join(
        [
            f"{story.estate_name} — synthetic enterprise evidence",
            story.scenario,
            "",
            (
                f"Evidence: {story.summary.assets} assets · "
                f"{story.summary.observations} observations · "
                f"{story.summary.evidence_sources} sources · "
                f"{story.summary.correlations} correlations"
            ),
            f"Primary outcome: {primary.outcome.upper()} · {primary.kind.replace('_', ' ')}",
            f"Vendor path: {sources}",
            "Asset path:",
            f"    {asset_path}",
            f"Data classifications: {', '.join(primary.data_classifications) or 'none'}",
            f"Collection limits: {', '.join(partial) if partial else 'none'}",
            "",
            "Next: agent-bom serve --demo-estate --allow-insecure-no-auth",
            "Then open: http://127.0.0.1:8000/demo-estate",
        ]
    )


@click.group("demo", cls=SuggestingGroup, invoke_without_command=True)
@click.pass_context
def demo_group(ctx: click.Context) -> None:
    """Inspect the bundled, explicitly synthetic enterprise estate."""

    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@click.command("story")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["table", "json"], case_sensitive=False),
    default="table",
    show_default=True,
    help="Render a concise operator view or the complete normalized JSON evidence.",
)
@click.option(
    "--output",
    type=click.Path(path_type=Path, dir_okay=False, writable=True),
    help="Write the complete normalized JSON evidence artifact to this path.",
)
@click.option("--tenant-id", default="demo-tenant", show_default=True)
def demo_story_cmd(output_format: str, output: Path | None, tenant_id: str) -> None:
    """Show the correlated multi-vendor enterprise scenario without network access."""

    story = build_enterprise_demo_story(tenant_id=tenant_id)
    json_payload = story.model_dump_json(indent=2)
    if output is not None:
        output.write_text(f"{json_payload}\n", encoding="utf-8")

    if output_format.casefold() == "json":
        click.echo(json_payload)
    else:
        click.echo(_render_story(story))
        if output is not None:
            click.echo(f"Artifact: {output}")


demo_group.add_command(demo_story_cmd, "story")

__all__ = ["demo_group", "demo_story_cmd"]
