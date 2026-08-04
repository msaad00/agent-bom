"""Offline enterprise-demo story commands."""

from __future__ import annotations

from pathlib import Path

import click

from agent_bom.cli._grouped_help import SuggestingGroup
from agent_bom.demo_estate.enterprise_findings import ESTATE_FINDING_SEVERITY_BUCKETS
from agent_bom.demo_estate.presentation import EnterpriseDemoStory, build_enterprise_demo_story

_SEVERITY_ORDER = ESTATE_FINDING_SEVERITY_BUCKETS
# Enough rows to show the incident and a little of the population around it.
# The summary above them always reports the whole estate, so this bound trims
# what is printed and never what is claimed.
_CLI_CHAIN_ROWS = 5
_CLI_CHAIN_CONTROLS = 4


def _render_story(story: EnterpriseDemoStory) -> str:
    primary = story.primary_correlation
    sources = " → ".join(source.value.replace("_", " ") for source in primary.sources)
    asset_path = "\n    → ".join(primary.asset_path)
    partial = [
        f"{row.source.value} ({row.failure_code})"
        for row in story.collection_health
        if row.status.value == "partial"
    ]
    posture = story.finding_summary
    severity = " · ".join(f"{band} {posture.by_severity[band]}" for band in _SEVERITY_ORDER)
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
            (
                f"Posture: {posture.total} findings on {posture.assets_affected} of "
                f"{posture.assets_total} assets · {posture.controls_evidenced} controls "
                f"across {len(posture.frameworks_evidenced)} frameworks"
            ),
            f"Severity: {severity}",
            f"Primary outcome: {primary.outcome.upper()} · {primary.kind.replace('_', ' ')}",
            f"Vendor path: {sources}",
            "Asset path:",
            f"    {asset_path}",
            f"Data classifications: {', '.join(primary.data_classifications) or 'none'}",
            f"Collection limits: {', '.join(partial) if partial else 'none'}",
            "",
            *_render_chain(story),
            "Next: agent-bom serve --demo-estate --allow-insecure-no-auth",
            "Then open: http://127.0.0.1:8000/demo-estate",
        ]
    )


def _render_chain(story: EnterpriseDemoStory) -> list[str]:
    """Show the top findings as chains, since the chain is the claim.

    A severity-sorted list of titles would say nothing a scanner cannot; what
    the product asserts is that each finding resolves to an asset, an identity,
    a configuration and a control, so print exactly that.
    """
    if not story.findings:
        return []
    rendered = story.findings[:_CLI_CHAIN_ROWS]
    # Count what is on screen, not the list it was sliced from. Reporting the
    # page's own size is fine; reporting a larger page's size as if it were on
    # screen is the same lie as reporting a page size as a total.
    lines = [f"Top findings ({len(rendered)} of {story.finding_summary.total} shown):"]
    for view in rendered:
        identity = view.identity_display_name or view.identity_actor_id or "—"
        lines.append(f"  [{view.severity}] {view.title}")
        lines.append(f"      asset    {view.asset_display_name} ({view.asset_id})")
        lines.append(f"      identity {identity}")
        lines.append(f"      config   {view.configuration_setting}: {view.configuration_observed} → expected {view.configuration_expected}")
        lines.append(f"      controls {', '.join(view.controls[:_CLI_CHAIN_CONTROLS]) or '—'}")
        if view.correlation_id:
            lines.append(f"      path     {' → '.join(view.attack_path)}")
    lines.append("")
    return lines


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
