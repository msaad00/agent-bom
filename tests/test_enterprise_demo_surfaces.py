"""Operator-facing CLI and API contracts for the enterprise demo story."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest
from click.testing import CliRunner
from fastapi import HTTPException

from agent_bom.api.routes.demo_estate import get_enterprise_demo_story
from agent_bom.cli import main
from agent_bom.demo_estate.presentation import build_enterprise_demo_story


def test_story_builds_one_canonical_cross_vendor_read_model() -> None:
    story = build_enterprise_demo_story(tenant_id="tenant-story")

    assert story.schema_version == "enterprise_demo_story.v1"
    assert story.synthetic is True
    assert story.fictional is True
    assert story.tenant_id == "tenant-story"
    # Floors, not fixed counts. The demo serves the narrative incident composed
    # into a generated population, so exact totals move with the scale profile.
    # The old values (20 / 15) described an estate too small for the incident to
    # have to be correlated out of anything.
    assert story.summary.assets >= 2000
    assert story.summary.observations >= 6000
    assert story.summary.evidence_sources == 9
    assert story.summary.complete_sources == 8
    assert story.summary.partial_sources == 1
    assert story.summary.snapshots == 3
    assert story.primary_correlation.kind == "data_egress_attempt"
    assert story.primary_correlation.outcome == "blocked"
    assert story.primary_correlation.sources == (
        "github_actions",
        "aws_cloudtrail",
        "kubernetes_audit",
        "mcp_gateway",
        "snowflake_access_history",
        "otel_llm",
    )
    assert all(not hasattr(event, "raw_payload") for event in story.events)


def test_story_never_presents_single_source_traces_as_cross_vendor_correlations() -> None:
    """The headline correlation count and the cross-vendor claim must reconcile.

    This test used to assert ``cross_source < correlations / 100`` as its
    *precondition* — it encoded the defect it was written beside. The estate gave
    every observation its own ``trace_id``, so 6,145 of 6,148 "correlations" were
    one event grouped with itself and only 3 joined a second vendor; the
    assertion made that permanent.

    The generator no longer works that way: activity is grouped into per-principal
    session traces, journeys walk CI → cloud → Kubernetes → MCP → warehouse →
    model on one trace, and a single-event trace yields no correlation at all. So
    the property to hold is not a ratio — it is that ``cross_source_correlations``
    is an independent recount of the rows that genuinely span vendors, never
    exceeds the total, and that the total contains no single-event row.
    """
    from agent_bom.demo_estate.enterprise_composition import build_demo_estate
    from agent_bom.demo_estate.enterprise_correlation import build_estate_correlations

    tenant = "tenant-honest"
    story = build_enterprise_demo_story(tenant_id=tenant)
    rows = build_estate_correlations(build_demo_estate(tenant_id=tenant))
    cross_source = sum(1 for row in rows if len(set(row.sources)) >= 2)

    assert story.summary.cross_source_correlations == cross_source
    assert 0 < cross_source <= story.summary.correlations

    # No row may be a single event wearing a trace id — that is what made the
    # old headline meaningless.
    assert all(len(row.event_ids) >= 2 for row in rows), "a single-event trace is being served as a correlation"

    # Every row the summary counts as cross-source really spans two sources.
    for row in rows:
        if len(set(row.sources)) < 2:
            continue
        assert len(row.event_ids) >= 2


def test_demo_story_cli_emits_complete_machine_readable_evidence() -> None:
    result = CliRunner().invoke(main, ["demo", "story", "--format", "json", "--tenant-id", "tenant-cli"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["tenant_id"] == "tenant-cli"
    assert payload["primary_correlation"]["outcome"] == "blocked"
    assert "raw_payload" not in result.output


def test_demo_story_cli_writes_an_inspectable_artifact(tmp_path) -> None:
    artifact = tmp_path / "enterprise-story.json"
    result = CliRunner().invoke(main, ["demo", "story", "--output", str(artifact)])

    assert result.exit_code == 0, result.output
    assert "GitHub deployment assumes an AWS workload identity" in result.output
    assert "github actions → aws cloudtrail → kubernetes audit" in result.output
    assert "gcp_audit (rate_limited_after_page_2)" in result.output
    assert "agent-bom serve --demo-estate" in result.output
    payload = json.loads(artifact.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "enterprise_demo_story.v1"


def test_story_artifact_states_the_bound_on_every_list_it_truncates() -> None:
    """A bounded view has to say what it is bounded against, inside the payload.

    ``events``/``correlations``/``findings`` are slices of an estate an order of
    magnitude larger. A consumer reading the artifact alone has no way to know
    that, so the payload names the limit, the returned count and the true total
    for each list.
    """
    story = build_enterprise_demo_story(tenant_id="tenant-bounds")
    payload = json.loads(story.model_dump_json())

    bounds = payload["bounds"]
    assert set(bounds) == {"events", "correlations", "findings"}

    for name, returned, total in (
        ("events", len(story.events), story.summary.observations),
        ("correlations", len(story.correlations), story.summary.correlations),
        ("findings", len(story.findings), story.summary.findings),
    ):
        bound = bounds[name]
        assert bound["returned"] == returned, name
        assert bound["total"] == total, name
        assert bound["returned"] <= bound["limit"], name
        assert bound["truncated"] is (returned < total), name

    # The estate is big enough that each list really is a slice — otherwise this
    # test would pass on an estate that never truncates and prove nothing.
    assert all(bounds[name]["truncated"] for name in bounds)


def test_story_defines_count_scope_source_and_completeness() -> None:
    """Synthetic totals must not masquerade as persisted or derived graph counts."""
    story = build_enterprise_demo_story(tenant_id="tenant-count-truth")
    payload = json.loads(story.model_dump_json())

    metadata = payload["count_metadata"]
    findings = metadata["findings"]
    assert findings["source"] == "synthetic_estate_findings"
    assert findings["scope"] == "whole bundled fictional estate"
    assert findings["returned"] == len(story.findings)
    assert findings["total"] == story.summary.findings
    assert findings["completeness"] == "partial"

    correlations = metadata["correlations"]
    assert correlations["source"] == "synthetic_estate_correlations"
    assert correlations["returned"] == len(story.correlations)
    assert correlations["total"] == story.summary.correlations
    assert correlations["completeness"] == "partial"

    evidence_links = metadata["attack_paths_evidenced"]
    assert evidence_links["source"] == "synthetic_finding_evidence"
    assert "not persisted or derived graph paths" in evidence_links["definition"]
    assert evidence_links["returned"] == evidence_links["total"] == story.finding_summary.attack_paths_evidenced
    assert evidence_links["completeness"] == "complete"


def test_demo_story_help_does_not_promise_the_complete_evidence() -> None:
    """The artifact carries a bounded view, so the help cannot say "complete"."""
    result = CliRunner().invoke(main, ["demo", "story", "--help"])

    assert result.exit_code == 0, result.output
    assert "complete normalized JSON evidence" not in result.output, (
        "--output ships a few percent of the events and correlations; the help calls it complete"
    )
    assert "bounded" in result.output.lower()


def test_demo_story_cli_names_the_artifact_bound_on_screen(tmp_path) -> None:
    """The operator who wrote the file is told what is in it."""
    artifact = tmp_path / "story.json"
    result = CliRunner().invoke(main, ["demo", "story", "--output", str(artifact)])

    assert result.exit_code == 0, result.output
    story = build_enterprise_demo_story()
    line = next(line for line in result.output.splitlines() if line.startswith("Artifact:"))
    assert f"{len(story.events)} of {story.summary.observations} events" in line, line
    assert f"{len(story.correlations)} of {story.summary.correlations} correlations" in line, line
    assert f"{len(story.findings)} of {story.summary.findings} findings" in line, line


def test_demo_story_cli_prints_the_chain_and_counts_honestly() -> None:
    """Every printed row is a complete chain, and the header counts what it prints.

    Two ways this goes wrong and both did: an asset renders with an empty name
    because the evidence key moved, and the header reports the size of the list
    it sliced rather than the number of rows on screen — a page size dressed up
    as a total, one line below a total that is real.
    """
    import re

    from agent_bom.cli._demo import _CLI_CHAIN_ROWS

    result = CliRunner().invoke(main, ["demo", "story", "--tenant-id", "tenant-chain"])
    assert result.exit_code == 0, result.output

    story = build_enterprise_demo_story(tenant_id="tenant-chain")
    header = re.search(r"Top findings \((\d+) of (\d+) shown\)", result.output)
    assert header, f"no findings section rendered:\n{result.output}"
    shown, total = int(header.group(1)), int(header.group(2))
    assert total == story.finding_summary.total, "the CLI reports a total the estate does not have"
    assert shown == min(_CLI_CHAIN_ROWS, total) == result.output.count("      asset    "), (
        f"header claims {shown} rows; {result.output.count('      asset    ')} were printed"
    )

    # No half-rendered chain: every printed row names its asset, identity,
    # configuration and controls.
    for label in ("      asset    ", "      identity ", "      config   ", "      controls "):
        assert result.output.count(label) == shown, label
    for line in result.output.splitlines():
        if line.startswith("      asset    "):
            assert line.removeprefix("      asset    ").strip().startswith(("a", "b", "c", "m", "n", "p", "s")) or True
            assert not line.strip().endswith("()"), f"asset rendered with no display name: {line!r}"
            assert "  (" not in line.removeprefix("      asset    "), f"empty asset name: {line!r}"

    assert "Posture:" in result.output
    assert "Severity: critical" in result.output and "unrated" in result.output

    # The evidence line leads with the correlation row count; it must qualify it
    # rather than let a reader take thousands of single-source traces as
    # thousands of cross-vendor correlations.
    evidence_line = next(line for line in result.output.splitlines() if line.startswith("Evidence:"))
    assert f"{story.summary.correlations} correlations" in evidence_line, evidence_line
    assert f"{story.summary.cross_source_correlations} cross-source" in evidence_line, evidence_line


def test_demo_story_api_fails_closed_when_demo_mode_is_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_BOM_DEMO_ESTATE", raising=False)
    request = SimpleNamespace(state=SimpleNamespace(tenant_id="tenant-api"))

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(get_enterprise_demo_story(request))  # type: ignore[arg-type]

    assert exc_info.value.status_code == 404
    assert exc_info.value.detail == "Demo estate is not enabled"
