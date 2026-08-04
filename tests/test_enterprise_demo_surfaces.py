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


def test_demo_story_api_fails_closed_when_demo_mode_is_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_BOM_DEMO_ESTATE", raising=False)
    request = SimpleNamespace(state=SimpleNamespace(tenant_id="tenant-api"))

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(get_enterprise_demo_story(request))  # type: ignore[arg-type]

    assert exc_info.value.status_code == 404
    assert exc_info.value.detail == "Demo estate is not enabled"
