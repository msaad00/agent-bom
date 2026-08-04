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
    assert story.summary.assets == 20
    assert story.summary.observations == 15
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


def test_demo_story_api_fails_closed_when_demo_mode_is_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_BOM_DEMO_ESTATE", raising=False)
    request = SimpleNamespace(state=SimpleNamespace(tenant_id="tenant-api"))

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(get_enterprise_demo_story(request))  # type: ignore[arg-type]

    assert exc_info.value.status_code == 404
    assert exc_info.value.detail == "Demo estate is not enabled"
