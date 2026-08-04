#!/usr/bin/env python3
"""Fail when the versioned synthetic enterprise story drifts across surfaces."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent_bom.cli import main
from agent_bom.demo_estate.presentation import build_enterprise_demo_story

REPO_ROOT = Path(__file__).resolve().parent.parent
EXPECTED_FIXTURES = {
    "enterprise_observations.jsonl",
}
EXPECTED_PRIMARY_SOURCES = (
    "github_actions",
    "aws_cloudtrail",
    "kubernetes_audit",
    "mcp_gateway",
    "snowflake_access_history",
    "otel_llm",
)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"enterprise demo surface drift: {message}")


def _contains_key(value: Any, key: str) -> bool:
    if isinstance(value, dict):
        return key in value or any(_contains_key(child, key) for child in value.values())
    if isinstance(value, list):
        return any(_contains_key(child, key) for child in value)
    return False


def _read(relative_path: str) -> str:
    path = REPO_ROOT / relative_path
    _require(path.is_file(), f"missing {relative_path}")
    return path.read_text(encoding="utf-8")


def main_check() -> None:
    story = build_enterprise_demo_story(tenant_id="contract-tenant")
    payload = story.model_dump(mode="json")

    _require(story.schema_version == "enterprise_demo_story.v1", "story schema version changed")
    _require(story.synthetic is True and story.fictional is True, "synthetic disclosure flags missing")
    _require(story.tenant_id == "contract-tenant", "tenant ID was not propagated")
    _require(story.summary.assets == 20, "asset count changed")
    _require(story.summary.observations == 15, "observation count changed")
    _require(story.summary.evidence_sources == 9, "evidence-source count changed")
    _require(story.summary.correlations == 4, "correlation count changed")
    _require(story.summary.snapshots == 3, "snapshot count changed")
    _require(story.primary_correlation.outcome == "blocked", "primary outcome is no longer blocked")
    _require(
        tuple(source.value for source in story.primary_correlation.sources)
        == EXPECTED_PRIMARY_SOURCES,
        "primary cross-vendor path changed",
    )
    gcp = next((row for row in story.collection_health if row.source.value == "gcp_audit"), None)
    _require(gcp is not None, "GCP collection health missing")
    _require(gcp.status.value == "partial", "GCP collection was promoted beyond available evidence")
    _require(gcp.failure_code == "rate_limited_after_page_2", "GCP failure provenance changed")
    _require(not _contains_key(payload, "raw_payload"), "normalized output exposes a raw payload")
    _require(len(story.estate_content_hash) == 64, "estate content hash is invalid")
    _require(len(story.story_content_hash) == 64, "story content hash is invalid")

    fixture_dir = REPO_ROOT / "src" / "agent_bom" / "demo_estate" / "data"
    fixtures = {path.name for path in fixture_dir.glob("enterprise*.jsonl")}
    _require(EXPECTED_FIXTURES <= fixtures, "one or more versioned fixture files are missing")
    package_config = _read("pyproject.toml")
    _require("demo_estate/data/*.jsonl" in package_config, "wheel package-data glob is missing")

    demo_group = main.commands.get("demo")
    _require(demo_group is not None, "CLI demo group is not registered")
    _require("story" in getattr(demo_group, "commands", {}), "CLI demo story command is not registered")

    openapi = json.loads(_read("docs/openapi/v1.json"))
    operation = openapi.get("paths", {}).get("/v1/demo-estate/story", {}).get("get", {})
    response_ref = (
        operation.get("responses", {})
        .get("200", {})
        .get("content", {})
        .get("application/json", {})
        .get("schema", {})
        .get("$ref")
    )
    _require(response_ref == "#/components/schemas/EnterpriseDemoStory", "OpenAPI story contract is missing")

    api_client = _read("ui/lib/api.ts")
    dashboard = _read("ui/app/demo-estate/page.tsx")
    _require('get<EnterpriseDemoStory>("/v1/demo-estate/story")' in api_client, "UI API client drifted")
    for marker in (
        "Synthetic enterprise evidence",
        "Fictional data boundary",
        "Normalized evidence timeline",
        "Collection truth",
        "Verified provenance",
    ):
        _require(marker in dashboard, f"dashboard lost required marker: {marker}")

    helm_profile = _read(
        "deploy/helm/agent-bom/examples/synthetic-enterprise-story-values.yaml"
    )
    for marker in (
        "AGENT_BOM_DEMO_ESTATE",
        "AGENT_BOM_ALLOW_UNAUTHENTICATED_API",
        "AGENT_BOM_NO_AUTH_ROLE",
        "viewer",
    ):
        _require(marker in helm_profile, f"Helm demo profile lost {marker}")

    runbook = _read("docs/ENTERPRISE_DEMO.md")
    for marker in (
        "agent-bom demo story --output enterprise-demo-story.json",
        "agent-bom serve --demo-estate --allow-insecure-no-auth",
        "rate_limited_after_page_2",
        "contains no customer telemetry",
        "python scripts/install_helm_profile.py synthetic-enterprise-story",
    ):
        _require(marker in runbook, f"runbook lost required operator evidence: {marker}")

    print("enterprise demo surface contract passed")


if __name__ == "__main__":
    main_check()
