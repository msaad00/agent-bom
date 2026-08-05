#!/usr/bin/env python3
"""Fail when the versioned synthetic enterprise story drifts across surfaces."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent

# Check the surfaces of THIS checkout. Without this the script imports whatever
# ``agent_bom`` happens to be installed — in a git worktree that is the sibling
# checkout, so a drift gate silently validated a tree the developer was not
# editing and passed. Every other preflight script that imports the package
# pins its own root the same way (see ``export_openapi.py``).
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from agent_bom.cli import main  # noqa: E402
from agent_bom.demo_estate.enterprise_findings import ESTATE_FINDING_SEVERITY_BUCKETS  # noqa: E402
from agent_bom.demo_estate.presentation import build_enterprise_demo_story  # noqa: E402

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
    # The demo serves the narrative estate composed into a generated population,
    # so these are floors rather than fixed counts: pinning exact totals would
    # make every scale-profile change a gate failure, while a floor still catches
    # the regression that matters — the estate silently shrinking back to the
    # 20-asset spine, where nothing has to be correlated out of anything.
    _require(story.summary.assets >= 2000, "estate is no longer enterprise-sized")
    _require(story.summary.observations >= 6000, "estate carries too little evidence to correlate")
    _require(story.summary.evidence_sources == 9, "evidence-source count changed")
    # Floor, not a fixed count: the composed estate correlates thousands of rows.
    _require(story.summary.correlations >= 4, "the narrative correlations are gone")
    # The view is bounded so the incident stays visible; the summary must still
    # report the unbounded truth, never the page size.
    _require(len(story.correlations) <= story.summary.correlations, "story claims more rows than it holds")
    _require(story.correlations[0] == story.primary_correlation, "the incident is no longer surfaced first")
    _require(story.summary.snapshots == 3, "snapshot count changed")
    _require(story.primary_correlation.outcome == "blocked", "primary outcome is no longer blocked")
    _require(
        tuple(source.value for source in story.primary_correlation.sources) == EXPECTED_PRIMARY_SOURCES,
        "primary cross-vendor path changed",
    )
    gcp = next((row for row in story.collection_health if row.source.value == "gcp_audit"), None)
    _require(gcp is not None, "GCP collection health missing")
    _require(gcp.status.value == "partial", "GCP collection was promoted beyond available evidence")
    _require(gcp.failure_code == "rate_limited_after_page_2", "GCP failure provenance changed")
    _require(not _contains_key(payload, "raw_payload"), "normalized output exposes a raw payload")
    _require(len(story.estate_content_hash) == 64, "estate content hash is invalid")
    _require(len(story.story_content_hash) == 64, "story content hash is invalid")

    # ── Posture: the chain, not just a count ────────────────────────────────
    # A findings count proves nothing. What must not regress is that each
    # rendered finding still resolves to an inventoried asset, an identity, a
    # configuration and a control — and that the bounded list never reports its
    # own length as the estate's total.
    posture = story.finding_summary
    _require(posture.total >= 300, "the estate lost its posture findings")
    _require(story.summary.findings == posture.total, "the summary and the posture total disagree")
    _require(
        sum(posture.by_severity.values()) == posture.total,
        "the severity histogram does not sum to the total — a finding was dropped",
    )
    _require(
        set(posture.by_severity) == set(ESTATE_FINDING_SEVERITY_BUCKETS),
        "the severity histogram lost a display bucket",
    )
    _require(
        posture.by_severity["unrated"] > 0,
        "no unrated finding remains, so an unevaluable control is indistinguishable from a pass",
    )
    _require(len(set(posture.by_severity.values())) > 2, "the estate collapsed into one severity band")
    _require(0 < posture.assets_affected < posture.assets_total, "every asset or no asset is affected")
    _require(posture.controls_evidenced > 0, "posture findings evidence no compliance control")
    _require(len(posture.frameworks_evidenced) >= 2, "posture findings evidence only one framework")
    _require(posture.attack_paths_evidenced > 0, "no finding sits on a correlated attack path")
    _require(0 < len(story.findings) < posture.total, "the rendered findings list is not bounded")
    for finding in story.findings:
        _require(bool(finding.asset_id and finding.asset_canonical_id), "a rendered finding resolves to no asset")
        _require(bool(finding.asset_display_name), "a rendered finding has an unnamed asset")
        _require(
            bool(finding.identity_asset_id or finding.identity_actor_id),
            "a rendered finding carries no identity edge",
        )
        _require(bool(finding.configuration_setting), "a rendered finding carries no configuration edge")
        _require(bool(finding.controls), "a rendered finding evidences no control")
    _require(bool(story.findings[0].correlation_id), "the bounded list no longer leads with the incident")

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
        operation.get("responses", {}).get("200", {}).get("content", {}).get("application/json", {}).get("schema", {}).get("$ref")
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
        "Correlated posture",
        "configuration_expected",
        "on a correlated attack path",
        # The bounded lists must keep saying what they are bounded against.
        # All three: the timeline renders `events`, which the API bounds to 200
        # while the strip above it reports every observation in the estate.
        "of {posture.total} — incident first",
        "of {story.summary.correlations} — the incident first",
        # The observations list carries the fuller wording that shipped; both
        # sibling lists use the short form. Assert what renders, not a variant.
        "of {story.summary.observations} normalized events",
    ):
        _require(marker in dashboard, f"dashboard lost required marker: {marker}")

    helm_profile = _read("deploy/helm/agent-bom/examples/synthetic-enterprise-story-values.yaml")
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
