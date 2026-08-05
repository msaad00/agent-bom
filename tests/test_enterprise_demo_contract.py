"""Contract tests for the versioned, realistic synthetic enterprise estate."""

from __future__ import annotations

import json
import re

from agent_bom.demo_estate.enterprise import (
    ENTERPRISE_SCHEMA_VERSION,
    CollectionStatus,
    EstateStage,
    load_enterprise_estate,
    verify_observation_hash,
)

EXPECTED_SOURCES = {
    "aws_cloudtrail",
    "azure_activity",
    "entra_signin",
    "gcp_audit",
    "github_actions",
    "kubernetes_audit",
    "mcp_gateway",
    "otel_llm",
    "snowflake_access_history",
}


def test_enterprise_estate_is_versioned_fictional_and_cross_cloud() -> None:
    estate = load_enterprise_estate()

    assert estate.schema_version == ENTERPRISE_SCHEMA_VERSION
    assert estate.synthetic is True
    assert estate.fictional is True
    assert "synthetic" in estate.disclosure.lower()
    assert estate.display_name == "Northstar Health AI"

    providers = {asset.provider for asset in estate.assets}
    assert {"aws", "azure", "gcp", "snowflake", "kubernetes", "github", "mcp"} <= providers
    assert {asset.environment for asset in estate.assets} >= {"production", "staging", "development"}
    assert {asset.owner for asset in estate.assets} >= {
        "ai-platform@northstar.example",
        "data-platform@northstar.example",
        "security@northstar.example",
    }
    assert {classification for asset in estate.assets for classification in asset.data_classifications} >= {
        "confidential",
        "phi",
        "pii",
    }


def test_enterprise_estate_has_three_ordered_reproducible_snapshots() -> None:
    first = load_enterprise_estate()
    replay = load_enterprise_estate()

    assert [snapshot.stage for snapshot in first.snapshots] == [
        EstateStage.BASELINE,
        EstateStage.CURRENT,
        EstateStage.REMEDIATED,
    ]
    assert [snapshot.observed_at for snapshot in first.snapshots] == sorted(snapshot.observed_at for snapshot in first.snapshots)
    assert first.model_dump(mode="json") == replay.model_dump(mode="json")
    assert first.content_hash == replay.content_hash


def test_raw_observations_are_referentially_complete_and_tamper_evident() -> None:
    estate = load_enterprise_estate()
    asset_ids = {asset.asset_id for asset in estate.assets}
    event_ids = [observation.event_id for observation in estate.observations]

    assert len(event_ids) == len(set(event_ids))
    assert {observation.source for observation in estate.observations} == EXPECTED_SOURCES
    for observation in estate.observations:
        assert set(observation.resource_ids) <= asset_ids
        assert observation.provenance.source == observation.source
        assert observation.provenance.source_event_id == observation.event_id
        assert observation.provenance.run_id
        assert observation.provenance.tenant_id == estate.tenant_id
        assert re.fullmatch(r"[0-9a-f]{64}", observation.provenance.evidence_hash)
        assert verify_observation_hash(observation)


def test_tenant_override_preserves_evidence_but_scopes_asset_identity() -> None:
    tenant_a = load_enterprise_estate(tenant_id="tenant-a")
    tenant_b = load_enterprise_estate(tenant_id="tenant-b")

    scoped_a = {asset.scoped_asset_id for asset in tenant_a.assets}
    scoped_b = {asset.scoped_asset_id for asset in tenant_b.assets}
    assert scoped_a.isdisjoint(scoped_b)
    assert {row.provenance.tenant_id for row in tenant_a.observations} == {"tenant-a"}
    assert {row.provenance.tenant_id for row in tenant_b.observations} == {"tenant-b"}

    hashes_a = {row.event_id: row.provenance.evidence_hash for row in tenant_a.observations}
    hashes_b = {row.event_id: row.provenance.evidence_hash for row in tenant_b.observations}
    assert hashes_a == hashes_b


def test_incident_trace_crosses_realistic_enterprise_surfaces_in_order() -> None:
    estate = load_enterprise_estate()
    incident = sorted(
        (row for row in estate.observations if row.trace_id == "7f3a9b12c4d5e6f7890abcde12345678"),
        key=lambda row: row.observed_at,
    )

    assert [row.source for row in incident] == [
        "github_actions",
        "aws_cloudtrail",
        "kubernetes_audit",
        "mcp_gateway",
        "snowflake_access_history",
        "otel_llm",
    ]
    assert all(row.stage is EstateStage.CURRENT for row in incident)
    assert (
        incident[-2].raw_payload["QUERY_HISTORY"]["QUERY_TEXT"]
        == "SELECT MEMBER_ID, RISK_SCORE, CARE_GAP FROM ANALYTICS.PHI.PATIENT_SUMMARY WHERE MEMBER_ID = ?"
    )
    assert incident[-1].raw_payload["attributes"]["agent_bom.decision"] == "block"


def test_collection_failures_remain_explicit_and_never_become_clean_evidence() -> None:
    estate = load_enterprise_estate()
    runs = {run.source: run for run in estate.collection_runs}

    assert set(runs) == EXPECTED_SOURCES
    assert runs["gcp_audit"].status is CollectionStatus.PARTIAL
    assert runs["gcp_audit"].records_read > 0
    assert runs["gcp_audit"].failure_code == "rate_limited_after_page_2"
    assert runs["gcp_audit"].next_cursor
    assert runs["azure_activity"].status is CollectionStatus.COMPLETE
    assert all(run.read_only for run in runs.values())
    assert all(run.source_schema and run.schema_url.startswith("https://") for run in runs.values())


def test_native_payloads_keep_required_vendor_fields() -> None:
    estate = load_enterprise_estate()
    by_source: dict[str, list[dict]] = {}
    for observation in estate.observations:
        by_source.setdefault(observation.source, []).append(observation.raw_payload)

    for event in by_source["aws_cloudtrail"]:
        assert event["eventVersion"] == "1.11"
        assert event["eventID"] and event["eventType"] == "AwsApiCall"
        assert event["recipientAccountId"] == "123456789012"

    workflow_run = by_source["github_actions"][0]
    assert workflow_run["action"] == "completed"
    assert workflow_run["workflow_run"]["conclusion"] == "success"
    assert workflow_run["repository"]["private"] is True
    assert workflow_run["sender"]["type"] == "Bot"

    kubernetes = by_source["kubernetes_audit"][0]
    assert kubernetes["apiVersion"] == "audit.k8s.io/v1"
    assert kubernetes["kind"] == "Event"
    assert kubernetes["objectRef"]["subresource"] == "exec"
    assert kubernetes["responseStatus"]["status"] == "Success"

    mcp = by_source["mcp_gateway"][0]
    assert mcp["jsonrpc"] == "2.0" and mcp["method"] == "tools/call"
    assert mcp["params"]["name"] == "execute_sql"

    snowflake = by_source["snowflake_access_history"][1]
    accessed = snowflake["ACCESS_HISTORY"]["DIRECT_OBJECTS_ACCESSED"][0]
    assert accessed["objectDomain"] == "Table"
    assert {column["columnName"] for column in accessed["columns"]} == {
        "MEMBER_ID",
        "RISK_SCORE",
        "CARE_GAP",
    }

    otel = by_source["otel_llm"][0]
    assert otel["attributes"]["gen_ai.provider.name"] == "openai"
    assert otel["attributes"]["gen_ai.operation.name"] == "chat"
    assert "gen_ai.system" not in otel["attributes"]


def test_fixture_contains_no_credential_material() -> None:
    serialized = json.dumps(load_enterprise_estate().model_dump(mode="json"), sort_keys=True)

    assert not re.search(r"(?:AKIA|ASIA)[A-Z0-9]{16}", serialized)
    assert "-----BEGIN PRIVATE KEY-----" not in serialized
    assert not re.search(r"Bearer\s+[A-Za-z0-9._~-]{20,}", serialized)
    assert "synthetic-secret-value" not in serialized
