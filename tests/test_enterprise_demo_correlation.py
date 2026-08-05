"""Production-path normalization and correlation for the enterprise demo estate."""

from __future__ import annotations

import pytest

from agent_bom.demo_estate.enterprise import load_enterprise_estate
from agent_bom.demo_estate.enterprise_correlation import correlate_enterprise_estate

INCIDENT_TRACE_ID = "7f3a9b12c4d5e6f7890abcde12345678"
REMEDIATION_TRACE_ID = "5e2a1c9d8b7f60431234567890abcdef"
AZURE_TRACE_ID = "91ab42cd63ef4087b2157d0300000001"


def test_every_observation_normalizes_without_copying_raw_payloads() -> None:
    estate = load_enterprise_estate()
    result = correlate_enterprise_estate(estate)

    assert len(result.events) == len(estate.observations) == 15
    for event in result.events:
        original = next(row for row in estate.observations if row.event_id == event.event_id)
        assert event.evidence_hash == original.provenance.evidence_hash
        assert event.tenant_id == estate.tenant_id
        assert not hasattr(event, "raw_payload")
        assert event.event_relationships["normalization_version"] == "1"
        assert event.graph_projection["schema_version"] == "agentic_identity_graph.v1"
        assert event.graph_projection["source"] == original.source
        for edge in event.graph_projection["edges"]:
            assert edge["evidence"]["event_id"] == event.event_id
            assert edge["evidence"]["tenant_id"] == estate.tenant_id


def test_primary_incident_correlates_ci_cloud_workload_mcp_data_and_llm() -> None:
    result = correlate_enterprise_estate(load_enterprise_estate())
    incident = result.correlation_by_trace(INCIDENT_TRACE_ID)

    assert incident is not None
    assert incident.kind == "data_egress_attempt"
    assert incident.outcome == "blocked"
    assert incident.event_ids == (
        "github-current-001",
        "aws-current-001",
        "k8s-current-001",
        "mcp-current-001",
        "snowflake-current-001",
        "otel-current-001",
    )
    assert incident.sources == (
        "github_actions",
        "aws_cloudtrail",
        "kubernetes_audit",
        "mcp_gateway",
        "snowflake_access_history",
        "otel_llm",
    )
    # The path walks the pipeline in order and now includes the hops the
    # ordering table used to skip: the repository behind the workflow, the image
    # the role deploys, the cluster the workload runs on, the MCP server that
    # owns the tool, and the database above the table. Every one was already in
    # the incident's evidence — the rendered chain simply jumped over them.
    assert incident.asset_path == (
        "github:repository:northstar-health/member-copilot",
        "github:workflow:member-copilot/deploy-prod",
        "cloud_resource:aws:iam:role:member-copilot-prod",
        (
            "cloud_resource:aws:ecr:image:member-copilot@sha256:"
            "4f2c8d66a10b490c6f5e7a2f91f7eb04cf9b1001df06d422ad2c42c5bc82f20a"
        ),
        "kubernetes:cluster:eks/member-ai-prod",
        "kubernetes:workload:member-ai-prod/ai-prod/member-copilot",
        "mcp:server:clinical-analytics",
        "mcp:tool:clinical-analytics/execute_sql",
        "snowflake:database:nh_prod/analytics",
        "snowflake:table:nh_prod/analytics/phi/patient_summary",
        "model:openai:gpt-4.1",
    )
    assert incident.data_classifications == ("phi", "pii")
    assert len(incident.evidence_hashes) == len(incident.event_ids)
    assert incident.evidence_quality == "complete"


def test_secondary_vendor_and_remediation_correlations_are_distinct() -> None:
    result = correlate_enterprise_estate(load_enterprise_estate())
    azure = result.correlation_by_trace(AZURE_TRACE_ID)
    remediation = result.correlation_by_trace(REMEDIATION_TRACE_ID)

    assert azure is not None
    assert azure.kind == "privilege_change"
    assert azure.outcome == "observed"
    assert azure.sources == ("entra_signin", "azure_activity")
    assert "identity:azure:service-principal:claims-enrichment" in azure.asset_ids

    assert remediation is not None
    assert remediation.kind == "remediation"
    assert remediation.outcome == "enforced"
    assert remediation.sources == ("aws_cloudtrail", "azure_activity", "mcp_gateway")


def test_partial_collection_health_survives_normalization() -> None:
    result = correlate_enterprise_estate(load_enterprise_estate())
    health = {row.source: row for row in result.collection_health}

    assert health["gcp_audit"].status == "partial"
    assert health["gcp_audit"].failure_code == "rate_limited_after_page_2"
    assert health["gcp_audit"].records_read == 2
    assert health["aws_cloudtrail"].status == "complete"
    assert result.complete_source_count == 8
    assert result.partial_source_count == 1


def test_replay_is_deterministic_and_tenant_scoped() -> None:
    first = correlate_enterprise_estate(load_enterprise_estate(tenant_id="tenant-a"))
    replay = correlate_enterprise_estate(load_enterprise_estate(tenant_id="tenant-a"))
    other = correlate_enterprise_estate(load_enterprise_estate(tenant_id="tenant-b"))

    assert first.model_dump(mode="json") == replay.model_dump(mode="json")
    assert first.content_hash == replay.content_hash
    assert {row.correlation_id for row in first.correlations}.isdisjoint({row.correlation_id for row in other.correlations})
    assert first.content_hash != other.content_hash


def test_tampered_raw_evidence_fails_closed() -> None:
    estate = load_enterprise_estate()
    original = estate.observations[0]
    tampered = original.model_copy(update={"raw_payload": {"eventName": "tampered"}})
    broken = estate.model_copy(update={"observations": (tampered, *estate.observations[1:])})

    with pytest.raises(ValueError, match="evidence hash mismatch.*aws-baseline-001"):
        correlate_enterprise_estate(broken)
