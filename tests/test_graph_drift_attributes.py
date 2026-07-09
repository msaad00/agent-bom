from __future__ import annotations

from agent_bom.graph.drift_attributes import (
    attribute_deltas,
    node_diff_metadata,
    node_snapshot_changed,
    summarize_attribute_delta,
)


def test_attribute_deltas_detect_public_exposure_flip() -> None:
    old = node_diff_metadata(
        node_id="cloud:pii-bucket",
        entity_type="cloud_resource",
        label="customer-pii-prod (S3)",
        status="",
        severity="",
        severity_id=0,
        risk_score=0.0,
        attributes={"internet_exposed": False},
        compliance_tags=["PII", "GDPR"],
    )
    new = node_diff_metadata(
        node_id="cloud:pii-bucket",
        entity_type="cloud_resource",
        label="customer-pii-prod (S3)",
        status="",
        severity="high",
        severity_id=0,
        risk_score=8.2,
        attributes={"internet_exposed": True},
        compliance_tags=["PII", "GDPR"],
    )
    deltas = attribute_deltas(old, new)
    fields = {row["field"] for row in deltas}
    assert "internet_exposed" in fields
    assert any(row["summary"] == "Public exposure opened" for row in deltas)
    assert node_snapshot_changed(old, new)


def test_summarize_attribute_delta_encryption_disabled() -> None:
    assert (
        summarize_attribute_delta("encryption_at_rest", True, False)
        == "Encryption at rest disabled"
    )
