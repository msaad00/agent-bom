"""Cloud org architecture verdict findings (single-account / flat hierarchy)."""

from __future__ import annotations

from agent_bom.cloud import aws_organizations, gcp_organizations
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.models import AIBOMReport


def test_aws_single_account_and_flat_findings() -> None:
    payload = {
        "status": "ok",
        "org_id": "o-abc",
        "accounts": [{"id": "111", "name": "only"}],
        "organizational_units": [{"id": "r-root", "name": "Root", "parent_id": "", "is_root": True}],
        "scps": [{"id": "p-full", "name": "FullAWSAccess", "aws_managed": True, "targets": []}],
        "findings": [],
    }
    aws_organizations._derive_findings(payload)
    assert payload["architecture"]["verdict"] == "single_account"
    check_ids = {f["check_id"] for f in payload["findings"]}
    assert "ORG-AWS-002" in check_ids  # single-account
    assert "ORG-AWS-004" in check_ids  # flat (no non-root OUs)
    assert "ORG-AWS-003" in check_ids  # no custom SCPs


def test_aws_not_in_org_finding() -> None:
    payload = {"status": "not_in_org", "accounts": [], "organizational_units": [], "scps": [], "findings": []}
    aws_organizations._derive_findings(payload)
    assert payload["architecture"]["verdict"] == "not_in_org"
    assert payload["findings"][0]["check_id"] == "ORG-AWS-001"


def test_gcp_single_project_finding() -> None:
    payload = {
        "status": "ok",
        "org_id": "123",
        "projects": [{"id": "proj-a"}],
        "folders": [],
        "org_policies": [],
        "findings": [],
    }
    gcp_organizations._derive_findings(payload)
    assert payload["architecture"]["verdict"] == "single_account"
    check_ids = {f["check_id"] for f in payload["findings"]}
    assert "ORG-GCP-002" in check_ids
    assert "ORG-GCP-004" in check_ids


def test_graph_promotes_org_architecture_misconfigs() -> None:
    g = build_unified_graph_from_report(
        {
            "aws_organization": {
                "status": "not_in_org",
                "org_id": "",
                "architecture": {"provider": "aws", "verdict": "not_in_org", "account_count": 1, "hierarchy_depth": 0},
                "findings": [
                    {
                        "check_id": "ORG-AWS-001",
                        "severity": "medium",
                        "title": "Standalone AWS account",
                        "detail": "not in org",
                        "category": "estate_architecture",
                    }
                ],
            }
        }
    )
    node = g.nodes.get("misconfig:cloud-org:aws:ORG-AWS-001")
    assert node is not None
    assert node.entity_type == EntityType.MISCONFIGURATION
    edges = list(g.edges.values()) if isinstance(g.edges, dict) else list(g.edges)
    assert any(
        e.source == "misconfig:cloud-org:aws:ORG-AWS-001"
        and e.target == "org:aws:standalone"
        and e.relationship == RelationshipType.AFFECTS
        for e in edges
    )


def test_unified_findings_include_org_architecture() -> None:
    report = AIBOMReport(agents=[], blast_radii=[])
    report.aws_organization_data = {
        "status": "ok",
        "org_id": "o-1",
        "findings": [
            {
                "check_id": "ORG-AWS-002",
                "severity": "medium",
                "title": "Single-account AWS Organization",
                "detail": "one account",
            }
        ],
    }
    findings = report.to_findings()
    matches = [f for f in findings if any("ORG-AWS-002" in tag for tag in (f.compliance_tags or []))]
    assert len(matches) == 1
    assert matches[0].finding_type.value == "CLOUD_BEST_PRACTICE_FAIL"
