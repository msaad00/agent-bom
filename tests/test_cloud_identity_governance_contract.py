"""Cloud identity coverage and non-duplicated usage findings."""

from datetime import datetime, timezone

import pytest

from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.nhi_governance import (
    build_ciem_over_privilege_findings,
    build_nhi_governance_findings,
    evaluate_identity_governance,
)
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType

NOW = datetime(2026, 9, 28, tzinfo=timezone.utc)


def test_collected_azure_service_principal_gets_governance_without_invented_usage():
    graph = build_unified_graph_from_report(
        {
            "cloud_inventory": {
                "provider": "azure",
                "status": "ok",
                "account_id": "sub-1",
                "subscription_id": "sub-1",
                "service_principals": [
                    {
                        "name": "scanner",
                        "arn": "directory-id",
                        "principal_id": "directory-id",
                        "principal_type": "service-principal",
                        "privilege_level": "unknown",
                        "policies": [],
                    }
                ],
            }
        }
    )
    node = next(n for n in graph.nodes.values() if n.entity_type == EntityType.SERVICE_PRINCIPAL)
    verdicts = evaluate_identity_governance(graph, now=NOW)
    assert len(verdicts) == 1
    verdict = verdicts[0]
    assert verdict.node_id == node.id
    assert verdict.provider == "azure"
    assert not verdict.is_dormant and not verdict.is_orphaned
    assert verdict.unused_targets == []
    assert build_nhi_governance_findings(graph, verdicts) == []
    assert build_ciem_over_privilege_findings(graph) == []
    assert node.attributes["nhi_is_dormant"] is False


def test_azure_service_principal_governance_uses_explicit_evidence():
    graph = UnifiedGraph(scan_id="scan", tenant_id="tenant")
    graph.add_node(
        UnifiedNode(
            id="sp",
            entity_type=EntityType.SERVICE_PRINCIPAL,
            label="scanner",
            attributes={
                "cloud_provider": "azure",
                "owner": "",
                "last_used_at": "2020-01-01T00:00:00Z",
            },
        )
    )
    for target in ("used", "unused"):
        graph.add_node(UnifiedNode(id=target, entity_type=EntityType.CLOUD_RESOURCE, label=target))
        graph.add_edge(UnifiedEdge(source="sp", target=target, relationship=RelationshipType.HAS_PERMISSION))
    verdicts = evaluate_identity_governance(graph, usage={"sp": {"used"}}, now=NOW)
    assert len(verdicts) == 1
    verdict = verdicts[0]
    assert verdict.is_dormant and verdict.is_orphaned
    assert verdict.unused_targets == ["unused"]
    findings = build_nhi_governance_findings(graph, verdicts)
    assert {f.evidence["nhi_governance"] for f in findings} == {"over_grant", "unattended_identity"}
    assert all(f.asset.location == "azure" for f in findings)
    assert build_ciem_over_privilege_findings(graph) == []


@pytest.mark.parametrize("used", [False, True])
@pytest.mark.parametrize("reverse", [False, True])
def test_access_advisor_and_nhi_emit_one_rightsizing_finding(used, reverse):
    graph = UnifiedGraph(scan_id="scan", tenant_id="tenant")
    graph.add_node(UnifiedNode(id="role", entity_type=EntityType.ROLE, label="app", attributes={"cloud_provider": "aws"}))
    for target in ("s3", "ec2"):
        graph.add_node(UnifiedNode(id=target, entity_type=EntityType.CLOUD_RESOURCE, label=target))
    observations = [("s3", None), ("ec2", None)]
    if used:
        observations.append(("s3", "2026-09-27T00:00:00Z"))
    for index, (target, timestamp) in enumerate(reversed(observations) if reverse else observations):
        graph.add_edge(
            UnifiedEdge(
                source="role",
                target=target,
                relationship=RelationshipType.SCOPED_TO if index == 2 else RelationshipType.HAS_PERMISSION,
                evidence={"access_advisor": True, "last_used_at": timestamp},
            )
        )
    verdicts = evaluate_identity_governance(graph, now=NOW)
    combined = build_nhi_governance_findings(graph, verdicts) + build_ciem_over_privilege_findings(graph)
    rightsizing = [f for f in combined if f.evidence.get("ciem") == "over_privilege" or f.evidence.get("nhi_governance") == "over_grant"]
    assert len(rightsizing) == 1
    evidence = rightsizing[0].evidence
    assert evidence["analysis"] == "access_advisor_rightsizing"
    assert evidence["granted_count"] == 2
    assert evidence["used_count"] == int(used)
    assert evidence["unused_permission_count"] == 2 - int(used)
