"""CIEM over-privilege findings from AWS Access-Advisor usage evidence.

Reproduces the last-mile gap: per-permission Access-Advisor usage evidence is
collected on IAM roles but never produced a finding. These tests assert the
bridge (usage_evidence -> grant-edge last_used_at -> over-privilege finding) and
the honest negatives (all-used, no-evidence, unavailable-evidence -> no finding).
"""

from __future__ import annotations

from agent_bom.finding import FindingType
from agent_bom.graph.builder import _add_inventory_principal
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.nhi_governance import build_ciem_over_privilege_findings
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType

_USED_AT = "2026-06-01T00:00:00+00:00"


def _role_node(g: UnifiedGraph, nid: str, label: str, **attrs) -> None:
    g.add_node(
        UnifiedNode(
            id=nid,
            entity_type=EntityType.ROLE,
            label=label,
            attributes={"cloud_provider": "aws", **attrs},
        )
    )


def _service_node(g: UnifiedGraph, nid: str, label: str) -> None:
    g.add_node(UnifiedNode(id=nid, entity_type=EntityType.RESOURCE, label=label, attributes={"cloud_service": label}))


def _advisor_grant(src: str, tgt: str, service: str, last_used: str | None) -> UnifiedEdge:
    return UnifiedEdge(
        source=src,
        target=tgt,
        relationship=RelationshipType.HAS_PERMISSION,
        evidence={"source": "access-advisor", "access_advisor": True, "service_namespace": service, "last_used_at": last_used},
    )


def test_access_advisor_unused_service_is_flagged_as_over_privilege() -> None:
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    _role_node(g, "role:aws:deployer", "deployer", privilege_level="admin")
    _service_node(g, "svc:s3", "s3")
    _service_node(g, "svc:ec2", "ec2")
    g.add_edge(_advisor_grant("role:aws:deployer", "svc:s3", "s3", _USED_AT))
    g.add_edge(_advisor_grant("role:aws:deployer", "svc:ec2", "ec2", None))

    findings = build_ciem_over_privilege_findings(g)
    ciem = [f for f in findings if f.finding_type == FindingType.CIEM_OVER_PRIVILEGE]
    assert len(ciem) == 1
    f = ciem[0]
    assert f.evidence["granted_count"] == 2
    assert f.evidence["used_count"] == 1
    assert f.evidence["unused_permission_count"] == 1
    assert "ec2" in f.evidence["unused_permissions"]
    assert "s3" not in f.evidence["unused_permissions"]
    assert "ec2" in f.title or "ec2" in f.description


def test_all_permissions_used_produces_no_finding() -> None:
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    _role_node(g, "role:aws:clean", "clean")
    _service_node(g, "svc:s3", "s3")
    g.add_edge(_advisor_grant("role:aws:clean", "svc:s3", "s3", _USED_AT))
    assert build_ciem_over_privilege_findings(g) == []


def test_grants_without_access_advisor_evidence_are_not_over_privilege() -> None:
    # A HAS_PERMISSION edge with no Access-Advisor marker (e.g. an effective-
    # permissions closure edge) must NOT be counted as unused, even with no
    # last_used_at — we only right-size where Access-Advisor evidence exists.
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    _role_node(g, "role:aws:closure", "closure")
    _service_node(g, "res:x", "x")
    g.add_edge(UnifiedEdge(source="role:aws:closure", target="res:x", relationship=RelationshipType.HAS_PERMISSION))
    assert build_ciem_over_privilege_findings(g) == []


def _principal(usage_state: str, records: list[dict]) -> dict:
    return {
        "principal_type": "iam-role",
        "name": "deployer",
        "arn": "arn:aws:iam::123456789012:role/deployer",
        "privilege_level": "admin",
        "policies": [],
        "usage_evidence": {
            "principal_arn": "arn:aws:iam::123456789012:role/deployer",
            "state": usage_state,
            "diagnostic": "access_advisor_available",
            "records": records,
        },
    }


def _record(service: str, state: str, last_accessed_at: str | None) -> dict:
    return {
        "service_namespace": service,
        "state": state,
        "observed": (last_accessed_at is not None) if state == "available" else None,
        "last_accessed_at": last_accessed_at,
    }


def test_builder_bridges_usage_evidence_into_over_privilege_finding() -> None:
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    principal = _principal(
        "available",
        [_record("s3", "available", _USED_AT), _record("ec2", "available", None)],
    )
    _add_inventory_principal(
        g,
        principal,
        provider="aws",
        account_node_id="",
        resource_ids=[],
        data_sources=["cloud-inventory"],
    )

    findings = build_ciem_over_privilege_findings(g)
    ciem = [f for f in findings if f.finding_type == FindingType.CIEM_OVER_PRIVILEGE]
    assert len(ciem) == 1
    assert "ec2" in ciem[0].evidence["unused_permissions"]
    assert "s3" not in ciem[0].evidence["unused_permissions"]


def test_ciem_over_privilege_routes_to_cspm_domain() -> None:
    from agent_bom.finding import FindingSource
    from agent_bom.finding_scope import security_domain_for

    assert security_domain_for(FindingSource.GRAPH_ANALYSIS, FindingType.CIEM_OVER_PRIVILEGE) == "cspm"


def test_report_surfaces_ciem_finding_and_serializes_to_sarif() -> None:
    from agent_bom.models import AIBOMReport
    from agent_bom.output.sarif import to_sarif

    g = UnifiedGraph(scan_id="s", tenant_id="t")
    _role_node(g, "role:aws:deployer", "deployer", privilege_level="admin", principal_id="arn:aws:iam::1:role/deployer")
    _service_node(g, "svc:s3", "s3")
    _service_node(g, "svc:ec2", "ec2")
    g.add_edge(_advisor_grant("role:aws:deployer", "svc:s3", "s3", _USED_AT))
    g.add_edge(_advisor_grant("role:aws:deployer", "svc:ec2", "ec2", None))

    from agent_bom.graph.nhi_governance import build_ciem_over_privilege_findings_data

    data = build_ciem_over_privilege_findings_data(g)
    assert len(data) == 1
    report = AIBOMReport(ciem_over_privilege_findings_data=data)

    types = {f.finding_type for f in report.to_findings()}
    assert FindingType.CIEM_OVER_PRIVILEGE in types

    sarif = to_sarif(report)
    rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert "finding/CIEM_OVER_PRIVILEGE" in rule_ids


def test_builder_omits_edges_when_access_advisor_unavailable() -> None:
    # Access-Advisor denied/unavailable -> no grant edges -> no fabricated
    # "unused" finding (honest counts: absence of evidence is not over-privilege).
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    principal = _principal("access_denied", [])
    _add_inventory_principal(
        g,
        principal,
        provider="aws",
        account_node_id="",
        resource_ids=[],
        data_sources=["cloud-inventory"],
    )
    advisor_edges = [e for e in g.edges if isinstance(e.evidence, dict) and e.evidence.get("access_advisor")]
    assert advisor_edges == []
    assert build_ciem_over_privilege_findings(g) == []
