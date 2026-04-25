from __future__ import annotations

from agent_bom.api.exception_store import ExceptionStatus, InMemoryExceptionStore, VulnException
from agent_bom.models import Agent, AgentType, BlastRadius, MCPServer, Package, Severity, Vulnerability
from agent_bom.output.json_fmt import to_json
from agent_bom.suppression_rules import apply_tenant_suppression_rules


def _blast_radius() -> BlastRadius:
    vuln = Vulnerability(id="CVE-2026-12345", summary="test", severity=Severity.HIGH)
    pkg = Package(name="requests", version="2.31.0", ecosystem="pypi")
    server = MCPServer(name="github")
    agent = Agent(name="agent", agent_type=AgentType.CUSTOM, config_path="/tmp/agent.json", mcp_servers=[server])
    br = BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[server],
        affected_agents=[agent],
        exposed_credentials=["GITHUB_TOKEN"],
        exposed_tools=[],
        risk_score=8.4,
    )
    return br


def test_tenant_suppression_marks_finding_without_deleting_evidence():
    store = InMemoryExceptionStore()
    store.put(
        VulnException(
            vuln_id="CVE-2026-12345",
            package_name="requests",
            server_name="github",
            reason="[finding_feedback:false_positive] scanner mismatch",
            requested_by="analyst",
            status=ExceptionStatus.ACTIVE,
            tenant_id="tenant-a",
        )
    )
    blast_radii = [_blast_radius()]

    summary = apply_tenant_suppression_rules(blast_radii, store, tenant_id="tenant-a")

    assert summary == {"evaluated": 1, "suppressed": 1}
    assert len(blast_radii) == 1
    assert blast_radii[0].suppressed is True
    assert blast_radii[0].suppression_state == "false_positive"
    assert blast_radii[0].suppression_reason == "scanner mismatch"
    assert blast_radii[0].unsuppressed_risk_score == 8.4
    assert blast_radii[0].risk_score == 0.0
    assert blast_radii[0].is_actionable is False


def test_tenant_suppression_does_not_cross_tenants():
    store = InMemoryExceptionStore()
    store.put(
        VulnException(
            vuln_id="CVE-2026-12345",
            package_name="requests",
            server_name="*",
            reason="[finding_feedback:accepted_risk] beta only",
            status=ExceptionStatus.ACTIVE,
            tenant_id="tenant-b",
        )
    )
    blast_radii = [_blast_radius()]

    summary = apply_tenant_suppression_rules(blast_radii, store, tenant_id="tenant-a")

    assert summary == {"evaluated": 1, "suppressed": 0}
    assert blast_radii[0].suppressed is False
    assert blast_radii[0].risk_score == 8.4


def test_suppression_metadata_is_exported_in_json_report():
    from agent_bom.models import AIBOMReport

    store = InMemoryExceptionStore()
    store.put(
        VulnException(
            vuln_id="CVE-2026-12345",
            package_name="requests",
            server_name="github",
            reason="[finding_feedback:not_applicable] not deployed",
            status=ExceptionStatus.ACTIVE,
            tenant_id="tenant-a",
        )
    )
    br = _blast_radius()
    apply_tenant_suppression_rules([br], store, tenant_id="tenant-a")

    payload = to_json(AIBOMReport(blast_radii=[br]))

    finding = payload["blast_radius"][0]
    assert finding["suppressed"] is True
    assert finding["suppression_state"] == "not_applicable"
    assert finding["suppression_reason"] == "not deployed"
    assert finding["unsuppressed_risk_score"] == 8.4
