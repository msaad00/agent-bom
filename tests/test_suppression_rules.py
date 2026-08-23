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
            reason="[finding_feedback:not_affected] not deployed",
            status=ExceptionStatus.ACTIVE,
            tenant_id="tenant-a",
        )
    )
    br = _blast_radius()
    apply_tenant_suppression_rules([br], store, tenant_id="tenant-a")

    payload = to_json(AIBOMReport(blast_radii=[br]))

    finding = payload["blast_radius"][0]
    assert finding["suppressed"] is True
    assert finding["suppression_state"] == "not_affected"
    assert finding["suppression_reason"] == "not deployed"
    assert finding["unsuppressed_risk_score"] == 8.4


def test_needs_review_feedback_does_not_suppress_actionability():
    store = InMemoryExceptionStore()
    store.put(
        VulnException(
            vuln_id="CVE-2026-12345",
            package_name="requests",
            server_name="github",
            reason="[finding_feedback:needs_review] low confidence runtime-only match",
            status=ExceptionStatus.ACTIVE,
            tenant_id="tenant-a",
        )
    )
    blast_radii = [_blast_radius()]

    summary = apply_tenant_suppression_rules(blast_radii, store, tenant_id="tenant-a")

    assert summary == {"evaluated": 1, "suppressed": 0}
    assert blast_radii[0].suppressed is False
    assert blast_radii[0].risk_score == 8.4


def test_approved_exception_has_one_suppression_contract_across_six_surfaces():
    from agent_bom.cli.agents._context import ScanContext
    from agent_bom.cli.agents._post import compute_exit_code
    from agent_bom.models import AIBOMReport
    from agent_bom.output.finding_views import active_cve_findings
    from agent_bom.output.sarif import to_sarif
    from agent_bom.vex import VexStatus, active_blast_radii, generate_vex

    store = InMemoryExceptionStore()
    store.put(
        VulnException(
            vuln_id="CVE-2026-12345",
            package_name="requests",
            server_name="github",
            reason="[finding_feedback:accepted_risk] approved until upgrade window",
            status=ExceptionStatus.APPROVED,
            tenant_id="tenant-a",
        )
    )
    br = _blast_radius()
    apply_tenant_suppression_rules([br], store, tenant_id="tenant-a")
    report = AIBOMReport(blast_radii=[br])

    # Console and MCP both consume the canonical active-finding views.
    assert active_cve_findings(report) == []
    assert active_blast_radii([br]) == []

    # JSON preserves the evidence overlay rather than deleting the finding.
    json_finding = to_json(report)["blast_radius"][0]
    assert json_finding["suppressed"] is True
    assert json_finding["suppression_state"] == "accepted_risk"

    # SARIF emits the standard suppressions[] contract.
    sarif_result = to_sarif(report)["runs"][0]["results"][0]
    assert sarif_result["suppressions"][0]["properties"]["suppression_state"] == "accepted_risk"

    # VEX retains the affected status and records the approved acceptance.
    statement = generate_vex(report).statements[0]
    assert statement.status == VexStatus.AFFECTED
    assert "approved until upgrade window" in (statement.action_statement or "")

    # The CLI severity gate sees the same inactive finding and exits cleanly.
    ctx = ScanContext(con=None, quiet=True, blast_radii=[br], report=report)
    assert (
        compute_exit_code(
            ctx,
            fail_on_severity="high",
            warn_on_severity=None,
            fail_on_kev=False,
            fail_if_ai_risk=False,
            push_url=None,
            push_api_key=None,
            quiet=True,
        )
        == 0
    )
