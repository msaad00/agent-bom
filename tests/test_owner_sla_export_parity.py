"""Owner/SLA workflow metadata must scale and survive user-facing exports."""

from __future__ import annotations

import csv
import dataclasses
import io
import json
from datetime import datetime, timezone

from agent_bom.api.exception_store import ExceptionStatus, InMemoryExceptionStore, SQLiteExceptionStore, VulnException
from agent_bom.api.routes import enterprise
from agent_bom.finding import Finding, blast_radius_to_finding
from agent_bom.models import Agent, AgentType, AIBOMReport, BlastRadius, MCPServer, Package, Severity, Vulnerability


def _owned_report() -> AIBOMReport:
    vuln = Vulnerability(
        id="CVE-2026-4242",
        summary="Owned workflow finding",
        severity=Severity.HIGH,
        cvss_score=8.8,
        fixed_version="2.0.0",
    )
    package = Package(name="owned-lib", version="1.0.0", ecosystem="pypi", vulnerabilities=[vuln])
    server = MCPServer(name="owned-server", packages=[package])
    agent = Agent(name="owned-agent", agent_type=AgentType.CLAUDE_DESKTOP, config_path="", mcp_servers=[server])
    radius = BlastRadius(
        vulnerability=vuln,
        package=package,
        affected_servers=[server],
        affected_agents=[agent],
        exposed_credentials=[],
        exposed_tools=[],
    )
    finding = blast_radius_to_finding(radius)
    finding.first_seen = "2026-08-01T00:00:00+00:00"
    finding.owner = "payments-security"
    finding.sla_due_at = "2026-08-08T00:00:00+00:00"
    finding.lifecycle_status = "in_progress"
    return AIBOMReport(
        agents=[agent],
        blast_radii=[radius],
        findings=[finding],
        generated_at=datetime(2026, 8, 1, tzinfo=timezone.utc),
        tool_version="0.0.0-test",
    )


def _shared_cve_report() -> AIBOMReport:
    agents: list[Agent] = []
    radii: list[BlastRadius] = []
    findings: list[Finding] = []
    for index, (package_name, owner, sla_due_at) in enumerate(
        (
            ("payments-lib", "payments-security", "2026-08-08T00:00:00+00:00"),
            ("identity-lib", "identity-security", "2026-08-15T00:00:00+00:00"),
        ),
        start=1,
    ):
        vuln = Vulnerability(
            id="CVE-2026-5151",
            summary="Shared advisory with package-scoped remediation",
            severity=Severity.HIGH,
            cvss_score=8.8,
            fixed_version="2.0.0",
        )
        package = Package(name=package_name, version="1.0.0", ecosystem="pypi", vulnerabilities=[vuln])
        server = MCPServer(name=f"owned-server-{index}", packages=[package])
        agent = Agent(
            name=f"owned-agent-{index}",
            agent_type=AgentType.CLAUDE_DESKTOP,
            config_path="",
            mcp_servers=[server],
        )
        radius = BlastRadius(
            vulnerability=vuln,
            package=package,
            affected_servers=[server],
            affected_agents=[agent],
            exposed_credentials=[],
            exposed_tools=[],
        )
        finding = blast_radius_to_finding(radius)
        finding.first_seen = "2026-08-01T00:00:00+00:00"
        finding.owner = owner
        finding.sla_due_at = sla_due_at
        finding.lifecycle_status = "in_progress"
        agents.append(agent)
        radii.append(radius)
        findings.append(finding)
    return AIBOMReport(
        agents=agents,
        blast_radii=radii,
        findings=findings,
        generated_at=datetime(2026, 8, 1, tzinfo=timezone.utc),
        tool_version="0.0.0-test",
    )


def test_finding_additive_lifecycle_status_preserves_legacy_positional_id_slot() -> None:
    template = _owned_report().findings[0]
    legacy_fields = [field for field in dataclasses.fields(Finding) if field.init and field.name != "lifecycle_status"]
    assert legacy_fields[-1].name == "id"
    legacy_args = [getattr(template, field.name) for field in legacy_fields]
    legacy_args[-1] = "legacy-explicit-id"

    reconstructed = Finding(*legacy_args)

    assert reconstructed.id == "legacy-explicit-id"
    assert reconstructed.lifecycle_status is None


def test_triage_owner_lookup_is_bounded_after_one_tenant_read(monkeypatch) -> None:
    matches_calls = 0
    original_matches = VulnException.matches

    def _counted_matches(self, vuln_id: str, package_name: str, server_name: str = "") -> bool:
        nonlocal matches_calls
        matches_calls += 1
        return original_matches(self, vuln_id, package_name, server_name)

    entries = [
        VulnException(
            vuln_id=f"CVE-2026-{index:04d}",
            package_name=f"pkg-{index}",
            server_name=f"server-{index}",
            reason='[finding_triage] {"assignee":"team-%d"}' % index,
            approved_by=f"team-{index}",
            status=ExceptionStatus.ACTIVE,
            tenant_id="tenant-a",
        )
        for index in range(200)
    ]

    class _Store:
        def list_all(self, *, tenant_id: str):
            assert tenant_id == "tenant-a"
            return entries

    monkeypatch.setattr(enterprise, "_get_exception_store", lambda: _Store())
    monkeypatch.setattr(VulnException, "matches", _counted_matches)

    index = enterprise.build_tenant_triage_owner_index("tenant-a")
    owner = enterprise.triage_owner_for(
        index,
        vuln_id="CVE-2026-0199",
        package="pkg-199",
        server_name="server-199",
    )

    assert owner == "team-199"
    assert matches_calls <= 8, "owner joins must be O(findings), not O(findings * triage entries)"


def test_sqlite_triage_lookup_has_tenant_status_match_index(tmp_path) -> None:
    store = SQLiteExceptionStore(str(tmp_path / "exceptions.db"))
    indexes = {row[1] for row in store._conn.execute("PRAGMA index_list('exceptions')").fetchall()}
    assert "idx_exc_tenant_status_match" in indexes


def test_flat_and_human_exports_preserve_owner_sla_and_workflow_status() -> None:
    from agent_bom.output.csv_fmt import to_csv
    from agent_bom.output.html import to_html
    from agent_bom.output.markdown import to_markdown
    from agent_bom.output.pdf import to_pdf

    report = _owned_report()
    row = next(csv.DictReader(io.StringIO(to_csv(report).lstrip("\ufeff"))))
    assert row["owner"] == "payments-security"
    assert row["sla_due_at"] == "2026-08-08T00:00:00+00:00"
    assert row["workflow_status"] == "in_progress"

    for name, rendered in {
        "markdown": to_markdown(report),
        "html": to_html(report),
        "pdf": to_pdf(report).decode("latin-1", "replace"),
    }.items():
        assert "payments-security" in rendered, f"owner dropped by {name}"
        assert "2026-08-08T00:00:00+00:00" in rendered, f"SLA dropped by {name}"
        assert "in_progress" in rendered, f"workflow status dropped by {name}"


def test_machine_interop_exports_preserve_owner_sla_and_workflow_status() -> None:
    from agent_bom.output.cyclonedx_fmt import to_cyclonedx
    from agent_bom.output.ocsf import finding_to_ocsf
    from agent_bom.output.spdx_fmt import to_spdx

    report = _owned_report()
    finding = report.findings[0]
    cdx = to_cyclonedx(report)
    cdx_vuln = next(row for row in cdx["vulnerabilities"] if row["id"] == finding.cve_id)
    assert sum(prop["name"] == "agent-bom:sla_due_at" for prop in cdx_vuln.get("properties", [])) == 1
    cdx_workflow = next(json.loads(prop["value"]) for prop in cdx_vuln.get("properties", []) if prop["name"] == "agent-bom:workflow")
    assert cdx_workflow["affects_ref"] == cdx_vuln["affects"][0]["ref"]
    assert cdx_workflow["owner"] == "payments-security"
    assert cdx_workflow["sla_due_at"] == "2026-08-08T00:00:00+00:00"
    assert cdx_workflow["workflow_status"] == "in_progress"

    spdx = json.dumps(to_spdx(report))
    assert "agent-bom:owner=payments-security" in spdx
    assert "agent-bom:sla-due-at=2026-08-08T00:00:00+00:00" in spdx
    assert "agent-bom:workflow-status=in_progress" in spdx

    ocsf = finding_to_ocsf(finding)
    assert ocsf["unmapped"]["owner"] == "payments-security"
    assert ocsf["unmapped"]["sla_due_at"] == "2026-08-08T00:00:00+00:00"
    assert ocsf["unmapped"]["workflow_status"] == "in_progress"


def test_tenant_assignment_is_joined_before_rescan_document_export(monkeypatch) -> None:
    from agent_bom.api.pipeline import _apply_tenant_workflow_metadata
    from agent_bom.output.cyclonedx_fmt import to_cyclonedx

    store = InMemoryExceptionStore()
    store.put(
        VulnException(
            vuln_id="CVE-2026-4242",
            package_name="owned-lib",
            server_name="owned-server",
            reason='[finding_triage] {"assignee":"payments-security"}',
            approved_by="security-lead",
            status=ExceptionStatus.ACTIVE,
            tenant_id="tenant-a",
        )
    )
    monkeypatch.setattr(enterprise, "_get_exception_store", lambda: store)
    report = _owned_report()
    finding = report.findings[0]
    finding.owner = None
    finding.first_seen = None
    finding.sla_due_at = None
    finding.lifecycle_status = None

    _apply_tenant_workflow_metadata(report, tenant_id="tenant-a")

    assert finding.owner == "payments-security"
    assert finding.first_seen == report.generated_at.isoformat()
    assert finding.lifecycle_status == "open"
    workflow = next(
        json.loads(row["value"])
        for row in to_cyclonedx(report)["vulnerabilities"][0].get("properties", [])
        if row["name"] == "agent-bom:workflow"
    )
    assert workflow["owner"] == "payments-security"
    assert workflow["workflow_status"] == "open"

    other_tenant = _owned_report()
    other_tenant.findings[0].owner = None
    _apply_tenant_workflow_metadata(other_tenant, tenant_id="tenant-b")
    assert other_tenant.findings[0].owner is None


def test_cyclonedx_scopes_shared_cve_workflow_to_each_affected_component() -> None:
    from agent_bom.output.cyclonedx_fmt import to_cyclonedx

    cdx = to_cyclonedx(_shared_cve_report())
    vulnerability = next(row for row in cdx["vulnerabilities"] if row["id"] == "CVE-2026-5151")
    component_refs = {
        component["name"]: component["bom-ref"]
        for component in cdx["components"]
        if component.get("name") in {"payments-lib", "identity-lib"}
    }
    workflow_rows = [json.loads(prop["value"]) for prop in vulnerability.get("properties", []) if prop["name"] == "agent-bom:workflow"]
    workflow_by_ref = {row["affects_ref"]: row for row in workflow_rows}

    assert {row["ref"] for row in vulnerability["affects"]} == set(component_refs.values())
    assert workflow_by_ref[component_refs["payments-lib"]] == {
        "affects_ref": component_refs["payments-lib"],
        "owner": "payments-security",
        "sla_due_at": "2026-08-08T00:00:00+00:00",
        "workflow_status": "in_progress",
    }
    assert workflow_by_ref[component_refs["identity-lib"]] == {
        "affects_ref": component_refs["identity-lib"],
        "owner": "identity-security",
        "sla_due_at": "2026-08-15T00:00:00+00:00",
        "workflow_status": "in_progress",
    }
    property_names = [prop["name"] for prop in vulnerability.get("properties", [])]
    assert "agent-bom:owner" not in property_names
    assert "agent-bom:workflow_status" not in property_names
    assert property_names.count("agent-bom:sla_due_at") == 1
    rendered = json.dumps(cdx)
    assert rendered.count("2026-08-08T00:00:00+00:00") == 1
    assert rendered.count("2026-08-15T00:00:00+00:00") == 1
