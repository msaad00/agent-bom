"""Tests for VEX (Vulnerability Exploitability eXchange) support."""

from __future__ import annotations

import json

import pytest

from agent_bom.models import (
    Agent,
    AIBOMReport,
    BlastRadius,
    MCPServer,
    Package,
    Severity,
    Vulnerability,
)
from agent_bom.vex import (
    VexDocument,
    VexJustification,
    VexStatement,
    VexStatus,
    apply_vex,
    export_openvex,
    generate_vex,
    is_vex_suppressed,
    load_vex,
    to_serializable,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _vuln(
    vid: str = "CVE-2024-1234",
    severity: Severity = Severity.HIGH,
    is_kev: bool = False,
    aliases: list[str] | None = None,
) -> Vulnerability:
    return Vulnerability(
        id=vid,
        summary=f"Test vuln {vid}",
        severity=severity,
        is_kev=is_kev,
        aliases=aliases or [],
    )


def _pkg(
    name: str = "test-pkg",
    version: str = "1.0.0",
    ecosystem: str = "npm",
    vulns: list[Vulnerability] | None = None,
) -> Package:
    return Package(
        name=name,
        version=version,
        ecosystem=ecosystem,
        purl=f"pkg:{ecosystem}/{name}@{version}",
        vulnerabilities=vulns or [],
    )


def _server(name: str = "test-server", packages: list[Package] | None = None) -> MCPServer:
    return MCPServer(name=name, command="npx", packages=packages or [])


def _agent(name: str = "agent-a", servers: list[MCPServer] | None = None) -> Agent:
    return Agent(name=name, agent_type="claude-desktop", config_path="/tmp/test", mcp_servers=servers or [])


def _report(vulns: list[tuple[Vulnerability, Package]] | None = None) -> AIBOMReport:
    """Build a minimal report with vulns assigned to packages."""
    if not vulns:
        return AIBOMReport()

    seen_pkgs: dict[str, Package] = {}
    blast_radii = []
    for vuln, pkg in vulns:
        if vuln not in pkg.vulnerabilities:
            pkg.vulnerabilities.append(vuln)
        seen_pkgs[f"{pkg.name}@{pkg.version}"] = pkg
        blast_radii.append(
            BlastRadius(
                vulnerability=vuln,
                package=pkg,
                affected_servers=[],
                affected_agents=[],
                exposed_credentials=[],
                exposed_tools=[],
            )
        )

    server = _server(packages=list(seen_pkgs.values()))
    agent = _agent(servers=[server])
    return AIBOMReport(agents=[agent], blast_radii=blast_radii)


# ---------------------------------------------------------------------------
# TestVexStatus
# ---------------------------------------------------------------------------


class TestVexStatus:
    def test_all_statuses(self):
        assert VexStatus.AFFECTED.value == "affected"
        assert VexStatus.NOT_AFFECTED.value == "not_affected"
        assert VexStatus.FIXED.value == "fixed"
        assert VexStatus.UNDER_INVESTIGATION.value == "under_investigation"

    def test_all_justifications(self):
        assert VexJustification.COMPONENT_NOT_PRESENT.value == "component_not_present"
        assert VexJustification.VULNERABLE_CODE_NOT_PRESENT.value == "vulnerable_code_not_present"
        assert VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH.value == "vulnerable_code_not_in_execute_path"
        assert (
            VexJustification.VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY.value == "vulnerable_code_cannot_be_controlled_by_adversary"
        )
        assert VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST.value == "inline_mitigations_already_exist"

    def test_statement_auto_timestamp(self):
        stmt = VexStatement(vulnerability_id="CVE-2024-0001", status=VexStatus.AFFECTED)
        assert stmt.timestamp != ""
        assert "T" in stmt.timestamp  # ISO 8601

    def test_statement_default_author(self):
        stmt = VexStatement(vulnerability_id="CVE-2024-0001", status=VexStatus.AFFECTED)
        assert stmt.author == "agent-bom"

    def test_document_auto_metadata(self):
        doc = VexDocument()
        assert "id" in doc.metadata
        assert doc.metadata["id"].startswith("urn:uuid:")
        assert doc.metadata["author"] == "agent-bom"
        assert doc.metadata["version"] == 1


# ---------------------------------------------------------------------------
# TestVexLoad
# ---------------------------------------------------------------------------


class TestVexLoad:
    def test_load_openvex_format(self, tmp_path):
        data = {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": "urn:uuid:test-doc",
            "author": "test-author",
            "timestamp": "2024-01-01T00:00:00Z",
            "version": 1,
            "statements": [
                {
                    "vulnerability": {"name": "CVE-2024-1234"},
                    "status": "not_affected",
                    "justification": "component_not_present",
                    "impact_statement": "Component not used",
                    "products": [{"@id": "pkg:npm/express@4.18.2"}],
                    "timestamp": "2024-01-01T00:00:00Z",
                }
            ],
        }
        path = tmp_path / "vex.json"
        path.write_text(json.dumps(data))
        doc = load_vex(str(path))
        assert len(doc.statements) == 1
        assert doc.statements[0].vulnerability_id == "CVE-2024-1234"
        assert doc.statements[0].status == VexStatus.NOT_AFFECTED
        assert doc.statements[0].justification == VexJustification.COMPONENT_NOT_PRESENT
        assert doc.statements[0].products == ["pkg:npm/express@4.18.2"]
        assert doc.metadata["id"] == "urn:uuid:test-doc"
        assert doc.metadata["author"] == "test-author"

    def test_load_simplified_format(self, tmp_path):
        data = {
            "statements": [
                {
                    "vulnerability_id": "CVE-2024-5678",
                    "status": "affected",
                    "action_statement": "Upgrade to 2.0.0",
                }
            ]
        }
        path = tmp_path / "vex.json"
        path.write_text(json.dumps(data))
        doc = load_vex(str(path))
        assert len(doc.statements) == 1
        assert doc.statements[0].vulnerability_id == "CVE-2024-5678"
        assert doc.statements[0].status == VexStatus.AFFECTED
        assert doc.statements[0].action_statement == "Upgrade to 2.0.0"

    def test_load_unknown_status_raises(self, tmp_path):
        data = {"statements": [{"vulnerability_id": "CVE-2024-0001", "status": "bogus_status"}]}
        path = tmp_path / "vex.json"
        path.write_text(json.dumps(data))
        with pytest.raises(ValueError, match="Unknown VEX status"):
            load_vex(str(path))

    def test_load_unknown_justification_ignored(self, tmp_path):
        data = {
            "statements": [
                {
                    "vulnerability_id": "CVE-2024-0001",
                    "status": "not_affected",
                    "justification": "bogus_justification",
                }
            ]
        }
        path = tmp_path / "vex.json"
        path.write_text(json.dumps(data))
        doc = load_vex(str(path))
        assert doc.statements[0].justification is None

    def test_load_empty_statements(self, tmp_path):
        data = {"statements": []}
        path = tmp_path / "vex.json"
        path.write_text(json.dumps(data))
        doc = load_vex(str(path))
        assert len(doc.statements) == 0

    def test_load_multiple_statements(self, tmp_path):
        data = {
            "statements": [
                {"vulnerability_id": "CVE-2024-0001", "status": "affected"},
                {"vulnerability_id": "CVE-2024-0002", "status": "fixed"},
                {"vulnerability_id": "CVE-2024-0003", "status": "not_affected", "justification": "vulnerable_code_not_present"},
            ]
        }
        path = tmp_path / "vex.json"
        path.write_text(json.dumps(data))
        doc = load_vex(str(path))
        assert len(doc.statements) == 3
        assert doc.statements[1].status == VexStatus.FIXED

    def test_load_openvex_with_vulnerability_id_key(self, tmp_path):
        """OpenVEX with vulnerability.id instead of vulnerability.name."""
        data = {
            "statements": [
                {
                    "vulnerability": {"id": "GHSA-abcd-efgh"},
                    "status": "under_investigation",
                }
            ]
        }
        path = tmp_path / "vex.json"
        path.write_text(json.dumps(data))
        doc = load_vex(str(path))
        assert doc.statements[0].vulnerability_id == "GHSA-abcd-efgh"


# ---------------------------------------------------------------------------
# TestVexGenerate
# ---------------------------------------------------------------------------


class TestVexGenerate:
    def test_generate_empty_report(self):
        report = AIBOMReport()
        doc = generate_vex(report)
        assert len(doc.statements) == 0

    def test_generate_under_investigation_default(self):
        vuln = _vuln("CVE-2024-1234")
        pkg = _pkg(vulns=[vuln])
        report = _report([(vuln, pkg)])
        doc = generate_vex(report)
        assert len(doc.statements) == 1
        assert doc.statements[0].status == VexStatus.UNDER_INVESTIGATION
        assert doc.statements[0].vulnerability_id == "CVE-2024-1234"

    def test_generate_kev_auto_triage(self):
        vuln = _vuln("CVE-2024-9999", is_kev=True)
        pkg = _pkg(vulns=[vuln])
        report = _report([(vuln, pkg)])
        doc = generate_vex(report, auto_triage=True)
        assert len(doc.statements) == 1
        assert doc.statements[0].status == VexStatus.AFFECTED
        assert "KEV" in doc.statements[0].action_statement

    def test_generate_non_kev_auto_triage(self):
        vuln = _vuln("CVE-2024-1111")
        pkg = _pkg(vulns=[vuln])
        report = _report([(vuln, pkg)])
        doc = generate_vex(report, auto_triage=True)
        assert doc.statements[0].status == VexStatus.UNDER_INVESTIGATION

    def test_generate_deduplicates_vulns(self):
        vuln = _vuln("CVE-2024-1234")
        pkg1 = _pkg(name="pkg-a", vulns=[vuln])
        pkg2 = _pkg(name="pkg-b", vulns=[vuln])
        report = _report([(vuln, pkg1), (vuln, pkg2)])
        doc = generate_vex(report)
        # Same vuln ID should appear only once
        assert len(doc.statements) == 1

    def test_generate_includes_products(self):
        vuln = _vuln("CVE-2024-1234")
        pkg = _pkg(name="express", version="4.18.2", ecosystem="npm", vulns=[vuln])
        report = _report([(vuln, pkg)])
        doc = generate_vex(report)
        assert len(doc.statements[0].products) == 1
        assert "express" in doc.statements[0].products[0]

    def test_generate_timestamp_format(self):
        vuln = _vuln("CVE-2024-1234")
        pkg = _pkg(vulns=[vuln])
        report = _report([(vuln, pkg)])
        doc = generate_vex(report)
        assert doc.metadata.get("timestamp")
        assert "T" in doc.metadata["timestamp"]

    def test_generate_multiple_vulns(self):
        vuln1 = _vuln("CVE-2024-0001", severity=Severity.CRITICAL, is_kev=True)
        vuln2 = _vuln("CVE-2024-0002", severity=Severity.MEDIUM)
        pkg = _pkg(vulns=[vuln1, vuln2])
        report = _report([(vuln1, pkg), (vuln2, pkg)])
        doc = generate_vex(report, auto_triage=True)
        assert len(doc.statements) == 2
        statuses = {s.vulnerability_id: s.status for s in doc.statements}
        assert statuses["CVE-2024-0001"] == VexStatus.AFFECTED
        assert statuses["CVE-2024-0002"] == VexStatus.UNDER_INVESTIGATION


# ---------------------------------------------------------------------------
# TestVexApply
# ---------------------------------------------------------------------------


class TestVexApply:
    def test_apply_sets_status(self):
        vuln = _vuln("CVE-2024-1234")
        pkg = _pkg(vulns=[vuln])
        report = _report([(vuln, pkg)])

        doc = VexDocument(
            statements=[
                VexStatement(
                    vulnerability_id="CVE-2024-1234",
                    status=VexStatus.NOT_AFFECTED,
                    justification=VexJustification.COMPONENT_NOT_PRESENT,
                )
            ]
        )
        count = apply_vex(report, doc)
        assert count == 1
        assert vuln.vex_status == "not_affected"
        assert vuln.vex_justification == "component_not_present"

    def test_apply_unmatched_unchanged(self):
        vuln = _vuln("CVE-2024-9999")
        pkg = _pkg(vulns=[vuln])
        report = _report([(vuln, pkg)])

        doc = VexDocument(statements=[VexStatement(vulnerability_id="CVE-2024-0000", status=VexStatus.FIXED)])
        count = apply_vex(report, doc)
        assert count == 0
        assert vuln.vex_status is None

    def test_apply_matches_by_alias(self):
        vuln = _vuln("CVE-2024-1234", aliases=["GHSA-abcd-efgh"])
        pkg = _pkg(vulns=[vuln])
        report = _report([(vuln, pkg)])

        doc = VexDocument(statements=[VexStatement(vulnerability_id="GHSA-abcd-efgh", status=VexStatus.FIXED)])
        count = apply_vex(report, doc)
        assert count == 1
        assert vuln.vex_status == "fixed"

    def test_apply_without_justification(self):
        vuln = _vuln("CVE-2024-1234")
        pkg = _pkg(vulns=[vuln])
        report = _report([(vuln, pkg)])

        doc = VexDocument(statements=[VexStatement(vulnerability_id="CVE-2024-1234", status=VexStatus.AFFECTED)])
        count = apply_vex(report, doc)
        assert count == 1
        assert vuln.vex_status == "affected"
        assert vuln.vex_justification is None

    def test_apply_multiple_vulns(self):
        vuln1 = _vuln("CVE-2024-0001")
        vuln2 = _vuln("CVE-2024-0002")
        pkg = _pkg(vulns=[vuln1, vuln2])
        report = _report([(vuln1, pkg), (vuln2, pkg)])

        doc = VexDocument(
            statements=[
                VexStatement(vulnerability_id="CVE-2024-0001", status=VexStatus.FIXED),
                VexStatement(
                    vulnerability_id="CVE-2024-0002",
                    status=VexStatus.NOT_AFFECTED,
                    justification=VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
                ),
            ]
        )
        count = apply_vex(report, doc)
        assert count == 2
        assert vuln1.vex_status == "fixed"
        assert vuln2.vex_status == "not_affected"

    def test_apply_empty_document(self):
        vuln = _vuln("CVE-2024-1234")
        pkg = _pkg(vulns=[vuln])
        report = _report([(vuln, pkg)])
        doc = VexDocument()
        count = apply_vex(report, doc)
        assert count == 0


# ---------------------------------------------------------------------------
# TestVexExport
# ---------------------------------------------------------------------------


class TestVexExport:
    def test_export_openvex_format(self):
        doc = VexDocument(
            statements=[
                VexStatement(
                    vulnerability_id="CVE-2024-1234",
                    status=VexStatus.NOT_AFFECTED,
                    justification=VexJustification.COMPONENT_NOT_PRESENT,
                    products=["pkg:npm/express@4.18.2"],
                )
            ]
        )
        result = export_openvex(doc)
        assert result["@context"] == "https://openvex.dev/ns/v0.2.0"
        assert "@id" in result
        assert len(result["statements"]) == 1
        stmt = result["statements"][0]
        assert stmt["vulnerability"]["name"] == "CVE-2024-1234"
        assert stmt["status"] == "not_affected"
        assert stmt["justification"] == "component_not_present"
        assert stmt["products"] == [{"@id": "pkg:npm/express@4.18.2"}]

    def test_export_openvex_no_justification(self):
        doc = VexDocument(statements=[VexStatement(vulnerability_id="CVE-2024-5678", status=VexStatus.AFFECTED)])
        result = export_openvex(doc)
        stmt = result["statements"][0]
        assert "justification" not in stmt

    def test_export_roundtrip(self, tmp_path):
        """Export to OpenVEX JSON, write to file, reload."""
        doc = VexDocument(
            statements=[
                VexStatement(
                    vulnerability_id="CVE-2024-1234",
                    status=VexStatus.NOT_AFFECTED,
                    justification=VexJustification.VULNERABLE_CODE_NOT_PRESENT,
                    impact_statement="Test impact",
                    products=["pkg:npm/test@1.0.0"],
                ),
                VexStatement(
                    vulnerability_id="CVE-2024-5678",
                    status=VexStatus.AFFECTED,
                    action_statement="Upgrade to 2.0.0",
                ),
            ]
        )
        exported = export_openvex(doc)
        path = tmp_path / "roundtrip.json"
        path.write_text(json.dumps(exported))

        reloaded = load_vex(str(path))
        assert len(reloaded.statements) == 2
        assert reloaded.statements[0].vulnerability_id == "CVE-2024-1234"
        assert reloaded.statements[0].status == VexStatus.NOT_AFFECTED
        assert reloaded.statements[0].justification == VexJustification.VULNERABLE_CODE_NOT_PRESENT
        assert reloaded.statements[1].vulnerability_id == "CVE-2024-5678"
        assert reloaded.statements[1].status == VexStatus.AFFECTED

    def test_export_empty_products(self):
        doc = VexDocument(statements=[VexStatement(vulnerability_id="CVE-2024-1234", status=VexStatus.FIXED)])
        result = export_openvex(doc)
        assert result["statements"][0]["products"] == []


# ---------------------------------------------------------------------------
# TestSerialization
# ---------------------------------------------------------------------------


class TestSerialization:
    def test_to_serializable_basic(self):
        doc = VexDocument(
            statements=[
                VexStatement(vulnerability_id="CVE-2024-1234", status=VexStatus.AFFECTED),
                VexStatement(
                    vulnerability_id="CVE-2024-5678", status=VexStatus.NOT_AFFECTED, justification=VexJustification.COMPONENT_NOT_PRESENT
                ),
            ]
        )
        data = to_serializable(doc)
        assert len(data["statements"]) == 2
        assert data["stats"]["total_statements"] == 2
        assert data["stats"]["affected"] == 1
        assert data["stats"]["not_affected"] == 1
        assert data["stats"]["fixed"] == 0
        assert data["stats"]["under_investigation"] == 0

    def test_to_serializable_empty(self):
        doc = VexDocument()
        data = to_serializable(doc)
        assert data["statements"] == []
        assert data["stats"]["total_statements"] == 0

    def test_to_serializable_metadata(self):
        doc = VexDocument()
        data = to_serializable(doc)
        assert "metadata" in data
        assert data["metadata"]["author"] == "agent-bom"

    def test_to_serializable_json_safe(self):
        """Ensure output is JSON-serializable."""
        doc = VexDocument(
            statements=[
                VexStatement(vulnerability_id="CVE-2024-1234", status=VexStatus.FIXED, products=["pkg:npm/test@1.0.0"]),
            ]
        )
        data = to_serializable(doc)
        json_str = json.dumps(data)
        assert "CVE-2024-1234" in json_str


# ---------------------------------------------------------------------------
# VEX Enforcement — is_vex_suppressed
# ---------------------------------------------------------------------------


class TestIsVexSuppressed:
    def test_not_affected_is_suppressed(self):
        v = _vuln("CVE-2024-0001")
        v.vex_status = "not_affected"
        assert is_vex_suppressed(v) is True

    def test_fixed_is_suppressed(self):
        v = _vuln("CVE-2024-0002", severity=Severity.CRITICAL)
        v.vex_status = "fixed"
        assert is_vex_suppressed(v) is True

    def test_affected_is_not_suppressed(self):
        v = _vuln("CVE-2024-0003")
        v.vex_status = "affected"
        assert is_vex_suppressed(v) is False

    def test_under_investigation_is_not_suppressed(self):
        v = _vuln("CVE-2024-0004", severity=Severity.MEDIUM)
        v.vex_status = "under_investigation"
        assert is_vex_suppressed(v) is False

    def test_no_vex_status_is_not_suppressed(self):
        v = _vuln("CVE-2024-0005", severity=Severity.LOW)
        assert is_vex_suppressed(v) is False

    def test_none_vex_status_is_not_suppressed(self):
        v = _vuln("CVE-2024-0006")
        v.vex_status = None
        assert is_vex_suppressed(v) is False

    def test_apply_then_suppress(self):
        """Full flow: apply VEX, then check suppression."""
        vuln = _vuln("CVE-2024-1000", severity=Severity.CRITICAL)
        pkg = _pkg(vulns=[vuln])
        server = _server(packages=[pkg])
        agent = _agent(servers=[server])
        report = AIBOMReport(agents=[agent])

        doc = VexDocument(
            statements=[
                VexStatement(
                    vulnerability_id="CVE-2024-1000",
                    status=VexStatus.NOT_AFFECTED,
                    justification=VexJustification.VULNERABLE_CODE_NOT_PRESENT,
                ),
            ]
        )
        count = apply_vex(report, doc)
        assert count == 1
        assert is_vex_suppressed(vuln) is True

    def test_suppressed_vulns_excluded_from_active_count(self):
        """Active blast radii exclude VEX-suppressed vulnerabilities."""
        v1 = _vuln("CVE-2024-A", severity=Severity.CRITICAL)
        v1.vex_status = "not_affected"
        v2 = _vuln("CVE-2024-B")
        v3 = _vuln("CVE-2024-C", severity=Severity.MEDIUM)
        v3.vex_status = "fixed"

        all_vulns = [v1, v2, v3]
        active = [v for v in all_vulns if not is_vex_suppressed(v)]
        assert len(active) == 1
        assert active[0].id == "CVE-2024-B"
