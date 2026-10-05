"""Export/import regressions for source locations and dependency evidence."""

import json

from agent_bom.models import Agent, AgentType, AIBOMReport, BlastRadius, MCPServer, Package, Severity, Vulnerability
from agent_bom.output.cyclonedx_fmt import to_cyclonedx
from agent_bom.output.sarif import to_sarif
from agent_bom.sbom import parse_cyclonedx


def _report(packages, path=""):
    server = MCPServer(name="tools", packages=packages)
    agent = Agent(name="developer", agent_type=AgentType.CUSTOM, config_path=str(path), mcp_servers=[server])
    radii = [
        BlastRadius(
            vulnerability=v, package=p, affected_agents=[agent], affected_servers=[server], exposed_credentials=[], exposed_tools=[]
        )
        for p in packages
        for v in p.vulnerabilities
    ]
    return AIBOMReport(agents=[agent], blast_radii=radii)


def test_sarif_nested_lockfile_provenance_beats_unrelated_root_manifest(tmp_path, monkeypatch):
    (tmp_path / "web").mkdir()
    lock = tmp_path / "web" / "package-lock.json"
    lock.write_text("{}")
    (tmp_path / "requirements.txt").write_text("flask==1.0\n")
    package = Package(
        name="lodash",
        version="4.17.4",
        ecosystem="npm",
        version_evidence=[{"type": "lockfile", "source_file": str(lock)}],
        vulnerabilities=[Vulnerability(id="CVE-2019-10744", severity=Severity.CRITICAL, summary="fixture")],
    )
    monkeypatch.chdir(tmp_path)
    result = to_sarif(_report([package], tmp_path))["runs"][0]["results"][0]
    physical = result["locations"][0]["physicalLocation"]
    assert physical["artifactLocation"]["uri"] == "web/package-lock.json"
    assert "region" not in physical  # no invented line 1 for an unknown location


def test_sarif_unknown_source_does_not_invent_a_manifest(tmp_path, monkeypatch):
    package = Package(
        name="a", version="1", ecosystem="npm", vulnerabilities=[Vulnerability(id="CVE-TEST", severity=Severity.HIGH, summary="fixture")]
    )
    monkeypatch.chdir(tmp_path)
    result = to_sarif(_report([package], tmp_path))["runs"][0]["results"][0]
    assert "physicalLocation" not in result["locations"][0]
    assert result["locations"][0]["logicalLocations"]


def test_cyclonedx_self_import_preserves_package_hierarchy_without_context_packages():
    packages = [
        Package(name="parent", version="1", ecosystem="npm"),
        Package(
            name="child",
            version="2",
            ecosystem="npm",
            is_direct=False,
            parent_package="parent",
            dependency_depth=1,
            reachability_evidence="lockfile",
        ),
        Package(name="orphan", version="3", ecosystem="npm", is_direct=False, reachability_evidence="unknown"),
    ]
    imported = parse_cyclonedx(to_cyclonedx(_report(packages)))
    assert {p.name for p in imported} == {"parent", "child", "orphan"}
    child = next(p for p in imported if p.name == "child")
    orphan = next(p for p in imported if p.name == "orphan")
    assert (child.is_direct, child.parent_package, child.dependency_depth) == (False, "parent", 1)
    assert not orphan.is_direct


def test_cyclonedx_required_scope_does_not_mean_direct_dependency():
    doc = {
        "components": [
            {"bom-ref": "parent", "name": "parent", "version": "1", "type": "library", "scope": "required", "purl": "pkg:npm/parent@1"},
            {"bom-ref": "child", "name": "child", "version": "2", "type": "library", "scope": "required", "purl": "pkg:npm/child@2"},
        ],
        "metadata": {"component": {"bom-ref": "root"}},
        "dependencies": [{"ref": "root", "dependsOn": ["parent"]}, {"ref": "parent", "dependsOn": ["child"]}],
    }
    child = next(p for p in parse_cyclonedx(doc) if p.name == "child")
    assert not child.is_direct and child.parent_package == "parent"


def test_cyclonedx_incomplete_composition_survives_import_export(tmp_path):
    from agent_bom.parsers.sbom_context import load_sbom_agent

    doc = to_cyclonedx(_report([Package(name="orphan", version="1", ecosystem="npm", is_direct=False)]))
    assert doc["compositions"][0]["aggregate"] == "incomplete"
    source = tmp_path / "import.json"
    source.write_text(json.dumps(doc))
    agent, _ = load_sbom_agent(str(source))
    exported = to_cyclonedx(AIBOMReport(agents=[agent]))
    assert exported["compositions"][0]["aggregate"] == "incomplete"


def test_cyclonedx_import_retains_multiple_server_memberships(tmp_path):
    from agent_bom.parsers.sbom_context import load_sbom_agent

    first = Package(name="a", version="1", ecosystem="npm")
    second = Package(name="b", version="2", ecosystem="npm", is_direct=False)
    report = _report([first])
    report.agents[0].mcp_servers.append(MCPServer(name="other-tools", packages=[second]))
    source = tmp_path / "bom.json"
    source.write_text(json.dumps(to_cyclonedx(report)))
    agent, _ = load_sbom_agent(str(source))
    assert {s.name: {p.name for p in s.packages} for s in agent.mcp_servers} == {"tools": {"a"}, "other-tools": {"b"}}
    assert len({server.stable_id for server in agent.mcp_servers}) == 2
    exported = to_cyclonedx(AIBOMReport(agents=[agent]))
    servers = {
        c["name"]: c
        for c in exported["components"]
        if any(p.get("name") == "agent-bom:type" and p.get("value") == "mcp-server" for p in c.get("properties", []))
    }
    assert set(servers) == {"tools", "other-tools"}
    memberships = {
        name: json.loads(next(p["value"] for p in component["properties"] if p["name"] == "agent-bom:inventory-members"))
        for name, component in servers.items()
    }
    assert memberships["tools"] == ["pkg-" + first.stable_id]
    assert memberships["other-tools"] == ["pkg-" + second.stable_id]


def test_cli_no_scan_preserves_imported_findings_and_unknown_reachability(tmp_path):
    from click.testing import CliRunner

    from agent_bom.cli import main

    package = Package(
        name="a",
        version="1",
        ecosystem="npm",
        vulnerabilities=[Vulnerability(id="CVE-TEST", severity=Severity.HIGH, summary="supplied evidence")],
    )
    source = tmp_path / "bom.json"
    source.write_text(json.dumps(to_cyclonedx(_report([package]))))
    output = tmp_path / "report.json"
    result = CliRunner().invoke(main, ["scan", "--sbom", str(source), "--no-scan", "--offline", "-f", "json", "-o", str(output)])
    assert output.exists(), result.output
    data = json.loads(output.read_text())
    assert data["summary"]["total_findings"] == 1
    finding = data["findings"][0]
    assert finding["reachability"] == "unknown"
    assert "direct_agent_dependency" not in str(finding.get("reachability_basis", []))


def test_declared_sbom_edges_do_not_claim_runtime_reachability():
    from agent_bom.graph.reachability_truth import assess_reachability

    for closure in (True, False, None):
        assert (
            assess_reachability(dependency_reachable=closure, direct_dependency=True, affected_agents=True, declaration_only=True).verdict
            == "unknown"
        )


def test_imported_checksums_and_incomplete_inventory_remain_evidence(tmp_path):
    from agent_bom.evidence.scan_run import effective_scan_run
    from agent_bom.parsers.sbom_context import load_sbom_agent

    package = Package(name="a", version="1", ecosystem="npm", checksums={"SHA-256": "ab" * 32})
    doc = to_cyclonedx(_report([package]))
    doc["compositions"][0]["aggregate"] = "incomplete"
    source = tmp_path / "bom.json"
    source.write_text(json.dumps(doc))
    agent, _ = load_sbom_agent(str(source))
    restored = agent.mcp_servers[0].packages[0]
    assert restored.checksums == package.checksums
    assert effective_scan_run(AIBOMReport(agents=[agent])).outcome.value == "partial"


def test_cyclonedx_duplicate_refs_are_rejected():
    import pytest

    doc = {
        "components": [
            {"bom-ref": "same", "name": "a", "version": "1", "purl": "pkg:npm/a@1"},
            {"bom-ref": "same", "name": "b", "version": "2", "purl": "pkg:npm/b@2"},
        ]
    }
    with pytest.raises(ValueError, match="Duplicate CycloneDX component reference"):
        parse_cyclonedx(doc)


def test_api_inventory_import_retains_findings_without_claiming_a_fresh_vulnerability_scan(tmp_path, monkeypatch):
    from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
    from agent_bom.api.pipeline import _run_scan_sync
    from agent_bom.api.store import InMemoryJobStore

    package = Package(
        name="a",
        version="1",
        ecosystem="npm",
        vulnerabilities=[Vulnerability(id="CVE-TEST", severity=Severity.HIGH, summary="supplied evidence")],
    )
    source = tmp_path / "bom.json"
    source.write_text(json.dumps(to_cyclonedx(_report([package]))))
    monkeypatch.setattr("agent_bom.api.pipeline._get_store", lambda: InMemoryJobStore())
    job = ScanJob(
        job_id="import-coverage", created_at="2026-10-05T00:00:00Z", request=ScanRequest(sbom=str(source), no_scan=True, offline=True)
    )
    _run_scan_sync(job)
    assert job.status == JobStatus.DONE
    assert job.result["summary"]["total_findings"] == 1
    assert "Vulnerability scanning skipped by request" in job.result["warnings"]
    assert job.result["findings"][0]["reachability"] == "unknown"


def test_cyclonedx_roundtrip_preserves_multiple_version_specific_parents(tmp_path):
    from agent_bom.parsers.sbom_context import load_sbom_agent

    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "components": [
            {"bom-ref": "a1", "name": "a", "version": "1", "type": "library", "purl": "pkg:npm/a@1"},
            {"bom-ref": "a2", "name": "a", "version": "2", "type": "library", "purl": "pkg:npm/a@2"},
            {"bom-ref": "b", "name": "b", "version": "1", "type": "library", "purl": "pkg:npm/b@1"},
        ],
        "metadata": {"component": {"bom-ref": "root", "name": "app", "type": "application"}},
        "dependencies": [
            {"ref": "root", "dependsOn": ["a1", "a2"]},
            {"ref": "a1", "dependsOn": ["b"]},
            {"ref": "a2", "dependsOn": ["b"]},
        ],
        "compositions": [{"aggregate": "complete"}],
    }
    source = tmp_path / "bom.json"
    source.write_text(json.dumps(doc))
    agent, _ = load_sbom_agent(str(source))
    exported = to_cyclonedx(AIBOMReport(agents=[agent]))
    identities = {c["bom-ref"]: c.get("purl") for c in exported["components"]}
    edges = {(identities[d["ref"]], identities[c]) for d in exported["dependencies"] for c in d["dependsOn"]}
    assert ("pkg:npm/a@1", "pkg:npm/b@1") in edges
    assert ("pkg:npm/a@2", "pkg:npm/b@1") in edges
    assert exported["compositions"][0]["aggregate"] == "complete"


def test_cyclonedx_import_keeps_remediation_as_supplied_evidence():
    vuln = Vulnerability(id="CVE-TEST", summary="reported", severity=Severity.HIGH, fixed_version="2.0", cvss_score=7.5)
    packages = parse_cyclonedx(to_cyclonedx(_report([Package(name="a", version="1", ecosystem="npm", vulnerabilities=[vuln])])))
    imported = packages[0].vulnerabilities[0]
    assert imported.fixed_version == "2.0"
    assert imported.severity_source == "sbom"
    exported = to_cyclonedx(_report(packages))["vulnerabilities"][0]
    assert exported["source"]["name"] == "SBOM"


def test_cyclonedx_nested_components_do_not_disappear():
    doc = {
        "components": [
            {
                "bom-ref": "a",
                "name": "a",
                "version": "1",
                "purl": "pkg:npm/a@1",
                "components": [{"bom-ref": "b", "name": "b", "version": "2", "purl": "pkg:npm/b@2"}],
            }
        ]
    }
    assert {p.name for p in parse_cyclonedx(doc)} == {"a", "b"}
