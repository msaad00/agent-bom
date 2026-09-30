"""Installed-package self scans have an identity, not a source file location."""

import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

from agent_bom.models import Agent, AIBOMReport, BlastRadius, Package, Severity, Vulnerability
from agent_bom.output.sarif import to_sarif


def _report(config_path: str, manifest: str | None = None) -> AIBOMReport:
    vuln = Vulnerability(id="CVE-2026-97687", summary="Proxy TLS isolation", severity=Severity.HIGH, fixed_version="2.8.0")
    pkg = Package(name="urllib3", version="2.7.0", ecosystem="pypi", vulnerabilities=[vuln])
    if manifest:
        pkg.version_evidence = [{"type": "manifest", "source_file": manifest, "line": 3}]
    agent = Agent(name="agent-bom", agent_type="cli", config_path=config_path, mcp_servers=[])
    blast = BlastRadius(
        vulnerability=vuln, package=pkg, affected_agents=[agent], affected_servers=[], exposed_credentials=[], exposed_tools=[]
    )
    return AIBOMReport(agents=[agent], blast_radii=[blast])


def test_self_scan_advisory_has_logical_identity_and_stable_fingerprint(tmp_path, monkeypatch):
    report = _report("self-scan://agent-bom")
    doc = to_sarif(report)
    result = doc["runs"][0]["results"][0]
    assert result["ruleId"] == "CVE-2026-97687"
    assert result["level"] == "error"
    assert "physicalLocation" not in result["locations"][0]
    assert result["locations"][0]["logicalLocations"][0]["fullyQualifiedName"] == "self-scan://agent-bom"
    assert "partialFingerprints" not in result  # No invented source line hash.
    assert result["fingerprints"]["agent-bom/v1"]
    schema = json.loads((Path(__file__).parent / "fixtures/sarif-schema-2.1.0.json").read_text())
    Draft7Validator(schema).validate(doc)
    monkeypatch.chdir(tmp_path)
    again = to_sarif(report)["runs"][0]["results"][0]
    assert again["fingerprints"] == result["fingerprints"]
    assert again["locations"] == result["locations"]


@pytest.mark.parametrize("config_path", ["self-scan://agent-bom", "agent-config.json"])
def test_real_package_manifest_retains_physical_location(config_path, tmp_path):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("# dependencies\n# vulnerable package\nurllib3==2.7.0\n")
    result = to_sarif(_report(config_path, str(manifest)))["runs"][0]["results"][0]
    physical = result["locations"][0]["physicalLocation"]
    assert physical["artifactLocation"] == {"uri": "requirements.txt", "uriBaseId": "%SRCROOT%"}
    assert physical["region"]["startLine"] == 3
    assert result["partialFingerprints"]["primaryLocationLineHash"]
