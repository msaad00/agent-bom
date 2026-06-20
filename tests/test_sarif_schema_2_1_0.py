"""Validate agent-bom SARIF output against the official SARIF 2.1.0 JSON schema.

agent-bom advertises ``"version": "2.1.0"`` and the OASIS schema URL in every
SARIF log. GitHub Code Scanning rejects logs that drift from the spec. This
suite generates SARIF from a report carrying MULTIPLE finding families
(dependency CVE + cloud CIS + IaC misconfig + credential/secret + AI-inventory)
and asserts the emitted document conforms to the vendored SARIF 2.1.0 schema,
plus the load-bearing required fields GitHub depends on.

The schema is vendored under ``tests/fixtures/sarif-schema-2.1.0.json`` (the
canonical OASIS errata01 artifact) so the suite is hermetic/offline.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from agent_bom.models import (
    Agent,
    AgentType,
    AIBOMReport,
    BlastRadius,
    Package,
    Severity,
    Vulnerability,
)

_SCHEMA_PATH = Path(__file__).parent / "fixtures" / "sarif-schema-2.1.0.json"


@pytest.fixture(scope="module")
def sarif_validator() -> Draft7Validator:
    schema = json.loads(_SCHEMA_PATH.read_text())
    # The vendored SARIF schema declares draft-07; validate with the matching
    # validator so meta-keywords (e.g. ``$ref`` resolution) behave per spec.
    return Draft7Validator(schema)


def _multi_finding_report() -> AIBOMReport:
    """A report spanning CVE + CIS + IaC + secret/SAST + AI-inventory families."""
    vuln = Vulnerability(
        id="CVE-2026-0001",
        summary="Remote code execution in express",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        fixed_version="4.18.0",
        epss_score=0.91,
        epss_percentile=99.0,
        is_kev=True,
        cwe_ids=["CWE-94"],
    )
    pkg = Package(
        name="express",
        version="4.17.1",
        ecosystem="npm",
        purl="pkg:npm/express@4.17.1",
        vulnerabilities=[vuln],
        is_direct=True,
    )
    agent = Agent(
        name="claude-desktop",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/claude-desktop.json",
        mcp_servers=[],
        version="1.0",
    )
    br = BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[],
        affected_agents=[agent],
        exposed_credentials=["AWS_SECRET_ACCESS_KEY"],
        exposed_tools=[],
    )
    br.calculate_risk_score()
    # Tag the blast radius with a compliance framework so a taxonomy is emitted.
    br.owasp_tags = ["LLM05"]

    # Credential-exposure + SAST findings drive the "unified non-CVE findings"
    # SARIF loop (distinct rule_id prefix ``finding/...``).
    secret_finding = Finding(
        finding_type=FindingType.CREDENTIAL_EXPOSURE,
        source=FindingSource.FILESYSTEM,
        asset=Asset(name="config.env", asset_type="package", location="/tmp/app/config.env"),
        severity="high",
        title="Hardcoded AWS secret key",
        description="An AWS secret access key was found committed to the repository.",
        risk_score=8.0,
    )
    sast_finding = Finding(
        finding_type=FindingType.SAST,
        source=FindingSource.SAST,
        asset=Asset(name="db.py", asset_type="package", location="/tmp/app/db.py"),
        severity="medium",
        title="SQL string construction",
        description="A SQL query is built via string concatenation.",
        risk_score=5.0,
    )

    report = AIBOMReport(
        agents=[agent],
        blast_radii=[br],
        findings=[secret_finding, sast_finding],
        scan_sources=["agent_discovery"],
        scan_id="schema-test-001",
    )

    # IaC misconfiguration family.
    report.iac_findings_data = {
        "findings": [
            {
                "rule_id": "DKR-001",
                "severity": "high",
                "file_path": "/tmp/app/Dockerfile",
                "line_number": 3,
                "title": "Container runs as root",
                "message": "No USER directive; container runs as root.",
                "category": "iac",
                "compliance": ["CIS-Docker-4.1"],
            }
        ]
    }

    # Cloud CIS benchmark family.
    report.cis_benchmark_data = {
        "checks": [
            {
                "check_id": "1.4",
                "status": "fail",
                "severity": "high",
                "title": "Ensure no root account access key exists",
                "recommendation": "Remove the root access key.",
                "cis_section": "1.4",
                "resource_ids": ["arn:aws:iam::123456789012:root"],
                "remediation": {
                    "docs": "https://docs.aws.amazon.com/iam",
                    "fix_cli": "aws iam delete-access-key",
                    "effort": "low",
                    "priority": 1,
                },
            }
        ]
    }

    # AI-inventory family (deprecated model / shadow AI).
    report.ai_inventory_data = {
        "components": [
            {
                "type": "deprecated_model",
                "severity": "medium",
                "name": "text-davinci-003",
                "file": "/tmp/app/llm.py",
                "line": 12,
                "description": "Deprecated model in use.",
            }
        ]
    }

    return report


@pytest.fixture(scope="module")
def sarif_doc() -> dict:
    from agent_bom.output.sarif import to_sarif

    return to_sarif(_multi_finding_report())


def test_sarif_conforms_to_official_schema(sarif_doc: dict, sarif_validator: Draft7Validator) -> None:
    """The emitted SARIF validates against the vendored SARIF 2.1.0 schema."""
    errors = sorted(sarif_validator.iter_errors(sarif_doc), key=lambda e: list(e.path))
    if errors:
        rendered = "\n".join(f"  - {'/'.join(str(p) for p in e.path)}: {e.message}" for e in errors[:20])
        pytest.fail(f"SARIF document is not schema-valid ({len(errors)} error(s)):\n{rendered}")


def test_sarif_top_level_required_fields(sarif_doc: dict) -> None:
    assert sarif_doc["version"] == "2.1.0"
    assert sarif_doc["$schema"].endswith("sarif-schema-2.1.0.json")
    assert isinstance(sarif_doc["runs"], list) and len(sarif_doc["runs"]) == 1


def test_sarif_run_has_tool_driver_with_rules(sarif_doc: dict) -> None:
    driver = sarif_doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "agent-bom"
    rules = driver["rules"]
    assert isinstance(rules, list) and rules, "driver must advertise its rule catalog"
    for rule in rules:
        assert rule.get("id"), f"rule missing id: {rule}"


def test_sarif_results_carry_required_fields(sarif_doc: dict) -> None:
    results = sarif_doc["runs"][0]["results"]
    assert results, "expected at least one result"
    rule_ids = {r["ruleId"] for r in results}
    for result in results:
        assert result.get("ruleId"), f"result missing ruleId: {result}"
        assert result.get("level") in {"none", "note", "warning", "error"}, result
        assert result["message"].get("text"), f"result missing message.text: {result}"
        loc = result["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"].get("uri"), result
    # Every advertised result.ruleId must resolve to a rule in the driver catalog.
    catalog = {rule["id"] for rule in sarif_doc["runs"][0]["tool"]["driver"]["rules"]}
    dangling = rule_ids - catalog
    assert not dangling, f"results reference rules absent from the driver catalog: {dangling}"


def test_sarif_spans_multiple_finding_families(sarif_doc: dict) -> None:
    """Confirm the document actually exercised every finding family, so the
    schema-conformance assertion above is meaningful (not a one-rule log)."""
    rule_ids = {r["ruleId"] for r in sarif_doc["runs"][0]["results"]}
    assert "CVE-2026-0001" in rule_ids  # dependency CVE
    assert any(rid.startswith("finding/") for rid in rule_ids)  # secret/SAST
    assert any(rid.startswith("iac/") for rid in rule_ids)  # IaC
    assert any(rid.startswith("cis/") for rid in rule_ids)  # cloud CIS
    assert any(rid.startswith("ai-inventory/") for rid in rule_ids)  # AI inventory
