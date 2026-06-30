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
    MCPServer,
    MCPTool,
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


def _full_chain_report() -> AIBOMReport:
    """A report whose blast radius spans agent → server → package → CVE → tool."""
    vuln = Vulnerability(
        id="GHSA-test-chain",
        summary="Code execution in pillow",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        fixed_version="9.0.1",
    )
    pkg = Package(
        name="pillow",
        version="9.0.0",
        ecosystem="pypi",
        purl="pkg:pypi/pillow@9.0.0",
        vulnerabilities=[vuln],
        is_direct=True,
    )
    server = MCPServer(
        name="database-server",
        tools=[MCPTool(name="run_query", description="Run a SQL query")],
        packages=[pkg],
    )
    agent = Agent(
        name="cursor",
        agent_type=AgentType.CURSOR,
        config_path="/tmp/cursor.json",
        mcp_servers=[server],
        version="1.0",
    )
    br = BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[server],
        affected_agents=[agent],
        exposed_credentials=["DATABASE_URL", "ANTHROPIC_API_KEY"],
        exposed_tools=[MCPTool(name="run_query", description="Run a SQL query")],
    )
    br.calculate_risk_score()
    return AIBOMReport(
        agents=[agent],
        blast_radii=[br],
        scan_sources=["agent_discovery"],
        scan_id="chain-test-001",
    )


def test_sarif_exposure_chain_in_message_and_related_locations() -> None:
    """The agent → server → package → CVE → tool spine is human/machine visible."""
    from agent_bom.output.sarif import to_sarif

    doc = to_sarif(_full_chain_report())
    result = next(r for r in doc["runs"][0]["results"] if r["ruleId"] == "GHSA-test-chain")

    # Human-visible: the chain + blast radius land in the SARIF message text.
    message = result["message"]["text"]
    assert "Exposure path:" in message
    expected_chain = "cursor → database-server → pillow@9.0.0 → GHSA-test-chain → run_query"
    assert expected_chain in message
    assert "Blast radius: 2 cred(s), 1 tool(s) reachable" in message

    # Machine-readable: condensed chain + full exposure_path in the properties bag.
    assert result["properties"]["exposure_chain"] == expected_chain
    assert result["properties"]["exposure_path"]["hops"]

    # Idiomatic SARIF: each hop is a relatedLocation logicalLocation.
    related = result["relatedLocations"]
    fq_names = [loc["logicalLocations"][0]["fullyQualifiedName"] for loc in related]
    assert "agent:cursor" in fq_names
    assert "server:database-server" in fq_names
    assert "tool:run_query" in fq_names


def test_sarif_exposure_chain_document_is_schema_valid(sarif_validator: Draft7Validator) -> None:
    """The exposure-path enrichment keeps the document schema-valid SARIF 2.1.0."""
    from agent_bom.output.sarif import to_sarif

    doc = to_sarif(_full_chain_report())
    errors = sorted(sarif_validator.iter_errors(doc), key=lambda e: list(e.path))
    if errors:
        rendered = "\n".join(f"  - {'/'.join(str(p) for p in e.path)}: {e.message}" for e in errors[:20])
        pytest.fail(f"SARIF document is not schema-valid ({len(errors)} error(s)):\n{rendered}")


def _cloud_cis_report() -> AIBOMReport:
    """A cloud report whose CIS failures flow through BOTH SARIF emission paths.

    ``to_findings()`` lifts every failed cloud CIS check into the unified non-CVE
    stream (``FindingType.CIS_FAIL``) AND the dedicated CIS loop emits each check
    with a per-check rule id. Without de-duplication, every aws/azure/gcp/snowflake
    benchmark failure lands in SARIF twice. databricks CIS + snowflake governance
    have no dedicated loop, so they must still be emitted (exactly once).
    """

    def _benchmark(check_id: str) -> dict:
        return {
            "checks": [
                {
                    "check_id": check_id,
                    "status": "fail",
                    "severity": "high",
                    "title": f"Ensure control {check_id}",
                    "recommendation": f"Fix control {check_id}.",
                    "cis_section": check_id,
                    "resource_ids": [f"resource-{check_id}"],
                    "remediation": {"docs": f"https://example.test/{check_id}", "fix_cli": "fix it", "effort": "low", "priority": 1},
                }
            ]
        }

    report = AIBOMReport(agents=[], blast_radii=[], scan_sources=["cloud"], scan_id="cis-dedup-001")
    report.cis_benchmark_data = _benchmark("1.4")
    report.azure_cis_benchmark_data = _benchmark("2.1")
    report.gcp_cis_benchmark_data = _benchmark("3.2")
    report.snowflake_cis_benchmark_data = _benchmark("4.3")
    # databricks CIS has no dedicated SARIF loop — it rides the unified path only.
    report.databricks_cis_benchmark_data = _benchmark("5.1")
    # snowflake governance findings also ride the unified path only.
    report.snowflake_governance_data = {
        "account": "acme",
        "findings": [
            {
                "category": "write_access",
                "severity": "high",
                "title": "Role has broad write access",
                "description": "A role can write to sensitive objects.",
                "agent_or_role": "ANALYST_ROLE",
                "object_name": "SENSITIVE.PII",
            }
        ],
    }
    return report


def test_sarif_cloud_cis_failure_emitted_once(sarif_validator: Draft7Validator) -> None:
    """Each failed cloud CIS check yields exactly one SARIF result (no duplicate).

    Regression for the double-emission bug: the unified non-CVE loop and the
    dedicated CIS loop both surfaced aws/azure/gcp/snowflake benchmark failures,
    double-counting them in the GitHub Security tab.
    """
    from agent_bom.output.sarif import to_sarif

    doc = to_sarif(_cloud_cis_report())
    results = doc["runs"][0]["results"]

    # No (ruleId, location-uri) pair appears twice anywhere in the document.
    seen: list[tuple[str, str]] = []
    for result in results:
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        seen.append((result["ruleId"], uri))
    assert len(seen) == len(set(seen)), f"duplicate (ruleId, location) SARIF results: {seen}"

    rule_ids = [r["ruleId"] for r in results]
    # Each dedicated-loop provider emits its rich per-check rule exactly once...
    for provider, check_id in (("aws", "1.4"), ("azure", "2.1"), ("gcp", "3.2"), ("snowflake", "4.3")):
        rid = f"cis/{provider}/{check_id}"
        assert rule_ids.count(rid) == 1, f"expected exactly one {rid}, got {rule_ids.count(rid)}"
    # ...and the generic unified CIS rule no longer double-emits those checks.
    # databricks CIS + snowflake governance keep the generic rule (one each).
    assert rule_ids.count("finding/CIS_FAIL") == 2, rule_ids

    # The single aws result keeps the richer structured remediation metadata.
    aws_result = next(r for r in results if r["ruleId"] == "cis/aws/1.4")
    assert aws_result["properties"]["remediation"]["docs"] == "https://example.test/1.4"
    aws_rule = next(r for r in doc["runs"][0]["tool"]["driver"]["rules"] if r["id"] == "cis/aws/1.4")
    assert aws_rule["helpUri"] == "https://example.test/1.4"

    # And the de-duplicated document stays schema-valid SARIF 2.1.0.
    errors = sorted(sarif_validator.iter_errors(doc), key=lambda e: list(e.path))
    assert not errors, [e.message for e in errors[:5]]
