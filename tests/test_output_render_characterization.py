"""Byte-exact characterization goldens for the SARIF and HTML graph renderers.

The goldens pin the serialized bytes each renderer produces, not a normalized
view: key order, whitespace and escaping are all part of the contract. Volatile
inputs (timestamps, tool version, scan id, first-seen anchors) are injected as
fixed values before rendering, so a golden only changes when rendering does.

Regenerate after an intentional output change with::

    AGENT_BOM_UPDATE_OUTPUT_GOLDENS=1 pytest tests/test_output_render_characterization.py
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import pytest
from click.testing import CliRunner

import agent_bom.output.sarif as sarif_module
from agent_bom.cli import main
from agent_bom.evidence.scan_run import ScanIssue
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
from agent_bom.output.html import render_graph_script, to_html
from agent_bom.output.sarif import export_sarif, to_sarif

GOLDEN_DIR = Path(__file__).parent / "fixtures" / "output_render"
MANIFEST = GOLDEN_DIR / "manifest.json"
UPDATE = os.environ.get("AGENT_BOM_UPDATE_OUTPUT_GOLDENS") == "1"
PINNED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
ROOT = "/tmp/output-golden"


def _pin(report: AIBOMReport, scan_id: str) -> AIBOMReport:
    report.generated_at = PINNED_AT
    report.tool_version = "0.0.0-golden"
    report.scan_id = scan_id
    for finding in report.findings:
        finding.first_seen = PINNED_AT.isoformat()
    return report


def _empty_report() -> AIBOMReport:
    return _pin(AIBOMReport(), "")


def _vuln(vuln_id: str, severity: Severity, **kwargs: object) -> Vulnerability:
    return Vulnerability(id=vuln_id, summary=f"{vuln_id} summary", severity=severity, **kwargs)  # type: ignore[arg-type]


def _rich_report() -> AIBOMReport:
    kev = _vuln(
        "CVE-2026-1001",
        Severity.CRITICAL,
        cvss_score=9.8,
        fixed_version="4.18.0",
        epss_score=0.91,
        epss_percentile=99.0,
        is_kev=True,
        kev_date_added="2026-01-01",
        kev_due_date="2026-01-22",
        cwe_ids=["CWE-94"],
    )
    unfixable = _vuln("CVE-2026-1002", Severity.HIGH, cvss_score=7.5, cwe_ids=["CWE-400"])
    vex_suppressed = _vuln(
        "GHSA-aaaa-bbbb-cccc",
        Severity.MEDIUM,
        cvss_score=5.3,
        fixed_version="2.0.1",
        vex_status="not_affected",
        vex_justification="vulnerable_code_not_in_execute_path",
    )
    express = Package(
        name="express",
        version="4.17.1",
        ecosystem="npm",
        purl="pkg:npm/express@4.17.1",
        vulnerabilities=[kev, unfixable],
        is_direct=True,
    )
    requests_pkg = Package(
        name="requests",
        version="2.19.0",
        ecosystem="pypi",
        purl="pkg:pypi/requests@2.19.0",
        vulnerabilities=[vex_suppressed],
    )
    tool = MCPTool(name="read_file", description="Read a file from disk")
    fs_server = MCPServer(
        name="filesystem",
        command="npx",
        args=["-y", "@modelcontextprotocol/server-filesystem"],
        env={"API_TOKEN": "${API_TOKEN}"},
        tools=[tool],
        packages=[express],
        config_path=f"{ROOT}/claude.json",
    )
    py_server = MCPServer(name="fetcher", command="uvx", args=["fetcher"], packages=[requests_pkg], config_path=f"{ROOT}/cursor.json")
    desktop = Agent(
        name="claude-desktop",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path=f"{ROOT}/claude.json",
        mcp_servers=[fs_server],
        version="1.0",
    )
    cursor = Agent(
        name="cursor",
        agent_type=AgentType.CURSOR,
        config_path=f"{ROOT}/cursor.json",
        mcp_servers=[py_server],
        version="2.0",
    )
    reachable = BlastRadius(
        vulnerability=kev,
        package=express,
        affected_servers=[fs_server],
        affected_agents=[desktop],
        exposed_credentials=["API_TOKEN"],
        exposed_tools=[tool],
        owasp_tags=["LLM05"],
        attack_tags=["T1190"],
        graph_reachable=True,
        graph_min_hop_distance=2,
        graph_reachable_from_agents=["claude-desktop"],
        symbol_reachability="function_reachable",
        reachable_affected_symbols=["express.static"],
    )
    reachable.calculate_risk_score()
    unfixable_radius = BlastRadius(
        vulnerability=unfixable,
        package=express,
        affected_servers=[fs_server],
        affected_agents=[desktop],
        exposed_credentials=[],
        exposed_tools=[],
    )
    unfixable_radius.calculate_risk_score()
    suppressed_radius = BlastRadius(
        vulnerability=vex_suppressed,
        package=requests_pkg,
        affected_servers=[py_server],
        affected_agents=[cursor],
        exposed_credentials=[],
        exposed_tools=[],
        suppressed=True,
        suppression_id="3f1c2b4a-5d6e-4f70-8a9b-0c1d2e3f4a5b",
        suppression_state="accepted_risk",
        suppression_reason="Not reachable in production",
        unsuppressed_risk_score=5.1,
    )
    suppressed_radius.calculate_risk_score()

    findings = [
        Finding(
            finding_type=FindingType.CREDENTIAL_EXPOSURE,
            source=FindingSource.FILESYSTEM,
            asset=Asset(name="config.env", asset_type="package", location=f"{ROOT}/app/config.env"),
            severity="high",
            title="Hardcoded AWS secret key",
            description="An AWS secret access key was found committed to the repository.",
            risk_score=8.0,
            evidence={"line_number": 4},
        ),
        Finding(
            finding_type=FindingType.SAST,
            source=FindingSource.SAST,
            asset=Asset(name="db.py", asset_type="source_file", location="src/app/db.py"),
            severity="medium",
            title="SQL string construction",
            description="A SQL query is built via string concatenation.",
            risk_score=5.0,
            cwe_ids=["CWE-89"],
            evidence={
                "rule_id": "AB-SAST-002",
                "line_number": 41,
                "category": "sql_injection",
                "entrypoint": "handler",
                "sink": "cursor.execute",
                "source": "request.args",
                "call_path": ["handler", "build_query", "cursor.execute"],
                "detector_categories": ["taint"],
            },
        ),
        Finding(
            finding_type=FindingType.CREDENTIAL_EXPOSURE,
            source=FindingSource.MCP_SCAN,
            asset=Asset(name="payments-agent", asset_type="agent"),
            severity="critical",
            title="Agent exposes a production credential",
            description="The agent can expose a production credential.",
            evidence={"category": "agent_credential_exposure"},
            suppressed=True,
            suppression_id="not-a-guid",
            suppression_state="false_positive",
            suppression_reason="Credential is a test fixture",
        ),
        Finding(
            finding_type=FindingType.CVE,
            source=FindingSource.SBOM,
            asset=Asset(name="imported-advisory", asset_type="package"),
            severity="high",
            title="Imported advisory without a package",
            description="An imported advisory could not be resolved to a package.",
            cve_id="CVE-2026-1003",
            evidence={"package_resolution": "unresolved"},
        ),
        Finding(
            finding_type=FindingType.CIS_FAIL,
            source=FindingSource.CLOUD_CIS,
            asset=Asset(name="root", asset_type="cloud_resource"),
            severity="high",
            title="Dedicated CIS check handled by the CIS loop",
            evidence={"benchmark": "CIS", "provider": "aws"},
        ),
        Finding(
            finding_type=FindingType.CIS_FAIL,
            source=FindingSource.CLOUD_CIS,
            asset=Asset(name="Dockerfile", asset_type="iac"),
            severity="high",
            title="IaC finding handled by the IaC loop",
            evidence={"iac": True},
        ),
        Finding(
            finding_type=FindingType.CIS_FAIL,
            source=FindingSource.CLOUD_CIS,
            asset=Asset(name="workspace", asset_type="cloud_resource"),
            severity="low",
            title="Databricks CIS check",
            description="Databricks workspace allows personal access tokens.",
            remediation_guidance="Disable personal access tokens.",
            evidence={"benchmark": "CIS", "provider": "databricks"},
        ),
    ]
    report = AIBOMReport(
        agents=[desktop, cursor],
        blast_radii=[reachable, unfixable_radius, suppressed_radius],
        findings=findings,
        scan_sources=["agent_discovery", "sast"],
    )
    report.iac_findings_data = {
        "findings": [
            {
                "rule_id": "DKR-001",
                "severity": "high",
                "file_path": f"{ROOT}/app/Dockerfile",
                "line_number": 3,
                "title": "Container runs as root",
                "message": "No USER directive; container runs as root.",
                "category": "iac",
                "compliance": ["CIS-Docker-4.1"],
                "remediation": "Add a non-root USER directive.",
            },
            {
                "rule_id": "DKR-001",
                "severity": "high",
                "file_path": f"{ROOT}/svc/Dockerfile",
                "title": "Container runs as root",
            },
            {"rule_id": "K8S-010", "severity": "LOW", "file_path": "", "title": "Pod lacks resource limits"},
        ]
    }
    report.ai_inventory_data = {
        "components": [
            {
                "type": "deprecated_model",
                "severity": "medium",
                "name": "text-davinci-003",
                "file": f"{ROOT}/app/llm.py",
                "line": 12,
                "description": "Deprecated model in use.",
                "recommendation": "Migrate to a supported model.",
            },
            {"type": "api_key", "severity": "critical", "name": "sk-live-0000", "file": f"{ROOT}/app/keys.py"},
            {"type": "sdk_import", "severity": "info", "name": "openai", "file": f"{ROOT}/app/llm.py"},
        ]
    }
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
                "evidence": "Root access key present",
                "remediation": {
                    "docs": "https://docs.aws.amazon.com/iam",
                    "fix_cli": "aws iam delete-access-key",
                    "effort": "low",
                    "priority": 1,
                    "guardrails": ["confirm break-glass access"],
                    "requires_human_review": True,
                },
            },
            {"check_id": "1.5", "status": "pass", "severity": "high", "title": "MFA on root"},
        ]
    }
    report.azure_cis_benchmark_data = {"checks": [{"check_id": "2.1", "status": "fail", "title": "Defender plan off"}]}
    report.trust_assessment_data = {"verdict": "review", "confidence": "medium", "internal_only": "dropped"}
    report.coverage_warnings = [{"ecosystem": "pypi", "release": "osv-2026-01", "detail": "Partial advisory coverage"}]
    report.scan_run.add_issue(
        ScanIssue(code="registry_timeout", stage="enrichment", source="registry", message="Registry lookup timed out", severity="warning")
    )
    return _pin(report, "golden-rich")


def _demo_report() -> AIBOMReport:
    captured: dict[str, AIBOMReport] = {}
    original = sarif_module.to_sarif

    def capture(report: AIBOMReport, **kwargs: object) -> dict:
        captured["report"] = report
        return original(report, **kwargs)  # type: ignore[arg-type]

    with (
        mock.patch.object(sarif_module, "to_sarif", capture),
        mock.patch("agent_bom.db.local_analytics.record_scan_report_best_effort", lambda *_a, **_k: None),
    ):
        out = Path(ROOT) / "demo.sarif"
        out.parent.mkdir(parents=True, exist_ok=True)
        CliRunner().invoke(
            main,
            ["scan", "--demo", "--offline", "--no-auto-update-db", "--quiet", "--format", "sarif", "--output", str(out)],
            catch_exceptions=False,
        )
    return _pin(captured["report"], "golden-demo")


CASES: dict[str, Callable[[], AIBOMReport]] = {
    "empty": _empty_report,
    "rich": _rich_report,
    "demo": _demo_report,
}
FULL_SARIF_GOLDENS = {"empty", "rich"}


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _render(report: AIBOMReport, tmp_dir: Path) -> dict[str, str]:
    exported = tmp_dir / "report.sarif"
    export_sarif(report, str(exported))
    return {
        "sarif_stdout": json.dumps(to_sarif(report), indent=2),
        "sarif_file": exported.read_text(encoding="utf-8"),
        "sarif_exclude_unfixable": json.dumps(to_sarif(report, exclude_unfixable=True), indent=2),
        "html": to_html(report, report.blast_radii),
        "html_offline": to_html(report, report.blast_radii, offline_assets=True),
    }


def _check_text(path: Path, actual: str) -> None:
    if UPDATE:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(actual, encoding="utf-8")
    assert path.exists(), f"missing golden {path}; run with AGENT_BOM_UPDATE_OUTPUT_GOLDENS=1"
    assert actual == path.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def manifest() -> dict[str, dict[str, str]]:
    stored = json.loads(MANIFEST.read_text(encoding="utf-8")) if MANIFEST.exists() else {}
    updated = dict(stored)
    yield updated
    if UPDATE:
        MANIFEST.parent.mkdir(parents=True, exist_ok=True)
        MANIFEST.write_text(json.dumps(updated, indent=1, sort_keys=True) + "\n", encoding="utf-8")


@pytest.mark.parametrize("name", sorted(CASES))
def test_renderer_bytes_match_golden(name: str, tmp_path: Path, manifest: dict[str, dict[str, str]]) -> None:
    rendered = _render(CASES[name](), tmp_path)
    digests = {key: _sha256(value) for key, value in rendered.items()}
    if name in FULL_SARIF_GOLDENS:
        _check_text(GOLDEN_DIR / f"{name}.sarif.json", rendered["sarif_stdout"])
    else:
        _check_text(GOLDEN_DIR / f"{name}.sarif.excerpt.json", "\n".join(rendered["sarif_stdout"].splitlines()[:80]) + "\n")
    if UPDATE:
        manifest[name] = digests
    assert name in manifest, f"missing digests for {name}; run with AGENT_BOM_UPDATE_OUTPUT_GOLDENS=1"
    assert digests == manifest[name]


def test_graph_script_bytes_match_golden() -> None:
    script = render_graph_script("__CHART_DATA__", "__GRAPH_ELEMENTS__", "__ATTACK_FLOW__")
    _check_text(GOLDEN_DIR / "graph_script.js", script)


def test_rich_fixture_reaches_every_sarif_family() -> None:
    doc = to_sarif(_rich_report())
    run = doc["runs"][0]
    prefixes = {result["ruleId"].split("/", 1)[0] for result in run["results"]}
    assert {"CVE-2026-1001", "CVE-2026-1002", "GHSA-aaaa-bbbb-cccc", "finding", "iac", "ai-inventory", "cis"} <= prefixes
    assert any(result.get("suppressions") for result in run["results"])
    assert run["invocations"][0]["toolExecutionNotifications"]
    assert run["properties"]["trust_assessment"] == {"verdict": "review", "confidence": "medium"}
    assert run.get("taxonomies")
    assert "ai-inventory/api_key/[REDACTED]" in {rule["id"] for rule in run["tool"]["driver"]["rules"]}
