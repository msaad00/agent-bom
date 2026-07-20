"""Regression coverage for untrusted data crossing output boundaries."""

from __future__ import annotations

import csv
import io
from datetime import datetime

from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from agent_bom.models import AIBOMReport, BlastRadius, Package, Severity, Vulnerability
from agent_bom.output import to_csv
from agent_bom.output.graph import export_graph_html


def _finding(
    *,
    finding_type: FindingType = FindingType.COMBINATION,
    title: str = "Graph finding",
    description: str = "Evidence description",
    cve_id: str | None = None,
) -> Finding:
    return Finding(
        finding_type=finding_type,
        source=FindingSource.GRAPH_ANALYSIS if not cve_id else FindingSource.SBOM,
        asset=Asset(name="attacker-controlled", asset_type="agent"),
        severity="high",
        title=title,
        description=description,
        cve_id=cve_id,
    )


def _report(findings: list[Finding]) -> AIBOMReport:
    return AIBOMReport(
        agents=[],
        blast_radii=[],
        findings=findings,
        generated_at=datetime(2026, 1, 1),
        tool_version="0.96.5",
    )


def test_csv_neutralizes_formula_cells_and_keeps_non_cve_cve_id_blank():
    report = _report(
        [
            _finding(
                title="=1+1",
                description="@SUM(1+1)",
            )
        ]
    )
    row = next(csv.DictReader(io.StringIO(to_csv(report).lstrip("\ufeff"))))

    assert row["cve_id"] == ""
    assert row["title"] == "'=1+1"
    assert row["summary"] == "'@SUM(1+1)"


def test_flat_exports_reconcile_legacy_and_unified_cve_streams():
    package = Package(name="legacy", version="1.0.0", ecosystem="pypi")
    vulnerability = Vulnerability(id="CVE-LEGACY-1", severity=Severity.HIGH, summary="legacy")
    legacy = BlastRadius(
        package=package,
        vulnerability=vulnerability,
        affected_servers=[],
        affected_agents=[],
        exposed_credentials=[],
        exposed_tools=[],
    )
    report = _report([_finding(finding_type=FindingType.CVE, title="Unified", cve_id="CVE-UNIFIED-2")])

    rows = list(csv.DictReader(io.StringIO(to_csv(report, [legacy]).lstrip("\ufeff"))))

    assert {row["cve_id"] for row in rows} == {"CVE-LEGACY-1", "CVE-UNIFIED-2"}


def test_graph_html_escapes_script_breakout_and_keeps_policy_findings_offline(tmp_path):
    payload = "</script><script>globalThis.PWNED=1</script>"
    report = _report([_finding(title=payload, description=payload)])
    interactive = tmp_path / "graph.html"
    offline = tmp_path / "offline.html"

    export_graph_html(report, [], str(interactive))
    export_graph_html(report, [], str(offline), offline_assets=True)

    interactive_html = interactive.read_text(encoding="utf-8")
    offline_html = offline.read_text(encoding="utf-8")
    assert payload not in interactive_html
    assert r"\u003c/script\u003e" in interactive_html
    assert "PWNED" in offline_html
    assert "high" in offline_html.lower()


def test_graph_policy_priority_points_to_finding_node():
    from agent_bom.output.graph import _graph_priority_summary

    finding = _finding(title="Policy title")
    assert _graph_priority_summary([finding])[0]["nodeId"] == f"finding:{finding.id}"
