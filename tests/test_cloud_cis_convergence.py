"""Cloud CIS failures converge into the unified findings stream + the gate."""

from __future__ import annotations

from agent_bom.models import AIBOMReport


def _report() -> AIBOMReport:
    r = AIBOMReport(scan_id="t")
    # AWS CIS: one HIGH fail, one pass
    r.cis_benchmark_data = {
        "checks": [
            {
                "check_id": "1.7",
                "title": "Root used",
                "status": "FAIL",
                "severity": "high",
                "evidence": "root login",
                "resource_ids": [],
                "attack_techniques": ["T1078"],
            },
            {"check_id": "2.1", "title": "S3 block", "status": "PASS", "severity": "high"},
        ]
    }
    # Azure CIS: one CRITICAL fail with a resource
    r.azure_cis_benchmark_data = {
        "checks": [
            {
                "check_id": "3.2",
                "title": "Storage open",
                "status": "FAIL",
                "severity": "critical",
                "evidence": "open",
                "resource_ids": ["/sub/x/sa/foo"],
            },
        ]
    }
    return r


def test_cis_fails_become_findings_across_providers() -> None:
    cis = [f for f in _report().to_findings() if f.finding_type.value == "CIS_FAIL"]
    assert len(cis) == 2  # AWS 1.7 + Azure 3.2; the PASS excluded
    by_title = {f.title: f for f in cis}
    assert "CIS 1.7: Root used" in by_title
    assert by_title["CIS 1.7: Root used"].attack_tags == ["T1078"]
    assert "CIS-1.7" in by_title["CIS 1.7: Root used"].compliance_tags
    az = by_title["CIS 3.2: Storage open"]
    assert az.severity == "CRITICAL"
    assert az.asset.identifier == "/sub/x/sa/foo"


def test_pass_checks_not_findings() -> None:
    titles = {f.title for f in _report().to_findings()}
    assert "CIS 2.1: S3 block" not in titles  # PASS never becomes a finding


def _gate(report: AIBOMReport) -> int:
    from rich.console import Console

    from agent_bom.cli.agents._context import ScanContext
    from agent_bom.cli.agents._post import compute_exit_code

    ctx = ScanContext(con=Console(quiet=True))
    ctx.report = report
    ctx.blast_radii = []
    return compute_exit_code(
        ctx,
        fail_on_severity="high",
        warn_on_severity=None,
        fail_on_kev=False,
        fail_if_ai_risk=False,
        push_url=None,
        push_api_key=None,
        quiet=True,
    )


def test_fail_on_severity_gate_catches_cloud_cis() -> None:
    # No CVEs/IaC — only cloud CIS. Gate at HIGH must trip on the CIS fails.
    assert _gate(_report()) != 0, "cloud CIS HIGH/CRITICAL failures must fail the gate"


def test_clean_cis_does_not_trip_gate() -> None:
    r = AIBOMReport(scan_id="t")
    r.cis_benchmark_data = {"checks": [{"check_id": "1.1", "title": "ok", "status": "PASS", "severity": "high"}]}
    assert _gate(r) == 0
