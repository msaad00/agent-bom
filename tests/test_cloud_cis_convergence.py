"""Cloud CIS failures converge into the unified findings stream + the gate."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.routes import scan as scan_routes
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import set_job_store
from agent_bom.models import AIBOMReport
from agent_bom.output.json_fmt import to_json


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


def test_cis_fail_posture_and_gate_agree() -> None:
    """The compact headline and the --fail-on-severity gate read the same report
    consistently: CIS HIGH fails are both non-CLEAN and gate-failing."""
    from io import StringIO

    from rich.console import Console

    import agent_bom.output as out_mod
    from agent_bom.output import print_compact_summary

    report = _report()
    buf = StringIO()
    con = Console(file=buf, width=120, force_terminal=True, no_color=True)
    orig = out_mod.console
    out_mod.console = con
    try:
        print_compact_summary(report, verbose=True)
    finally:
        out_mod.console = orig
    rendered = buf.getvalue()
    assert "CLEAN" not in rendered  # headline reflects CIS fails
    assert _gate(report) != 0  # gate agrees


def test_json_finding_summary_counts_cloud_cis_findings() -> None:
    payload = to_json(_report())
    assert payload["summary"]["total_vulnerabilities"] == 0
    assert payload["summary"]["total_findings"] == 2
    assert payload["summary"]["critical_unified_findings"] == 1
    assert payload["summary"]["high_unified_findings"] == 1
    assert payload["finding_summary"]["by_type"]["CIS_FAIL"] == 2
    assert payload["finding_summary"]["by_source"]["CLOUD_CIS"] == 2


@pytest.mark.asyncio
async def test_findings_endpoint_filters_cloud_cis_by_scan_id() -> None:
    store = InMemoryJobStore()
    set_job_store(store)
    target = _report()
    target.scan_id = "scan-cloud"
    other = AIBOMReport(scan_id="scan-other")
    other.cis_benchmark_data = {"checks": [{"check_id": "1.1", "title": "Other", "status": "PASS", "severity": "high"}]}
    for report in (target, other):
        store.put(
            ScanJob(
                job_id=report.scan_id,
                tenant_id="tenant-cis",
                status=JobStatus.DONE,
                created_at="2026-06-29T00:00:00Z",
                completed_at="2026-06-29T00:00:01Z",
                request=ScanRequest(),
                result=to_json(report),
            )
        )

    request = SimpleNamespace(state=SimpleNamespace(tenant_id="tenant-cis", api_key_name="tester"))
    response = await scan_routes.list_findings(request, scan_id="scan-cloud")

    assert response["scan_id"] == "scan-cloud"
    assert response["total"] == 2
    assert {finding["finding_type"] for finding in response["findings"]} == {"CIS_FAIL"}
    assert {finding["scan_id"] for finding in response["findings"]} == {"scan-cloud"}


def _html_section(html: str, section_id: str) -> str:
    """Slice out a single top-level ``<section id=...>...</section>`` block."""
    start = html.index(f'id="{section_id}"')
    return html[start : html.index("</section>", start)]


def _html_dedup_report() -> AIBOMReport:
    """A cloud report whose CIS failures hit BOTH HTML render paths.

    ``_non_cve_findings()`` lifts every failed cloud CIS check into the unified
    policy-findings section AND the dedicated CIS Benchmark Posture table renders
    the same checks. The dedicated table covers aws/azure/gcp/snowflake/databricks
    (``_CIS_CLOUD_LABELS``); snowflake governance findings have no dedicated table.
    """

    def _bench(check_id: str) -> dict:
        return {
            "checks": [
                {
                    "check_id": check_id,
                    "title": f"Ensure control {check_id}",
                    "status": "fail",
                    "severity": "high",
                    "recommendation": f"Fix {check_id}.",
                    "cis_section": check_id,
                    "resource_ids": [f"resource-{check_id}"],
                }
            ],
            "pass_rate": 0.0,
            "passed": 0,
        }

    report = AIBOMReport(scan_id="cis-html-dedup")
    report.cis_benchmark_data = _bench("1.4")
    report.databricks_cis_benchmark_data = _bench("5.1")
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


def test_html_cloud_cis_failure_rendered_once() -> None:
    """Each failed cloud CIS check renders exactly once in the HTML report.

    Regression for the double-emission bug: ``_non_cve_findings()`` lifted cloud
    CIS failures into the unified policy-findings section while the dedicated CIS
    Benchmark Posture table rendered them again. After de-duplication the failed
    check appears only in the dedicated table, while snowflake governance findings
    (no dedicated table) keep flowing through the unified policy section.
    """
    from agent_bom.output.html import to_html

    html = to_html(_html_dedup_report())
    policy = _html_section(html, "policyfindings")
    cis = _html_section(html, "cisbenchmarks")

    # aws + databricks both have a dedicated table -> deduped out of the unified
    # policy section, present in the CIS table (row cell, not double-emitted).
    for check_id in ("1.4", "5.1"):
        assert f"CIS {check_id}:" not in policy, f"CIS {check_id} double-emitted in policy section"
        assert f">{check_id}<" in cis, f"CIS {check_id} missing from dedicated CIS table"

    # snowflake governance has no dedicated table -> still in the unified section.
    assert "Role has broad write access" in policy
    assert "Role has broad write access" not in cis
