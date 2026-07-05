"""Regression tests for canonical severity ordering in API/output sort paths."""

from __future__ import annotations

from agent_bom.api.routes.scan import _finding_sort_key
from agent_bom.graph.severity import severity_policy_rank, severity_worst_first_rank


def test_finding_sort_key_uses_policy_rank_for_severity_sort() -> None:
    critical = {"severity": "critical", "cvss_score": 1.0}
    high = {"severity": "high", "cvss_score": 9.0}
    assert _finding_sort_key(critical, "severity") < _finding_sort_key(high, "severity")


def test_finding_sort_key_matches_compliance_hub_policy_rank() -> None:
    row = {"severity": "medium", "cvss_score": 0.0}
    _, _, neg_rank = _finding_sort_key(row, "severity")
    assert -neg_rank == severity_policy_rank("medium")


def test_worst_first_rank_orders_critical_before_low() -> None:
    assert severity_worst_first_rank("critical") < severity_worst_first_rank("low")


def test_html_cis_section_sorts_critical_before_medium() -> None:
    from agent_bom.models import AIBOMReport
    from agent_bom.output.html import _cis_benchmark_section

    bundle = {
        "pass_rate": 50.0,
        "passed": 1,
        "failed": 2,
        "total": 3,
        "checks": [
            {"check_id": "med-1", "status": "fail", "severity": "medium", "remediation": {"priority": 1}},
            {"check_id": "crit-1", "status": "fail", "severity": "critical", "remediation": {"priority": 3}},
            {"check_id": "ok-1", "status": "pass", "severity": "low"},
        ],
    }
    report = AIBOMReport(tool_version="0.1")
    report.cis_benchmark_data = bundle
    html = _cis_benchmark_section(report)
    assert html.index("crit-1") < html.index("med-1")


def test_console_cis_sort_key_orders_critical_before_medium() -> None:
    from agent_bom.output.console_render import _cis_check_sort_key

    medium = {"check_id": "med-1", "severity": "medium", "remediation": {"priority": 1}}
    critical = {"check_id": "crit-1", "severity": "critical", "remediation": {"priority": 3}}
    assert _cis_check_sort_key(critical) < _cis_check_sort_key(medium)
