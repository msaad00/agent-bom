"""Report UX: grouped/collapsed terminal CIS plan + shareable HTML.

Covers the readable-at-scale terminal renderer
(:func:`print_cis_findings`) and the enhanced HTML CIS posture section
(:func:`_cis_benchmark_section`): grouping by severity, collapsing PASS
checks, per-finding evidence + remediation, summary header, and
determinism.
"""

from __future__ import annotations

from io import StringIO

from rich.console import Console

from agent_bom.models import AIBOMReport
from agent_bom.output.console_render import print_cis_findings
from agent_bom.output.html import _cis_benchmark_section


def _check(check_id, status, severity, *, section="1 - IAM", resources=None, fix_cli=None, review=False):
    return {
        "check_id": check_id,
        "title": f"Ensure check {check_id} is configured",
        "status": status,
        "severity": severity,
        "evidence": f"evidence for {check_id}",
        "resource_ids": resources or [],
        "recommendation": f"Remediate {check_id}.",
        "remediation": {
            "fix_cli": fix_cli,
            "fix_console": "Console -> fix it" if not fix_cli else "",
            "effort": "low",
            "priority": 1 if severity == "critical" else 2,
            "guardrails": ["identity", "least-privilege"],
            "requires_human_review": review,
            "docs": "",
        },
        "cis_section": section,
        "attack_techniques": [],
    }


def _large_bundle() -> dict:
    """60-check bundle: 4 critical fails, 6 high fails, 5 medium, 45 pass."""
    checks = []
    for i in range(4):
        checks.append(_check(f"c{i}", "fail", "critical", section="1 - IAM", resources=[f"arn:res:{i}"], fix_cli=f"aws fix-{i}"))
    for i in range(6):
        checks.append(_check(f"h{i}", "fail", "high", section="2 - Logging", resources=[f"bucket-{i}"]))
    for i in range(5):
        checks.append(_check(f"m{i}", "fail", "medium", section="3 - Networking", review=True))
    for i in range(45):
        checks.append(_check(f"p{i}", "pass", "low"))
    return {
        "benchmark": "CIS AWS Foundations",
        "benchmark_version": "3.0",
        "account_id": "123456789012",
        "pass_rate": 75.0,
        "passed": 45,
        "failed": 15,
        "total": 60,
        "checks": checks,
    }


def _report_large() -> AIBOMReport:
    report = AIBOMReport(tool_version="0.77.1")
    report.cis_benchmark_data = _large_bundle()
    return report


def _render(report, **kwargs) -> str:
    buf = StringIO()
    con = Console(file=buf, force_terminal=False, width=200)
    import agent_bom.output as output_mod

    original = output_mod.console
    output_mod.console = con
    try:
        print_cis_findings(report, **kwargs)
    finally:
        output_mod.console = original
    return buf.getvalue()


# ── Terminal: grouped + collapsed ────────────────────────────────────────────


def test_terminal_groups_by_severity():
    out = _render(_report_large())
    # Severity band headers present and CRITICAL precedes HIGH precedes MEDIUM.
    assert "CRITICAL" in out and "HIGH" in out and "MEDIUM" in out
    assert out.index("CRITICAL") < out.index("HIGH") < out.index("MEDIUM")


def test_terminal_collapses_passed_by_default():
    out = _render(_report_large())
    assert "45 passed" in out
    assert "--show-passed" in out
    # Passed check ids must NOT be listed when collapsed.
    assert "p0  Ensure check p0" not in out


def test_terminal_show_passed_lists_them():
    out = _render(_report_large(), show_passed=True)
    assert "Passed (45)" in out
    assert "p0" in out


def test_terminal_each_failed_has_evidence_and_recommendation():
    out = _render(_report_large())
    assert "evidence:" in out
    assert "fix:" in out
    # A resource id (evidence) and a fix command both surface.
    assert "arn:res:0" in out
    assert "aws fix-0" in out


def test_terminal_header_has_verdict_and_pass_rate():
    out = _render(_report_large())
    assert "75% pass" in out
    assert "GAPS" in out  # verdict driven by worst failing severity
    assert "top risks:" in out


def test_terminal_silent_without_cis_data():
    assert _render(AIBOMReport(tool_version="0.77.1")) == ""


def test_terminal_clean_scan_renders_cleanly():
    bundle = {
        "pass_rate": 100.0,
        "passed": 3,
        "failed": 0,
        "total": 3,
        "checks": [_check(f"ok{i}", "pass", "low") for i in range(3)],
    }
    report = AIBOMReport(tool_version="0.77.1")
    report.cis_benchmark_data = bundle
    out = _render(report)
    assert "100% pass" in out
    assert "no failed checks" in out
    assert "PASS" in out


def test_terminal_deterministic():
    r1 = _render(_report_large())
    r2 = _render(_report_large())
    assert r1 == r2


# ── HTML: shareable report ───────────────────────────────────────────────────


def test_html_has_summary_header_and_verdict():
    html = _cis_benchmark_section(_report_large())
    assert html
    assert 'id="cisbenchmarks"' in html
    assert "75% pass" in html
    assert "GAPS" in html  # verdict badge
    assert "top risks" in html


def test_html_per_finding_evidence_and_remediation():
    html = _cis_benchmark_section(_report_large())
    assert "Evidence" in html  # column header
    assert "arn:res:0" in html  # resource id evidence rendered
    assert "aws fix-0" in html  # remediation command rendered


def test_html_rows_carry_severity_for_filtering():
    html = _cis_benchmark_section(_report_large())
    assert 'class="cis-row" data-sev="critical"' in html
    assert "cis-filter-btn" in html  # severity filter controls


def test_html_empty_when_no_data():
    assert _cis_benchmark_section(AIBOMReport(tool_version="0.77.1")) == ""


def test_html_clean_scan_renders_no_failures():
    bundle = {
        "pass_rate": 100.0,
        "passed": 2,
        "failed": 0,
        "total": 2,
        "checks": [_check(f"ok{i}", "pass", "low") for i in range(2)],
    }
    report = AIBOMReport(tool_version="0.77.1")
    report.cis_benchmark_data = bundle
    html = _cis_benchmark_section(report)
    assert "No failed CIS checks" in html
    assert "PASS" in html


def test_html_deterministic():
    h1 = _cis_benchmark_section(_report_large())
    h2 = _cis_benchmark_section(_report_large())
    assert h1 == h2
