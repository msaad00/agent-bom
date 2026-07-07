"""Scale-readiness tests for the tabbed, paginated HTML report.

Covers the enhancements that keep a large real-estate scan (thousands of
findings) readable and interactive:

* tabbed section layout (only tabs with data render);
* client-side pagination controls + windowed rows on the findings tables;
* a large finding set produces a single self-contained file that ships the
  pagination JS instead of inlining every row as visible.
"""

from __future__ import annotations

from datetime import datetime

from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from agent_bom.models import (
    Agent,
    AgentStatus,
    AgentType,
    AIBOMReport,
    BlastRadius,
    Package,
    Severity,
)
from agent_bom.output.html import _PAGE_SIZE, to_html

_SEVS = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
_ECO = ["npm", "pypi", "go", "cargo", "maven"]
# Fixed number of policy (non-CVE) findings the helper attaches; these render in
# a second paginated table and also carry the ``pg-row`` class.
_POLICY_N = 30


def _agent(i: int) -> Agent:
    return Agent(
        name=f"agent-{i % 8}",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path=f"/tmp/agent-{i % 8}.json",
        mcp_servers=[],
        status=AgentStatus.CONFIGURED,
    )


def _blast(i: int) -> BlastRadius:
    from agent_bom.models import Vulnerability

    sev = _SEVS[i % 4]
    return BlastRadius(
        package=Package(name=f"pkg-{i % 300}", version=f"1.{i % 9}.0", ecosystem=_ECO[i % 5]),
        vulnerability=Vulnerability(
            id=f"CVE-2026-{20000 + i}",
            severity=sev,
            summary=f"Synthetic finding {i}.",
            cvss_score=round(9.8 - (i % 4) * 2.1, 1),
            fixed_version=f"1.{i % 9}.1" if i % 3 else None,
            is_kev=(i % 15 == 0),
        ),
        affected_agents=[_agent(i)] if i % 2 else [],
        affected_servers=[],
        exposed_credentials=[],
        exposed_tools=[],
    )


def _large_report(n: int) -> tuple[AIBOMReport, list[BlastRadius]]:
    brs = [_blast(i) for i in range(n)]
    report = AIBOMReport(
        agents=[_agent(i) for i in range(8)],
        blast_radii=brs,
        generated_at=datetime(2026, 7, 7, 12, 0, 0),
        tool_version="0.92.0",
    )
    report.findings = [
        Finding(
            finding_type=FindingType.MCP_BLOCKLIST,
            source=FindingSource.MCP_SCAN,
            asset=Asset(name=f"srv-{i}", asset_type="mcp_server", identifier=f"srv-{i}"),
            severity=str(_SEVS[i % 4]).lower().split(".")[-1],
            title=f"Policy finding {i}",
            description="Matched the MCP intelligence blocklist.",
            evidence={"rule": f"R{i}"},
        )
        for i in range(_POLICY_N)
    ]
    return report, brs


# ── Tabs ─────────────────────────────────────────────────────────────────────


def test_report_renders_tab_bar_with_expected_tabs():
    report, brs = _large_report(120)
    html = to_html(report, brs)

    assert 'class="tab-bar"' in html
    # Sections are tagged with their tab group.
    assert '<section id="summary" data-tab="summary"' in html
    assert '<section id="vulns" data-tab="findings"' in html
    # Tab buttons exist for the groups that have data.
    assert 'data-tab="summary" role="tab"' in html
    assert 'data-tab="findings" role="tab"' in html
    # The JS tab layer + activation is present.
    assert "js-tabs" in html
    assert "function activateTab" in html


def test_tabs_only_render_when_data_present():
    """A report with no governance sections must not emit a governance tab."""
    report, brs = _large_report(20)
    html = to_html(report, brs)
    assert 'data-tab="governance" role="tab"' not in html
    assert 'data-tab="compliance" role="tab"' in html  # compliance section renders


# ── Pagination ───────────────────────────────────────────────────────────────


def test_findings_tables_render_pagination_controls():
    report, brs = _large_report(120)
    html = to_html(report, brs)

    assert 'data-pager="vulnTable"' in html
    assert 'data-pager="policyFindingsTable"' in html
    assert 'data-act="next"' in html
    assert 'data-act="prev"' in html
    assert 'class="pager-size"' in html
    # The pagination engine ships in the file.
    assert "function makePaginator" in html
    assert "window.PAGINATORS" in html


def test_large_finding_set_windows_rows_not_all_visible():
    n = 2000
    report, brs = _large_report(n)
    html = to_html(report, brs)

    # Every finding is present in the file (self-contained, nothing dropped)...
    assert html.count("data-cvss=") == n
    # ...but rows beyond the first page are windowed out by default so the page
    # does not paint 2000 rows at once. Only the vuln table overflows a page
    # (the policy table's _POLICY_N rows fit on one page).
    hidden_rows = html.count('class="pg-row pg-hidden"')
    assert hidden_rows == n - _PAGE_SIZE
    # First page of vulns + all policy rows stay visible.
    assert html.count('class="pg-row"') == _PAGE_SIZE + _POLICY_N


def test_large_report_is_single_self_contained_file():
    report, brs = _large_report(2000)
    html = to_html(report, brs)

    assert html.startswith("<!DOCTYPE html>")
    assert html.rstrip().endswith("</html>")
    # Pagination + tab logic are inlined, not fetched.
    assert "makePaginator" in html
    assert "activateTab" in html


def test_small_report_still_lists_all_rows_without_windowing():
    report, brs = _large_report(10)
    html = to_html(report, brs)
    # Under one page: no row is windowed out at render time.
    assert 'class="pg-row pg-hidden"' not in html
    assert html.count('class="pg-row"') == 10 + _POLICY_N


def test_pagination_survives_offline_mode_gracefully():
    """Offline mode drops interactivity but must remain a valid single page."""
    report, brs = _large_report(200)
    html = to_html(report, brs, offline_assets=True)
    assert html.startswith("<!DOCTYPE html>")
    # No dead tab bar in the static offline export.
    assert 'class="tab-bar"' not in html
