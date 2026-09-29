"""Severity orderings that used to be hand-rolled tables now come from ``core.severity``.

The expected orders below were captured from each call site *before* it was
moved onto the core helpers, over one mixed list covering mixed case, ``None``,
empty, ``info``, ``none``, ``unknown`` and an unrecognized label. Each site keeps
its own sort direction. The only intended change is that vendor aliases
(``moderate``/``important``) now land in their canonical band instead of the
unrated tail — see the ``*_aliases`` tests.
"""

from __future__ import annotations

import pytest

from agent_bom.core.severity import severity_band_rank, severity_fix_priority

MIXED = ["low", "CRITICAL", "info", None, "unknown", "High", "medium", "none", "", "critical", "bogus"]
# Positions in MIXED, worst first; ties keep input (or id) order.
WORST_FIRST = [1, 9, 5, 6, 0, 2, 3, 4, 7, 8, 10]


def test_severity_band_rank_table():
    assert [severity_band_rank(s) for s in MIXED] == [3, 0, 4, 4, 4, 1, 2, 4, 4, 0, 4]
    assert severity_band_rank(" Critical ") == 0
    assert severity_band_rank("moderate") == 2
    assert severity_band_rank("important") == 1
    assert severity_band_rank("informational") == 4


def test_severity_fix_priority_table():
    assert [severity_fix_priority(s) for s in MIXED] == [3, 1, 4, 3, 3, 1, 2, 3, 3, 1, 3]
    assert severity_fix_priority("informational") == 4


def test_executive_headline_orders_worst_first_then_id():
    from agent_bom.output.executive_headline import build_executive_headline

    rows = [{"id": f"r{i:02d}", "title": f"t{i}", "severity": sev} for i, sev in enumerate(MIXED)]
    headline = build_executive_headline(rows, limit=len(rows))
    assert [risk.id for risk in headline.top_risks] == [f"r{i:02d}" for i in WORST_FIRST]


def test_executive_headline_aliases():
    from agent_bom.output.executive_headline import build_executive_headline

    rows = [
        {"id": "a", "title": "a", "severity": "low"},
        {"id": "b", "title": "b", "severity": "Moderate"},
        {"id": "c", "title": "c", "severity": "important"},
    ]
    headline = build_executive_headline(rows, limit=3)
    assert [risk.id for risk in headline.top_risks] == ["c", "b", "a"]


def test_scan_response_top_findings_orders_score_then_worst_first():
    from agent_bom.mcp_tools.scan_response import _top_findings

    findings = [{"id": f"f{i}", "severity": sev, "risk_score": 5.0} for i, sev in enumerate(MIXED)]
    findings.append({"id": "top", "severity": "low", "risk_score": 9.0})
    ranked = _top_findings(findings, top_n=len(findings))
    assert [row["id"] for row in ranked] == ["top", *[f"f{i}" for i in WORST_FIRST]]


def test_scan_response_counts_keep_bucket_keys():
    from agent_bom.mcp_tools.scan_response import _counts

    findings = [{"severity": sev} for sev in MIXED]
    by_severity = _counts({}, findings, [])["findings_by_severity"]
    assert list(by_severity) == ["critical", "high", "medium", "low", "unknown"]
    assert by_severity == {"critical": 2, "high": 1, "medium": 1, "low": 1, "unknown": 4}


def test_mermaid_priority_orders_worst_first_then_insertion():
    from agent_bom.output.graph_export import DepGraph, _mermaid_priority_nodes

    graph = DepGraph()
    for i, sev in enumerate(MIXED):
        graph.add_node(f"n{i}", f"n{i}", "cve", sev or "")
    assert [node.id for node in _mermaid_priority_nodes(graph)] == [f"n{i}" for i in WORST_FIRST]


def test_mermaid_priority_propagates_upstream():
    from agent_bom.output.graph_export import DepGraph, _mermaid_priority_nodes

    graph = DepGraph()
    graph.add_node("pkg-a", "a", "pkg")
    graph.add_node("pkg-b", "b", "pkg")
    graph.add_node("cve-low", "l", "cve", "low")
    graph.add_node("cve-crit", "c", "cve", "CRITICAL")
    graph.add_edge("pkg-a", "cve-low", "affects")
    graph.add_edge("pkg-b", "cve-crit", "affects")
    assert [node.id for node in _mermaid_priority_nodes(graph)] == ["cve-crit", "pkg-b", "cve-low", "pkg-a"]


def test_mermaid_priority_aliases():
    from agent_bom.output.graph_export import DepGraph, _mermaid_priority_nodes

    graph = DepGraph()
    graph.add_node("low", "low", "cve", "low")
    graph.add_node("moderate", "moderate", "cve", "moderate")
    assert [node.id for node in _mermaid_priority_nodes(graph)] == ["moderate", "low"]


@pytest.mark.parametrize("module", ["agent_bom.remediation", "agent_bom.cloud.cis_remediation"])
def test_remediation_priority_table(module):
    import importlib

    priority_for = importlib.import_module(module)._priority_for
    assert [priority_for(sev) for sev in MIXED] == [3, 1, 4, 3, 3, 1, 2, 3, 3, 1, 3]
    assert priority_for("informational") == 4


@pytest.mark.parametrize("module", ["agent_bom.remediation", "agent_bom.cloud.cis_remediation"])
def test_remediation_priority_aliases(module):
    import importlib

    priority_for = importlib.import_module(module)._priority_for
    assert priority_for("moderate") == 2
    assert priority_for("important") == 1


def test_scan_request_severity_enum_order_is_stable():
    from agent_bom.api.models import _SCAN_SEVERITY_ORDER

    assert _SCAN_SEVERITY_ORDER == ("low", "medium", "high", "critical")
