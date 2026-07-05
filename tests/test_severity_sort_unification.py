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
