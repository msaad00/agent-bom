"""Regression tests for the unified severity system."""

from __future__ import annotations

from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from agent_bom.graph.severity import (
    SEVERITY_POLICY_ORDER,
    normalize_severity,
    severity_at_or_above,
    severity_policy_rank,
    severity_worst_first_rank,
)


def test_normalize_severity_lowercases_and_maps_informational():
    assert normalize_severity("CRITICAL") == "critical"
    assert normalize_severity(" High ") == "high"
    assert normalize_severity("INFORMATIONAL") == "info"
    assert normalize_severity("bogus") == "unknown"
    assert normalize_severity(None) == "unknown"


def test_policy_order_unknown_below_none():
    assert SEVERITY_POLICY_ORDER["UNKNOWN"] < SEVERITY_POLICY_ORDER["NONE"]
    assert severity_policy_rank("unknown") < severity_policy_rank("none")
    assert severity_at_or_above("none", "unknown") is True
    assert severity_at_or_above("unknown", "none") is False


def test_policy_order_info_above_none():
    assert severity_policy_rank("info") > severity_policy_rank("none")
    assert severity_worst_first_rank("info") < severity_worst_first_rank("none")


def test_worst_first_rank_sorts_critical_before_low():
    assert severity_worst_first_rank("critical") < severity_worst_first_rank("high")
    assert severity_worst_first_rank("high") < severity_worst_first_rank("medium")
    assert severity_worst_first_rank("medium") < severity_worst_first_rank("low")
    assert severity_worst_first_rank("low") < severity_worst_first_rank("unknown")


def test_finding_normalizes_severity_at_ingest():
    finding = Finding(
        finding_type=FindingType.CREDENTIAL_EXPOSURE,
        source=FindingSource.SECRET_SCAN,
        asset=Asset(name="config.py", asset_type="file"),
        severity="CRITICAL",
        title="Hardcoded credential",
    )
    assert finding.severity == "critical"
