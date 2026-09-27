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


def test_normalize_severity_maps_vendor_labels_to_canonical_bands():
    # GHSA publishes MODERATE; Red Hat publishes Important/Moderate.
    assert normalize_severity("MODERATE") == "medium"
    assert normalize_severity(" Moderate ") == "medium"
    assert normalize_severity("Important") == "high"
    assert normalize_severity("IMPORTANT ") == "high"
    for label in ("critical", "high", "medium", "low", "none", "info"):
        assert normalize_severity(label.upper()) == label


def test_finding_ingest_keeps_ghsa_moderate_as_medium():
    finding = Finding(
        finding_type=FindingType.CREDENTIAL_EXPOSURE,
        source=FindingSource.SECRET_SCAN,
        asset=Asset(name="config.py", asset_type="file"),
        severity="MODERATE",
        title="GHSA advisory",
    )
    assert finding.severity == "medium"


def test_bulk_ingest_severity_uses_central_vendor_mapping():
    from agent_bom.api.routes.scan import _coerce_bulk_severity

    assert _coerce_bulk_severity("MODERATE", ordinal=0) == "medium"
    assert _coerce_bulk_severity("Important", ordinal=0) == "high"
    assert _coerce_bulk_severity("not-a-severity", ordinal=0) == "unknown"


def test_rank_and_ocsf_helpers_strip_whitespace_and_accept_vendor_labels():
    from agent_bom.graph.severity import OCSFSeverity, severity_rank, severity_to_ocsf

    assert severity_rank(" high ") == severity_rank("high") == 4
    assert severity_rank("Moderate") == severity_rank("medium")
    assert severity_rank("informational") == severity_rank("info") == 1
    assert severity_to_ocsf(" CRITICAL ") == OCSFSeverity.CRITICAL
    assert severity_to_ocsf("Important") == OCSFSeverity.HIGH
    assert severity_to_ocsf("informational") == OCSFSeverity.INFORMATIONAL
    assert severity_to_ocsf("") == OCSFSeverity.UNKNOWN
