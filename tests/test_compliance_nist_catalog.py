"""Direct unit tests for the shared catalog-backed NIST 800-53 scorer.

The route, MCP tool, narrative, and CLI all call these functions, so pinning
their behavior here guards the one-source-of-truth reconciliation across every
surface (§11).
"""

from __future__ import annotations

from agent_bom.compliance_nist_catalog import (
    build_family_rollup,
    build_nist_800_53_catalog_line,
    build_nist_800_53_drill,
    evaluated_control_status,
)
from agent_bom.framework_mapping import FRAMEWORK_CONTROL_CATALOG, FRAMEWORK_NIST_800_53


def _scenario() -> tuple[list[dict], dict[tuple[str, str], str]]:
    """CVE-driven SI-10 fail + a CIS estate exercising pass/fail/error/N-A."""
    all_blast = [
        {"vulnerability_id": "CVE-1", "severity": "high", "nist_800_53_tags": ["SI-10"]},
        {"vulnerability_id": "CVE-2", "severity": "critical", "nist_800_53_tags": ["RA-5"]},
    ]
    cis_statuses = {
        ("aws", "2.1.2"): "pass",  # SC-28 pass
        ("aws", "2.1.1"): "fail",  # AC-3, SC-7 fail
        ("aws", "1.12"): "fail",  # AC-2, IA-5 fail
        ("aws", "1.4"): "error",  # AC-6, IA-5 error
        ("aws", "1.5"): "not_applicable",  # IA-2 ignored
    }
    return all_blast, cis_statuses


def test_evaluated_control_status_severity_bands():
    assert evaluated_control_status({"critical": 1}) == "fail"
    assert evaluated_control_status({"high": 1}) == "fail"
    assert evaluated_control_status({"medium": 1}) == "warning"
    assert evaluated_control_status({"low": 1}) == "warning"
    # Evidence exists but severity ungraded -> not a silent pass.
    assert evaluated_control_status({"critical": 0, "high": 0, "medium": 0, "low": 0}) == "not_evaluated"


def test_catalog_line_scores_over_evaluated_only():
    all_blast, cis_statuses = _scenario()
    line = build_nist_800_53_catalog_line(all_blast, cis_statuses, scan_count=1)
    s = line["summary"]
    assert line["vendor_asserted"] is True
    assert line["framework_key"] == "nist_800_53_catalog"
    # fail: SI-10, AC-3, SC-7, AC-2, IA-5 = 5 ; pass: SC-28 = 1 ; error: AC-6 = 1
    assert (s["fail"], s["pass"], s["error"], s["warning"]) == (5, 1, 1, 0)
    assert s["evaluated"] == 7
    assert s["catalog_size"] == len(FRAMEWORK_CONTROL_CATALOG[FRAMEWORK_NIST_800_53])
    assert s["not_evaluated"] == s["catalog_size"] - 7
    assert line["score"] == 14.3
    by_id = {c["control_id"]: c["status"] for c in line["controls"]}
    assert by_id["IA-5"] == "fail"  # fail (1.12) beats error (1.4)
    assert "RA-5" not in by_id  # vuln-intrinsic tag, no curated check


def test_no_data_when_nothing_mapped():
    line = build_nist_800_53_catalog_line([], {}, scan_count=1)
    assert line["status"] == "no_data"
    assert line["score"] == 0.0
    assert line["summary"]["evaluated"] == 0


def test_drill_reconciles_and_family_rollup_sums_back():
    all_blast, cis_statuses = _scenario()
    line = build_nist_800_53_catalog_line(all_blast, cis_statuses, scan_count=1)
    drill = build_nist_800_53_drill(line)
    assert drill["summary"] == line["summary"]
    assert sum(f["evaluated"] for f in drill["families"]) == line["summary"]["evaluated"]
    assert sum(f["total"] for f in drill["families"]) == line["summary"]["catalog_size"]

    full = build_nist_800_53_drill(line, include_not_evaluated=True)
    assert len(full["controls"]) == full["summary"]["catalog_size"]
    only_fail = build_nist_800_53_drill(line, status="fail")
    assert only_fail["controls"] and all(c["status"] == "fail" for c in only_fail["controls"])
    # A display filter never changes the counts.
    assert only_fail["summary"]["pass"] == 1


def test_family_rollup_not_evaluated_is_remainder():
    catalog = FRAMEWORK_CONTROL_CATALOG[FRAMEWORK_NIST_800_53]
    rollup = build_family_rollup([], catalog)
    assert sum(f["total"] for f in rollup) == len(catalog)
    assert all(f["not_evaluated"] == f["total"] and f["evaluated"] == 0 for f in rollup)
