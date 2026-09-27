"""Cross-surface severity semantics and invalid-score regression contracts."""

import math

import pytest

from agent_bom.graph.severity import normalize_severity, severity_display_bucket
from agent_bom.models import Severity
from agent_bom.scanners.risk import cvss_to_severity, parse_cvss_vector, severity_from_label


@pytest.mark.parametrize(
    "label,band", [(" moderate ", "medium"), ("IMPORTANT", "high"), ("minor", "low"), ("negligible", "low"), ("unimportant", "low")]
)
def test_vendor_label_agrees_in_scanner_rank_and_histogram(label, band):
    assert severity_from_label(label).value == normalize_severity(label) == severity_display_bucket(label) == band


@pytest.mark.parametrize("score", [math.nan, math.inf, -math.inf, -1, 10.1])
def test_invalid_cvss_score_never_means_no_vulnerability(score):
    assert cvss_to_severity(score) is Severity.UNKNOWN


def test_cvss_vector_trims_surrounding_whitespace():
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert parse_cvss_vector(" \t" + vector + "\n") == parse_cvss_vector(vector) == 9.8


@pytest.mark.parametrize("score", [math.nan, math.inf, -math.inf, "not-a-score", "   "])
def test_cvss_sort_is_finite_and_agrees_with_cursor(score):
    from agent_bom.api.finding_cursor import cvss_sort_value
    from agent_bom.api.routes.scan import _finding_sort_key

    row = {"severity": "high", "cvss_score": score}
    key = _finding_sort_key(row, "cvss")
    assert all(math.isfinite(part) for part in key)
    assert key[0] == key[1] == -cvss_sort_value(score) == 0


@pytest.mark.parametrize("score,expected", [(0, Severity.NONE), (math.nan, Severity.UNKNOWN), (8, Severity.HIGH)])
def test_vendor_score_adapters_use_canonical_cvss(score, expected):
    from agent_bom.scanners.amd_advisory_fetch import _cvss_to_severity
    from agent_bom.scanners.nvidia_advisory import _parse_csaf_severity

    assert _cvss_to_severity(score, "") == expected.value
    assert _parse_csaf_severity([{"cvss_v3": {"baseScore": score}}])[0] is expected
