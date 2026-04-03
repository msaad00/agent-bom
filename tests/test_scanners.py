"""Tests for agent_bom.scanners to improve coverage."""

from __future__ import annotations

from agent_bom.models import Package, Severity
from agent_bom.scanners import (
    _parse_cvss4_vector,
    build_vulnerabilities,
    cvss_to_severity,
    parse_cvss_vector,
    parse_fixed_version,
    parse_osv_severity,
)

# ---------------------------------------------------------------------------
# cvss_to_severity
# ---------------------------------------------------------------------------


def test_cvss_to_severity_none():
    assert cvss_to_severity(None) == Severity.UNKNOWN


def test_cvss_to_severity_critical():
    assert cvss_to_severity(9.8) == Severity.CRITICAL


def test_cvss_to_severity_high():
    assert cvss_to_severity(7.5) == Severity.HIGH


def test_cvss_to_severity_medium():
    assert cvss_to_severity(5.0) == Severity.MEDIUM


def test_cvss_to_severity_low():
    assert cvss_to_severity(2.0) == Severity.LOW


def test_cvss_to_severity_none_score():
    assert cvss_to_severity(0.0) == Severity.NONE


# ---------------------------------------------------------------------------
# Severity defaults — unknown/unrecognized must NEVER silently become MEDIUM
# ---------------------------------------------------------------------------


def test_osv_severity_unknown_label_not_medium():
    """OSV vuln with unrecognized severity label must return UNKNOWN, not MEDIUM."""
    vuln = {"database_specific": {"severity": "BOGUS"}}
    severity, _, _sev_src = parse_osv_severity(vuln)
    assert severity == Severity.UNKNOWN


def test_ghsa_severity_unknown_label_not_medium():
    """GHSA advisory with unrecognized severity must return UNKNOWN, not MEDIUM."""
    from agent_bom.scanners.ghsa_advisory import _parse_ghsa_severity

    severity, _ = _parse_ghsa_severity({"severity": "BOGUS", "cvss": {"score": None}})
    assert severity == Severity.UNKNOWN


def test_snyk_severity_unknown_label_not_medium():
    """Snyk issue with unrecognized severity must return UNKNOWN, not MEDIUM."""
    from agent_bom.snyk import _severity_from_snyk

    assert _severity_from_snyk("bogus") == Severity.UNKNOWN


def test_local_db_severity_none_not_medium():
    """Local DB vuln with None severity must return UNKNOWN, not MEDIUM."""
    from types import SimpleNamespace

    from agent_bom.scanners import _local_vuln_to_vulnerability

    lv = SimpleNamespace(
        id="CVE-2099-0001",
        summary="test",
        severity=None,
        cvss_score=None,
        fixed_version=None,
        epss_probability=None,
        epss_percentile=None,
        is_kev=False,
        kev_date_added=None,
    )
    v = _local_vuln_to_vulnerability(lv)
    assert v.severity == Severity.UNKNOWN


# ---------------------------------------------------------------------------
# parse_cvss_vector — CVSS 3.x
# ---------------------------------------------------------------------------


def test_parse_cvss_vector_v31_critical():
    """Standard critical CVSS 3.1 vector."""
    score = parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert score is not None
    assert score >= 9.0


def test_parse_cvss_vector_v31_scope_changed():
    """CVSS 3.1 with Scope Changed."""
    score = parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H")
    assert score is not None
    assert score >= 9.0


def test_parse_cvss_vector_v31_low():
    score = parse_cvss_vector("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N")
    assert score is not None
    assert score < 4.0


def test_parse_cvss_vector_v31_zero_impact():
    """Zero impact = score 0."""
    score = parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
    assert score == 0.0


def test_parse_cvss_vector_invalid():
    assert parse_cvss_vector("not-a-vector") is None


def test_parse_cvss_vector_v2_unsupported():
    assert parse_cvss_vector("CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C") is None


def test_parse_cvss_vector_missing_metrics():
    assert parse_cvss_vector("CVSS:3.1/AV:N") is None


# ---------------------------------------------------------------------------
# parse_cvss_vector — CVSS 4.0
# ---------------------------------------------------------------------------


def test_parse_cvss4_critical():
    vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    score = parse_cvss_vector(vector)
    assert score is not None
    assert score >= 8.0


def test_parse_cvss4_with_subsequent():
    vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
    score = parse_cvss_vector(vector)
    assert score is not None


def test_parse_cvss4_low():
    vector = "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
    score = parse_cvss_vector(vector)
    assert score is not None
    assert score < 5.0


def test_parse_cvss4_missing_metrics():
    assert _parse_cvss4_vector("CVSS:4.0/AV:N") is None


def test_parse_cvss4_zero_impact():
    vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"
    score = _parse_cvss4_vector(vector)
    assert score == 0.0


def test_parse_cvss4_malformed():
    assert _parse_cvss4_vector("garbage") is None


# ---------------------------------------------------------------------------
# parse_osv_severity
# ---------------------------------------------------------------------------


def test_parse_osv_severity_cvss_score():
    vuln = {"severity": [{"type": "CVSS_V3", "score": "9.8"}]}
    sev, score, _sev_src = parse_osv_severity(vuln)
    assert sev == Severity.CRITICAL
    assert score == 9.8


def test_parse_osv_severity_cvss_vector():
    vuln = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
    sev, score, _sev_src = parse_osv_severity(vuln)
    assert sev == Severity.CRITICAL


def test_parse_osv_severity_database_specific():
    vuln = {"database_specific": {"severity": "HIGH"}}
    sev, score, _sev_src = parse_osv_severity(vuln)
    assert sev == Severity.HIGH


def test_parse_osv_severity_moderate():
    vuln = {"database_specific": {"severity": "MODERATE"}}
    sev, score, _sev_src = parse_osv_severity(vuln)
    assert sev == Severity.MEDIUM


def test_parse_osv_severity_no_data():
    sev, score, _sev_src = parse_osv_severity({})
    assert sev == Severity.UNKNOWN  # no data must not inflate to MEDIUM
    assert score is None


def test_parse_osv_severity_cvss4():
    vuln = {"severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}]}
    sev, score, _sev_src = parse_osv_severity(vuln)
    assert score is not None


def test_parse_osv_severity_invalid_score():
    vuln = {"severity": [{"type": "CVSS_V3", "score": "not-a-number"}]}
    sev, score, _sev_src = parse_osv_severity(vuln)
    # Falls back to UNKNOWN since it can't parse — not MEDIUM
    assert sev == Severity.UNKNOWN


def test_parse_osv_severity_out_of_range():
    vuln = {"severity": [{"type": "CVSS_V3", "score": "15.0"}]}
    sev, score, _sev_src = parse_osv_severity(vuln)
    assert score is None  # Out of 0-10 range


# ---------------------------------------------------------------------------
# parse_fixed_version
# ---------------------------------------------------------------------------


def test_parse_fixed_version_found():
    vuln = {
        "affected": [
            {
                "package": {"name": "lodash"},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.17.22"}]}],
            }
        ]
    }
    assert parse_fixed_version(vuln, "lodash") == "4.17.22"


def test_parse_fixed_version_not_found():
    vuln = {"affected": [{"package": {"name": "other"}, "ranges": []}]}
    assert parse_fixed_version(vuln, "lodash") is None


def test_parse_fixed_version_prerelease():
    vuln = {
        "affected": [
            {
                "package": {"name": "foo"},
                "ranges": [{"events": [{"fixed": "1.0.0rc1"}]}],
            }
        ]
    }
    result = parse_fixed_version(vuln, "foo")
    assert result is None


def test_parse_fixed_version_empty():
    assert parse_fixed_version({}, "pkg") is None


def test_parse_fixed_version_pep503_mixed_separators():
    """Underscore vs hyphen in OSV name must still match via PEP 503 normalization."""
    vuln = {
        "affected": [
            {
                "package": {"name": "Requests_OAuthlib", "ecosystem": "PyPI"},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}],
            }
        ]
    }
    # Input uses hyphen; OSV data uses underscore — should match after normalization
    assert parse_fixed_version(vuln, "requests-oauthlib", "PyPI") == "2.0.0"


def test_parse_fixed_version_pep503_dot_separator():
    """Dot-separated OSV name must match hyphen input."""
    vuln = {
        "affected": [
            {
                "package": {"name": "my.package", "ecosystem": "PyPI"},
                "ranges": [{"events": [{"fixed": "1.5.0"}]}],
            }
        ]
    }
    assert parse_fixed_version(vuln, "my-package", "PyPI") == "1.5.0"


def test_parse_fixed_version_ecosystem_fallback():
    """Ecosystem defaults to empty string; comparison still works via lowercasing."""
    vuln = {
        "affected": [
            {
                "package": {"name": "lodash"},
                "ranges": [{"events": [{"fixed": "4.17.22"}]}],
            }
        ]
    }
    assert parse_fixed_version(vuln, "lodash") == "4.17.22"


# ---------------------------------------------------------------------------
# build_vulnerabilities
# ---------------------------------------------------------------------------


def test_build_vulnerabilities_basic():
    pkg = Package(name="lodash", version="4.17.20", ecosystem="npm")
    vuln_data = [
        {
            "id": "CVE-2025-0001",
            "summary": "Test vulnerability",
            "severity": [{"type": "CVSS_V3", "score": "7.5"}],
            "references": [{"url": "https://example.com"}],
            "affected": [
                {
                    "package": {"name": "lodash"},
                    "ranges": [{"events": [{"fixed": "4.17.22"}]}],
                }
            ],
        }
    ]
    vulns = build_vulnerabilities(vuln_data, pkg)
    assert len(vulns) == 1
    assert vulns[0].id == "CVE-2025-0001"
    assert vulns[0].fixed_version == "4.17.22"


def test_build_vulnerabilities_deduplication():
    pkg = Package(name="lodash", version="4.17.20", ecosystem="npm")
    vuln_data = [
        {"id": "CVE-2025-0001", "summary": "test"},
        {"id": "CVE-2025-0001", "summary": "duplicate"},
    ]
    vulns = build_vulnerabilities(vuln_data, pkg)
    assert len(vulns) == 1


def test_build_vulnerabilities_ghsa_with_cve_alias():
    """GHSA ID with CVE alias should use CVE as canonical ID."""
    pkg = Package(name="lodash", version="4.17.20", ecosystem="npm")
    vuln_data = [
        {
            "id": "GHSA-xxxx-yyyy-zzzz",
            "summary": "test",
            "aliases": ["CVE-2025-0001"],
        }
    ]
    vulns = build_vulnerabilities(vuln_data, pkg)
    assert len(vulns) == 1
    assert vulns[0].id == "CVE-2025-0001"


def test_build_vulnerabilities_no_summary():
    pkg = Package(name="pkg", version="1.0", ecosystem="pypi")
    vuln_data = [{"id": "CVE-1", "details": "Detailed description here"}]
    vulns = build_vulnerabilities(vuln_data, pkg)
    assert vulns[0].summary == "Detailed description here"


def test_build_vulnerabilities_empty():
    pkg = Package(name="pkg", version="1.0", ecosystem="pypi")
    assert build_vulnerabilities([], pkg) == []
