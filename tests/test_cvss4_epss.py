"""Tests for CVSS v4.0 parsing and EPSS freshness validation."""

from __future__ import annotations

import time

from agent_bom.models import Severity
from agent_bom.scanners import _parse_cvss4_vector, parse_cvss_vector, parse_osv_severity

# ── CVSS v4.0 vector parsing ──────────────────────────────────────────────────


_FLASK_GHSA = {
    # Live api.osv.dev shape of GHSA-562c-5r94-xh97 (flask 0.12): v3.1 then v4.0.
    "id": "GHSA-562c-5r94-xh97",
    "aliases": ["CVE-2018-1000656", "PYSEC-2018-66"],
    "summary": "Flask is vulnerable to Denial of Service via incorrect encoding of JSON data",
    "severity": [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"},
        {"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"},
    ],
    "database_specific": {"severity": "HIGH"},
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "flask"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0.12.3"}]}],
        }
    ],
}


def test_live_osv_finding_keeps_the_vector_paired_with_its_score():
    from agent_bom.models import Package
    from agent_bom.output.cyclonedx_fmt import _cyclonedx_vulnerability
    from agent_bom.scanners import build_vulnerabilities

    (vuln,) = build_vulnerabilities([_FLASK_GHSA], Package(name="flask", version="0.12", ecosystem="pypi"))
    assert vuln.cvss_score == 8.7
    assert vuln.severity == Severity.HIGH
    assert vuln.cvss_vector == _FLASK_GHSA["severity"][1]["score"]

    rating = _cyclonedx_vulnerability(vuln, "pkg:pypi/flask@0.12")["ratings"][0]
    assert rating["method"] == "CVSSv4"
    assert rating["score"] == 8.7
    assert rating["vector"].startswith("CVSS:4.0/")


def test_live_osv_v3_only_finding_is_labelled_cvssv31():
    from agent_bom.models import Package
    from agent_bom.output.cyclonedx_fmt import _cyclonedx_vulnerability
    from agent_bom.scanners import build_vulnerabilities

    data = dict(_FLASK_GHSA, severity=[_FLASK_GHSA["severity"][0]])
    (vuln,) = build_vulnerabilities([data], Package(name="flask", version="0.12", ecosystem="pypi"))
    assert vuln.cvss_score == 7.5
    rating = _cyclonedx_vulnerability(vuln, "pkg:pypi/flask@0.12")["ratings"][0]
    assert (rating["method"], rating["vector"]) == ("CVSSv31", data["severity"][0]["score"])


class TestCVSS4Parsing:
    def test_single_high_confidentiality_impact_is_high_not_critical(self):
        """The former approximation scored this vector 9.4 instead of 8.7."""
        vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
        assert parse_cvss_vector(vector) == 8.7
        severity, score, source = parse_osv_severity({"severity": [{"type": "CVSS_V4", "score": vector}]})
        assert (severity, score, source) == (Severity.HIGH, 8.7, "cvss")

    def test_critical_network_vector(self):
        """CVSS:4.0 all-high network vector should score >= 9.0."""
        v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        score = parse_cvss_vector(v)
        assert score is not None
        assert score >= 9.0

    def test_low_impact_vector(self):
        """Low-impact vector should score well below critical."""
        v = "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
        score = parse_cvss_vector(v)
        assert score is not None
        assert score < 4.0

    def test_medium_vector(self):
        """Medium complexity vector should be in the 4-7 range."""
        v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"
        score = parse_cvss_vector(v)
        assert score is not None
        assert 3.0 <= score <= 7.0

    def test_with_subsequent_impact(self):
        """Subsequent-system impact should amplify the score."""
        base = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        amplified = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
        base_score = parse_cvss_vector(base)
        amp_score = parse_cvss_vector(amplified)
        assert amp_score is not None
        assert base_score is not None
        assert amp_score >= base_score

    def test_invalid_vector(self):
        """Missing required metrics should return None."""
        assert _parse_cvss4_vector("CVSS:4.0/AV:N") is None

    def test_v3_still_works(self):
        """Ensure CVSS 3.1 vectors still parse correctly."""
        v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        score = parse_cvss_vector(v)
        assert score == 9.8

    def test_unknown_version_returns_none(self):
        assert parse_cvss_vector("CVSS:2.0/AV:N") is None

    def test_zero_impact(self):
        """All-None impact should return 0.0."""
        v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"
        score = parse_cvss_vector(v)
        assert score == 0.0


# ── OSV severity with CVSS v4 ────────────────────────────────────────────────


class TestOSVSeverityV4:
    def test_cvss_v4_type_parsed(self):
        """OSV entries with CVSS_V4 type should be parsed."""
        vuln = {
            "severity": [
                {
                    "type": "CVSS_V4",
                    "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                }
            ]
        }
        severity, score, _sev_src = parse_osv_severity(vuln)
        assert score is not None
        assert score >= 9.0
        assert severity == Severity.CRITICAL

    def test_numeric_v4_score(self):
        """Numeric score in CVSS_V4 entry should be used directly."""
        vuln = {"severity": [{"type": "CVSS_V4", "score": "7.5"}]}
        severity, score, _sev_src = parse_osv_severity(vuln)
        assert score == 7.5
        assert severity == Severity.HIGH


# ── EPSS freshness validation ─────────────────────────────────────────────────


class TestEPSSFreshness:
    def test_stale_cache_entry_refetched(self):
        """Entries older than 30 days should be treated as uncached."""
        from agent_bom import enrichment

        old_cache = enrichment._epss_file_cache.copy()
        try:
            enrichment._epss_file_cache.clear()
            enrichment._epss_file_cache["CVE-2024-1234"] = {
                "score": 0.5,
                "percentile": 0.9,
                "date": "2024-01-01",
                "_cached_at": time.time() - (31 * 86400),  # 31 days ago
            }

            scores = {}
            uncached = []
            now = time.time()
            _max_age = 30 * 86400
            for cve_id in ["CVE-2024-1234"]:
                if cve_id in enrichment._epss_file_cache:
                    cached = enrichment._epss_file_cache[cve_id]
                    cached_at = cached.get("_cached_at", 0)
                    if now - cached_at < _max_age:
                        scores[cve_id] = cached
                    else:
                        uncached.append(cve_id)

            assert "CVE-2024-1234" not in scores
            assert "CVE-2024-1234" in uncached
        finally:
            enrichment._epss_file_cache.clear()
            enrichment._epss_file_cache.update(old_cache)

    def test_fresh_cache_entry_used(self):
        """Entries within 30 days should be served from cache."""
        from agent_bom import enrichment

        old_cache = enrichment._epss_file_cache.copy()
        try:
            enrichment._epss_file_cache.clear()
            enrichment._epss_file_cache["CVE-2024-5678"] = {
                "score": 0.3,
                "percentile": 0.7,
                "date": "2025-01-01",
                "_cached_at": time.time() - (5 * 86400),  # 5 days ago — fresh
            }

            now = time.time()
            _max_age = 30 * 86400
            cached = enrichment._epss_file_cache["CVE-2024-5678"]
            assert now - cached["_cached_at"] < _max_age
        finally:
            enrichment._epss_file_cache.clear()
            enrichment._epss_file_cache.update(old_cache)
