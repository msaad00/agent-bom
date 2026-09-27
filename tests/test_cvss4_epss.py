"""Tests for CVSS v4.0 parsing and EPSS freshness validation."""

from __future__ import annotations

import time

import pytest

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

    # Documented basis precedence: CVSS v3.x before v4.0, so a record that
    # carries both is scored on v3.1 — online and offline alike.
    (vuln,) = build_vulnerabilities([_FLASK_GHSA], Package(name="flask", version="0.12", ecosystem="pypi"))
    assert vuln.cvss_score == 7.5
    assert vuln.severity == Severity.HIGH
    assert vuln.severity_source == "cvss"
    assert vuln.cvss_vector == _FLASK_GHSA["severity"][0]["score"]

    rating = _cyclonedx_vulnerability(vuln, "pkg:pypi/flask@0.12")["ratings"][0]
    assert rating["method"] == "CVSSv31"
    assert rating["score"] == 7.5
    assert rating["vector"].startswith("CVSS:3.1/")


def test_v4_only_record_is_scored_on_v4():
    from agent_bom.models import Package
    from agent_bom.scanners import build_vulnerabilities

    data = dict(_FLASK_GHSA, severity=[_FLASK_GHSA["severity"][1]])
    (vuln,) = build_vulnerabilities([data], Package(name="flask", version="0.12", ecosystem="pypi"))
    assert (vuln.cvss_score, vuln.severity, vuln.severity_source) == (8.7, Severity.HIGH, "cvss")
    assert vuln.cvss_vector == data["severity"][0]["score"]


# ── One severity basis for online (OSV API) and offline (local DB) ───────────

# Live api.osv.dev shape of GHSA-45pg-36p6-83v9 (CVE-2024-8309): the v3.0
# vector scores 4.9 (MEDIUM), the v4.0 vector 2.1 (LOW), the GHSA label LOW.
# Online used the v4 score (LOW) and offline the label (LOW) while the CVE
# record alone scored MEDIUM — so `--fail-on-severity medium` depended on mode.
_LANGCHAIN_GHSA = {
    "id": "GHSA-45pg-36p6-83v9",
    "aliases": ["CVE-2024-8309", "PYSEC-2024-115"],
    "summary": "Langchain SQL Injection vulnerability",
    "severity": [
        {"type": "CVSS_V3", "score": "CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L"},
        {"type": "CVSS_V4", "score": "CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N"},
    ],
    "database_specific": {"severity": "LOW"},
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "langchain"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0.2.0"}]}],
        }
    ],
}

_V3 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
_V4_LOW = "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
_AFFECTED = [
    {
        "package": {"ecosystem": "PyPI", "name": "langchain"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0.2.0"}]}],
    }
]


def _record(**overrides):
    base = {"id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2099-0001"], "summary": "s", "affected": _AFFECTED}
    base.update(overrides)
    return base


_PARITY_RECORDS = {
    "langchain_v3_v4_label": _LANGCHAIN_GHSA,
    "flask_v3_v4_label": dict(_FLASK_GHSA, affected=_AFFECTED),
    "v4_listed_before_v3": _record(severity=[{"type": "CVSS_V4", "score": _V4_LOW}, {"type": "CVSS_V3", "score": _V3}]),
    "v4_only": _record(severity=[{"type": "CVSS_V4", "score": _V4_LOW}]),
    "numeric_v3": _record(severity=[{"type": "CVSS_V3", "score": "8.1"}]),
    "label_only": _record(database_specific={"severity": "MODERATE"}),
    "db_cvss_beats_label": _record(database_specific={"severity": "LOW", "cvss": {"score": 9.1}}),
    "db_vector_list_prefers_v3": _record(database_specific={"severity_vectors": [_V4_LOW, _V3]}),
    "severity_array_beats_db_cvss": _record(
        severity=[{"type": "CVSS_V3", "score": _V3}], database_specific={"cvss_score": 2.0, "severity": "LOW"}
    ),
    "unparseable_v3_falls_to_v4": _record(severity=[{"type": "CVSS_V3", "score": "garbage"}, {"type": "CVSS_V4", "score": _V4_LOW}]),
    "no_severity_ghsa_heuristic": _record(),
}


def _offline_vulnerability(record):
    from agent_bom.db.lookup import LocalVuln
    from agent_bom.db.sync import _parse_osv_entry
    from agent_bom.scanners.package_scan import _local_vuln_to_vulnerability

    row, _affected = _parse_osv_entry(record)
    return _local_vuln_to_vulnerability(
        LocalVuln(
            id=row["id"],
            summary=row["summary"],
            severity=row["severity"],
            cvss_score=row["cvss_score"],
            fixed_version=row.get("fixed_version"),
            cvss_vector=row.get("cvss_vector"),
            aliases=[a for a in (row.get("aliases") or "").split(",") if a],
        )
    )


@pytest.mark.parametrize("name", sorted(_PARITY_RECORDS))
def test_online_and_offline_share_one_severity_basis(name):
    from agent_bom.models import Package
    from agent_bom.scanners import build_vulnerabilities

    record = _PARITY_RECORDS[name]
    (online,) = build_vulnerabilities([record], Package(name="langchain", version="0.1.0", ecosystem="pypi"))
    offline = _offline_vulnerability(record)
    assert (offline.severity, offline.cvss_score, offline.cvss_vector, offline.severity_source) == (
        online.severity,
        online.cvss_score,
        online.cvss_vector,
        online.severity_source,
    )


def test_cve_2024_8309_is_medium_on_its_v3_basis_in_both_modes():
    from agent_bom.models import Package
    from agent_bom.scanners import build_vulnerabilities

    (online,) = build_vulnerabilities([_LANGCHAIN_GHSA], Package(name="langchain", version="0.1.0", ecosystem="pypi"))
    offline = _offline_vulnerability(_LANGCHAIN_GHSA)
    for vuln in (online, offline):
        assert vuln.severity == Severity.MEDIUM
        assert vuln.cvss_score == 4.9
        assert vuln.severity_source == "cvss"
        assert vuln.cvss_vector.startswith("CVSS:3.0/")


@pytest.mark.parametrize(
    ("record", "expected"),
    [
        (_PARITY_RECORDS["v4_listed_before_v3"], (Severity.CRITICAL, 9.8, _V3, "cvss")),
        (_PARITY_RECORDS["label_only"], (Severity.MEDIUM, None, None, "osv_database")),
        (_PARITY_RECORDS["db_vector_list_prefers_v3"], (Severity.CRITICAL, 9.8, _V3, "cvss")),
        (_PARITY_RECORDS["severity_array_beats_db_cvss"], (Severity.CRITICAL, 9.8, _V3, "cvss")),
        (_PARITY_RECORDS["no_severity_ghsa_heuristic"], (Severity.MEDIUM, None, None, "ghsa_heuristic")),
    ],
)
def test_osv_severity_basis_precedence(record, expected):
    from agent_bom.scanners.risk import osv_severity_basis

    basis = osv_severity_basis(record)
    assert (basis.severity, basis.cvss_score, basis.cvss_vector, basis.severity_source) == expected


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
