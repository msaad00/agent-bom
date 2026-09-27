"""One CVE, several advisories, conflicting bands — take the most severe.

The vulnerability DB carries a separate row per advisory source, so a single
CVE can appear as GHSA-… and PYSEC-… with *different* severity labels (GitHub
rates several Jinja2 sandbox escapes "Moderate" where PySec rates them "high").

The local-DB merge skipped any advisory whose id or alias had already been
seen, so whichever row the query returned first won. GHSA sorted first, its
"medium" stood, PySec's "high" was discarded, and the finding shipped as
`severity: medium` beside `cvss_score: 8.8` — a band no CVSS scale produces
from that score. `--fail-on-severity high` then exited 0 on it.

For a security scanner, resolving a disagreement downward silently under-blocks.
"""

from __future__ import annotations

from types import SimpleNamespace

from agent_bom.models import Severity


def _local(vuln_id: str, severity: str, aliases: list[str], cvss: float):
    return SimpleNamespace(
        id=vuln_id,
        summary="Jinja2 sandbox escape",
        severity=severity,
        cvss_score=cvss,
        cvss_vector=None,
        fixed_version="3.1.5",
        aliases=aliases,
        source="osv",
        epss_probability=None,
        epss_percentile=None,
        is_kev=False,
        kev_date_added=None,
        published_at=None,
        modified_at=None,
        cwe_ids=[],
    )


def _merge(local_vulns):
    from agent_bom.scanners.package_scan import merge_local_vulns

    pkg = SimpleNamespace(vulnerabilities=[])
    merge_local_vulns(pkg, local_vulns)
    return pkg.vulnerabilities


def test_conflicting_bands_resolve_to_the_most_severe():
    """GHSA says medium, PySec says high, same CVE — high must win."""
    merged = _merge(
        [
            _local("GHSA-gmj6-6f8f-6699", "medium", ["CVE-2024-56201"], 8.8),
            _local("PYSEC-2026-1472", "high", ["CVE-2024-56201"], 8.8),
        ]
    )
    assert len(merged) == 1, "the alias cluster must still collapse to one finding"
    assert merged[0].severity == Severity.HIGH


def test_resolution_is_not_dependent_on_advisory_order():
    """The same cluster in the opposite order must give the same answer."""
    forward = _merge(
        [
            _local("GHSA-gmj6-6f8f-6699", "medium", ["CVE-2024-56201"], 8.8),
            _local("PYSEC-2026-1472", "high", ["CVE-2024-56201"], 8.8),
        ]
    )
    reverse = _merge(
        [
            _local("PYSEC-2026-1472", "high", ["CVE-2024-56201"], 8.8),
            _local("GHSA-gmj6-6f8f-6699", "medium", ["CVE-2024-56201"], 8.8),
        ]
    )
    assert forward[0].severity == reverse[0].severity == Severity.HIGH


def test_agreeing_advisories_are_left_alone():
    """No disagreement, no escalation — this must not inflate severity."""
    merged = _merge(
        [
            _local("GHSA-aaaa-bbbb-cccc", "medium", ["CVE-2024-00001"], 5.4),
            _local("PYSEC-2026-9999", "medium", ["CVE-2024-00001"], 5.4),
        ]
    )
    assert len(merged) == 1
    assert merged[0].severity == Severity.MEDIUM


def test_distinct_cves_are_never_merged():
    """Escalation must not leak across unrelated advisories."""
    merged = _merge(
        [
            _local("GHSA-aaaa-bbbb-cccc", "medium", ["CVE-2024-00001"], 5.4),
            _local("PYSEC-2026-9999", "critical", ["CVE-2024-00002"], 9.8),
        ]
    )
    assert len(merged) == 2
    assert {v.severity for v in merged} == {Severity.MEDIUM, Severity.CRITICAL}


def test_escalation_records_where_the_band_came_from():
    """severity_source shipped empty, which is why this was hard to diagnose."""
    merged = _merge(
        [
            _local("GHSA-gmj6-6f8f-6699", "medium", ["CVE-2024-56201"], 5.4),
            _local("PYSEC-2026-1472", "high", ["CVE-2024-56201"], 8.8),
        ]
    )
    assert merged[0].severity == Severity.HIGH
    assert merged[0].severity_source, "an escalated band must say which advisory set it"
    assert "PYSEC-2026-1472" in str(merged[0].severity_source)


def test_online_and_offline_alias_clusters_share_order_independent_evidence():
    from dataclasses import asdict
    from itertools import permutations

    from agent_bom.models import Package
    from agent_bom.scanners.package_scan import build_vulnerabilities

    raw = [
        {"id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2026-1234"], "summary": "lower", "database_specific": {"severity": "MODERATE"}},
        {"id": "PYSEC-2026-42", "aliases": ["CVE-2026-1234"], "summary": "higher", "database_specific": {"severity": "HIGH"}},
    ]
    online = [build_vulnerabilities(list(order), Package(name="example", version="", ecosystem="pypi")) for order in permutations(raw)]
    assert all(len(rows) == 1 and rows[0].severity == Severity.HIGH for rows in online)
    assert asdict(online[0][0]) == asdict(online[1][0])
    offline = _merge([_local(r["id"], r["database_specific"]["severity"], r["aliases"], None) for r in raw])
    for field in ("id", "severity", "severity_source", "aliases", "cvss_score", "cvss_vector"):
        assert getattr(online[0][0], field) == getattr(offline[0], field)


def test_transitive_alias_bridge_collapses_all_clusters_with_matching_score():
    from dataclasses import asdict
    from itertools import permutations

    from agent_bom.models import Package, Vulnerability
    from agent_bom.scanners.package_scan import merge_scanner_vulnerabilities

    records = [
        Vulnerability(id="GHSA-a", summary="low", severity=Severity.LOW, cvss_score=3.1, aliases=["CVE-2026-1234"]),
        Vulnerability(id="PYSEC-b", summary="high", severity=Severity.HIGH, cvss_score=8.8, aliases=["GHSA-b"]),
        Vulnerability(id="GHSA-b", summary="bridge", severity=Severity.MEDIUM, cvss_score=5.4, aliases=["GHSA-a"]),
    ]
    outcomes = []
    for order in permutations(records):
        pkg = Package(name="example", version="1", ecosystem="pypi")
        added = merge_scanner_vulnerabilities(pkg, list(order))
        assert len(added) == len(pkg.vulnerabilities) == 1
        vuln = pkg.vulnerabilities[0]
        assert vuln.id == "CVE-2026-1234"
        assert vuln.cvss_score == 8.8
        assert vuln.severity == Severity.HIGH
        assert set(vuln.aliases) == {"GHSA-a", "GHSA-b", "PYSEC-b"}
        outcomes.append(asdict(vuln))
    assert all(item == outcomes[0] for item in outcomes)


def test_incremental_alias_merge_preserves_winning_advisory_provenance():
    from dataclasses import asdict
    from itertools import permutations

    from agent_bom.models import Package, Vulnerability
    from agent_bom.scanners.package_scan import merge_scanner_vulnerabilities

    records = [
        Vulnerability(id="PYSEC-winner", summary="high", severity=Severity.HIGH, cvss_score=8.8, aliases=["GHSA-bridge"]),
        Vulnerability(id="GHSA-first", summary="low", severity=Severity.LOW, aliases=["CVE-2026-1234"]),
        Vulnerability(id="GHSA-bridge", summary="bridge", severity=Severity.MEDIUM, aliases=["GHSA-first"]),
    ]
    outcomes = []
    for order in permutations(records):
        pkg = Package(name="example", version="1", ecosystem="pypi")
        for record in order:
            merge_scanner_vulnerabilities(pkg, [record])
        assert len(pkg.vulnerabilities) == 1
        winner = pkg.vulnerabilities[0]
        assert winner.severity_source == "advisory:PYSEC-winner"
        outcomes.append(asdict(winner))
    assert all(outcome == outcomes[0] for outcome in outcomes)
