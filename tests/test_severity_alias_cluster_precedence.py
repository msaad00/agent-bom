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
            _local("GHSA-gmj6-6f8f-6699", "medium", ["CVE-2024-56201"], 8.8),
            _local("PYSEC-2026-1472", "high", ["CVE-2024-56201"], 8.8),
        ]
    )
    assert merged[0].severity_source, "an escalated band must say which advisory set it"
    assert "PYSEC-2026-1472" in str(merged[0].severity_source)
