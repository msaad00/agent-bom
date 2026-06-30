"""Regression: alpine 3.14.2 distro-confirmed CVE set should be Trivy-superset."""

from __future__ import annotations

from agent_bom.advisory_ids import all_cve_identifiers, canonical_vulnerability_id
from agent_bom.db.lookup import LocalVuln
from agent_bom.finding import blast_radius_to_finding
from agent_bom.models import BlastRadius, Package, Severity, Vulnerability

# Frozen Trivy 0.69.3 unique CVE IDs for alpine:3.14.2 (distro-confirmed baseline).
TRIVY_ALPINE_3_14_2_CVES = frozenset(
    {
        "CVE-2018-25032",
        "CVE-2021-42374",
        "CVE-2021-42375",
        "CVE-2021-42378",
        "CVE-2021-42379",
        "CVE-2021-42380",
        "CVE-2021-42381",
        "CVE-2021-42382",
        "CVE-2021-42383",
        "CVE-2021-42384",
        "CVE-2021-42385",
        "CVE-2021-42386",
        "CVE-2022-0778",
        "CVE-2022-2097",
        "CVE-2022-28391",
        "CVE-2022-37434",
        "CVE-2022-4304",
        "CVE-2022-4450",
        "CVE-2023-0286",
        "CVE-2023-0464",
        "CVE-2023-0465",
        "CVE-2023-2650",
    }
)

# Representative alpine secdb rows agent-bom may emit as ALPINE-CVE-* before canonicalization.
ALPINE_ADVISORY_ROWS = [
    "ALPINE-CVE-2022-0778",
    "ALPINE-CVE-2022-2097",
    "ALPINE-CVE-2022-28391",
    "ALPINE-CVE-2021-42374",
    "CVE-2023-0286",
]


def test_alpine_advisory_rows_normalize_to_cve_ids() -> None:
    normalized = {canonical_vulnerability_id(row)[0] for row in ALPINE_ADVISORY_ROWS}
    assert all(cid.startswith("CVE-") for cid in normalized)
    assert "CVE-2022-0778" in normalized


def test_finding_export_includes_canonical_cve_ids() -> None:
    pkg = Package(name="busybox", version="1.33.1-r3", ecosystem="apk", distro_version="3.14.2")
    vuln = Vulnerability(
        id="CVE-2022-28391",
        summary="zlib issue",
        severity=Severity.HIGH,
        aliases=["ALPINE-CVE-2022-28391"],
        match_confidence_tier="distro_confirmed",
    )
    br = BlastRadius(
        vulnerability=vuln,
        package=pkg,
        risk_score=7.0,
        affected_agents=[],
        affected_servers=[],
        exposed_credentials=[],
        exposed_tools=[],
    )
    finding = blast_radius_to_finding(br)
    payload = finding.to_dict()
    assert payload["cve_id"] == "CVE-2022-28391"
    assert payload["cve_ids"] == ["CVE-2022-28391"]
    assert payload["match_confidence_tier"] == "distro_confirmed"
    assert "ALPINE-CVE-2022-28391" in payload["advisory_aliases"]


def test_trivy_baseline_subset_of_canonicalized_local_rows() -> None:
    """Every frozen Trivy CVE must be derivable from at least one advisory id form."""
    from agent_bom.scanners import _local_vuln_to_vulnerability

    # Simulate a superset of distro-confirmed rows including one Trivy-only gap filler.
    simulated_rows = list(TRIVY_ALPINE_3_14_2_CVES) + ["CVE-2020-28928"]
    emitted: set[str] = set()
    for advisory_id in simulated_rows:
        if advisory_id.startswith("ALPINE-"):
            lv = LocalVuln(id=advisory_id, summary="", severity="high", cvss_score=7.0, fixed_version="1.0-r1")
        else:
            lv = LocalVuln(
                id=f"ALPINE-CVE-{advisory_id.removeprefix('CVE-')}",
                summary="",
                severity="high",
                cvss_score=7.0,
                fixed_version="1.0-r1",
            )
        vuln = _local_vuln_to_vulnerability(lv)
        emitted.update(all_cve_identifiers(vuln.id, vuln.aliases))

    assert TRIVY_ALPINE_3_14_2_CVES.issubset(emitted)
