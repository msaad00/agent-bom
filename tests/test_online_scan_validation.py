"""Online scan-accuracy validation against live sources + a real Trivy diff.

These are ``network``-marked (skipped by CI's ``-m "not network"``) and meant to
run on demand / on a scheduled job as the *live* regression net that the
deterministic offline test cannot provide:

* live OSV — known-vulnerable packages must still resolve to their **specific**
  ground-truth CVE (not just "len > 0"), so a recall regression is caught.
* live Trivy binary diff — when the ``trivy`` binary is installed, agent-bom's
  native distro-confirmed CVEs for a pinned image must be a near-superset of
  Trivy's, proving real parity rather than canonicalization-only.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess  # nosec B404 - controlled, fixed-arg invocation of the trivy CLI in a gated test

import pytest

from agent_bom.models import Package, normalize_package_name
from agent_bom.scanners import default_scan_options, query_osv_batch, scan_packages

pytestmark = pytest.mark.network


def _scan_one(pkg: Package) -> set[str]:
    results = asyncio.run(query_osv_batch([pkg]))
    key = f"{pkg.ecosystem.lower()}:{normalize_package_name(pkg.name, pkg.ecosystem)}@{pkg.version}"
    vulns = results.get(key, [])
    ids: set[str] = set()
    for v in vulns:
        ids.add(str(v.get("id", "")))
        ids.update(str(a) for a in (v.get("aliases") or []))
    return ids


# (package, version, ecosystem, a CVE that MUST appear) — real OSV ground truth.
_GROUND_TRUTH = [
    ("requests", "2.25.0", "pypi", "CVE-2023-32681"),   # header leak on redirect
    ("jinja2", "3.1.2", "pypi", "CVE-2024-22195"),      # xmlattr XSS
    ("pyyaml", "5.3", "pypi", "CVE-2020-14343"),        # arbitrary code exec on load
]


@pytest.mark.parametrize("name,version,eco,expected_cve", _GROUND_TRUTH)
def test_live_osv_finds_specific_ground_truth_cve(name, version, eco, expected_cve) -> None:
    found = _scan_one(Package(name=name, version=version, ecosystem=eco))
    assert expected_cve in found, f"{name} {version}: live OSV must still flag {expected_cve}; got {sorted(found)[:8]}"


@pytest.mark.skipif(shutil.which("trivy") is None, reason="trivy binary not installed")
def test_agent_bom_recall_matches_trivy_on_pinned_image(tmp_path) -> None:
    """agent-bom's native image scan must recall >=90% of Trivy's CVEs (real diff)."""
    image = "alpine:3.14.2"
    # Trivy ground truth
    out = subprocess.run(  # nosec B603 - fixed args, trivy from PATH, gated by skipif
        ["trivy", "image", "--quiet", "--format", "json", "--scanners", "vuln", image],
        capture_output=True,
        text=True,
        timeout=600,
        check=True,
    )
    trivy_cves = {
        v["VulnerabilityID"]
        for res in (json.loads(out.stdout).get("Results") or [])
        for v in (res.get("Vulnerabilities") or [])
        if str(v.get("VulnerabilityID", "")).startswith("CVE-")
    }
    assert trivy_cves, "trivy returned no CVEs — image/network problem, not an agent-bom result"

    from agent_bom.image import scan_image  # local import: heavy module

    packages, _strategy = scan_image(image)
    asyncio.run(scan_packages(packages, options=default_scan_options(prefer_local_db=True)))
    ab_cves: set[str] = set()
    for pkg in packages:
        for v in getattr(pkg, "vulnerabilities", []) or []:
            ab_cves.add(str(getattr(v, "id", "")))
            ab_cves.update(str(a) for a in (getattr(v, "aliases", []) or []))

    recall = len(trivy_cves & ab_cves) / len(trivy_cves)
    missed = sorted(trivy_cves - ab_cves)
    assert recall >= 0.90, f"recall {recall:.0%} (<90%) vs Trivy on {image}; missed {missed[:15]}"
