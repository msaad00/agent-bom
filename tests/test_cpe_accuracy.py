"""CPE matcher accuracy / parity harness.

Validates the ``nvd_cpe_candidate`` matcher against a curated ground-truth set of
NVD-shaped CPE applicability statements + components with known expected results.
Asserts **precision** (no false positives across vendors/products/versions) and
**recall** (every truly-affected component is caught) — the same idea as the
frozen Trivy/Grype image-parity baseline, applied to CPE matching. It also pins
the value of vendor disambiguation (the main false-positive control).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.cpe_match import match_component_cpe
from agent_bom.db.schema import init_db
from agent_bom.models import Package
from agent_bom.scanners import _scan_packages_db_conn

# Ground truth: (cve, vendor, product, exact_version, vstart, vstart_op, vend, vend_op)
_GROUND_TRUTH = [
    # apache struts RCE affecting [2.0.0, 2.5.30)
    ("CVE-T-STRUTS", "apache", "struts", None, "2.0.0", "including", "2.5.30", "excluding"),
    # log4j exact 2.14.1
    ("CVE-T-LOG4J", "apache", "log4j", "2.14.1", None, None, None, None),
    # openssl <= 3.0.6 (inclusive end)
    ("CVE-T-OPENSSL", "openssl", "openssl", None, None, None, "3.0.6", "including"),
    # a DIFFERENT vendor's product also named "log4j" with no version bounds — the
    # cross-vendor name collision that vendor filtering must suppress.
    ("CVE-T-FAKELOG", "acme", "log4j", None, None, None, None, None),
    # exclusive lower bound: versions must be strictly greater than 1.0.0
    ("CVE-T-STARTEX", "acme", "widget", None, "1.0.0", "excluding", "2.0.0", "excluding"),
]

# (component_name, version, vendor_hint, expected_cves)
_CASES = [
    ("struts", "2.5.0", "apache", {"CVE-T-STRUTS"}),   # in range
    ("struts", "2.5.30", "apache", set()),             # exclusive end -> excluded
    ("struts", "1.9.0", "apache", set()),              # below start
    ("log4j", "2.14.1", "apache", {"CVE-T-LOG4J"}),    # exact hit
    ("log4j", "2.14.2", "apache", set()),              # exact mismatch
    ("openssl", "3.0.6", None, {"CVE-T-OPENSSL"}),     # inclusive end -> included
    ("openssl", "3.0.7", None, set()),                 # above inclusive end
    # No vendor hint: the acme no-bounds "log4j" collision DOES match (apache log4j
    # is exact-2.14.1 so it does not at 9.9.9). This is the false-positive risk.
    ("log4j", "9.9.9", None, {"CVE-T-FAKELOG"}),
    # With the correct vendor hint, the acme collision is suppressed -> clean.
    ("log4j", "9.9.9", "apache", set()),
    ("widget", "1.0.0", "acme", set()),                 # exclusive start -> excluded
    ("widget", "1.0.1", "acme", {"CVE-T-STARTEX"}),     # above exclusive start -> included
    ("nonexistent", "1.0", None, set()),               # unknown product
]


def _seed(conn) -> None:
    conn.executemany(
        "INSERT INTO cpe_matches (cve_id, criteria, vendor, product, version, "
        "version_start, version_start_op, version_end, version_end_op) VALUES (?,?,?,?,?,?,?,?,?)",
        [
            (cve, f"cpe:2.3:a:{vendor}:{product}", vendor, product, ver, vs, vso, ve, veo)
            for (cve, vendor, product, ver, vs, vso, ve, veo) in _GROUND_TRUTH
        ],
    )
    conn.commit()


@pytest.mark.parametrize("name,version,vendor,expected", _CASES)
def test_cpe_matcher_precision_recall(name, version, vendor, expected) -> None:
    conn = init_db(Path(":memory:"))
    _seed(conn)
    got = {m["cve_id"] for m in match_component_cpe(conn, name, version, vendor=vendor)}
    assert got == expected, f"{name}@{version} vendor={vendor}: expected {expected}, got {got}"


def test_vendor_filter_eliminates_cross_vendor_false_positive() -> None:
    """The headline precision property: a vendor hint removes same-named-product noise."""
    conn = init_db(Path(":memory:"))
    _seed(conn)
    no_hint = {m["cve_id"] for m in match_component_cpe(conn, "log4j", "9.9.9")}
    with_hint = {m["cve_id"] for m in match_component_cpe(conn, "log4j", "9.9.9", vendor="apache")}
    assert "CVE-T-FAKELOG" in no_hint  # the collision is reachable without a vendor
    assert "CVE-T-FAKELOG" not in with_hint  # ...and suppressed with one


def test_batch_scanner_uses_cpe_candidates_with_vendor_hint(monkeypatch: pytest.MonkeyPatch) -> None:
    """Large scans take the batch path; opt-in CPE matching must still run there."""
    from agent_bom import config

    monkeypatch.setattr(config, "ENABLE_CPE_MATCH", True)
    conn = init_db(Path(":memory:"))
    conn.execute(
        "INSERT INTO vulns (id, summary, severity, cvss_score, cvss_vector, fixed_version, cwe_ids, aliases, source) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("CVE-T-BATCH", "batch CPE candidate", "high", 8.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "", "CWE-94", "", "nvd"),
    )
    conn.execute(
        "INSERT INTO cpe_matches (cve_id, criteria, vendor, product, version, "
        "version_start, version_start_op, version_end, version_end_op) VALUES (?,?,?,?,?,?,?,?,?)",
        ("CVE-T-BATCH", "cpe:2.3:a:apache:widget", "apache", "widget", None, "1.0.0", "including", "2.0.0", "excluding"),
    )
    conn.commit()

    packages = [
        Package(name=f"dummy-{idx}", version="1.0.0", ecosystem="generic")
        for idx in range(50)
    ]
    target = Package(name="widget", version="1.2.3", ecosystem="generic", purl="pkg:generic/apache/widget@1.2.3")
    packages.append(target)

    covered: set[str] = set()
    total = _scan_packages_db_conn(conn, packages, covered)

    assert total == 1
    assert [v.id for v in target.vulnerabilities] == ["CVE-T-BATCH"]
    assert target.vulnerabilities[0].match_confidence_tier == "nvd_cpe_candidate"
