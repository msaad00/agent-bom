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
