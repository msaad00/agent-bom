"""CPE version-bound semantics — inclusive/exclusive must be honored exactly.

NVD stores ``versionStartExcluding`` / ``versionEndExcluding`` etc. A boundary
version must only be vulnerable when the source says so, or agent-bom flags false
positives. Regression net for the exclusive-bound fix.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.cpe_match import match_component_cpe
from agent_bom.db.schema import init_db


def _seed(conn, *, start=None, start_op=None, end=None, end_op=None) -> None:
    conn.execute(
        "INSERT INTO cpe_matches (cve_id, criteria, vendor, product, version, "
        "version_start, version_start_op, version_end, version_end_op) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        ("CVE-BOUND", "cpe:2.3:a:acme:widget:*", "acme", "widget", None, start, start_op, end, end_op),
    )
    conn.commit()


def _hits(conn, version: str) -> bool:
    return bool(match_component_cpe(conn, "widget", version))


# The canonical example: versionStartExcluding=1.0.0, versionEndExcluding=2.0.0
@pytest.mark.parametrize(
    "version,expected",
    [("0.9.9", False), ("1.0.0", False), ("1.0.1", True), ("1.9.9", True), ("2.0.0", False), ("2.1.0", False)],
)
def test_exclusive_start_and_end(version, expected) -> None:
    conn = init_db(Path(":memory:"))
    _seed(conn, start="1.0.0", start_op="excluding", end="2.0.0", end_op="excluding")
    assert _hits(conn, version) is expected, f"{version}: expected vulnerable={expected}"


def test_inclusive_start_includes_boundary() -> None:
    conn = init_db(Path(":memory:"))
    _seed(conn, start="1.0.0", start_op="including", end="2.0.0", end_op="excluding")
    assert _hits(conn, "1.0.0") is True  # inclusive start -> boundary IS vulnerable
    assert _hits(conn, "0.9.9") is False


def test_inclusive_end_includes_boundary() -> None:
    conn = init_db(Path(":memory:"))
    _seed(conn, start="1.0.0", start_op="including", end="2.0.0", end_op="including")
    assert _hits(conn, "2.0.0") is True  # inclusive end -> boundary IS vulnerable
    assert _hits(conn, "2.0.1") is False


def test_incomparable_version_fails_safe() -> None:
    conn = init_db(Path(":memory:"))
    _seed(conn, start="1.0.0", start_op="including", end="2.0.0", end_op="excluding")
    # A garbage version that can't be ordered must NOT be flagged (no boundary invention).
    assert _hits(conn, "not-a-version") is False
