"""Opening the vuln DB must not read the whole file.

`init_db()` ran `PRAGMA quick_check` on **every** open
(`src/agent_bom/db/schema.py`), and `intel_lookup` opens the DB once per
request in four places. On a fully synced `vulns.db` (1.95 GB) that made every
`/v1/intel/*` call re-validate the entire database:

    GET /v1/intel/advisories/CVE-2024-3094   2,218 bytes in 58.27 s
    GET /v1/intel/sources                    9,450 bytes in 22.24 s
    POST /v1/intel/match                    20,861 bytes in 14.94 s

    PRAGMA quick_check on that file: 191 s cold, 10-21 s warm

It reaches a shipped surface: the Integrations → Intel panel calls
`getIntelSources()` with `{ ttlMs: 0 }`, so the client cache is explicitly
disabled and every visit pays it again.

The docstring justified the cost by claiming `quick_check` "validates the
B-tree structure without reading every row". That premise is wrong —
`quick_check` walks every page of every btree; what it skips is the
index-vs-table cross-check that `integrity_check` adds. So the check was never
cheap, and it was never free to put on an open.

It is invisible in dev and CI because the cost scales with the size of
`vulns.db`, not with the estate — the one axis fixtures never exercise. These
tests therefore assert the *structure* (who runs the check) rather than timing,
which would pass on any small fixture DB.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from agent_bom.db import schema


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "vulns.db"


def _spy_on_integrity(monkeypatch: pytest.MonkeyPatch) -> list[Path]:
    checked: list[Path] = []

    def _record(conn: sqlite3.Connection, path: Path) -> None:
        checked.append(path)

    monkeypatch.setattr(schema, "_check_integrity", _record)
    return checked


def test_a_plain_open_does_not_validate_the_database(db_path, monkeypatch) -> None:
    """The read path: four intel endpoints open the DB per request."""
    checked = _spy_on_integrity(monkeypatch)
    conn = schema.init_db(db_path)
    conn.close()
    assert checked == [], "opening the vuln DB still runs a full-file integrity check"


def test_the_check_is_still_available_when_asked_for(db_path, monkeypatch) -> None:
    """Removing the cost must not remove the capability."""
    checked = _spy_on_integrity(monkeypatch)
    conn = schema.init_db(db_path, verify_integrity=True)
    conn.close()
    assert checked == [db_path]


def test_a_plain_open_still_produces_a_usable_database(db_path) -> None:
    """The whole point is that everything else about the open is unchanged."""
    conn = schema.init_db(db_path)
    try:
        version = conn.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
        assert version is not None and version[0] >= 1
        assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    finally:
        conn.close()


def test_verification_still_reports_a_corrupt_database(db_path, caplog) -> None:
    """A real corrupt file must still be caught on the path that opts in."""
    schema.init_db(db_path).close()
    # Truncating mid-file leaves a header SQLite accepts and pages it cannot.
    with open(db_path, "r+b") as handle:
        handle.truncate(max(1024, db_path.stat().st_size // 2))

    with caplog.at_level("WARNING"):
        try:
            schema.init_db(db_path, verify_integrity=True).close()
        except sqlite3.DatabaseError:
            return  # refusing outright is also an acceptable answer
    assert any("integrity" in record.message.lower() for record in caplog.records), caplog.text


def test_the_intel_read_path_opens_without_verifying(monkeypatch, db_path) -> None:
    """The four per-request opens are the reason this matters."""
    import agent_bom.intel_lookup as intel

    checked = _spy_on_integrity(monkeypatch)
    monkeypatch.setattr(intel, "resolve_intel_db_path", lambda: db_path)
    intel.list_intel_sources()
    assert checked == [], "an intel request still triggers a full-file integrity check"
