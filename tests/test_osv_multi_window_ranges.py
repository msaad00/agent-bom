"""Multi-window OSV range handling.

OSV encodes per-branch fixes as alternating ``introduced``/``fixed`` events
inside a *single* range object. A parser that keeps only the last event pair
collapses every branch but one, so versions fixed on an earlier branch are
reported as unaffected — a silent false negative.

Shape below mirrors PYSEC-2024-102 (Django), which fixes 4.2.16, 5.0.9 and
5.1.1 on their respective branches.
"""

import json
import sqlite3

import pytest

from agent_bom.db.lookup import lookup_package
from agent_bom.db.schema import _SCHEMA_VERSION, init_db
from agent_bom.db.sync import _ingest_osv_file, _parse_osv_entry

MULTI_WINDOW_ADVISORY = {
    "id": "PYSEC-TEST-MULTIWINDOW",
    "summary": "Multi-branch fix advisory",
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "django"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [
                        {"introduced": "4.2"},
                        {"fixed": "4.2.16"},
                        {"introduced": "5.0"},
                        {"fixed": "5.0.9"},
                        {"introduced": "5.1"},
                        {"fixed": "5.1.1"},
                    ],
                }
            ],
        }
    ],
}

# Two branches that both start at "0" — a shape the affected-table primary key
# must be able to hold twice, otherwise the second row overwrites the first.
SHARED_INTRODUCED_ADVISORY = {
    "id": "PYSEC-TEST-SHAREDINTRO",
    "summary": "Two branches both introduced at 0",
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "samplepkg"},
            "ranges": [
                {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.4"}]},
                {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.7"}]},
            ],
        }
    ],
}


def _ingest(conn, advisory):
    return _ingest_osv_file(conn, json.dumps(advisory).encode(), f"{advisory['id']}.json")


def test_parse_emits_one_row_per_window():
    """Each (introduced, fixed) pair becomes its own affected row."""
    parsed = _parse_osv_entry(MULTI_WINDOW_ADVISORY)
    assert parsed is not None
    _vuln_row, affected_rows = parsed

    windows = {(row["introduced"], row["fixed"]) for row in affected_rows}
    assert windows == {("4.2", "4.2.16"), ("5.0", "5.0.9"), ("5.1", "5.1.1")}


@pytest.mark.parametrize("version", ["4.2.5", "5.0.5", "5.1.0"])
def test_versions_on_every_branch_are_reported_affected(tmp_path, version):
    """A vulnerable version on any branch must be found, not just the last."""
    conn = init_db(tmp_path / "vulns.db")
    _ingest(conn, MULTI_WINDOW_ADVISORY)

    hits = lookup_package(conn, "PyPI", "django", version)

    assert [v.id for v in hits] == ["PYSEC-TEST-MULTIWINDOW"], f"django {version} is inside a vulnerable window but was not reported"
    conn.close()


@pytest.mark.parametrize("version", ["4.2.16", "5.0.9", "5.1.1"])
def test_fixed_versions_on_every_branch_are_clean(tmp_path, version):
    """The fix version of each branch must not be reported as affected."""
    conn = init_db(tmp_path / "vulns.db")
    _ingest(conn, MULTI_WINDOW_ADVISORY)

    assert lookup_package(conn, "PyPI", "django", version) == []
    conn.close()


def test_branches_sharing_an_introduced_bound_both_persist(tmp_path):
    """Two windows with the same ``introduced`` must not overwrite each other.

    Guards the affected-table primary key: keying on ``introduced`` alone
    silently drops every branch after the first.
    """
    conn = init_db(tmp_path / "vulns.db")
    _ingest(conn, SHARED_INTRODUCED_ADVISORY)

    rows = conn.execute("SELECT introduced, fixed FROM affected WHERE package_name = 'samplepkg' ORDER BY fixed").fetchall()

    assert [tuple(r) for r in rows] == [("0", "1.4"), ("0", "2.7")]
    conn.close()


_V4_AFFECTED_DDL = """
CREATE TABLE vulns (
    id              TEXT PRIMARY KEY,
    summary         TEXT NOT NULL,
    severity        TEXT,
    cvss_score      REAL,
    cvss_vector     TEXT,
    fixed_version   TEXT,
    cwe_ids         TEXT DEFAULT '',
    aliases         TEXT DEFAULT '',
    published       TEXT,
    modified        TEXT,
    source          TEXT
);
CREATE TABLE affected (
    vuln_id         TEXT NOT NULL REFERENCES vulns(id) ON DELETE CASCADE,
    ecosystem       TEXT NOT NULL,
    package_name    TEXT NOT NULL,
    introduced      TEXT,
    fixed           TEXT,
    last_affected   TEXT,
    PRIMARY KEY (vuln_id, ecosystem, package_name, introduced)
);
CREATE TABLE sync_meta (
    source          TEXT PRIMARY KEY,
    last_synced     TEXT,
    record_count    INTEGER DEFAULT 0,
    metadata_json   TEXT DEFAULT ''
);
CREATE TABLE schema_version (version INTEGER NOT NULL);
"""


def _build_v4_db(path):
    conn = sqlite3.connect(path)
    conn.executescript(_V4_AFFECTED_DDL)
    conn.execute("INSERT INTO vulns(id, summary) VALUES ('CVE-0000-0001', 'legacy row')")
    conn.execute("INSERT INTO affected VALUES ('CVE-0000-0001', 'pypi', 'legacypkg', '1.0', '1.2', '')")
    conn.execute("INSERT INTO sync_meta(source, last_synced) VALUES ('osv', '2026-01-01T00:00:00Z')")
    conn.execute("INSERT INTO schema_version(version) VALUES (4)")
    conn.commit()
    conn.close()


def test_v4_database_migrates_and_forces_resync(tmp_path):
    """v4 → v5 keeps existing windows and clears sync state for a full re-ingest."""
    db_file = tmp_path / "legacy.db"
    _build_v4_db(db_file)

    conn = init_db(db_file)

    assert conn.execute("SELECT version FROM schema_version").fetchone()[0] == _SCHEMA_VERSION
    # The v4 row was a genuine window — an incomplete set, not a wrong one.
    assert conn.execute("SELECT COUNT(*) FROM affected").fetchone()[0] == 1
    # Cleared so the next `db update` re-ingests and restores dropped windows.
    assert conn.execute("SELECT COUNT(*) FROM sync_meta").fetchone()[0] == 0
    conn.close()


def test_migrated_database_accepts_sibling_windows(tmp_path):
    """After migrating, a re-ingest can store windows the v4 key would collide on."""
    db_file = tmp_path / "legacy.db"
    _build_v4_db(db_file)
    conn = init_db(db_file)

    _ingest(conn, SHARED_INTRODUCED_ADVISORY)

    rows = conn.execute("SELECT COUNT(*) FROM affected WHERE package_name = 'samplepkg'").fetchone()
    assert rows[0] == 2
    conn.close()
