"""SQLite schema for the local vulnerability database.

Tables:
    vulns          — core vulnerability records (CVE/OSV ID, severity, CVSS, summary)
    affected       — package + version ranges affected by a vuln
    epss_scores    — EPSS probability scores per CVE
    kev_entries    — CISA KEV catalog entries
    sync_meta      — last-sync timestamps per source
"""

from __future__ import annotations

import logging
import os
import sqlite3
from pathlib import Path

_logger = logging.getLogger(__name__)

# Default DB path — overridable via env var
_DEFAULT_DB_DIR = Path.home() / ".agent-bom" / "db"
DB_PATH: Path = Path(os.environ.get("AGENT_BOM_DB_PATH", str(_DEFAULT_DB_DIR / "vulns.db")))

# Schema version — bump when DDL changes incompatibly
_SCHEMA_VERSION = 1

_DDL = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_version (
    version     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS vulns (
    id              TEXT PRIMARY KEY,   -- CVE-XXXX-YYYY or GHSA-* or OSV-*
    summary         TEXT NOT NULL,
    severity        TEXT NOT NULL,      -- critical | high | medium | low | unknown
    cvss_score      REAL,
    cvss_vector     TEXT,
    fixed_version   TEXT,
    published       TEXT,               -- ISO-8601
    modified        TEXT,               -- ISO-8601
    source          TEXT NOT NULL       -- osv | nvd | ghsa | nvidia
);

CREATE TABLE IF NOT EXISTS affected (
    vuln_id         TEXT NOT NULL REFERENCES vulns(id) ON DELETE CASCADE,
    ecosystem       TEXT NOT NULL,      -- PyPI | npm | Go | Maven | …
    package_name    TEXT NOT NULL,      -- normalized (lowercase, PEP 503 for PyPI)
    introduced      TEXT,               -- semver or "" (means all)
    fixed           TEXT,               -- semver or "" (means no fix)
    last_affected   TEXT,
    PRIMARY KEY (vuln_id, ecosystem, package_name, introduced)
);
CREATE INDEX IF NOT EXISTS idx_affected_pkg ON affected(ecosystem, package_name);

CREATE TABLE IF NOT EXISTS epss_scores (
    cve_id          TEXT PRIMARY KEY,
    probability     REAL NOT NULL,      -- 0.0–1.0
    percentile      REAL,               -- 0.0–100.0
    updated_at      TEXT NOT NULL       -- ISO-8601
);

CREATE TABLE IF NOT EXISTS kev_entries (
    cve_id          TEXT PRIMARY KEY,
    date_added      TEXT,
    due_date        TEXT,
    product         TEXT,
    vendor_project  TEXT
);

CREATE TABLE IF NOT EXISTS sync_meta (
    source          TEXT PRIMARY KEY,   -- osv | epss | kev
    last_synced     TEXT,               -- ISO-8601 UTC
    record_count    INTEGER DEFAULT 0
);
"""


def init_db(path: Path | None = None) -> sqlite3.Connection:
    """Open (and initialise if needed) the local vuln DB.

    Creates the DB file and parent directories if they don't exist.
    Returns an open connection with WAL mode and foreign keys enabled.
    """
    db_path = path or DB_PATH
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.executescript(_DDL)

    # Seed schema_version on first creation
    row = conn.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
    if row is None:
        conn.execute("INSERT INTO schema_version(version) VALUES (?)", (_SCHEMA_VERSION,))
        conn.commit()
        _logger.debug("Initialised local vuln DB at %s (schema v%d)", db_path, _SCHEMA_VERSION)
    else:
        current = row["version"]
        if current < _SCHEMA_VERSION:
            _logger.warning(
                "DB schema v%d is older than code v%d — run 'agent-bom db update' to migrate",
                current,
                _SCHEMA_VERSION,
            )

    return conn


def db_stats(conn: sqlite3.Connection) -> dict:
    """Return a summary dict of record counts and last-sync times."""
    stats: dict = {}
    stats["vuln_count"] = conn.execute("SELECT COUNT(*) FROM vulns").fetchone()[0]
    stats["affected_count"] = conn.execute("SELECT COUNT(*) FROM affected").fetchone()[0]
    stats["epss_count"] = conn.execute("SELECT COUNT(*) FROM epss_scores").fetchone()[0]
    stats["kev_count"] = conn.execute("SELECT COUNT(*) FROM kev_entries").fetchone()[0]
    rows = conn.execute("SELECT source, last_synced, record_count FROM sync_meta").fetchall()
    stats["sync_meta"] = {r["source"]: {"last_synced": r["last_synced"], "count": r["record_count"]} for r in rows}
    return stats
