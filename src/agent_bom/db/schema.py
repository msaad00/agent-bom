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
import stat
import tempfile
from pathlib import Path

_logger = logging.getLogger(__name__)

# Default DB path — overridable via env var
_DEFAULT_DB_DIR = Path.home() / ".agent-bom" / "db"
_RAW_DB_PATH = os.environ.get("AGENT_BOM_DB_PATH", str(_DEFAULT_DB_DIR / "vulns.db"))


def _validated_db_path(raw: str) -> Path:
    """Resolve and validate the DB path.

    Accepts paths inside the user's home directory or /tmp (for tests).
    Rejects path traversal, symlink escapes, and arbitrary filesystem locations.
    Raises ``ValueError`` on invalid paths so callers get a clear error at startup.
    """
    from agent_bom.security import SecurityError, validate_path

    p = Path(raw).expanduser()
    home = Path.home().resolve()
    # Use the real system temp dir (macOS: /private/tmp or /private/var/folders/…)
    tmp = Path(tempfile.gettempdir()).resolve()

    # Allow home subtree or system temp subtree (test fixtures land in temp)
    try:
        resolved = p.resolve()
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"AGENT_BOM_DB_PATH is not a valid path: {raw!r}") from exc

    if not (resolved.is_relative_to(home) or resolved.is_relative_to(tmp)):
        raise ValueError(f"AGENT_BOM_DB_PATH must be inside the home directory or /tmp, got: {raw!r}")

    try:
        validate_path(p)
    except SecurityError as exc:
        raise ValueError(f"AGENT_BOM_DB_PATH failed security check: {exc}") from exc

    return p


DB_PATH: Path = _validated_db_path(_RAW_DB_PATH)

# Schema version — bump when DDL changes incompatibly
_SCHEMA_VERSION = 3

# Migration scripts: list of (from_version, to_version, sql) tuples.
# Add a new entry here whenever _SCHEMA_VERSION is bumped.
# Each migration must be idempotent (use IF NOT EXISTS / IF EXISTS guards).
_MIGRATIONS: list[tuple[int, int, str]] = [
    (1, 2, "ALTER TABLE vulns ADD COLUMN cwe_ids TEXT DEFAULT '';"),
    (2, 3, "ALTER TABLE vulns ADD COLUMN aliases TEXT DEFAULT '';"),
]

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
    cwe_ids         TEXT DEFAULT '',    -- comma-separated CWE IDs (e.g. "CWE-79,CWE-89")
    aliases         TEXT DEFAULT '',    -- comma-separated advisory aliases (e.g. "CVE-2023-1234,PYSEC-2023-56")
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


def _set_db_permissions(db_path: Path) -> None:
    """Restrict the DB file to owner read/write only (0600).

    No-ops silently on platforms where chmod is not supported (Windows).
    """
    try:
        db_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except (NotImplementedError, OSError):
        pass  # Windows or read-only filesystem — best effort


def _check_integrity(conn: sqlite3.Connection, db_path: Path) -> None:
    """Run SQLite integrity_check; log a warning if the DB is corrupt."""
    result = conn.execute("PRAGMA integrity_check").fetchone()
    if result and result[0] != "ok":
        _logger.warning(
            "Local vuln DB at %s failed integrity check: %s — consider deleting and re-running 'agent-bom db update'",
            db_path,
            result[0],
        )


def init_db(path: Path | None = None) -> sqlite3.Connection:
    """Open (and initialise if needed) the local vuln DB.

    Creates the DB file and parent directories if they don't exist.
    Applies 0600 file permissions and runs an integrity check on open.
    Returns an open connection with WAL mode and foreign keys enabled.
    """
    db_path = path or DB_PATH
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.executescript(_DDL)

    # Lock down file permissions after first creation
    _set_db_permissions(db_path)

    # Integrity check — warn on corrupt DB, don't crash (read-only callers are safe)
    _check_integrity(conn, db_path)

    # Seed schema_version on first creation
    row = conn.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
    if row is None:
        conn.execute("INSERT INTO schema_version(version) VALUES (?)", (_SCHEMA_VERSION,))
        conn.commit()
        _logger.debug("Initialised local vuln DB at %s (schema v%d)", db_path, _SCHEMA_VERSION)
    else:
        current = row["version"]
        if current < _SCHEMA_VERSION:
            _migrate(conn, current)
        elif current > _SCHEMA_VERSION:
            _logger.warning(
                "DB schema v%d is newer than code v%d — upgrade agent-bom",
                current,
                _SCHEMA_VERSION,
            )

    return conn


def _migrate(conn: sqlite3.Connection, from_version: int) -> None:
    """Apply sequential migrations from *from_version* up to _SCHEMA_VERSION."""
    current = from_version
    for src, dst, sql in _MIGRATIONS:
        if current == src:
            _logger.info("Migrating local vuln DB schema v%d → v%d", src, dst)
            try:
                conn.executescript(sql)
                conn.execute("UPDATE schema_version SET version = ?", (dst,))
                conn.commit()
                current = dst
                _logger.info("Migration v%d → v%d complete", src, dst)
            except Exception as exc:
                _logger.error(
                    "Migration v%d → v%d failed: %s — DB may be in a partial state. "
                    "Delete the DB and re-run 'agent-bom db update' to rebuild.",
                    src,
                    dst,
                    exc,
                )
                raise
    if current < _SCHEMA_VERSION:
        _logger.warning(
            "DB schema v%d is older than code v%d — no migration path found. Delete the DB and re-run 'agent-bom db update' to rebuild.",
            current,
            _SCHEMA_VERSION,
        )


def db_freshness_days(path: Path | None = None) -> int | None:
    """Return the age in days of the oldest synced source, or None if DB absent / never synced.

    Opens a temporary connection — safe to call before the main scan opens VulnDB.
    """
    from datetime import datetime, timezone

    db_path = path or DB_PATH
    if not db_path.exists():
        return None
    try:
        conn = sqlite3.connect(str(db_path))
        try:
            rows = conn.execute("SELECT last_synced FROM sync_meta").fetchall()
        finally:
            conn.close()
    except Exception:
        return None

    if not rows:
        return None

    oldest: datetime | None = None
    now = datetime.now(timezone.utc)
    for (ts,) in rows:
        if not ts:
            continue
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            if oldest is None or dt < oldest:
                oldest = dt
        except ValueError:
            continue

    if oldest is None:
        return None
    return (now - oldest).days


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
