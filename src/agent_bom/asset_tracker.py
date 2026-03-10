"""Persistent asset tracker — first_seen / last_seen / resolved per vulnerability.

Stores a lightweight SQLite database at ``~/.agent-bom/assets.db`` that tracks
every vulnerability across scans.  Each scan call to ``record_scan()`` updates
the tracker: new findings get ``first_seen``, existing findings get ``last_seen``
bumped, and findings no longer present are marked ``resolved``.

Usage::

    from agent_bom.asset_tracker import AssetTracker
    tracker = AssetTracker()
    diff = tracker.record_scan(report_json)
    # diff = {"new": [...], "resolved": [...], "reopened": [...], "unchanged": int}
    assets = tracker.list_assets(status="open")
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

DEFAULT_DB_PATH = Path.home() / ".agent-bom" / "assets.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
    vuln_id     TEXT NOT NULL,
    package     TEXT NOT NULL,
    ecosystem   TEXT NOT NULL DEFAULT '',
    severity    TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'open',  -- open | resolved | reopened
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    resolved_at TEXT,
    scan_count  INTEGER NOT NULL DEFAULT 1,
    metadata    TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (vuln_id, package, ecosystem)
);

CREATE INDEX IF NOT EXISTS idx_assets_status ON assets(status);
CREATE INDEX IF NOT EXISTS idx_assets_severity ON assets(severity);
"""


class AssetTracker:
    """SQLite-backed vulnerability asset tracker."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self._db_path = db_path or DEFAULT_DB_PATH
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    # ── Record a scan ───────────────────────────────────────────────────

    def record_scan(self, report: dict) -> dict:
        """Process a scan report and update asset state.

        Args:
            report: Full AI-BOM JSON report dict.

        Returns:
            Diff dict with ``new``, ``resolved``, ``reopened``, ``unchanged`` counts
            and lists of affected vulnerability IDs.
        """
        now = datetime.now(timezone.utc).isoformat()

        # Extract current findings from blast_radius
        current: dict[tuple[str, str, str], dict] = {}
        for br in report.get("blast_radius", []):
            key = (
                br.get("vulnerability_id", ""),
                br.get("package", ""),
                br.get("ecosystem", ""),
            )
            if key[0]:  # skip empty vuln IDs
                current[key] = br

        # Load existing open/reopened assets
        cursor = self._conn.execute("SELECT vuln_id, package, ecosystem, status FROM assets WHERE status IN ('open', 'reopened')")
        existing_open: set[tuple[str, str, str]] = set()
        for row in cursor:
            existing_open.add((row["vuln_id"], row["package"], row["ecosystem"]))

        # Load all known assets (including resolved) for reopening detection
        cursor = self._conn.execute("SELECT vuln_id, package, ecosystem, status FROM assets")
        all_known: dict[tuple[str, str, str], str] = {}
        for row in cursor:
            all_known[(row["vuln_id"], row["package"], row["ecosystem"])] = row["status"]

        new_findings: list[str] = []
        reopened_findings: list[str] = []
        unchanged_count = 0

        # Process current findings
        for key, br in current.items():
            vuln_id, package, ecosystem = key
            severity = (br.get("severity") or "").lower()
            meta = json.dumps(
                {
                    "cvss_score": br.get("cvss_score"),
                    "epss_score": br.get("epss_score"),
                    "cisa_kev": br.get("cisa_kev") or br.get("is_kev"),
                    "affected_agents": br.get("affected_agents", []),
                    "blast_score": br.get("blast_score"),
                }
            )

            if key not in all_known:
                # Brand new finding
                self._conn.execute(
                    """INSERT INTO assets (vuln_id, package, ecosystem, severity, status, first_seen, last_seen, scan_count, metadata)
                       VALUES (?, ?, ?, ?, 'open', ?, ?, 1, ?)""",
                    (vuln_id, package, ecosystem, severity, now, now, meta),
                )
                new_findings.append(vuln_id)
            elif all_known[key] == "resolved":
                # Was resolved, now back — reopen
                self._conn.execute(
                    """UPDATE assets SET status='reopened', last_seen=?, resolved_at=NULL,
                       scan_count=scan_count+1, severity=?, metadata=?
                       WHERE vuln_id=? AND package=? AND ecosystem=?""",
                    (now, severity, meta, vuln_id, package, ecosystem),
                )
                reopened_findings.append(vuln_id)
            else:
                # Still open — bump last_seen
                self._conn.execute(
                    """UPDATE assets SET last_seen=?, scan_count=scan_count+1, severity=?, metadata=?
                       WHERE vuln_id=? AND package=? AND ecosystem=?""",
                    (now, severity, meta, vuln_id, package, ecosystem),
                )
                unchanged_count += 1

        # Mark findings no longer present as resolved
        resolved_findings: list[str] = []
        current_keys = set(current.keys())
        for key in existing_open:
            if key not in current_keys:
                vuln_id, package, ecosystem = key
                self._conn.execute(
                    """UPDATE assets SET status='resolved', resolved_at=?
                       WHERE vuln_id=? AND package=? AND ecosystem=?""",
                    (now, vuln_id, package, ecosystem),
                )
                resolved_findings.append(vuln_id)

        self._conn.commit()

        return {
            "new": new_findings,
            "resolved": resolved_findings,
            "reopened": reopened_findings,
            "unchanged": unchanged_count,
            "summary": {
                "new_count": len(new_findings),
                "resolved_count": len(resolved_findings),
                "reopened_count": len(reopened_findings),
                "unchanged_count": unchanged_count,
                "total_open": len(new_findings) + len(reopened_findings) + unchanged_count,
            },
        }

    # ── Query assets ────────────────────────────────────────────────────

    def list_assets(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 500,
    ) -> list[dict]:
        """List tracked vulnerability assets with optional filters.

        Args:
            status: Filter by status (open, resolved, reopened). None = all.
            severity: Filter by severity (critical, high, medium, low). None = all.
            limit: Max rows to return.

        Returns:
            List of asset dicts with first_seen, last_seen, status, etc.
        """
        query = "SELECT * FROM assets WHERE 1=1"
        params: list = []
        if status:
            query += " AND status = ?"
            params.append(status)
        if severity:
            query += " AND severity = ?"
            params.append(severity.lower())
        query += " ORDER BY last_seen DESC LIMIT ?"
        params.append(limit)

        cursor = self._conn.execute(query, params)
        results = []
        for row in cursor:
            d = dict(row)
            # Parse metadata JSON
            d["metadata"] = json.loads(d.get("metadata", "{}"))
            results.append(d)
        return results

    def get_asset(self, vuln_id: str, package: str, ecosystem: str = "") -> Optional[dict]:
        """Get a single asset by primary key."""
        cursor = self._conn.execute(
            "SELECT * FROM assets WHERE vuln_id=? AND package=? AND ecosystem=?",
            (vuln_id, package, ecosystem),
        )
        row = cursor.fetchone()
        if row:
            d = dict(row)
            d["metadata"] = json.loads(d.get("metadata", "{}"))
            return d
        return None

    def stats(self) -> dict:
        """Return aggregate asset statistics."""
        cursor = self._conn.execute(
            """SELECT
                COUNT(*) as total,
                SUM(CASE WHEN status IN ('open','reopened') THEN 1 ELSE 0 END) as open,
                SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) as resolved,
                SUM(CASE WHEN status = 'reopened' THEN 1 ELSE 0 END) as reopened,
                SUM(CASE WHEN severity = 'critical' AND status IN ('open','reopened') THEN 1 ELSE 0 END) as critical_open,
                SUM(CASE WHEN severity = 'high' AND status IN ('open','reopened') THEN 1 ELSE 0 END) as high_open,
                AVG(scan_count) as avg_scan_count
            FROM assets"""
        )
        row = cursor.fetchone()
        return dict(row) if row else {}

    def mttr_days(self) -> Optional[float]:
        """Calculate Mean Time To Remediate in days for resolved findings.

        Returns:
            Average days between first_seen and resolved_at, or None if no resolved assets.
        """
        cursor = self._conn.execute(
            """SELECT AVG(
                (julianday(resolved_at) - julianday(first_seen))
            ) as avg_days
            FROM assets WHERE status = 'resolved' AND resolved_at IS NOT NULL"""
        )
        row = cursor.fetchone()
        val = row["avg_days"] if row else None
        return round(val, 1) if val is not None else None
