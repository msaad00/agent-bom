"""Baseline comparison — track new, resolved, and persistent vulnerabilities.

Compares two scan reports to show what changed:
    - New vulnerabilities (not in previous scan)
    - Resolved vulnerabilities (were in previous, not in current)
    - Persistent vulnerabilities (in both scans)
    - Severity changes (upgraded/downgraded)

Also computes trend metrics for historical analysis.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from dataclasses import dataclass, field, replace
from typing import Protocol

logger = logging.getLogger(__name__)

# Bound identities transferred/retained while projecting a history request.
HISTORY_METADATA_BUDGET_BYTES = 16 * 1024 * 1024


@dataclass
class BaselineDiff:
    """Result of comparing two scan reports."""

    new_vulns: list[dict] = field(default_factory=list)
    resolved_vulns: list[dict] = field(default_factory=list)
    persistent_vulns: list[dict] = field(default_factory=list)
    severity_changes: list[dict] = field(default_factory=list)
    new_count: int = 0
    resolved_count: int = 0
    persistent_count: int = 0

    def __post_init__(self) -> None:
        self.new_count = len(self.new_vulns)
        self.resolved_count = len(self.resolved_vulns)
        self.persistent_count = len(self.persistent_vulns)

    @property
    def improving(self) -> bool:
        return self.resolved_count > self.new_count

    @property
    def net_change(self) -> int:
        return self.new_count - self.resolved_count

    def to_dict(self) -> dict:
        return {
            "new_vulns": self.new_vulns,
            "resolved_vulns": self.resolved_vulns,
            "persistent_vulns": self.persistent_vulns,
            "severity_changes": self.severity_changes,
            "new_count": self.new_count,
            "resolved_count": self.resolved_count,
            "persistent_count": self.persistent_count,
            "net_change": self.net_change,
            "improving": self.improving,
        }


def compare_reports(previous: dict, current: dict) -> BaselineDiff:
    """Compare two scan report dicts and produce a baseline diff.

    Each report should have a 'blast_radius' key with vulnerability entries.
    """
    prev_vulns = _extract_vuln_map(previous)
    curr_vulns = _extract_vuln_map(current)

    prev_keys = set(prev_vulns.keys())
    curr_keys = set(curr_vulns.keys())

    new_keys = curr_keys - prev_keys
    resolved_keys = prev_keys - curr_keys
    persistent_keys = prev_keys & curr_keys

    new_vulns = [curr_vulns[k] for k in sorted(new_keys)]
    resolved_vulns = [prev_vulns[k] for k in sorted(resolved_keys)]
    persistent_vulns = [curr_vulns[k] for k in sorted(persistent_keys)]

    severity_changes = []
    for key in persistent_keys:
        prev_sev = prev_vulns[key].get("severity", "")
        curr_sev = curr_vulns[key].get("severity", "")
        if prev_sev != curr_sev:
            severity_changes.append(
                {
                    "vuln_key": key,
                    "previous_severity": prev_sev,
                    "current_severity": curr_sev,
                    "package": curr_vulns[key].get("package", ""),
                }
            )

    return BaselineDiff(
        new_vulns=new_vulns,
        resolved_vulns=resolved_vulns,
        persistent_vulns=persistent_vulns,
        severity_changes=severity_changes,
    )


def _extract_vuln_map(report: dict) -> dict[str, dict]:
    """Extract a vuln_id+package key → entry map from a report."""
    result = {}
    blast_radii = report.get("blast_radius", []) or report.get("blast_radii", [])
    for br in blast_radii:
        vuln_id = br.get("vulnerability_id") or br.get("id", "")
        package = br.get("package_name") or br.get("package", "")
        key = f"{vuln_id}:{package}"
        result[key] = {
            "vulnerability_id": vuln_id,
            "package": package,
            "severity": (br.get("severity") or "").lower(),
            "risk_score": br.get("risk_score", 0),
            "is_kev": br.get("is_kev") or br.get("cisa_kev", False),
            "fixed_version": br.get("fixed_version"),
        }
    return result


# ── Trend Analysis ──────────────────────────────────────────────────


@dataclass
class TrendPoint:
    """Single data point in trend history."""

    timestamp: str
    total_vulns: int
    critical: int
    high: int
    medium: int
    low: int
    posture_score: float
    posture_grade: str
    tenant_id: str = "default"
    scan_id: str | None = None
    comparison_metadata: dict = field(default_factory=dict)

    @property
    def idempotency_key(self) -> str:
        """Stable write key; scan-backed points cannot duplicate on retry."""
        return f"{self.tenant_id}:{self.scan_id or self.timestamp}"

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "total_vulns": self.total_vulns,
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "posture_score": self.posture_score,
            "posture_grade": self.posture_grade,
        }


class TrendStore(Protocol):
    """Protocol for trend data persistence."""

    def record(self, point: TrendPoint) -> None: ...
    def get_history(self, limit: int = 30, tenant_id: str | None = None) -> list[TrendPoint]: ...


class InMemoryTrendStore:
    _MAX_POINTS = 365

    def __init__(self) -> None:
        self._points: list[TrendPoint] = []
        self._lock = threading.Lock()

    def record(self, point: TrendPoint) -> None:
        with self._lock:
            if point.scan_id:
                for index, existing in enumerate(self._points):
                    if existing.idempotency_key == point.idempotency_key:
                        self._points[index] = point
                        break
                else:
                    self._points.append(point)
            else:
                self._points.append(point)
            tenant_points = sorted(
                (row for row in self._points if row.tenant_id == point.tenant_id),
                key=lambda row: row.timestamp,
                reverse=True,
            )
            retained = {id(row) for row in tenant_points[: self._MAX_POINTS]}
            self._points = [row for row in self._points if row.tenant_id != point.tenant_id or id(row) in retained]

    def get_history(self, limit: int = 30, tenant_id: str | None = None) -> list[TrendPoint]:
        with self._lock:
            points = self._points
            if tenant_id is not None:
                points = [point for point in points if point.tenant_id == tenant_id]
            selected = sorted(points, key=lambda point: point.timestamp, reverse=True)[:limit]
            used = 0
            result = []
            for point in selected:
                used += len(json.dumps(point.comparison_metadata).encode())
                result.append(
                    point
                    if used <= HISTORY_METADATA_BUDGET_BYTES
                    else replace(point, comparison_metadata={"history_processing_limit": True})
                )
            return result


class SQLiteTrendStore:
    def __init__(self, db_path: str = "agent_bom_jobs.db") -> None:
        self._db_path = db_path
        self._local = threading.local()
        self._init_db()

    @property
    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._local.conn.execute("PRAGMA journal_mode=WAL")
        return self._local.conn

    def _init_db(self) -> None:
        self._conn.execute("""CREATE TABLE IF NOT EXISTS trend_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            tenant_id TEXT NOT NULL DEFAULT 'default',
            total_vulns INTEGER NOT NULL,
            critical INTEGER NOT NULL DEFAULT 0,
            high INTEGER NOT NULL DEFAULT 0,
            medium INTEGER NOT NULL DEFAULT 0,
            low INTEGER NOT NULL DEFAULT 0,
            posture_score REAL NOT NULL DEFAULT 0,
            posture_grade TEXT NOT NULL DEFAULT '',
            scan_id TEXT
        )""")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_trend_ts ON trend_history(timestamp)")
        cols = {row[1] for row in self._conn.execute("PRAGMA table_info(trend_history)").fetchall()}
        if "tenant_id" not in cols:
            self._conn.execute("ALTER TABLE trend_history ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'")
        if "comparison_metadata" not in cols:
            self._conn.execute("ALTER TABLE trend_history ADD COLUMN comparison_metadata TEXT NOT NULL DEFAULT '{}'")
        if "scan_id" not in cols:
            self._conn.execute("ALTER TABLE trend_history ADD COLUMN scan_id TEXT")
        self._conn.execute(
            "DELETE FROM trend_history WHERE scan_id IS NOT NULL AND id NOT IN "
            "(SELECT MAX(id) FROM trend_history WHERE scan_id IS NOT NULL GROUP BY tenant_id, scan_id)"
        )
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_trend_tenant_ts ON trend_history(tenant_id, timestamp)")
        self._conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_trend_tenant_scan ON trend_history(tenant_id, scan_id) WHERE scan_id IS NOT NULL"
        )
        from agent_bom.api.storage_schema import ensure_sqlite_schema_version

        ensure_sqlite_schema_version(self._conn, "trend_history", version=2)
        self._conn.commit()

    def record(self, point: TrendPoint) -> None:
        self._conn.execute(
            "INSERT INTO trend_history "
            "(timestamp, tenant_id, total_vulns, critical, high, medium, low, posture_score, posture_grade, scan_id, comparison_metadata) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT (tenant_id, scan_id) WHERE scan_id IS NOT NULL DO UPDATE SET "
            "timestamp = excluded.timestamp, total_vulns = excluded.total_vulns, critical = excluded.critical, "
            "high = excluded.high, medium = excluded.medium, low = excluded.low, "
            "posture_score = excluded.posture_score, posture_grade = excluded.posture_grade, "
            "comparison_metadata = excluded.comparison_metadata",
            (
                point.timestamp,
                point.tenant_id,
                point.total_vulns,
                point.critical,
                point.high,
                point.medium,
                point.low,
                point.posture_score,
                point.posture_grade,
                point.scan_id,
                json.dumps(point.comparison_metadata),
            ),
        )
        self._conn.commit()

    def get_history(self, limit: int = 30, tenant_id: str | None = None) -> list[TrendPoint]:
        if tenant_id is None:
            rows = self._conn.execute(
                "SELECT timestamp, total_vulns, critical, high, medium, low, "
                "posture_score, posture_grade, tenant_id, scan_id, "
                "CASE WHEN SUM(LENGTH(CAST(comparison_metadata AS BLOB))) OVER "
                "(ORDER BY timestamp DESC, id DESC ROWS UNBOUNDED PRECEDING) <= 16777216 "
                "THEN comparison_metadata ELSE '{\"history_processing_limit\":true}' END "
                "FROM trend_history ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT timestamp, total_vulns, critical, high, medium, low, "
                "posture_score, posture_grade, tenant_id, scan_id, "
                "CASE WHEN SUM(LENGTH(CAST(comparison_metadata AS BLOB))) OVER "
                "(ORDER BY timestamp DESC, id DESC ROWS UNBOUNDED PRECEDING) <= 16777216 "
                "THEN comparison_metadata ELSE '{\"history_processing_limit\":true}' END "
                "FROM trend_history WHERE tenant_id = ? ORDER BY timestamp DESC LIMIT ?",
                (tenant_id, limit),
            ).fetchall()
        return [
            TrendPoint(
                timestamp=r[0],
                total_vulns=r[1],
                critical=r[2],
                high=r[3],
                medium=r[4],
                low=r[5],
                posture_score=r[6],
                posture_grade=r[7],
                tenant_id=r[8] if len(r) > 8 else "default",
                scan_id=r[9] if len(r) > 9 else None,
                comparison_metadata=json.loads(r[10]) if len(r) > 10 else {},
            )
            for r in rows
        ]
