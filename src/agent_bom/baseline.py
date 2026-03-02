"""Baseline comparison — track new, resolved, and persistent vulnerabilities.

Compares two scan reports to show what changed:
    - New vulnerabilities (not in previous scan)
    - Resolved vulnerabilities (were in previous, not in current)
    - Persistent vulnerabilities (in both scans)
    - Severity changes (upgraded/downgraded)

Also computes trend metrics for historical analysis.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from dataclasses import dataclass, field
from typing import Protocol

logger = logging.getLogger(__name__)


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

    def to_dict(self) -> dict:
        return {
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
    def get_history(self, limit: int = 30) -> list[TrendPoint]: ...


class InMemoryTrendStore:
    _MAX_POINTS = 365

    def __init__(self) -> None:
        self._points: list[TrendPoint] = []
        self._lock = threading.Lock()

    def record(self, point: TrendPoint) -> None:
        with self._lock:
            self._points.append(point)
            if len(self._points) > self._MAX_POINTS:
                self._points = self._points[-self._MAX_POINTS :]

    def get_history(self, limit: int = 30) -> list[TrendPoint]:
        with self._lock:
            return list(reversed(self._points[-limit:]))


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
            total_vulns INTEGER NOT NULL,
            critical INTEGER NOT NULL DEFAULT 0,
            high INTEGER NOT NULL DEFAULT 0,
            medium INTEGER NOT NULL DEFAULT 0,
            low INTEGER NOT NULL DEFAULT 0,
            posture_score REAL NOT NULL DEFAULT 0,
            posture_grade TEXT NOT NULL DEFAULT ''
        )""")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_trend_ts ON trend_history(timestamp)")
        self._conn.commit()

    def record(self, point: TrendPoint) -> None:
        self._conn.execute(
            "INSERT INTO trend_history (timestamp, total_vulns, critical, high, medium, low, posture_score, posture_grade) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                point.timestamp,
                point.total_vulns,
                point.critical,
                point.high,
                point.medium,
                point.low,
                point.posture_score,
                point.posture_grade,
            ),
        )
        self._conn.commit()

    def get_history(self, limit: int = 30) -> list[TrendPoint]:
        rows = self._conn.execute(
            "SELECT timestamp, total_vulns, critical, high, medium, low, posture_score, posture_grade "
            "FROM trend_history ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            TrendPoint(
                timestamp=r[0], total_vulns=r[1], critical=r[2], high=r[3], medium=r[4], low=r[5], posture_score=r[6], posture_grade=r[7]
            )
            for r in rows
        ]
