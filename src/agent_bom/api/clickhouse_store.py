"""ClickHouse-backed analytics store for OLAP workloads.

Provides ``AnalyticsStore`` protocol with two implementations:

* **ClickHouseAnalyticsStore** — real ClickHouse backend for vuln trends,
  runtime events, and posture snapshots.
* **NullAnalyticsStore** — silent no-op when ClickHouse is not configured.

Security note — SQL injection mitigation:
  ClickHouse's HTTP interface does not support parameterized queries in the
  same way as traditional RDBMS drivers.  All numeric parameters are cast via
  ``int()``/``float()`` before interpolation, and string parameters are
  sanitized through ``_escape()`` which strips null bytes and escapes
  backslashes and single quotes.  Bandit ``nosec B608`` annotations suppress
  the string-concatenation warnings where these guards are in place.
"""

from __future__ import annotations

import logging
import re
import uuid
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger(__name__)
_CLICKHOUSE_SAFE_STRING_RE = re.compile(r"[\x20-\x7E]+")


# ------------------------------------------------------------------
# Protocol
# ------------------------------------------------------------------


@runtime_checkable
class AnalyticsStore(Protocol):
    """Protocol for analytics persistence (OLAP)."""

    def record_scan(self, scan_id: str, agent_name: str, vulns: list[dict]) -> None:
        """Append vulnerability scan results."""
        ...

    def record_event(self, event: dict) -> None:
        """Append a runtime protection event."""
        ...

    def record_posture(self, agent_name: str, snapshot: dict) -> None:
        """Append a posture score snapshot."""
        ...

    def query_vuln_trends(self, days: int = 30, agent: str | None = None) -> list[dict]:
        """Vulnerability counts grouped by day and severity."""
        ...

    def query_top_cves(self, limit: int = 20) -> list[dict]:
        """Most frequent CVEs across all scans."""
        ...

    def query_posture_history(self, agent: str | None = None, days: int = 90) -> list[dict]:
        """Posture grade time-series."""
        ...

    def query_event_summary(self, hours: int = 24) -> list[dict]:
        """Runtime event counts grouped by type."""
        ...

    def record_scan_metadata(self, metadata: dict) -> None:
        """Record scan-level metadata (agent count, vuln count, grade)."""
        ...


# ------------------------------------------------------------------
# Null implementation (default — zero overhead)
# ------------------------------------------------------------------


class NullAnalyticsStore:
    """Silent no-op analytics store used when ClickHouse is not configured."""

    def record_scan(self, scan_id: str, agent_name: str, vulns: list[dict]) -> None:
        pass

    def record_event(self, event: dict) -> None:
        pass

    def record_posture(self, agent_name: str, snapshot: dict) -> None:
        pass

    def query_vuln_trends(self, days: int = 30, agent: str | None = None) -> list[dict]:
        return []

    def query_top_cves(self, limit: int = 20) -> list[dict]:
        return []

    def query_posture_history(self, agent: str | None = None, days: int = 90) -> list[dict]:
        return []

    def query_event_summary(self, hours: int = 24) -> list[dict]:
        return []

    def record_scan_metadata(self, metadata: dict) -> None:
        pass


# ------------------------------------------------------------------
# ClickHouse implementation
# ------------------------------------------------------------------


class ClickHouseAnalyticsStore:
    """ClickHouse-backed analytics store."""

    def __init__(self, url: str | None = None, **kwargs: Any) -> None:
        from agent_bom.cloud.clickhouse import ClickHouseClient

        self._client = ClickHouseClient(url=url, **kwargs)
        self._client.ensure_tables()

    # -- writes --------------------------------------------------------

    def record_scan(self, scan_id: str, agent_name: str, vulns: list[dict]) -> None:
        if not vulns:
            return

        def _split_package(v: dict) -> tuple[str, str]:
            pkg_name = v.get("package_name", "")
            pkg_version = v.get("package_version", "") or v.get("version", "")
            if pkg_name:
                return pkg_name, pkg_version
            pkg = v.get("package", "")
            if isinstance(pkg, str) and "@" in pkg:
                name, version = pkg.rsplit("@", 1)
                return name, version
            return str(pkg or ""), pkg_version

        rows = [
            {
                "scan_id": scan_id,
                "package_name": _split_package(v)[0],
                "package_version": _split_package(v)[1],
                "ecosystem": v.get("ecosystem", ""),
                "cve_id": v.get("cve_id", v.get("id", "")),
                "cvss_score": float(v.get("cvss_score", 0.0)),
                "epss_score": float(v.get("epss_score", 0.0)),
                "severity": v.get("severity", "UNKNOWN"),
                "source": v.get("source", "osv"),
                "agent_name": agent_name,
                "environment": v.get("environment", ""),
                "cmmc_tags": list(v.get("cmmc_tags", [])),
            }
            for v in vulns
        ]
        self._client.insert_json("vulnerability_scans", rows)

    def record_event(self, event: dict) -> None:
        row = {
            "event_id": event.get("event_id", str(uuid.uuid4())),
            "event_type": event.get("event_type", event.get("type", "")),
            "detector": event.get("detector", ""),
            "severity": event.get("severity", "INFO"),
            "tool_name": event.get("tool_name", event.get("tool", "")),
            "message": event.get("message", ""),
            "agent_name": event.get("agent_name", ""),
        }
        self._client.insert_json("runtime_events", [row])

    def record_posture(self, agent_name: str, snapshot: dict) -> None:
        row = {
            "agent_name": agent_name,
            "total_packages": int(snapshot.get("total_packages", 0)),
            "critical_vulns": int(snapshot.get("critical", 0)),
            "high_vulns": int(snapshot.get("high", 0)),
            "medium_vulns": int(snapshot.get("medium", 0)),
            "posture_grade": snapshot.get("grade", ""),
            "risk_score": float(snapshot.get("risk_score", 0.0)),
            "compliance_score": float(snapshot.get("compliance_score", 0.0)),
        }
        self._client.insert_json("posture_scores", [row])

    # -- reads ---------------------------------------------------------

    def query_vuln_trends(self, days: int = 30, agent: str | None = None) -> list[dict]:
        # days is int-only, agent is escaped via _escape() — safe from injection
        where = f"scan_timestamp >= now() - INTERVAL {int(days)} DAY"
        if agent:
            where += f" AND agent_name = '{_escape(agent)}'"
        query = (
            f"SELECT toDate(scan_timestamp) AS day, severity, count() AS cnt "  # nosec B608
            f"FROM vulnerability_scans WHERE {where} "
            f"GROUP BY day, severity ORDER BY day"
        )
        return self._client.query_json(query)

    def query_top_cves(self, limit: int = 20) -> list[dict]:
        # limit is int-only via int() cast — safe from injection
        query = (
            f"SELECT cve_id, count() AS cnt, max(cvss_score) AS max_cvss "  # nosec B608
            f"FROM vulnerability_scans WHERE cve_id != '' "
            f"GROUP BY cve_id ORDER BY cnt DESC LIMIT {int(limit)}"
        )
        return self._client.query_json(query)

    def query_posture_history(self, agent: str | None = None, days: int = 90) -> list[dict]:
        # days is int-only, agent is escaped via _escape() — safe from injection
        where = f"measured_at >= now() - INTERVAL {int(days)} DAY"
        if agent:
            where += f" AND agent_name = '{_escape(agent)}'"
        query = (
            f"SELECT toDate(measured_at) AS day, agent_name, posture_grade, "  # nosec B608
            f"risk_score, compliance_score "
            f"FROM posture_scores WHERE {where} "
            f"ORDER BY day"
        )
        return self._client.query_json(query)

    def query_event_summary(self, hours: int = 24) -> list[dict]:
        # hours is int-only via int() cast — safe from injection
        query = (
            f"SELECT event_type, severity, count() AS cnt "  # nosec B608
            f"FROM runtime_events "
            f"WHERE event_timestamp >= now() - INTERVAL {int(hours)} HOUR "
            f"GROUP BY event_type, severity ORDER BY cnt DESC"
        )
        return self._client.query_json(query)

    def record_scan_metadata(self, metadata: dict) -> None:
        row = {
            "scan_id": metadata.get("scan_id", str(uuid.uuid4())),
            "agent_count": int(metadata.get("agent_count", 0)),
            "package_count": int(metadata.get("package_count", 0)),
            "vuln_count": int(metadata.get("vuln_count", 0)),
            "critical_count": int(metadata.get("critical_count", 0)),
            "high_count": int(metadata.get("high_count", 0)),
            "posture_grade": metadata.get("posture_grade", ""),
            "scan_duration_ms": int(metadata.get("scan_duration_ms", 0)),
            "source": metadata.get("source", "cli"),
            "aisvs_score": float(metadata.get("aisvs_score", 0.0)),
            "has_runtime_correlation": int(bool(metadata.get("has_runtime_correlation", False))),
        }
        self._client.insert_json("scan_metadata", [row])


def _escape(value: str) -> str:
    """Escape a string value for ClickHouse SQL.

    Defence-in-depth against injection: strips null bytes (which can truncate
    queries in some drivers), normalizes control characters to spaces, limits
    the string to printable ASCII, and escapes backslashes and single quotes.
    All callers also enforce type constraints (int casts for numeric params).
    See module docstring for full rationale.
    """
    sanitized = value.replace("\x00", " ")
    sanitized = "".join(ch if ch == "\t" or ch == "\n" or ch == "\r" or 32 <= ord(ch) <= 126 else " " for ch in sanitized)
    sanitized = " ".join(_CLICKHOUSE_SAFE_STRING_RE.findall(sanitized))
    return sanitized.replace("\\", "\\\\").replace("'", "\\'")
