"""ClickHouse-backed analytics store for OLAP workloads.

Provides ``AnalyticsStore`` protocol with two implementations:

* **ClickHouseAnalyticsStore** — real ClickHouse backend for vuln trends,
  runtime events, and posture snapshots.
* **NullAnalyticsStore** — silent no-op when ClickHouse is not configured.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


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
        rows = [
            {
                "scan_id": scan_id,
                "package_name": v.get("package", ""),
                "package_version": v.get("version", ""),
                "ecosystem": v.get("ecosystem", ""),
                "cve_id": v.get("cve_id", v.get("id", "")),
                "cvss_score": float(v.get("cvss_score", 0.0)),
                "epss_score": float(v.get("epss_score", 0.0)),
                "severity": v.get("severity", "UNKNOWN"),
                "source": v.get("source", "osv"),
                "agent_name": agent_name,
                "environment": v.get("environment", ""),
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
        where = f"scan_timestamp >= now() - INTERVAL {int(days)} DAY"
        if agent:
            where += f" AND agent_name = '{_escape(agent)}'"
        return self._client.query_json(  # nosec B608 — days is int-only, agent is escaped
            f"SELECT toDate(scan_timestamp) AS day, severity, count() AS cnt "
            f"FROM vulnerability_scans WHERE {where} "
            f"GROUP BY day, severity ORDER BY day"
        )

    def query_top_cves(self, limit: int = 20) -> list[dict]:
        return self._client.query_json(  # nosec B608 — limit is int-only
            f"SELECT cve_id, count() AS cnt, max(cvss_score) AS max_cvss "
            f"FROM vulnerability_scans WHERE cve_id != '' "
            f"GROUP BY cve_id ORDER BY cnt DESC LIMIT {int(limit)}"
        )

    def query_posture_history(self, agent: str | None = None, days: int = 90) -> list[dict]:
        where = f"measured_at >= now() - INTERVAL {int(days)} DAY"
        if agent:
            where += f" AND agent_name = '{_escape(agent)}'"
        return self._client.query_json(  # nosec B608 — days is int-only, agent is escaped
            f"SELECT toDate(measured_at) AS day, agent_name, posture_grade, "
            f"risk_score, compliance_score "
            f"FROM posture_scores WHERE {where} "
            f"ORDER BY day"
        )

    def query_event_summary(self, hours: int = 24) -> list[dict]:
        return self._client.query_json(  # nosec B608 — hours is int-only
            f"SELECT event_type, severity, count() AS cnt "
            f"FROM runtime_events "
            f"WHERE event_timestamp >= now() - INTERVAL {int(hours)} HOUR "
            f"GROUP BY event_type, severity ORDER BY cnt DESC"
        )


def _escape(value: str) -> str:
    """Escape a string value for ClickHouse SQL (prevent injection)."""
    return value.replace("\\", "\\\\").replace("'", "\\'")
