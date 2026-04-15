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
import queue
import re
import threading
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

    def record_events(self, events: list[dict]) -> None:
        """Append multiple runtime protection events in one batch."""
        ...

    def record_posture(self, agent_name: str, snapshot: dict) -> None:
        """Append a posture score snapshot."""
        ...

    def record_fleet_snapshot(self, snapshot: dict) -> None:
        """Append a fleet-agent snapshot."""
        ...

    def record_compliance_control(self, control: dict) -> None:
        """Append a compliance control measurement."""
        ...

    def record_audit_event(self, event: dict) -> None:
        """Append an audit event for analytics/trending."""
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

    def query_top_riskiest_agents(self, limit: int = 20) -> list[dict]:
        """Top fleet agents by trust/risk posture."""
        ...

    def query_compliance_heatmap(self, days: int = 30) -> list[dict]:
        """Compliance control pass/fail summary grouped by framework."""
        ...

    def record_scan_metadata(self, metadata: dict) -> None:
        """Record scan-level metadata (agent count, vuln count, grade)."""
        ...

    def close(self) -> None:
        """Flush and release any buffered resources."""
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

    def record_events(self, events: list[dict]) -> None:
        pass

    def record_posture(self, agent_name: str, snapshot: dict) -> None:
        pass

    def record_fleet_snapshot(self, snapshot: dict) -> None:
        pass

    def record_compliance_control(self, control: dict) -> None:
        pass

    def record_audit_event(self, event: dict) -> None:
        pass

    def query_vuln_trends(self, days: int = 30, agent: str | None = None) -> list[dict]:
        return []

    def query_top_cves(self, limit: int = 20) -> list[dict]:
        return []

    def query_posture_history(self, agent: str | None = None, days: int = 90) -> list[dict]:
        return []

    def query_event_summary(self, hours: int = 24) -> list[dict]:
        return []

    def query_top_riskiest_agents(self, limit: int = 20) -> list[dict]:
        return []

    def query_compliance_heatmap(self, days: int = 30) -> list[dict]:
        return []

    def record_scan_metadata(self, metadata: dict) -> None:
        pass

    def close(self) -> None:
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
        rows = self._scan_rows(scan_id, agent_name, vulns)
        if rows:
            self._client.insert_json("vulnerability_scans", rows)

    def _scan_rows(self, scan_id: str, agent_name: str, vulns: list[dict]) -> list[dict[str, Any]]:
        if not vulns:
            return []

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

        return [
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

    def record_event(self, event: dict) -> None:
        self.record_events([event])

    def record_events(self, events: list[dict]) -> None:
        rows = [self._event_row(event) for event in events if event]
        if rows:
            self._client.insert_json("runtime_events", rows)

    def _event_row(self, event: dict) -> dict[str, Any]:
        return {
            "event_id": event.get("event_id", str(uuid.uuid4())),
            "event_type": event.get("event_type", event.get("type", "")),
            "detector": event.get("detector", ""),
            "severity": event.get("severity", "INFO"),
            "tool_name": event.get("tool_name", event.get("tool", "")),
            "message": event.get("message", ""),
            "agent_name": event.get("agent_name", ""),
        }

    def record_posture(self, agent_name: str, snapshot: dict) -> None:
        self._client.insert_json("posture_scores", [self._posture_row(agent_name, snapshot)])

    def _posture_row(self, agent_name: str, snapshot: dict) -> dict[str, Any]:
        return {
            "agent_name": agent_name,
            "total_packages": int(snapshot.get("total_packages", 0)),
            "critical_vulns": int(snapshot.get("critical", 0)),
            "high_vulns": int(snapshot.get("high", 0)),
            "medium_vulns": int(snapshot.get("medium", 0)),
            "posture_grade": snapshot.get("grade", ""),
            "risk_score": float(snapshot.get("risk_score", 0.0)),
            "compliance_score": float(snapshot.get("compliance_score", 0.0)),
        }

    def record_fleet_snapshot(self, snapshot: dict) -> None:
        self._client.insert_json("fleet_agents", [self._fleet_row(snapshot)])

    def _fleet_row(self, snapshot: dict) -> dict[str, Any]:
        return {
            "measured_at": snapshot.get("last_seen"),
            "agent_name": snapshot.get("agent_name", ""),
            "agent_type": snapshot.get("agent_type", ""),
            "lifecycle_state": snapshot.get("lifecycle_state", ""),
            "trust_score": float(snapshot.get("trust_score", 0.0)),
            "server_count": int(snapshot.get("server_count", 0)),
            "package_count": int(snapshot.get("package_count", 0)),
            "credential_count": int(snapshot.get("credential_count", 0)),
            "vuln_count": int(snapshot.get("vuln_count", 0)),
            "tenant_id": snapshot.get("tenant_id", "default"),
        }

    def record_compliance_control(self, control: dict) -> None:
        self._client.insert_json("compliance_controls", [self._compliance_row(control)])

    def _compliance_row(self, control: dict) -> dict[str, Any]:
        return {
            "measured_at": control.get("measured_at"),
            "scan_id": control.get("scan_id", ""),
            "framework": control.get("framework", ""),
            "control_id": control.get("control_id", ""),
            "control_name": control.get("control_name", ""),
            "status": control.get("status", "unknown"),
            "finding_count": int(control.get("finding_count", 0)),
            "score": float(control.get("score", 0.0)),
        }

    def record_audit_event(self, event: dict) -> None:
        self._client.insert_json("audit_events", [self._audit_row(event)])

    def _audit_row(self, event: dict) -> dict[str, Any]:
        return {
            "event_timestamp": event.get("timestamp"),
            "entry_id": event.get("entry_id", str(uuid.uuid4())),
            "action": event.get("action", ""),
            "actor": event.get("actor", ""),
            "resource": event.get("resource", ""),
            "tenant_id": event.get("tenant_id", "default"),
        }

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

    def query_top_riskiest_agents(self, limit: int = 20) -> list[dict]:
        query = (
            f"SELECT agent_name, anyLast(lifecycle_state) AS lifecycle_state, "
            f"max(trust_score) AS trust_score, max(vuln_count) AS vuln_count, "
            f"max(credential_count) AS credential_count, anyLast(tenant_id) AS tenant_id "  # nosec B608
            f"FROM fleet_agents GROUP BY agent_name ORDER BY trust_score ASC, vuln_count DESC "
            f"LIMIT {int(limit)}"
        )
        return self._client.query_json(query)

    def query_compliance_heatmap(self, days: int = 30) -> list[dict]:
        query = (
            f"SELECT framework, status, count() AS cnt, avg(score) AS avg_score "  # nosec B608
            f"FROM compliance_controls "
            f"WHERE measured_at >= now() - INTERVAL {int(days)} DAY "
            f"GROUP BY framework, status ORDER BY framework, status"
        )
        return self._client.query_json(query)

    def record_scan_metadata(self, metadata: dict) -> None:
        self._client.insert_json("scan_metadata", [self._metadata_row(metadata)])

    def _metadata_row(self, metadata: dict) -> dict[str, Any]:
        return {
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

    def close(self) -> None:
        """Synchronous store has nothing buffered to flush."""


class BufferedAnalyticsStore:
    """Buffered wrapper for ClickHouse analytics writes.

    Writes are queued and flushed from a background thread so scan and runtime
    paths do not block on ClickHouse round-trips.
    """

    def __init__(self, store: ClickHouseAnalyticsStore, *, max_batch: int = 200, flush_interval: float = 1.0) -> None:
        self._store = store
        self._max_batch = max(1, int(max_batch))
        self._flush_interval = max(0.1, float(flush_interval))
        self._queue: queue.Queue[tuple[str, tuple[Any, ...]]] = queue.Queue()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="agent-bom-clickhouse-buffer", daemon=True)
        self._thread.start()

    def record_scan(self, scan_id: str, agent_name: str, vulns: list[dict]) -> None:
        self._queue.put(("scan", (scan_id, agent_name, vulns)))

    def record_event(self, event: dict) -> None:
        self._queue.put(("event", (event,)))

    def record_events(self, events: list[dict]) -> None:
        if events:
            self._queue.put(("event_batch", (events,)))

    def record_posture(self, agent_name: str, snapshot: dict) -> None:
        self._queue.put(("posture", (agent_name, snapshot)))

    def record_scan_metadata(self, metadata: dict) -> None:
        self._queue.put(("metadata", (metadata,)))

    def record_fleet_snapshot(self, snapshot: dict) -> None:
        self._queue.put(("fleet", (snapshot,)))

    def record_compliance_control(self, control: dict) -> None:
        self._queue.put(("compliance", (control,)))

    def record_audit_event(self, event: dict) -> None:
        self._queue.put(("audit", (event,)))

    def query_vuln_trends(self, days: int = 30, agent: str | None = None) -> list[dict]:
        self._flush_pending()
        return self._store.query_vuln_trends(days=days, agent=agent)

    def query_top_cves(self, limit: int = 20) -> list[dict]:
        self._flush_pending()
        return self._store.query_top_cves(limit=limit)

    def query_posture_history(self, agent: str | None = None, days: int = 90) -> list[dict]:
        self._flush_pending()
        return self._store.query_posture_history(agent=agent, days=days)

    def query_event_summary(self, hours: int = 24) -> list[dict]:
        self._flush_pending()
        return self._store.query_event_summary(hours=hours)

    def query_top_riskiest_agents(self, limit: int = 20) -> list[dict]:
        self._flush_pending()
        return self._store.query_top_riskiest_agents(limit=limit)

    def query_compliance_heatmap(self, days: int = 30) -> list[dict]:
        self._flush_pending()
        return self._store.query_compliance_heatmap(days=days)

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=max(1.0, self._flush_interval * 4))
        self._flush_pending()
        self._store.close()

    def _run(self) -> None:
        while not self._stop.is_set():
            self._flush_pending()
            self._stop.wait(self._flush_interval)

    def _drain(self) -> list[tuple[str, tuple[Any, ...]]]:
        drained: list[tuple[str, tuple[Any, ...]]] = []
        while len(drained) < self._max_batch:
            try:
                drained.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return drained

    def _flush_pending(self) -> None:
        drained = self._drain()
        if not drained:
            return

        scan_rows: list[dict[str, Any]] = []
        event_rows: list[dict[str, Any]] = []
        posture_rows: list[dict[str, Any]] = []
        metadata_rows: list[dict[str, Any]] = []
        fleet_rows: list[dict[str, Any]] = []
        compliance_rows: list[dict[str, Any]] = []
        audit_rows: list[dict[str, Any]] = []

        for kind, payload in drained:
            if kind == "scan":
                scan_id, agent_name, vulns = payload
                scan_rows.extend(self._store._scan_rows(str(scan_id), str(agent_name), list(vulns)))
            elif kind == "event":
                (event,) = payload
                event_rows.append(self._store._event_row(dict(event)))
            elif kind == "event_batch":
                (events,) = payload
                event_rows.extend(self._store._event_row(dict(event)) for event in events if event)
            elif kind == "posture":
                agent_name, snapshot = payload
                posture_rows.append(self._store._posture_row(str(agent_name), dict(snapshot)))
            elif kind == "metadata":
                (metadata,) = payload
                metadata_rows.append(self._store._metadata_row(dict(metadata)))
            elif kind == "fleet":
                (snapshot,) = payload
                fleet_rows.append(self._store._fleet_row(dict(snapshot)))
            elif kind == "compliance":
                (control,) = payload
                compliance_rows.append(self._store._compliance_row(dict(control)))
            elif kind == "audit":
                (event,) = payload
                audit_rows.append(self._store._audit_row(dict(event)))

        try:
            if scan_rows:
                self._store._client.insert_json("vulnerability_scans", scan_rows)
            if event_rows:
                self._store._client.insert_json("runtime_events", event_rows)
            if posture_rows:
                self._store._client.insert_json("posture_scores", posture_rows)
            if metadata_rows:
                self._store._client.insert_json("scan_metadata", metadata_rows)
            if fleet_rows:
                self._store._client.insert_json("fleet_agents", fleet_rows)
            if compliance_rows:
                self._store._client.insert_json("compliance_controls", compliance_rows)
            if audit_rows:
                self._store._client.insert_json("audit_events", audit_rows)
        except Exception:
            logger.warning("Buffered ClickHouse flush failed", exc_info=True)

    @property
    def flush_interval(self) -> float:
        return self._flush_interval

    @property
    def max_batch(self) -> int:
        return self._max_batch


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
