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

import json
import logging
import queue
import re
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger(__name__)
_CLICKHOUSE_SAFE_STRING_RE = re.compile(r"[\x20-\x7E]+")


def _coerce_clickhouse_timestamp(value: Any) -> str | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    candidate = str(value).strip()
    if not candidate:
        return None
    try:
        dt = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
    except ValueError:
        return candidate
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


# ------------------------------------------------------------------
# Protocol
# ------------------------------------------------------------------


@runtime_checkable
class AnalyticsStore(Protocol):
    """Protocol for analytics persistence (OLAP).

    Every write carries a ``tenant_id`` so the shared ClickHouse cluster
    stays segregated per-tenant at row level. Read methods accept an
    optional ``tenant_id``; ``None`` is an explicit cross-tenant scan used
    only by admin-scoped operator dashboards. All call sites on the
    user-facing API path must supply the tenant_id from the request state.
    """

    def record_scan(
        self,
        scan_id: str,
        agent_name: str,
        vulns: list[dict],
        *,
        tenant_id: str = "default",
    ) -> None:
        """Append vulnerability scan results."""
        ...

    def record_event(self, event: dict, *, tenant_id: str = "default") -> None:
        """Append a runtime protection event."""
        ...

    def record_events(self, events: list[dict], *, tenant_id: str = "default") -> None:
        """Append multiple runtime protection events in one batch."""
        ...

    def record_posture(self, agent_name: str, snapshot: dict, *, tenant_id: str = "default") -> None:
        """Append a posture score snapshot."""
        ...

    def record_fleet_snapshot(self, snapshot: dict) -> None:
        """Append a fleet-agent snapshot."""
        ...

    def record_compliance_control(self, control: dict, *, tenant_id: str = "default") -> None:
        """Append a compliance control measurement."""
        ...

    def record_cis_benchmark_checks(self, checks: list[dict], *, tenant_id: str = "default") -> None:
        """Append normalized CIS benchmark check rows."""
        ...

    def record_audit_event(self, event: dict) -> None:
        """Append an audit event for analytics/trending."""
        ...

    def query_vuln_trends(
        self,
        days: int = 30,
        agent: str | None = None,
        *,
        tenant_id: str | None = None,
    ) -> list[dict]:
        """Vulnerability counts grouped by day and severity."""
        ...

    def query_top_cves(self, limit: int = 20, *, tenant_id: str | None = None) -> list[dict]:
        """Most frequent CVEs across all scans."""
        ...

    def query_posture_history(
        self,
        agent: str | None = None,
        days: int = 90,
        *,
        tenant_id: str | None = None,
    ) -> list[dict]:
        """Posture grade time-series."""
        ...

    def query_event_summary(self, hours: int = 24, *, tenant_id: str | None = None) -> list[dict]:
        """Runtime event counts grouped by type."""
        ...

    def query_top_riskiest_agents(self, limit: int = 20, *, tenant_id: str | None = None) -> list[dict]:
        """Top fleet agents by trust/risk posture."""
        ...

    def query_compliance_heatmap(self, days: int = 30, *, tenant_id: str | None = None) -> list[dict]:
        """Compliance control pass/fail summary grouped by framework."""
        ...

    def query_cis_benchmark_checks(
        self,
        *,
        cloud: str | None = None,
        status: str | None = None,
        priority: int | None = None,
        limit: int = 100,
        offset: int = 0,
        tenant_id: str | None = None,
    ) -> list[dict]:
        """List normalized CIS benchmark checks."""
        ...

    def record_scan_metadata(self, metadata: dict, *, tenant_id: str = "default") -> None:
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

    def record_scan(
        self,
        scan_id: str,
        agent_name: str,
        vulns: list[dict],
        *,
        tenant_id: str = "default",
    ) -> None:
        pass

    def record_event(self, event: dict, *, tenant_id: str = "default") -> None:
        pass

    def record_events(self, events: list[dict], *, tenant_id: str = "default") -> None:
        pass

    def record_posture(self, agent_name: str, snapshot: dict, *, tenant_id: str = "default") -> None:
        pass

    def record_fleet_snapshot(self, snapshot: dict) -> None:
        pass

    def record_compliance_control(self, control: dict, *, tenant_id: str = "default") -> None:
        pass

    def record_cis_benchmark_checks(self, checks: list[dict], *, tenant_id: str = "default") -> None:
        pass

    def record_audit_event(self, event: dict) -> None:
        pass

    def query_vuln_trends(
        self,
        days: int = 30,
        agent: str | None = None,
        *,
        tenant_id: str | None = None,
    ) -> list[dict]:
        return []

    def query_top_cves(self, limit: int = 20, *, tenant_id: str | None = None) -> list[dict]:
        return []

    def query_posture_history(
        self,
        agent: str | None = None,
        days: int = 90,
        *,
        tenant_id: str | None = None,
    ) -> list[dict]:
        return []

    def query_event_summary(self, hours: int = 24, *, tenant_id: str | None = None) -> list[dict]:
        return []

    def query_top_riskiest_agents(self, limit: int = 20, *, tenant_id: str | None = None) -> list[dict]:
        return []

    def query_compliance_heatmap(self, days: int = 30, *, tenant_id: str | None = None) -> list[dict]:
        return []

    def query_cis_benchmark_checks(
        self,
        *,
        cloud: str | None = None,
        status: str | None = None,
        priority: int | None = None,
        limit: int = 100,
        offset: int = 0,
        tenant_id: str | None = None,
    ) -> list[dict]:
        return []

    def record_scan_metadata(self, metadata: dict, *, tenant_id: str = "default") -> None:
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

    def record_scan(
        self,
        scan_id: str,
        agent_name: str,
        vulns: list[dict],
        *,
        tenant_id: str = "default",
    ) -> None:
        rows = self._scan_rows(scan_id, agent_name, vulns, tenant_id=tenant_id)
        if rows:
            self._client.insert_json("vulnerability_scans", rows)

    def _scan_rows(
        self,
        scan_id: str,
        agent_name: str,
        vulns: list[dict],
        *,
        tenant_id: str = "default",
    ) -> list[dict[str, Any]]:
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
                "tenant_id": str(v.get("tenant_id") or tenant_id or "default"),
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

    def record_event(self, event: dict, *, tenant_id: str = "default") -> None:
        self.record_events([event], tenant_id=tenant_id)

    def record_events(self, events: list[dict], *, tenant_id: str = "default") -> None:
        rows = [self._event_row(event, tenant_id=tenant_id) for event in events if event]
        if rows:
            self._client.insert_json("runtime_events", rows)

    def _event_row(self, event: dict, *, tenant_id: str = "default") -> dict[str, Any]:
        return {
            "event_id": event.get("event_id", str(uuid.uuid4())),
            "event_timestamp": _coerce_clickhouse_timestamp(event.get("event_timestamp") or event.get("timestamp") or event.get("ts")),
            "tenant_id": str(event.get("tenant_id") or tenant_id or "default"),
            "event_type": event.get("event_type", event.get("type", "")),
            "detector": event.get("detector", ""),
            "severity": event.get("severity", "INFO"),
            "tool_name": event.get("tool_name", event.get("tool", "")),
            "message": event.get("message", ""),
            "agent_name": event.get("agent_name", ""),
            "session_id": str(event.get("session_id", "") or ""),
            "trace_id": str(event.get("trace_id", "") or ""),
            "request_id": str(event.get("request_id", "") or ""),
            "source_id": str(event.get("source_id", "") or ""),
        }

    def record_posture(self, agent_name: str, snapshot: dict, *, tenant_id: str = "default") -> None:
        self._client.insert_json(
            "posture_scores",
            [self._posture_row(agent_name, snapshot, tenant_id=tenant_id)],
        )

    def _posture_row(
        self,
        agent_name: str,
        snapshot: dict,
        *,
        tenant_id: str = "default",
    ) -> dict[str, Any]:
        return {
            "tenant_id": str(snapshot.get("tenant_id") or tenant_id or "default"),
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

    def record_compliance_control(self, control: dict, *, tenant_id: str = "default") -> None:
        self._client.insert_json(
            "compliance_controls",
            [self._compliance_row(control, tenant_id=tenant_id)],
        )

    def record_cis_benchmark_checks(self, checks: list[dict], *, tenant_id: str = "default") -> None:
        rows = [self._cis_check_row(check, tenant_id=tenant_id) for check in checks if check]
        if rows:
            self._client.insert_json("cis_benchmark_checks", rows)

    def _compliance_row(self, control: dict, *, tenant_id: str = "default") -> dict[str, Any]:
        return {
            "measured_at": control.get("measured_at"),
            "scan_id": control.get("scan_id", ""),
            "tenant_id": str(control.get("tenant_id") or tenant_id or "default"),
            "framework": control.get("framework", ""),
            "control_id": control.get("control_id", ""),
            "control_name": control.get("control_name", ""),
            "status": control.get("status", "unknown"),
            "finding_count": int(control.get("finding_count", 0)),
            "score": float(control.get("score", 0.0)),
        }

    def _cis_check_row(self, check: dict, *, tenant_id: str = "default") -> dict[str, Any]:
        return {
            "measured_at": _coerce_clickhouse_timestamp(check.get("measured_at")),
            "scan_id": check.get("scan_id", ""),
            "tenant_id": str(check.get("tenant_id") or tenant_id or "default"),
            "cloud": check.get("cloud", ""),
            "check_id": check.get("check_id", ""),
            "title": check.get("title", ""),
            "status": check.get("status", "unknown"),
            "severity": check.get("severity", "unknown"),
            "cis_section": check.get("cis_section", ""),
            "evidence": check.get("evidence", ""),
            "resource_ids": list(check.get("resource_ids", []) or []),
            "remediation": json.dumps(check.get("remediation", {}) or {}, sort_keys=True),
            "fix_cli": check.get("fix_cli", ""),
            "fix_console": check.get("fix_console", ""),
            "effort": check.get("effort", ""),
            "priority": int(check.get("priority", 0) or 0),
            "guardrails": list(check.get("guardrails", []) or []),
            "requires_human_review": int(bool(check.get("requires_human_review", False))),
        }

    def record_audit_event(self, event: dict) -> None:
        self._client.insert_json("audit_events", [self._audit_row(event)])

    def _audit_row(self, event: dict) -> dict[str, Any]:
        return {
            "event_timestamp": _coerce_clickhouse_timestamp(event.get("event_timestamp") or event.get("timestamp")),
            "entry_id": event.get("entry_id", str(uuid.uuid4())),
            "action": event.get("action", ""),
            "actor": event.get("actor", ""),
            "resource": event.get("resource", ""),
            "tenant_id": event.get("tenant_id", "default"),
            "session_id": str(event.get("session_id", "") or ""),
            "trace_id": str(event.get("trace_id", "") or ""),
            "request_id": str(event.get("request_id", "") or ""),
        }

    # -- reads ---------------------------------------------------------

    def query_vuln_trends(
        self,
        days: int = 30,
        agent: str | None = None,
        *,
        tenant_id: str | None = None,
    ) -> list[dict]:
        # days is int-only, agent + tenant_id are escaped via _escape() — safe from injection
        where = f"scan_timestamp >= now() - INTERVAL {int(days)} DAY"
        if agent:
            where += f" AND agent_name = '{_escape(agent)}'"
        if tenant_id is not None:
            where += f" AND tenant_id = '{_escape(tenant_id)}'"
        query = (
            f"SELECT toDate(scan_timestamp) AS day, severity, count() AS cnt "  # nosec B608
            f"FROM vulnerability_scans WHERE {where} "
            f"GROUP BY day, severity ORDER BY day"
        )
        return self._client.query_json(query)

    def query_top_cves(self, limit: int = 20, *, tenant_id: str | None = None) -> list[dict]:
        # limit is int-only via int() cast — safe from injection
        where = "cve_id != ''"
        if tenant_id is not None:
            where += f" AND tenant_id = '{_escape(tenant_id)}'"
        query = (
            f"SELECT cve_id, count() AS cnt, max(cvss_score) AS max_cvss "  # nosec B608
            f"FROM vulnerability_scans WHERE {where} "
            f"GROUP BY cve_id ORDER BY cnt DESC LIMIT {int(limit)}"
        )
        return self._client.query_json(query)

    def query_posture_history(
        self,
        agent: str | None = None,
        days: int = 90,
        *,
        tenant_id: str | None = None,
    ) -> list[dict]:
        # days is int-only, agent + tenant_id are escaped via _escape() — safe from injection
        where = f"measured_at >= now() - INTERVAL {int(days)} DAY"
        if agent:
            where += f" AND agent_name = '{_escape(agent)}'"
        if tenant_id is not None:
            where += f" AND tenant_id = '{_escape(tenant_id)}'"
        query = (
            f"SELECT toDate(measured_at) AS day, agent_name, posture_grade, "  # nosec B608
            f"risk_score, compliance_score "
            f"FROM posture_scores WHERE {where} "
            f"ORDER BY day"
        )
        return self._client.query_json(query)

    def query_event_summary(self, hours: int = 24, *, tenant_id: str | None = None) -> list[dict]:
        # hours is int-only via int() cast — safe from injection
        where = f"event_timestamp >= now() - INTERVAL {int(hours)} HOUR"
        if tenant_id is not None:
            where += f" AND tenant_id = '{_escape(tenant_id)}'"
        query = (
            f"SELECT event_type, severity, count() AS cnt "  # nosec B608
            f"FROM runtime_events "
            f"WHERE {where} "
            f"GROUP BY event_type, severity ORDER BY cnt DESC"
        )
        return self._client.query_json(query)

    def query_top_riskiest_agents(self, limit: int = 20, *, tenant_id: str | None = None) -> list[dict]:
        where_clause = ""
        if tenant_id is not None:
            where_clause = f" WHERE tenant_id = '{_escape(tenant_id)}'"
        query = (
            f"SELECT agent_name, anyLast(lifecycle_state) AS lifecycle_state, "
            f"max(trust_score) AS trust_score, max(vuln_count) AS vuln_count, "
            f"max(credential_count) AS credential_count, anyLast(tenant_id) AS tenant_id "  # nosec B608
            f"FROM fleet_agents{where_clause} GROUP BY agent_name ORDER BY trust_score ASC, vuln_count DESC "
            f"LIMIT {int(limit)}"
        )
        return self._client.query_json(query)

    def query_compliance_heatmap(self, days: int = 30, *, tenant_id: str | None = None) -> list[dict]:
        where = f"measured_at >= now() - INTERVAL {int(days)} DAY"
        if tenant_id is not None:
            where += f" AND tenant_id = '{_escape(tenant_id)}'"
        query = (
            f"SELECT framework, status, count() AS cnt, avg(score) AS avg_score "  # nosec B608
            f"FROM compliance_controls "
            f"WHERE {where} "
            f"GROUP BY framework, status ORDER BY framework, status"
        )
        return self._client.query_json(query)

    def query_cis_benchmark_checks(
        self,
        *,
        cloud: str | None = None,
        status: str | None = None,
        priority: int | None = None,
        limit: int = 100,
        offset: int = 0,
        tenant_id: str | None = None,
    ) -> list[dict]:
        clauses: list[str] = []
        if tenant_id is not None:
            clauses.append(f"tenant_id = '{_escape(tenant_id)}'")
        if cloud:
            clauses.append(f"cloud = '{_escape(cloud)}'")
        if status:
            clauses.append(f"status = '{_escape(status)}'")
        if priority is not None:
            clauses.append(f"priority = {int(priority)}")
        where = " AND ".join(clauses) if clauses else "1"
        safe_limit = max(1, min(int(limit), 500))
        safe_offset = max(0, int(offset))
        query = (
            "SELECT scan_id, measured_at, tenant_id, cloud, check_id, title, status, severity, cis_section, "
            "evidence, resource_ids, remediation, fix_cli, fix_console, effort, priority, guardrails, "
            "requires_human_review "  # nosec B608
            f"FROM cis_benchmark_checks WHERE {where} "
            f"ORDER BY measured_at DESC, priority ASC, cloud, check_id LIMIT {safe_limit} OFFSET {safe_offset}"
        )
        return self._client.query_json(query)

    def aggregate_cis_benchmark_checks(
        self,
        *,
        days: int = 30,
        cloud: str | None = None,
        section: str | None = None,
        status: str | None = None,
        severity: str | None = None,
        bucket: str = "day",
        tenant_id: str | None = None,
    ) -> list[dict]:
        """Time-bucketed CIS finding counts (#1832).

        Mirrors :meth:`PostgresJobStore.aggregate_cis_benchmark_checks` so
        the API trend endpoint can fall back to ClickHouse when the
        primary scan store is in-memory or otherwise lacks the columnar
        index. Bucket is whitelisted (``hour``/``day``/``week``) and
        every filter value flows through the existing ``_escape`` helper.
        """
        bucket_unit = {"hour": "toStartOfHour", "day": "toStartOfDay", "week": "toStartOfWeek"}.get(str(bucket).lower(), "toStartOfDay")
        clauses: list[str] = [f"measured_at >= now() - INTERVAL {max(1, min(int(days), 366))} DAY"]
        if tenant_id is not None:
            clauses.append(f"tenant_id = '{_escape(tenant_id)}'")
        if cloud:
            clauses.append(f"cloud = '{_escape(cloud)}'")
        if section:
            clauses.append(f"cis_section = '{_escape(section)}'")
        if status:
            clauses.append(f"status = '{_escape(status)}'")
        if severity:
            clauses.append(f"severity = '{_escape(severity)}'")
        where = " AND ".join(clauses)
        query = (
            f"SELECT {bucket_unit}(measured_at) AS bucket, cloud, cis_section, status, severity, "
            "count() AS count "  # nosec B608
            f"FROM cis_benchmark_checks WHERE {where} "
            "GROUP BY bucket, cloud, cis_section, status, severity "
            "ORDER BY bucket DESC, cloud, cis_section, status, severity"
        )
        rows = self._client.query_json(query)
        return [
            {
                "bucket": str(row.get("bucket", "")),
                "cloud": row.get("cloud", ""),
                "cis_section": row.get("cis_section", ""),
                "status": row.get("status", ""),
                "severity": row.get("severity", ""),
                "count": int(row.get("count", 0)),
            }
            for row in rows
        ]

    def record_scan_metadata(self, metadata: dict, *, tenant_id: str = "default") -> None:
        self._client.insert_json(
            "scan_metadata",
            [self._metadata_row(metadata, tenant_id=tenant_id)],
        )

    def _metadata_row(self, metadata: dict, *, tenant_id: str = "default") -> dict[str, Any]:
        return {
            "scan_id": metadata.get("scan_id", str(uuid.uuid4())),
            "tenant_id": str(metadata.get("tenant_id") or tenant_id or "default"),
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

    def record_scan(
        self,
        scan_id: str,
        agent_name: str,
        vulns: list[dict],
        *,
        tenant_id: str = "default",
    ) -> None:
        self._queue.put(("scan", (scan_id, agent_name, vulns, tenant_id)))

    def record_event(self, event: dict, *, tenant_id: str = "default") -> None:
        self._queue.put(("event", (event, tenant_id)))

    def record_events(self, events: list[dict], *, tenant_id: str = "default") -> None:
        if events:
            self._queue.put(("event_batch", (events, tenant_id)))

    def record_posture(self, agent_name: str, snapshot: dict, *, tenant_id: str = "default") -> None:
        self._queue.put(("posture", (agent_name, snapshot, tenant_id)))

    def record_scan_metadata(self, metadata: dict, *, tenant_id: str = "default") -> None:
        self._queue.put(("metadata", (metadata, tenant_id)))

    def record_fleet_snapshot(self, snapshot: dict) -> None:
        self._queue.put(("fleet", (snapshot,)))

    def record_compliance_control(self, control: dict, *, tenant_id: str = "default") -> None:
        self._queue.put(("compliance", (control, tenant_id)))

    def record_cis_benchmark_checks(self, checks: list[dict], *, tenant_id: str = "default") -> None:
        if checks:
            self._queue.put(("cis_checks", (checks, tenant_id)))

    def record_audit_event(self, event: dict) -> None:
        self._queue.put(("audit", (event,)))

    def query_vuln_trends(
        self,
        days: int = 30,
        agent: str | None = None,
        *,
        tenant_id: str | None = None,
    ) -> list[dict]:
        self._flush_pending()
        return self._store.query_vuln_trends(days=days, agent=agent, tenant_id=tenant_id)

    def query_top_cves(self, limit: int = 20, *, tenant_id: str | None = None) -> list[dict]:
        self._flush_pending()
        return self._store.query_top_cves(limit=limit, tenant_id=tenant_id)

    def query_posture_history(
        self,
        agent: str | None = None,
        days: int = 90,
        *,
        tenant_id: str | None = None,
    ) -> list[dict]:
        self._flush_pending()
        return self._store.query_posture_history(agent=agent, days=days, tenant_id=tenant_id)

    def query_event_summary(self, hours: int = 24, *, tenant_id: str | None = None) -> list[dict]:
        self._flush_pending()
        return self._store.query_event_summary(hours=hours, tenant_id=tenant_id)

    def query_top_riskiest_agents(self, limit: int = 20, *, tenant_id: str | None = None) -> list[dict]:
        self._flush_pending()
        return self._store.query_top_riskiest_agents(limit=limit, tenant_id=tenant_id)

    def query_compliance_heatmap(self, days: int = 30, *, tenant_id: str | None = None) -> list[dict]:
        self._flush_pending()
        return self._store.query_compliance_heatmap(days=days, tenant_id=tenant_id)

    def query_cis_benchmark_checks(
        self,
        *,
        cloud: str | None = None,
        status: str | None = None,
        priority: int | None = None,
        limit: int = 100,
        offset: int = 0,
        tenant_id: str | None = None,
    ) -> list[dict]:
        self._flush_pending()
        return self._store.query_cis_benchmark_checks(
            cloud=cloud,
            status=status,
            priority=priority,
            limit=limit,
            offset=offset,
            tenant_id=tenant_id,
        )

    def aggregate_cis_benchmark_checks(
        self,
        *,
        days: int = 30,
        cloud: str | None = None,
        section: str | None = None,
        status: str | None = None,
        severity: str | None = None,
        bucket: str = "day",
        tenant_id: str | None = None,
    ) -> list[dict]:
        """Proxy to the underlying store after flushing the write queue (#1832)."""
        self._flush_pending()
        return self._store.aggregate_cis_benchmark_checks(
            days=days,
            cloud=cloud,
            section=section,
            status=status,
            severity=severity,
            bucket=bucket,
            tenant_id=tenant_id,
        )

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
        cis_check_rows: list[dict[str, Any]] = []
        audit_rows: list[dict[str, Any]] = []

        for kind, payload in drained:
            if kind == "scan":
                scan_id, agent_name, vulns, tenant_id = payload
                scan_rows.extend(self._store._scan_rows(str(scan_id), str(agent_name), list(vulns), tenant_id=str(tenant_id)))
            elif kind == "event":
                event, tenant_id = payload
                event_rows.append(self._store._event_row(dict(event), tenant_id=str(tenant_id)))
            elif kind == "event_batch":
                events, tenant_id = payload
                event_rows.extend(self._store._event_row(dict(event), tenant_id=str(tenant_id)) for event in events if event)
            elif kind == "posture":
                agent_name, snapshot, tenant_id = payload
                posture_rows.append(self._store._posture_row(str(agent_name), dict(snapshot), tenant_id=str(tenant_id)))
            elif kind == "metadata":
                metadata, tenant_id = payload
                metadata_rows.append(self._store._metadata_row(dict(metadata), tenant_id=str(tenant_id)))
            elif kind == "fleet":
                (snapshot,) = payload
                fleet_rows.append(self._store._fleet_row(dict(snapshot)))
            elif kind == "compliance":
                control, tenant_id = payload
                compliance_rows.append(self._store._compliance_row(dict(control), tenant_id=str(tenant_id)))
            elif kind == "cis_checks":
                checks, tenant_id = payload
                cis_check_rows.extend(self._store._cis_check_row(dict(check), tenant_id=str(tenant_id)) for check in checks if check)
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
            if cis_check_rows:
                self._store._client.insert_json("cis_benchmark_checks", cis_check_rows)
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
