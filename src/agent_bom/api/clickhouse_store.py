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
import os
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


def _deterministic_event_id(*parts: Any) -> str:
    """Return a stable content-derived event id for id-less analytics events.

    Mirrors the runtime observation store fallback so an event retried without
    a caller-supplied id collapses under ``runtime_events`` ReplacingMergeTree
    dedup instead of appending a new row each time (audit item J).
    """
    from agent_bom.canonical_ids import canonical_id

    return canonical_id("analytics_event", *parts)


def _deterministic_row_key(kind: str, *parts: Any) -> str:
    """Return a stable dedup key for canonical analytics rows (#3484)."""
    from agent_bom.canonical_ids import canonical_id

    return canonical_id(f"analytics_{kind}", *parts)


def _insert_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


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
                "finding_key": _deterministic_row_key(
                    "finding",
                    str(v.get("tenant_id") or tenant_id or "default"),
                    scan_id,
                    agent_name,
                    v.get("cve_id", v.get("id", "")),
                    _split_package(v)[0],
                    _split_package(v)[1],
                ),
                "updated_at": _insert_timestamp(),
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
        resolved_tenant = str(event.get("tenant_id") or tenant_id or "default")
        event_timestamp = _coerce_clickhouse_timestamp(event.get("event_timestamp") or event.get("timestamp") or event.get("ts"))
        event_type = event.get("event_type", event.get("type", ""))
        detector = event.get("detector", "")
        tool_name = event.get("tool_name", event.get("tool", ""))
        message = event.get("message", "")
        event_id = str(event.get("event_id") or "").strip()
        if not event_id:
            # Deterministic content-derived ID so retries collapse under the
            # runtime_events ReplacingMergeTree instead of double-counting on a
            # fresh uuid4 (audit item J).
            event_id = _deterministic_event_id(
                resolved_tenant,
                str(event.get("source_id") or ""),
                str(event_timestamp or ""),
                event_type,
                detector,
                tool_name,
                message,
            )
        return {
            "event_id": event_id,
            "event_timestamp": event_timestamp,
            "updated_at": _insert_timestamp(),
            "tenant_id": resolved_tenant,
            "event_type": event_type,
            "detector": detector,
            "severity": event.get("severity", "INFO"),
            "tool_name": tool_name,
            "message": message,
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
            "updated_at": _insert_timestamp(),
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
            "measured_at": _coerce_clickhouse_timestamp(snapshot.get("last_seen")),
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
        resolved_tenant = str(control.get("tenant_id") or tenant_id or "default")
        scan_id = control.get("scan_id", "")
        framework = control.get("framework", "")
        control_id = control.get("control_id", "")
        return {
            "measured_at": _coerce_clickhouse_timestamp(control.get("measured_at")),
            "scan_id": scan_id,
            "tenant_id": resolved_tenant,
            "control_key": _deterministic_row_key("control", resolved_tenant, scan_id, framework, control_id),
            "updated_at": _insert_timestamp(),
            "framework": framework,
            "control_id": control_id,
            "control_name": control.get("control_name", ""),
            "status": control.get("status", "unknown"),
            "finding_count": int(control.get("finding_count", 0)),
            "score": float(control.get("score", 0.0)),
        }

    def _cis_check_row(self, check: dict, *, tenant_id: str = "default") -> dict[str, Any]:
        resolved_tenant = str(check.get("tenant_id") or tenant_id or "default")
        scan_id = check.get("scan_id", "")
        cloud = check.get("cloud", "")
        check_id = check.get("check_id", "")
        return {
            "measured_at": _coerce_clickhouse_timestamp(check.get("measured_at")),
            "scan_id": scan_id,
            "tenant_id": resolved_tenant,
            "check_key": _deterministic_row_key("cis_check", resolved_tenant, scan_id, cloud, check_id),
            "updated_at": _insert_timestamp(),
            "cloud": cloud,
            "check_id": check_id,
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
        tenant_id = str(event.get("tenant_id", "default"))
        event_timestamp = _coerce_clickhouse_timestamp(event.get("event_timestamp") or event.get("timestamp"))
        entry_id = str(event.get("entry_id") or "").strip()
        if not entry_id:
            entry_id = _deterministic_event_id(
                tenant_id,
                event.get("action", ""),
                event.get("actor", ""),
                event.get("resource", ""),
                str(event_timestamp or ""),
                str(event.get("session_id", "") or ""),
                str(event.get("trace_id", "") or ""),
                str(event.get("request_id", "") or ""),
            )
        return {
            "event_timestamp": event_timestamp,
            "entry_id": entry_id,
            "updated_at": _insert_timestamp(),
            "action": event.get("action", ""),
            "actor": event.get("actor", ""),
            "resource": event.get("resource", ""),
            "tenant_id": tenant_id,
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
            f"SELECT toDate(scan_timestamp) AS day, severity, "  # nosec B608
            f"uniqExact(if(finding_key != '', finding_key, "
            f"concat(tenant_id, ':', scan_id, ':', agent_name, ':', cve_id, ':', package_name, ':', package_version))) AS cnt "
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
            f"SELECT cve_id, "  # nosec B608
            f"uniqExact(if(finding_key != '', finding_key, "
            f"concat(tenant_id, ':', scan_id, ':', agent_name, ':', cve_id, ':', package_name, ':', package_version))) AS cnt, "
            f"max(cvss_score) AS max_cvss "
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
            f"SELECT event_type, severity, uniqExact(event_id) AS cnt "  # nosec B608
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
        resolved_tenant = str(metadata.get("tenant_id") or tenant_id or "default")
        scan_id = metadata.get("scan_id", str(uuid.uuid4()))
        return {
            "scan_id": scan_id,
            "tenant_id": resolved_tenant,
            "updated_at": _insert_timestamp(),
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
    paths do not block on ClickHouse round-trips. ClickHouse tables already
    carry server-side TTL clauses (see ``agent_bom.cloud.clickhouse``); local
    SQLite/Postgres mirrors and runtime observations are capped separately via
    ``AGENT_BOM_ANALYTICS_MAX_EVENTS``.
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
            logger.warning("Buffered ClickHouse flush failed; re-queuing batch", exc_info=True)
            for item in drained:
                self._queue.put(item)

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


# ------------------------------------------------------------------
# Best-effort findings ingest from a serialized scan report
# ------------------------------------------------------------------


def build_scan_ingest_rows(
    report_json: dict[str, Any],
    *,
    source: str = "cli",
) -> tuple[str, dict[str, list[dict[str, Any]]], dict[str, Any]]:
    """Derive ClickHouse ingest rows from a serialized scan report dict.

    Returns ``(scan_id, findings_by_agent, scan_metadata)``. This mirrors
    ``agent_bom.analytics_contract._build_agent_findings`` / scan-metadata but
    operates purely on the report JSON (no in-memory ``AIBOMReport``), so the
    history save hook can ingest a completed CLI scan. Column names match what
    the ``analytics`` query command reads from ``vulnerability_scans`` and
    ``scan_metadata``.

    The ``scan_id`` is derived deterministically from the report's
    ``scan_id``/``generated_at`` so re-saving the same report collapses under
    the ``vulnerability_scans`` ReplacingMergeTree dedup (finding_key) instead
    of double-counting — consistent with the local analytics mirror.
    """
    blast_radius = report_json.get("blast_radius") or report_json.get("blast_radii") or []
    if not isinstance(blast_radius, list):
        blast_radius = []

    scan_id = str(report_json.get("scan_id") or "").strip()
    if not scan_id:
        generated_key = "".join(ch for ch in str(report_json.get("generated_at") or "") if ch.isalnum())
        scan_id = f"local-{generated_key}" if generated_key else str(uuid.uuid4())

    findings_by_agent: dict[str, list[dict[str, Any]]] = {}
    for item in blast_radius:
        if not isinstance(item, dict):
            continue
        finding = {
            "package_name": item.get("package_name", ""),
            "package_version": item.get("package_version", ""),
            "package": item.get("package", ""),
            "ecosystem": item.get("ecosystem", ""),
            "cve_id": item.get("vulnerability_id", "") or item.get("cve_id", ""),
            "cvss_score": float(item.get("cvss_score") or 0.0),
            "epss_score": float(item.get("epss_score") or 0.0),
            "severity": item.get("severity", "unknown"),
            "source": item.get("primary_advisory_source") or item.get("source") or "osv",
            "environment": item.get("environment", ""),
            "cmmc_tags": list(item.get("cmmc_tags", []) or []),
        }
        # Fan out per affected agent (matching the API/CLI contract path). When
        # a finding is not attributed to any agent, still record it once under
        # an empty agent_name so no finding is silently dropped from analytics.
        agents = [a for a in (item.get("affected_agents") or []) if a] or [""]
        for agent_name in agents:
            findings_by_agent.setdefault(agent_name, []).append(dict(finding))

    summary = report_json.get("summary")
    summary = summary if isinstance(summary, dict) else {}
    posture = report_json.get("posture_scorecard")
    posture = posture if isinstance(posture, dict) else {}
    scan_metadata = {
        "scan_id": scan_id,
        "agent_count": int(summary.get("total_agents", 0) or 0),
        "package_count": int(summary.get("total_packages", 0) or 0),
        "vuln_count": int(summary.get("total_vulnerabilities", 0) or 0),
        "critical_count": int(summary.get("critical_findings", 0) or 0),
        "high_count": sum(
            1 for item in blast_radius if isinstance(item, dict) and str(item.get("severity", "")).lower() == "high"
        ),
        "posture_grade": str(posture.get("grade", "") or ""),
        "scan_duration_ms": int(report_json.get("scan_duration_ms", 0) or 0),
        "source": source,
    }
    return scan_id, findings_by_agent, scan_metadata


def ingest_scan_report_best_effort(
    report_json: dict[str, Any],
    *,
    source: str = "cli",
    tenant_id: str = "default",
    url: str | None = None,
    store: Any | None = None,
) -> str | None:
    """Best-effort ClickHouse mirror of a completed scan report.

    No-op (zero overhead — one env lookup then return) when neither *store* nor
    *url* is supplied and ``AGENT_BOM_CLICKHOUSE_URL`` is unset. Any ClickHouse
    connection/insert error is swallowed and logged at debug so analytics
    ingest can never fail a scan — mirrors
    ``agent_bom.db.local_analytics.record_scan_report_best_effort``.

    Returns the ingested ``scan_id`` on success, else ``None``.
    """
    resolved_url = url or os.environ.get("AGENT_BOM_CLICKHOUSE_URL")
    if store is None and not resolved_url:
        return None
    try:
        ch_store = store if store is not None else ClickHouseAnalyticsStore(url=resolved_url)
        scan_id, findings_by_agent, metadata = build_scan_ingest_rows(report_json, source=source)
        for agent_name, findings in findings_by_agent.items():
            if findings:
                ch_store.record_scan(scan_id, agent_name, findings, tenant_id=tenant_id)
        ch_store.record_scan_metadata(metadata, tenant_id=tenant_id)
        return scan_id
    except Exception:
        logger.debug("ClickHouse findings-ingest skipped (best-effort)", exc_info=True)
        return None
