"""Tenant-isolation contract for the ClickHouse analytics backend.

Locks three guarantees without standing up a real ClickHouse:

1. Every ``record_*`` write emits rows carrying a ``tenant_id`` column.
   A row missing the column would be silently written with the table
   default, letting cross-tenant reads see it.
2. Every ``query_*`` read with an explicit tenant scope emits a
   ``tenant_id = '<scope>'`` predicate. Missing the predicate would
   leak one tenant's aggregates into another tenant's dashboard.
3. ``ensure_tables`` applies the forward-compatible ALTER migrations
   that give pre-tenant deployments the column on upgrade.

Covers the BufferedAnalyticsStore path too because it drains through the
same row builders via a worker thread.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest

from agent_bom.api.clickhouse_store import (
    BufferedAnalyticsStore,
    ClickHouseAnalyticsStore,
)
from agent_bom.cloud.clickhouse import _TABLE_MIGRATIONS, ClickHouseClient

# ─── Helpers ────────────────────────────────────────────────────────────────


class _CapturingClient:
    """Records every insert + query call so tests can assert contents."""

    def __init__(self) -> None:
        self.inserts: list[tuple[str, list[dict[str, Any]]]] = []
        self.queries: list[str] = []

    def insert_json(self, table: str, rows: list[dict[str, Any]]) -> None:
        # Defensive copy so later mutations by the real code don't mask bugs
        self.inserts.append((table, [dict(r) for r in rows]))

    def query_json(self, query: str) -> list[dict[str, Any]]:
        self.queries.append(query)
        return []


def _make_store() -> tuple[ClickHouseAnalyticsStore, _CapturingClient]:
    """Build a ClickHouseAnalyticsStore with a captured fake client."""
    capturer = _CapturingClient()
    # Patch __init__ side-effects so we can use a real store object
    with patch.object(ClickHouseAnalyticsStore, "__init__", return_value=None):
        store = ClickHouseAnalyticsStore()
    store._client = capturer  # type: ignore[attr-defined]
    return store, capturer


# ─── Writes carry tenant_id ────────────────────────────────────────────────


class TestWritesCarryTenantId:
    def test_record_scan(self) -> None:
        store, cap = _make_store()
        vulns = [
            {"cve_id": "CVE-2024-0001", "severity": "HIGH", "package_name": "axios", "package_version": "1.4.0"},
            {"cve_id": "CVE-2024-0002", "severity": "CRITICAL", "package_name": "certifi", "package_version": "2022.12.7"},
        ]
        store.record_scan("scan-123", "claude-desktop", vulns, tenant_id="tenant-a")
        assert cap.inserts, "record_scan must insert at least one batch"
        table, rows = cap.inserts[0]
        assert table == "vulnerability_scans"
        assert len(rows) == 2
        for row in rows:
            assert row["tenant_id"] == "tenant-a"

    def test_record_event(self) -> None:
        store, cap = _make_store()
        store.record_event({"event_type": "tool_call", "severity": "HIGH"}, tenant_id="tenant-b")
        table, rows = cap.inserts[0]
        assert table == "runtime_events"
        assert rows[0]["tenant_id"] == "tenant-b"

    def test_record_events_batch(self) -> None:
        store, cap = _make_store()
        store.record_events(
            [
                {"event_type": "tool_call", "severity": "HIGH"},
                {"event_type": "tool_result", "severity": "INFO"},
            ],
            tenant_id="tenant-c",
        )
        _, rows = cap.inserts[0]
        assert len(rows) == 2
        assert all(r["tenant_id"] == "tenant-c" for r in rows)

    def test_record_posture(self) -> None:
        store, cap = _make_store()
        store.record_posture("cursor", {"grade": "B", "critical": 1}, tenant_id="tenant-d")
        _, rows = cap.inserts[0]
        assert rows[0]["tenant_id"] == "tenant-d"

    def test_record_compliance_control(self) -> None:
        store, cap = _make_store()
        store.record_compliance_control(
            {"framework": "fedramp", "control_id": "AC-2", "status": "pass"},
            tenant_id="tenant-e",
        )
        _, rows = cap.inserts[0]
        assert rows[0]["tenant_id"] == "tenant-e"

    def test_record_scan_metadata(self) -> None:
        store, cap = _make_store()
        store.record_scan_metadata({"scan_id": "s-1", "agent_count": 3}, tenant_id="tenant-f")
        _, rows = cap.inserts[0]
        assert rows[0]["tenant_id"] == "tenant-f"

    def test_row_dict_tenant_overrides_kwarg(self) -> None:
        """If the caller already supplied tenant_id in the payload dict, it wins."""
        store, cap = _make_store()
        store.record_event({"event_type": "x", "tenant_id": "explicit"}, tenant_id="default")
        _, rows = cap.inserts[0]
        assert rows[0]["tenant_id"] == "explicit"

    def test_default_when_unset(self) -> None:
        store, cap = _make_store()
        store.record_event({"event_type": "x"})
        _, rows = cap.inserts[0]
        assert rows[0]["tenant_id"] == "default"


# ─── Reads apply tenant_id filter ──────────────────────────────────────────


class TestReadsApplyTenantFilter:
    @pytest.mark.parametrize(
        "method,kwargs,expected_table",
        [
            ("query_vuln_trends", {"days": 30}, "vulnerability_scans"),
            ("query_top_cves", {"limit": 10}, "vulnerability_scans"),
            ("query_posture_history", {"days": 90}, "posture_scores"),
            ("query_event_summary", {"hours": 24}, "runtime_events"),
            ("query_top_riskiest_agents", {"limit": 10}, "fleet_agents"),
            ("query_compliance_heatmap", {"days": 30}, "compliance_controls"),
        ],
    )
    def test_tenant_predicate_present(
        self, method: str, kwargs: dict[str, Any], expected_table: str
    ) -> None:
        store, cap = _make_store()
        getattr(store, method)(tenant_id="tenant-a", **kwargs)
        assert cap.queries, f"{method} must issue a query"
        query = cap.queries[0]
        assert expected_table in query, f"{method} must read from {expected_table}"
        assert "tenant_id = 'tenant-a'" in query, (
            f"{method} must include tenant predicate; actual:\n{query}"
        )

    @pytest.mark.parametrize(
        "method,kwargs",
        [
            ("query_vuln_trends", {"days": 30}),
            ("query_top_cves", {"limit": 10}),
            ("query_posture_history", {"days": 90}),
            ("query_event_summary", {"hours": 24}),
            ("query_top_riskiest_agents", {"limit": 10}),
            ("query_compliance_heatmap", {"days": 30}),
        ],
    )
    def test_no_tenant_kwarg_means_admin_scope(self, method: str, kwargs: dict[str, Any]) -> None:
        """Absence of tenant_id deliberately reads cross-tenant (admin-only use)."""
        store, cap = _make_store()
        getattr(store, method)(**kwargs)
        query = cap.queries[0]
        assert "tenant_id =" not in query, (
            f"{method} without tenant_id must not inject a tenant predicate; actual:\n{query}"
        )

    def test_tenant_id_is_escaped(self) -> None:
        """Tenant identifiers that contain SQL metacharacters must not break queries."""
        store, cap = _make_store()
        store.query_vuln_trends(days=30, tenant_id="evil'--")
        query = cap.queries[0]
        # Single-quote in the value must have been escaped; raw unescaped
        # injection would leave a literal ' inside the predicate.
        assert "tenant_id = 'evil\\'--'" in query or "tenant_id = 'evil--'" in query, (
            f"tenant_id must be escaped in the query; actual:\n{query}"
        )


# ─── BufferedAnalyticsStore preserves tenant_id through the queue ──────────


class TestBufferedStoreCarriesTenant:
    def test_buffered_scan_flush_preserves_tenant(self) -> None:
        store, cap = _make_store()
        buffered = BufferedAnalyticsStore(store, max_batch=8, flush_interval=0.05)
        try:
            buffered.record_scan(
                "scan-x",
                "claude-desktop",
                [{"cve_id": "CVE-2024-9999", "package_name": "axios", "package_version": "1.4.0"}],
                tenant_id="tenant-buffered",
            )
            buffered.record_compliance_control(
                {"framework": "soc2", "control_id": "CC6.1", "status": "pass"},
                tenant_id="tenant-buffered",
            )
            buffered.record_event(
                {"event_type": "tool_call", "severity": "HIGH"},
                tenant_id="tenant-buffered",
            )
            # Force a flush by issuing a read
            buffered.query_top_cves(limit=1, tenant_id="tenant-buffered")
        finally:
            buffered.close()

        # All three writes drained into separate inserts
        tables_seen = {table for table, _ in cap.inserts}
        assert {"vulnerability_scans", "compliance_controls", "runtime_events"}.issubset(tables_seen)
        for _, rows in cap.inserts:
            for row in rows:
                # Every row inserted via the buffered path should carry the
                # caller-supplied tenant.
                assert row.get("tenant_id") == "tenant-buffered", row


# ─── Forward-compatible migrations exist for every tenant-less table ───────


class TestMigrationCoverage:
    def test_migration_covers_every_table_missing_tenant(self) -> None:
        """The ALTER migrations must cover every CREATE TABLE that lacks tenant_id natively.

        Without this coverage, pre-tenant deployments would keep running
        without the column and cross-tenant reads would silently succeed.
        """
        required = {
            "vulnerability_scans",
            "runtime_events",
            "posture_scores",
            "scan_metadata",
            "compliance_controls",
        }
        for table in required:
            assert any(
                migration.startswith(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS tenant_id")
                for migration in _TABLE_MIGRATIONS
            ), f"Missing ALTER migration for table '{table}'"

    def test_ensure_tables_runs_migrations(self) -> None:
        """Schema bootstrap calls each migration exactly once."""
        from agent_bom.cloud.clickhouse import _TABLE_DDL

        client = ClickHouseClient.__new__(ClickHouseClient)
        client.url = "http://unused"  # type: ignore[attr-defined]
        client.user = "default"  # type: ignore[attr-defined]
        client.password = ""  # type: ignore[attr-defined]
        client.database = "agent_bom_test"  # type: ignore[attr-defined]
        client.timeout = 5  # type: ignore[attr-defined]
        executed: list[str] = []

        def _fake_execute(query: str) -> str:
            executed.append(query)
            return "{}"

        client.execute = _fake_execute  # type: ignore[assignment]
        client.ensure_tables()
        # Must run: CREATE DATABASE + every CREATE TABLE DDL + every migration
        expected_calls = 1 + len(_TABLE_DDL) + len(_TABLE_MIGRATIONS)
        assert len(executed) == expected_calls, (
            f"ensure_tables should execute CREATE DATABASE + {len(_TABLE_DDL)} tables + "
            f"{len(_TABLE_MIGRATIONS)} migrations = {expected_calls} statements, "
            f"got {len(executed)}"
        )
        migrations_run = [stmt for stmt in executed if stmt.startswith("ALTER TABLE ")]
        assert set(migrations_run) == set(_TABLE_MIGRATIONS)
