"""Bounded retention + default ~90d time-window filters (#4009).

Covers:
- ``time_window`` helper: default resolution, cutoff, and honest metadata.
- Snapshot read-window: ``list_snapshots`` / ``graph_history`` filter on
  ``created_at`` and default to the configured window; ``window_days=0`` clears.
- Findings read-window: ``list_current_page`` filters on ``last_seen`` for the
  in-memory and SQLite hub stores; the window is tenant-scoped and idempotent.
- Postgres graph snapshot retention: the on-save purge selects only aged
  snapshots, is tenant-scoped, and fail-closes on unparseable timestamps.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

# ═══════════════════════════════════════════════════════════════════════════
# time_window helper
# ═══════════════════════════════════════════════════════════════════════════

NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)


class TestTimeWindowHelper:
    def test_default_window_days_reads_config(self, monkeypatch):
        from agent_bom import config
        from agent_bom.api import time_window

        monkeypatch.setattr(config, "RETENTION_DAYS", 90)
        assert time_window.default_window_days() == 90

    def test_normalize_none_uses_default(self, monkeypatch):
        from agent_bom import config
        from agent_bom.api import time_window

        monkeypatch.setattr(config, "RETENTION_DAYS", 90)
        assert time_window.normalize_window_days(None) == 90

    def test_normalize_zero_and_negative_mean_all_history(self):
        from agent_bom.api import time_window

        assert time_window.normalize_window_days(0) == 0
        assert time_window.normalize_window_days(-5) == 0

    def test_normalize_positive_passthrough(self):
        from agent_bom.api import time_window

        assert time_window.normalize_window_days(30) == 30

    def test_cutoff_is_none_when_unbounded(self):
        from agent_bom.api import time_window

        assert time_window.window_cutoff(0, now=NOW) is None

    def test_cutoff_subtracts_window(self):
        from agent_bom.api import time_window

        assert time_window.window_cutoff(90, now=NOW) == NOW - timedelta(days=90)

    def test_metadata_applied_and_labelled(self):
        from agent_bom.api import time_window

        meta = time_window.window_metadata(90, now=NOW)
        assert meta["applied"] is True
        assert meta["days"] == 90
        assert meta["label"] == "Last 90 days"
        assert meta["since"] == (NOW - timedelta(days=90)).isoformat()

    def test_metadata_all_time_when_cleared(self):
        from agent_bom.api import time_window

        meta = time_window.window_metadata(0, now=NOW)
        assert meta["applied"] is False
        assert meta["since"] is None
        assert meta["label"] == "All time"


# ═══════════════════════════════════════════════════════════════════════════
# Snapshot read-window
# ═══════════════════════════════════════════════════════════════════════════


@pytest.fixture
def db():
    from agent_bom.db.graph_store import _init_db

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    _init_db(conn)
    yield conn
    conn.close()


def _insert_snapshot(conn: sqlite3.Connection, scan_id: str, created_at: str, tenant: str = "default") -> None:
    conn.execute(
        "INSERT INTO graph_snapshots (scan_id, tenant_id, created_at, node_count, edge_count, risk_summary) VALUES (?, ?, ?, ?, ?, ?)",
        (scan_id, tenant, created_at, 1, 0, "{}"),
    )
    conn.commit()


class TestSnapshotWindow:
    def test_list_snapshots_filters_by_since(self, db):
        from agent_bom.api import time_window
        from agent_bom.db.graph_store import list_snapshots

        _insert_snapshot(db, "old", (NOW - timedelta(days=200)).isoformat())
        _insert_snapshot(db, "recent", (NOW - timedelta(days=10)).isoformat())

        since = time_window.window_since_iso(90, now=NOW)
        scan_ids = [s["scan_id"] for s in list_snapshots(db, since=since)]
        assert scan_ids == ["recent"]

    def test_list_snapshots_no_window_returns_all(self, db):
        from agent_bom.db.graph_store import list_snapshots

        _insert_snapshot(db, "old", (NOW - timedelta(days=200)).isoformat())
        _insert_snapshot(db, "recent", (NOW - timedelta(days=10)).isoformat())

        scan_ids = {s["scan_id"] for s in list_snapshots(db, since=None)}
        assert scan_ids == {"old", "recent"}

    def test_graph_history_threads_window(self, db):
        from agent_bom.api import time_window
        from agent_bom.db.graph_store import graph_history

        _insert_snapshot(db, "old", (NOW - timedelta(days=200)).isoformat())
        _insert_snapshot(db, "recent", (NOW - timedelta(days=10)).isoformat())

        since = time_window.window_since_iso(90, now=NOW)
        result = graph_history(db, since=since)
        assert [s["scan_id"] for s in result["snapshots"]] == ["recent"]


# ═══════════════════════════════════════════════════════════════════════════
# Findings read-window
# ═══════════════════════════════════════════════════════════════════════════


def _put_finding(store, tenant: str, canonical_id: str, last_seen: str) -> None:
    store.upsert_current_batch(
        tenant,
        [{"id": canonical_id, "severity": "high", "scan_id": "s1"}],
        observed_at=last_seen,
        batch_id=f"batch-{tenant}-{canonical_id}",
        source="test",
    )


class TestFindingsWindow:
    def _make_store(self):
        from agent_bom.api.compliance_hub_store import InMemoryComplianceHubStore

        return InMemoryComplianceHubStore()

    def test_in_memory_store_filters_by_since(self):
        from agent_bom.api import time_window

        store = self._make_store()
        _put_finding(store, "t1", "old", (NOW - timedelta(days=200)).isoformat())
        _put_finding(store, "t1", "recent", (NOW - timedelta(days=5)).isoformat())

        since = time_window.window_since_iso(90, now=NOW)
        rows, total, _cursor = store.list_current_page("t1", limit=100, since=since)
        assert len(rows) == 1
        assert total == 1

    def test_in_memory_store_no_window_returns_all(self):
        store = self._make_store()
        _put_finding(store, "t1", "old", (NOW - timedelta(days=200)).isoformat())
        _put_finding(store, "t1", "recent", (NOW - timedelta(days=5)).isoformat())

        rows, total, _cursor = store.list_current_page("t1", limit=100, since=None)
        assert len(rows) == 2
        assert total == 2

    def test_window_is_tenant_scoped(self):
        from agent_bom.api import time_window

        store = self._make_store()
        _put_finding(store, "t1", "t1-recent", (NOW - timedelta(days=5)).isoformat())
        _put_finding(store, "t2", "t2-old", (NOW - timedelta(days=200)).isoformat())

        since = time_window.window_since_iso(90, now=NOW)
        rows_t1, _t, _c = store.list_current_page("t1", limit=100, since=since)
        rows_t2, _t2, _c2 = store.list_current_page("t2", limit=100, since=since)
        assert len(rows_t1) == 1
        assert rows_t2 == []

    def test_window_is_idempotent(self):
        from agent_bom.api import time_window

        store = self._make_store()
        _put_finding(store, "t1", "recent", (NOW - timedelta(days=5)).isoformat())
        since = time_window.window_since_iso(90, now=NOW)
        first, _t, _c = store.list_current_page("t1", limit=100, since=since)
        second, _t2, _c2 = store.list_current_page("t1", limit=100, since=since)
        assert len(first) == len(second) == 1

    def test_sqlite_store_filters_by_since(self):
        from agent_bom.api import time_window
        from agent_bom.api.compliance_hub_store import SQLiteComplianceHubStore

        store = SQLiteComplianceHubStore(":memory:")
        _put_finding(store, "t1", "old", (NOW - timedelta(days=200)).isoformat())
        _put_finding(store, "t1", "recent", (NOW - timedelta(days=5)).isoformat())

        since = time_window.window_since_iso(90, now=NOW)
        rows, total, _cursor = store.list_current_page("t1", limit=100, since=since)
        assert len(rows) == 1
        assert total == 1

        rows_all, total_all, _c = store.list_current_page("t1", limit=100, since=None)
        assert len(rows_all) == 2
        assert total_all == 2


# ═══════════════════════════════════════════════════════════════════════════
# Postgres graph snapshot retention (pure selection helper)
# ═══════════════════════════════════════════════════════════════════════════


class TestFindingsRouteWindow:
    """`/v1/findings` echoes the applied read-window so counts label honestly."""

    def _client(self):
        from starlette.testclient import TestClient

        from agent_bom.api.compliance_hub_store import reset_compliance_hub_store
        from agent_bom.api.server import app, set_job_store
        from agent_bom.api.store import InMemoryJobStore
        from tests.auth_helpers import enable_trusted_proxy_env, proxy_headers

        enable_trusted_proxy_env()
        reset_compliance_hub_store()
        set_job_store(InMemoryJobStore())
        client = TestClient(app)
        client.headers.update(proxy_headers(role="admin", tenant="tenant-window"))
        return client

    def test_default_window_is_applied_and_labelled(self, monkeypatch):
        from agent_bom import config

        monkeypatch.setattr(config, "RETENTION_DAYS", 90)
        client = self._client()
        body = client.get("/v1/findings").json()
        assert body["window"]["days"] == 90
        assert body["window"]["applied"] is True
        assert body["window"]["label"] == "Last 90 days"

    def test_window_can_be_cleared_to_all_history(self, monkeypatch):
        from agent_bom import config

        monkeypatch.setattr(config, "RETENTION_DAYS", 90)
        client = self._client()
        body = client.get("/v1/findings?window_days=0").json()
        assert body["window"]["applied"] is False
        assert body["window"]["label"] == "All time"


class TestPostgresSnapshotPurgeSelection:
    def test_selects_only_aged_snapshots(self):
        from agent_bom.api.postgres_graph import select_expired_snapshot_ids

        rows = [
            ("old", "default", (NOW - timedelta(days=200)).isoformat()),
            ("recent", "default", (NOW - timedelta(days=10)).isoformat()),
        ]
        expired = select_expired_snapshot_ids(rows, now=NOW, resolve_days=lambda _t: 180)
        assert expired == [("old", "default")]

    def test_fail_closed_on_unparseable_timestamp(self):
        from agent_bom.api.postgres_graph import select_expired_snapshot_ids

        rows = [("malformed", "default", "not-a-timestamp")]
        expired = select_expired_snapshot_ids(rows, now=NOW, resolve_days=lambda _t: 1)
        assert expired == []

    def test_per_tenant_windows(self):
        from agent_bom.api.postgres_graph import select_expired_snapshot_ids

        rows = [
            ("a-old", "tenant-a", (NOW - timedelta(days=45)).isoformat()),
            ("b-old", "tenant-b", (NOW - timedelta(days=45)).isoformat()),
        ]
        windows = {"tenant-a": 30, "tenant-b": 90}
        expired = select_expired_snapshot_ids(rows, now=NOW, resolve_days=lambda t: windows[t])
        assert expired == [("a-old", "tenant-a")]
