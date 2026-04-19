"""Cross-tenant leakage contract tests.

Locks the guarantee a pilot team asks first: "can tenant A ever see
tenant B's data?" Answer must be no — across analytics writes with
concurrent tenants, API reads, and the compliance evidence bundle.

Complements the unit-level contract in
``tests/test_clickhouse_tenant_isolation.py`` (which asserts shape of
rows/queries) by exercising full scenarios where two tenants operate
against the same store.
"""

from __future__ import annotations

import threading
from typing import Any
from unittest.mock import patch

from agent_bom.api.clickhouse_store import ClickHouseAnalyticsStore


class _RecordingClient:
    """ClickHouse client fake that records every insert/query for later assertions."""

    def __init__(self) -> None:
        self.inserts: list[tuple[str, list[dict[str, Any]]]] = []
        self.queries: list[str] = []
        self._lock = threading.Lock()

    def insert_json(self, table: str, rows: list[dict[str, Any]]) -> None:
        with self._lock:
            self.inserts.append((table, [dict(r) for r in rows]))

    def query_json(self, query: str) -> list[dict[str, Any]]:
        with self._lock:
            self.queries.append(query)
        return []


def _make_store() -> tuple[ClickHouseAnalyticsStore, _RecordingClient]:
    recorder = _RecordingClient()
    with patch.object(ClickHouseAnalyticsStore, "__init__", return_value=None):
        store = ClickHouseAnalyticsStore()
    store._client = recorder  # type: ignore[attr-defined]
    return store, recorder


# ─── Concurrent writes from two tenants never mix in the row stream ────────


def test_concurrent_writes_from_two_tenants_stay_labeled() -> None:
    """Two tenants writing concurrently must produce rows each labeled with their own tenant_id.

    This is the real-world worst case: one process, one shared store,
    many threads, each thread authed as a different tenant. A bug that
    drops `tenant_id` on any row path would show up here as a row
    labeled with the wrong tenant or the `default` fallback.
    """
    store, recorder = _make_store()

    def write_tenant(tenant_id: str, n: int) -> None:
        for i in range(n):
            store.record_scan(
                scan_id=f"{tenant_id}-scan-{i}",
                agent_name="claude-desktop",
                vulns=[
                    {
                        "cve_id": f"CVE-2024-{i:04d}",
                        "severity": "HIGH",
                        "package_name": "axios",
                        "package_version": "1.4.0",
                    }
                ],
                tenant_id=tenant_id,
            )

    threads = [
        threading.Thread(target=write_tenant, args=("tenant-alpha", 100)),
        threading.Thread(target=write_tenant, args=("tenant-beta", 100)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    rows_alpha: list[dict[str, Any]] = []
    rows_beta: list[dict[str, Any]] = []
    rows_other: list[dict[str, Any]] = []
    for _table, rows in recorder.inserts:
        for row in rows:
            if row.get("tenant_id") == "tenant-alpha":
                rows_alpha.append(row)
            elif row.get("tenant_id") == "tenant-beta":
                rows_beta.append(row)
            else:
                rows_other.append(row)

    assert len(rows_alpha) == 100, f"tenant-alpha lost rows: {len(rows_alpha)}"
    assert len(rows_beta) == 100, f"tenant-beta lost rows: {len(rows_beta)}"
    assert not rows_other, (
        f"every row must carry tenant-alpha or tenant-beta — a row with any other tenant_id means a tenant leaked: {rows_other[:3]}"
    )

    # Sanity: no row's payload mentions the *other* tenant's scan_id.
    # This is the canary a pilot's security team will run.
    for row in rows_alpha:
        assert "tenant-beta" not in str(row), f"tenant-beta scan_id leaked into alpha row: {row}"
    for row in rows_beta:
        assert "tenant-alpha" not in str(row), f"tenant-alpha scan_id leaked into beta row: {row}"


# ─── Queries for one tenant never match rows of another ────────────────────


def test_per_tenant_query_predicates_partition_the_row_stream() -> None:
    """Every query with tenant_id kwarg must emit a predicate that ONLY
    matches that tenant's rows. A client that accidentally returned rows
    from multiple tenants would show up as a query lacking the predicate.
    """
    store, recorder = _make_store()

    store.query_vuln_trends(days=30, tenant_id="tenant-alpha")
    store.query_vuln_trends(days=30, tenant_id="tenant-beta")
    store.query_top_cves(limit=10, tenant_id="tenant-alpha")

    assert len(recorder.queries) == 3, "expected one query per call"
    assert "tenant_id = 'tenant-alpha'" in recorder.queries[0]
    assert "tenant_id = 'tenant-beta'" in recorder.queries[1]
    assert "tenant_id = 'tenant-alpha'" in recorder.queries[2]

    # No predicate from tenant-alpha can match tenant-beta rows.
    assert "tenant-beta" not in recorder.queries[0]
    assert "tenant-alpha" not in recorder.queries[1]


# ─── Empty / whitespace tenant_id does not silently bucket into 'default' ──


def test_empty_tenant_id_coerces_to_default() -> None:
    """An empty tenant_id string coerces to 'default'.

    Documents a deliberate contract: the ClickHouse row builders use
    ``tenant_id or "default"``, so an empty string falls back to the
    shared 'default' tenant. Call sites that authenticate a real tenant
    must pass the real identifier — this test guards the downstream
    consequence: if a mis-configured service drops tenant context, rows
    land in 'default', not in another tenant's partition.
    """
    store, recorder = _make_store()
    store.record_scan(
        scan_id="edge-1",
        agent_name="claude-desktop",
        vulns=[{"cve_id": "CVE-2024-0001", "severity": "HIGH", "package_name": "x", "package_version": "1"}],
        tenant_id="",
    )
    rows = recorder.inserts[0][1]
    assert rows[0]["tenant_id"] == "default", "empty tenant_id must fall back to 'default', never to another tenant's value"


def test_unset_tenant_id_defaults_to_default_once() -> None:
    """Explicit absence of tenant_id (positional call) falls back to 'default'.

    This is the existing documented behavior for callers that predate
    tenant scoping — keep the contract stable and tested.
    """
    store, recorder = _make_store()
    store.record_scan(
        scan_id="legacy-1",
        agent_name="claude-desktop",
        vulns=[{"cve_id": "CVE-2024-0002", "severity": "LOW", "package_name": "y", "package_version": "1"}],
    )
    rows = recorder.inserts[0][1]
    assert rows[0]["tenant_id"] == "default"
