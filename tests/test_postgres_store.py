"""Tests for PostgreSQL storage backends.

Uses a mock psycopg_pool to avoid needing a real PostgreSQL instance.
"""

import json

import pytest

# ─── Mock psycopg infrastructure ─────────────────────────────────────────────


class MockCursor:
    """Mock database cursor."""

    def __init__(self, rows=None):
        self.rows = rows or []
        self.rowcount = 0
        self._executed = []

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows


class MockConnection:
    """Mock database connection with execute tracking."""

    def __init__(self):
        self._store: dict[str, dict] = {}  # table -> {pk: data}
        self._cursors: list[MockCursor] = []

    def execute(self, sql, params=None):
        cursor = MockCursor()
        sql_lower = sql.strip().lower()

        if sql_lower.startswith("create table") or sql_lower.startswith("create index"):
            pass  # DDL — no-op
        elif sql_lower.startswith("insert"):
            cursor.rowcount = 1
            # Track inserted data by first param (primary key)
            if params:
                table = "default"
                if "scan_jobs" in sql:
                    table = "scan_jobs"
                elif "fleet_agents" in sql:
                    table = "fleet_agents"
                elif "gateway_policies" in sql:
                    table = "gateway_policies"
                elif "policy_audit_log" in sql:
                    table = "audit"
                elif "scan_schedules" in sql:
                    table = "scan_schedules"
                elif "osv_cache" in sql:
                    table = "osv_cache"
                if table not in self._store:
                    self._store[table] = {}
                self._store[table][params[0]] = params
        elif sql_lower.startswith("select"):
            if "group by" in sql_lower:
                # Aggregate query — return empty list
                cursor.rows = []
            elif "count(*)" in sql_lower:
                # COUNT query
                total = sum(len(td) for td in self._store.values())
                cursor.rows = [(total,)]
            elif params:
                for table_data in self._store.values():
                    for pk, row in table_data.items():
                        if pk == params[0]:
                            if "osv_cache" in sql and "vulns_json" in sql:
                                # Cache query returns (vulns_json, cached_at)
                                cursor.rows = [(row[1], row[2])]
                            else:
                                # Return the last element (data column)
                                cursor.rows = [(row[-1],)]
                            break
            else:
                # List all
                all_rows = []
                for table_data in self._store.values():
                    for row in table_data.values():
                        all_rows.append(row)
                cursor.rows = [(r[-1],) for r in all_rows] if all_rows else []
        elif sql_lower.startswith("delete"):
            if params:
                for table_data in self._store.values():
                    if params[0] in table_data:
                        del table_data[params[0]]
                        cursor.rowcount = 1
                        break
        elif sql_lower.startswith("update"):
            cursor.rowcount = 1

        self._cursors.append(cursor)
        return cursor

    def commit(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class MockPool:
    """Mock psycopg_pool.ConnectionPool."""

    def __init__(self, *args, **kwargs):
        self._conn = MockConnection()

    def connection(self):
        return self._conn


@pytest.fixture()
def mock_pool():
    """Return a fresh mock pool."""
    return MockPool()


# ─── PostgresJobStore ─────────────────────────────────────────────────────────


def test_job_store_init(mock_pool):
    from agent_bom.api.postgres_store import PostgresJobStore

    store = PostgresJobStore(pool=mock_pool)
    assert store is not None


def test_job_store_put_get(mock_pool):
    from agent_bom.api.postgres_store import PostgresJobStore
    from agent_bom.api.server import JobStatus, ScanJob, ScanRequest

    store = PostgresJobStore(pool=mock_pool)
    job = ScanJob(
        job_id="j-1",
        status=JobStatus.PENDING,
        created_at="2026-01-01T00:00:00Z",
        request=ScanRequest(),
    )
    store.put(job)

    # Mock get by storing data properly
    mock_pool._conn._store.setdefault("scan_jobs", {})["j-1"] = (
        "j-1",
        "pending",
        "2026-01-01T00:00:00Z",
        None,
        job.model_dump_json(),
    )

    retrieved = store.get("j-1")
    assert retrieved is not None
    assert retrieved.job_id == "j-1"


def test_job_store_get_nonexistent(mock_pool):
    from agent_bom.api.postgres_store import PostgresJobStore

    store = PostgresJobStore(pool=mock_pool)
    assert store.get("nonexistent") is None


def test_job_store_delete(mock_pool):
    from agent_bom.api.postgres_store import PostgresJobStore

    store = PostgresJobStore(pool=mock_pool)
    mock_pool._conn._store.setdefault("scan_jobs", {})["j-1"] = ("j-1", "done", "", None, "{}")
    assert store.delete("j-1") is True


def test_job_store_delete_nonexistent(mock_pool):
    from agent_bom.api.postgres_store import PostgresJobStore

    store = PostgresJobStore(pool=mock_pool)
    assert store.delete("nonexistent") is False


def test_job_store_list_summary(mock_pool):
    from agent_bom.api.postgres_store import PostgresJobStore

    store = PostgresJobStore(pool=mock_pool)
    # list_summary returns dicts from column-based query
    result = store.list_summary()
    assert isinstance(result, list)


def test_job_store_cleanup(mock_pool):
    from agent_bom.api.postgres_store import PostgresJobStore

    store = PostgresJobStore(pool=mock_pool)
    count = store.cleanup_expired()
    assert isinstance(count, int)


# ─── PostgresFleetStore ───────────────────────────────────────────────────────


def test_fleet_store_init(mock_pool):
    from agent_bom.api.postgres_store import PostgresFleetStore

    store = PostgresFleetStore(pool=mock_pool)
    assert store is not None


def test_fleet_store_put_get(mock_pool):
    from agent_bom.api.fleet_store import FleetAgent, FleetLifecycleState
    from agent_bom.api.postgres_store import PostgresFleetStore

    store = PostgresFleetStore(pool=mock_pool)
    agent = FleetAgent(
        agent_id="a-1",
        name="test-agent",
        agent_type="claude_desktop",
        lifecycle_state=FleetLifecycleState.DISCOVERED,
        updated_at="2026-01-01T00:00:00Z",
    )
    store.put(agent)

    # Set up mock data for retrieval
    mock_pool._conn._store.setdefault("fleet_agents", {})["a-1"] = (
        "a-1",
        "test-agent",
        "discovered",
        0.0,
        "default",
        "2026-01-01T00:00:00Z",
        agent.model_dump_json(),
    )

    retrieved = store.get("a-1")
    assert retrieved is not None
    assert retrieved.agent_id == "a-1"
    assert retrieved.name == "test-agent"


def test_fleet_store_get_nonexistent(mock_pool):
    from agent_bom.api.postgres_store import PostgresFleetStore

    store = PostgresFleetStore(pool=mock_pool)
    assert store.get("nonexistent") is None


def test_fleet_store_get_by_name(mock_pool):
    from agent_bom.api.fleet_store import FleetAgent, FleetLifecycleState
    from agent_bom.api.postgres_store import PostgresFleetStore

    store = PostgresFleetStore(pool=mock_pool)
    agent = FleetAgent(
        agent_id="a-1",
        name="test-agent",
        agent_type="cursor",
        lifecycle_state=FleetLifecycleState.APPROVED,
        updated_at="2026-01-01T00:00:00Z",
    )

    mock_pool._conn._store.setdefault("fleet_agents", {})["test-agent"] = (
        "test-agent",
        "test-agent",
        "approved",
        0.0,
        "default",
        "2026-01-01T00:00:00Z",
        agent.model_dump_json(),
    )

    result = store.get_by_name("test-agent")
    assert result is not None


def test_fleet_store_delete(mock_pool):
    from agent_bom.api.postgres_store import PostgresFleetStore

    store = PostgresFleetStore(pool=mock_pool)
    mock_pool._conn._store.setdefault("fleet_agents", {})["a-1"] = ("a-1",)
    assert store.delete("a-1") is True


def test_fleet_store_list_all(mock_pool):
    from agent_bom.api.postgres_store import PostgresFleetStore

    store = PostgresFleetStore(pool=mock_pool)
    result = store.list_all()
    assert isinstance(result, list)


def test_fleet_store_list_summary(mock_pool):
    from agent_bom.api.postgres_store import PostgresFleetStore

    store = PostgresFleetStore(pool=mock_pool)
    result = store.list_summary()
    assert isinstance(result, list)


def test_fleet_store_list_by_tenant(mock_pool):
    from agent_bom.api.postgres_store import PostgresFleetStore

    store = PostgresFleetStore(pool=mock_pool)
    result = store.list_by_tenant("default")
    assert isinstance(result, list)


def test_fleet_store_list_tenants(mock_pool):
    from agent_bom.api.postgres_store import PostgresFleetStore

    store = PostgresFleetStore(pool=mock_pool)
    result = store.list_tenants()
    assert isinstance(result, list)


def test_fleet_store_update_state(mock_pool):
    from agent_bom.api.fleet_store import FleetLifecycleState
    from agent_bom.api.postgres_store import PostgresFleetStore

    store = PostgresFleetStore(pool=mock_pool)
    # Mock existing agent
    mock_pool._conn._store.setdefault("fleet_agents", {})["a-1"] = (
        "a-1",
        "test",
        "discovered",
        0.0,
        "default",
        "2026-01-01",
        json.dumps({"lifecycle_state": "discovered"}),
    )
    result = store.update_state("a-1", FleetLifecycleState.APPROVED)
    assert result is True


def test_fleet_store_batch_put(mock_pool):
    from agent_bom.api.fleet_store import FleetAgent, FleetLifecycleState
    from agent_bom.api.postgres_store import PostgresFleetStore

    store = PostgresFleetStore(pool=mock_pool)
    agents = [
        FleetAgent(
            agent_id=f"a-{i}",
            name=f"agent-{i}",
            agent_type="cursor",
            lifecycle_state=FleetLifecycleState.DISCOVERED,
            updated_at="2026-01-01T00:00:00Z",
        )
        for i in range(3)
    ]
    count = store.batch_put(agents)
    assert count == 3


# ─── PostgresPolicyStore ──────────────────────────────────────────────────────


def test_policy_store_init(mock_pool):
    from agent_bom.api.postgres_store import PostgresPolicyStore

    store = PostgresPolicyStore(pool=mock_pool)
    assert store is not None


def test_policy_store_put_get(mock_pool):
    from agent_bom.api.policy_store import GatewayPolicy
    from agent_bom.api.postgres_store import PostgresPolicyStore

    store = PostgresPolicyStore(pool=mock_pool)
    policy = GatewayPolicy(
        policy_id="p-1",
        name="test-policy",
        description="Test",
        rules=[],
    )
    store.put_policy(policy)

    mock_pool._conn._store.setdefault("gateway_policies", {})["p-1"] = (
        "p-1",
        policy.model_dump_json(),
    )

    retrieved = store.get_policy("p-1")
    assert retrieved is not None
    assert retrieved.policy_id == "p-1"


def test_policy_store_delete(mock_pool):
    from agent_bom.api.postgres_store import PostgresPolicyStore

    store = PostgresPolicyStore(pool=mock_pool)
    mock_pool._conn._store.setdefault("gateway_policies", {})["p-1"] = ("p-1", "{}")
    assert store.delete_policy("p-1") is True


def test_policy_store_list_policies(mock_pool):
    from agent_bom.api.postgres_store import PostgresPolicyStore

    store = PostgresPolicyStore(pool=mock_pool)
    result = store.list_policies()
    assert isinstance(result, list)


def test_policy_store_put_audit_entry(mock_pool):
    from agent_bom.api.postgres_store import PostgresPolicyStore

    store = PostgresPolicyStore(pool=mock_pool)
    entry = {"tool_name": "read_file", "action": "allowed", "ts": "2026-01-01T00:00:00Z"}
    store.put_audit_entry(entry)
    # Should not raise


def test_policy_store_list_audit_entries(mock_pool):
    from agent_bom.api.postgres_store import PostgresPolicyStore

    store = PostgresPolicyStore(pool=mock_pool)
    result = store.list_audit_entries()
    assert isinstance(result, list)


# ─── Pool / Config ────────────────────────────────────────────────────────────


def test_reset_pool():
    from agent_bom.api.postgres_store import reset_pool

    reset_pool()
    # Should not raise


def test_get_pool_missing_env(monkeypatch):
    """Missing AGENT_BOM_POSTGRES_URL raises ValueError (or ImportError if psycopg not installed)."""
    from agent_bom.api.postgres_store import _get_pool, reset_pool

    reset_pool()
    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)

    with pytest.raises((ValueError, ImportError)):
        _get_pool()

    reset_pool()


def test_get_pool_missing_psycopg(monkeypatch):
    """Missing psycopg raises ImportError."""
    import sys

    from agent_bom.api.postgres_store import reset_pool

    reset_pool()
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://localhost/test")

    # Remove psycopg_pool from sys.modules to simulate missing
    saved = sys.modules.get("psycopg_pool")
    sys.modules["psycopg_pool"] = None  # type: ignore[assignment]

    try:
        from agent_bom.api import postgres_store

        # Force reimport
        reset_pool()
        with pytest.raises(ImportError, match="psycopg"):
            postgres_store._get_pool()
    finally:
        if saved is not None:
            sys.modules["psycopg_pool"] = saved
        else:
            sys.modules.pop("psycopg_pool", None)
        reset_pool()


# ─── Server lifespan integration ─────────────────────────────────────────────


def test_server_lifespan_postgres_env_var():
    """AGENT_BOM_POSTGRES_URL env var is checked in server lifespan."""
    # Just verify the env var key is referenced in server.py
    import inspect

    from agent_bom.api import server

    source = inspect.getsource(server._lifespan)
    assert "AGENT_BOM_POSTGRES_URL" in source


# ─── PostgresScheduleStore ───────────────────────────────────────────────────


def test_schedule_store_init(mock_pool):
    from agent_bom.api.postgres_store import PostgresScheduleStore

    store = PostgresScheduleStore(pool=mock_pool)
    assert store is not None


def test_schedule_store_put_get(mock_pool):
    from agent_bom.api.postgres_store import PostgresScheduleStore
    from agent_bom.api.schedule_store import ScanSchedule

    store = PostgresScheduleStore(pool=mock_pool)
    schedule = ScanSchedule(
        schedule_id="sched-1",
        name="nightly-scan",
        cron_expression="0 */6 * * *",
        scan_config={"images": ["nginx:latest"]},
        enabled=True,
        next_run="2025-01-01T00:00:00+00:00",
        created_at="2025-01-01T00:00:00+00:00",
        updated_at="2025-01-01T00:00:00+00:00",
    )
    store.put(schedule)

    mock_pool._conn._store.setdefault("scan_schedules", {})["sched-1"] = (
        "sched-1",
        1,
        "2025-01-01T00:00:00+00:00",
        schedule.model_dump_json(),
    )

    retrieved = store.get("sched-1")
    assert retrieved is not None
    assert retrieved.schedule_id == "sched-1"
    assert retrieved.name == "nightly-scan"


def test_schedule_store_get_nonexistent(mock_pool):
    from agent_bom.api.postgres_store import PostgresScheduleStore

    store = PostgresScheduleStore(pool=mock_pool)
    assert store.get("nonexistent") is None


def test_schedule_store_delete(mock_pool):
    from agent_bom.api.postgres_store import PostgresScheduleStore

    store = PostgresScheduleStore(pool=mock_pool)
    mock_pool._conn._store.setdefault("scan_schedules", {})["sched-1"] = ("sched-1", 1, None, "{}")
    assert store.delete("sched-1") is True


def test_schedule_store_delete_nonexistent(mock_pool):
    from agent_bom.api.postgres_store import PostgresScheduleStore

    store = PostgresScheduleStore(pool=mock_pool)
    assert store.delete("nonexistent") is False


def test_schedule_store_list_all(mock_pool):
    from agent_bom.api.postgres_store import PostgresScheduleStore

    store = PostgresScheduleStore(pool=mock_pool)
    result = store.list_all()
    assert isinstance(result, list)


def test_schedule_store_list_due(mock_pool):
    from agent_bom.api.postgres_store import PostgresScheduleStore

    store = PostgresScheduleStore(pool=mock_pool)
    result = store.list_due("2025-06-15T12:00:00+00:00")
    assert isinstance(result, list)


# ─── PostgresScanCache ───────────────────────────────────────────────────────


def test_scan_cache_init(mock_pool):
    from agent_bom.api.postgres_store import PostgresScanCache

    cache = PostgresScanCache(pool=mock_pool)
    assert cache is not None


def test_scan_cache_put_get(mock_pool):
    from agent_bom.api.postgres_store import PostgresScanCache

    cache = PostgresScanCache(pool=mock_pool)
    vulns = [{"id": "CVE-2024-1234", "severity": "HIGH"}]
    cache.put("pypi", "requests", "2.31.0", vulns)

    # Set up mock data for retrieval — (key, vulns_json, cached_at)
    import time

    key = "pypi:requests@2.31.0"
    mock_pool._conn._store.setdefault("osv_cache", {})[key] = (
        key,
        json.dumps(vulns),
        time.time(),
    )

    result = cache.get("pypi", "requests", "2.31.0")
    assert result is not None
    assert len(result) == 1
    assert result[0]["id"] == "CVE-2024-1234"


def test_scan_cache_get_miss(mock_pool):
    from agent_bom.api.postgres_store import PostgresScanCache

    cache = PostgresScanCache(pool=mock_pool)
    assert cache.get("pypi", "nonexistent", "0.0.0") is None


def test_scan_cache_get_expired(mock_pool):
    from agent_bom.api.postgres_store import PostgresScanCache

    cache = PostgresScanCache(pool=mock_pool, ttl_seconds=1)

    key = "pypi:old@1.0.0"
    mock_pool._conn._store.setdefault("osv_cache", {})[key] = (
        key,
        json.dumps([]),
        0.0,  # epoch — definitely expired
    )

    result = cache.get("pypi", "old", "1.0.0")
    assert result is None


def test_scan_cache_cleanup(mock_pool):
    from agent_bom.api.postgres_store import PostgresScanCache

    cache = PostgresScanCache(pool=mock_pool)
    count = cache.cleanup_expired()
    assert isinstance(count, int)


def test_scan_cache_clear(mock_pool):
    from agent_bom.api.postgres_store import PostgresScanCache

    cache = PostgresScanCache(pool=mock_pool)
    cache.clear()  # should not raise


def test_scan_cache_size(mock_pool):
    from agent_bom.api.postgres_store import PostgresScanCache

    cache = PostgresScanCache(pool=mock_pool)
    assert isinstance(cache.size, int)


def test_scan_cache_key():
    from agent_bom.api.postgres_store import PostgresScanCache

    assert PostgresScanCache._key("pypi", "requests", "2.31.0") == "pypi:requests@2.31.0"


# ─── Lifespan schedule store Postgres path ───────────────────────────────────


def test_server_lifespan_postgres_schedule_store():
    """PostgresScheduleStore is referenced in server lifespan."""
    import inspect

    from agent_bom.api import server

    source = inspect.getsource(server._lifespan)
    assert "PostgresScheduleStore" in source
