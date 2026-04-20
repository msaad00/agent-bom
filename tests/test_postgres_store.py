"""Tests for PostgreSQL storage backends.

Uses a mock psycopg_pool to avoid needing a real PostgreSQL instance.
"""

import json
import sys
import types

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
        self.executed: list[tuple[str, object]] = []

    def execute(self, sql, params=None):
        cursor = MockCursor()
        sql_lower = sql.strip().lower()
        self.executed.append((sql, params))

        if (
            sql_lower.startswith("create table")
            or sql_lower.startswith("create index")
            or sql_lower.startswith("create or replace function")
            or sql_lower.startswith("alter table")
            or sql_lower.startswith("do $$")
        ):
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
                elif "api_keys" in sql:
                    table = "api_keys"
                elif "exceptions" in sql:
                    table = "exceptions"
                elif "gateway_policies" in sql:
                    table = "gateway_policies"
                elif "policy_audit_log" in sql:
                    table = "policy_audit_log"
                elif "audit_log" in sql:
                    table = "audit_log"
                elif "trend_history" in sql:
                    table = "trend_history"
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
            elif (
                "from api_keys" in sql_lower
                and "key_id, key_hash, key_salt, key_prefix" in sql_lower
                and "name, role, team_id, scopes, created_at, expires_at" in sql_lower
            ):
                rows = list(self._store.get("api_keys", {}).values())
                if params:
                    if "key_prefix = %s" in sql_lower:
                        rows = [r for r in rows if r[3] == params[0]]
                    elif "key_id = %s" in sql_lower:
                        rows = [r for r in rows if r[0] == params[0]]
                    elif "team_id = %s" in sql_lower:
                        rows = [r for r in rows if r[6] == params[0]]
                cursor.rows = [(r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9]) for r in rows]
            elif (
                "from exceptions" in sql_lower
                and "exception_id, vuln_id, package_name" in sql_lower
                and "server_name, reason, requested_by, approved_by" in sql_lower
            ):
                rows = list(self._store.get("exceptions", {}).values())
                if params:
                    if "exception_id = %s" in sql_lower:
                        rows = [r for r in rows if r[0] == params[0]]
                    elif "team_id = %s" in sql_lower:
                        rows = [r for r in rows if r[12] == params[0]]
                        if len(params) > 1:
                            rows = [r for r in rows if r[7] == params[1]]
                cursor.rows = [tuple(r[:13]) for r in rows]
            elif "from gateway_policies" in sql_lower:
                rows = list(self._store.get("gateway_policies", {}).values())
                if "where policy_id" in sql_lower and params:
                    rows = [r for r in rows if r[0] == params[0]]
                    if len(params) > 1:
                        rows = [r for r in rows if r[1] == params[1]]
                elif "where team_id" in sql_lower and params:
                    rows = [r for r in rows if r[1] == params[0]]
                cursor.rows = [(r[-1],) for r in rows]
            elif "from policy_audit_log" in sql_lower:
                rows = list(self._store.get("policy_audit_log", {}).values())
                if "where team_id" in sql_lower and params:
                    rows = [r for r in rows if r[1] == params[0]]
                cursor.rows = [(r[-1],) for r in rows]
            elif (
                "from audit_log" in sql_lower
                and "entry_id, timestamp, action, actor, resource, details, prev_signature, hmac_signature" in sql_lower
            ):
                rows = list(self._store.get("audit_log", {}).values())
                if params:
                    if "action = %s" in sql_lower:
                        rows = [r for r in rows if r[2] == params[0]]
                    elif "resource like %s" in sql_lower:
                        prefix = str(params[0]).rstrip("%")
                        rows = [r for r in rows if str(r[4]).startswith(prefix)]
                cursor.rows = [(r[0], r[1], r[2], r[3], r[4], r[6], r[7], r[8]) for r in rows]
            elif "from trend_history" in sql_lower:
                rows = list(self._store.get("trend_history", {}).values())
                cursor.rows = [(r[0], r[2], r[3], r[4], r[5], r[6], r[7], r[8]) for r in rows]
            elif "from scan_jobs" in sql_lower and "job_id, team_id, status, created_at, completed_at" in sql_lower:
                rows = list(self._store.get("scan_jobs", {}).values())
                cursor.rows = [(r[0], r[1], r[2], r[3], r[4]) for r in rows]
            elif "from fleet_agents" in sql_lower and "agent_id, name, lifecycle_state, trust_score" in sql_lower:
                rows = list(self._store.get("fleet_agents", {}).values())
                cursor.rows = [(r[0], r[1], r[2], r[3]) for r in rows]
            elif params:
                for table_data in self._store.values():
                    for pk, row in table_data.items():
                        if pk == params[0]:
                            if "osv_cache" in sql and "vulns_json" in sql:
                                # Cache query returns (vulns_json, cached_at)
                                cursor.rows = [(row[1], row[2])]
                            elif "from gateway_policies" in sql:
                                cursor.rows = [(row[-1],)]
                            elif "from policy_audit_log" in sql:
                                cursor.rows = [(row[-1],)]
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
        tenant_id="tenant-alpha",
        status=JobStatus.PENDING,
        created_at="2026-01-01T00:00:00Z",
        request=ScanRequest(),
    )
    store.put(job)

    # Mock get by storing data properly
    mock_pool._conn._store.setdefault("scan_jobs", {})["j-1"] = (
        "j-1",
        "tenant-alpha",
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


def test_job_store_list_summary_includes_tenant(mock_pool):
    from agent_bom.api.postgres_store import PostgresJobStore

    store = PostgresJobStore(pool=mock_pool)
    mock_pool._conn._store.setdefault("scan_jobs", {})["j-1"] = (
        "j-1",
        "tenant-alpha",
        "done",
        "2026-01-01T00:00:00Z",
        None,
        "{}",
    )
    result = store.list_summary()
    assert result[0]["tenant_id"] == "tenant-alpha"


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


# ─── PostgresKeyStore ────────────────────────────────────────────────────────


def test_key_store_add_get_list_verify_remove(mock_pool):
    from agent_bom.api.auth import Role, create_api_key
    from agent_bom.api.postgres_store import PostgresKeyStore

    store = PostgresKeyStore(pool=mock_pool)
    raw_key, api_key = create_api_key("alpha-admin", Role.ADMIN, tenant_id="tenant-alpha")
    store.add(api_key)

    mock_pool._conn._store.setdefault("api_keys", {})[api_key.key_id] = (
        api_key.key_id,
        api_key.key_hash,
        api_key.key_salt,
        api_key.key_prefix,
        api_key.name,
        api_key.role.value,
        api_key.tenant_id,
        json.dumps(api_key.scopes),
        api_key.created_at,
        api_key.expires_at,
    )

    loaded = store.get(api_key.key_id)
    assert loaded is not None
    assert loaded.tenant_id == "tenant-alpha"

    listed = store.list_keys("tenant-alpha")
    assert len(listed) == 1
    assert listed[0].key_id == api_key.key_id

    verified = store.verify(raw_key)
    assert verified is not None
    assert verified.key_id == api_key.key_id

    assert store.remove(api_key.key_id) is True


# ─── PostgresExceptionStore ──────────────────────────────────────────────────


def test_exception_store_put_get_list_delete(mock_pool):
    from agent_bom.api.exception_store import ExceptionStatus, VulnException
    from agent_bom.api.postgres_store import PostgresExceptionStore

    store = PostgresExceptionStore(pool=mock_pool)
    exc = VulnException(
        exception_id="exc-1",
        vuln_id="CVE-1",
        package_name="requests",
        status=ExceptionStatus.ACTIVE,
        tenant_id="tenant-alpha",
    )
    store.put(exc)

    mock_pool._conn._store.setdefault("exceptions", {})[exc.exception_id] = (
        exc.exception_id,
        exc.vuln_id,
        exc.package_name,
        exc.server_name,
        exc.reason,
        exc.requested_by,
        exc.approved_by,
        exc.status.value,
        exc.created_at,
        exc.expires_at,
        exc.approved_at,
        exc.revoked_at,
        exc.tenant_id,
    )

    loaded = store.get(exc.exception_id)
    assert loaded is not None
    assert loaded.tenant_id == "tenant-alpha"

    listed = store.list_all(tenant_id="tenant-alpha")
    assert len(listed) == 1
    assert listed[0].exception_id == exc.exception_id

    match = store.find_matching("CVE-1", "requests", tenant_id="tenant-alpha")
    assert match is not None
    assert match.exception_id == exc.exception_id

    assert store.delete(exc.exception_id) is True


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
        "default",
        policy.model_dump_json(),
    )

    retrieved = store.get_policy("p-1")
    assert retrieved is not None
    assert retrieved.policy_id == "p-1"


def test_policy_store_delete(mock_pool):
    from agent_bom.api.postgres_store import PostgresPolicyStore

    store = PostgresPolicyStore(pool=mock_pool)
    mock_pool._conn._store.setdefault("gateway_policies", {})["p-1"] = ("p-1", "default", "{}")
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


def test_policy_store_tenant_filters(mock_pool):
    from agent_bom.api.policy_store import GatewayPolicy, PolicyAuditEntry
    from agent_bom.api.postgres_store import PostgresPolicyStore

    store = PostgresPolicyStore(pool=mock_pool)
    policy = GatewayPolicy(policy_id="p-1", name="tenant-a-policy", rules=[], tenant_id="tenant-a")
    store.put_policy(policy)
    mock_pool._conn._store.setdefault("gateway_policies", {})["p-1"] = ("p-1", "tenant-a", policy.model_dump_json())
    assert store.get_policy("p-1", tenant_id="tenant-a") is not None
    assert store.get_policy("p-1", tenant_id="tenant-b") is None

    entry = PolicyAuditEntry(
        entry_id="e-1",
        policy_id="p-1",
        policy_name="tenant-a-policy",
        rule_id="r1",
        agent_name="agent-a",
        tool_name="read_file",
        action_taken="allowed",
        reason="ok",
        tenant_id="tenant-a",
    )
    store.put_audit_entry(entry)
    mock_pool._conn._store.setdefault("policy_audit_log", {})["e-1"] = ("2026-01-01T00:00:00Z", "tenant-a", entry.model_dump_json())
    assert store.list_audit_entries(tenant_id="tenant-a")


def test_postgres_audit_log_roundtrip(mock_pool):
    from agent_bom.api.audit_log import AuditEntry
    from agent_bom.api.postgres_store import PostgresAuditLog

    store = PostgresAuditLog(pool=mock_pool)
    entry = AuditEntry(action="scan", actor="admin", resource="job/1", details={"packages": 42})
    store.append(entry)

    mock_pool._conn._store.setdefault("audit_log", {})[entry.entry_id] = (
        entry.entry_id,
        entry.timestamp,
        entry.action,
        entry.actor,
        entry.resource,
        "default",
        json.dumps(entry.details),
        entry.prev_signature,
        entry.hmac_signature,
    )

    entries = store.list_entries()
    assert len(entries) == 1
    assert entries[0].details == {"packages": 42}
    verified, tampered = store.verify_integrity()
    assert verified == 1
    assert tampered == 0


def test_postgres_trend_store_roundtrip(mock_pool):
    from agent_bom.api.postgres_store import PostgresTrendStore
    from agent_bom.baseline import TrendPoint

    store = PostgresTrendStore(pool=mock_pool)
    point = TrendPoint(
        timestamp="2026-01-01T00:00:00Z",
        total_vulns=10,
        critical=1,
        high=2,
        medium=3,
        low=4,
        posture_score=82.5,
        posture_grade="B",
    )
    store.record(point)
    mock_pool._conn._store.setdefault("trend_history", {})["2026-01-01T00:00:00Z"] = (
        point.timestamp,
        "default",
        point.total_vulns,
        point.critical,
        point.high,
        point.medium,
        point.low,
        point.posture_score,
        point.posture_grade,
    )
    history = store.get_history()
    assert len(history) == 1
    assert history[0].posture_grade == "B"


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


def test_get_pool_uses_tuned_pool_sizes_and_connect_timeout(monkeypatch):
    """Pool creation should honor operator-controlled sizing and connect timeout envs."""
    from agent_bom.api import postgres_store

    captured: dict[str, object] = {}

    class CapturePool:
        def __init__(self, url, min_size, max_size, kwargs=None):
            captured["url"] = url
            captured["min_size"] = min_size
            captured["max_size"] = max_size
            captured["kwargs"] = kwargs or {}

    reset = postgres_store.reset_pool
    reset()
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://localhost/test")
    monkeypatch.setenv("AGENT_BOM_POSTGRES_POOL_MIN_SIZE", "7")
    monkeypatch.setenv("AGENT_BOM_POSTGRES_POOL_MAX_SIZE", "21")
    monkeypatch.setenv("AGENT_BOM_POSTGRES_CONNECT_TIMEOUT_SECONDS", "9")
    monkeypatch.setattr(
        postgres_store,
        "POSTGRES_POOL_MIN_SIZE",
        7,
        raising=False,
    )
    monkeypatch.setattr(
        postgres_store,
        "POSTGRES_POOL_MAX_SIZE",
        21,
        raising=False,
    )
    monkeypatch.setattr(
        postgres_store,
        "POSTGRES_CONNECT_TIMEOUT_SECONDS",
        9,
        raising=False,
    )
    monkeypatch.setitem(sys.modules, "psycopg_pool", types.SimpleNamespace(ConnectionPool=CapturePool))

    try:
        postgres_store._get_pool()
        assert captured == {
            "url": "postgresql://localhost/test",
            "min_size": 7,
            "max_size": 21,
            "kwargs": {"connect_timeout": 9},
        }
    finally:
        reset()


def test_apply_tenant_session_sets_statement_timeout(monkeypatch):
    """Tenant session setup should apply the configured statement timeout."""
    from agent_bom.api import postgres_store

    conn = MockConnection()
    monkeypatch.setattr(postgres_store, "POSTGRES_STATEMENT_TIMEOUT_MS", 12_000, raising=False)

    postgres_store._apply_tenant_session(conn)

    assert any("app.tenant_id" in sql for sql, _ in conn.executed)
    assert any("statement_timeout" in sql and params == ("12000",) for sql, params in conn.executed)


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


def test_tenant_context_is_applied_to_postgres_session(mock_pool):
    from agent_bom.api.postgres_store import PostgresFleetStore, reset_current_tenant, set_current_tenant

    token = set_current_tenant("tenant-zeta")
    try:
        store = PostgresFleetStore(pool=mock_pool)
        store.list_by_tenant("tenant-zeta")
    finally:
        reset_current_tenant(token)

    assert any("set_config('app.tenant_id'" in sql for sql, _ in mock_pool._conn.executed)
    assert any(params == ("tenant-zeta",) for sql, params in mock_pool._conn.executed if "set_config('app.tenant_id'" in sql)


def test_scheduler_bypass_sets_rls_flag(mock_pool):
    from agent_bom.api.postgres_store import PostgresScheduleStore, bypass_tenant_rls

    store = PostgresScheduleStore(pool=mock_pool)
    with bypass_tenant_rls():
        store.list_due("2025-06-15T12:00:00+00:00")

    assert any("set_config('app.bypass_rls'" in sql for sql, _ in mock_pool._conn.executed)
    assert any(params == ("1",) for sql, params in mock_pool._conn.executed if "set_config('app.bypass_rls'" in sql)


# ─── PostgresScanCache ───────────────────────────────────────────────────────


def test_scan_cache_init(mock_pool):
    from agent_bom.api.postgres_store import PostgresScanCache

    cache = PostgresScanCache(pool=mock_pool)
    assert cache is not None
    assert any("idx_cache_age" in sql for sql, _ in mock_pool._conn.executed)


def test_graph_store_init_adds_query_indexes(mock_pool):
    from agent_bom.api.postgres_store import PostgresGraphStore

    store = PostgresGraphStore(pool=mock_pool)
    assert store is not None
    assert any("idx_pg_graph_nodes_scan_order" in sql for sql, _ in mock_pool._conn.executed)
    assert any("idx_pg_graph_edges_scan_source" in sql for sql, _ in mock_pool._conn.executed)
    assert any("idx_pg_graph_edges_scan_target" in sql for sql, _ in mock_pool._conn.executed)
    assert any("idx_pg_attack_paths_scan_risk" in sql for sql, _ in mock_pool._conn.executed)


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


def test_server_lifespan_postgres_enterprise_stores():
    """Postgres-backed enterprise stores are referenced in server lifespan."""
    import inspect

    from agent_bom.api import server

    source = inspect.getsource(server._lifespan)
    assert "PostgresKeyStore" in source
    assert "PostgresExceptionStore" in source
    assert "PostgresAuditLog" in source
    assert "PostgresTrendStore" in source
