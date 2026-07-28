"""Durable canonical managed-identity to MCP profile bindings (#4152)."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from agent_bom.api.agent_identity_store import (
    InMemoryAgentIdentityStore,
    issue_identity,
    set_agent_identity_store,
)
from agent_bom.api.mcp_config_store import (
    InMemoryMcpConfigStore,
    McpConfigConflictError,
    SQLiteMcpConfigStore,
    _bounded_identity_history_limit,
    create_assignment,
    revoke_assignment,
    set_mcp_config_store,
)


class _FakeCursor:
    def __init__(self, row=None) -> None:
        self._row = row

    def fetchone(self):
        return self._row


class _FakePostgresConnection:
    def __init__(self) -> None:
        self.statements: list[str] = []
        self.commits = 0

    def execute(self, sql, params=None):
        self.statements.append(str(sql))
        return _FakeCursor()

    def commit(self) -> None:
        self.commits += 1


class _FakePostgresPool:
    def __init__(self, connection: _FakePostgresConnection) -> None:
        self._connection = connection

    @contextmanager
    def connection(self):
        yield self._connection


@pytest.fixture(params=["memory", "sqlite"])
def profile_store(request: pytest.FixtureRequest, tmp_path: Path):
    if request.param == "sqlite":
        return SQLiteMcpConfigStore(str(tmp_path / "profiles.db"))
    return InMemoryMcpConfigStore()


def test_exact_active_binding_is_tenant_scoped_unique_and_not_list_limited(profile_store) -> None:
    bound = create_assignment(
        profile_store,
        tenant_id="tenant-a",
        name="canonical",
        profile_id="finance",
        connector_ids=["snowflake"],
        identity_id="identity-a",
        issuer="agent-bom",
        environment="prod",
    )
    # A resolver must not depend on the tenant-list presentation limit. Put the
    # canonical row behind more than the API's maximum 1,000 returned rows.
    for index in range(1001):
        create_assignment(
            profile_store,
            tenant_id="tenant-a",
            name=f"distractor-{index}",
            profile_id="developer",
            connector_ids=["filesystem"],
        )
    create_assignment(
        profile_store,
        tenant_id="tenant-b",
        name="foreign",
        profile_id="finance",
        connector_ids=["snowflake"],
        identity_id="identity-a",
        issuer="agent-bom",
        environment="prod",
    )

    resolved = profile_store.get_active_for_identity("tenant-a", "identity-a")
    assert resolved is not None
    assert resolved.config_id == bound.config_id
    assert profile_store.get_active_for_identity("tenant-c", "identity-a") is None

    with pytest.raises(McpConfigConflictError):
        create_assignment(
            profile_store,
            tenant_id="tenant-a",
            name="ambiguous",
            profile_id="finance",
            connector_ids=["snowflake"],
            identity_id="identity-a",
            issuer="agent-bom",
            environment="prod",
        )


def test_revoke_is_atomic_versioned_and_releases_the_identity_binding(profile_store) -> None:
    assignment = create_assignment(
        profile_store,
        tenant_id="tenant-a",
        name="canonical",
        profile_id="developer",
        connector_ids=["filesystem"],
        identity_id="identity-a",
        issuer="agent-bom",
        environment="prod",
    )
    assert assignment.revision == 1

    revoked = revoke_assignment(profile_store, tenant_id="tenant-a", config_id=assignment.config_id)
    assert revoked is not None
    assert revoked.revoked is True
    assert revoked.status == "revoked"
    assert revoked.revision == 2
    # Idempotent retries do not create phantom revisions.
    retried = revoke_assignment(profile_store, tenant_id="tenant-a", config_id=assignment.config_id)
    assert retried is not None
    assert retried.revision == 2
    assert profile_store.get_active_for_identity("tenant-a", "identity-a") is None

    replacement = create_assignment(
        profile_store,
        tenant_id="tenant-a",
        name="replacement",
        profile_id="developer",
        connector_ids=["filesystem"],
        identity_id="identity-a",
        issuer="agent-bom",
        environment="prod",
    )
    assert replacement.revision == 1
    assert profile_store.get_active_for_identity("tenant-a", "identity-a").config_id == replacement.config_id
    bounded_history = profile_store.list_for_identity("tenant-a", "identity-a", limit=1)
    assert [row.config_id for row in bounded_history] == [replacement.config_id]


def test_put_cannot_rebind_a_distribution_assignment_to_an_identity(profile_store) -> None:
    assignment = create_assignment(
        profile_store,
        tenant_id="tenant-a",
        name="distribution-only",
        profile_id="developer",
        connector_ids=["filesystem"],
    )

    with pytest.raises(McpConfigConflictError):
        profile_store.put(
            replace(
                assignment,
                identity_id="identity-a",
                issuer="agent-bom",
                environment="prod",
            )
        )

    assert profile_store.get_active_for_identity("tenant-a", "identity-a") is None
    assert profile_store.get("tenant-a", assignment.config_id).identity_id == ""


def test_put_cannot_move_an_assignment_between_tenants(profile_store) -> None:
    assignment = create_assignment(
        profile_store,
        tenant_id="tenant-a",
        name="canonical",
        profile_id="developer",
        connector_ids=["filesystem"],
        identity_id="identity-a",
        issuer="agent-bom",
        environment="prod",
    )

    with pytest.raises(McpConfigConflictError):
        profile_store.put(replace(assignment, tenant_id="tenant-b"))

    assert profile_store.get("tenant-b", assignment.config_id) is None
    assert profile_store.get_active_for_identity("tenant-a", "identity-a") is not None


def test_put_is_insert_only_and_cannot_roll_back_a_revision(profile_store) -> None:
    assignment = create_assignment(
        profile_store,
        tenant_id="tenant-a",
        name="canonical",
        profile_id="developer",
        connector_ids=["filesystem"],
        identity_id="identity-a",
        issuer="agent-bom",
        environment="prod",
    )
    updated = profile_store.compare_and_swap(
        replace(assignment, name="revision-two"),
        expected_revision=1,
    )
    assert updated.revision == 2

    with pytest.raises(McpConfigConflictError):
        profile_store.put(assignment)

    readback = profile_store.get("tenant-a", assignment.config_id)
    assert readback is not None
    assert readback.revision == 2
    assert readback.name == "revision-two"


def test_memory_store_does_not_expose_mutable_assignment_state() -> None:
    store = InMemoryMcpConfigStore()
    assignment = create_assignment(
        store,
        tenant_id="tenant-a",
        name="canonical",
        profile_id="developer",
        connector_ids=["filesystem"],
        identity_id="identity-a",
        issuer="agent-bom",
        environment="prod",
    )

    assignment.identity_id = "identity-b"
    assignment.connector_ids.append("snowflake")
    readback = store.get("tenant-a", assignment.config_id)
    assert readback is not None
    readback.identity_id = "identity-c"
    readback.connector_ids.append("github")

    resolved = store.get_active_for_identity("tenant-a", "identity-a")
    assert resolved is not None
    assert resolved.identity_id == "identity-a"
    assert resolved.connector_ids == ["filesystem"]
    assert store.get_active_for_identity("tenant-a", "identity-b") is None
    assert store.get_active_for_identity("tenant-a", "identity-c") is None


def test_sqlite_v1_upgrade_overlays_authoritative_profile_columns(tmp_path: Path) -> None:
    db_path = tmp_path / "legacy-profiles.db"
    conn = sqlite3.connect(db_path)
    legacy = {
        "config_id": "legacy-revoked",
        "tenant_id": "tenant-a",
        "name": "legacy",
        "profile_id": "developer",
        "connector_ids": ["filesystem"],
        "connection_ids": [],
        "created_at": "2026-01-01T00:00:00+00:00",
        "created_by": "operator",
        "revoked": True,
    }
    conn.execute(
        "CREATE TABLE mcp_client_configs (config_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, "
        "name TEXT NOT NULL, profile_id TEXT NOT NULL, created_at TEXT NOT NULL, "
        "revoked INTEGER NOT NULL DEFAULT 0, data TEXT NOT NULL)"
    )
    conn.execute(
        "INSERT INTO mcp_client_configs "
        "(config_id, tenant_id, name, profile_id, created_at, revoked, data) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            legacy["config_id"],
            legacy["tenant_id"],
            legacy["name"],
            legacy["profile_id"],
            legacy["created_at"],
            1,
            json.dumps(legacy),
        ),
    )
    conn.commit()
    conn.close()

    store = SQLiteMcpConfigStore(str(db_path))
    upgraded = store.get("tenant-a", "legacy-revoked")
    assert upgraded is not None
    assert upgraded.identity_id == ""
    assert upgraded.status == "revoked"
    assert upgraded.revision == 1
    assert upgraded.updated_at == legacy["created_at"]
    assert store.revoke("tenant-a", "legacy-revoked").status == "revoked"


def test_sqlite_identity_queries_use_partial_indexes(tmp_path: Path) -> None:
    store = SQLiteMcpConfigStore(str(tmp_path / "profile-indexes.db"))
    active_plan = store._conn.execute(
        "EXPLAIN QUERY PLAN SELECT data FROM mcp_client_configs "
        "WHERE tenant_id = ? AND identity_id = ? AND identity_id <> '' "
        "AND revoked = 0 AND status = 'active'",
        ("tenant-a", "identity-a"),
    ).fetchall()
    history_plan = store._conn.execute(
        "EXPLAIN QUERY PLAN SELECT data FROM mcp_client_configs "
        "WHERE tenant_id = ? AND identity_id = ? AND identity_id <> '' "
        "ORDER BY updated_at DESC, config_id DESC LIMIT ?",
        ("tenant-a", "identity-a", 2),
    ).fetchall()

    assert "idx_mcp_client_configs_active_identity" in " ".join(str(row[3]) for row in active_plan)
    assert "idx_mcp_client_configs_identity_history" in " ".join(str(row[3]) for row in history_plan)


def test_identity_history_limit_is_bounded() -> None:
    assert _bounded_identity_history_limit(0) == 1
    assert _bounded_identity_history_limit(2) == 2
    assert _bounded_identity_history_limit(100_000) == 1_000


def test_postgres_development_bootstrap_upgrades_v1_before_identity_indexes(monkeypatch) -> None:
    import agent_bom.api.postgres_mcp_config as postgres_module

    connection = _FakePostgresConnection()
    monkeypatch.setattr(postgres_module, "ensure_postgres_schema_version", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(postgres_module, "_ensure_tenant_rls", lambda *_args, **_kwargs: None)

    postgres_module.PostgresMcpConfigStore(_FakePostgresPool(connection))

    sql = "\n".join(connection.statements)
    assert sql.index("ALTER TABLE mcp_client_configs ADD COLUMN IF NOT EXISTS identity_id") < sql.index(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_mcp_client_configs_active_identity"
    )
    assert "UPDATE mcp_client_configs SET identity_id = COALESCE(identity_id, '')" in sql
    assert "ALTER TABLE mcp_client_configs ALTER COLUMN identity_id SET NOT NULL" in sql
    assert connection.commits == 1


@pytest.fixture()
def bound_client() -> Iterator[tuple[TestClient, InMemoryAgentIdentityStore]]:
    config_store = InMemoryMcpConfigStore()
    identity_store = InMemoryAgentIdentityStore()
    set_mcp_config_store(config_store)
    set_agent_identity_store(identity_store)
    from agent_bom.api.server import app

    try:
        yield TestClient(app), identity_store
    finally:
        set_agent_identity_store(None)
        set_mcp_config_store(None)


def _first_connector_id(client: TestClient) -> str:
    servers = client.get("/v1/registry").json()["servers"]
    assert servers
    return str(servers[0]["id"])


def test_bound_profile_api_uses_tenant_identity_and_compare_and_swap(bound_client) -> None:
    client, identities = bound_client
    identity, _token = issue_identity(
        identities,
        agent_id="agent-a",
        tenant_id="default",
        blueprint_id="developer",
        owner="platform-security",
    )
    connector_id = _first_connector_id(client)
    created = client.post(
        "/v1/mcp-config/assignments",
        json={
            "name": "developer-prod",
            "profile_id": "developer",
            "connector_ids": [connector_id],
            "identity_id": identity.identity_id,
            "issuer": "agent-bom",
            "environment": "prod",
            "allowed_tools": ["read_file"],
            "policy_ids": ["policy-developer"],
        },
    )
    assert created.status_code == 201, created.text
    assignment = created.json()["assignment"]
    assert assignment["identity_id"] == identity.identity_id
    assert assignment["owner"] == "platform-security"
    assert assignment["revision"] == 1
    assert "token_hash" not in created.text

    updated = client.put(
        f"/v1/mcp-config/assignments/{assignment['config_id']}",
        json={
            "expected_revision": 1,
            "name": "developer-prod-v2",
            "profile_id": "developer",
            "connector_ids": [connector_id],
            "environment": "prod",
            "allowed_tools": ["read_file", "list_directory"],
            "policy_ids": ["policy-developer-v2"],
        },
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["assignment"]["revision"] == 2
    assert updated.json()["assignment"]["allowed_tools"] == ["read_file", "list_directory"]

    stale = client.put(
        f"/v1/mcp-config/assignments/{assignment['config_id']}",
        json={
            "expected_revision": 1,
            "name": "stale",
            "profile_id": "finance",
            "connector_ids": [connector_id],
            "environment": "dev",
        },
    )
    assert stale.status_code == 409
    readback = client.get(f"/v1/mcp-config/assignments/{assignment['config_id']}").json()["assignment"]
    assert readback["revision"] == 2
    assert readback["name"] == "developer-prod-v2"
    assert readback["profile_id"] == "developer"
    assert readback["environment"] == "prod"


def test_bound_profile_api_hides_foreign_identity(bound_client) -> None:
    client, identities = bound_client
    foreign, _token = issue_identity(
        identities,
        agent_id="foreign-agent",
        tenant_id="foreign-tenant",
        blueprint_id="developer",
    )
    response = client.post(
        "/v1/mcp-config/assignments",
        json={
            "name": "foreign",
            "profile_id": "developer",
            "connector_ids": [_first_connector_id(client)],
            "identity_id": foreign.identity_id,
            "issuer": "agent-bom",
            "environment": "prod",
        },
    )
    assert response.status_code == 404


def test_unbound_profile_update_rejects_runtime_constraints(bound_client) -> None:
    client, _identities = bound_client
    connector_id = _first_connector_id(client)
    created = client.post(
        "/v1/mcp-config/assignments",
        json={
            "name": "distribution-only",
            "profile_id": "developer",
            "connector_ids": [connector_id],
        },
    )
    assert created.status_code == 201, created.text
    assignment = created.json()["assignment"]

    response = client.put(
        f"/v1/mcp-config/assignments/{assignment['config_id']}",
        json={
            "expected_revision": 1,
            "name": "invalid-runtime-metadata",
            "profile_id": "developer",
            "connector_ids": [connector_id],
            "environment": "prod",
            "allowed_tools": ["read_file"],
        },
    )

    assert response.status_code == 400
    readback = client.get(f"/v1/mcp-config/assignments/{assignment['config_id']}").json()["assignment"]
    assert readback["revision"] == 1
    assert readback["environment"] == ""
    assert readback["allowed_tools"] == []
