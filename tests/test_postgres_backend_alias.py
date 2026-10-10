"""A Postgres DSN in AGENT_BOM_DB must use the same security boundaries."""

import importlib

import pytest


@pytest.mark.parametrize(
    "owner,getter,slot,adapter,class_name",
    [
        ("stores", "_get_idempotency_store", "_idempotency_store", "idempotency_store", "PostgresIdempotencyStore"),
        (
            "stores",
            "_get_tenant_graph_retention_store",
            "_tenant_graph_retention_store",
            "tenant_graph_retention_store",
            "PostgresTenantGraphRetentionStore",
        ),
        (
            "stores",
            "_get_tenant_score_config_store",
            "_tenant_score_config_store",
            "postgres_tenant_score_config",
            "PostgresTenantScoreConfigStore",
        ),
        ("stores", "_get_scim_store", "_scim_store", "postgres_scim", "PostgresSCIMStore"),
        ("stores", "_get_trend_store", "_trend_store", "postgres_store", "PostgresTrendStore"),
        ("stores", "_get_graph_store", "_graph_store", "postgres_store", "PostgresGraphStore"),
        ("auth", "get_key_store", "_key_store", "postgres_access", "PostgresKeyStore"),
        ("audit_log", "get_audit_log", "_audit_log", "postgres_audit", "PostgresAuditLog"),
    ],
)
def test_db_alias_selects_existing_postgres_store(monkeypatch, owner, getter, slot, adapter, class_name):
    owner_module = importlib.import_module("agent_bom.api." + owner)
    adapter_module = importlib.import_module("agent_bom.api." + adapter)
    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    monkeypatch.delenv("AGENT_BOM_GRAPH_BACKEND", raising=False)
    monkeypatch.setenv("AGENT_BOM_DB", "postgresql://fixture.invalid/registry")
    monkeypatch.setattr(owner_module, slot, None)
    sentinel = object()
    monkeypatch.setattr(adapter_module, class_name, lambda: sentinel)
    if getter == "_get_graph_store":
        monkeypatch.setattr(owner_module, "_get_store", lambda: object())
        monkeypatch.setattr("agent_bom.api.current_graph.current_graph_store", lambda graph, jobs: graph)
    assert getattr(owner_module, getter)() is sentinel


def test_db_alias_runs_role_preflight(monkeypatch):
    from agent_bom.api.server import _preflight_postgres_tenant_isolation

    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    monkeypatch.delenv("SNOWFLAKE_ACCOUNT", raising=False)
    monkeypatch.setenv("AGENT_BOM_DB", "postgresql://fixture.invalid/registry")
    monkeypatch.setattr(
        "agent_bom.api.postgres_common.preflight_rls_capable_role", lambda: (_ for _ in ()).throw(RuntimeError("restricted role required"))
    )
    with pytest.raises(RuntimeError, match="restricted role required"):
        _preflight_postgres_tenant_isolation()
