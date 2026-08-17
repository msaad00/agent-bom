"""Bare ASGI startup must enforce the same Postgres RLS role guard as CLI serve."""

from __future__ import annotations


def test_server_postgres_preflight_runs_for_bare_asgi_start(monkeypatch) -> None:
    from agent_bom.api import postgres_common, server

    calls: list[str] = []
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://db.example/agent_bom")
    monkeypatch.setattr(postgres_common, "preflight_rls_capable_role", lambda: calls.append("guarded"))

    server._preflight_postgres_tenant_isolation()

    assert calls == ["guarded"]


def test_server_postgres_preflight_is_noop_without_postgres(monkeypatch) -> None:
    from agent_bom.api import postgres_common, server

    calls: list[str] = []
    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    monkeypatch.setattr(postgres_common, "preflight_rls_capable_role", lambda: calls.append("guarded"))

    server._preflight_postgres_tenant_isolation()

    assert calls == []
