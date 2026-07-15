"""Governance audit actor attribution (pre-release bug-fix).

The identity/delegation/JIT/conditional-access/access-review and mcp-config
lifecycle routes seal an ``actor`` into the signed audit chain and fan it out to
governance webhooks. ``request.state.actor`` is never populated in ``src/`` — the
auth middleware sets ``request.state.api_key_name`` — so the ``_actor`` helper
must fall back to ``api_key_name`` before the ``"api"`` sentinel, exactly like
``routes/blueprints.py``. Otherwise every governance action records a blank
``actor="api"``, destroying the accountability the surface exists to provide.
"""

from __future__ import annotations

from types import SimpleNamespace

from agent_bom.api.audit_log import InMemoryAuditLog, log_action, set_audit_log
from agent_bom.api.routes import identities as identities_routes
from agent_bom.api.routes import mcp_config as mcp_config_routes


def _request(api_key_name: str | None = None, actor: str | None = None) -> SimpleNamespace:
    return SimpleNamespace(state=SimpleNamespace(api_key_name=api_key_name, actor=actor))


def test_identities_actor_prefers_api_key_name() -> None:
    assert identities_routes._actor(_request(api_key_name="ci-token")) == "ci-token"


def test_mcp_config_actor_prefers_api_key_name() -> None:
    assert mcp_config_routes._actor(_request(api_key_name="ci-token")) == "ci-token"


def test_actor_prefers_explicit_actor_over_api_key_name() -> None:
    req = _request(api_key_name="ci-token", actor="alice@corp")
    assert identities_routes._actor(req) == "alice@corp"
    assert mcp_config_routes._actor(req) == "alice@corp"


def test_actor_falls_back_to_api_sentinel_when_unset() -> None:
    req = _request()
    assert identities_routes._actor(req) == "api"
    assert mcp_config_routes._actor(req) == "api"


def test_governance_audit_records_api_key_name_and_chain_verifies() -> None:
    """Identity + mcp-config actions seal the real actor and the chain verifies."""
    store = InMemoryAuditLog()
    set_audit_log(store)

    req = _request(api_key_name="ci-token")
    identity_actor = identities_routes._actor(req)
    mcp_actor = mcp_config_routes._actor(req)

    log_action("agent_identity.issue", actor=identity_actor, resource="agent-1", tenant_id="default")
    log_action("mcp_config.assign", actor=mcp_actor, resource="cfg-1", tenant_id="default")

    entries = store.list_entries(limit=10, tenant_id="default")
    actors = {e.action: e.actor for e in entries}
    assert actors["agent_identity.issue"] == "ci-token"
    assert actors["mcp_config.assign"] == "ci-token"
    assert "api" not in actors.values()

    verified, tampered = store.verify_integrity(tenant_id="default")
    assert tampered == 0
    assert verified >= 2
