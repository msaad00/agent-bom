"""Gateway isolates quarantined fleet agents (detection → enforcement).

The fleet roster's QUARANTINED lifecycle state was advisory-only — an operator
could quarantine a compromised or under-review agent but it kept relaying. These
tests cover the opt-in enforcement: `enforce` blocks every call from a
quarantined agent, `warn` audits it, `off` stays advisory, and a fleet-store
failure fails open.
"""

from __future__ import annotations

from typing import Any

import pytest
from starlette.testclient import TestClient

from agent_bom.api.fleet_store import FleetAgent, FleetLifecycleState, InMemoryFleetStore
from agent_bom.api.stores import set_fleet_store
from agent_bom.gateway_server import GatewaySettings, create_gateway_app
from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry


def _registry() -> UpstreamRegistry:
    return UpstreamRegistry([UpstreamConfig(name="filesystem", url="http://fs.local:8100")])


def _call(token: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "/tmp/x"}, "_meta": {"agent_identity": token}},
    }


async def _ok_caller(upstream, message, extra_headers):
    return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}


def _settings(mode: str, audit: list[dict[str, Any]] | None = None) -> GatewaySettings:
    async def _sink(event: dict[str, Any]) -> None:
        if audit is not None:
            audit.append(event)

    return GatewaySettings(
        registry=_registry(),
        policy={"agent_tokens": {"token-a": "agent-a", "token-b": "agent-b"}},
        upstream_caller=_ok_caller,
        audit_sink=_sink if audit is not None else None,
        fleet_enforcement_mode=mode,
    )


def _seed_fleet() -> None:
    store = InMemoryFleetStore()
    store.put(
        FleetAgent(
            agent_id="agent-a",
            name="agent-a",
            agent_type="custom",
            tenant_id="default",
            lifecycle_state=FleetLifecycleState.QUARANTINED,
        )
    )
    store.put(
        FleetAgent(
            agent_id="agent-b",
            name="agent-b",
            agent_type="custom",
            tenant_id="default",
            lifecycle_state=FleetLifecycleState.APPROVED,
        )
    )
    set_fleet_store(store)


def _is_blocked(resp) -> bool:
    body = resp.json()
    return resp.status_code == 200 and isinstance(body.get("error"), dict) and body["error"].get("code") == -32001


@pytest.fixture(autouse=True)
def _reset():
    yield
    set_fleet_store(None)


def test_enforce_blocks_quarantined_agent():
    _seed_fleet()
    client = TestClient(create_gateway_app(_settings("enforce")))
    resp = client.post("/mcp/filesystem", json=_call("token-a"))
    assert _is_blocked(resp), resp.text
    assert resp.json()["error"]["data"]["policy_source"] == "fleet_quarantine"


def test_enforce_allows_approved_agent():
    _seed_fleet()
    client = TestClient(create_gateway_app(_settings("enforce")))
    resp = client.post("/mcp/filesystem", json=_call("token-b"))
    assert resp.status_code == 200 and resp.json().get("result") == {"ok": True}


def test_warn_audits_but_does_not_block():
    _seed_fleet()
    audit: list[dict[str, Any]] = []
    client = TestClient(create_gateway_app(_settings("warn", audit=audit)))
    resp = client.post("/mcp/filesystem", json=_call("token-a"))
    assert resp.status_code == 200 and resp.json().get("result") == {"ok": True}
    assert any(e.get("action") == "gateway.fleet_warned" for e in audit)


def test_off_is_advisory_no_block():
    _seed_fleet()
    client = TestClient(create_gateway_app(_settings("off")))
    resp = client.post("/mcp/filesystem", json=_call("token-a"))
    assert resp.status_code == 200 and resp.json().get("result") == {"ok": True}


def test_fleet_store_failure_fails_open():
    class _Boom:
        def list_by_tenant(self, *a, **k):
            raise RuntimeError("store down")

    set_fleet_store(_Boom())
    client = TestClient(create_gateway_app(_settings("enforce")))
    resp = client.post("/mcp/filesystem", json=_call("token-a"))
    assert resp.status_code == 200 and resp.json().get("result") == {"ok": True}


# ── Identity revocation for non-managed callers (JWT / opaque tokens) ──────────
#
# The gateway resolves a managed (``abi_``) token through ``identity_for_token``,
# which consults ``AgentIdentity.status`` on every call. A JWKS/OIDC JWT or an
# opaque ``policy.agent_tokens`` mapping never touches the identity store, so the
# agent's revocation was a runtime no-op for exactly the deployments most likely
# to use a real IdP.


def _identity(agent_id: str, status: str):
    from agent_bom.api.agent_identity_store import AgentIdentity

    return AgentIdentity(
        identity_id=f"id-{agent_id}-{status}",
        agent_id=agent_id,
        tenant_id="default",
        token_hash=f"hash-{agent_id}-{status}",
        token_prefix="abi_test",
        role="agent",
        blueprint_id="",
        status=status,
        issued_at="2026-01-01T00:00:00Z",
        expires_at="",
    )


def _seed_identities(*identities) -> None:
    from agent_bom.api.agent_identity_store import InMemoryAgentIdentityStore, set_agent_identity_store

    store = InMemoryAgentIdentityStore()
    for identity in identities:
        store.put(identity)
    set_agent_identity_store(store)


@pytest.fixture(autouse=True)
def _reset_identity_store():
    yield
    from agent_bom.api.agent_identity_store import set_agent_identity_store

    set_agent_identity_store(None)


def test_opaque_caller_with_revoked_identity_is_denied():
    """The bypass proof: an opaque-token caller whose identity was revoked."""
    _seed_fleet()
    _seed_identities(_identity("agent-b", "revoked"))
    client = TestClient(create_gateway_app(_settings("enforce")))
    resp = client.post("/mcp/filesystem", json=_call("token-b"))
    assert _is_blocked(resp), resp.text


def test_opaque_caller_with_live_identity_is_allowed():
    _seed_fleet()
    _seed_identities(_identity("agent-b", "active"))
    client = TestClient(create_gateway_app(_settings("enforce")))
    resp = client.post("/mcp/filesystem", json=_call("token-b"))
    assert resp.status_code == 200 and resp.json().get("result") == {"ok": True}


def test_caller_with_no_managed_identity_record_is_unaffected():
    """Deployments that never issued a managed identity must not start failing."""
    _seed_fleet()
    _seed_identities()  # empty store
    client = TestClient(create_gateway_app(_settings("enforce")))
    resp = client.post("/mcp/filesystem", json=_call("token-b"))
    assert resp.status_code == 200 and resp.json().get("result") == {"ok": True}


def test_agent_with_one_live_identity_among_revoked_is_allowed():
    """Rotation leaves revoked rows behind; only an agent with NO live identity is dead."""
    _seed_fleet()
    _seed_identities(_identity("agent-b", "revoked"), _identity("agent-b", "active"))
    client = TestClient(create_gateway_app(_settings("enforce")))
    resp = client.post("/mcp/filesystem", json=_call("token-b"))
    assert resp.status_code == 200 and resp.json().get("result") == {"ok": True}


def test_revocation_blocks_non_tool_methods():
    """Pins the check ABOVE the tool-call branch.

    ``allowed_tools`` and the JIT-grant path only run for ``tools/call``. If the
    revocation check were placed there, a revoked caller could still run
    ``tools/list``, ``initialize`` and ``resources/read``.
    """
    _seed_fleet()
    _seed_identities(_identity("agent-b", "revoked"))
    client = TestClient(create_gateway_app(_settings("enforce")))
    resp = client.post(
        "/mcp/filesystem",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {"_meta": {"agent_identity": "token-b"}},
        },
    )
    assert _is_blocked(resp), resp.text


def test_identity_store_failure_fails_open_for_unsecured_posture():
    """An identity-store outage must not become a fleet-wide outage.

    Only the revocation lookup is broken here. Breaking the whole store would
    also take out conditional access, which fails *closed* by design — that
    would test the wrong subsystem.
    """
    from agent_bom.api.agent_identity_store import InMemoryAgentIdentityStore, set_agent_identity_store

    class _RevocationLookupDown(InMemoryAgentIdentityStore):
        def list(self, *a, **k):
            raise RuntimeError("identity store down")

        def list_by_agent(self, *a, **k):
            raise RuntimeError("identity store down")

    _seed_fleet()
    set_agent_identity_store(_RevocationLookupDown())
    client = TestClient(create_gateway_app(_settings("enforce")))
    resp = client.post("/mcp/filesystem", json=_call("token-b"))
    assert resp.status_code == 200 and resp.json().get("result") == {"ok": True}


def test_identity_store_failure_fails_closed_when_identity_is_required():
    """Under a secured posture an unprovable revocation status must deny."""
    from agent_bom.api.agent_identity_store import InMemoryAgentIdentityStore, set_agent_identity_store

    class _RevocationLookupDown(InMemoryAgentIdentityStore):
        def list(self, *a, **k):
            raise RuntimeError("identity store down")

        def list_by_agent(self, *a, **k):
            raise RuntimeError("identity store down")

    _seed_fleet()
    set_agent_identity_store(_RevocationLookupDown())
    settings = _settings("enforce")
    settings.policy["require_agent_identity"] = True
    client = TestClient(create_gateway_app(settings))
    resp = client.post("/mcp/filesystem", json=_call("token-b"))
    assert _is_blocked(resp), resp.text


def test_fleet_enforcement_defaults_to_enforce():
    """Quarantine is an explicit operator action; 'off' made it a no-op."""
    settings = GatewaySettings(registry=_registry(), policy={}, upstream_caller=_ok_caller)
    assert settings.fleet_enforcement_mode == "enforce"


def test_boot_warns_and_names_agents_that_enforcement_will_block(caplog):
    """The default flip must not be a silent behaviour change on upgrade."""
    import logging

    _seed_fleet()
    with caplog.at_level(logging.WARNING, logger="agent_bom.gateway_server"):
        create_gateway_app(_settings("enforce"))
    warnings = [r.getMessage() for r in caplog.records if "fleet enforcement is active" in r.getMessage()]
    assert warnings, "operators must be told which agents will now be blocked"
    assert "agent-a" in warnings[0]
    assert "--fleet-enforcement off" in warnings[0]


def test_boot_is_silent_when_enforcement_is_opted_out(caplog):
    import logging

    _seed_fleet()
    with caplog.at_level(logging.WARNING, logger="agent_bom.gateway_server"):
        create_gateway_app(_settings("off"))
    assert not [r for r in caplog.records if "fleet enforcement is active" in r.getMessage()]


def _roster(revoked_agent: str, fillers: int):
    """A revoked identity buried under *fillers* NEWER identities.

    The victim is the OLDEST row, so any ``ORDER BY issued_at DESC LIMIT n``
    window with ``n <= fillers`` drops it. Sizing the filler count off the real
    module constant is the point: the previous version of this guard hardcoded
    500 against a 5000-row cap, so the victim never left the window and the
    assertion could not fail.
    """
    victim = _identity(revoked_agent, "revoked")
    victim.issued_at = "2020-01-01T00:00:00Z"
    identities = [victim]
    for i in range(fillers):
        filler = _identity(f"filler-{i}", "active")
        filler.identity_id = f"filler-id-{i}"
        filler.token_hash = f"filler-hash-{i}"
        filler.issued_at = "2026-01-01T00:00:00Z"
        identities.append(filler)
    return identities


class _RosterScanOnlyStore:
    """A store from before the agent-keyed lookup existed.

    Exposes only the legacy surface, so ``identities_for_agent`` has to fall
    back to the recency-capped roster scan. This keeps the truncated-lookup
    signal reachable — and therefore keeps the gateway's fail-closed branch
    for it honest rather than dead code.
    """

    def __init__(self, inner) -> None:
        self._inner = inner

    def put(self, identity) -> None:
        self._inner.put(identity)

    def get(self, identity_id: str, *, tenant_id: str):
        return self._inner.get(identity_id, tenant_id=tenant_id)

    def get_by_token_hash(self, token_hash: str):
        return self._inner.get_by_token_hash(token_hash)

    def list(self, tenant_id: str, *, include_inactive: bool = False, limit: int = 200):
        return self._inner.list(tenant_id, include_inactive=include_inactive, limit=limit)

    def active_jit_grant(self, *a, **k):
        return self._inner.active_jit_grant(*a, **k)

    def list_conditional_policies(self, *a, **k):
        return self._inner.list_conditional_policies(*a, **k)


def test_revocation_is_not_defeated_by_a_large_identity_roster():
    """The lookup must not silently fail open once a tenant grows.

    ``store.list()`` returns the N most recently issued identities. A revoked
    agent whose identity is older than that window fell out of the result, the
    helper saw "no identities for this agent", and concluded "not revoked" —
    reporting no degradation, so the fail-closed branch never fired either.
    Rosters grow monotonically (rotation leaves revoked rows behind), so this
    is reached by ordinary operation, not by an operator mistake.
    """
    from agent_bom.api import agent_identity_store as store_mod
    from agent_bom.api.agent_identity_store import agent_identity_revoked, get_agent_identity_store

    _seed_fleet()
    _seed_identities(*_roster("agent-b", store_mod._IDENTITY_LOOKUP_CAP + 1))

    assert agent_identity_revoked(get_agent_identity_store(), "default", "agent-b") == (True, False)

    client = TestClient(create_gateway_app(_settings("enforce")))
    resp = client.post("/mcp/filesystem", json=_call("token-b"))
    assert _is_blocked(resp), "a revoked agent must stay blocked regardless of roster size"


def test_revocation_lookup_is_agent_keyed_not_a_roster_scan():
    """The root cause: the lookup read the roster instead of the agent.

    An agent-keyed lookup makes the roster size irrelevant, so the cap can
    never hide a revoked row again. Breaking ``list`` proves the revocation
    path no longer depends on it.
    """
    from agent_bom.api.agent_identity_store import (
        InMemoryAgentIdentityStore,
        agent_identity_revoked,
        set_agent_identity_store,
    )

    class _NoRosterScans(InMemoryAgentIdentityStore):
        def list(self, *a, **k):
            raise AssertionError("revocation must not scan the tenant roster")

    store = _NoRosterScans()
    for identity in _roster("agent-b", 3):
        store.put(identity)
    set_agent_identity_store(store)

    assert agent_identity_revoked(store, "default", "agent-b") == (True, False)

    _seed_fleet()
    client = TestClient(create_gateway_app(_settings("enforce")))
    resp = client.post("/mcp/filesystem", json=_call("token-b"))
    assert _is_blocked(resp), resp.text


def test_a_truncated_revocation_lookup_denies_even_on_a_loopback_listener():
    """The safety net, independent of the root-cause fix.

    A truncated lookup is an unproven negative. The gateway converted it to a
    block only when ``require_agent_identity`` was set or anonymous agents were
    disallowed — and anonymous agents are allowed unconditionally on a loopback
    listener, which is the default and the sidecar/single-node shape. Revocation
    is an emergency control: a partial answer must deny on every listener.
    """
    from agent_bom.api import agent_identity_store as store_mod
    from agent_bom.api.agent_identity_store import InMemoryAgentIdentityStore, set_agent_identity_store

    original_cap = store_mod._IDENTITY_LOOKUP_CAP
    store_mod._IDENTITY_LOOKUP_CAP = 10
    try:
        inner = InMemoryAgentIdentityStore()
        for identity in _roster("agent-b", 20):
            inner.put(identity)
        set_agent_identity_store(_RosterScanOnlyStore(inner))

        _seed_fleet()
        settings = _settings("enforce")
        assert settings.listener_host == "127.0.0.1", "the default listener is the exposed surface"
        assert not settings.policy.get("require_agent_identity")

        client = TestClient(create_gateway_app(settings))
        resp = client.post("/mcp/filesystem", json=_call("token-b"))
        assert _is_blocked(resp), "an unproven revocation status must not reach the upstream"
    finally:
        store_mod._IDENTITY_LOOKUP_CAP = original_cap


def test_unknown_agent_in_a_capped_roster_reports_the_lookup_as_incomplete():
    """Absence past the scan cap is unproven, not evidence of absence.

    With a roster larger than the cap and no matching identity, the helper must
    say so rather than returning a confident "not revoked" — otherwise the
    caller's fail-closed branch can never fire. Only a store without the
    agent-keyed lookup still scans, so that is what this pins; a store that
    supports it is covered by ``..._is_agent_keyed_not_a_roster_scan``.
    """
    from agent_bom.api import agent_identity_store as store_mod
    from agent_bom.api.agent_identity_store import (
        InMemoryAgentIdentityStore,
        agent_identity_revoked,
        get_agent_identity_store,
        set_agent_identity_store,
    )

    original_cap = store_mod._IDENTITY_LOOKUP_CAP
    store_mod._IDENTITY_LOOKUP_CAP = 10
    try:
        inner = InMemoryAgentIdentityStore()
        for i in range(20):
            filler = _identity(f"filler-{i}", "active")
            filler.identity_id = f"filler-id-{i}"
            filler.token_hash = f"filler-hash-{i}"
            inner.put(filler)
        set_agent_identity_store(_RosterScanOnlyStore(inner))

        revoked, incomplete = agent_identity_revoked(get_agent_identity_store(), "default", "agent-zzz")
        assert revoked is False
        assert incomplete is True, "a capped lookup must not read as a clean negative"
    finally:
        store_mod._IDENTITY_LOOKUP_CAP = original_cap


def test_small_roster_reports_a_clean_negative():
    """Below the cap, absence IS proven — this must not start failing closed."""
    from agent_bom.api.agent_identity_store import agent_identity_revoked, get_agent_identity_store

    _seed_identities(_identity("agent-b", "active"))
    assert agent_identity_revoked(get_agent_identity_store(), "default", "agent-zzz") == (False, False)


# ── Tenant scoping of the new indexed lookups ────────────────────────────────
#
# Both revocation and quarantine now resolve one agent through an index rather
# than filtering a tenant-scoped list in Python. A new index and a new WHERE
# clause are exactly where tenant scoping gets dropped, and two tenants naming
# an agent the same way is ordinary — "assistant", "ci-bot", "claude-code".


@pytest.mark.parametrize("store_kind", ["memory", "sqlite"])
def test_revocation_does_not_leak_across_tenants_sharing_an_agent_id(store_kind, tmp_path):
    """One tenant revoking its agent must not revoke another tenant's."""
    from agent_bom.api.agent_identity_store import (
        InMemoryAgentIdentityStore,
        SQLiteAgentIdentityStore,
        agent_identity_revoked,
    )

    store = InMemoryAgentIdentityStore() if store_kind == "memory" else SQLiteAgentIdentityStore(db_path=str(tmp_path / "identity.db"))
    revoked = _identity("shared-agent", "revoked")
    revoked.tenant_id = "tenant-a"
    live = _identity("shared-agent", "active")
    live.tenant_id = "tenant-b"
    live.identity_id = "id-shared-agent-active-b"
    live.token_hash = "hash-shared-agent-active-b"
    store.put(revoked)
    store.put(live)

    assert agent_identity_revoked(store, "tenant-a", "shared-agent") == (True, False)
    assert agent_identity_revoked(store, "tenant-b", "shared-agent") == (False, False)
    # And neither tenant sees the other's row at all.
    assert [i.tenant_id for i in store.list_by_agent("tenant-a", "shared-agent")] == ["tenant-a"]
    assert [i.tenant_id for i in store.list_by_agent("tenant-b", "shared-agent")] == ["tenant-b"]


@pytest.mark.parametrize("store_kind", ["memory", "sqlite"])
def test_quarantine_does_not_leak_across_tenants_sharing_an_agent_name(store_kind, tmp_path):
    """Quarantining one tenant's agent must not isolate another tenant's."""
    from agent_bom.api.fleet_store import SQLiteFleetStore, find_fleet_agent

    store = InMemoryFleetStore() if store_kind == "memory" else SQLiteFleetStore(db_path=str(tmp_path / "fleet.db"))
    store.put(
        FleetAgent(
            agent_id="agent-a-1",
            name="shared-name",
            agent_type="custom",
            tenant_id="tenant-a",
            lifecycle_state=FleetLifecycleState.QUARANTINED,
        )
    )
    store.put(
        FleetAgent(
            agent_id="agent-b-1",
            name="shared-name",
            agent_type="custom",
            tenant_id="tenant-b",
            lifecycle_state=FleetLifecycleState.APPROVED,
        )
    )

    found_a = find_fleet_agent(store, "tenant-a", "shared-name")
    found_b = find_fleet_agent(store, "tenant-b", "shared-name")

    assert found_a is not None and found_a.tenant_id == "tenant-a"
    assert found_a.lifecycle_state == FleetLifecycleState.QUARANTINED
    assert found_b is not None and found_b.tenant_id == "tenant-b"
    assert found_b.lifecycle_state == FleetLifecycleState.APPROVED
    assert find_fleet_agent(store, "tenant-c", "shared-name") is None


@pytest.mark.parametrize("store_kind", ["memory", "sqlite"])
def test_quarantine_lookup_stays_case_insensitive(store_kind, tmp_path):
    """The roster scan matched case-insensitively; the indexed lookup must too.

    An exact-match index would have quietly turned a case mismatch into a
    missed quarantine — a fail-open regression hidden inside a perf fix.
    """
    from agent_bom.api.fleet_store import SQLiteFleetStore, find_fleet_agent

    store = InMemoryFleetStore() if store_kind == "memory" else SQLiteFleetStore(db_path=str(tmp_path / "fleet.db"))
    store.put(
        FleetAgent(
            agent_id="Agent-Mixed-Case",
            name="Agent-Mixed-Case",
            agent_type="custom",
            tenant_id="default",
            lifecycle_state=FleetLifecycleState.QUARANTINED,
        )
    )

    for identifier in ("agent-mixed-case", "AGENT-MIXED-CASE", "Agent-Mixed-Case", "  agent-mixed-case  "):
        found = find_fleet_agent(store, "default", identifier)
        assert found is not None, f"{identifier!r} did not resolve"
        assert found.lifecycle_state == FleetLifecycleState.QUARANTINED
