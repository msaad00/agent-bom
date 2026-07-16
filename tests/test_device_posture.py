"""EDR/MDM device-posture ingest + ABAC device-attribute enrichment.

Device posture/compliance signals from EDR (endpoint detection & response) and
MDM (mobile device management) sources are normalized to a vendor-neutral
:class:`DeviceSignal`, persisted per tenant, and surfaced to the
conditional-access (ABAC) evaluation so a policy can require a *managed* /
*compliant* / *disk-encrypted* device.

These tests assert: vendor payload → normalized signal round-trip (one EDR, one
MDM adapter), tenant isolation in the store, and that an ingested signal makes a
require-compliant conditional-access policy allow/deny correctly.
"""

from __future__ import annotations

from agent_bom.api.agent_identity_store import (
    AccessContext,
    ConditionalAccessPolicy,
    InMemoryAgentIdentityStore,
    create_conditional_policy,
    evaluate_conditional_access,
)
from agent_bom.device_posture import (
    DeviceSignal,
    InMemoryDevicePostureStore,
    apply_device_posture,
    create_device_connector,
    list_device_connectors,
)

# ── vendor adapters (round-trip) ─────────────────────────────────────────────


def test_crowdstrike_edr_payload_normalizes():
    conn = create_device_connector("crowdstrike")
    payload = {
        "resources": [
            {
                "device_id": "cs-abc",
                "hostname": "laptop-1",
                "platform_name": "Mac",
                "os_version": "14.5",
                "status": "normal",
                "reduced_functionality_mode": "no",
                "last_seen": "2026-07-15T12:00:00Z",
            }
        ]
    }
    signals = conn.normalize(payload, tenant_id="tenant-a")
    assert len(signals) == 1
    sig = signals[0]
    assert sig.source == "crowdstrike"
    assert sig.device_id == "cs-abc"
    assert sig.managed is True  # a reporting CrowdStrike sensor = managed
    assert sig.compliant is True  # normal + not reduced-functionality
    assert sig.os_version == "14.5"


def test_crowdstrike_reduced_functionality_is_not_compliant():
    conn = create_device_connector("crowdstrike")
    payload = {"resources": [{"device_id": "cs-x", "status": "normal", "reduced_functionality_mode": "yes"}]}
    sig = conn.normalize(payload, tenant_id="t")[0]
    assert sig.managed is True
    assert sig.compliant is False


def test_crowdstrike_sparse_host_is_unknown_not_compliant():
    # A partial/sparse CrowdStrike payload (device_id only, no status and no
    # enrollment evidence) must NOT fail open: posture is unknown, not compliant,
    # and managed is not asserted True — so a require_device_* gate fails closed.
    conn = create_device_connector("crowdstrike")
    payload = {"resources": [{"device_id": "cs-sparse"}]}
    sig = conn.normalize(payload, tenant_id="t")[0]
    assert sig.compliant is None  # unknown, NOT compliant
    assert sig.managed is not True  # no enrollment evidence → not asserted managed

    # And it must be denied by a require-compliant policy (fail closed).
    policy = ConditionalAccessPolicy(
        policy_id="p1",
        tenant_id="t",
        name="require compliant device",
        effect="require",
        status="active",
        created_at="2026-07-16T00:00:00+00:00",
        require_device_compliant=True,
    )
    store = InMemoryDevicePostureStore()
    store.put(sig)
    ctx = AccessContext(device_id="cs-sparse")
    apply_device_posture(store, ctx, tenant_id="t")
    denied, _reason, _pid = evaluate_conditional_access([policy], ctx)
    assert denied is False


def test_crowdstrike_empty_status_with_enrollment_evidence_is_managed_but_unknown_compliant():
    # A host that evidences a reporting sensor (last_seen present) but reports no
    # status is managed=True yet compliant=None (unknown, fails closed).
    conn = create_device_connector("crowdstrike")
    payload = {"resources": [{"device_id": "cs-seen", "last_seen": "2026-07-15T12:00:00Z"}]}
    sig = conn.normalize(payload, tenant_id="t")[0]
    assert sig.managed is True
    assert sig.compliant is None


def test_intune_mdm_payload_normalizes():
    conn = create_device_connector("intune")
    payload = {
        "value": [
            {
                "id": "intune-dev-1",
                "deviceName": "phone-1",
                "operatingSystem": "iOS",
                "osVersion": "17.5",
                "complianceState": "compliant",
                "managementState": "managed",
                "isEncrypted": True,
                "lastSyncDateTime": "2026-07-15T09:00:00Z",
            }
        ]
    }
    signals = conn.normalize(payload, tenant_id="tenant-a")
    assert len(signals) == 1
    sig = signals[0]
    assert sig.source == "intune"
    assert sig.device_id == "intune-dev-1"
    assert sig.compliant is True
    assert sig.managed is True
    assert sig.disk_encrypted is True


def test_intune_noncompliant_device():
    conn = create_device_connector("intune")
    payload = {"value": [{"id": "d2", "complianceState": "noncompliant", "isEncrypted": False}]}
    sig = conn.normalize(payload, tenant_id="t")[0]
    assert sig.compliant is False
    assert sig.disk_encrypted is False


def test_generic_ingest_normalizes_canonical_shape():
    conn = create_device_connector("generic")
    payload = {
        "signals": [
            {
                "device_id": "dev-9",
                "managed": True,
                "compliant": True,
                "disk_encrypted": True,
                "os_version": "13.0",
                "risk_level": "low",
            }
        ]
    }
    signals = conn.normalize(payload, tenant_id="tenant-a")
    assert signals[0].device_id == "dev-9"
    assert signals[0].compliant is True


def test_connectors_are_listed_and_unknown_rejected():
    names = list_device_connectors()
    assert {"crowdstrike", "intune", "generic"} <= set(names)
    import pytest

    with pytest.raises(ValueError):
        create_device_connector("does-not-exist")


# ── store + tenant isolation ─────────────────────────────────────────────────


def test_store_is_tenant_scoped():
    store = InMemoryDevicePostureStore()
    store.put(DeviceSignal(tenant_id="tenant-a", device_id="dev-1", source="generic", compliant=True))
    store.put(DeviceSignal(tenant_id="tenant-b", device_id="dev-1", source="generic", compliant=False))
    a = store.get("dev-1", tenant_id="tenant-a")
    b = store.get("dev-1", tenant_id="tenant-b")
    assert a is not None and a.compliant is True
    assert b is not None and b.compliant is False
    # A device known to tenant-a is invisible to tenant-c.
    assert store.get("dev-1", tenant_id="tenant-c") is None


def test_store_upsert_keeps_latest():
    store = InMemoryDevicePostureStore()
    store.put(DeviceSignal(tenant_id="t", device_id="d", source="crowdstrike", compliant=False))
    store.put(DeviceSignal(tenant_id="t", device_id="d", source="crowdstrike", compliant=True))
    got = store.get("d", tenant_id="t")
    assert got is not None and got.compliant is True
    assert len(store.list("t")) == 1


# ── ABAC enrichment ──────────────────────────────────────────────────────────


def test_apply_device_posture_fills_context():
    store = InMemoryDevicePostureStore()
    store.put(
        DeviceSignal(tenant_id="t", device_id="dev-1", source="intune", managed=True, compliant=True, disk_encrypted=True)
    )
    ctx = AccessContext(device_id="dev-1")
    apply_device_posture(store, ctx, tenant_id="t")
    assert ctx.device_managed is True
    assert ctx.device_compliant is True
    assert ctx.device_disk_encrypted is True


def test_apply_device_posture_unknown_device_stays_none():
    store = InMemoryDevicePostureStore()
    ctx = AccessContext(device_id="ghost")
    apply_device_posture(store, ctx, tenant_id="t")
    assert ctx.device_compliant is None


def test_require_compliant_policy_denies_noncompliant_device():
    policy = ConditionalAccessPolicy(
        policy_id="p1",
        tenant_id="t",
        name="require compliant device",
        effect="require",
        status="active",
        created_at="2026-07-16T00:00:00+00:00",
        require_device_compliant=True,
    )
    # Compliant device → allowed.
    ok, _reason, _pid = evaluate_conditional_access(
        [policy], AccessContext(device_id="dev-1", device_compliant=True)
    )
    assert ok is True
    # Non-compliant device → denied (fail closed).
    denied, reason, pid = evaluate_conditional_access(
        [policy], AccessContext(device_id="dev-2", device_compliant=False)
    )
    assert denied is False
    assert pid == "p1"
    # Unknown posture (None) → denied (fail closed).
    unknown, _reason, _pid = evaluate_conditional_access(
        [policy], AccessContext(device_id="dev-3", device_compliant=None)
    )
    assert unknown is False


def test_end_to_end_ingest_to_abac():
    # EDR payload → normalized signal → store → posture into context → policy eval.
    store = InMemoryDevicePostureStore()
    conn = create_device_connector("crowdstrike")
    for sig in conn.normalize({"resources": [{"device_id": "cs-1", "status": "normal"}]}, tenant_id="t"):
        store.put(sig)
    ident_store = InMemoryAgentIdentityStore()
    create_conditional_policy(
        ident_store,
        tenant_id="t",
        name="managed-device guardrail",
        effect="require",
        require_device_managed=True,
    )
    ctx = AccessContext(device_id="cs-1")
    apply_device_posture(store, ctx, tenant_id="t")
    ok, _reason, _pid = evaluate_conditional_access(
        ident_store.list_conditional_policies("t"), ctx
    )
    assert ok is True


# ── API route + gateway end-to-end ───────────────────────────────────────────


def _client(store):
    import pytest as _pytest

    _pytest.importorskip("fastapi")
    from starlette.testclient import TestClient

    from agent_bom import agent_identity
    from agent_bom.api.agent_identity_store import set_agent_identity_store, verify_token
    from agent_bom.api.server import app

    set_agent_identity_store(store)
    agent_identity.set_local_identity_verifier(lambda tok: verify_token(store, tok))
    return TestClient(app)


def test_ingest_route_normalizes_and_persists(monkeypatch):
    import pytest as _pytest

    _pytest.importorskip("fastapi")
    from agent_bom.device_posture import get_device_posture_store, set_device_posture_store

    posture = InMemoryDevicePostureStore()
    set_device_posture_store(posture)
    ident = InMemoryAgentIdentityStore()
    try:
        client = _client(ident)
        resp = client.post(
            "/v1/device-posture",
            json={"source": "intune", "payload": {"value": [{"id": "d1", "complianceState": "compliant", "isEncrypted": True}]}},
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["ingested"] == 1
        assert body["devices"][0]["compliant"] is True
        # Persisted + readable back through the tenant-scoped GET.
        got = client.get("/v1/device-posture/d1")
        assert got.status_code == 200
        assert got.json()["device"]["disk_encrypted"] is True
        assert get_device_posture_store().get("d1", tenant_id="default") is not None
    finally:
        set_device_posture_store(None)
        from agent_bom.api.agent_identity_store import set_agent_identity_store

        set_agent_identity_store(None)


def test_ingest_route_rejects_unknown_source():
    import pytest as _pytest

    _pytest.importorskip("fastapi")
    from agent_bom.device_posture import set_device_posture_store

    set_device_posture_store(InMemoryDevicePostureStore())
    ident = InMemoryAgentIdentityStore()
    try:
        client = _client(ident)
        resp = client.post("/v1/device-posture", json={"source": "nope", "payload": {}})
        assert resp.status_code == 400
    finally:
        set_device_posture_store(None)
        from agent_bom.api.agent_identity_store import set_agent_identity_store

        set_agent_identity_store(None)


def test_gateway_blocks_noncompliant_device_end_to_end():
    import pytest as _pytest

    _pytest.importorskip("fastapi")
    from starlette.testclient import TestClient

    from agent_bom import agent_identity
    from agent_bom.api.agent_identity_store import (
        issue_identity,
        set_agent_identity_store,
        verify_token,
    )
    from agent_bom.device_posture import DeviceSignal, InMemoryDevicePostureStore, set_device_posture_store
    from agent_bom.gateway_server import GatewaySettings, create_gateway_app
    from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry

    ident = InMemoryAgentIdentityStore()
    set_agent_identity_store(ident)
    agent_identity.set_local_identity_verifier(lambda tok: verify_token(ident, tok))
    posture = InMemoryDevicePostureStore()
    posture.put(DeviceSignal(tenant_id="default", device_id="dev-ok", source="crowdstrike", managed=True, compliant=True))
    posture.put(DeviceSignal(tenant_id="default", device_id="dev-bad", source="crowdstrike", managed=True, compliant=False))
    set_device_posture_store(posture)
    try:
        issue_identity(ident, agent_id="agent-a", tenant_id="default")
        create_conditional_policy(ident, tenant_id="default", name="compliant-only", effect="require", require_device_compliant=True)

        async def ok_caller(upstream, message, extra_headers):
            return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}

        settings = GatewaySettings(
            registry=UpstreamRegistry([UpstreamConfig(name="filesystem", url="http://fs.local:8100")]),
            policy={},
            upstream_caller=ok_caller,
        )
        client = TestClient(create_gateway_app(settings))
        message = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "list_files", "arguments": {}}}

        blocked = client.post("/mcp/filesystem", json=message, headers={"x-agent-device-id": "dev-bad"})
        assert blocked.json().get("error", {}).get("code") == -32001, blocked.text

        allowed = client.post("/mcp/filesystem", json=message, headers={"x-agent-device-id": "dev-ok"})
        assert allowed.status_code == 200 and allowed.json()["result"] == {"ok": True}
    finally:
        set_device_posture_store(None)
        set_agent_identity_store(None)
        agent_identity.set_local_identity_verifier(None)
