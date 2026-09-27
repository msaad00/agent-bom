"""Read-only vendor API fixtures, atomic resume, freshness and tenant boundaries."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from cryptography.fernet import Fernet

from agent_bom.api import connection_crypto
from agent_bom.connectors.endpoints import service
from agent_bom.connectors.endpoints.models import ConnectionCreate, SyncRequest, scoped_device_id
from agent_bom.connectors.endpoints.providers import freshness
from agent_bom.connectors.endpoints.store import EndpointStore
from agent_bom.connectors.endpoints.transport import CollectionError, EndpointClient

CID = "a" * 32
AT = datetime.now(timezone.utc).isoformat()
SECRET = "fixture-endpoint-secret-never-public"


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_BOM_CONNECTIONS_KEY", Fernet.generate_key().decode())
    monkeypatch.delenv("AGENT_BOM_CONNECTIONS_KEY_PROVIDER", raising=False)
    connection_crypto.reset_key_cache()
    yield EndpointStore(str(tmp_path / "endpoints.db"))
    connection_crypto.reset_key_cache()


def connection(store, provider="jamf", tenant="tenant-a", page_size=1):
    return service.create_connection(
        store,
        tenant,
        ConnectionCreate(
            name=provider,
            provider=provider,
            account_id="acme.jamfcloud.com" if provider == "jamf" else CID,
            jamf_url="https://acme.jamfcloud.com" if provider == "jamf" else "",
            client_id="fixture-client",
            client_secret=SECRET,
            page_size=page_size,
        ),
    )


def jamf_device(id="1", **general):
    return {
        "id": id,
        "udid": "udid-" + id,
        "general": {"name": "same-host", "reportDate": AT, "remoteManagement": {"managed": True}, **general},
        "operatingSystem": {"version": "15.2", "fileVault2Status": "ALL_ENCRYPTED"},
    }


def mock_client(monkeypatch, handler):
    original = EndpointClient
    monkeypatch.setattr(service, "EndpointClient", lambda spec, secret: original(spec, secret, transport=httpx.MockTransport(handler)))


def auth_or(request):
    if request.method == "POST":
        assert request.url.path in {"/api/v1/oauth/token", "/oauth2/token"}
        assert SECRET.encode() in request.content
        return httpx.Response(200, json={"access_token": "fixture-bearer", "expires_in": 120})
    assert request.method == "GET"
    assert request.headers["Authorization"] == "Bearer fixture-bearer"
    return None


def test_jamf_atomic_resume_after_restart_and_encrypted_secret(store, monkeypatch):
    conn = connection(store)
    calls = []
    fail = True

    def handler(request):
        auth = auth_or(request)
        if auth:
            return auth
        assert request.url.path == "/api/v4/computers-inventory"
        assert request.url.params.get_list("section") == ["GENERAL", "OPERATING_SYSTEM"]
        page = int(request.url.params["page"])
        calls.append(page)
        if page == 1 and fail:
            return httpx.Response(403, json={"error": SECRET})
        return httpx.Response(200, json={"totalCount": 2, "results": [jamf_device(str(page + 1))]})

    mock_client(monkeypatch, handler)
    failed = service.sync_connection(store, "tenant-a", conn.id, SyncRequest())
    assert (failed.status, failed.device_count, failed.cursor, failed.gap) == ("partial", 1, "1", "permission_denied")
    assert SECRET not in open(store.path, "rb").read().decode(errors="ignore")
    fail = False
    restarted = EndpointStore(store.path)
    done = service.sync_connection(restarted, "tenant-a", conn.id, SyncRequest())
    assert done.status == "complete" and done.device_count == 2
    assert done.run_id == failed.run_id and calls == [0, 1, 1]
    output = service.device_page(restarted, "tenant-a", conn.id)
    assert len(output["devices"]) == 2
    assert output["devices"][0]["managed"] is True
    assert output["devices"][0]["compliant"] is None
    assert SECRET not in json.dumps(output)


def test_tenants_accounts_and_names_cannot_join(store):
    a, b = connection(store), connection(store, tenant="tenant-b")
    assert store.get("tenant-b", a.id) is None
    assert [c.id for c in store.connections("tenant-b")] == [b.id]
    with pytest.raises(CollectionError, match="not_found"):
        service.sync_connection(store, "tenant-b", a.id, SyncRequest())
    assert (
        len(
            {
                scoped_device_id(t, p, ac, "1")
                for t, p, ac in [("a", "jamf", "a"), ("b", "jamf", "a"), ("a", "jamf", "b"), ("a", "crowdstrike", "a")]
            }
        )
        == 4
    )


def test_falcon_inventory_details_health_not_compliance(store, monkeypatch):
    conn = connection(store, "crowdstrike")

    def handler(request):
        auth = auth_or(request)
        if auth:
            return auth
        if request.url.path == "/devices/queries/devices-scroll/v1":
            return httpx.Response(
                200,
                json={
                    "resources": [] if request.url.params.get("offset") else ["aid"],
                    "meta": {"pagination": {"total": 1, "offset": "next"}},
                },
            )
        assert request.url.params.get_list("ids") == ["aid"]
        return httpx.Response(
            200,
            json={"resources": [{"device_id": "aid", "cid": CID, "status": "normal", "reduced_functionality_mode": "no", "last_seen": AT}]},
        )

    mock_client(monkeypatch, handler)
    result = service.sync_connection(store, "tenant-a", conn.id, SyncRequest())
    assert result.status == "complete"
    signal = store.devices("tenant-a", conn.id, result.run_id)[0]
    assert signal.attributes["sensor_healthy"] is True
    assert signal.compliant is None and signal.disk_encrypted is None


@pytest.mark.parametrize(
    "response,gap",
    [
        ({"resources": []}, "host_details_gap"),
        ({"resources": [{"device_id": "aid", "cid": "b" * 32}]}, "provider_account_mismatch"),
        ({"errors": [{"message": SECRET}], "resources": []}, "invalid_or_partial_provider_response"),
    ],
)
def test_falcon_partial_details_never_advance_cursor(store, monkeypatch, response, gap):
    conn = connection(store, "crowdstrike")

    def handler(request):
        auth = auth_or(request)
        if auth:
            return auth
        return httpx.Response(
            200,
            json=response
            if "entities" in request.url.path
            else {"resources": ["aid"], "meta": {"pagination": {"offset": "next", "total": 1}}},
        )

    mock_client(monkeypatch, handler)
    state = service.sync_connection(store, "tenant-a", conn.id, SyncRequest())
    assert state.gap == gap and state.cursor == "" and state.device_count == 0


def test_duplicate_page_rolls_back_devices_and_cursor(store, monkeypatch):
    conn = connection(store)
    mock_client(monkeypatch, lambda req: auth_or(req) or httpx.Response(200, json={"totalCount": 2, "results": [jamf_device()]}))
    state = service.sync_connection(store, "tenant-a", conn.id, SyncRequest())
    assert state.gap == "duplicate_device_across_pages" and state.device_count == 1 and state.cursor == "1"
    assert len(store.devices("tenant-a", conn.id, state.run_id)) == 1


def test_concurrent_sync_claim_and_stale_worker_are_fenced(store):
    conn = connection(store)
    store.claim("tenant-a", conn.id, "worker-a")
    with pytest.raises(CollectionError, match="already_running"):
        EndpointStore(store.path).claim("tenant-a", conn.id, "worker-b")
    store.release("tenant-a", conn.id, "worker-b")
    with pytest.raises(CollectionError):
        store.claim("tenant-a", conn.id, "worker-b")
    state = service._resume_state(store, conn, False)
    with pytest.raises(CollectionError, match="lease_lost"):
        store.checkpoint(state, [], "worker-b")


def test_expired_falcon_scroll_restarts_without_erasing_old_evidence(store):
    conn = connection(store, "crowdstrike")
    store.claim("tenant-a", conn.id, "worker")
    state = service._resume_state(store, conn, False)
    state.cursor = "old-offset"
    state.cursor_at = (datetime.now(timezone.utc) - timedelta(minutes=3)).isoformat()
    store.checkpoint(state, [], "worker")
    renewed = service._resume_state(store, conn, False)
    assert renewed.run_id != state.run_id and renewed.cursor == ""
    assert store.latest("tenant-a", conn.id).run_id == state.run_id


@pytest.mark.parametrize(
    "timestamp,expected",
    [(AT, "fresh"), ("", "unknown"), ("garbage", "unknown"), ("2020-01-01T00:00:00Z", "stale"), ("2099-01-01T00:00:00Z", "unknown")],
    ids=["fresh", "missing", "invalid", "stale", "future"],
)
def test_freshness(timestamp, expected):
    assert freshness(timestamp, 24, AT) == expected


@pytest.mark.parametrize(
    "url",
    [
        "http://acme.jamfcloud.com",
        "https://evil.test",
        "https://acme.jamfcloud.com.evil.test",
        "https://user:pass@acme.jamfcloud.com",
        "https://acme.jamfcloud.com:8443",
        "https://acme.jamfcloud.com/path",
        "https://127.0.0.1",
    ],
)
def test_untrusted_credential_destinations_rejected(url):
    with pytest.raises(ValueError):
        ConnectionCreate(name="x", provider="jamf", account_id="acme.jamfcloud.com", jamf_url=url, client_id="x", client_secret=SECRET)


@pytest.mark.parametrize("status,gap", [(302, "provider_request_rejected"), (401, "authentication_failed"), (403, "permission_denied")])
def test_token_errors_are_safe_and_no_redirects(store, status, gap):
    conn = connection(store)
    calls = []

    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(status, headers={"Location": "https://evil.test"}, json={"error": SECRET})

    client = EndpointClient(conn, SECRET, transport=httpx.MockTransport(handler))
    with pytest.raises(CollectionError, match=gap):
        client.get("/api/v4/computers-inventory", [])
    client.close()
    assert len(calls) == 1


def test_retry_429_then_success(store, monkeypatch):
    conn = connection(store)
    sleeps, calls = [], []
    monkeypatch.setattr("agent_bom.connectors.endpoints.transport.time.sleep", sleeps.append)

    def handler(request):
        calls.append(request)
        return httpx.Response(429, headers={"Retry-After": "2"}) if len(calls) == 1 else httpx.Response(200, json={"ok": True})

    client = EndpointClient(conn, SECRET, transport=httpx.MockTransport(handler))
    assert client._request("GET", "/test") == {"ok": True}
    assert sleeps == [2]
    client.close()


def test_complete_inventory_becomes_unknown_at_access_time(store, monkeypatch):
    from agent_bom.api.agent_identity_store import AccessContext
    from agent_bom.device_posture import InMemoryDevicePostureStore, apply_device_posture

    conn = connection(store)
    mock_client(monkeypatch, lambda req: auth_or(req) or httpx.Response(200, json={"totalCount": 1, "results": [jamf_device()]}))
    state = service.sync_connection(store, "tenant-a", conn.id, SyncRequest())
    signal = store.devices("tenant-a", conn.id, state.run_id)[0]
    monkeypatch.setattr("agent_bom.connectors.endpoints.store.EndpointStore", lambda: store)
    ctx = AccessContext(device_id=signal.device_id)
    apply_device_posture(InMemoryDevicePostureStore(), ctx, tenant_id="tenant-a")
    assert ctx.device_managed is True and ctx.device_disk_encrypted is True and ctx.device_compliant is None
    monkeypatch.setattr(service, "now", lambda: (datetime.now(timezone.utc) + timedelta(days=2)).isoformat())
    apply_device_posture(InMemoryDevicePostureStore(), ctx, tenant_id="tenant-a")
    assert ctx.device_managed is None and ctx.device_disk_encrypted is None
    ctx.device_managed = True
    apply_device_posture(InMemoryDevicePostureStore(), ctx, tenant_id="tenant-b")
    assert ctx.device_managed is None


def test_new_empty_collection_does_not_reuse_old_device(store, monkeypatch):
    conn = connection(store)
    mock_client(monkeypatch, lambda req: auth_or(req) or httpx.Response(200, json={"totalCount": 1, "results": [jamf_device()]}))
    old = service.sync_connection(store, "tenant-a", conn.id, SyncRequest())
    signal = store.devices("tenant-a", conn.id, old.run_id)[0]
    mock_client(monkeypatch, lambda req: auth_or(req) or httpx.Response(200, json={"totalCount": 0, "results": []}))
    current = service.sync_connection(store, "tenant-a", conn.id, SyncRequest())
    assert current.status == "complete" and current.device_count == 0
    assert store.current_device("tenant-a", signal.device_id) is None
    assert len(store.devices("tenant-a", conn.id, old.run_id)) == 1


def test_failure_receipt_survives_successful_resume(store, monkeypatch):
    conn = connection(store)
    mock_client(monkeypatch, lambda req: auth_or(req) or httpx.Response(403))
    failed = service.sync_connection(store, "tenant-a", conn.id, SyncRequest())
    mock_client(monkeypatch, lambda req: auth_or(req) or httpx.Response(200, json={"totalCount": 0, "results": []}))
    done = service.sync_connection(store, "tenant-a", conn.id, SyncRequest())
    assert done.run_id == failed.run_id and done.status == "complete"
    assert any(receipt.gap == "permission_denied" for receipt in store.history("tenant-a", conn.id))


def test_duplicate_connection_cannot_replace_stored_secret(store):
    conn = connection(store)
    with pytest.raises(CollectionError, match="already_exists"):
        connection(store)
    assert store.get("tenant-a", conn.id)[0] == conn


def test_token_refresh_only_once_after_401(store):
    conn = connection(store)
    counts = {"POST": 0, "GET": 0}

    def handler(request):
        counts[request.method] += 1
        if request.method == "POST":
            return httpx.Response(200, json={"access_token": f"token-{counts['POST']}", "expires_in": 120})
        return httpx.Response(401) if counts["GET"] == 1 else httpx.Response(200, json={"ok": True})

    client = EndpointClient(conn, SECRET, transport=httpx.MockTransport(handler))
    assert client.get("/test", []) == {"ok": True}
    assert counts == {"POST": 2, "GET": 2}
    client.close()


def test_provider_budget_stops_further_requests(store):
    import time

    conn = connection(store)
    calls = []
    client = EndpointClient(conn, SECRET, transport=httpx.MockTransport(lambda req: calls.append(req)))
    client._deadline = time.monotonic() - 1
    with pytest.raises(CollectionError, match="time_budget"):
        client.get("/test", [])
    assert not calls
    client.close()


def test_binding_limit_preserves_retirement_and_tenant_isolation(store):
    for number in range(100):
        store.bind_agent("a", "device", str(number), {"agent_id": str(number), "active": True})
    with pytest.raises(CollectionError, match="device_agent_binding_limit_reached"):
        store.bind_agent("a", "device", "extra", {"active": True})
    store.bind_agent("a", "device", "0", {"agent_id": "0", "active": False})
    assert len(store.agent_bindings("a", "device")) == 100
    assert store.agent_bindings("a", "device")[0]["active"] is False
    assert store.bindings_for_devices("b", ["device"]) == {}
    assert store.bindings_for_devices("a", []) == {}


def test_malformed_jamf_posture_records_gap_without_advancing(store, monkeypatch):
    conn = connection(store)
    device = jamf_device()
    device["operatingSystem"]["fileVault2Status"] = {"unexpected": True}
    mock_client(monkeypatch, lambda request: auth_or(request) or httpx.Response(200, json={"results": [device], "totalCount": 1}))
    state = service.sync_connection(store, conn.tenant_id, conn.id, SyncRequest())
    assert state.status == "failed"
    assert state.gap == "invalid_encryption_posture"
    assert state.device_count == 0 and state.cursor == ""


@pytest.mark.asyncio
async def test_mcp_listing_matches_api_service_with_status_and_no_secret(store, monkeypatch):
    from agent_bom.mcp_tools import endpoint_connectors as mcp

    conn = connection(store)
    monkeypatch.setattr(mcp, "EndpointStore", lambda: store)
    monkeypatch.setattr(mcp, "resolve_mcp_tool_tenant_id", lambda tenant: tenant)
    payload = await mcp.endpoint_inventory_impl(tenant_id=conn.tenant_id)
    assert json.loads(payload) == service.connection_list(store, conn.tenant_id)
    assert json.loads(payload)["connections"][0]["sync"] is None
    assert SECRET not in payload and "client_secret" not in payload
