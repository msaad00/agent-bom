"""The authenticated submission context survives every runtime projection."""

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agent_bom.api.auth import KeyStore, Role, create_api_key, set_key_store
from agent_bom.api.gateway_activity_store import SQLiteGatewayActivityStore, set_gateway_activity_store
from agent_bom.api.middleware import APIKeyMiddleware, TrustHeadersMiddleware
from agent_bom.api.routes import proxy
from agent_bom.api.stores import set_analytics_store


@pytest.fixture
def boundary(tmp_path):
    keys = KeyStore()
    set_key_store(keys)
    tokens = {}
    for name, role, tenant in [
        ("analyst", Role.ANALYST, "tenant-a"),
        ("viewer", Role.VIEWER, "tenant-a"),
        ("other", Role.ANALYST, "tenant-a"),
        ("legacy", Role.ANALYST, "tenant-a"),
    ]:
        raw, key = create_api_key(name, role, tenant_id=tenant, principal_id=None if name == "legacy" else f"principal-{name}")
        keys.add(key)
        tokens[name] = raw
    events = []
    set_analytics_store(SimpleNamespace(record_events=lambda rows, **kwargs: events.extend(rows)))
    ledger = SQLiteGatewayActivityStore(str(tmp_path / "ledger.db"))
    set_gateway_activity_store(ledger)
    proxy._reset_proxy_runtime_for_tests()
    app = FastAPI()
    app.include_router(proxy.router, prefix="/v1")
    app.add_middleware(APIKeyMiddleware, api_key="", allow_unauthenticated=False)
    app.add_middleware(TrustHeadersMiddleware)
    with TestClient(app) as client:
        yield client, ledger, events, tokens
    proxy._reset_proxy_runtime_for_tests()
    set_gateway_activity_store(None)
    set_analytics_store(None)


def body(event_id="event"):
    return {
        "source_id": "collector",
        "session_id": "batch",
        "alerts": [
            {
                "event_type": "gateway.tool_call.allowed",
                "event_id": event_id,
                "event_timestamp": datetime.now(timezone.utc).isoformat(),
                "agent_id": "agent",
                "tool": "read_file",
                "upstream": "files",
                "decision": "allow",
                "policy_source": "reported",
                "source_id": "runtime-a",
                "session_id": "runtime-session",
                "tenant_id": "tenant-b",
                "producer_assurance": "verified",
                "submission_provenance": {"producer_assurance": "verified", "submitter_principal_id": "forged"},
            }
        ],
        "summary": {
            "source_id": "runtime-summary",
            "session_id": "summary-session",
            "producer_assurance": "verified",
            "total_tool_calls": 1,
        },
    }


def post(boundary, payload, who="analyst"):
    client, _, _, tokens = boundary
    return client.post("/v1/proxy/audit", headers={"Authorization": "Bearer " + tokens[who]}, json=payload)


def test_canonical_submission_and_reported_origins_match_all_projections(boundary):
    assert post(boundary, body()).status_code == 200
    _, ledger, events, _ = boundary
    ring = proxy._load_proxy_alerts("tenant-a")[0]
    stored = ledger.list_activity("tenant-a").events[0]
    for row in (ring, stored, events[0], proxy._runtime_metrics_for_tenant("tenant-a")):
        assert row["source_id"] == "collector" and row["session_id"] == "batch"
        assert row["tenant_id"] == "tenant-a"
        p = row["submission_provenance"]
        p = p.model_dump() if hasattr(p, "model_dump") else p
        assert p["producer_assurance"] == "caller_asserted"
        assert p["submitter_principal_id"] == "principal-analyst"
        assert p["authentication_method"] == "api_key"
        assert p["reported_source_id"].startswith("runtime-")
        assert "forged" not in str(p)
    assert ring["producer_assurance"] == "caller_asserted"
    assert ledger.list_activity("tenant-b").events == []
    assert post(boundary, body("viewer"), who="viewer").status_code == 403


def test_multi_source_relay_batch_keeps_distinct_reported_origins(boundary):
    payload = body()
    second = dict(payload["alerts"][0], event_id="second", source_id="runtime-b", session_id="session-b")
    payload["alerts"].append(second)
    assert post(boundary, payload).status_code == 200
    rows = boundary[1].list_activity("tenant-a").events
    assert [row["submission_provenance"]["reported_source_id"] for row in rows] == ["runtime-a", "runtime-b"]
    assert {row["source_id"] for row in rows} == {"collector"}


def test_changed_actor_or_claim_is_not_a_duplicate(boundary):
    payload = body()
    assert post(boundary, payload).json()["durable_accepted_count"] == 1
    assert post(boundary, payload).json()["durable_duplicate_count"] == 1
    assert post(boundary, payload, who="other").json()["durable_conflict_count"] == 1
    payload["alerts"][0]["source_id"] = "changed-runtime"
    assert post(boundary, payload).json()["durable_conflict_count"] == 1


def test_legacy_retry_preserves_original_unknown_record(boundary):
    from agent_bom.api.routes.proxy import _gateway_activity_record_from_alert

    payload = body()
    payload["alerts"][0].pop("source_id")
    payload["alerts"][0].pop("session_id")
    legacy = _gateway_activity_record_from_alert(
        payload["alerts"][0],
        tenant_id="tenant-a",
        source_id="collector",
        session_id="batch",
        received_at=datetime.now(timezone.utc),
        request_trace_id="",
    )
    boundary[1].append_batch([legacy])
    assert post(boundary, payload).json()["durable_duplicate_count"] == 1
    stored = boundary[1].list_activity("tenant-a").events[0]
    assert stored["record_schema_version"] == "gateway.activity.record.v1"
    assert stored["event_digest"] == legacy.event_digest
    assert "submission_provenance" not in stored
    assert proxy._load_proxy_alerts("tenant-a") == []
    assert boundary[2] == []
    payload["alerts"][0]["source_id"] = "historically-unknown-origin"
    assert post(boundary, payload).json()["durable_conflict_count"] == 1
    payload["alerts"][0].pop("source_id")
    payload["alerts"][0]["tool"] = "different_tool"
    assert post(boundary, payload).json()["durable_conflict_count"] == 1


def test_idempotency_cache_cannot_replay_another_submitter(boundary):
    payload = body("idempotent")
    payload["idempotency_key"] = "same-request"
    assert post(boundary, payload).status_code == 200
    assert post(boundary, payload).json()["idempotent_replay"] is True
    assert post(boundary, payload, who="other").status_code == 409


def test_in_process_untyped_metadata_cannot_self_attest():
    forged = {"tenant_id": "tenant-a", "producer_assurance": "verified", "submission_provenance": {"producer_assurance": "verified"}}
    proxy.push_proxy_alert(forged)
    proxy.push_proxy_metrics(forged)
    for row in (proxy._load_proxy_alerts("tenant-a")[-1], proxy._runtime_metrics_for_tenant("tenant-a")):
        assert row["producer_assurance"] == "unknown"
        assert "submission_provenance" not in row


def test_missing_stable_principal_stays_unknown_despite_body_assertion(boundary):
    payload = body("legacy-key")
    payload["alerts"][0]["principal_id"] = "forged-person"
    payload["alerts"][0]["submitter_principal_id"] = "forged-person"
    assert post(boundary, payload, who="legacy").status_code == 200
    metadata = boundary[1].list_activity("tenant-a").events[0]["submission_provenance"]
    assert metadata["submitter_principal_id"] == ""
    assert metadata["authentication_method"] == "api_key"
    assert metadata["producer_assurance"] == "caller_asserted"


def test_invalid_summary_context_does_not_partially_commit_alerts(boundary):
    payload = body("invalid-summary")
    payload["summary"]["source_id"] = "x" * 201
    assert post(boundary, payload).status_code == 422
    assert boundary[1].list_activity("tenant-a").events == []
    assert proxy._load_proxy_alerts("tenant-a") == []


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_v1_tombstone_replay_is_conservative_across_store_backends(backend, tmp_path):
    from dataclasses import replace

    from agent_bom.api.gateway_activity_store import GatewayActivityConflictError, InMemoryGatewayActivityStore, _digest_payload
    from agent_bom.api.proxy_provenance import GatewaySubmissionProvenance

    store = (
        InMemoryGatewayActivityStore(max_events_per_tenant=1)
        if backend == "memory"
        else SQLiteGatewayActivityStore(str(tmp_path / "bounded.db"), max_events_per_tenant=1)
    )
    payload = body("original")["alerts"][0]
    old = proxy._gateway_activity_record_from_alert(
        payload,
        tenant_id="tenant-a",
        source_id="collector",
        session_id="batch",
        received_at=datetime.now(timezone.utc),
        request_trace_id="",
    )
    store.append_batch([old])
    later = replace(old, event_id="later", decision_id="later")
    store.append_batch([replace(later, event_digest=_digest_payload(later))])
    metadata = GatewaySubmissionProvenance(
        submission_source_id="collector", submission_session_id="batch", producer_assurance="caller_asserted"
    )
    upgraded = replace(old, record_schema_version="gateway.activity.record.v2", submission_provenance=metadata)
    upgraded = replace(upgraded, event_digest=_digest_payload(upgraded))
    assert store.append_batch([upgraded]).duplicate_event_ids == ("original",)
    changed = replace(upgraded, tool="changed")
    with pytest.raises(GatewayActivityConflictError):
        store.append_batch([replace(changed, event_digest=_digest_payload(changed))])
    assert [row["event_id"] for row in store.list_activity("tenant-a").events] == ["later"]


def test_reported_credentials_do_not_survive_any_projection(boundary):
    import json

    marker = "ghp_" + "A" * 36
    payload = body("redaction")
    payload["alerts"][0].update(source_id=marker, session_id=marker)
    payload["summary"].update(source_id=marker, session_id=marker)
    assert post(boundary, payload).status_code == 200
    _, ledger, analytics, _ = boundary
    for row in [
        *proxy._load_proxy_alerts("tenant-a"),
        *ledger.list_activity("tenant-a").events,
        *analytics,
        proxy._runtime_metrics_for_tenant("tenant-a"),
    ]:
        metadata = row["submission_provenance"]
        metadata = metadata.model_dump() if hasattr(metadata, "model_dump") else metadata
        if marker in json.dumps(metadata):
            pytest.fail("synthetic credential marker persisted")


def test_verified_sensitive_principals_have_distinct_safe_pseudonyms():
    from agent_bom.api.proxy_provenance import GatewaySubmissionProvenance

    first = GatewaySubmissionProvenance(
        submission_source_id="collector", submission_session_id="batch", submitter_principal_id="alice@example.test"
    )
    second = GatewaySubmissionProvenance(
        submission_source_id="collector", submission_session_id="batch", submitter_principal_id="amy@example.test"
    )
    assert first.submitter_principal_id.startswith("principal-sha256:")
    assert first.submitter_principal_id != second.submitter_principal_id
    assert "@" not in first.submitter_principal_id


def test_typed_model_copy_does_not_bypass_persistence_redaction():
    import json

    from agent_bom.api.clickhouse_store import ClickHouseAnalyticsStore
    from agent_bom.api.proxy_provenance import GatewaySubmissionProvenance

    marker = "ghp_" + "B" * 36
    typed = GatewaySubmissionProvenance(submission_source_id="collector", submission_session_id="batch").model_copy(
        update={"reported_source_id": marker}
    )
    row = object.__new__(ClickHouseAnalyticsStore)._event_row({"event_id": "copy", "submission_provenance": typed})
    if marker in row["submission_provenance"]:
        pytest.fail("model copy bypassed analytics redaction")
    proxy.push_proxy_alert({"tenant_id": "copy"}, submission_provenance=typed)
    if marker in json.dumps(proxy._load_proxy_alerts("copy")[-1]):
        pytest.fail("model copy bypassed ring redaction")
    forged = typed.model_copy(update={"producer_assurance": "verified"})
    with pytest.raises(ValueError):
        object.__new__(ClickHouseAnalyticsStore)._event_row({"event_id": "forged", "submission_provenance": forged})


@pytest.mark.parametrize("source", ["reported", "legacy", "empty"])
def test_metrics_websocket_preserves_http_receipt_health_and_assurance(boundary, source, monkeypatch):
    from agent_bom.api.server import configure_api

    monkeypatch.delenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", raising=False)
    configure_api(api_key=None, allow_unauthenticated=False)
    client, _, _, tokens = boundary
    client.app.include_router(proxy.ws_router)
    if source == "reported":
        assert post(boundary, body()).status_code == 200
    elif source == "legacy":
        proxy.push_proxy_metrics({"tenant_id": "tenant-a", "total_tool_calls": 1, "source_id": "legacy", "session_id": "batch"})
    headers = {"Authorization": "Bearer " + tokens["analyst"]}
    status = client.get("/v1/proxy/status", headers=headers)
    assert status.status_code == 200
    with client.websocket_connect("/ws/proxy/metrics", headers=headers) as socket:
        snapshot = socket.receive_json()
    expected = status.json()
    assert snapshot["producer_assurance"] == expected["producer_assurance"]
    for field in ("assurance_basis", "producer_assurance", "state", "live", "heartbeat_at", "stale_after_seconds", "reason"):
        assert snapshot["health"][field] == expected["health"][field]
    assert snapshot["producer_assurance"] == ("caller_asserted" if source == "reported" else "unknown")
    assert snapshot["total_tool_calls"] == (0 if source == "empty" else 1)


def test_metrics_websocket_does_not_copy_another_tenants_assurance(boundary, monkeypatch):
    from agent_bom.api.auth import get_key_store
    from agent_bom.api.server import configure_api

    monkeypatch.delenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", raising=False)
    configure_api(api_key=None, allow_unauthenticated=False)

    client, _, _, _ = boundary
    client.app.include_router(proxy.ws_router)
    assert post(boundary, body()).status_code == 200
    token, key = create_api_key("other-tenant", Role.ANALYST, tenant_id="tenant-b", principal_id="principal-b")
    get_key_store().add(key)
    with client.websocket_connect("/ws/proxy/metrics", headers={"Authorization": "Bearer " + token}) as socket:
        snapshot = socket.receive_json()
    assert snapshot["total_tool_calls"] == 0
    assert snapshot["producer_assurance"] == "unknown"
    assert snapshot["health"]["state"] == "unavailable"
    assert snapshot["health"]["heartbeat_at"] is None


@pytest.mark.parametrize("producer_trace", [None, "producer-trace"])
def test_request_trace_is_receipt_metadata_not_event_identity(boundary, producer_trace):
    import json

    payload = body("trace-retry")
    payload["alerts"][0]["receipt_trace_id"] = "forged-receipt"
    if producer_trace is not None:
        payload["alerts"][0]["trace_id"] = producer_trace
    first = post(boundary, payload)
    assert first.status_code == 200
    ledger = boundary[1]
    original = ledger.list_activity("tenant-a").events[0]
    original_json = json.dumps(original, sort_keys=True)
    second = post(boundary, payload)
    assert second.json()["durable_duplicate_count"] == 1
    assert second.json()["durable_conflict_count"] == 0
    assert original["trace_id"] == (producer_trace or "trace-retry")
    assert original["receipt_trace_id"] == first.headers["X-Trace-ID"]
    assert second.headers["X-Trace-ID"] != first.headers["X-Trace-ID"]
    assert original["receipt_trace_id"] != original["trace_id"]
    assert json.dumps(ledger.list_activity("tenant-a").events[0], sort_keys=True) == original_json
    reopened = SQLiteGatewayActivityStore(ledger.db_path)
    assert json.dumps(reopened.list_activity("tenant-a").events[0], sort_keys=True) == original_json
    payload["alerts"][0]["trace_id"] = "changed-producer-trace"
    assert post(boundary, payload).json()["durable_conflict_count"] == 1
    if producer_trace is None:
        payload["alerts"][0].pop("trace_id")
    else:
        payload["alerts"][0]["trace_id"] = producer_trace
    payload["alerts"][0]["tool"] = "different_tool"
    assert post(boundary, payload).json()["durable_conflict_count"] == 1
    assert json.dumps(ledger.list_activity("tenant-a").events[0], sort_keys=True) == original_json
