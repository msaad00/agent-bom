"""Governance webhooks: subscription store, dispatch, API, and emit wiring."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from agent_bom.api.webhook_store import (
    InMemoryWebhookSubscriptionStore,
    WebhookSubscription,
    create_subscription,
    emit_governance_event,
    set_subscription_status,
    set_webhook_subscription_store,
)


class _FakeOutbox:
    def __init__(self):
        self.enqueued = []

    def enqueue(self, event, destination):
        self.enqueued.append((event, destination))
        return len(self.enqueued)


@pytest.fixture()
def sub_store():
    store = InMemoryWebhookSubscriptionStore()
    set_webhook_subscription_store(store)
    try:
        yield store
    finally:
        set_webhook_subscription_store(None)


# ── store + filtering ───────────────────────────────────────────────────────


def test_wants_filters_by_event_type_and_status():
    sub = WebhookSubscription(
        subscription_id="s1", tenant_id="t1", url="https://x/y", signing_secret="z", event_types=["drift.detected", "identity.*"]
    )
    assert sub.wants("drift.detected")
    assert sub.wants("identity.revoked")  # wildcard prefix
    assert not sub.wants("budget.exceeded")
    sub.status = "disabled"
    assert not sub.wants("drift.detected")

    catch_all = WebhookSubscription(subscription_id="s2", tenant_id="t1", url="https://x/y", signing_secret="z", event_types=[])
    assert catch_all.wants("anything.at.all")


def test_create_subscription_validates_url_and_masks_secret(sub_store):
    secret_url = "https://hooks.example.com/services/T000/B111/SUPERSECRET?token=ALSOSECRET"
    sub = create_subscription(sub_store, tenant_id="t1", url=secret_url, event_types=["drift.detected"])
    assert sub.signing_secret.startswith("whsec_")
    public = sub.to_public_dict()
    assert "signing_secret" not in public
    assert public["secret_fingerprint"]
    assert public["url"].startswith("https://hooks.example.com/")
    assert "SUPERSECRET" not in public["url"]
    assert "ALSOSECRET" not in public["url"]
    assert public["url"] != secret_url
    # SSRF: localhost is rejected unless allow_private_networks.
    with pytest.raises(ValueError):
        create_subscription(sub_store, tenant_id="t1", url="http://localhost:9999/in")


def test_emit_enqueues_only_matching_subscriptions(sub_store):
    create_subscription(sub_store, tenant_id="t1", url="https://a.example.com/h", event_types=["drift.detected"])
    create_subscription(sub_store, tenant_id="t1", url="https://b.example.com/h", event_types=["budget.exceeded"])
    create_subscription(sub_store, tenant_id="t1", url="https://c.example.com/h", event_types=[])  # catch-all
    create_subscription(sub_store, tenant_id="other", url="https://d.example.com/h", event_types=["drift.detected"])

    outbox = _FakeOutbox()
    n = emit_governance_event(
        event_type="drift.detected",
        tenant_id="t1",
        source="test",
        payload={"incident_id": "inc1"},
        store=sub_store,
        outbox=outbox,
    )
    # drift-only + catch-all in tenant t1 → 2; the budget-only and other-tenant subs excluded.
    assert n == 2
    urls = {d.url for _e, d in outbox.enqueued}
    assert urls == {"https://a.example.com/h", "https://c.example.com/h"}


def test_emit_is_best_effort_when_no_subscriptions(sub_store):
    outbox = _FakeOutbox()
    assert emit_governance_event(event_type="drift.detected", tenant_id="t1", source="t", payload={}, store=sub_store, outbox=outbox) == 0
    assert outbox.enqueued == []


def test_disable_stops_matching(sub_store):
    sub = create_subscription(sub_store, tenant_id="t1", url="https://a.example.com/h", event_types=["drift.detected"])
    set_subscription_status(sub_store, sub.subscription_id, status="disabled")
    outbox = _FakeOutbox()
    assert emit_governance_event(event_type="drift.detected", tenant_id="t1", source="t", payload={}, store=sub_store, outbox=outbox) == 0


# ── API ──────────────────────────────────────────────────────────────────────


@pytest.fixture()
def client(sub_store):
    from agent_bom.api.server import app

    return TestClient(app)


def test_webhook_api_crud(client):
    created = client.post(
        "/v1/webhooks", json={"url": "https://hooks.example.com/in", "event_types": ["drift.detected", "identity.revoked"]}
    )
    assert created.status_code == 201, created.text
    body = created.json()
    sid = body["subscription"]["subscription_id"]
    assert body["signing_secret"].startswith("whsec_")
    assert "signing_secret" not in body["subscription"]

    listed = client.get("/v1/webhooks").json()
    assert listed["count"] == 1
    assert "drift.detected" in listed["event_catalog"]

    assert client.post(f"/v1/webhooks/{sid}/disable").json()["subscription"]["status"] == "disabled"
    assert client.get("/v1/webhooks").json()["count"] == 0
    assert client.get("/v1/webhooks?include_disabled=true").json()["count"] == 1
    assert client.post(f"/v1/webhooks/{sid}/enable").json()["subscription"]["status"] == "active"

    assert client.delete(f"/v1/webhooks/{sid}").json()["deleted"] is True
    assert client.get(f"/v1/webhooks/{sid}").status_code == 404


def test_webhook_create_audit_log_omits_secret_url(client):
    """A webhook URL can be the secret itself (Slack-style incoming webhooks put
    the token in the path); the persisted audit entry must never contain the
    cleartext secret. The route redacts the URL (defense in depth) and the
    evidence-tier policy independently drops URL-valued fields."""
    from agent_bom.api.audit_log import get_audit_log

    secret_url = "https://hooks.example.com/services/T00000/B11111/SUPERSECRETTOKEN999"
    created = client.post("/v1/webhooks", json={"url": secret_url, "event_types": ["drift.detected"]})
    assert created.status_code == 201, created.text

    entries = get_audit_log().list_entries(limit=50)
    created_entries = [e for e in entries if e.action == "webhook.subscription_created"]
    assert created_entries, "expected a webhook.subscription_created audit entry"
    blob = " ".join(str(e.to_dict()) for e in created_entries)
    assert "SUPERSECRETTOKEN999" not in blob
    assert "services/T00000" not in blob


def test_webhook_api_rejects_unknown_event_and_bad_url(client):
    assert client.post("/v1/webhooks", json={"url": "https://x.example.com/h", "event_types": ["nope.bad"]}).status_code == 400
    assert client.post("/v1/webhooks", json={"url": "http://169.254.169.254/latest"}).status_code == 400
    assert client.post("/v1/webhooks", json={}).status_code == 400


def test_identity_revoke_emits_webhook(client):
    # Register a catch-all subscription, then revoke an identity and confirm a
    # delivery was queued to the durable outbox for this tenant.
    import agent_bom.posture_streaming as ps
    from agent_bom.posture_streaming import WebhookOutbox

    captured = []

    class _CaptureOutbox(WebhookOutbox):  # type: ignore[misc]
        def __init__(self):
            pass

        def enqueue(self, event, destination):
            captured.append((event.event_type, destination.url))
            return len(captured)

    original = ps.default_webhook_outbox
    ps.default_webhook_outbox = lambda: _CaptureOutbox()  # type: ignore[assignment]
    try:
        client.post("/v1/webhooks", json={"url": "https://hooks.example.com/in", "event_types": []})
        issued = client.post("/v1/identities", json={"agent_id": "agent-a"})
        iid = issued.json()["identity"]["identity_id"]
        client.post(f"/v1/identities/{iid}/revoke", json={"reason": "test"})
        assert any(evt == "identity.revoked" for evt, _url in captured)
    finally:
        ps.default_webhook_outbox = original
