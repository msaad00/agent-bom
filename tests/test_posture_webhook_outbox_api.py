"""API tests for posture webhook outbox observability."""

from __future__ import annotations

from pathlib import Path

from starlette.testclient import TestClient

from agent_bom.api.routes.posture_streaming import set_posture_webhook_outbox
from agent_bom.api.server import app
from agent_bom.posture_streaming import PostureEvent, WebhookDestination, WebhookOutbox
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()


def teardown_function() -> None:
    set_posture_webhook_outbox(None)


def _client(tenant: str = "tenant-alpha", role: str = "analyst") -> TestClient:
    client = TestClient(app)
    client.headers.update(proxy_headers(role=role, tenant=tenant))
    return client


def _seed_outbox(path: Path, tenant: str = "tenant-alpha") -> tuple[WebhookOutbox, int]:
    outbox = WebhookOutbox(path)
    event = PostureEvent(
        event_type="finding.created",
        tenant_id=tenant,
        source="test",
        subject_id="finding-1",
        payload={"id": "finding-1", "severity": "high"},
    )
    destination = WebhookDestination(
        destination_id="siem",
        tenant_id=tenant,
        url="https://siem.example.test/webhook/SUPERSECRET?token=ALSOSECRET",
        signing_secret="secret",
    )
    row_id = outbox.enqueue(event, destination)
    set_posture_webhook_outbox(outbox)
    return outbox, row_id


def test_outbox_stats_and_records_are_tenant_scoped(tmp_path: Path) -> None:
    _seed_outbox(tmp_path / "outbox.db", tenant="tenant-alpha")

    alpha = _client(tenant="tenant-alpha").get("/v1/posture/webhooks/outbox")
    beta = _client(tenant="tenant-beta").get("/v1/posture/webhooks/outbox")

    assert alpha.status_code == 200
    body = alpha.json()
    assert body["count"] == 1
    assert body["stats"]["by_status"] == {"pending": 1}
    assert body["records"][0]["destination_id"] == "siem"
    assert body["records"][0]["tenant_id"] == "tenant-alpha"
    assert body["records"][0]["url"].startswith("https://siem.example.test/")
    assert "SUPERSECRET" not in body["records"][0]["url"]
    assert "ALSOSECRET" not in body["records"][0]["url"]
    assert beta.json()["count"] == 0


def test_outbox_filter_and_stats_endpoint(tmp_path: Path) -> None:
    outbox, row_id = _seed_outbox(tmp_path / "outbox.db")
    outbox.mark_delivered(row_id, delivered_at=100.0)

    pending = _client().get("/v1/posture/webhooks/outbox?status=pending")
    delivered = _client().get("/v1/posture/webhooks/outbox?status=delivered")
    stats = _client().get("/v1/posture/webhooks/outbox/stats")

    assert pending.json()["count"] == 0
    assert delivered.json()["count"] == 1
    assert stats.json()["stats"]["by_status"] == {"delivered": 1}


def test_retry_dead_letter_requires_admin_and_current_tenant(tmp_path: Path) -> None:
    outbox, row_id = _seed_outbox(tmp_path / "outbox.db")
    outbox.mark_failed(row_id, error="network token abc123", retry_at=10.0, max_attempts=1)

    viewer = _client(role="analyst").post(f"/v1/posture/webhooks/outbox/{row_id}/retry")
    other_tenant = _client(tenant="tenant-beta", role="admin").post(f"/v1/posture/webhooks/outbox/{row_id}/retry")
    admin = _client(role="admin").post(f"/v1/posture/webhooks/outbox/{row_id}/retry")

    assert viewer.status_code == 403
    assert other_tenant.status_code == 404
    assert admin.status_code == 202
    assert admin.json()["status"] == "pending"
    assert outbox.stats(tenant_id="tenant-alpha")["by_status"] == {"pending": 1}
