"""Tests for posture-event webhook outbox streaming."""

from __future__ import annotations

import hmac
import json

import pytest

from agent_bom.posture_streaming import (
    PostureEvent,
    WebhookDestination,
    WebhookOutbox,
    deliver_due_webhooks,
    signed_webhook_headers,
)


def test_posture_event_redacts_sensitive_payload_and_is_idempotent():
    event_a = PostureEvent(
        event_type="finding.created",
        tenant_id="tenant-a",
        source="test",
        subject_id="finding-1",
        payload={"api_token": "ghp_abcdefghijklmnopqrstuvwxyz123456", "severity": "high"},
    )
    event_b = PostureEvent(
        event_type="finding.created",
        tenant_id="tenant-a",
        source="test",
        subject_id="finding-1",
        payload={"api_token": "ghp_abcdefghijklmnopqrstuvwxyz123456", "severity": "high"},
    )

    assert event_a.event_id == event_b.event_id
    assert event_a.payload["api_token"] == "***REDACTED***"
    assert "abcdefghijklmnopqrstuvwxyz" not in json.dumps(event_a.to_dict())
    assert event_a.idempotency_key == f"tenant-a:{event_a.event_id}"


def test_webhook_outbox_enforces_tenant_scope_and_deduplicates(tmp_path):
    outbox = WebhookOutbox(tmp_path / "outbox.db")
    event = PostureEvent(event_type="exposure_path.changed", tenant_id="tenant-a", source="graph", payload={"path_id": "p1"})
    destination = WebhookDestination(
        destination_id="siem",
        tenant_id="tenant-a",
        url="https://siem.example.test/webhook",
        signing_secret="secret",
    )

    first_id = outbox.enqueue(event, destination)
    second_id = outbox.enqueue(event, destination)

    assert first_id == second_id
    assert len(outbox.due(tenant_id="tenant-a", now=event.created_at + 1)) == 1
    assert outbox.due(tenant_id="tenant-b", now=event.created_at + 1) == []

    wrong_tenant = WebhookDestination(
        destination_id="siem",
        tenant_id="tenant-b",
        url="https://siem.example.test/webhook",
        signing_secret="secret",
    )
    with pytest.raises(ValueError, match="tenant_id"):
        outbox.enqueue(event, wrong_tenant)


def test_webhook_destination_rejects_unsafe_urls():
    with pytest.raises(ValueError, match="https"):
        WebhookDestination(destination_id="bad", tenant_id="tenant-a", url="http://example.test/hook", signing_secret="secret")
    with pytest.raises(ValueError, match="credentials"):
        WebhookDestination(destination_id="bad", tenant_id="tenant-a", url="https://user:pass@example.test/hook", signing_secret="secret")
    with pytest.raises(ValueError, match="private networks"):
        WebhookDestination(destination_id="bad", tenant_id="tenant-a", url="https://localhost/hook", signing_secret="secret")
    with pytest.raises(ValueError, match="private networks"):
        WebhookDestination(destination_id="bad", tenant_id="tenant-a", url="https://10.0.0.5/hook", signing_secret="secret")

    destination = WebhookDestination(
        destination_id="internal-siem",
        tenant_id="tenant-a",
        url="https://10.0.0.5/hook",
        signing_secret="secret",
        allow_private_networks=True,
    )
    assert destination.url == "https://10.0.0.5/hook"


def test_signed_headers_are_verifiable():
    event = PostureEvent(event_type="skill.verdict", tenant_id="tenant-a", source="skills", payload={"verdict": "review"})
    destination = WebhookDestination(
        destination_id="soc",
        tenant_id="tenant-a",
        url="https://soc.example.test/webhook",
        signing_secret="top-secret",
    )

    headers = signed_webhook_headers(event, destination, attempt=3)

    assert headers["x-agent-bom-event-id"] == event.event_id
    assert headers["x-agent-bom-tenant-id"] == "tenant-a"
    assert headers["x-agent-bom-delivery-attempt"] == "3"
    expected = hmac.new(
        b"top-secret",
        json.dumps(event.to_dict(), sort_keys=True, separators=(",", ":"), default=str).encode("utf-8"),
        "sha256",
    ).hexdigest()
    assert headers["x-agent-bom-signature"] == f"sha256={expected}"


@pytest.mark.asyncio
async def test_deliver_due_webhooks_marks_success(tmp_path):
    outbox = WebhookOutbox(tmp_path / "outbox.db")
    event = PostureEvent(event_type="deploy.decision", tenant_id="tenant-a", source="mcp", payload={"decision": "warn"})
    destination = WebhookDestination(
        destination_id="agent-queue",
        tenant_id="tenant-a",
        url="https://queue.example.test/webhook",
        signing_secret="secret",
    )
    outbox.enqueue(event, destination)
    sent = []

    async def sender(url, headers, payload):
        sent.append((url, headers, payload))
        return 202

    result = await deliver_due_webhooks(outbox, destination=destination, sender=sender, now=event.created_at + 1)

    assert result == {"delivered": 1, "failed": 0, "dead_lettered": 0}
    assert sent[0][0] == destination.url
    assert outbox.due(tenant_id="tenant-a", now=event.created_at + 2) == []


@pytest.mark.asyncio
async def test_deliver_due_webhooks_tracks_retry_and_dead_letter(tmp_path):
    outbox = WebhookOutbox(tmp_path / "outbox.db")
    event = PostureEvent(event_type="audit.delta", tenant_id="tenant-a", source="audit", payload={"status": "tampered"})
    destination = WebhookDestination(
        destination_id="soc",
        tenant_id="tenant-a",
        url="https://soc.example.test/webhook",
        signing_secret="secret",
    )
    outbox.enqueue(event, destination)

    async def sender(_url, _headers, _payload):
        return 500

    first = await deliver_due_webhooks(
        outbox,
        destination=destination,
        sender=sender,
        now=event.created_at + 1,
        max_attempts=2,
    )
    assert first == {"delivered": 0, "failed": 1, "dead_lettered": 0}
    retry = outbox.due(tenant_id="tenant-a", now=event.created_at + 1.5)
    assert retry == []
    retry = outbox.due(tenant_id="tenant-a", now=event.created_at + 2)
    assert retry[0].attempts == 1
    assert "HTTP 500" in retry[0].last_error

    second = await deliver_due_webhooks(
        outbox,
        destination=destination,
        sender=sender,
        now=event.created_at + 2,
        max_attempts=2,
    )
    assert second == {"delivered": 0, "failed": 1, "dead_lettered": 1}
    assert outbox.due(tenant_id="tenant-a", now=event.created_at + 100) == []
