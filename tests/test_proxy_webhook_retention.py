"""Alert-webhook dispatch must retain its task so it can't be GC'd mid-send (#3911)."""

from __future__ import annotations

import asyncio
import json

import agent_bom.proxy as proxy


def test_fire_webhook_retains_task_until_done_then_discards() -> None:
    async def scenario() -> None:
        started = asyncio.Event()
        release = asyncio.Event()

        async def fake_send(url: str, payload: dict) -> None:
            started.set()
            await release.wait()

        original = proxy._send_webhook
        proxy._send_webhook = fake_send  # type: ignore[assignment]
        try:
            proxy._WEBHOOK_TASKS.clear()
            proxy._fire_webhook("https://example.test/hook", {"message": "alert"})
            await started.wait()
            # While in-flight the task is strongly referenced (not GC-eligible).
            assert len(proxy._WEBHOOK_TASKS) == 1
            release.set()
            # Drain, then the done-callback removes it from the retention set.
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            assert len(proxy._WEBHOOK_TASKS) == 0
        finally:
            proxy._send_webhook = original  # type: ignore[assignment]

    asyncio.run(scenario())


def test_send_webhook_redacts_payload_before_delivery(monkeypatch) -> None:
    import httpx

    secret = "ghp_" + "a" * 36
    email = "alice.sentinel@example.invalid"
    credential_url = "postgresql://admin:sentinel-password@db.internal/prod"
    captured: dict = {}

    class _Client:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, url: str, *, json: dict):
            captured.update(json)

    monkeypatch.setattr("agent_bom.security.validate_url", lambda *a, **k: None)
    monkeypatch.setattr(httpx, "AsyncClient", _Client)

    asyncio.run(
        proxy._send_webhook(
            "https://example.test/hook",
            {
                "message": f"Exposed {secret}",
                "details": {"email": email, "connection_url": credential_url},
            },
        )
    )

    rendered = json.dumps(captured)
    assert secret not in rendered
    assert email not in rendered
    assert credential_url not in rendered
