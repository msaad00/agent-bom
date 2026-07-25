"""Key verification never runs on the event loop.

``KeyStore.verify`` performs a deliberately expensive scrypt derivation (or a
blocking DB read on the Postgres store). Both surfaces below are reachable
*before* a caller is authenticated, so running verification inline lets an
unauthenticated client stall the loop on demand.
"""

from __future__ import annotations

import asyncio
import threading
import time
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

_BLOCKING_SECONDS = 0.4
_TICK_SECONDS = 0.01
_MIN_TICKS_WHILE_OFFLOADED = 5


def _slow_key_store() -> MagicMock:
    store = MagicMock()
    store.has_keys.return_value = True

    def _slow_verify(_raw: str) -> None:
        time.sleep(_BLOCKING_SECONDS)
        return None

    store.verify.side_effect = _slow_verify
    return store


@pytest.mark.asyncio
async def test_browser_session_verify_keeps_the_loop_responsive() -> None:
    """POST /v1/auth/browser-session is auth-exempt — it must not block."""
    import httpx

    from agent_bom.api.server import app

    ticks = 0

    async def heartbeat() -> None:
        nonlocal ticks
        while True:
            await asyncio.sleep(_TICK_SECONDS)
            ticks += 1

    with patch("agent_bom.api.auth.get_key_store", return_value=_slow_key_store()):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            beat = asyncio.create_task(heartbeat())
            await asyncio.sleep(_TICK_SECONDS * 2)
            before = ticks
            await client.post("/v1/auth/session", json={"api_key": "abom_whatever"})
            observed = ticks - before
            beat.cancel()

    assert observed >= _MIN_TICKS_WHILE_OFFLOADED, (
        f"event loop advanced only {observed} tick(s) during a {_BLOCKING_SECONDS}s scrypt verify — it ran inline"
    )


@pytest.mark.asyncio
async def test_websocket_handshake_verifies_off_the_loop_thread() -> None:
    """The pre-auth WebSocket handshake offloads verification too."""
    from agent_bom.api.routes import proxy

    loop_thread = threading.get_ident()
    seen: dict[str, Any] = {}

    def _record(_token: str, *, bearer: bool = True) -> None:
        seen["thread"] = threading.get_ident()
        return None

    class _FakeWebSocket:
        headers = {"authorization": "Bearer abom_whatever"}
        query_params: dict[str, str] = {}

        async def accept(self) -> None:
            return None

        async def receive_json(self) -> dict[str, Any]:
            raise asyncio.CancelledError

        async def close(self, code: int = 1000) -> None:
            return None

    with (
        patch.object(proxy, "_ws_auth_from_token", _record),
        patch.object(proxy, "_ws_auth_required", return_value=True),
        patch.object(proxy, "_ws_auth_from_trusted_proxy", return_value=None),
    ):
        try:
            await proxy._ws_accept_and_check_auth(_FakeWebSocket())  # type: ignore[arg-type]
        except (asyncio.CancelledError, Exception):
            pass

    assert seen.get("thread") is not None, "verification was never invoked"
    assert seen["thread"] != loop_thread, "key verification ran on the event loop thread"
