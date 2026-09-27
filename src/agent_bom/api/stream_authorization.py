"""Bound the lifetime of cached authorization on long-lived API streams."""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import suppress
from typing import Any

from starlette.requests import Request
from starlette.responses import Response

STREAM_RECHECK_SECONDS = 5.0
_CHECK_TIMEOUT_SECONDS = 5.0
_RECONNECT_EVENT = {"event": "reconnect", "data": '{"reason":"reauthenticate"}'}


class StreamAuthorization:
    """One bounded lease per connection; failed checks remain terminal."""

    def __init__(self, check: Callable[[], Awaitable[bool]]) -> None:
        self._check = check
        self._next_check = time.monotonic() + STREAM_RECHECK_SECONDS
        self._allowed = True

    async def allowed(self) -> bool:
        if not self._allowed:
            return False
        if time.monotonic() < self._next_check:
            return True
        try:
            self._allowed = await asyncio.wait_for(self._check(), timeout=_CHECK_TIMEOUT_SECONDS)
        except Exception:  # noqa: BLE001 - storage/identity failures terminate without exposing details
            self._allowed = False
        self._next_check = time.monotonic() + STREAM_RECHECK_SECONDS
        return self._allowed


def bind_http_stream_authorization(request: Request, authenticate: Callable[..., Awaitable[Response]]) -> None:
    """Re-run the owning auth resolver against credentials, never stale state."""
    if request.scope.get("_stream_reauthentication") or not request.url.path.endswith("/stream"):
        return
    identity = _identity(request)
    scope = dict(request.scope)
    scope.pop("state", None)
    scope["_stream_reauthentication"] = True

    async def check() -> bool:
        fresh = Request({**scope, "state": {}})
        accepted = False

        async def compare(resolved: Request) -> Response:
            nonlocal accepted
            accepted = _identity(resolved) == identity
            return Response(status_code=204)

        response = await authenticate(fresh, compare)
        return response.status_code == 204 and accepted

    request.state.stream_authorization = StreamAuthorization(check)


def _identity(request: Request) -> tuple[Any, ...]:
    return tuple(getattr(request.state, key, None) for key in ("tenant_id", "auth_method", "api_key_id", "api_key_name", "api_key_role"))


async def authorized_events(request: Request, events: AsyncIterator[dict[str, Any]]) -> AsyncIterator[dict[str, Any]]:
    """Check idle streams and slow page reads as well as outgoing data frames."""
    lease = getattr(request.state, "stream_authorization", None)
    pending: asyncio.Future[dict[str, Any]] | None = None
    try:
        if not isinstance(lease, StreamAuthorization):
            yield dict(_RECONNECT_EVENT)
            return
        while await lease.allowed():
            pending = asyncio.ensure_future(anext(events))
            while True:
                done, _ = await asyncio.wait({pending}, timeout=STREAM_RECHECK_SECONDS)
                if not await lease.allowed():
                    yield dict(_RECONNECT_EVENT)
                    return
                if done:
                    break
            try:
                event = pending.result()
            except StopAsyncIteration:
                return
            pending = None
            yield event
        yield dict(_RECONNECT_EVENT)
    finally:
        if pending is not None:
            pending.cancel()
            with suppress(asyncio.CancelledError, Exception):
                await pending
        close = getattr(events, "aclose", None)
        if close is not None:
            await close()
