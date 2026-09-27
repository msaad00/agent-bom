"""SSE transport adapter for live HTTP authorization leases."""

from collections.abc import AsyncIterator
from typing import Any

from sse_starlette.sse import EventSourceResponse
from starlette.requests import Request
from starlette.types import Receive, Scope, Send

from agent_bom.api.stream_authorization import authorized_events

_STREAM_SEND_TIMEOUT_SECONDS = 5.0


class AuthorizedEventSourceResponse(EventSourceResponse):
    body_iterator: AsyncIterator[dict[str, Any]]

    def __init__(self, content: Any, status_code: int = 200, **kwargs: Any) -> None:
        kwargs.setdefault("send_timeout", _STREAM_SEND_TIMEOUT_SECONDS)
        super().__init__(content, status_code=status_code, **kwargs)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        self.body_iterator = authorized_events(Request(scope), self.body_iterator)
        await super().__call__(scope, receive, send)
