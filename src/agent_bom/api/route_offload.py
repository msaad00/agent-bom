"""Call a sync API route handler from async code without blocking the loop.

Await-free route handlers are plain ``def`` so FastAPI runs them in its
threadpool. Non-HTTP callers (MCP tools) that reuse those handlers must do the
same instead of calling them on the event loop.
"""

from __future__ import annotations

from asyncio import to_thread
from typing import Any


async def call_route(handler: Any, request: object, *args: Any, **kwargs: Any) -> Any:
    """Run ``handler(request, *args, **kwargs)`` in a worker thread."""
    return await to_thread(handler, request, *args, **kwargs)
