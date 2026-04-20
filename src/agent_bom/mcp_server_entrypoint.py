"""Entry-point helpers for the agent-bom MCP server."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


def create_smithery_server(factory: Callable[[], Any]) -> Any:
    """Return a Smithery-decorated MCP server when the SDK is installed."""
    try:
        from smithery.decorators import smithery

        @smithery.server()
        def _factory():
            return factory()

        return _factory()
    except ImportError:
        return factory()
