"""Resolve MCP identity only from the SDK's verified authentication boundary."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mcp.server.auth.provider import AccessToken


def verified_access_token(context: Any) -> AccessToken | None:
    """Prefer the current HTTP message over a transport task's ambient context.

    Streamable HTTP dispatch can run in a long-lived session task, so its
    ContextVars need not describe the current message. An unauthenticated HTTP
    request must never inherit a token from that task. Older transports without
    a request object use the SDK's authenticated context, never tool metadata.
    """
    from mcp.server.auth.middleware.auth_context import get_access_token
    from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser

    request = getattr(context, "request", None)
    if request is not None:
        user = getattr(request, "scope", {}).get("user")
        token = user.access_token if isinstance(user, AuthenticatedUser) else None
    else:
        token = get_access_token()
    if token is not None and token.expires_at is not None and token.expires_at <= time.time():
        return None
    return token
