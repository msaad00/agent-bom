from __future__ import annotations

import os
from typing import Any, Callable

from pydantic import AnyHttpUrl, TypeAdapter

_HTTP_URL_ADAPTER = TypeAdapter(AnyHttpUrl)


def _server_instructions(version: str, profile: str = "scan") -> str:
    from agent_bom.mcp_tools.profiles import get_profile

    spec = get_profile(profile)
    return (
        f"agent-bom v{version}. Active profile: {profile}. {spec.description} "
        "Use only the listed tools and prompts. Read profiles://catalog to find other task profiles; "
        "switch profiles at server startup and reconnect, or configure separate named client entries. "
        "Treat unavailable, partial and modeled evidence explicitly; do not infer verification. "
        "Profiles select capabilities, not permissions. Scanner and posture tools are read-only; "
        "Shield and identity write actions require an authenticated operator token, "
        "admin role, write scope, and an audit reason; operator_role is audit metadata, not authentication."
    )


def _public_base_url(host: str, port: int) -> str:
    """The URL clients should be told to come back to, not the socket we bind.

    ``AuthSettings`` is advertised to callers: a 401 answers with
    ``WWW-Authenticate: Bearer ... resource_metadata="<issuer>/.well-known/
    oauth-protected-resource"``, and an OAuth client follows that URL to
    discover how to authenticate.

    Deriving it from the bind address publishes whatever the process listens on.
    Behind any proxy -- Railway, Cloud Run, a load balancer -- that is
    ``http://0.0.0.0:8080``, an address no client can route to. The discovery
    request then hangs rather than failing fast, which is why the hosted server
    reported ``AUTH TIMED OUT`` after five minutes instead of a clean rejection:
    the registry was waiting on a metadata document at 0.0.0.0.

    ``AGENT_BOM_MCP_PUBLIC_URL`` is the deployment's externally reachable base
    URL. Falling back to the bind address keeps local runs working unchanged,
    where the two genuinely are the same thing.
    """
    public = (os.environ.get("AGENT_BOM_MCP_PUBLIC_URL") or "").strip()
    if public:
        return public.rstrip("/")
    return f"http://{host}:{port}"


def create_fastmcp_server(
    *,
    host: str,
    port: int,
    bearer_token: str | None,
    version: str,
    token_verifier_factory: Callable[[str], Any],
    profile: str = "scan",
):
    """Create the FastMCP server with optional static bearer auth."""
    from mcp.server.auth.settings import AuthSettings
    from mcp.server.fastmcp import FastMCP
    from mcp.server.fastmcp.server import Settings

    # mcp 1.29 can leave the generic lifespan annotation unresolved under
    # pydantic-settings 2.15. Rebuild once before Settings is instantiated so
    # startup is warning-free and every settings source sees complete metadata.
    Settings.model_rebuild()

    auth_settings = None
    token_verifier = None
    if bearer_token:
        resource_url: AnyHttpUrl = _HTTP_URL_ADAPTER.validate_python(_public_base_url(host, port))
        auth_settings = AuthSettings(
            issuer_url=resource_url,
            # Static credentials have no authorization server to advertise.
            # Suppress SDK OAuth discovery rather than publishing a minting
            # endpoint without resource-owner authorization.
            resource_server_url=None,
            required_scopes=[],
        )
        token_verifier = token_verifier_factory(bearer_token)

    mcp = FastMCP(
        name="agent-bom",
        host=host,
        port=port,
        auth=auth_settings,
        token_verifier=token_verifier,
        instructions=_server_instructions(version, profile),
    )
    # Set the actual agent-bom version (FastMCP defaults to SDK version)
    mcp._mcp_server.version = version
    return mcp
