from __future__ import annotations

import os
from typing import Any, Callable

from pydantic import AnyHttpUrl, TypeAdapter

_HTTP_URL_ADAPTER = TypeAdapter(AnyHttpUrl)


def _server_instructions(version: str) -> str:
    return (
        f"agent-bom v{version} — AI infrastructure security scanner with MCP security tools. "
        "Scans packages and images for CVEs (OSV, NVD, EPSS, CISA KEV), maps blast radius "
        "from vulnerabilities to credentials and tools, generates SBOMs (CycloneDX, SPDX), "
        "checks security policies, and maps to 14 compliance frameworks"
        "(OWASP LLM/MCP/Agentic, MITRE ATLAS, NIST AI RMF/CSF/800-53, FedRAMP, EU AI Act, ISO 27001, SOC 2). "
        "Discovers 29 first-class MCP client types plus dynamic/project surfaces. "
        "Scanner and posture tools are read-only; Shield and identity write actions require an authenticated operator token, "
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
):
    """Create the FastMCP server with optional static bearer auth."""
    from mcp.server.auth.settings import AuthSettings
    from mcp.server.fastmcp import FastMCP

    auth_settings = None
    token_verifier = None
    if bearer_token:
        resource_url: AnyHttpUrl = _HTTP_URL_ADAPTER.validate_python(_public_base_url(host, port))
        auth_settings = AuthSettings(
            issuer_url=resource_url,
            resource_server_url=resource_url,
            required_scopes=[],
        )
        token_verifier = token_verifier_factory(bearer_token)

    mcp = FastMCP(
        name="agent-bom",
        host=host,
        port=port,
        auth=auth_settings,
        token_verifier=token_verifier,
        instructions=_server_instructions(version),
    )
    # Set the actual agent-bom version (FastMCP defaults to SDK version)
    mcp._mcp_server.version = version
    return mcp
