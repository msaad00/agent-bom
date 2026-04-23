from __future__ import annotations

from typing import Any, Callable

from pydantic import AnyHttpUrl, TypeAdapter

_HTTP_URL_ADAPTER = TypeAdapter(AnyHttpUrl)


def _server_instructions(version: str) -> str:
    return (
        f"agent-bom v{version} — AI infrastructure security scanner with MCP security tools. "
        "Scans packages and images for CVEs (OSV, NVD, EPSS, CISA KEV), maps blast radius "
        "from vulnerabilities to credentials and tools, generates SBOMs (CycloneDX, SPDX), "
        "enforces security policies, and maps to 14 compliance frameworks"
        "(OWASP LLM/MCP/Agentic, MITRE ATLAS, NIST AI RMF/CSF/800-53, FedRAMP, EU AI Act, ISO 27001, SOC 2). "
        "Discovers 30 MCP clients. Read-only, agentless, no credentials required."
    )


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
        resource_url: AnyHttpUrl = _HTTP_URL_ADAPTER.validate_python(f"http://{host}:{port}")
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
