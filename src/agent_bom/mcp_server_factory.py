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


def build_mcp_authorization_server(issuer: str):
    """The OAuth 2.1 AS this MCP server both advertises and honours.

    ``issuer`` must be the exact string the SDK publishes in the
    protected-resource document's ``authorization_servers`` — see
    ``_mount_oauth_authorization_server``.

    Scopes are pinned to ``read``. The AS can therefore never mint a token that
    reaches a write tool: those require the separately-configured operator
    token, and a dynamically-registered third-party client must not be able to
    self-assert administrative authority by asking for the scope.
    """
    from agent_bom.api.oauth_as import OAuthAuthorizationServer

    return OAuthAuthorizationServer(
        issuer=issuer,
        supported_scopes=["read"],
        # The issuer is explicit, so never let a client's Host header define it.
        allow_host_derived_issuer=False,
    )


def _mount_oauth_authorization_server(mcp: Any, server: Any) -> None:
    """Serve the AS endpoints the protected-resource document points at.

    FastMCP mounts ``create_auth_routes`` only when an ``auth_server_provider``
    is configured. We run as a resource server (static bearer + token
    verifier), so it published ``/.well-known/oauth-protected-resource`` naming
    an authorization server whose ``/authorize`` and ``/token`` returned 404.
    Discovery resolved and the flow then died, which is why Smithery's scanner
    settles as AUTH_REQUIRED and its catalog advertises a fraction of our tools.

    These are thin transport adapters: every decision lives in
    ``OAuthAuthorizationServer``, the same object the gateway serves through its
    FastAPI router, so there is one implementation and two bindings rather than
    two authorization servers.

    ``custom_route`` handlers are deliberately unauthenticated — they ARE the
    bootstrap that issues the token, so requiring one would be circular. Note
    the SDK mounts custom routes last, at the lowest matching precedence, so
    these cannot and must not shadow a built-in route.
    """
    from starlette.responses import JSONResponse, RedirectResponse, Response

    from agent_bom.api.oauth_as import OAuthError, _basic_auth_from_header

    @mcp.custom_route("/.well-known/oauth-authorization-server", methods=["GET"])
    async def _as_metadata(request: Any) -> Response:
        try:
            return JSONResponse(server.metadata(str(request.base_url).rstrip("/")))
        except OAuthError as exc:
            return JSONResponse(exc.to_dict(), status_code=exc.status)

    @mcp.custom_route("/oauth/jwks.json", methods=["GET"])
    async def _as_jwks(_request: Any) -> Response:
        return JSONResponse(server.jwks())

    @mcp.custom_route("/oauth/register", methods=["POST"])
    async def _as_register(request: Any) -> Response:
        try:
            payload = await request.json()
        except Exception:  # noqa: BLE001 - a non-JSON body is a client error, not a crash
            return JSONResponse(
                {"error": "invalid_client_metadata", "error_description": "body must be JSON"},
                status_code=400,
            )
        try:
            registered = server.register_client(payload if isinstance(payload, dict) else {})
        except OAuthError as exc:
            return JSONResponse(exc.to_dict(), status_code=exc.status)
        return JSONResponse(registered, status_code=201)

    @mcp.custom_route("/oauth/authorize", methods=["GET"])
    async def _as_authorize(request: Any) -> Response:
        try:
            location = server.authorize(dict(request.query_params))
        except OAuthError as exc:
            if exc.redirect_location:
                return RedirectResponse(exc.redirect_location, status_code=302)
            return JSONResponse(exc.to_dict(), status_code=exc.status)
        return RedirectResponse(location, status_code=302)

    @mcp.custom_route("/oauth/token", methods=["POST"])
    async def _as_token(request: Any) -> Response:
        form = dict(await request.form())
        try:
            issued = server.token(
                form,
                basic_auth=_basic_auth_from_header(request.headers.get("authorization")),
                request_base_url=str(request.base_url).rstrip("/"),
            )
        except OAuthError as exc:
            headers = {"WWW-Authenticate": "Basic"} if exc.status == 401 else None
            return JSONResponse(exc.to_dict(), status_code=exc.status, headers=headers)
        # Tokens must never be cached (OAuth 2.1 §token-response).
        return JSONResponse(issued, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})


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
    if auth_settings is not None:
        # The issuer is taken from AuthSettings AFTER pydantic has normalized
        # it, not from the raw string, because that normalized form is exactly
        # what the SDK writes into the protected-resource document's
        # ``authorization_servers`` — and ``AnyHttpUrl`` renders a bare host
        # with a trailing slash. Deriving the AS issuer independently produced
        # two documents disagreeing by one character.
        authorization_server = build_mcp_authorization_server(str(auth_settings.issuer_url))
        _mount_oauth_authorization_server(mcp, authorization_server)
        # Without this the flow completes and then every call 401s: the client
        # holds a valid AS-issued token that the static verifier has never
        # heard of. Advertising an AS whose tokens we reject is worse than not
        # advertising one.
        accept_issued = getattr(token_verifier, "accept_tokens_issued_by", None)
        if callable(accept_issued):
            accept_issued(authorization_server)
    # Set the actual agent-bom version (FastMCP defaults to SDK version)
    mcp._mcp_server.version = version
    return mcp
