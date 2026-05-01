"""Server commands — REST API, MCP server, combined serve."""

from __future__ import annotations

import ipaddress
import os
import ssl
import sys
from pathlib import Path
from typing import Any, Optional

import click


def _is_loopback_host(host: str) -> bool:
    """Return True when ``host`` resolves to loopback-only access."""
    cleaned = host.strip().lower()
    if cleaned in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        return ipaddress.ip_address(cleaned).is_loopback
    except ValueError:
        return False


def _oidc_enabled() -> bool:
    """Return True when OIDC auth is configured via environment."""
    from agent_bom.api.oidc import oidc_enabled_from_env

    return oidc_enabled_from_env()


def _enforce_auth_defaults(command: str, host: str, api_key: str | None, allow_insecure_no_auth: bool) -> None:
    """Refuse unauthenticated non-loopback binds unless explicitly overridden."""
    if api_key or _oidc_enabled() or _is_loopback_host(host):
        return
    if allow_insecure_no_auth:
        return
    raise click.ClickException(
        f"Refusing to expose `{command}` on non-loopback host {host!r} without authentication. "
        "Set --api-key / AGENT_BOM_API_KEY or configure AGENT_BOM_OIDC_ISSUER / "
        "AGENT_BOM_OIDC_TENANT_PROVIDERS_JSON, "
        "or pass --allow-insecure-no-auth to override."
    )


def _uvicorn_tls_kwargs() -> dict[str, Any]:
    """Return uvicorn TLS kwargs from app-native control-plane TLS env vars."""
    cert_file = os.environ.get("AGENT_BOM_TLS_CERT_FILE", "").strip()
    key_file = os.environ.get("AGENT_BOM_TLS_KEY_FILE", "").strip()
    client_ca_file = os.environ.get("AGENT_BOM_TLS_CLIENT_CA_FILE", "").strip()
    require_client_cert = os.environ.get("AGENT_BOM_TLS_REQUIRE_CLIENT_CERT", "").strip().lower() in {"1", "true", "yes", "on"}

    if require_client_cert and not client_ca_file:
        raise click.ClickException("AGENT_BOM_TLS_REQUIRE_CLIENT_CERT requires AGENT_BOM_TLS_CLIENT_CA_FILE.")
    if client_ca_file and not require_client_cert:
        raise click.ClickException("AGENT_BOM_TLS_CLIENT_CA_FILE requires AGENT_BOM_TLS_REQUIRE_CLIENT_CERT=1.")
    if bool(cert_file) != bool(key_file):
        raise click.ClickException("AGENT_BOM_TLS_CERT_FILE and AGENT_BOM_TLS_KEY_FILE must be configured together.")
    if not cert_file:
        return {}

    kwargs: dict[str, Any] = {
        "ssl_certfile": cert_file,
        "ssl_keyfile": key_file,
    }
    if require_client_cert:
        kwargs["ssl_ca_certs"] = client_ca_file
        kwargs["ssl_cert_reqs"] = ssl.CERT_REQUIRED
    return kwargs


def _enforce_control_plane_listener_posture(host: str) -> None:
    """Fail closed when production/clustered direct listener posture is unsafe."""
    from agent_bom.api.middleware import require_safe_control_plane_listener

    try:
        require_safe_control_plane_listener(listener_host=host)
    except RuntimeError as exc:
        raise click.ClickException(str(exc)) from exc


def _enforce_remote_mcp_auth_defaults(host: str, bearer_token: str | None, allow_insecure_no_auth: bool) -> None:
    """Refuse unauthenticated remote MCP transports on non-loopback binds."""
    if bearer_token or _is_loopback_host(host):
        return
    if allow_insecure_no_auth:
        return
    raise click.ClickException(
        f"Refusing to expose `mcp server` on non-loopback host {host!r} without transport authentication. "
        "Set --bearer-token / AGENT_BOM_MCP_BEARER_TOKEN or pass --allow-insecure-no-auth to override."
    )


def _configure_analytics_backend(
    *,
    analytics_backend: str | None,
    clickhouse_url: str | None,
    analytics_buffered: bool,
    analytics_flush_interval: float,
    analytics_max_batch: int,
) -> tuple[str, str | None]:
    """Resolve and export the requested analytics backend contract."""
    resolved_backend = (analytics_backend or "").strip().lower()
    env_clickhouse_url = os.environ.get("AGENT_BOM_CLICKHOUSE_URL") or ""
    resolved_url = (clickhouse_url or env_clickhouse_url).strip() or None
    if resolved_backend in {"", "auto"}:
        resolved_backend = "clickhouse" if resolved_url else "disabled"
    if resolved_backend == "clickhouse" and not resolved_url:
        raise click.ClickException("ClickHouse analytics requires --clickhouse-url or AGENT_BOM_CLICKHOUSE_URL.")

    os.environ["AGENT_BOM_ANALYTICS_BACKEND"] = resolved_backend
    if resolved_url:
        os.environ["AGENT_BOM_CLICKHOUSE_URL"] = resolved_url
    elif resolved_backend == "disabled":
        os.environ.pop("AGENT_BOM_CLICKHOUSE_URL", None)

    os.environ["AGENT_BOM_CLICKHOUSE_BUFFERED"] = "1" if analytics_buffered else "0"
    os.environ["AGENT_BOM_CLICKHOUSE_FLUSH_INTERVAL"] = f"{analytics_flush_interval:.3f}"
    os.environ["AGENT_BOM_CLICKHOUSE_MAX_BATCH"] = str(max(1, analytics_max_batch))
    return resolved_backend, resolved_url


def _emit_runtime_summary(title: str, rows: list[tuple[str, str]], *, err: bool = False) -> None:
    """Print a compact, aligned startup summary block."""
    click.echo("", err=err)
    click.echo(f"  {title}", err=err)
    for label, value in rows:
        click.echo(f"  {label:<11} {value}", err=err)
    click.echo("  Press Ctrl+C to stop.\n", err=err)


def _auth_summary(
    *,
    host: str,
    api_key: str | None = None,
    bearer_token: str | None = None,
    allow_insecure_no_auth: bool = False,
    oidc_enabled: bool = False,
    mcp_remote: bool = False,
) -> str:
    """Return a user-facing summary for the active auth mode."""
    if api_key:
        return "API key required (Bearer / X-API-Key)"
    if bearer_token:
        return "Bearer token required"
    if oidc_enabled:
        return "OIDC bearer token required"
    if allow_insecure_no_auth and not _is_loopback_host(host):
        return "Disabled by explicit override (--allow-insecure-no-auth)"
    if mcp_remote:
        return "Loopback-only without transport auth; add --bearer-token before exposing remotely"
    return "local unauthenticated mode (loopback only); add --api-key or OIDC before exposing remotely"


def _storage_summary(*, persist: str | None) -> str:
    """Describe the active API job storage mode."""
    pg_url = os.environ.get("AGENT_BOM_POSTGRES_URL")
    if pg_url and not persist:
        return "PostgreSQL"
    if persist:
        return f"SQLite ({persist})"
    return "In-memory (ephemeral)"


def _analytics_summary_rows(
    *,
    resolved_backend: str,
    resolved_url: str | None,
    analytics_buffered: bool,
    analytics_flush_interval: float,
    analytics_max_batch: int,
) -> list[tuple[str, str]]:
    """Describe analytics mode in one or two aligned rows."""
    if resolved_backend != "clickhouse":
        return [("Analytics", "Disabled")]
    mode = "buffered" if analytics_buffered else "direct"
    return [
        (
            "Analytics",
            f"ClickHouse ({mode}, batch={max(1, analytics_max_batch)}, flush={analytics_flush_interval:.2f}s)",
        ),
        ("Analytics URL", resolved_url or "(unset)"),
    ]


@click.command("serve")
@click.option(
    "--host",
    default="127.0.0.1",
    show_default=True,
    help="Host to bind to (non-loopback requires --api-key / OIDC or --allow-insecure-no-auth).",
)
@click.option("--port", default=8422, show_default=True, help="API server port")
@click.option("--persist", default=None, metavar="DB_PATH", help="Enable persistent job storage via SQLite (e.g. --persist jobs.db).")
@click.option("--cors-allow-all", is_flag=True, default=False, help="Allow all CORS origins (dev mode).")
@click.option(
    "--api-key",
    default=None,
    envvar="AGENT_BOM_API_KEY",
    metavar="KEY",
    help="Require API key auth (Bearer token or X-API-Key header).",
)
@click.option(
    "--allow-insecure-no-auth",
    is_flag=True,
    default=False,
    help="Allow unauthenticated non-loopback API exposure. Unsafe outside local development.",
)
@click.option("--reload", is_flag=True, help="Auto-reload on code changes (development mode)")
@click.option(
    "--log-level",
    "log_level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False),
    default="INFO",
)
@click.option("--log-json", "log_json", is_flag=True, help="Structured JSON logs")
@click.option(
    "--analytics-backend",
    type=click.Choice(["auto", "disabled", "clickhouse"], case_sensitive=False),
    default="auto",
    show_default=True,
    help="Analytics backend for trend/event persistence.",
)
@click.option(
    "--clickhouse-url",
    default=None,
    envvar="AGENT_BOM_CLICKHOUSE_URL",
    metavar="URL",
    help="ClickHouse HTTP URL for analytics.",
)
@click.option(
    "--analytics-buffered/--no-analytics-buffered",
    default=True,
    show_default=True,
    help="Buffer ClickHouse analytics writes in a background thread.",
)
@click.option(
    "--analytics-flush-interval",
    default=1.0,
    show_default=True,
    type=float,
    metavar="SECONDS",
    help="Buffered ClickHouse flush interval.",
)
@click.option(
    "--analytics-max-batch",
    default=200,
    show_default=True,
    type=int,
    metavar="ROWS",
    help="Maximum rows to flush per ClickHouse batch.",
)
def serve_cmd(
    host: str,
    port: int,
    persist: Optional[str],
    cors_allow_all: bool,
    api_key: str | None,
    allow_insecure_no_auth: bool,
    reload: bool,
    log_level: str,
    log_json: bool,
    analytics_backend: str,
    clickhouse_url: str | None,
    analytics_buffered: bool,
    analytics_flush_interval: float,
    analytics_max_batch: int,
):
    """Start the API server and serve the dashboard when UI assets are built.

    \b
    Requires:  pip install 'agent-bom[ui]'
               make build-ui   (for the bundled dashboard)

    \b
    Usage:
      Local only:
        agent-bom serve
      Remote with auth:
        agent-bom serve --host 0.0.0.0 --api-key <key>
      Persistent jobs:
        agent-bom serve --port 8422 --persist jobs.db
    """
    from agent_bom.logging_config import setup_logging

    setup_logging(level=log_level, json_output=log_json)

    try:
        import uvicorn  # noqa: F401
    except ImportError:
        click.echo(
            "ERROR: FastAPI + Uvicorn are required for `agent-bom serve`.\n"
            "Install them with:  uv pip install 'agent-bom[ui]'  "
            "(or: pip install 'agent-bom[ui]')",
            err=True,
        )
        sys.exit(1)

    import os as _os

    if persist:
        _os.environ["AGENT_BOM_DB"] = str(Path(persist).resolve())
    if cors_allow_all:
        _os.environ["AGENT_BOM_CORS_ALL"] = "1"
    resolved_backend, resolved_url = _configure_analytics_backend(
        analytics_backend=analytics_backend,
        clickhouse_url=clickhouse_url,
        analytics_buffered=analytics_buffered,
        analytics_flush_interval=analytics_flush_interval,
        analytics_max_batch=analytics_max_batch,
    )

    _enforce_auth_defaults("serve", host, api_key, allow_insecure_no_auth)
    _enforce_control_plane_listener_posture(host)
    tls_kwargs = _uvicorn_tls_kwargs()

    from agent_bom.api.server import configure_api

    configure_api(
        cors_allow_all=cors_allow_all,
        api_key=api_key,
    )

    _ui_dist = Path(__file__).resolve().parents[1] / "ui_dist"
    rows = [
        ("API", f"http://{host}:{port}"),
        ("Docs", f"http://{host}:{port}/docs"),
        (
            "Dashboard",
            f"http://{host}:{port}" if (_ui_dist / "index.html").exists() else "Not bundled (run: make build-ui)",
        ),
        ("Auth", _auth_summary(host=host, api_key=api_key, allow_insecure_no_auth=allow_insecure_no_auth, oidc_enabled=_oidc_enabled())),
        ("TLS", "app-native mTLS" if tls_kwargs.get("ssl_ca_certs") else ("server TLS" if tls_kwargs else "delegated/none")),
        ("Storage", _storage_summary(persist=persist)),
        *_analytics_summary_rows(
            resolved_backend=resolved_backend,
            resolved_url=resolved_url,
            analytics_buffered=analytics_buffered,
            analytics_flush_interval=analytics_flush_interval,
            analytics_max_batch=analytics_max_batch,
        ),
    ]
    _emit_runtime_summary("agent-bom serve", rows)

    import uvicorn as _uvicorn

    _uvicorn.run(
        "agent_bom.api.server:app",
        host=host,
        port=port,
        reload=reload,
        timeout_keep_alive=5,
        limit_concurrency=500,
        **tls_kwargs,
    )


@click.command("api")
@click.option(
    "--host",
    default="127.0.0.1",
    show_default=True,
    help="Host to bind to (non-loopback requires --api-key / OIDC or --allow-insecure-no-auth).",
)
@click.option("--port", default=8422, show_default=True, help="Port to listen on")
@click.option("--reload", is_flag=True, help="Auto-reload on code changes (development mode)")
@click.option("--workers", default=1, show_default=True, help="Number of worker processes")
@click.option("--cors-origins", default=None, metavar="ORIGINS", help="Comma-separated CORS origins (default: localhost:3000).")
@click.option("--cors-allow-all", is_flag=True, default=False, help="Allow all CORS origins (dev mode).")
@click.option(
    "--api-key",
    default=None,
    envvar="AGENT_BOM_API_KEY",
    metavar="KEY",
    help="Require API key auth (Bearer token or X-API-Key header).",
)
@click.option(
    "--allow-insecure-no-auth",
    is_flag=True,
    default=False,
    help="Allow unauthenticated non-loopback API exposure. Unsafe outside local development.",
)
@click.option(
    "--rate-limit",
    "rate_limit_rpm",
    default=60,
    show_default=True,
    type=int,
    metavar="RPM",
    help="Rate limit for scan endpoints (requests/minute per IP).",
)
@click.option(
    "--persist",
    default=None,
    metavar="DB_PATH",
    help="Enable persistent job storage via SQLite (e.g. --persist jobs.db). Jobs survive restarts.",
)
@click.option(
    "--log-level",
    "log_level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False),
    default="INFO",
    show_default=True,
    help="Log verbosity level.",
)
@click.option("--log-json", "log_json", is_flag=True, help="Emit structured JSON logs (for log aggregation pipelines).")
@click.option(
    "--analytics-backend",
    type=click.Choice(["auto", "disabled", "clickhouse"], case_sensitive=False),
    default="auto",
    show_default=True,
    help="Analytics backend for trend/event persistence.",
)
@click.option(
    "--clickhouse-url",
    default=None,
    envvar="AGENT_BOM_CLICKHOUSE_URL",
    metavar="URL",
    help="ClickHouse HTTP URL for analytics.",
)
@click.option(
    "--analytics-buffered/--no-analytics-buffered",
    default=True,
    show_default=True,
    help="Buffer ClickHouse analytics writes in a background thread.",
)
@click.option(
    "--analytics-flush-interval",
    default=1.0,
    show_default=True,
    type=float,
    metavar="SECONDS",
    help="Buffered ClickHouse flush interval.",
)
@click.option(
    "--analytics-max-batch",
    default=200,
    show_default=True,
    type=int,
    metavar="ROWS",
    help="Maximum rows to flush per ClickHouse batch.",
)
def api_cmd(
    host: str,
    port: int,
    reload: bool,
    workers: int,
    cors_origins: str | None,
    cors_allow_all: bool,
    api_key: str | None,
    allow_insecure_no_auth: bool,
    rate_limit_rpm: int,
    persist: str | None,
    log_level: str,
    log_json: bool,
    analytics_backend: str,
    clickhouse_url: str | None,
    analytics_buffered: bool,
    analytics_flush_interval: float,
    analytics_max_batch: int,
):
    """Start the agent-bom REST API server.

    \b
    Requires:  pip install 'agent-bom[api]'

    \b
    Endpoints:
      GET  /docs                   Interactive API docs (Swagger UI)
      GET  /health                 Liveness probe
      GET  /version                Version info
      POST /v1/scan                Start a scan (async, returns job_id)
      GET  /v1/scan/{job_id}       Poll status + results
      GET  /v1/scan/{job_id}/stream  SSE real-time progress
      GET  /v1/agents              Quick agent discovery (no CVE scan)
      GET  /v1/jobs                List all scan jobs

    \b
    Usage:
      Local only:
        agent-bom api
      Remote with auth:
        agent-bom api --host 0.0.0.0 --api-key <key>
      Custom port / dev reload:
        agent-bom api --port 9000
        agent-bom api --reload
    """
    from agent_bom.logging_config import setup_logging

    setup_logging(level=log_level, json_output=log_json)

    try:
        import uvicorn
    except ImportError:
        click.echo(
            "ERROR: uvicorn is required for `agent-bom api`.\n"
            "Install it with:  uv pip install 'agent-bom[api]'  "
            "(or: pip install 'agent-bom[api]')",
            err=True,
        )
        sys.exit(1)

    import os as _os

    resolved_backend, resolved_url = _configure_analytics_backend(
        analytics_backend=analytics_backend,
        clickhouse_url=clickhouse_url,
        analytics_buffered=analytics_buffered,
        analytics_flush_interval=analytics_flush_interval,
        analytics_max_batch=analytics_max_batch,
    )

    from agent_bom import __version__ as _ver
    from agent_bom.api.server import configure_api, set_job_store

    _enforce_auth_defaults("api", host, api_key, allow_insecure_no_auth)
    _enforce_control_plane_listener_posture(host)
    tls_kwargs = _uvicorn_tls_kwargs()

    origins = cors_origins.split(",") if cors_origins else None
    configure_api(
        cors_origins=origins,
        cors_allow_all=cors_allow_all,
        api_key=api_key,
        rate_limit_rpm=rate_limit_rpm,
    )

    pg_url = _os.environ.get("AGENT_BOM_POSTGRES_URL")
    if pg_url and not persist:
        # Postgres takes priority when no explicit --persist flag
        from agent_bom.api.postgres_store import PostgresJobStore

        set_job_store(PostgresJobStore())
    elif persist:
        from agent_bom.api.store import SQLiteJobStore

        set_job_store(SQLiteJobStore(db_path=persist))

    rows = [
        ("Version", _ver),
        ("Bind", f"http://{host}:{port}"),
        ("Docs", f"http://{host}:{port}/docs"),
        ("Auth", _auth_summary(host=host, api_key=api_key, allow_insecure_no_auth=allow_insecure_no_auth, oidc_enabled=_oidc_enabled())),
        ("TLS", "app-native mTLS" if tls_kwargs.get("ssl_ca_certs") else ("server TLS" if tls_kwargs else "delegated/none")),
        ("Storage", _storage_summary(persist=persist)),
        *_analytics_summary_rows(
            resolved_backend=resolved_backend,
            resolved_url=resolved_url,
            analytics_buffered=analytics_buffered,
            analytics_flush_interval=analytics_flush_interval,
            analytics_max_batch=analytics_max_batch,
        ),
    ]
    _emit_runtime_summary("agent-bom API", rows)

    uvicorn.run(
        "agent_bom.api.server:app",
        host=host,
        port=port,
        reload=reload,
        workers=1 if reload else workers,
        log_level=log_level.lower(),
        # Slowloris / connection-exhaustion hardening:
        # Close idle keep-alive connections after 5s (uvicorn default is 5s but
        # we set it explicitly so it's visible and auditable).
        timeout_keep_alive=5,
        # Hard cap on concurrent in-flight requests; prevents thread/FD exhaustion
        # under a slow-connection flood. 500 ≫ any realistic single-server load.
        limit_concurrency=500,
        **tls_kwargs,
    )


@click.command("mcp-server")
@click.option(
    "--transport",
    type=click.Choice(["stdio", "sse", "streamable-http"]),
    default="stdio",
    show_default=True,
    help="MCP transport protocol.",
)
@click.option("--port", default=8423, show_default=True, help="Port for HTTP/SSE transport.")
@click.option("--host", default="127.0.0.1", show_default=True, help="Host for HTTP/SSE transport.")
@click.option(
    "--bearer-token",
    default=None,
    envvar="AGENT_BOM_MCP_BEARER_TOKEN",
    metavar="TOKEN",
    help="Require Bearer token auth for SSE / Streamable HTTP transports.",
)
@click.option(
    "--allow-insecure-no-auth",
    is_flag=True,
    default=False,
    help="Allow unauthenticated non-loopback SSE / HTTP exposure. Unsafe outside local development.",
)
@click.option("--log-level", "log_level", type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False), default="INFO")
@click.option("--log-json", "log_json", is_flag=True, help="Structured JSON logs")
def mcp_server_cmd(
    transport: str,
    port: int,
    host: str,
    bearer_token: str | None,
    allow_insecure_no_auth: bool,
    log_level: str,
    log_json: bool,
):
    """Start agent-bom as an MCP server.

    \b
    Requires:  pip install 'agent-bom[mcp-server]'

    \b
    Exposes 36 security tools via MCP protocol:
      scan                   Full scan — CVEs, config security, blast radius, compliance
      check                  Check a specific package for CVEs before installing
      blast_radius           Look up blast radius for a specific CVE
      policy_check           Evaluate policy rules against scan findings
      registry_lookup        Query MCP server security metadata registry
      generate_sbom          Generate CycloneDX or SPDX SBOM
      compliance             14-framework compliance posture
      remediate              Generate actionable remediation plan
      skill_scan             Scan instruction files for trust, provenance, and findings
      skill_verify           Verify Sigstore provenance for instruction files
      skill_trust            Trust assessment for SKILL.md files
      verify                 Package integrity + SLSA provenance verification
      where                  Show all MCP discovery paths + existence status
      tool_risk_assessment   Score live MCP tool capabilities and server risk
      inventory              List agents/servers without CVE scanning
      diff                   Compare scan against baseline for new/resolved vulns
      marketplace_check      Pre-install marketplace trust check
      code_scan              SAST scanning via Semgrep with CWE mapping
      context_graph          Agent context graph with lateral movement analysis
      graph_export           Export dependency graph as GraphML, Cypher, DOT, or Mermaid
      analytics_query        Query vulnerability trends from ClickHouse
      cis_benchmark          Run CIS benchmark checks (AWS/Snowflake)
      fleet_scan             Batch registry lookup for fleet inventories
      runtime_correlate      Cross-reference runtime logs with CVE findings
      vector_db_scan         Discover vector databases and assess auth exposure
      aisvs_benchmark        OWASP AISVS v1.0 compliance checks
      gpu_infra_scan         GPU container and K8s node inventory + DCGM probe
      ai_inventory_scan      Detect AI SDK imports, shadow AI, deprecated models
      browser_extension_scan Audit browser extensions for AI/MCP capabilities
      dataset_card_scan      Scan dataset cards for license and provenance
      ingest_external_scan   Import Trivy/Grype/Syft scan results
      license_compliance_scan License risk detection for dependencies
      model_file_scan        Scan ML model files for security risks
      model_provenance_scan  Verify model origin and supply chain integrity
      prompt_scan            Detect prompt injection patterns
      training_pipeline_scan Audit ML training pipeline configurations

    \b
    Usage:
      Local stdio:
        agent-bom mcp server
      Remote with bearer auth:
        agent-bom mcp server --transport sse --bearer-token <token>
        agent-bom mcp server --transport streamable-http --bearer-token <token>

    \b
    Claude Desktop config (~/.claude/claude_desktop_config.json):
      {"mcpServers": {"agent-bom": {"command": "agent-bom", "args": ["mcp", "server"]}}}
    """
    from agent_bom.logging_config import setup_logging

    setup_logging(level=log_level, json_output=log_json)

    try:
        from agent_bom.mcp_server import create_mcp_server
    except ImportError:
        click.echo(
            "ERROR: mcp SDK is required for `agent-bom mcp server`.\nInstall it with:  pip install 'agent-bom[mcp-server]'",
            err=True,
        )
        sys.exit(1)

    if transport in ("sse", "streamable-http"):
        _enforce_remote_mcp_auth_defaults(host, bearer_token, allow_insecure_no_auth)

    server = create_mcp_server(host=host, port=port, bearer_token=bearer_token)

    if transport in ("sse", "streamable-http"):
        from agent_bom import __version__ as _ver

        rows = [
            ("Version", _ver),
            ("Transport", transport),
            ("Bind", f"http://{host}:{port}"),
            (
                "Auth",
                _auth_summary(
                    host=host,
                    bearer_token=bearer_token,
                    allow_insecure_no_auth=allow_insecure_no_auth,
                    mcp_remote=True,
                ),
            ),
        ]
        _emit_runtime_summary("agent-bom MCP server", rows, err=True)
        server.run(transport=transport)
    else:
        if bearer_token:
            click.echo("  Warning:   --bearer-token applies only to SSE / Streamable HTTP transports", err=True)
        server.run(transport="stdio")
