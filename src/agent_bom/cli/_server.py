"""Server commands — REST API, MCP server, combined serve."""

from __future__ import annotations

import importlib.util
import ipaddress
import os
import secrets
import ssl
import sys
from pathlib import Path
from typing import Any, Optional

import click

from agent_bom.cli._common import LISTEN_PORT_RANGE


def _require_optional_dependencies(command: str, extra: str, modules: dict[str, str]) -> None:
    """Fail fast with an actionable install hint for optional runtime surfaces."""
    missing = [label for label, module_name in modules.items() if importlib.util.find_spec(module_name) is None]
    if not missing:
        return
    _fail_missing_optional_dependencies(command, extra, missing)


def _fail_missing_optional_dependencies(command: str, extra: str, missing: list[str]) -> None:
    """Print the shared optional-extra install hint and exit."""
    missing_text = ", ".join(missing)
    click.echo(
        f"ERROR: {missing_text} required for `{command}`.\n"
        f"Install with:  uv pip install 'agent-bom[{extra}]'  (or: pip install 'agent-bom[{extra}]')",
        err=True,
    )
    sys.exit(1)


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


def _scim_bearer_enabled() -> bool:
    """True when a SCIM bearer token is configured.

    Imported lazily so command-line tooling that doesn't touch SCIM doesn't
    pay the import cost.
    """
    from agent_bom.api.scim import scim_enabled_from_env

    return scim_enabled_from_env()


def _enforce_auth_defaults(command: str, host: str, api_key: str | None, allow_insecure_no_auth: bool) -> None:
    """Refuse unauthenticated non-loopback binds unless explicitly overridden.

    Recognises four auth paths:
    - explicit API key (--api-key / AGENT_BOM_API_KEY)
    - OIDC (AGENT_BOM_OIDC_ISSUER + tenant providers)
    - SCIM bearer (AGENT_BOM_SCIM_BEARER_TOKEN) -- the SCIM middleware
      authenticates every endpoint when this is configured
    - --allow-insecure-no-auth (explicit override; emits a loud warning when
      another auth method is also configured so operators understand that
      their `--allow-insecure-no-auth` does NOT actually disable the SCIM /
      OIDC / API-key middleware path that's still in effect)
    """
    if _is_loopback_host(host):
        return
    has_api_key = bool(api_key or os.environ.get("AGENT_BOM_API_KEYS", "").strip())
    has_oidc = _oidc_enabled()
    has_scim = _scim_bearer_enabled()
    if has_api_key or has_oidc or has_scim:
        if allow_insecure_no_auth:
            active: list[str] = []
            if has_api_key:
                active.append("API-key")
            if has_oidc:
                active.append("OIDC")
            if has_scim:
                active.append("SCIM-bearer")
            click.secho(
                f"warning: --allow-insecure-no-auth was passed but {', '.join(active)} authentication is "
                "still configured -- requests will continue to be authenticated. "
                "Unset the relevant env vars to actually run unauthenticated.",
                fg="yellow",
                err=True,
            )
        return
    if allow_insecure_no_auth:
        return
    raise click.ClickException(
        f"Refusing to expose `{command}` on non-loopback host {host!r} without authentication. "
        "Set --api-key / AGENT_BOM_API_KEY, configure AGENT_BOM_API_KEYS, configure AGENT_BOM_OIDC_ISSUER / "
        "AGENT_BOM_OIDC_TENANT_PROVIDERS_JSON, set AGENT_BOM_SCIM_BEARER_TOKEN, "
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


_MCP_WORKFLOW_NAMES = (
    "quick-audit",
    "pre-install-check",
    "compliance-report",
    "fleet-audit",
    "incident-triage",
    "remediation-plan",
    "cloud-connection-review",
    "gateway-fleet-live-demo",
)


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
    if api_key or os.environ.get("AGENT_BOM_API_KEYS", "").strip():
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


def _env_truthy(name: str) -> bool:
    """Return True when environment variable ``name`` holds a truthy flag."""
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _resolve_allow_unauthenticated(allow_insecure_no_auth: bool) -> bool:
    """Resolve the effective unauthenticated-API posture the server will apply.

    Mirrors ``configure_api``: the ``--allow-insecure-no-auth`` flag OR the
    ``AGENT_BOM_ALLOW_UNAUTHENTICATED_API`` env var enables it. Non-loopback
    binds are already gated fail-closed by ``_enforce_auth_defaults`` before
    this runs, so the env var can only take effect on loopback.
    """
    return bool(allow_insecure_no_auth) or _env_truthy("AGENT_BOM_ALLOW_UNAUTHENTICATED_API")


_DEV_API_KEY_PREFIX = "abk"


def _generate_dev_api_key() -> str:
    """Return a fresh ephemeral loopback dev API key (per-process, not persisted)."""
    return f"{_DEV_API_KEY_PREFIX}_{secrets.token_urlsafe(24)}"


def _should_auto_generate_dev_key(*, host: str, api_key: str | None, allow_insecure_no_auth: bool) -> bool:
    """Decide whether a zero-config loopback dev API key should be auto-generated.

    Fail-closed by construction: only ever true on a loopback bind with no other
    auth path configured. Any explicit key, override, configured auth backend, or
    the ``AGENT_BOM_NO_AUTO_DEV_KEY`` opt-out keeps the current behaviour (fail
    closed on loopback, or the existing non-loopback refusal in
    ``_enforce_auth_defaults``). A non-loopback host NEVER auto-generates a key.
    """
    if not _is_loopback_host(host):
        return False
    if _env_truthy("AGENT_BOM_NO_AUTO_DEV_KEY"):
        return False
    if api_key or allow_insecure_no_auth:
        return False
    if os.environ.get("AGENT_BOM_API_KEYS", "").strip():
        return False
    if _oidc_enabled() or _scim_bearer_enabled():
        return False
    if _env_truthy("AGENT_BOM_ALLOW_UNAUTHENTICATED_API"):
        return False
    if _env_truthy("AGENT_BOM_TRUST_PROXY_AUTH"):
        return False
    return True


def _api_auth_summary(
    *,
    host: str,
    api_key: str | None,
    oidc_enabled: bool,
    allow_unauthenticated: bool,
    dev_api_key: str | None = None,
) -> str:
    """Return a startup banner that matches the server's real auth posture.

    Derived from the same inputs ``configure_api`` uses so the banner can never
    claim unauthenticated access while the API actually fails closed (or vice
    versa). ``allow_unauthenticated`` is the resolved flag-OR-env value.
    ``dev_api_key`` is the auto-generated loopback key, if one was minted.
    """
    if api_key or os.environ.get("AGENT_BOM_API_KEYS", "").strip():
        return "API key required (Bearer / X-API-Key)"
    if dev_api_key:
        return "auto dev API key (loopback only); the local UI uses it automatically"
    if oidc_enabled:
        return "OIDC bearer token required"
    if _scim_bearer_enabled():
        return "SCIM bearer token required"
    if _env_truthy("AGENT_BOM_TRUST_PROXY_AUTH"):
        return "Reverse-proxy auth (trusted proxy headers)"
    if allow_unauthenticated:
        if _is_loopback_host(host):
            return "local unauthenticated mode (loopback only); add --api-key or OIDC before exposing remotely"
        return "Disabled by explicit override (--allow-insecure-no-auth)"
    return (
        "auth required but no key configured; requests fail closed (401). "
        "Pass --allow-insecure-no-auth for a local demo, or set --api-key / AGENT_BOM_API_KEY."
    )


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
@click.option("--port", default=8422, show_default=True, type=LISTEN_PORT_RANGE, help="API server port")
@click.option("--persist", default=None, metavar="DB_PATH", help="Enable persistent job storage via SQLite (e.g. --persist jobs.db).")
@click.option("--cors-allow-all", is_flag=True, default=False, help="Allow all CORS origins (dev mode).")
@click.option(
    "--api-key",
    default=None,
    envvar="AGENT_BOM_API_KEY",
    metavar="KEY",
    help=(
        "Require API key auth (Bearer token or X-API-Key header). "
        "Other accepted auth paths: AGENT_BOM_OIDC_ISSUER (OIDC) and "
        "AGENT_BOM_SCIM_BEARER_TOKEN (SCIM bearer for IdP integration)."
    ),
)
@click.option(
    "--allow-insecure-no-auth",
    is_flag=True,
    default=False,
    help=(
        "Allow unauthenticated non-loopback API exposure. Unsafe outside local development. "
        "Note: when AGENT_BOM_API_KEY / AGENT_BOM_OIDC_ISSUER / "
        "AGENT_BOM_SCIM_BEARER_TOKEN is also set, those auth paths still "
        "enforce; the flag emits a warning instead of bypassing them."
    ),
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

    _require_optional_dependencies(
        "agent-bom serve",
        "ui",
        {"FastAPI": "fastapi", "Uvicorn": "uvicorn"},
    )

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

    # Zero-config loopback: when bound to loopback with no auth configured and no
    # opt-out, mint an ephemeral dev key so the dashboard loads without flags.
    # Non-loopback binds never reach here unauthenticated (see the gate above),
    # so this can only ever fire on loopback.
    dev_api_key = (
        _generate_dev_api_key()
        if _should_auto_generate_dev_key(host=host, api_key=api_key, allow_insecure_no_auth=allow_insecure_no_auth)
        else None
    )

    from agent_bom.api.server import configure_api, set_dev_api_key

    configure_api(
        cors_allow_all=cors_allow_all,
        api_key=api_key or dev_api_key,
        allow_unauthenticated=allow_insecure_no_auth,
    )
    set_dev_api_key(dev_api_key)

    _ui_dist = Path(__file__).resolve().parents[1] / "ui_dist"
    rows = [
        ("API", f"http://{host}:{port}"),
        ("Docs", f"http://{host}:{port}/docs"),
        (
            "Dashboard",
            f"http://{host}:{port}" if (_ui_dist / "index.html").exists() else "Not bundled (run: make build-ui)",
        ),
        (
            "Auth",
            _api_auth_summary(
                host=host,
                api_key=api_key,
                oidc_enabled=_oidc_enabled(),
                allow_unauthenticated=_resolve_allow_unauthenticated(allow_insecure_no_auth),
                dev_api_key=dev_api_key,
            ),
        ),
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
    if dev_api_key:
        click.secho(
            f"  Dev API key (loopback only): {dev_api_key}",
            fg="cyan",
            bold=True,
        )
        click.echo(
            "  The local dashboard uses this automatically. Send it as "
            "'Authorization: Bearer <key>' for CLI/API calls.\n"
            "  Ephemeral (per-process, not saved). Set AGENT_BOM_NO_AUTO_DEV_KEY=1 to disable.\n"
        )

    try:
        import uvicorn as _uvicorn
    except ImportError:
        _fail_missing_optional_dependencies("agent-bom serve", "ui", ["Uvicorn"])

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
@click.option("--port", default=8422, show_default=True, type=LISTEN_PORT_RANGE, help="Port to listen on")
@click.option("--reload", is_flag=True, help="Auto-reload on code changes (development mode)")
@click.option("--workers", default=1, show_default=True, help="Number of worker processes")
@click.option("--cors-origins", default=None, metavar="ORIGINS", help="Comma-separated CORS origins (default: localhost:3000).")
@click.option("--cors-allow-all", is_flag=True, default=False, help="Allow all CORS origins (dev mode).")
@click.option(
    "--api-key",
    default=None,
    envvar="AGENT_BOM_API_KEY",
    metavar="KEY",
    help=(
        "Require API key auth (Bearer token or X-API-Key header). "
        "Other accepted auth paths: AGENT_BOM_OIDC_ISSUER (OIDC) and "
        "AGENT_BOM_SCIM_BEARER_TOKEN (SCIM bearer for IdP integration)."
    ),
)
@click.option(
    "--allow-insecure-no-auth",
    is_flag=True,
    default=False,
    help=(
        "Allow unauthenticated non-loopback API exposure. Unsafe outside local development. "
        "Note: when AGENT_BOM_API_KEY / AGENT_BOM_OIDC_ISSUER / "
        "AGENT_BOM_SCIM_BEARER_TOKEN is also set, those auth paths still "
        "enforce; the flag emits a warning instead of bypassing them."
    ),
)
@click.option(
    "--rate-limit",
    "rate_limit_rpm",
    default=600,
    show_default=True,
    type=click.IntRange(1, 60_000),
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

    _require_optional_dependencies(
        "agent-bom api",
        "api",
        {"FastAPI": "fastapi", "Uvicorn": "uvicorn"},
    )

    import os as _os

    try:
        import uvicorn
    except ImportError:
        _fail_missing_optional_dependencies("agent-bom api", "api", ["Uvicorn"])

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
        allow_unauthenticated=allow_insecure_no_auth,
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
        (
            "Auth",
            _api_auth_summary(
                host=host,
                api_key=api_key,
                oidc_enabled=_oidc_enabled(),
                allow_unauthenticated=_resolve_allow_unauthenticated(allow_insecure_no_auth),
            ),
        ),
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
@click.option("--port", default=8423, show_default=True, type=LISTEN_PORT_RANGE, help="Port for HTTP/SSE transport.")
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
    Workflow prompts first:
      quick-audit              scan -> exposure_paths -> compliance
      pre-install-check        check -> registry_lookup -> should_i_deploy
      compliance-report        compliance -> audit_integrity -> report export
      fleet-audit              fleet_scan -> context_graph -> policy_check
      incident-triage          intel_lookup -> exposure_paths -> runtime_correlate
      remediation-plan         remediate -> generate_sbom -> policy_check
      cloud-connection-review  connection evidence -> cis_benchmark -> graph_export
      gateway-fleet-live-demo  gateway_status -> proxy_alerts -> fleet_scan -> firewall_check

    \b
    The server still exposes the full tool catalog for advanced agents. Start
    from prompts unless you already know the exact tool sequence. See:
      docs/MCP_WORKFLOWS.md

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

    _require_optional_dependencies(
        "agent-bom mcp server",
        "mcp-server",
        {"MCP SDK": "mcp"},
    )

    try:
        from agent_bom.mcp_server import create_mcp_server
    except ImportError:
        _fail_missing_optional_dependencies("agent-bom mcp server", "mcp-server", ["MCP SDK"])

    if transport in ("sse", "streamable-http"):
        _enforce_remote_mcp_auth_defaults(host, bearer_token, allow_insecure_no_auth)
        # Signal a remotely-bound (internet-reachable) MCP transport so repo
        # scans fail closed unless an explicit host allowlist is configured.
        if not _is_loopback_host(host):
            os.environ["AGENT_BOM_MCP_REMOTE_BIND"] = "1"

    server = create_mcp_server(host=host, port=port, bearer_token=bearer_token)

    if transport in ("sse", "streamable-http"):
        from agent_bom import __version__ as _ver

        rows = [
            ("Version", _ver),
            ("Transport", transport),
            ("Bind", f"http://{host}:{port}"),
            ("Workflows", f"{len(_MCP_WORKFLOW_NAMES)} prompts; see docs/MCP_WORKFLOWS.md"),
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
