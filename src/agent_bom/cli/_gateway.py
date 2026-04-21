"""`agent-bom gateway serve` — multi-MCP HTTP gateway CLI.

Fronts N upstream MCP servers through one URL, so laptop editors
(Cursor / VS Code / Claude / Codex / Copilot) point at one gateway
endpoint instead of configuring a proxy per MCP.

See docs/design/MULTI_MCP_GATEWAY.md.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import click

from agent_bom.cli._server import _enforce_remote_mcp_auth_defaults

logger = logging.getLogger(__name__)


@click.group(help="Multi-MCP gateway commands.")
def gateway_group() -> None:
    """Entry point for gateway subcommands."""


@gateway_group.command("serve")
@click.option(
    "--upstreams",
    "upstreams_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help=(
        "YAML file listing upstream MCP servers (see "
        "docs/design/MULTI_MCP_GATEWAY.md). When --from-control-plane is also "
        "set, entries here overlay on top of discovered upstreams — use to "
        "attach bearer-token auth to a discovered upstream."
    ),
)
@click.option(
    "--from-control-plane",
    "control_plane_url",
    default=None,
    help=(
        "Pull auto-discovered upstreams from this agent-bom control plane URL "
        "(hits /v1/gateway/upstreams/discovered). Fleet scans surface remote "
        "HTTP/SSE MCPs into this endpoint — the gateway registers whatever the "
        "fleet has discovered, so pilot teams don't start from a blank YAML."
    ),
)
@click.option(
    "--control-plane-token",
    "control_plane_token",
    envvar="AGENT_BOM_CONTROL_PLANE_TOKEN",
    default=None,
    help="Bearer token for the control plane API key (or set AGENT_BOM_CONTROL_PLANE_TOKEN).",
)
@click.option(
    "--policy",
    "policy_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Optional runtime policy JSON file (same format as `agent-bom proxy --policy`).",
)
@click.option("--bind", default="0.0.0.0:8090", show_default=True, help="Bind address host:port.")
@click.option(
    "--runtime-rate-limit-per-tenant-per-minute",
    type=int,
    envvar="AGENT_BOM_GATEWAY_RATE_LIMIT_PER_TENANT_PER_MINUTE",
    default=0,
    show_default=True,
    help="Tenant-scoped runtime request limit for gateway relay traffic (0 disables).",
)
@click.option(
    "--require-shared-rate-limit",
    is_flag=True,
    envvar="AGENT_BOM_GATEWAY_REQUIRE_SHARED_RATE_LIMIT",
    default=False,
    help="Fail closed unless gateway runtime rate limiting uses a shared backend.",
)
@click.option(
    "--bearer-token",
    envvar="AGENT_BOM_GATEWAY_BEARER_TOKEN",
    default=None,
    help="Require incoming bearer/API-key auth for gateway clients.",
)
@click.option(
    "--allow-insecure-no-auth",
    is_flag=True,
    default=False,
    help="Allow unauthenticated non-loopback gateway exposure. Unsafe outside local development.",
)
@click.option(
    "--detect-visual-leaks",
    is_flag=True,
    envvar="AGENT_BOM_GATEWAY_DETECT_VISUAL_LEAKS",
    default=False,
    help="OCR-scan image tool responses for credentials/PII (requires 'agent-bom[visual]').",
)
@click.option(
    "--allow-visual-leak-best-effort",
    is_flag=True,
    default=False,
    help="Continue startup if visual leak detection is enabled but OCR runtime support is unavailable.",
)
@click.option(
    "--log-level",
    type=click.Choice(["debug", "info", "warning", "error"], case_sensitive=False),
    default="info",
    show_default=True,
)
def serve_cmd(
    upstreams_path: Path | None,
    control_plane_url: str | None,
    control_plane_token: str | None,
    policy_path: Path | None,
    bind: str,
    runtime_rate_limit_per_tenant_per_minute: int,
    require_shared_rate_limit: bool,
    bearer_token: str | None,
    allow_insecure_no_auth: bool,
    detect_visual_leaks: bool,
    allow_visual_leak_best_effort: bool,
    log_level: str,
) -> None:
    """Run the gateway server on ``bind``.

    Upstreams come from (a) ``--from-control-plane`` auto-discovery, (b)
    a local ``--upstreams`` YAML, or both (YAML overlays on top of
    discovery). Must provide at least one — an empty gateway serves
    nothing.
    """
    logging.basicConfig(level=log_level.upper(), format="%(asctime)s %(levelname)s %(name)s %(message)s")

    if upstreams_path is None and control_plane_url is None:
        click.echo(
            "error: pass --upstreams or --from-control-plane (or both). See `agent-bom gateway serve --help`.",
            err=True,
        )
        sys.exit(2)

    try:
        import uvicorn
    except ImportError:
        click.echo(
            "The gateway requires the 'api' extra — install with `pip install 'agent-bom[api]'`",
            err=True,
        )
        sys.exit(2)

    from agent_bom.gateway_server import GatewaySettings, create_gateway_app
    from agent_bom.gateway_upstreams import (
        UpstreamConfigError,
        UpstreamRegistry,
        fetch_discovered_upstreams,
    )
    from agent_bom.runtime.visual_leak_detector import require_visual_leak_runtime

    registry: UpstreamRegistry | None = None

    if control_plane_url is not None:
        try:
            payload = fetch_discovered_upstreams(control_plane_url, token=control_plane_token)
            discovered = UpstreamRegistry.from_discovery_response(payload)
            click.echo(f"discovered {len(discovered)} upstream(s) from {control_plane_url}: {', '.join(discovered.names()) or '(none)'}")
            registry = discovered
        except Exception as exc:  # noqa: BLE001 — network/DNS/permission all surface here
            click.echo(f"control-plane discovery failed: {exc}", err=True)
            if upstreams_path is None:
                sys.exit(2)
            click.echo("continuing with local --upstreams only", err=True)

    if upstreams_path is not None:
        try:
            local = UpstreamRegistry.from_yaml(upstreams_path)
        except UpstreamConfigError as exc:
            click.echo(f"upstreams config error: {exc}", err=True)
            sys.exit(2)
        registry = local if registry is None else registry.merged_with(local)

    assert registry is not None  # guarded above

    policy: dict = {}
    if policy_path is not None:
        try:
            policy = json.loads(policy_path.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            click.echo(f"policy file error: {exc}", err=True)
            sys.exit(2)

    host, _, port = bind.partition(":")
    host = host or "0.0.0.0"  # nosec B104
    _enforce_remote_mcp_auth_defaults(host, bearer_token, allow_insecure_no_auth)
    if detect_visual_leaks and not allow_visual_leak_best_effort:
        try:
            require_visual_leak_runtime()
        except RuntimeError as exc:
            raise click.ClickException(str(exc)) from exc

    settings = GatewaySettings(
        registry=registry,
        policy=policy,
        audit_sink=None,
        bearer_token=bearer_token,
        enable_visual_leak_detection=detect_visual_leaks,
        require_visual_leak_detection_ready=detect_visual_leaks and not allow_visual_leak_best_effort,
        runtime_rate_limit_per_tenant_per_minute=max(runtime_rate_limit_per_tenant_per_minute, 0),
        require_shared_rate_limit=require_shared_rate_limit,
    )
    app = create_gateway_app(settings)

    # Binding to 0.0.0.0 is intentional for containerized deploys — ingress /
    # service mesh terminates external traffic in front of this pod. Set
    # --bind 127.0.0.1:8090 on a dev workstation to restrict.
    host = host  # nosec B104
    port_num = int(port or "8090")

    click.echo(f"agent-bom gateway serving on http://{host}:{port_num} fronting {len(registry)} upstream(s): {', '.join(registry.names())}")
    if bearer_token:
        click.echo("Auth: bearer/API-key token required for incoming gateway clients")
    elif allow_insecure_no_auth:
        click.echo("Auth: disabled by explicit override (--allow-insecure-no-auth)")
    if detect_visual_leaks:
        mode = "best-effort" if allow_visual_leak_best_effort else "required"
        click.echo(f"Visual leak detection: enabled ({mode})")
    uvicorn.run(app, host=host, port=port_num, log_level=log_level.lower())


__all__ = ["gateway_group", "serve_cmd"]
