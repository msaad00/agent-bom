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

logger = logging.getLogger(__name__)


@click.group(help="Multi-MCP gateway commands.")
def gateway_group() -> None:
    """Entry point for gateway subcommands."""


@gateway_group.command("serve")
@click.option(
    "--upstreams",
    "upstreams_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="YAML file listing upstream MCP servers (see docs/design/MULTI_MCP_GATEWAY.md).",
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
    "--log-level",
    type=click.Choice(["debug", "info", "warning", "error"], case_sensitive=False),
    default="info",
    show_default=True,
)
def serve_cmd(
    upstreams_path: Path,
    policy_path: Path | None,
    bind: str,
    log_level: str,
) -> None:
    """Run the gateway server on ``bind`` and front the upstreams in ``upstreams.yaml``."""
    logging.basicConfig(level=log_level.upper(), format="%(asctime)s %(levelname)s %(name)s %(message)s")

    try:
        import uvicorn
    except ImportError:
        click.echo(
            "The gateway requires the 'api' extra — install with `pip install 'agent-bom[api]'`",
            err=True,
        )
        sys.exit(2)

    from agent_bom.gateway_server import GatewaySettings, create_gateway_app
    from agent_bom.gateway_upstreams import UpstreamConfigError, UpstreamRegistry

    try:
        registry = UpstreamRegistry.from_yaml(upstreams_path)
    except UpstreamConfigError as exc:
        click.echo(f"upstreams config error: {exc}", err=True)
        sys.exit(2)

    policy: dict = {}
    if policy_path is not None:
        try:
            policy = json.loads(policy_path.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            click.echo(f"policy file error: {exc}", err=True)
            sys.exit(2)

    settings = GatewaySettings(registry=registry, policy=policy, audit_sink=None)
    app = create_gateway_app(settings)

    host, _, port = bind.partition(":")
    # Binding to 0.0.0.0 is intentional for containerized deploys — ingress /
    # service mesh terminates external traffic in front of this pod. Set
    # --bind 127.0.0.1:8090 on a dev workstation to restrict.
    host = host or "0.0.0.0"  # nosec B104
    port_num = int(port or "8090")

    click.echo(f"agent-bom gateway serving on http://{host}:{port_num} fronting {len(registry)} upstream(s): {', '.join(registry.names())}")
    uvicorn.run(app, host=host, port=port_num, log_level=log_level.lower())


__all__ = ["gateway_group", "serve_cmd"]
