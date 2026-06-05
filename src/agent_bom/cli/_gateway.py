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
from typing import cast

import click

from agent_bom.cli._common import read_json_file_for_cli
from agent_bom.cli._grouped_help import SuggestingGroup
from agent_bom.cli._server import _is_loopback_host

logger = logging.getLogger(__name__)


def _parse_bind(bind: str) -> tuple[str, int]:
    host, sep, port_text = bind.rpartition(":")
    if not sep:
        raise click.UsageError("--bind must be in host:port form, for example 127.0.0.1:8090.")
    host = host or "0.0.0.0"  # nosec B104 - explicit gateway bind default
    try:
        port_num = int(port_text)
    except ValueError as exc:
        raise click.UsageError("--bind port must be an integer from 1 to 65535.") from exc
    if not 1 <= port_num <= 65535:
        raise click.UsageError("--bind port must be in range 1..65535.")
    return host, port_num


def _enforce_gateway_auth_defaults(host: str, bearer_token: str | None, allow_insecure_no_auth: bool) -> None:
    if bearer_token or _is_loopback_host(host):
        return
    try:
        from agent_bom.api.auth import get_key_store

        if get_key_store().has_keys():
            return
    except Exception:
        # App construction performs the fail-closed check and reports
        # authentication backend startup errors without falling open.
        return
    if allow_insecure_no_auth:
        return
    raise click.ClickException(
        f"Refusing to expose `gateway serve` on non-loopback host {host!r} without incoming authentication. "
        "Set --bearer-token / AGENT_BOM_GATEWAY_BEARER_TOKEN, configure gateway API keys, "
        "or pass --allow-insecure-no-auth to override."
    )


@click.group(cls=SuggestingGroup, help="Multi-MCP gateway commands.")
def gateway_group() -> None:
    """Entry point for gateway subcommands."""


@gateway_group.command("init-policy")
@click.option(
    "--output",
    "-o",
    "output_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=Path("gateway-baseline-policy.json"),
    show_default=True,
    help="Output path for the rendered gateway baseline policy.",
)
@click.option(
    "--mode",
    type=click.Choice(["audit", "enforce"], case_sensitive=False),
    default="audit",
    show_default=True,
    help="Policy rollout mode. Audit renders advisory rules; enforce renders blocking rules.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["proxy", "control-plane"], case_sensitive=False),
    default="proxy",
    show_default=True,
    help="Render for local `gateway serve --policy` or for control-plane policy import.",
)
@click.option(
    "--tenant-id",
    default="default",
    show_default=True,
    help="Tenant id embedded in control-plane policy output.",
)
def init_policy_cmd(output_path: Path, mode: str, output_format: str, tenant_id: str) -> None:
    """Render the bundled secure-by-default gateway baseline policy."""
    from agent_bom.gateway_policy_templates import GatewayBaselineFormat, GatewayBaselineMode, render_gateway_baseline_policy
    from agent_bom.proxy_policy import summarize_policy_bundle

    mode_value = cast(GatewayBaselineMode, mode.lower())
    format_value = cast(GatewayBaselineFormat, output_format.lower())
    rendered = render_gateway_baseline_policy(
        mode=mode_value,
        output_format=format_value,
        tenant_id=tenant_id,
    )
    output_path.write_text(json.dumps(rendered, indent=2) + "\n")

    if output_format.lower() == "proxy":
        summary = summarize_policy_bundle(rendered)
        click.echo(f"Gateway baseline policy written to {output_path}")
        click.echo(f"Use it with: agent-bom gateway serve --policy {output_path} --upstreams <upstreams.yaml>")
        click.echo(
            f"Mode={mode.lower()} rules={summary['total_rules']} blocks={summary['blocking_rules']} warnings={summary['advisory_rules']}"
        )
    else:
        click.echo(f"Gateway baseline control-plane policy written to {output_path}")


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
        "streamable HTTP MCPs into this endpoint — the gateway registers whatever the "
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
@click.option(
    "--policy-reload-seconds",
    type=int,
    envvar="AGENT_BOM_GATEWAY_POLICY_RELOAD_SECONDS",
    default=0,
    show_default=True,
    help="Reload the gateway policy JSON file in-process on this interval (0 disables hot reload).",
)
@click.option(
    "--policy-bundle",
    "policy_bundle_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help=(
        "Control-plane GatewayPolicy bundle JSON (a list of policies, or "
        "{'policies': [...]}). Unlike --policy, these are enforced per "
        "source_agent via bound_agents/bound_agent_types/bound_environments, "
        "matching the per-MCP proxy. Export from the control plane's "
        "/v1/gateway/policies."
    ),
)
@click.option(
    "--firewall-policy",
    "firewall_policy_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help=("Inter-agent firewall policy JSON file (#982). Schema: see `agent-bom firewall validate --help` and docs/AGENT_FIREWALL.md."),
)
@click.option(
    "--firewall-policy-reload-seconds",
    type=int,
    envvar="AGENT_BOM_GATEWAY_FIREWALL_POLICY_RELOAD_SECONDS",
    default=0,
    show_default=True,
    help="Hot-reload the firewall policy JSON file on this interval (0 disables).",
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
    "--drift-enforcement",
    type=click.Choice(["off", "warn", "enforce"]),
    envvar="AGENT_BOM_GATEWAY_DRIFT_ENFORCEMENT",
    default="off",
    show_default=True,
    help="Act on open behavioral-drift incidents: 'enforce' blocks out-of-blueprint tools, 'warn' audits them, 'off' stays advisory.",
)
@click.option(
    "--anomaly-enforcement",
    type=click.Choice(["off", "warn", "enforce"]),
    envvar="AGENT_BOM_GATEWAY_ANOMALY_ENFORCEMENT",
    default="off",
    show_default=True,
    help="Act on cost-spike anomalies: 'enforce' blocks a runaway agent, 'warn' audits it, 'off' stays advisory.",
)
@click.option(
    "--fleet-enforcement",
    type=click.Choice(["off", "warn", "enforce"]),
    envvar="AGENT_BOM_GATEWAY_FLEET_ENFORCEMENT",
    default="off",
    show_default=True,
    help="Act on quarantined fleet agents: 'enforce' blocks every call from a quarantined agent, 'warn' audits it, 'off' stays advisory.",
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
    policy_reload_seconds: int,
    policy_bundle_path: Path | None,
    firewall_policy_path: Path | None,
    firewall_policy_reload_seconds: int,
    bind: str,
    runtime_rate_limit_per_tenant_per_minute: int,
    require_shared_rate_limit: bool,
    bearer_token: str | None,
    allow_insecure_no_auth: bool,
    detect_visual_leaks: bool,
    drift_enforcement: str,
    anomaly_enforcement: str,
    fleet_enforcement: str,
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

    host, port_num = _parse_bind(bind)

    from agent_bom.gateway_server import GatewaySettings, build_control_plane_audit_sink, create_gateway_app
    from agent_bom.gateway_upstreams import (
        UpstreamConfigError,
        UpstreamRegistry,
        fetch_discovered_upstreams,
    )
    from agent_bom.proxy_policy import summarize_policy_bundle

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
        policy = read_json_file_for_cli(policy_path, label="policy file")
    if policy_reload_seconds < 0:
        raise click.ClickException("--policy-reload-seconds must be >= 0")
    if policy_reload_seconds > 0 and policy_path is None:
        raise click.ClickException("--policy-reload-seconds requires --policy")

    if firewall_policy_reload_seconds < 0:
        raise click.ClickException("--firewall-policy-reload-seconds must be >= 0")
    if firewall_policy_reload_seconds > 0 and firewall_policy_path is None:
        raise click.ClickException("--firewall-policy-reload-seconds requires --firewall-policy")
    # Fail fast on a malformed firewall policy at startup so operators see the
    # error immediately instead of after the gateway is up. The same loader
    # runs on every hot reload.
    if firewall_policy_path is not None:
        from agent_bom.firewall import FirewallPolicyError, load_firewall_policy_file

        try:
            load_firewall_policy_file(firewall_policy_path)
        except FirewallPolicyError as exc:
            raise click.ClickException(f"firewall policy invalid: {exc}") from exc

    _enforce_gateway_auth_defaults(host, bearer_token, allow_insecure_no_auth)
    if detect_visual_leaks and not allow_visual_leak_best_effort:
        try:
            from agent_bom.runtime.visual_leak_detector import require_visual_leak_runtime

            require_visual_leak_runtime()
        except RuntimeError as exc:
            raise click.ClickException(str(exc)) from exc

    audit_sink = build_control_plane_audit_sink(control_plane_url, control_plane_token, source_id="gateway") if control_plane_url else None

    control_plane_policies: list[dict] = []
    if policy_bundle_path is not None:
        import json as _json

        raw_bundle = _json.loads(policy_bundle_path.read_text())
        bundle_list = raw_bundle.get("policies", []) if isinstance(raw_bundle, dict) else raw_bundle
        if not isinstance(bundle_list, list):
            raise click.ClickException("--policy-bundle must be a JSON list of policies or {'policies': [...]}")
        control_plane_policies = [p for p in bundle_list if isinstance(p, dict)]
        click.echo(f"loaded {len(control_plane_policies)} control-plane policy/policies from {policy_bundle_path}")

    settings = GatewaySettings(
        registry=registry,
        policy=policy,
        audit_sink=audit_sink,
        control_plane_policies=control_plane_policies,
        bearer_token=bearer_token,
        enable_visual_leak_detection=detect_visual_leaks,
        require_visual_leak_detection_ready=detect_visual_leaks and not allow_visual_leak_best_effort,
        runtime_rate_limit_per_tenant_per_minute=max(runtime_rate_limit_per_tenant_per_minute, 0),
        require_shared_rate_limit=require_shared_rate_limit,
        policy_path=policy_path,
        policy_reload_interval_seconds=max(policy_reload_seconds, 0),
        firewall_policy_path=firewall_policy_path,
        firewall_policy_reload_interval_seconds=max(firewall_policy_reload_seconds, 0),
        listener_host=host,
        allow_insecure_no_auth=allow_insecure_no_auth,
        drift_enforcement_mode=drift_enforcement,
        anomaly_enforcement_mode=anomaly_enforcement,
        fleet_enforcement_mode=fleet_enforcement,
    )
    app = create_gateway_app(settings)
    policy_summary = summarize_policy_bundle(policy)

    # Binding to 0.0.0.0 is intentional for containerized deploys — ingress /
    # service mesh terminates external traffic in front of this pod. Set
    # --bind 127.0.0.1:8090 on a dev workstation to restrict.
    host = host  # nosec B104
    click.echo(f"agent-bom gateway serving on http://{host}:{port_num} fronting {len(registry)} upstream(s): {', '.join(registry.names())}")
    rows = [
        ("Bind", f"http://{host}:{port_num}"),
        ("Upstreams", f"{len(registry)} configured: {', '.join(registry.names()) or '(none)'}"),
        (
            "Auth",
            "Bearer/API-key token required for incoming gateway clients"
            if bearer_token
            else (
                "Disabled by explicit override (--allow-insecure-no-auth)"
                if allow_insecure_no_auth
                else "Loopback-only without transport auth; add --bearer-token before exposing remotely"
            ),
        ),
        (
            "Policy",
            (
                f"{policy_summary['summary']} "
                f"Rules={policy_summary['total_rules']} "
                f"(block={policy_summary['blocking_rules']}, warn={policy_summary['advisory_rules']})"
            ),
        ),
    ]
    if detect_visual_leaks:
        mode = "best-effort" if allow_visual_leak_best_effort else "required"
        rows.append(("Visual leaks", f"Enabled ({mode})"))
    if policy_path and policy_reload_seconds > 0:
        rows.append(("Policy reload", f"Policy hot reload: enabled every {policy_reload_seconds}s from {policy_path}"))
    if firewall_policy_path is not None:
        from agent_bom.firewall import load_firewall_policy_file

        firewall_policy = load_firewall_policy_file(firewall_policy_path)
        rows.append(
            (
                "Firewall",
                f"{len(firewall_policy.rules)} rule(s) "
                f"(default={firewall_policy.default_decision.value}, mode={firewall_policy.enforcement_mode.value}) "
                f"from {firewall_policy_path}",
            )
        )
    if firewall_policy_path and firewall_policy_reload_seconds > 0:
        rows.append(
            (
                "Firewall reload",
                f"Firewall hot reload: enabled every {firewall_policy_reload_seconds}s from {firewall_policy_path}",
            )
        )
    click.echo("")
    click.echo("  agent-bom gateway")
    for label, value in rows:
        click.echo(f"  {label:<11} {value}")
    click.echo("  Press Ctrl+C to stop.\n")
    uvicorn.run(app, host=host, port=port_num, log_level=log_level.lower())


__all__ = ["gateway_group", "init_policy_cmd", "serve_cmd"]
