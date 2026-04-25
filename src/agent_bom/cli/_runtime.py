"""Runtime commands — proxy, protect, watch, audit-replay."""

from __future__ import annotations

import sys

import click
from rich.console import Console


@click.command("proxy")
@click.option("--policy", type=click.Path(exists=True), help="Policy file for runtime enforcement")
@click.option("--log", "log_path", default=None, help="Audit log output path (JSONL)")
@click.option("--block-undeclared", is_flag=True, help="Block tool calls not in tools/list response")
@click.option("--detect-credentials", is_flag=True, help="Detect credential leaks in tool responses")
@click.option(
    "--detect-visual-leaks",
    is_flag=True,
    help="OCR-scan image tool responses for credentials/PII (requires 'agent-bom[visual]')",
)
@click.option("--rate-limit-threshold", type=int, default=0, help="Max calls per tool per 60s (0=disabled)")
@click.option("--log-only", is_flag=True, help="Log alerts without blocking (advisory mode)")
@click.option(
    "--alert-webhook", default=None, envvar="AGENT_BOM_ALERT_WEBHOOK", help="Webhook URL for runtime alerts (Slack/Teams/PagerDuty)"
)
@click.option("--metrics-port", default=8422, show_default=True, help="Prometheus metrics port (0 to disable)")
@click.option("--metrics-token", default=None, envvar="AGENT_BOM_METRICS_TOKEN", help="Bearer token for Prometheus /metrics endpoint")
@click.option(
    "--control-plane-url",
    default=None,
    envvar="AGENT_BOM_API_URL",
    help="Control-plane base URL for gateway policy pull and proxy audit push",
)
@click.option(
    "--control-plane-token",
    default=None,
    envvar="AGENT_BOM_API_TOKEN",
    help="Bearer token or API key for control-plane auth",
)
@click.option(
    "--policy-refresh-seconds",
    type=int,
    default=30,
    show_default=True,
    help="How often to refresh enabled gateway policies from the control plane",
)
@click.option(
    "--audit-push-interval",
    type=int,
    default=10,
    show_default=True,
    help="How often to batch-push proxy alerts to the control plane",
)
@click.option(
    "--response-sign-key",
    default=None,
    envvar="AGENT_BOM_RESPONSE_SIGN_KEY",
    help="Secret key for HMAC-SHA256 response signing written to audit log (tamper detection)",
)
@click.option(
    "--url",
    default=None,
    envvar="AGENT_BOM_PROXY_URL",
    help="SSE/HTTP MCP server URL (use instead of server_cmd for HTTP/SSE transport)",
)
@click.option(
    "--isolate/--no-isolate",
    default=False,
    envvar="AGENT_BOM_MCP_SANDBOX",
    help="Run the stdio MCP server through a hardened Docker/Podman container.",
)
@click.option(
    "--sandbox-runtime",
    default=None,
    envvar="AGENT_BOM_MCP_SANDBOX_RUNTIME",
    type=click.Choice(["auto", "docker", "podman"]),
    help="Container runtime for --isolate (default: auto).",
)
@click.option(
    "--sandbox-image",
    default=None,
    envvar="AGENT_BOM_MCP_SANDBOX_IMAGE",
    help="Container image used to run non-container server commands in --isolate mode.",
)
@click.option(
    "--sandbox-mount",
    multiple=True,
    metavar="HOST:CONTAINER[:ro|rw]",
    help="Explicit bind mount for --isolate. Defaults to read-only.",
)
@click.option("--sandbox-cpus", default=None, envvar="AGENT_BOM_MCP_SANDBOX_CPUS", help="CPU limit for isolated MCP server.")
@click.option("--sandbox-memory", default=None, envvar="AGENT_BOM_MCP_SANDBOX_MEMORY", help="Memory limit for isolated MCP server.")
@click.option(
    "--sandbox-pids-limit",
    default=None,
    type=int,
    envvar="AGENT_BOM_MCP_SANDBOX_PIDS_LIMIT",
    help="Process limit for isolated MCP server.",
)
@click.option(
    "--sandbox-tmpfs-size",
    default=None,
    envvar="AGENT_BOM_MCP_SANDBOX_TMPFS_SIZE",
    help="Writable /tmp tmpfs size for isolated MCP server, for example 64m.",
)
@click.option(
    "--sandbox-timeout-seconds",
    default=None,
    type=int,
    envvar="AGENT_BOM_MCP_SANDBOX_TIMEOUT_SECONDS",
    help="Optional max runtime before the isolated MCP server is terminated.",
)
@click.option(
    "--sandbox-egress",
    default=None,
    envvar="AGENT_BOM_MCP_SANDBOX_EGRESS",
    type=click.Choice(["deny", "allow-all"]),
    help="Network egress posture for isolated MCP server.",
)
@click.argument("server_cmd", nargs=-1, required=False)
def proxy_cmd(
    policy,
    log_path,
    block_undeclared,
    detect_credentials,
    detect_visual_leaks,
    rate_limit_threshold,
    log_only,
    alert_webhook,
    metrics_port,
    metrics_token,
    control_plane_url,
    control_plane_token,
    policy_refresh_seconds,
    audit_push_interval,
    response_sign_key,
    url,
    isolate,
    sandbox_runtime,
    sandbox_image,
    sandbox_mount,
    sandbox_cpus,
    sandbox_memory,
    sandbox_pids_limit,
    sandbox_tmpfs_size,
    sandbox_timeout_seconds,
    sandbox_egress,
    server_cmd,
):
    """Run an MCP server through agent-bom's security proxy.

    \b
    Intercepts JSON-RPC messages between client and server:
    - Logs every tools/call invocation to an audit trail
    - Optionally enforces policy rules in real-time
    - Blocks undeclared tools (not in tools/list response)
    - Detects tool drift (rug pull), dangerous arguments, credential leaks
    - Rate limiting and suspicious sequence detection
    - HMAC-SHA256 response signing in audit log (--response-sign-key)

    Boundary:
    - scanner and MCP server modes are read-only
    - proxy mode intentionally executes the wrapped stdio server or connects
      to the remote MCP endpoint so it can enforce policy on live traffic

    \b
    Usage (stdio — subprocess):
      agent-bom proxy -- npx @modelcontextprotocol/server-filesystem /tmp
      agent-bom proxy --log audit.jsonl -- npx @mcp/server-github
      agent-bom proxy --policy policy.json --detect-credentials --block-undeclared -- npx @mcp/server-postgres
      agent-bom proxy --detect-credentials --log-only -- npx @mcp/server-github
      agent-bom proxy --log audit.jsonl --response-sign-key $MY_SECRET -- npx @mcp/server-github

    \b
    Usage (SSE/HTTP — remote server):
      agent-bom proxy --url http://localhost:3000
      agent-bom proxy --url https://mcp.example.com --log audit.jsonl --detect-credentials --block-undeclared
      agent-bom proxy --url http://localhost:3000 --policy policy.json

    \b
    Configure in your MCP client (e.g. Claude Desktop):
      {
        "mcpServers": {
          "filesystem": {
            "command": "agent-bom",
        "args": ["proxy", "--log", "audit.jsonl", "--detect-credentials",
                 "--block-undeclared",
                 "--", "npx", "@modelcontextprotocol/server-filesystem", "/tmp"]
          }
        }
      }
    """
    import asyncio

    from agent_bom.project_config import get_policy_path, load_project_config

    # Auto-load .agent-bom.yaml policy if --policy not explicitly given
    if not policy:
        _cfg = load_project_config()
        if _cfg and (cfg_policy := get_policy_path(_cfg)):
            policy = str(cfg_policy)

    # SSE/HTTP mode: --url provided
    if url:
        from agent_bom.proxy import _proxy_sse_server

        exit_code = asyncio.run(
            _proxy_sse_server(
                url=url,
                policy_path=policy,
                log_path=log_path,
                block_undeclared=block_undeclared,
                alert_webhook=alert_webhook,
            )
        )
        sys.exit(exit_code)

    # Stdio mode: server_cmd required
    if not server_cmd:
        raise click.UsageError("Provide a server command (e.g. -- npx @mcp/server-filesystem /tmp) or --url for SSE/HTTP mode.")

    from agent_bom.proxy import run_proxy
    from agent_bom.proxy_sandbox import sandbox_config_from_env

    try:
        sandbox_config = sandbox_config_from_env(
            enabled=isolate,
            runtime=sandbox_runtime,
            image=sandbox_image,
            mounts=tuple(sandbox_mount),
            cpus=sandbox_cpus,
            memory=sandbox_memory,
            pids_limit=sandbox_pids_limit,
            tmpfs_size=sandbox_tmpfs_size,
            timeout_seconds=sandbox_timeout_seconds,
            egress_policy=sandbox_egress,
        )
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc

    exit_code = asyncio.run(
        run_proxy(
            server_cmd=list(server_cmd),
            policy_path=policy,
            log_path=log_path,
            block_undeclared=block_undeclared,
            detect_credentials=detect_credentials,
            detect_visual_leaks=detect_visual_leaks,
            rate_limit_threshold=rate_limit_threshold,
            log_only=log_only,
            alert_webhook=alert_webhook,
            metrics_port=metrics_port,
            metrics_token=metrics_token,
            control_plane_url=control_plane_url,
            control_plane_token=control_plane_token,
            policy_refresh_seconds=policy_refresh_seconds,
            audit_push_interval=audit_push_interval,
            response_signing_key=response_sign_key,
            sandbox_config=sandbox_config,
        )
    )
    sys.exit(exit_code)


@click.command("proxy-configure")
@click.option("--policy", type=click.Path(exists=True), default=None, help="Policy JSON file to pass to each proxy instance")
@click.option("--log-dir", default=None, type=click.Path(), help="Directory for per-server audit JSONL logs")
@click.option(
    "--secure-defaults/--no-secure-defaults",
    default=True,
    show_default=True,
    help="Inject the recommended hardening flags (--detect-credentials and --block-undeclared)",
)
@click.option("--detect-credentials", is_flag=True, help="Enable credential leak detection in each proxy")
@click.option("--block-undeclared", is_flag=True, help="Block undeclared tools in each proxy")
@click.option(
    "--control-plane-url",
    default=None,
    envvar="AGENT_BOM_API_URL",
    help="Control-plane base URL for gateway policy pull and proxy audit push",
)
@click.option(
    "--control-plane-token",
    default=None,
    envvar="AGENT_BOM_API_TOKEN",
    help="Bearer token or API key for control-plane auth",
)
@click.option(
    "--policy-refresh-seconds",
    type=int,
    default=30,
    show_default=True,
    help="How often to refresh enabled gateway policies from the control plane",
)
@click.option(
    "--audit-push-interval",
    type=int,
    default=10,
    show_default=True,
    help="How often to batch-push proxy alerts to the control plane",
)
@click.option(
    "--apply",
    is_flag=True,
    help="Write proxy config back to source JSON config files (default: preview only)",
)
@click.option("--project", default=None, type=click.Path(exists=True), help="Project directory to scan for MCP configs")
def proxy_configure_cmd(
    policy,
    log_dir,
    secure_defaults,
    detect_credentials,
    block_undeclared,
    control_plane_url,
    control_plane_token,
    policy_refresh_seconds,
    audit_push_interval,
    apply,
    project,
):
    """Auto-configure the agent-bom proxy for discovered MCP servers.

    \b
    Discovers all MCP servers on this machine, then generates proxy-wrapped
    configuration entries for every STDIO server.  The proxy adds:
    - Audit logging (--log-dir)
    - Policy enforcement (--policy)
    - Credential leak detection (--detect-credentials)
    - Undeclared-tool blocking (--block-undeclared)

    \b
    By default, shows a preview.  Use --apply to write changes back to the
    original config files (JSON only — claude_desktop_config.json, mcp.json…).

    Recommended hardening for developer environments:
    - secure defaults already inject --detect-credentials and --block-undeclared
    - --log-dir for auditable JSONL logs
    - --policy for explicit allowlist/blocklist/read-only enforcement

    \b
    Example:
      agent-bom proxy-configure --log-dir ~/.agent-bom/logs
      agent-bom proxy-configure --policy policy.json --log-dir ~/.agent-bom/logs --apply
      agent-bom proxy-configure --control-plane-url https://agent-bom.example.com --control-plane-token "$TOKEN" --apply
      agent-bom proxy-configure --no-secure-defaults --apply
    """
    from agent_bom.discovery import discover_all
    from agent_bom.proxy_configure import apply_proxy_configs, auto_configure_proxies

    con = Console()

    agents = discover_all(project_dir=project)
    configs = auto_configure_proxies(
        agents,
        policy_path=policy,
        log_dir=log_dir,
        secure_defaults=secure_defaults,
        detect_credentials=detect_credentials,
        block_undeclared=block_undeclared,
        control_plane_url=control_plane_url,
        control_plane_token=control_plane_token,
        policy_refresh_seconds=policy_refresh_seconds,
        audit_push_interval=audit_push_interval,
    )

    if not configs:
        con.print("[yellow]No eligible STDIO MCP servers found (need command + stdio transport).[/yellow]")
        return

    con.print(f"\n[bold blue]Proxy configuration for {len(configs)} MCP server(s):[/bold blue]\n")

    for cfg in configs:
        con.print(f"  [bold]{cfg.server_name}[/bold]  [dim]({cfg.config_path})[/dim]")
        con.print(f"    Original : {cfg.original_command} {' '.join(cfg.original_args)}")
        proxy_preview = f"agent-bom {' '.join(cfg.proxied_args)}"
        con.print(f"    Proxied  : [green]{proxy_preview}[/green]")
        con.print()

    if apply:
        n = apply_proxy_configs(configs, dry_run=False)
        if n:
            con.print(f"[green]✓[/green] Patched {n} config file(s).")
        else:
            con.print("[yellow]⚠[/yellow] No JSON config files were patched (SSE servers, missing files, or no matching entries).")
    else:
        con.print("[dim]Pass --apply to write these changes to config files.[/dim]")


@click.command("proxy-bootstrap")
@click.option(
    "--bundle-dir",
    required=True,
    type=click.Path(path_type=str),
    help="Directory where the endpoint onboarding artifacts should be written",
)
@click.option(
    "--control-plane-url",
    required=True,
    envvar="AGENT_BOM_API_URL",
    help="Control-plane base URL for gateway policy pull and proxy audit push",
)
@click.option(
    "--control-plane-token",
    default=None,
    envvar="AGENT_BOM_API_TOKEN",
    help="Bearer token or API key for control-plane auth",
)
@click.option("--push-url", default=None, help="Optional fleet sync endpoint to write into managed endpoint artifacts")
@click.option("--push-api-key", default=None, help="Optional fleet sync API key to write into managed endpoint artifacts")
@click.option("--source-id", default=None, help="Optional stable endpoint source ID to embed in the rollout bundle")
@click.option("--enrollment-name", default=None, help="Optional rollout or enrollment name to stamp into the bundle manifest")
@click.option("--owner", default=None, help="Optional owning team or operator for the endpoint rollout manifest")
@click.option("--environment", default=None, help="Optional environment label to stamp into the endpoint rollout manifest")
@click.option("--tag", "tags", multiple=True, help="Optional repeated tag to stamp into the endpoint rollout manifest")
@click.option(
    "--mdm-provider",
    type=click.Choice(["jamf", "intune", "kandji"], case_sensitive=False),
    default=None,
    help="Optional primary MDM provider label for the endpoint rollout manifest",
)
@click.option("--policy", type=click.Path(exists=True), default=None, help="Policy JSON file to pass to each proxy instance")
@click.option(
    "--log-dir",
    default="~/.agent-bom/logs",
    show_default=True,
    type=click.Path(),
    help="Directory for per-server audit JSONL logs",
)
@click.option(
    "--secure-defaults/--no-secure-defaults",
    default=True,
    show_default=True,
    help="Inject the recommended hardening flags (--detect-credentials and --block-undeclared)",
)
@click.option("--detect-credentials", is_flag=True, help="Enable credential leak detection in each proxy")
@click.option("--block-undeclared", is_flag=True, help="Block undeclared tools in each proxy")
@click.option(
    "--policy-refresh-seconds",
    type=int,
    default=30,
    show_default=True,
    help="How often to refresh enabled gateway policies from the control plane",
)
@click.option(
    "--audit-push-interval",
    type=int,
    default=10,
    show_default=True,
    help="How often to batch-push proxy alerts to the control plane",
)
@click.option("--project", default=None, type=click.Path(exists=True), help="Project directory to scan for MCP configs")
@click.option("--apply", is_flag=True, help="Also patch the current machine's supported JSON MCP configs")
def proxy_bootstrap_cmd(
    bundle_dir,
    control_plane_url,
    control_plane_token,
    push_url,
    push_api_key,
    source_id,
    enrollment_name,
    owner,
    environment,
    tags,
    mdm_provider,
    policy,
    log_dir,
    secure_defaults,
    detect_credentials,
    block_undeclared,
    policy_refresh_seconds,
    audit_push_interval,
    project,
    apply,
):
    """Generate managed endpoint onboarding artifacts for proxy + fleet rollout.

    \b
    Writes:
    - macOS/Linux shell bootstrap script
    - Windows PowerShell bootstrap script
    - optional fleet-sync env + launchd plist artifacts
    - machine-readable summary JSON

    \b
    Use this when you want one IT-owned bundle instead of hand-editing MCP
    configs on every laptop.
    """
    from pathlib import Path

    from agent_bom.discovery import discover_all
    from agent_bom.endpoint_onboarding import write_endpoint_onboarding_bundle
    from agent_bom.proxy_configure import apply_proxy_configs, auto_configure_proxies

    con = Console()
    bundle_path = Path(bundle_dir).expanduser()
    artifacts = write_endpoint_onboarding_bundle(
        bundle_path,
        control_plane_url=control_plane_url,
        control_plane_token=control_plane_token,
        policy_refresh_seconds=policy_refresh_seconds,
        audit_push_interval=audit_push_interval,
        policy_path=policy,
        log_dir=log_dir,
        secure_defaults=secure_defaults,
        detect_credentials=detect_credentials,
        block_undeclared=block_undeclared,
        push_url=push_url,
        push_api_key=push_api_key,
        source_id=source_id,
        enrollment_name=enrollment_name,
        owner=owner,
        environment=environment,
        tags=list(tags),
        mdm_provider=mdm_provider,
    )
    con.print(f"[green]✓[/green] Wrote endpoint onboarding bundle to [bold]{bundle_path}[/bold]")
    for name, artifact_path in artifacts.items():
        con.print(f"  [bold]{name}[/bold]: [dim]{artifact_path}[/dim]")

    if not apply:
        return

    agents = discover_all(project_dir=project)
    configs = auto_configure_proxies(
        agents,
        policy_path=policy,
        log_dir=log_dir,
        secure_defaults=secure_defaults,
        detect_credentials=detect_credentials,
        block_undeclared=block_undeclared,
        control_plane_url=control_plane_url,
        control_plane_token=control_plane_token,
        policy_refresh_seconds=policy_refresh_seconds,
        audit_push_interval=audit_push_interval,
    )
    if not configs:
        con.print("[yellow]No eligible STDIO MCP servers found for local patching.[/yellow]")
        return
    patched = apply_proxy_configs(configs, dry_run=False)
    if patched:
        con.print(f"[green]✓[/green] Patched {patched} local config file(s).")
    else:
        con.print("[yellow]⚠[/yellow] No local config files were patched.")


@click.command("protect")
@click.option(
    "--mode",
    type=click.Choice(["stdin", "http"]),
    default="stdin",
    show_default=True,
    help="Input mode: stdin (line-delimited JSON) or http (HTTP endpoint)",
)
@click.option("--port", default=8423, show_default=True, help="HTTP listen port (used with --mode http)")
@click.option("--host", default="127.0.0.1", show_default=True, help="HTTP bind address (used with --mode http)")
@click.option("--detectors", default="all", show_default=True, help="Comma-separated detector list: drift,args,creds,rate,sequence")
@click.option("--alert-file", default=None, help="Write alerts to JSONL file")
@click.option(
    "--alert-webhook", default=None, envvar="AGENT_BOM_ALERT_WEBHOOK", help="Webhook URL for runtime alerts (Slack/Teams/PagerDuty)"
)
@click.option("--log-level", "log_level", type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False), default="INFO")
@click.option("--log-json", "log_json", is_flag=True, help="Structured JSON logs")
@click.option("--shield", is_flag=True, help="Enable deep defense mode (correlated threat scoring, escalation, kill-switch)")
@click.option(
    "--correlation-window",
    default=30.0,
    show_default=True,
    help="Alert correlation window in seconds (used with --shield)",
)
def protect_cmd(mode, port, host, detectors, alert_file, alert_webhook, log_level, log_json, shield, correlation_window):
    """Run the runtime protection engine as a standalone monitor.

    \b
    Analyzes tool calls and responses through 8 security detectors:
    - Tool drift detection (rug pull / capability changes)
    - Argument analysis (shell injection, path traversal)
    - Credential leak detection (API keys, tokens in responses)
    - Rate limiting (abnormal call frequency)
    - Sequence analysis (suspicious multi-step patterns)
    - Response inspection (cloaking, SVG, invisible characters)
    - Vector DB injection detection (RAG/cache poisoning)
    - Cross-agent correlation (lateral movement patterns)

    \b
    stdin mode (default) — pipe line-delimited JSON:
      echo '{"tool_name":"exec","arguments":{"cmd":"rm -rf /"}}' | agent-bom runtime protect
      cat otel-export.jsonl | agent-bom runtime protect --alert-file alerts.jsonl

    \b
    http mode — start an HTTP endpoint:
      agent-bom runtime protect --mode http --port 8423
      # POST /tool-call, /tool-response, /drift-check; GET /status

    \b
    Input JSON formats:
      Tool call:     {"tool_name": "read_file", "arguments": {"path": "/etc/passwd"}}
      Response:      {"type": "response", "tool_name": "read_file", "text": "..."}
      Drift check:   {"type": "drift", "tools": ["read_file", "exec_cmd"]}
    """
    import asyncio
    import signal

    from agent_bom.alerts.dispatcher import AlertDispatcher
    from agent_bom.logging_config import setup_logging
    from agent_bom.project_config import load_project_config

    # Auto-load .agent-bom.yaml for alert_webhook if not explicitly given
    _proj_cfg = load_project_config()
    if _proj_cfg:
        if not alert_webhook and _proj_cfg.get("alert_webhook"):
            alert_webhook = _proj_cfg["alert_webhook"]
    from agent_bom.runtime.protection import ProtectionEngine
    from agent_bom.runtime.server import run_http_mode, run_stdin_mode

    setup_logging(level=log_level, json_output=log_json)

    # Build dispatcher with configured channels
    dispatcher = AlertDispatcher()

    if alert_webhook:
        dispatcher.add_webhook(alert_webhook)

    # File channel: append alerts as JSONL
    if alert_file:

        class _FileChannel:
            def __init__(self, path: str) -> None:
                self._path = path

            async def send(self, alert: dict) -> bool:
                import json as _json

                with open(self._path, "a") as f:
                    f.write(_json.dumps(alert) + "\n")
                return True

        dispatcher.add_channel(_FileChannel(alert_file))

    # Build engine
    engine = ProtectionEngine(
        dispatcher=dispatcher,
        shield=shield,
        correlation_window=correlation_window,
    )

    # Configure detectors based on selection
    if detectors != "all":
        enabled = {d.strip().lower() for d in detectors.split(",")}
        detector_map = {
            "drift": "drift_detector",
            "args": "arg_analyzer",
            "creds": "cred_detector",
            "rate": "rate_tracker",
            "sequence": "seq_analyzer",
        }
        active_count = 0
        for name, attr in detector_map.items():
            if name not in enabled:
                # Replace with a no-op stub
                setattr(engine, attr, _NoOpDetector())
            else:
                active_count += 1
        engine._stats.detectors_active = active_count

    console = Console(stderr=True)
    console.print(f"[bold green]Runtime protection engine starting ({mode} mode)[/bold green]")

    async def _run() -> None:
        loop = asyncio.get_running_loop()
        stop_event = asyncio.Event()

        def _signal_handler() -> None:
            console.print("\n[yellow]Shutting down...[/yellow]")
            stop_event.set()

        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, _signal_handler)

        if mode == "http":
            task = asyncio.create_task(run_http_mode(engine, host, port))
        else:
            task = asyncio.create_task(run_stdin_mode(engine))

        # Wait for stop signal or task completion
        done = asyncio.create_task(stop_event.wait())
        await asyncio.wait([task, done], return_when=asyncio.FIRST_COMPLETED)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        engine.stop()
        stats = engine.status()
        console.print(f"[dim]Tool calls analyzed: {stats['tool_calls_analyzed']}, Alerts: {stats['alerts_generated']}[/dim]")

    asyncio.run(_run())


class _NoOpDetector:
    """Stub detector that does nothing — used when a detector is disabled."""

    def check(self, *args, **kwargs):  # noqa: N805
        return []

    def record(self, *args, **kwargs):
        return []


@click.command("watch")
@click.option("--webhook", default=None, help="Webhook URL for alerts (Slack/Teams/PagerDuty)")
@click.option("--log", "alert_log", default=None, help="Alert log file (JSONL)")
@click.option("--interval", default=2.0, type=float, help="Debounce interval in seconds")
def watch_cmd(webhook, alert_log, interval):
    """Watch MCP configs for changes and alert on new risks.

    \b
    Continuously monitors MCP client configuration files. On change:
    - Re-scans the affected config
    - Diffs against the last scan
    - Alerts if new vulnerabilities or risks are introduced

    \b
    Requires: pip install 'agent-bom[watch]'

    \b
    Usage:
      agent-bom runtime watch
      agent-bom runtime watch --webhook https://hooks.slack.com/services/...
      agent-bom runtime watch --log alerts.jsonl
    """
    from agent_bom.watch import (
        AlertSink,
        ConsoleAlertSink,
        FileAlertSink,
        WebhookAlertSink,
        discover_config_dirs,
        start_watching,
    )

    console = Console()

    sinks: list[AlertSink] = [ConsoleAlertSink()]
    if webhook:
        sinks.append(WebhookAlertSink(webhook))
    if alert_log:
        sinks.append(FileAlertSink(alert_log))

    dirs = discover_config_dirs()
    if not dirs:
        console.print("[yellow]No MCP config directories found to watch.[/yellow]")
        sys.exit(0)

    console.print(f"\n[bold blue]Watching {len(dirs)} config director{'ies' if len(dirs) > 1 else 'y'}...[/bold blue]")
    for d in dirs:
        console.print(f"  [dim]{d}[/dim]")
    console.print("\n  [dim]Press Ctrl+C to stop.[/dim]\n")

    start_watching(sinks, debounce_seconds=interval)


@click.command("audit-replay")
@click.argument("log_path", type=click.Path(exists=True))
@click.option("--tool", default=None, help="Filter entries by tool name (substring match)")
@click.option("--type", "entry_type", default=None, help="Filter by entry type (tools/call, relay_error, …)")
@click.option("--blocked-only", is_flag=True, help="Show only blocked tool calls")
@click.option("--alerts-only", is_flag=True, help="Show only runtime detector alerts")
@click.option(
    "--sign-key",
    default=None,
    envvar="AGENT_BOM_RESPONSE_SIGN_KEY",
    help="Secret key used when the proxy was started with --response-sign-key",
)
@click.option("--verify-hmac", is_flag=True, help="Verify HMAC-SHA256 response signatures in the log")
@click.option("--verify-chain", is_flag=True, help="Verify prev-hash chaining across audit log records")
@click.option("--json", "as_json", is_flag=True, help="Output machine-readable JSON summary (for CI)")
def audit_replay_cmd(log_path, tool, entry_type, blocked_only, alerts_only, sign_key, verify_hmac, verify_chain, as_json):
    """View and analyse a proxy audit JSONL log.

    \b
    Renders a colour-coded summary of all recorded tool calls, alerts,
    relay errors, and optional HMAC response signatures.

    \b
    Exits 1 when the log contains blocked calls or relay errors (useful
    as a CI gate after running a test suite through the proxy).

    \b
    Examples:
      agent-bom runtime audit audit.jsonl
      agent-bom runtime audit audit.jsonl --blocked-only
      agent-bom runtime audit audit.jsonl --alerts-only
      agent-bom runtime audit audit.jsonl --tool read_file
      agent-bom runtime audit audit.jsonl --sign-key $SECRET --verify-hmac
      agent-bom runtime audit audit.jsonl --verify-chain
      agent-bom runtime audit audit.jsonl --json
    """
    from agent_bom.audit_replay import replay

    exit_code = replay(
        log_path,
        tool=tool,
        entry_type=entry_type,
        blocked_only=blocked_only,
        alerts_only=alerts_only,
        sign_key=sign_key,
        verify_hmac=verify_hmac,
        verify_chain=verify_chain,
        as_json=as_json,
    )
    sys.exit(exit_code)
