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
@click.option("--rate-limit-threshold", type=int, default=0, help="Max calls per tool per 60s (0=disabled)")
@click.option("--log-only", is_flag=True, help="Log alerts without blocking (advisory mode)")
@click.option(
    "--alert-webhook", default=None, envvar="AGENT_BOM_ALERT_WEBHOOK", help="Webhook URL for runtime alerts (Slack/Teams/PagerDuty)"
)
@click.option("--metrics-port", default=8422, show_default=True, help="Prometheus metrics port (0 to disable)")
@click.option("--metrics-token", default=None, envvar="AGENT_BOM_METRICS_TOKEN", help="Bearer token for Prometheus /metrics endpoint")
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
@click.argument("server_cmd", nargs=-1, required=False)
def proxy_cmd(
    policy,
    log_path,
    block_undeclared,
    detect_credentials,
    rate_limit_threshold,
    log_only,
    alert_webhook,
    metrics_port,
    metrics_token,
    response_sign_key,
    url,
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

    \b
    Usage (stdio — subprocess):
      agent-bom proxy -- npx @modelcontextprotocol/server-filesystem /tmp
      agent-bom proxy --log audit.jsonl -- npx @mcp/server-github
      agent-bom proxy --policy policy.json --block-undeclared -- npx @mcp/server-postgres
      agent-bom proxy --detect-credentials --log-only -- npx @mcp/server-github
      agent-bom proxy --log audit.jsonl --response-sign-key $MY_SECRET -- npx @mcp/server-github

    \b
    Usage (SSE/HTTP — remote server):
      agent-bom proxy --url http://localhost:3000
      agent-bom proxy --url https://mcp.example.com --log audit.jsonl --block-undeclared
      agent-bom proxy --url http://localhost:3000 --policy policy.json

    \b
    Configure in your MCP client (e.g. Claude Desktop):
      {
        "mcpServers": {
          "filesystem": {
            "command": "agent-bom",
            "args": ["proxy", "--log", "audit.jsonl", "--detect-credentials",
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

    exit_code = asyncio.run(
        run_proxy(
            server_cmd=list(server_cmd),
            policy_path=policy,
            log_path=log_path,
            block_undeclared=block_undeclared,
            detect_credentials=detect_credentials,
            rate_limit_threshold=rate_limit_threshold,
            log_only=log_only,
            alert_webhook=alert_webhook,
            metrics_port=metrics_port,
            metrics_token=metrics_token,
            response_signing_key=response_sign_key,
        )
    )
    sys.exit(exit_code)


@click.command("proxy-configure")
@click.option("--policy", type=click.Path(exists=True), default=None, help="Policy JSON file to pass to each proxy instance")
@click.option("--log-dir", default=None, type=click.Path(), help="Directory for per-server audit JSONL logs")
@click.option("--detect-credentials", is_flag=True, help="Enable credential leak detection in each proxy")
@click.option("--block-undeclared", is_flag=True, help="Block undeclared tools in each proxy")
@click.option(
    "--apply",
    is_flag=True,
    help="Write proxy config back to source JSON config files (default: preview only)",
)
@click.option("--project", default=None, type=click.Path(exists=True), help="Project directory to scan for MCP configs")
def proxy_configure_cmd(policy, log_dir, detect_credentials, block_undeclared, apply, project):
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

    \b
    Example:
      agent-bom runtime configure --log-dir ~/.agent-bom/logs --detect-credentials
      agent-bom runtime configure --policy policy.json --block-undeclared --apply
    """
    from agent_bom.discovery import discover_all
    from agent_bom.proxy_configure import apply_proxy_configs, auto_configure_proxies

    con = Console()

    agents = discover_all(project_dir=project)
    configs = auto_configure_proxies(
        agents,
        policy_path=policy,
        log_dir=log_dir,
        detect_credentials=detect_credentials,
        block_undeclared=block_undeclared,
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
    Analyzes tool calls through 5 security detectors:
    - Tool drift detection (rug pull / capability changes)
    - Argument analysis (shell injection, path traversal)
    - Credential leak detection (API keys, tokens in responses)
    - Rate limiting (abnormal call frequency)
    - Sequence analysis (suspicious multi-step patterns)

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
        ConsoleAlertSink,
        FileAlertSink,
        WebhookAlertSink,
        discover_config_dirs,
        start_watching,
    )

    console = Console()

    sinks = [ConsoleAlertSink()]
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
@click.option("--json", "as_json", is_flag=True, help="Output machine-readable JSON summary (for CI)")
def audit_replay_cmd(log_path, tool, entry_type, blocked_only, alerts_only, sign_key, verify_hmac, as_json):
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
        as_json=as_json,
    )
    sys.exit(exit_code)
