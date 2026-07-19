"""Preflight diagnostic command — checks environment readiness."""

from __future__ import annotations

import os
import shutil
import sys
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO

import click
from rich.console import Console


@click.command("doctor")
def doctor_cmd() -> None:
    """Check environment readiness for scanning.

    \b
    Verifies:  Python, agent-bom version, local vuln DB, network,
               Docker, kubectl, MCP configs, API keys.
    """
    console = Console()
    console.print()

    from agent_bom import __version__

    core_checks: list[tuple[str, str, str]] = []
    runtime_checks: list[tuple[str, str, str]] = []
    platform_checks: list[tuple[str, str, str]] = []
    cloud_sdk_checks: list[tuple[str, str, str]] = []
    cloud_api_checks: list[tuple[str, str, str]] = []
    pin_drift_checks: list[tuple[str, str, str]] = []

    # Python version
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    py_ok = sys.version_info >= (3, 11)
    core_checks.append(("Python", py_ver, "ok" if py_ok else "warn"))

    # agent-bom version
    core_checks.append(("agent-bom", __version__, "ok"))

    # Local vulnerability DB — check the same path ScanCache() uses
    try:
        import os as _os
        from pathlib import Path

        _db_env = _os.environ.get("AGENT_BOM_SCAN_CACHE")
        db_path = Path(_db_env) if _db_env else Path.home() / ".agent-bom" / "scan_cache.db"
        if db_path.exists():
            size_kb = db_path.stat().st_size // 1024
            # Count cached entries to distinguish "empty" from "populated"
            try:
                import sqlite3 as _sqlite3

                _conn = _sqlite3.connect(str(db_path), check_same_thread=False)
                _row = _conn.execute("SELECT COUNT(*) FROM osv_cache").fetchone()
                _conn.close()
                entry_count = _row[0] if _row else 0
                if entry_count == 0:
                    core_checks.append(("Local DB", f"exists but empty ({size_kb} KB) — run a scan to populate", "info"))
                else:
                    core_checks.append(("Local DB", f"exists ({size_kb} KB, {entry_count} cached entries)", "ok"))
            except Exception:
                core_checks.append(("Local DB", f"exists ({size_kb} KB)", "ok"))
        else:
            core_checks.append(("Local DB", "not yet created (run a scan first)", "info"))
    except Exception:
        core_checks.append(("Local DB", "not available", "info"))

    # Network — OSV API
    try:
        import urllib.request

        urllib.request.urlopen("https://api.osv.dev/v1", timeout=5)  # nosec B310 — hardcoded HTTPS URL
        core_checks.append(("Network", "api.osv.dev reachable", "ok"))
    except Exception:
        core_checks.append(("Network", "api.osv.dev unreachable", "warn"))

    # Docker
    docker_path = shutil.which("docker")
    if docker_path:
        runtime_checks.append(("Docker", "available", "ok"))
    else:
        runtime_checks.append(("Docker", "not found", "info"))

    # kubectl
    kubectl_path = shutil.which("kubectl")
    if kubectl_path:
        runtime_checks.append(("kubectl", "available", "ok"))
    else:
        runtime_checks.append(("kubectl", "not found", "info"))

    # MCP configs
    try:
        from agent_bom.discovery import discover_global_configs

        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            configs = discover_global_configs(quiet=True)
        server_count = sum(len(agent.mcp_servers) for agent in configs)
        if configs:
            client_names = ", ".join(agent.name for agent in configs[:3])
            suffix = "" if len(configs) <= 3 else f", +{len(configs) - 3} more"
            runtime_checks.append(
                (
                    "MCP discovery",
                    f"{len(configs)} client config(s), {server_count} MCP server(s) ({client_names}{suffix})",
                    "ok",
                )
            )
        else:
            runtime_checks.append(("MCP discovery", "0 client configs, 0 MCP servers", "info"))
    except Exception:
        runtime_checks.append(("MCP discovery", "discovery error", "warn"))

    # API keys
    api_keys = {
        "NVD_API_KEY": "NVD enrichment",
        "GITHUB_TOKEN": "GitHub advisories",
        "SNOWFLAKE_ACCOUNT": "Snowflake governance",
    }
    for key, label in api_keys.items():
        if os.environ.get(key):
            platform_checks.append((label, "configured", "ok"))
        else:
            platform_checks.append((label, "not set", "info"))

    # Cloud SDK freshness — the tool's own provider SDK layer, checked against
    # the version floor the connectors are built against. A stale SDK can
    # silently under-cover a provider's estate, so it is never left silent.
    try:
        from agent_bom.cloud_sdk_freshness import cloud_sdk_posture

        _sdk_status_map = {"ok": "ok", "outdated": "warn", "not_installed": "info", "unknown": "info"}
        for sdk in cloud_sdk_posture()["sdks"]:
            if sdk["status"] == "ok":
                value = f"{sdk['installed_version']} (≥ floor {sdk['recommended_floor']})"
            elif sdk["status"] == "outdated":
                value = f"{sdk['installed_version']} < recommended floor {sdk['recommended_floor']} — upgrade agent-bom[{sdk['provider']}]"
            elif sdk["status"] == "not_installed":
                value = f"not installed (install agent-bom[{sdk['provider']}] to scan {sdk['provider']})"
            else:
                value = f"version unknown (floor {sdk['recommended_floor']})"
            cloud_sdk_checks.append((sdk["distribution"], value, _sdk_status_map.get(sdk["status"], "info")))
    except Exception:
        cloud_sdk_checks.append(("Cloud SDKs", "freshness check unavailable", "info"))

    # Provider-API deprecation posture — a legacy-SDK exposure guard for
    # retired/deprecating provider APIs (Azure AD Graph, oauth2client, …).
    # Honest default is "clear": agent-bom uses the modern replacements, so this
    # only lights up if a legacy SDK is dragged into the environment.
    try:
        from agent_bom.cloud_sdk_freshness import cloud_api_deprecation_posture

        _api_status_map = {"clear": "ok", "at_risk": "warn", "gated": "warn"}
        for api in cloud_api_deprecation_posture()["apis"]:
            if api["status"] == "clear":
                value = f"clear (uses {api['replacement']})"
            elif api["status"] == "gated":
                value = f"retired + {api['distribution']} present — exposure detected; migrate to {api['replacement']}"
            else:
                when = f" on {api['retirement_date']}" if api["retirement_date"] else ""
                value = f"deprecating{when} — {api['distribution']} present; migrate to {api['replacement']}"
            cloud_api_checks.append((api["api"], value, _api_status_map.get(api["status"], "info")))
    except Exception:
        cloud_api_checks.append(("Cloud API deprecations", "check unavailable", "info"))

    # Cloud SDK pin drift — how far the repo's own pinned version floors lag the
    # ecosystem, measured against a dated in-repo reference (offline, provenance-
    # honest). Complements the installed-vs-floor check above: that answers "is
    # my install at the floor?"; this answers "is the floor itself stale?". A
    # non-blocking signal; never claims "current" without the dated reference.
    try:
        from agent_bom.cloud_sdk_freshness import cloud_sdk_pin_drift

        drift = cloud_sdk_pin_drift()
        _drift_status_map = {"current": "ok", "behind": "warn", "unknown": "info"}
        checked_on = drift["last_checked"] or "never"
        for sdk in drift["sdks"]:
            if sdk["status"] == "current":
                value = f"floor {sdk['floor']} current with latest {sdk['known_latest']} (as of {checked_on})"
            elif sdk["status"] == "behind":
                months = f", ~{sdk['months_behind']}mo" if sdk["months_behind"] else ""
                value = f"floor {sdk['floor']} behind latest {sdk['known_latest']}{months} (as of {checked_on})"
            else:
                value = f"floor {sdk['floor']} — pin currency unknown (last checked {checked_on})"
            pin_drift_checks.append((sdk["distribution"], value, _drift_status_map.get(sdk["status"], "info")))
    except Exception:
        pin_drift_checks.append(("Cloud SDK pin drift", "check unavailable", "info"))

    checks = [*core_checks, *runtime_checks, *platform_checks]
    warns = sum(1 for _, _, s in checks if s == "warn")

    from agent_bom.cli._agent_mode import agent_mode_requested

    if agent_mode_requested():
        from agent_bom.cli._agent_mode import emit_command_envelope

        def _section(rows: list[tuple[str, str, str]]) -> list[dict[str, str]]:
            return [{"label": label, "value": value, "status": status} for label, value, status in rows]

        capabilities: list[dict[str, str]] = []
        coverage = None
        try:
            from agent_bom.capabilities import coverage_line, resolved_capabilities

            for cap, status in resolved_capabilities():
                capabilities.append({"name": cap.name, "state": status.state.value, "detail": status.detail})
            coverage = coverage_line()
        except Exception:
            capabilities = []

        emit_command_envelope(
            command="doctor",
            data={
                "core": _section(core_checks),
                "runtime": _section(runtime_checks),
                "platform": _section(platform_checks),
                "cloud_sdk": _section(cloud_sdk_checks),
                "cloud_api_deprecations": _section(cloud_api_checks),
                "cloud_sdk_pin_drift": _section(pin_drift_checks),
                "capabilities": capabilities,
                "coverage": coverage,
                "ready": warns == 0,
                "warnings": warns,
            },
            summary={"warnings": warns, "ready": warns == 0},
        )
        return

    # Print results
    console.print("  [bold]agent-bom doctor[/bold]")
    console.print()

    _print_section(console, "Core readiness", core_checks)
    _print_section(console, "Runtime surfaces", runtime_checks)
    _print_section(console, "Platform integrations", platform_checks)
    _print_section(console, "Cloud SDK freshness", cloud_sdk_checks)
    _print_section(console, "Cloud API deprecations", cloud_api_checks)
    _print_section(console, "Cloud SDK pin drift", pin_drift_checks)

    # Nothing-silent capability view — every gated feature with its state and
    # unlock path, so a skipped/degraded capability is never silent.
    try:
        from agent_bom.capabilities import coverage_line, resolved_capabilities

        console.print("  [bold]Capabilities[/bold] [dim](run `agent-bom capabilities` for unlock paths)[/dim]")
        _state_icon = {"on": "[green]✓[/green]", "off": "[dim]○[/dim]", "degraded": "[yellow]◐[/yellow]", "unknown": "[red]?[/red]"}
        for cap, status in resolved_capabilities():
            icon = _state_icon.get(status.state.value, "[dim]○[/dim]")
            console.print(f"    {icon}  {cap.name + ':':<34s} {status.detail}")
        console.print()
        console.print(f"  [dim]{coverage_line()}[/dim]")
        console.print()
    except Exception:
        # Never let the capability view break the core preflight output.
        pass

    console.print()

    if warns == 0:
        console.print("  [green]Ready to scan.[/green]")
    else:
        console.print(f"  [yellow]{warns} warning(s) — scanning may be limited.[/yellow]")
    console.print()
    console.print("  [bold]Next commands[/bold]")
    console.print("    • agent-bom agents --demo --offline")
    console.print("    • agent-bom where")
    console.print("    • agent-bom proxy --help")
    console.print()


def _print_section(console: Console, title: str, checks: list[tuple[str, str, str]]) -> None:
    console.print(f"  [bold]{title}[/bold]")
    for label, value, status in checks:
        if status == "ok":
            icon = "[green]✓[/green]"
        elif status == "warn":
            icon = "[yellow]⚠[/yellow]"
        else:
            icon = "[dim]○[/dim]"
        console.print(f"    {icon}  {label + ':':<20s} {value}")
    console.print()
