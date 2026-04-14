"""Preflight diagnostic command — checks environment readiness."""

from __future__ import annotations

import os
import shutil
import sys

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

        configs = discover_global_configs()
        runtime_checks.append(("MCP configs", f"{len(configs)} found", "ok" if configs else "info"))
    except Exception:
        runtime_checks.append(("MCP configs", "discovery error", "warn"))

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

    # Print results
    console.print("  [bold]agent-bom doctor[/bold]")
    console.print()

    _print_section(console, "Core readiness", core_checks)
    _print_section(console, "Runtime surfaces", runtime_checks)
    _print_section(console, "Platform integrations", platform_checks)

    console.print()

    checks = [*core_checks, *runtime_checks, *platform_checks]
    warns = sum(1 for _, _, s in checks if s == "warn")
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
