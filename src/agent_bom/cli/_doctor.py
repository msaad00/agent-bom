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

    checks: list[tuple[str, str, str]] = []  # (label, value, status)

    # Python version
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    py_ok = sys.version_info >= (3, 11)
    checks.append(("Python", py_ver, "ok" if py_ok else "warn"))

    # agent-bom version
    checks.append(("agent-bom", __version__, "ok"))

    # Local vulnerability DB
    try:
        from pathlib import Path

        db_path = Path.home() / ".agent-bom" / "scan_cache.db"
        if db_path.exists():
            size_kb = db_path.stat().st_size // 1024
            checks.append(("Local DB", f"exists ({size_kb} KB)", "ok"))
        else:
            checks.append(("Local DB", "not yet created (run a scan first)", "info"))
    except Exception:
        checks.append(("Local DB", "not available", "info"))

    # Network — OSV API
    try:
        import urllib.request

        urllib.request.urlopen("https://api.osv.dev/v1", timeout=5)  # nosec B310 — hardcoded HTTPS URL
        checks.append(("Network", "api.osv.dev reachable", "ok"))
    except Exception:
        checks.append(("Network", "api.osv.dev unreachable", "warn"))

    # Docker
    docker_path = shutil.which("docker")
    if docker_path:
        checks.append(("Docker", "available", "ok"))
    else:
        checks.append(("Docker", "not found", "info"))

    # kubectl
    kubectl_path = shutil.which("kubectl")
    if kubectl_path:
        checks.append(("kubectl", "available", "ok"))
    else:
        checks.append(("kubectl", "not found", "info"))

    # MCP configs
    try:
        from agent_bom.discovery import discover_global_configs

        configs = discover_global_configs()
        checks.append(("MCP configs", f"{len(configs)} found", "ok" if configs else "info"))
    except Exception:
        checks.append(("MCP configs", "discovery error", "warn"))

    # API keys
    api_keys = {
        "NVD_API_KEY": "NVD enrichment",
        "GITHUB_TOKEN": "GitHub advisories",
        "SNOWFLAKE_ACCOUNT": "Snowflake governance",
    }
    for key, label in api_keys.items():
        if os.environ.get(key):
            checks.append((label, "configured", "ok"))
        else:
            checks.append((label, "not set", "info"))

    # Print results
    console.print("  [bold]agent-bom doctor[/bold]")
    console.print()
    for label, value, status in checks:
        if status == "ok":
            icon = "[green]✓[/green]"
        elif status == "warn":
            icon = "[yellow]⚠[/yellow]"
        else:
            icon = "[dim]○[/dim]"
        console.print(f"  {icon}  {label + ':':<20s} {value}")

    console.print()

    warns = sum(1 for _, _, s in checks if s == "warn")
    if warns == 0:
        console.print("  [green]Ready to scan.[/green]")
    else:
        console.print(f"  [yellow]{warns} warning(s) — scanning may be limited.[/yellow]")
    console.print()
