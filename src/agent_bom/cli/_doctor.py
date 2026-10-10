"""Preflight diagnostic command — checks environment readiness."""

from __future__ import annotations

import shutil
import sys
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO

import click
from rich.console import Console
from rich.markup import escape

from agent_bom.core.settings import env_raw, env_str
from agent_bom.scan_cache import CACHE_KEY_PREFIX
from agent_bom.storage import state_home
from agent_bom.storage.tiers import StorageTier, classify_storage, storage_selection_from_env


@click.command("doctor")
@click.option("--offline", is_flag=True, help="Check local installation only; skip network and database connections.")
def doctor_cmd(offline: bool = False) -> None:
    """Check environment readiness for scanning.

    \b
    Verifies:  Python, agent-bom version, local vuln DB, network,
               Docker, kubectl, MCP configs, API keys, storage support tiers.

    Use --offline for local diagnostics without OSV or Postgres connections.
    Skipped probes do not establish network or database readiness.
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

    core_checks.append(_vuln_db_check())

    # OSV lookup cache — check the same path ScanCache() uses
    try:
        from pathlib import Path

        _db_env = env_str("AGENT_BOM_SCAN_CACHE")
        db_path = Path(_db_env) if _db_env else state_home.state_path("scan_cache.db")
        if db_path.exists():
            size_kb = db_path.stat().st_size // 1024
            # Count cached entries to distinguish "empty" from "populated"
            try:
                import sqlite3 as _sqlite3

                _conn = _sqlite3.connect(str(db_path), check_same_thread=False)
                _row = _conn.execute("SELECT COUNT(*) FROM osv_cache WHERE cache_key LIKE ?", (f"{CACHE_KEY_PREFIX}%",)).fetchone()
                _conn.close()
                entry_count = _row[0] if _row else 0
                if entry_count == 0:
                    core_checks.append(("Scan cache", f"exists but empty ({size_kb} KB) — run a scan to populate", "info"))
                else:
                    core_checks.append(("Scan cache", f"exists ({size_kb} KB, {entry_count} cached entries)", "ok"))
            except Exception:
                core_checks.append(("Scan cache", f"exists ({size_kb} KB)", "ok"))
        else:
            core_checks.append(("Scan cache", "not yet created (run a scan first)", "info"))
    except Exception:
        core_checks.append(("Scan cache", "not available", "info"))

    core_checks.append(_network_check(offline))

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
        if env_raw(key):
            platform_checks.append((label, "configured", "ok"))
        else:
            platform_checks.append((label, "not set", "info"))
    platform_checks.extend(_storage_tier_checks())

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
                provider = sdk["provider"]
                value = f"not installed (install with: pip install 'agent-bom[{provider}]' to scan {provider.upper()})"
            else:
                value = f"version unknown (floor {sdk['recommended_floor']})"
            cloud_sdk_checks.append((sdk["distribution"], value, _sdk_status_map.get(sdk["status"], "info")))
    except Exception:
        cloud_sdk_checks.append(("Cloud SDKs", "freshness check unavailable", "info"))

    # Provider-API deprecation posture — a legacy-SDK exposure guard for retired/deprecating provider APIs (Azure AD Graph,
    # oauth2client, …). Honest default is "clear": agent-bom uses the modern replacements, so this only lights up if a
    # legacy SDK is dragged into the environment.
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

    postgres_checks, postgres_payload = _postgres_checks(offline)

    checks = [*core_checks, *runtime_checks, *platform_checks, *cloud_sdk_checks, *cloud_api_checks, *pin_drift_checks, *postgres_checks]
    warns = sum(1 for _, _, s in checks if s == "warn")
    readiness = {
        "readiness_scope": "local_only" if offline else "configured_probes",
        "checks_passed": warns == 0,
        "ready": not offline and warns == 0,
        "warnings": warns,
    }

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
                "postgres_portability": postgres_payload,
                "capabilities": capabilities,
                "coverage": coverage,
                **readiness,
            },
            summary=readiness,
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
    if postgres_checks:
        _print_section(console, "Postgres portability", postgres_checks)

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

    if offline:
        console.print("  Local checks complete; network and database readiness not assessed.")
        if warns:
            console.print(f"  [yellow]{warns} local warning(s) — scanning may be limited.[/yellow]")
    elif warns == 0:
        console.print("  [green]Ready to scan.[/green]")
    else:
        console.print(f"  [yellow]{warns} warning(s) — scanning may be limited.[/yellow]")
    console.print()
    console.print("  [bold]Next commands[/bold]")
    console.print("    • agent-bom scan --demo --offline")
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
        console.print(f"    {icon}  {escape(label + ':'):<20s} {escape(value)}")
    console.print()


_STORAGE_COMPONENT_LABELS = {"control_plane": "Control-plane store", "graph": "Graph store", "analytics": "Analytics sink"}


def _storage_tier_checks() -> list[tuple[str, str, str]]:
    """One row per selected storage component with its support tier (see docs/STORAGE_BACKENDS.md)."""
    rows: list[tuple[str, str, str]] = []
    for item in classify_storage(storage_selection_from_env()).components:
        label = _STORAGE_COMPONENT_LABELS.get(item.component, item.component)
        if item.tier is StorageTier.EXPERIMENTAL:
            rows.append((label, f"{item.backend} — experimental; see docs/STORAGE_BACKENDS.md", "warn"))
        elif item.backend == "memory":
            rows.append((label, "memory — local only, not durable", "info"))
        else:
            rows.append((label, f"{item.backend} — {item.tier.value.replace('_', ' ')}", "ok"))
    return rows


def _vuln_db_check() -> tuple[str, str, str]:
    """Report the local vulnerability DB with the same staleness rule scans apply."""
    from agent_bom.vuln_freshness import compute_freshness, db_stale_days_threshold, db_staleness

    freshness = compute_freshness()
    stale, age_days = db_staleness(freshness)
    threshold = db_stale_days_threshold()
    if freshness.mode == "live":
        return ("Vuln DB", "not synced — scans query OSV/GHSA/NVD live; run `agent-bom db update` for offline scans", "info")
    if age_days is None:
        return ("Vuln DB", "sync time unknown — run `agent-bom db update`", "warn")
    records = f"{freshness.record_count:,} records, " if freshness.record_count else ""
    if stale:
        return ("Vuln DB", f"stale ({records}{age_days}d old; threshold {threshold}d) — run `agent-bom db update`", "warn")
    return ("Vuln DB", f"fresh ({records}{age_days}d old; threshold {threshold}d)", "ok")


def _network_check(offline: bool) -> tuple[str, str, str]:
    """Probe OSV only when connections are explicitly allowed by the mode."""
    if offline:
        return ("Network", "not assessed (--offline)", "info")
    else:
        # Network — OSV API
        try:
            import json
            import urllib.request

            request = urllib.request.Request(  # nosec B310 — hardcoded HTTPS URL
                "https://api.osv.dev/v1/query",
                data=json.dumps({"package": {"name": "jinja2", "ecosystem": "PyPI"}, "version": "3.1.4"}).encode(),
                headers={"Content-Type": "application/json", "User-Agent": "agent-bom-doctor"},
                method="POST",
            )
            urllib.request.urlopen(request, timeout=5)  # nosec B310 — hardcoded HTTPS URL
            return ("Network", "api.osv.dev reachable", "ok")
        except Exception:
            return ("Network", "api.osv.dev unreachable", "warn")


def _postgres_checks(offline: bool) -> tuple[list[tuple[str, str, str]], dict[str, object] | None]:
    """Keep offline diagnostics separate from a configured database probe."""
    postgres_checks: list[tuple[str, str, str]] = []
    postgres_payload: dict[str, object] | None = None
    postgres_url = env_raw("AGENT_BOM_POSTGRES_URL", "")
    database_url = env_raw("AGENT_BOM_DB", "")
    postgres_configured = bool(postgres_url or database_url.startswith(("postgres://", "postgresql://")))
    if offline:
        postgres_payload = {"status": "not_assessed", "evidence": "offline", "configured": postgres_configured}
        postgres_checks.append(("Connection", "not assessed (--offline)", "info"))
    elif postgres_configured:
        from agent_bom.storage.postgres_capabilities import probe_postgres_portability

        probe = probe_postgres_portability()
        postgres_payload = probe.to_dict()
        probe_status = "ok" if probe.status == "ready" else "warn"
        postgres_checks.extend(
            [
                ("Provider", probe.provider, probe_status),
                ("Evidence", probe.evidence, "ok" if probe.evidence == "controlled_verified" else "info"),
                ("Contract", probe.contract, "ok"),
                ("Server", probe.server_version or "unavailable", probe_status),
                ("TLS", "active" if probe.tls else "inactive or unavailable", probe_status),
                (
                    "Runtime role",
                    "RLS-safe" if probe.runtime_role_rls_safe else "unsafe or unavailable",
                    probe_status,
                ),
                (
                    "Migrations",
                    "present" if probe.alembic_schema_present and probe.control_plane_schema_present else "missing or unavailable",
                    probe_status,
                ),
                (
                    "Maintenance role",
                    "configured" if probe.maintenance_role_configured else "not configured",
                    "ok" if probe.maintenance_role_configured else "warn",
                ),
            ]
        )

    return postgres_checks, postgres_payload
