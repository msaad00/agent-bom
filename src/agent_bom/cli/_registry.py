"""Registry and schedule group commands."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console


@click.group()
def schedule():
    """Manage recurring scan schedules."""


@schedule.command("add")
@click.option("--name", "-n", required=True, help="Schedule name")
@click.option("--cron", "-c", required=True, help="Cron expression (e.g. '0 */6 * * *')")
@click.option("--config", "-f", type=click.Path(exists=True), default=None, help="Scan config JSON file")
def schedule_add(name: str, cron: str, config: Optional[str]):
    """Add a recurring scan schedule."""
    import uuid as _uuid

    from agent_bom.api.schedule_store import InMemoryScheduleStore, ScanSchedule, SQLiteScheduleStore
    from agent_bom.api.scheduler import parse_cron_next, validate_cron_expression

    console = Console()

    scan_config: dict = {}
    if config:
        scan_config = json.loads(Path(config).read_text())

    import os as _os
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    if not validate_cron_expression(cron):
        raise click.ClickException("Invalid cron expression")
    next_run = parse_cron_next(cron, now)

    db_path = _os.environ.get("AGENT_BOM_DB")
    store = SQLiteScheduleStore(db_path) if db_path else InMemoryScheduleStore()

    sched = ScanSchedule(
        schedule_id=str(_uuid.uuid4()),
        name=name,
        cron_expression=cron,
        scan_config=scan_config,
        enabled=True,
        next_run=next_run.isoformat() if next_run else None,
        created_at=now.isoformat(),
        updated_at=now.isoformat(),
    )
    store.put(sched)
    console.print(f"[green]Schedule created:[/green] {sched.schedule_id}")
    if next_run:
        console.print(f"  Next run: {next_run.isoformat()}")
    else:
        console.print("  [yellow]Warning: could not compute next run from cron expression[/yellow]")


@schedule.command("list")
def schedule_list():
    """List all scan schedules."""
    import os as _os

    from agent_bom.api.schedule_store import InMemoryScheduleStore, SQLiteScheduleStore

    console = Console()
    db_path = _os.environ.get("AGENT_BOM_DB")
    store = SQLiteScheduleStore(db_path) if db_path else InMemoryScheduleStore()

    schedules = store.list_all()
    if not schedules:
        console.print("[dim]No schedules found.[/dim]")
        return

    for s in schedules:
        status = "[green]enabled[/green]" if s.enabled else "[red]disabled[/red]"
        console.print(f"  {s.schedule_id[:8]}  {s.name}  {s.cron_expression}  {status}  next={s.next_run or 'n/a'}")


@schedule.command("remove")
@click.argument("schedule_id")
def schedule_remove(schedule_id: str):
    """Remove a scan schedule by ID."""
    import os as _os

    from agent_bom.api.schedule_store import InMemoryScheduleStore, SQLiteScheduleStore

    console = Console()
    db_path = _os.environ.get("AGENT_BOM_DB")
    store = SQLiteScheduleStore(db_path) if db_path else InMemoryScheduleStore()

    if store.delete(schedule_id):
        console.print(f"[green]Deleted schedule {schedule_id}[/green]")
    else:
        console.print(f"[red]Schedule {schedule_id} not found[/red]")
        sys.exit(1)


@click.group()
def registry():
    """Manage the MCP server registry."""


@registry.command("list")
@click.option("--category", "-c", default=None, help="Filter by category (e.g. database, filesystem).")
@click.option("--risk-level", "-r", type=click.Choice(["low", "medium", "high"]), default=None, help="Filter by risk level.")
@click.option("--ecosystem", "-e", type=click.Choice(["npm", "pypi"]), default=None, help="Filter by ecosystem.")
@click.option("--format", "-f", "fmt", type=click.Choice(["table", "json"]), default="table", help="Output format.")
def registry_list(category, risk_level, ecosystem, fmt):
    """List all known MCP servers in the registry."""
    from agent_bom.registry import list_registry

    entries = list_registry(ecosystem=ecosystem, category=category, risk_level=risk_level)

    if fmt == "json":
        click.echo(json.dumps(entries, indent=2))
        return

    from rich.console import Console
    from rich.table import Table

    con = Console(width=160)
    table = Table(title=f"MCP Server Registry ({len(entries)} servers)", expand=False)
    table.add_column("Name", style="cyan", overflow="fold")
    table.add_column("Version", style="green", no_wrap=True)
    table.add_column("Ecosystem", no_wrap=True)
    table.add_column("Category", overflow="fold")
    table.add_column("Risk", style="bold", no_wrap=True)
    table.add_column("Verified", no_wrap=True)

    risk_colors = {"high": "red", "medium": "yellow", "low": "green"}
    for entry in entries:
        rl = entry.get("risk_level", "")
        color = risk_colors.get(rl, "white")
        table.add_row(
            entry.get("package", entry.get("name", "")),
            entry.get("latest_version", "?"),
            entry.get("ecosystem", ""),
            entry.get("category", ""),
            f"[{color}]{rl}[/{color}]",
            "Yes" if entry.get("verified") else "No",
        )
    con.print(table)


@registry.command("search")
@click.argument("query")
@click.option("--category", "-c", default=None, help="Also filter by category.")
def registry_search(query, category):
    """Search the MCP registry by name or description."""
    from agent_bom.registry import search_registry

    results = search_registry(query, category=category)

    if not results:
        click.echo(f"No results for '{query}'.")
        return

    from rich.console import Console
    from rich.table import Table

    con = Console()
    table = Table(title=f"Search results for '{query}' ({len(results)} matches)")
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("Version", style="green")
    table.add_column("Ecosystem")
    table.add_column("Category")
    table.add_column("Risk")
    table.add_column("Description", max_width=50)

    risk_colors = {"high": "red", "medium": "yellow", "low": "green"}
    for entry in results:
        rl = entry.get("risk_level", "")
        color = risk_colors.get(rl, "white")
        table.add_row(
            entry.get("package", entry.get("name", "")),
            entry.get("latest_version", "?"),
            entry.get("ecosystem", ""),
            entry.get("category", ""),
            f"[{color}]{rl}[/{color}]",
            (entry.get("description", "")[:50] + "...") if len(entry.get("description", "")) > 50 else entry.get("description", ""),
        )
    con.print(table)


@registry.command("status")
@click.option("--stale-after-days", type=int, default=14, show_default=True, help="Mark registry stale after this many days.")
@click.option("--format", "-f", "fmt", type=click.Choice(["table", "json"]), default="table", help="Output format.")
@click.option("--fail-on-stale", is_flag=True, help="Exit 1 when the bundled registry is stale or has never synced.")
def registry_status(stale_after_days: int, fmt: str, fail_on_stale: bool):
    """Show MCP registry freshness and source posture."""
    from rich.console import Console
    from rich.table import Table

    from agent_bom.registry import registry_freshness_status

    status = registry_freshness_status(stale_after_days=stale_after_days)
    payload = status.to_dict()
    if fmt == "json":
        click.echo(json.dumps(payload, indent=2))
        if fail_on_stale and status.needs_refresh:
            raise click.exceptions.Exit(1)
        return

    con = Console()
    color = {
        "fresh": "green",
        "stale": "yellow",
        "airgapped": "cyan",
        "airgapped_stale": "yellow",
        "never_synced": "red",
    }.get(status.status, "white")
    table = Table(title="MCP Registry Freshness")
    table.add_column("Field", style="cyan")
    table.add_column("Value")
    table.add_row("Status", f"[{color}]{status.status}[/{color}]")
    table.add_row("Last synced", status.last_synced_at or "unknown")
    table.add_row("Age", "unknown" if status.age_days is None else f"{status.age_days} day(s)")
    table.add_row("Stale after", f"{status.stale_after_days} day(s)")
    table.add_row("Servers", str(status.server_count))
    table.add_row("Sources", ", ".join(status.sources) if status.sources else "unknown")
    table.add_row("Recommended action", status.recommended_action)
    if status.airgapped:
        table.add_row("Airgapped", "yes")
    if status.error:
        table.add_row("Error", status.error)
    con.print(table)
    if fail_on_stale and status.needs_refresh:
        raise click.exceptions.Exit(1)


@registry.command("update")
@click.option("--concurrency", default=5, type=int, help="Max concurrent API requests.")
@click.option("--dry-run", is_flag=True, help="Show what would be updated without writing.")
def registry_update(concurrency, dry_run):
    """Fetch latest package versions from npm/PyPI for all registry servers."""
    from rich.console import Console

    from agent_bom.registry import update_registry_versions_sync

    con = Console(stderr=True)
    con.print("[bold]Updating MCP registry versions...[/bold]")
    if dry_run:
        con.print("[dim](dry run — no files will be modified)[/dim]")

    result = update_registry_versions_sync(concurrency=concurrency, dry_run=dry_run)

    # Show updated packages
    updated = [d for d in result.details if d["status"] == "updated"]
    if updated:
        con.print(f"\n[bold green]Updated {len(updated)} package(s):[/bold green]")
        for d in updated:
            con.print(f"  {d['package']}: {d['old']} → {d['new']}")

    # Show failures
    failed = [d for d in result.details if d["status"] == "failed"]
    if failed:
        con.print(f"\n[yellow]Failed to resolve {len(failed)} package(s):[/yellow]")
        for d in failed[:5]:
            con.print(f"  {d['package']}")
        if len(failed) > 5:
            con.print(f"  ... and {len(failed) - 5} more")

    con.print(
        f"\n[bold]Summary:[/bold] {result.updated} updated, {result.unchanged} unchanged, {result.failed} failed (of {result.total} total)"
    )
    if not dry_run and result.updated > 0:
        con.print("[green]Registry file updated.[/green]")


@registry.command("enrich")
@click.option("--dry-run", is_flag=True, help="Show enrichment without writing.")
def registry_enrich(dry_run):
    """Enrich registry entries missing risk, tools, or credentials.

    \b
    Fills in empty metadata fields using heuristic inference:
    - risk_level from category/package name patterns
    - credential_env_vars from known service patterns
    - risk_justification from category templates

    Useful after 'registry update' adds new entries from CI.
    """
    from rich.console import Console

    from agent_bom.registry import enrich_registry_entries

    con = Console(stderr=True)
    con.print("[bold]Enriching MCP registry entries...[/bold]")
    if dry_run:
        con.print("[dim](dry run — no files will be modified)[/dim]")

    result = enrich_registry_entries(dry_run=dry_run)

    if result.enriched:
        con.print(f"\n[bold green]Enriched {result.enriched} entry/entries:[/bold green]")
        for d in result.details:
            fields = ", ".join(d["fields_enriched"])
            con.print(f"  {d['server']}: {fields}")
    else:
        con.print("\n[green]All entries already have complete metadata.[/green]")

    con.print(f"\n[bold]Summary:[/bold] {result.enriched} enriched, {result.skipped} already complete (of {result.total} total)")
    if not dry_run and result.enriched > 0:
        con.print("[green]Registry file updated.[/green]")


@registry.command("enrich-cves")
@click.option("--nvd-api-key", envvar="NVD_API_KEY", default=None, help="NVD API key for higher rate limits.")
@click.option("--dry-run", is_flag=True, help="Preview CVE enrichment without writing.")
def registry_enrich_cves(nvd_api_key, dry_run):
    """Enrich registry with CVE data from OSV, EPSS, and CISA KEV.

    \b
    Scans all npm/pypi packages in the registry for known vulnerabilities:
    - Queries OSV batch API for CVEs affecting each package version
    - Fetches EPSS exploit prediction scores
    - Checks CISA KEV (Known Exploited Vulnerabilities) catalog
    - Extracts fix versions from OSV affected ranges

    \b
    Example:
      agent-bom registry enrich-cves
      agent-bom registry enrich-cves --dry-run
    """
    from rich.console import Console

    from agent_bom.registry import enrich_registry_with_cves_sync

    con = Console(stderr=True)
    con.print("[bold]Enriching registry with CVE data (OSV + EPSS + KEV)...[/bold]")
    if dry_run:
        con.print("[dim](dry run — no files will be modified)[/dim]")

    result = enrich_registry_with_cves_sync(nvd_api_key=nvd_api_key, dry_run=dry_run)

    if result.enriched:
        con.print(f"\n[bold red]Found vulnerabilities in {result.enriched} server(s):[/bold red]")
        for d in result.details:
            kev_tag = " [KEV]" if d["kev"] else ""
            con.print(f"  {d['server']}: {d['cve_count']} CVEs, {d['ghsa_count']} GHSAs{kev_tag}")
            if d["cves"]:
                con.print(f"    {', '.join(d['cves'][:5])}")
    else:
        con.print("\n[green]No known CVEs found in scannable registry packages.[/green]")

    con.print(
        f"\n[bold]Summary:[/bold] {result.scannable} scannable, {result.enriched} with CVEs, "
        f"{result.total_cves} total CVEs, {result.total_critical} critical, {result.total_kev} KEV "
        f"(of {result.total} total servers)"
    )
    if not dry_run and result.enriched > 0:
        con.print("[green]Registry file updated with CVE data.[/green]")


@registry.command("smithery-sync")
@click.option("--token", envvar="SMITHERY_API_KEY", help="Smithery API key (or set SMITHERY_API_KEY).")
@click.option("--max-pages", type=int, default=10, show_default=True, help="Maximum pages to fetch from Smithery.")
@click.option("--dry-run", is_flag=True, help="Preview without writing to registry.")
def registry_smithery_sync(token, max_pages, dry_run):
    """Import MCP servers from Smithery.ai into the local registry.

    \b
    Fetches servers from smithery.ai and adds new entries that don't already
    exist in mcp_registry.json. Does not overwrite existing entries.
    Extends coverage from ~112 to 2800+ MCP servers.

    \b
    Requires a Smithery API key:
      export SMITHERY_API_KEY=your-key
      agent-bom registry smithery-sync
    """
    from rich.console import Console

    from agent_bom.smithery import sync_from_smithery_sync

    con = Console(stderr=True)
    if not token:
        con.print("[red]Error: Smithery API key required.[/red]")
        con.print("Set SMITHERY_API_KEY env var or use --token.")
        sys.exit(1)

    con.print("[bold]Syncing MCP servers from Smithery.ai...[/bold]")
    if dry_run:
        con.print("[dim](dry run — no files will be modified)[/dim]")

    result = sync_from_smithery_sync(token=token, max_pages=max_pages, dry_run=dry_run)

    if result.added:
        con.print(f"\n[bold green]Added {result.added} new server(s):[/bold green]")
        for d in result.details[:20]:
            verified = "[green]verified[/green]" if d["verified"] else "[yellow]unverified[/yellow]"
            con.print(f"  {d['display_name']}: {verified}, {d['use_count']} installs, risk={d['risk_level']}")
        if len(result.details) > 20:
            con.print(f"  ... and {len(result.details) - 20} more")
    else:
        con.print("\n[green]No new servers found (all already in local registry).[/green]")

    con.print(f"\n[bold]Summary:[/bold] {result.added} added, {result.skipped} already known (of {result.total_fetched} fetched)")
    if not dry_run and result.added > 0:
        con.print("[green]Registry file updated.[/green]")


@registry.command("mcp-sync")
@click.option("--max-pages", type=int, default=10, show_default=True, help="Maximum pages to fetch from the official registry.")
@click.option("--dry-run", is_flag=True, help="Preview without writing to registry.")
def registry_mcp_sync(max_pages, dry_run):
    """Import MCP servers from the Official MCP Registry into the local registry.

    \b
    Fetches servers from registry.modelcontextprotocol.io and adds new entries
    that don't already exist in mcp_registry.json. No authentication required.

    \b
    Usage:
      agent-bom registry mcp-sync
      agent-bom registry mcp-sync --dry-run
    """
    from rich.console import Console

    from agent_bom.mcp_official_registry import sync_from_official_registry_sync

    con = Console(stderr=True)
    con.print("[bold]Syncing MCP servers from Official MCP Registry...[/bold]")
    if dry_run:
        con.print("[dim](dry run — no files will be modified)[/dim]")

    result = sync_from_official_registry_sync(max_pages=max_pages, dry_run=dry_run)

    if result.added:
        con.print(f"\n[bold green]Added {result.added} new server(s):[/bold green]")
        for d in result.details[:20]:
            con.print(f"  {d['server']}" + (f" (v{d['version']})" if d.get("version") else ""))
        if len(result.details) > 20:
            con.print(f"  ... and {len(result.details) - 20} more")
    else:
        con.print("\n[green]No new servers found (all already in local registry).[/green]")

    con.print(f"\n[bold]Summary:[/bold] {result.added} added, {result.skipped} already known (of {result.total_fetched} fetched)")
    if not dry_run and result.added > 0:
        con.print("[green]Registry file updated.[/green]")


@registry.command("glama-sync")
@click.option("--max-pages", type=int, default=10, show_default=True, help="Maximum pages to fetch from Glama.")
@click.option("--dry-run", is_flag=True, help="Preview without writing to registry.")
def registry_glama_sync(max_pages, dry_run):
    """Import MCP servers from Glama.ai into the local registry.

    \b
    Fetches servers from glama.ai/api/mcp/v1/servers and adds new entries
    that don't already exist in mcp_registry.json. No authentication required.

    \b
    Usage:
      agent-bom registry glama-sync
      agent-bom registry glama-sync --max-pages 50 --dry-run
    """
    from rich.console import Console

    from agent_bom.glama import sync_from_glama_sync

    con = Console(stderr=True)
    con.print("[bold]Syncing MCP servers from Glama.ai...[/bold]")
    if dry_run:
        con.print("[dim](dry run — no files will be modified)[/dim]")

    result = sync_from_glama_sync(max_pages=max_pages, dry_run=dry_run)

    if result.added:
        con.print(f"\n[bold green]Added {result.added} new server(s):[/bold green]")
        for d in result.details[:20]:
            con.print(f"  {d['server']}")
        if len(result.details) > 20:
            con.print(f"  ... and {len(result.details) - 20} more")
    else:
        con.print("\n[green]No new servers found (all already in local registry).[/green]")

    con.print(f"\n[bold]Summary:[/bold] {result.added} added, {result.skipped} already known (of {result.total_fetched} fetched)")
    if not dry_run and result.added > 0:
        con.print("[green]Registry file updated.[/green]")


@registry.command("sync-all")
@click.option("--max-pages", type=int, default=10, show_default=True, help="Maximum pages per source.")
@click.option("--smithery-token", envvar="SMITHERY_API_KEY", default=None, help="Smithery API key.")
@click.option("--dry-run", is_flag=True, help="Preview without writing to registry.")
def registry_sync_all(max_pages, smithery_token, dry_run):
    """Sync from ALL registry sources (Official MCP + Smithery + Glama).

    \b
    Runs all three sync sources in sequence and reports combined results.
    Smithery requires SMITHERY_API_KEY env var or --smithery-token flag.

    \b
    Usage:
      agent-bom registry sync-all
      agent-bom registry sync-all --dry-run
    """
    from rich.console import Console

    con = Console(stderr=True)
    con.print("[bold]Syncing from all registry sources...[/bold]")
    if dry_run:
        con.print("[dim](dry run — no files will be modified)[/dim]")

    total_added = 0
    total_fetched = 0

    # 1. Official MCP Registry
    con.print("\n[blue]1/3[/blue] Official MCP Registry...")
    from agent_bom.mcp_official_registry import sync_from_official_registry_sync

    r1 = sync_from_official_registry_sync(max_pages=max_pages, dry_run=dry_run)
    con.print(f"  Added: {r1.added}, Skipped: {r1.skipped}, Fetched: {r1.total_fetched}")
    total_added += r1.added
    total_fetched += r1.total_fetched

    # 2. Smithery
    con.print("\n[blue]2/3[/blue] Smithery.ai...")
    if smithery_token:
        from agent_bom.smithery import sync_from_smithery_sync

        r2 = sync_from_smithery_sync(token=smithery_token, max_pages=max_pages, dry_run=dry_run)
        con.print(f"  Added: {r2.added}, Skipped: {r2.skipped}, Fetched: {r2.total_fetched}")
        total_added += r2.added
        total_fetched += r2.total_fetched
    else:
        con.print("  [dim]Skipped (no SMITHERY_API_KEY)[/dim]")

    # 3. Glama
    con.print("\n[blue]3/3[/blue] Glama.ai...")
    from agent_bom.glama import sync_from_glama_sync

    r3 = sync_from_glama_sync(max_pages=max_pages, dry_run=dry_run)
    con.print(f"  Added: {r3.added}, Skipped: {r3.skipped}, Fetched: {r3.total_fetched}")
    total_added += r3.added
    total_fetched += r3.total_fetched

    con.print(f"\n[bold]Total:[/bold] {total_added} added from {total_fetched} fetched across all sources")
    if not dry_run and total_added > 0:
        con.print("[green]Registry file updated.[/green]")
