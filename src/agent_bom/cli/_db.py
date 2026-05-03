"""CLI commands for the local vulnerability database.

Commands:
    agent-bom db update   — sync from OSV / Alpine secdb / EPSS / KEV / GHSA / NVD
    agent-bom db update-frameworks — refresh local MITRE framework catalogs
    agent-bom db status   — show DB stats and last-sync timestamps
    agent-bom db path     — print the DB file path
"""

from __future__ import annotations

import click


@click.group("db")
def db_cmd() -> None:
    """Manage the local vulnerability database."""


@db_cmd.command("update")
@click.option(
    "--source",
    "sources",
    multiple=True,
    type=click.Choice(["osv", "alpine", "epss", "kev", "ghsa", "nvd"], case_sensitive=False),
    help="Which sources to sync (default: osv, alpine, epss, kev). Repeatable. "
    "Use --source alpine to sync Alpine package secfix data from Alpine secdb. "
    "Use --source ghsa to sync GitHub Security Advisories (all ecosystems). "
    "Use --source nvd to enrich unknown-severity CVEs from NVD (slow without NVD_API_KEY).",
)
@click.option("--path", "db_path", type=click.Path(), default=None, help="Override DB file path.")
@click.option(
    "--max-osv-entries",
    type=int,
    default=0,
    help="Limit OSV entries (for testing). 0 = unlimited.",
    hidden=True,
)
@click.option(
    "--max-ghsa-entries",
    type=int,
    default=5000,
    help="Limit GHSA advisories to ingest (default: 5000).",
    hidden=True,
)
@click.option(
    "--max-nvd-entries",
    type=int,
    default=1000,
    help="Limit NVD CVEs to enrich (default: 1000).",
    hidden=True,
)
@click.option(
    "--ghsa-ecosystems",
    "ghsa_ecosystems",
    multiple=True,
    type=click.Choice(["pip", "npm", "go", "maven", "nuget", "rubygems", "cargo"], case_sensitive=False),
    help="Filter GHSA sync to specific ecosystems (default: all). Repeatable.",
)
def db_update(
    sources: tuple,
    db_path: str | None,
    max_osv_entries: int,
    max_ghsa_entries: int,
    max_nvd_entries: int,
    ghsa_ecosystems: tuple,
) -> None:
    """Download and sync the local vulnerability database.

    Pulls from OSV.dev (bulk export), Alpine secdb, FIRST EPSS scores, and CISA KEV catalog by default.
    Pass --source ghsa to also fetch GitHub Security Advisories across all supported
    ecosystems (pip, npm, go, maven, nuget, rubygems, cargo).
    Pass --source nvd to enrich CVEs missing CVSS data from the NVD API (requires NVD_API_KEY
    for reasonable speed; without a key the rate limit is 5 req/30s).

    Requires internet access. First sync is ~50 MB and takes several minutes.
    Subsequent syncs are incremental (upsert by ID).
    """
    from pathlib import Path

    from rich.console import Console

    from agent_bom.db.sync import sync_db

    con = Console()
    selected = list(sources) or ["osv", "alpine", "epss", "kev"]
    con.print(f"[bold]Syncing local vuln DB[/bold] — sources: {', '.join(selected)}")

    try:
        results = sync_db(
            path=Path(db_path) if db_path else None,
            sources=selected,
            max_osv_entries=max_osv_entries,
            max_ghsa_entries=max_ghsa_entries,
            max_nvd_entries=max_nvd_entries,
            ghsa_ecosystems=list(ghsa_ecosystems) if ghsa_ecosystems else None,
        )
    except Exception as exc:
        con.print(f"[red]Sync failed: {exc}[/red]")
        raise SystemExit(1) from exc

    for src, count in results.items():
        con.print(f"  [green]✓[/green] {src}: {count:,} records")
    con.print("[bold green]Done.[/bold green]")


@db_cmd.command("status")
@click.option("--path", "db_path", type=click.Path(), default=None, help="Override DB file path.")
def db_status(db_path: str | None) -> None:
    """Show local vulnerability database statistics and sync timestamps."""
    from pathlib import Path

    from rich.console import Console
    from rich.table import Table

    from agent_bom.db.schema import DB_PATH, db_stats, init_db

    con = Console()
    db_file = Path(db_path) if db_path else DB_PATH

    if not db_file.exists():
        con.print(f"[yellow]No local DB found at {db_file}[/yellow]")
        con.print("Run [bold]agent-bom db update[/bold] to create it.")
        return

    conn = init_db(db_file)
    try:
        stats = db_stats(conn)
    finally:
        conn.close()

    con.print(f"[bold]Local vulnerability DB[/bold]  {db_file}")
    con.print(f"  Vulnerabilities : {stats['vuln_count']:,}")
    con.print(f"  Affected ranges : {stats['affected_count']:,}")
    con.print(f"  EPSS scores     : {stats['epss_count']:,}")
    con.print(f"  KEV entries     : {stats['kev_count']:,}")

    meta = stats.get("sync_meta", {})
    if meta:
        from agent_bom.db.schema import db_freshness_days

        age = db_freshness_days(db_file)
        if age is None:
            freshness_msg = "[yellow]Never synced — run agent-bom db update[/yellow]"
        elif age <= 7:
            freshness_msg = f"[green]Fresh ({age}d ago)[/green]"
        elif age <= 14:
            freshness_msg = f"[yellow]Aging ({age}d ago) — consider running db update[/yellow]"
        else:
            freshness_msg = f"[red]Stale ({age}d ago) — run agent-bom db update[/red]"
        con.print(f"  Freshness       : {freshness_msg}")

        table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
        table.add_column("Source")
        table.add_column("Last synced")
        table.add_column("Records", justify="right")
        for src, info in sorted(meta.items()):
            table.add_row(src, info.get("last_synced") or "—", f"{info.get('count', 0):,}")
        con.print(table)
    else:
        con.print("  [yellow]No sync data — run agent-bom db update to populate.[/yellow]")

    from agent_bom.mitre_fetch import get_catalog_metadata

    framework_meta = get_catalog_metadata()
    con.print("\n[bold]Framework catalogs[/bold]")
    con.print(
        "  MITRE ATT&CK/CAPEC : "
        f"{framework_meta.get('attack_version') or 'unknown'}"
        f"  [dim]({framework_meta.get('source', 'unknown')}, "
        f"{framework_meta.get('technique_count', 0)} techniques, "
        f"{framework_meta.get('cwe_mapping_count', 0)} CWE mappings)[/dim]"
    )
    updated_at = framework_meta.get("updated_at") or "unknown"
    con.print(f"  Updated at         : {updated_at}")


@db_cmd.command("update-frameworks")
@click.option(
    "--framework",
    "frameworks",
    multiple=True,
    type=click.Choice(["mitre", "atlas"], case_sensitive=False),
    help="Framework catalog to refresh (default: mitre + atlas). Repeatable.",
)
@click.option(
    "--catalog-path",
    type=click.Path(),
    default=None,
    help="Override the local MITRE ATT&CK catalog path (default: ~/.agent-bom/catalogs/mitre_attack_catalog.json).",
)
@click.option(
    "--atlas-catalog-path",
    type=click.Path(),
    default=None,
    help="Override the local MITRE ATLAS catalog path (default: ~/.agent-bom/catalogs/mitre_atlas_catalog.json).",
)
def db_update_frameworks(frameworks: tuple[str, ...], catalog_path: str | None, atlas_catalog_path: str | None) -> None:
    """Refresh locally cached framework catalogs without touching the scan hot path."""
    from pathlib import Path

    from rich.console import Console

    from agent_bom.atlas_fetch import get_catalog_metadata as get_atlas_metadata
    from agent_bom.atlas_fetch import sync_catalog as sync_atlas_catalog
    from agent_bom.mitre_fetch import get_catalog_metadata, sync_catalog

    con = Console()
    selected = [s.lower() for s in frameworks] or ["mitre", "atlas"]

    if "mitre" in selected:
        con.print("[bold]Refreshing framework catalogs[/bold] — mitre")
        catalog = sync_catalog(output_path=Path(catalog_path) if catalog_path else None)
        meta = (
            get_catalog_metadata()
            if catalog_path is None
            else {
                "path": str(Path(catalog_path)),
                "source": catalog.get("source", "synced"),
                "attack_version": catalog.get("attack_version", "unknown"),
                "updated_at": catalog.get("updated_at", ""),
                "technique_count": len(catalog.get("techniques", {})),
                "cwe_mapping_count": len(catalog.get("cwe_to_attack", {})),
                "normalized_sha256": catalog.get("normalized_sha256", ""),
            }
        )
        con.print(
            f"  [green]✓[/green] MITRE ATT&CK/CAPEC: {meta.get('attack_version', 'unknown')} "
            f"[dim]({meta.get('technique_count', 0)} techniques, {meta.get('cwe_mapping_count', 0)} CWE mappings)[/dim]"
        )
        con.print(f"  [dim]Source:[/dim] {meta.get('source', 'unknown')}")
        con.print(f"  [dim]Updated:[/dim] {meta.get('updated_at', '')}")
        con.print(f"  [dim]SHA256:[/dim] {meta.get('normalized_sha256', '')}")
        if meta.get("path"):
            con.print(f"  [dim]Path:[/dim] {meta['path']}")

    if "atlas" in selected:
        con.print("[bold]Refreshing framework catalogs[/bold] — atlas")
        atlas_catalog = sync_atlas_catalog(output_path=Path(atlas_catalog_path) if atlas_catalog_path else None)
        atlas_meta = (
            get_atlas_metadata()
            if atlas_catalog_path is None
            else {
                "path": str(Path(atlas_catalog_path)),
                "source": atlas_catalog.get("source", "synced"),
                "atlas_version": atlas_catalog.get("atlas_version", "unknown"),
                "updated_at": atlas_catalog.get("updated_at", ""),
                "technique_count": len(atlas_catalog.get("techniques", {})),
                "tactic_count": len(atlas_catalog.get("tactics", {})),
                "normalized_sha256": atlas_catalog.get("normalized_sha256", ""),
            }
        )
        con.print(
            f"  [green]✓[/green] MITRE ATLAS: {atlas_meta.get('atlas_version', 'unknown')} "
            f"[dim]({atlas_meta.get('technique_count', 0)} techniques, {atlas_meta.get('tactic_count', 0)} tactics)[/dim]"
        )
        con.print(f"  [dim]Source:[/dim] {atlas_meta.get('source', 'unknown')}")
        con.print(f"  [dim]Updated:[/dim] {atlas_meta.get('updated_at', '')}")
        con.print(f"  [dim]SHA256:[/dim] {atlas_meta.get('normalized_sha256', '')}")
        if atlas_meta.get("path"):
            con.print(f"  [dim]Path:[/dim] {atlas_meta['path']}")

    con.print("[bold green]Done.[/bold green]")


@db_cmd.command("framework-status")
@click.option(
    "--framework",
    "frameworks",
    multiple=True,
    type=click.Choice(["mitre", "atlas"], case_sensitive=False),
    help="Framework catalog to inspect (default: all). Repeatable.",
)
@click.option(
    "--stale-after-days",
    type=int,
    default=180,
    show_default=True,
    help="Mark a bundled framework catalog stale after this many days since upstream snapshot.",
)
@click.option(
    "--format",
    "-f",
    "fmt",
    type=click.Choice(["table", "json"]),
    default="table",
    help="Output format.",
)
@click.option(
    "--fail-on-stale",
    is_flag=True,
    help="Exit 1 when any inspected framework catalog is stale, missing, or has zero techniques.",
)
def db_framework_status(frameworks: tuple[str, ...], stale_after_days: int, fmt: str, fail_on_stale: bool) -> None:
    """Show bundled framework catalog freshness (mirrors ``registry status`` shape).

    Used in CI release gates to fail-fast when bundled MITRE catalogs are
    stale or empty.
    """
    import json
    from datetime import datetime, timezone

    from rich.console import Console
    from rich.table import Table

    from agent_bom.atlas import curated_total
    from agent_bom.atlas_fetch import get_catalog_metadata as get_atlas_metadata
    from agent_bom.mitre_fetch import get_catalog_metadata as get_mitre_metadata

    selected = [s.lower() for s in frameworks] or ["mitre", "atlas"]

    def _age_days(updated_at: str) -> int | None:
        if not updated_at:
            return None
        for fmt_ in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(updated_at, fmt_)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return max(0, (datetime.now(timezone.utc) - dt).days)
            except ValueError:
                continue
        return None

    rows: list[dict] = []
    any_stale = False
    if "mitre" in selected:
        meta = get_mitre_metadata()
        age = _age_days(meta.get("updated_at", ""))
        techniques = int(meta.get("technique_count", 0) or 0)
        is_stale = techniques == 0 or (age is not None and age > stale_after_days)
        any_stale = any_stale or is_stale
        rows.append(
            {
                "framework": "mitre_attack",
                "version": meta.get("attack_version", "unknown"),
                "source": meta.get("source", "unknown"),
                "techniques": techniques,
                "updated_at": meta.get("updated_at", ""),
                "age_days": age,
                "stale_after_days": stale_after_days,
                "status": "stale" if is_stale else "fresh",
            }
        )
    if "atlas" in selected:
        meta = get_atlas_metadata()
        age = _age_days(meta.get("updated_at", ""))
        techniques = int(meta.get("technique_count", 0) or 0)
        is_stale = techniques == 0 or (age is not None and age > stale_after_days)
        any_stale = any_stale or is_stale
        rows.append(
            {
                "framework": "mitre_atlas",
                "version": meta.get("atlas_version", "unknown"),
                "source": meta.get("source", "unknown"),
                "techniques": techniques,
                "curated_techniques": curated_total(),
                "updated_at": meta.get("updated_at", ""),
                "age_days": age,
                "stale_after_days": stale_after_days,
                "status": "stale" if is_stale else "fresh",
            }
        )

    if fmt == "json":
        click.echo(json.dumps({"frameworks": rows}, indent=2))
        if fail_on_stale and any_stale:
            raise click.exceptions.Exit(1)
        return

    con = Console()
    table = Table(title="Bundled framework catalog freshness")
    table.add_column("Framework")
    table.add_column("Version")
    table.add_column("Source")
    table.add_column("Techniques", justify="right")
    table.add_column("Updated at")
    table.add_column("Age")
    table.add_column("Status")
    for r in rows:
        status_color = "green" if r["status"] == "fresh" else "red"
        techs = str(r["techniques"])
        if "curated_techniques" in r:
            techs = f"{r['curated_techniques']} curated / {r['techniques']} upstream"
        age_str = "unknown" if r["age_days"] is None else f"{r['age_days']}d"
        table.add_row(
            r["framework"],
            r["version"],
            r["source"],
            techs,
            r["updated_at"] or "—",
            age_str,
            f"[{status_color}]{r['status']}[/{status_color}]",
        )
    con.print(table)
    if fail_on_stale and any_stale:
        raise click.exceptions.Exit(1)


@db_cmd.command("path")
@click.option("--path", "db_path", type=click.Path(), default=None, help="Override DB file path.")
def db_path_cmd(db_path: str | None) -> None:
    """Print the local vulnerability database file path."""
    from pathlib import Path

    from agent_bom.db.schema import DB_PATH

    click.echo(str(Path(db_path) if db_path else DB_PATH))
