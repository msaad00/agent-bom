"""CLI commands for the local vulnerability database.

Commands:
    agent-bom db update   — sync from OSV / EPSS / KEV
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
    type=click.Choice(["osv", "epss", "kev"], case_sensitive=False),
    help="Which sources to sync (default: all). Repeatable.",
)
@click.option("--path", "db_path", type=click.Path(), default=None, help="Override DB file path.")
@click.option(
    "--max-osv-entries",
    type=int,
    default=0,
    help="Limit OSV entries (for testing). 0 = unlimited.",
    hidden=True,
)
def db_update(sources: tuple, db_path: str | None, max_osv_entries: int) -> None:
    """Download and sync the local vulnerability database.

    Pulls from OSV.dev (bulk export), FIRST EPSS scores, and CISA KEV catalog.
    Requires internet access. First sync is ~50 MB and takes several minutes.
    Subsequent syncs are incremental (upsert by ID).
    """
    from pathlib import Path

    from rich.console import Console

    from agent_bom.db.sync import sync_db

    con = Console()
    selected = list(sources) or ["osv", "epss", "kev"]
    con.print(f"[bold]Syncing local vuln DB[/bold] — sources: {', '.join(selected)}")

    try:
        results = sync_db(
            path=Path(db_path) if db_path else None,
            sources=selected,
            max_osv_entries=max_osv_entries,
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
        table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
        table.add_column("Source")
        table.add_column("Last synced")
        table.add_column("Records", justify="right")
        for src, info in sorted(meta.items()):
            table.add_row(src, info.get("last_synced") or "—", f"{info.get('count', 0):,}")
        con.print(table)


@db_cmd.command("path")
@click.option("--path", "db_path", type=click.Path(), default=None, help="Override DB file path.")
def db_path_cmd(db_path: str | None) -> None:
    """Print the local vulnerability database file path."""
    from pathlib import Path

    from agent_bom.db.schema import DB_PATH

    click.echo(str(Path(db_path) if db_path else DB_PATH))
