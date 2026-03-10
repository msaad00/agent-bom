"""Policy template generation and auto-apply commands."""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console


@click.command("policy-template")
@click.option("--output", "-o", type=str, default="policy.json", help="Output path for the generated policy file")
def policy_template(output: str):
    """Generate a starter policy file with common rules.

    \b
    Example:
      agent-bom policy-template                    # writes policy.json
      agent-bom policy-template -o my-policy.json  # custom path

    Edit the generated file, then use it with:
      agent-bom scan --policy policy.json
    """
    import json as _json

    from agent_bom.policy import POLICY_TEMPLATE

    console = Console()
    out_path = Path(output)
    out_path.write_text(_json.dumps(POLICY_TEMPLATE, indent=2))
    console.print(f"\n  [green]✓[/green] Policy template written to {out_path}")
    console.print("  [dim]Edit the rules, then run:[/dim]")
    console.print(f"  [bold]agent-bom scan --policy {out_path}[/bold]\n")


@click.command("apply")
@click.argument("scan_json", type=click.Path(exists=True))
@click.option("--dir", "-d", "project_dir", type=click.Path(exists=True), default=".", help="Project directory containing dependency files")
@click.option("--dry-run", is_flag=True, help="Preview changes without modifying files")
@click.option("--no-backup", is_flag=True, help="Skip creating backup files")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompt (for CI/scripting)")
def apply_command(scan_json, project_dir, dry_run, no_backup, yes):
    """Apply remediation fixes from a scan result JSON file.

    Reads vulnerability fixes from a previous scan output and modifies
    package.json / requirements.txt with fixed versions.
    Creates backups by default. Use --dry-run to preview first.

    \b
    Example:
        agent-bom scan --format json --output scan.json
        agent-bom apply scan.json --dir ./my-project --dry-run
        agent-bom apply scan.json --dir ./my-project --yes
    """
    from rich.console import Console

    from agent_bom.remediate import apply_fixes_from_json

    con = Console(stderr=True)
    con.print(f"\n  Applying fixes from [bold]{scan_json}[/bold] to [bold]{project_dir}[/bold]")

    if not dry_run and not yes:
        con.print(
            "\n  [yellow]This will modify dependency files in the project directory.[/yellow]\n"
            f"  Backups will be created {'(disabled by --no-backup)' if no_backup else 'automatically'}.\n"
        )
        if not click.confirm("  Proceed?", default=False):
            con.print("  Aborted.")
            return

    result = apply_fixes_from_json(
        scan_json,
        project_dir,
        dry_run=dry_run,
        backup=not no_backup,
    )

    if not result.applied and not result.skipped:
        con.print("  [green]✓[/green] No fixable vulnerabilities in scan output")
        return

    if result.dry_run:
        con.print("  [yellow]Dry run — no files modified[/yellow]\n")

    for fix in result.applied:
        con.print(f"  [green]✓[/green] {fix.package} {fix.current_version} → {fix.fixed_version} ({fix.ecosystem})")

    for fix in result.skipped:
        con.print(f"  [dim]  Skipped {fix.package} — no {fix.ecosystem} dependency file found[/dim]")

    if result.backed_up:
        con.print(f"\n  Backups: {', '.join(result.backed_up)}")

    con.print(f"\n  Applied: {len(result.applied)}, Skipped: {len(result.skipped)}")
