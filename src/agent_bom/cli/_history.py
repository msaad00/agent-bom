"""Scan history, diff, and rescan commands."""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

from agent_bom.cli._common import BANNER
from agent_bom.output import print_diff

logger = logging.getLogger(__name__)


@click.command("history")
@click.option("--limit", "-n", type=int, default=10, help="Number of recent scans to show")
def history_cmd(limit: int):
    """List saved scan reports from ~/.agent-bom/history/."""
    from agent_bom.history import list_reports, load_report

    console = Console()
    console.print(BANNER, style="bold blue")

    reports = list_reports()
    if not reports:
        console.print("\n  [dim]No saved scans yet. Run with --save to start tracking history.[/dim]\n")
        return

    console.print(f"\n[bold blue]📂 Scan History[/bold blue]  ({len(reports)} total, showing {min(limit, len(reports))})\n")

    from rich.table import Table

    table = Table()
    table.add_column("File", width=30)
    table.add_column("Generated", width=22)
    table.add_column("Agents", width=7, justify="center")
    table.add_column("Packages", width=9, justify="center")
    table.add_column("Vulns", width=6, justify="center")
    table.add_column("Critical", width=9, justify="center")

    for path in reports[:limit]:
        try:
            data = load_report(path)
            summary = data.get("summary", {})
            table.add_row(
                path.name,
                data.get("generated_at", "unknown")[:19].replace("T", " "),
                str(summary.get("total_agents", "?")),
                str(summary.get("total_packages", "?")),
                str(summary.get("total_vulnerabilities", "?")),
                str(summary.get("critical_findings", "?")),
            )
        except Exception:
            table.add_row(path.name, "—", "—", "—", "—", "—")

    console.print(table)
    console.print(f"\n  [dim]History directory: {reports[0].parent}[/dim]\n")


@click.command("diff")
@click.argument("baseline", type=click.Path(exists=True))
@click.argument("current", type=click.Path(exists=True), required=False)
def diff_cmd(baseline: str, current: Optional[str]):
    """Diff two scan reports to see what changed.

    \b
    Usage:
      agent-bom diff baseline.json                # diff against latest saved scan
      agent-bom diff baseline.json current.json   # diff two specific files

    \b
    Exit codes:
      0  No new findings
      1  New vulnerability findings detected
    """
    from agent_bom.history import diff_reports, latest_report, load_report

    console = Console()

    baseline_data = load_report(Path(baseline))

    if current:
        current_data = load_report(Path(current))
    else:
        latest = latest_report()
        if not latest:
            console.print("[red]No saved scans in history. Run: agent-bom scan --save[/red]")
            sys.exit(1)
        current_data = load_report(latest)

    diff = diff_reports(baseline_data, current_data)
    print_diff(diff)

    if diff["summary"]["new_findings"] > 0:
        sys.exit(1)


@click.command("rescan")
@click.argument("baseline", type=click.Path(exists=True))
@click.option(
    "--output",
    "-o",
    type=str,
    default=None,
    help="Write verification report to this JSON file",
)
@click.option(
    "--md",
    type=str,
    default=None,
    help="Write human-readable verification report to this Markdown file",
)
@click.option("--enrich", is_flag=True, default=False, help="Enrich re-scan with NVD/EPSS/CISA KEV data")
def rescan_command(baseline: str, output: Optional[str], md: Optional[str], enrich: bool):
    """Re-scan previously vulnerable packages to verify remediation.

    Loads a prior scan result, extracts all vulnerable packages, forces a fresh
    OSV query (bypassing cache), and shows what was resolved vs what remains.

    \b
    Typical remediation verification workflow:
      agent-bom scan --format json --output before.json
      # ... apply fixes: agent-bom apply before.json  OR  pip install -U ...
      agent-bom rescan before.json
      agent-bom rescan before.json --output verification.json --md verification.md

    \b
    Exit codes:
      0  All vulnerabilities resolved
      1  Vulnerabilities remain
      2  Error loading baseline
    """
    import asyncio
    import json as _json

    from rich.console import Console
    from rich.table import Table

    from agent_bom.scan_cache import ScanCache
    from agent_bom.scanners import build_vulnerabilities, query_osv_batch

    con = Console(stderr=True)
    con.print(f"\n  [bold blue]Remediation Verification[/bold blue]  —  baseline: [bold]{baseline}[/bold]\n")

    # ── Load baseline ─────────────────────────────────────────────────────────
    try:
        baseline_data = _json.loads(Path(baseline).read_text())
    except Exception as exc:
        con.print(f"  [red]Error loading baseline: {exc}[/red]")
        sys.exit(2)

    blast_radii = baseline_data.get("blast_radius", [])
    if not blast_radii:
        con.print("  [green]✓[/green] Baseline has no vulnerabilities — nothing to verify.")
        sys.exit(0)

    # ── Extract unique vulnerable packages from baseline ──────────────────────
    seen: set[tuple[str, str, str]] = set()
    vuln_packages: list[tuple[str, str, str]] = []  # (ecosystem, name, version)
    for br in blast_radii:
        pkg_str = br.get("package", "")  # "name@version"
        eco = br.get("ecosystem", "pypi").lower()
        if "@" in pkg_str:
            name, ver = pkg_str.rsplit("@", 1)
        else:
            name, ver = pkg_str, ""
        if ver and (eco, name, ver) not in seen:
            seen.add((eco, name, ver))
            vuln_packages.append((eco, name, ver))

    if not vuln_packages:
        con.print("  [yellow]Could not extract package versions from baseline.[/yellow]")
        sys.exit(2)

    con.print(f"  Re-scanning [bold]{len(vuln_packages)}[/bold] previously vulnerable package(s)...\n")

    # ── Evict cached results so we get fresh OSV data ─────────────────────────
    try:
        cache = ScanCache()
        evicted = cache.evict_many([(eco, name, ver) for eco, name, ver in vuln_packages])
        if evicted:
            con.print(f"  [dim]Cache cleared for {evicted} package(s)[/dim]")
    except Exception as exc:
        # Cache eviction failure is non-fatal
        logger.debug("Cache eviction failed: %s", exc, exc_info=True)

    # ── Re-scan via OSV ───────────────────────────────────────────────────────
    from agent_bom.models import Package

    packages = [Package(name=name, version=ver, ecosystem=eco) for eco, name, ver in vuln_packages]
    try:
        fresh_results = asyncio.run(query_osv_batch(packages))
    except Exception as exc:
        con.print(f"  [red]OSV query failed: {exc}[/red]")
        sys.exit(2)

    from agent_bom.models import normalize_package_name

    # ── Optional NVD/EPSS/KEV enrichment ─────────────────────────────────────
    if enrich:
        try:
            from agent_bom.enrichment import enrich_vulnerabilities

            for pkg in packages:
                key = f"{pkg.ecosystem.lower()}:{normalize_package_name(pkg.name, pkg.ecosystem)}@{pkg.version}"
                vulns = [build_vulnerabilities([v], pkg) for v in fresh_results.get(key, [])]
                flat = [v for sub in vulns for v in sub]
                asyncio.run(enrich_vulnerabilities(flat))
        except Exception as exc:
            logger.debug("Re-scan enrichment failed: %s", exc, exc_info=True)

    # ── Compare before vs after ───────────────────────────────────────────────
    # Build vuln-id sets from baseline
    baseline_vuln_ids: dict[str, set[str]] = {}  # pkg_key → set of vuln IDs
    for br in blast_radii:
        pkg_str = br.get("package", "")
        eco = br.get("ecosystem", "pypi").lower()
        pkg_key = f"{eco}:{pkg_str}"
        vid = br.get("vulnerability_id", "")
        baseline_vuln_ids.setdefault(pkg_key, set()).add(vid)

    resolved: list[dict] = []
    remaining: list[dict] = []
    newly_found: list[dict] = []

    for pkg in packages:
        key = f"{pkg.ecosystem.lower()}:{normalize_package_name(pkg.name, pkg.ecosystem)}@{pkg.version}"
        baseline_key = f"{pkg.ecosystem.lower()}:{normalize_package_name(pkg.name, pkg.ecosystem)}@{pkg.version}"
        old_ids = baseline_vuln_ids.get(baseline_key, set())
        fresh_vulns = build_vulnerabilities(fresh_results.get(key, []), pkg)
        new_ids = {v.id for v in fresh_vulns}

        for vid in old_ids - new_ids:
            resolved.append({"id": vid, "package": f"{pkg.name}@{pkg.version}", "ecosystem": pkg.ecosystem})
        for vid in old_ids & new_ids:
            v = next((x for x in fresh_vulns if x.id == vid), None)
            remaining.append(
                {
                    "id": vid,
                    "package": f"{pkg.name}@{pkg.version}",
                    "ecosystem": pkg.ecosystem,
                    "severity": v.severity.value if v else "unknown",
                    "fixed_version": v.fixed_version if v else None,
                }
            )
        for vid in new_ids - old_ids:
            v = next((x for x in fresh_vulns if x.id == vid), None)
            newly_found.append(
                {
                    "id": vid,
                    "package": f"{pkg.name}@{pkg.version}",
                    "ecosystem": pkg.ecosystem,
                    "severity": v.severity.value if v else "unknown",
                }
            )

    # ── Print results ─────────────────────────────────────────────────────────
    if resolved:
        con.print(f"  [green bold]✓ Resolved ({len(resolved)}):[/green bold]")
        for r in resolved:
            con.print(f"    [green]✓[/green]  {r['id']}  {r['package']} ({r['ecosystem']})")

    if remaining:
        con.print(f"\n  [red bold]✗ Still vulnerable ({len(remaining)}):[/red bold]")
        tbl = Table(show_header=True, header_style="bold red", box=None, padding=(0, 2))
        tbl.add_column("CVE / Advisory")
        tbl.add_column("Package")
        tbl.add_column("Severity")
        tbl.add_column("Fix available")
        for r in remaining:
            fix = r.get("fixed_version") or "[red dim]none[/red dim]"
            sev = r["severity"].upper()
            sev_style = "red" if sev in ("CRITICAL", "HIGH") else "yellow"
            tbl.add_row(r["id"], f"{r['package']} ({r['ecosystem']})", f"[{sev_style}]{sev}[/{sev_style}]", fix)
        con.print(tbl)
        for r in remaining:
            if r.get("fixed_version"):
                eco = r["ecosystem"].lower()
                name = r["package"].split("@")[0]
                fix = r["fixed_version"]
                if eco == "pypi":
                    con.print(f"    [cyan]pip install '{name}>={fix}'[/cyan]")
                elif eco == "npm":
                    con.print(f"    [cyan]npm install {name}@{fix}[/cyan]")
                elif eco == "go":
                    con.print(f"    [cyan]go get {name}@v{fix}[/cyan]")
                elif eco == "cargo":
                    con.print(f"    [cyan]cargo update -p {name}[/cyan]")

    if newly_found:
        con.print(f"\n  [yellow bold]⚠ New findings ({len(newly_found)}) — not in baseline:[/yellow bold]")
        for r in newly_found:
            con.print(f"    [yellow]![/yellow]  {r['id']}  {r['package']}  [{r['severity']}]")

    # ── Summary ───────────────────────────────────────────────────────────────
    con.print()
    con.print(
        f"  Resolved: [green]{len(resolved)}[/green]  "
        f"Remaining: [{'red' if remaining else 'green'}]{len(remaining)}[/{'red' if remaining else 'green'}]  "
        f"New: [{'yellow' if newly_found else 'dim'}]{len(newly_found)}[/{'yellow' if newly_found else 'dim'}]"
    )

    # ── Write outputs ─────────────────────────────────────────────────────────
    from datetime import datetime, timezone

    verification = {
        "type": "remediation_verification",
        "baseline": str(baseline),
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "resolved": len(resolved),
            "remaining": len(remaining),
            "newly_found": len(newly_found),
            "packages_rescanned": len(vuln_packages),
        },
        "resolved": resolved,
        "remaining": remaining,
        "newly_found": newly_found,
    }

    if output:
        Path(output).write_text(_json.dumps(verification, indent=2))
        con.print(f"\n  [green]✓[/green] Verification report: {output}")

    if md:
        lines = [
            "# Remediation Verification Report\n",
            f"**Baseline:** `{baseline}`  \n",
            f"**Verified at:** {verification['verified_at']}  \n",
            f"**Packages re-scanned:** {len(vuln_packages)}\n\n",
            "## Summary\n\n",
            "| Status | Count |\n|--------|-------|\n",
            f"| ✅ Resolved | {len(resolved)} |\n",
            f"| ❌ Remaining | {len(remaining)} |\n",
            f"| ⚠️ Newly found | {len(newly_found)} |\n\n",
        ]
        if resolved:
            lines.append("## Resolved\n\n")
            for r in resolved:
                lines.append(f"- ✅ `{r['id']}` — {r['package']} ({r['ecosystem']})\n")
            lines.append("\n")
        if remaining:
            lines.append("## Still Vulnerable\n\n")
            lines.append("| CVE / Advisory | Package | Severity | Fix |\n|---|---|---|---|\n")
            for r in remaining:
                fix = r.get("fixed_version") or "none"
                lines.append(f"| `{r['id']}` | {r['package']} | {r['severity']} | {fix} |\n")
            lines.append("\n")
        if newly_found:
            lines.append("## New Findings (not in baseline)\n\n")
            for r in newly_found:
                lines.append(f"- ⚠️ `{r['id']}` — {r['package']} [{r['severity']}]\n")
            lines.append("\n")
        Path(md).write_text("".join(lines))
        con.print(f"  [green]✓[/green] Verification report (Markdown): {md}")

    con.print()
    sys.exit(1 if remaining else 0)
