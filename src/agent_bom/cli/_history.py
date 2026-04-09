"""Scan history, diff, and rescan commands."""

from __future__ import annotations

import json as _json
import logging
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Optional, cast

import click
from rich.console import Console

from agent_bom.output import print_diff
from agent_bom.output.compliance_narrative import ALL_FRAMEWORK_SLUGS

if TYPE_CHECKING:
    from agent_bom.models import Agent, AIBOMReport, BlastRadius

logger = logging.getLogger(__name__)


@dataclass
class _NarrativeReport:
    """Lightweight report shim for compliance narratives loaded from saved JSON."""

    agents: list["Agent"]
    blast_radii: list["BlastRadius"]
    summary_total_agents: int
    summary_total_packages: int

    @property
    def total_agents(self) -> int:
        return max(self.summary_total_agents, len(self.agents))

    @property
    def total_packages(self) -> int:
        if self.summary_total_packages > 0:
            return self.summary_total_packages
        return len({(br.package.ecosystem, br.package.name, br.package.version) for br in self.blast_radii})


def _report_from_json(data: dict) -> "_NarrativeReport":
    """Rebuild the minimal report structure required for compliance narratives."""
    from agent_bom.models import Agent, AgentType, BlastRadius, MCPServer, Package, Severity, Vulnerability

    blast_radii: list[BlastRadius] = []
    agents_by_name: dict[str, Agent] = {}
    servers_by_name: dict[str, MCPServer] = {}
    package_index: dict[tuple[str, str, str], Package] = {}
    package_server_links: set[tuple[str, tuple[str, str, str]]] = set()
    agent_server_links: set[tuple[str, str]] = set()

    for br in data.get("blast_radius", []):
        pkg_spec = str(br.get("package", ""))
        if "@" in pkg_spec:
            pkg_name, pkg_version = pkg_spec.rsplit("@", 1)
        else:
            pkg_name, pkg_version = pkg_spec, "unknown"
        ecosystem = str(br.get("ecosystem") or "pypi")

        vuln = Vulnerability(
            id=str(br.get("id") or br.get("vulnerability_id") or "UNKNOWN"),
            summary=str(br.get("summary") or "No description available"),
            severity=Severity(str(br.get("severity") or "unknown").lower()),
            fixed_version=br.get("fixed_version"),
            is_kev=bool(br.get("is_kev")),
        )
        package_key = (ecosystem, pkg_name, pkg_version)
        package = package_index.get(package_key)
        if package is None:
            package = Package(name=pkg_name, version=pkg_version, ecosystem=ecosystem, vulnerabilities=[vuln])
            package_index[package_key] = package
        elif all(existing.id != vuln.id for existing in package.vulnerabilities):
            package.vulnerabilities.append(vuln)

        agents: list[Agent] = []
        for name in br.get("affected_agents", []):
            agent = agents_by_name.get(name)
            if agent is None:
                agent = Agent(name=name, agent_type=AgentType.CUSTOM, config_path="scan-report://agent")
                agents_by_name[name] = agent
            agents.append(agent)

        servers: list[MCPServer] = []
        for name in br.get("affected_servers", []):
            server = servers_by_name.get(name)
            if server is None:
                server = MCPServer(name=name, config_path="scan-report://server")
                servers_by_name[name] = server
            servers.append(server)
            package_link_key = (name, package_key)
            if package_link_key not in package_server_links:
                package_server_links.add(package_link_key)
                server.packages.append(package)

        for agent in agents:
            for server in servers:
                agent_link_key = (agent.name, server.name)
                if agent_link_key not in agent_server_links:
                    agent_server_links.add(agent_link_key)
                    agent.mcp_servers.append(server)

        blast_radii.append(
            BlastRadius(
                vulnerability=vuln,
                package=package,
                affected_servers=servers,
                affected_agents=agents,
                exposed_credentials=list(br.get("exposed_credentials", [])),
                exposed_tools=[],
                risk_score=float(br.get("risk_score") or 0.0),
                owasp_tags=list(br.get("owasp_tags", [])),
                atlas_tags=list(br.get("atlas_tags", [])),
                nist_ai_rmf_tags=list(br.get("nist_ai_rmf_tags", [])),
                owasp_mcp_tags=list(br.get("owasp_mcp_tags", [])),
                owasp_agentic_tags=list(br.get("owasp_agentic_tags", [])),
                eu_ai_act_tags=list(br.get("eu_ai_act_tags", [])),
                nist_csf_tags=list(br.get("nist_csf_tags", [])),
                iso_27001_tags=list(br.get("iso_27001_tags", [])),
                soc2_tags=list(br.get("soc2_tags", [])),
                cis_tags=list(br.get("cis_tags", [])),
                cmmc_tags=list(br.get("cmmc_tags", [])),
                nist_800_53_tags=list(br.get("nist_800_53_tags", [])),
                fedramp_tags=list(br.get("fedramp_tags", [])),
            )
        )

    summary = data.get("summary") or {}
    return _NarrativeReport(
        agents=[agents_by_name[name] for name in sorted(agents_by_name)],
        blast_radii=blast_radii,
        summary_total_agents=int(summary.get("total_agents") or 0),
        summary_total_packages=int(summary.get("total_packages") or 0),
    )


def _write_cli_output(payload: dict, output_path: str | None) -> None:
    """Write JSON payload to stdout or a file."""
    text = _json.dumps(payload, indent=2)
    if output_path and output_path != "-":
        Path(output_path).write_text(text, encoding="utf-8")
        return
    click.echo(text)


@click.command("history")
@click.option("--limit", "-n", type=int, default=10, help="Number of recent scans to show")
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["console", "json"], case_sensitive=False),
    default="console",
    show_default=True,
    help="Output format.",
)
@click.option("--output", "-o", type=str, default=None, help="Write JSON output to a file (use '-' for stdout).")
@click.option("--quiet", "-q", is_flag=True, help="Suppress headings and footer metadata in console output.")
def history_cmd(limit: int, output_format: str, output: str | None, quiet: bool):
    """List saved scan reports from ~/.agent-bom/history/."""
    from agent_bom.history import list_reports, load_report

    if output and output_format != "json":
        raise click.ClickException("`report history --output` requires `--format json`.")

    console = Console()

    reports = list_reports()
    if not reports:
        if output_format == "json":
            _write_cli_output(
                {
                    "history_dir": str(Path.home() / ".agent-bom" / "history"),
                    "total_reports": 0,
                    "reports": [],
                },
                output,
            )
            return
        console.print("\n  [dim]No saved scans yet. Run with --save to start tracking history.[/dim]\n")
        return

    rows: list[dict[str, object]] = []
    for path in reports[:limit]:
        row: dict[str, object] = {
            "path": str(path),
            "file": path.name,
            "generated_at": None,
            "total_agents": None,
            "total_packages": None,
            "total_vulnerabilities": None,
            "critical_findings": None,
        }
        try:
            data = load_report(path)
            summary = data.get("summary", {})
            row.update(
                {
                    "generated_at": data.get("generated_at", "unknown"),
                    "total_agents": summary.get("total_agents"),
                    "total_packages": summary.get("total_packages"),
                    "total_vulnerabilities": summary.get("total_vulnerabilities"),
                    "critical_findings": summary.get("critical_findings"),
                }
            )
        except Exception as exc:  # noqa: BLE001
            row["error"] = str(exc)
        rows.append(row)

    if output_format == "json":
        _write_cli_output(
            {
                "history_dir": str(reports[0].parent),
                "total_reports": len(reports),
                "returned_reports": len(rows),
                "reports": rows,
            },
            output,
        )
        return

    if not quiet:
        console.print(f"\n[bold blue]📂 Scan History[/bold blue]  ({len(reports)} total, showing {min(limit, len(reports))})\n")

    from rich.table import Table

    table = Table()
    table.add_column("File", width=30)
    table.add_column("Generated", width=22)
    table.add_column("Agents", width=7, justify="center")
    table.add_column("Packages", width=9, justify="center")
    table.add_column("Vulns", width=6, justify="center")
    table.add_column("Critical", width=9, justify="center")

    for row in rows:
        generated_at = row.get("generated_at")
        if isinstance(generated_at, str) and generated_at not in {"", "unknown"}:
            generated = generated_at[:19].replace("T", " ")
        else:
            generated = "—"
        table.add_row(
            str(row["file"]),
            generated,
            str(row.get("total_agents", "?") if row.get("total_agents") is not None else "—"),
            str(row.get("total_packages", "?") if row.get("total_packages") is not None else "—"),
            str(row.get("total_vulnerabilities", "?") if row.get("total_vulnerabilities") is not None else "—"),
            str(row.get("critical_findings", "?") if row.get("critical_findings") is not None else "—"),
        )

    console.print(table)
    if not quiet:
        console.print(f"\n  [dim]History directory: {reports[0].parent}[/dim]\n")


@click.command("diff")
@click.argument("baseline", type=click.Path(exists=True))
@click.argument("current", type=click.Path(exists=True), required=False)
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["console", "json"], case_sensitive=False),
    default="console",
    show_default=True,
    help="Output format.",
)
@click.option("--output", "-o", type=str, default=None, help="Write JSON output to a file (use '-' for stdout).")
@click.option("--quiet", "-q", is_flag=True, help="Only print a compact summary in console output.")
def diff_cmd(baseline: str, current: Optional[str], output_format: str, output: str | None, quiet: bool):
    """Diff two scan reports to see what changed.

    \b
    Usage:
      agent-bom report diff baseline.json                # diff against latest saved scan
      agent-bom report diff baseline.json current.json   # diff two specific files
      agent-bom report diff baseline.cdx.json current.spdx.json   # diff two external SBOMs
      agent-bom report diff baseline.cdx.json latest-scan.json    # diff external SBOM vs agent-bom report

    \b
    Exit codes:
      0  No new findings
      1  New vulnerability findings detected
    """
    from agent_bom.history import diff_reports, latest_report, load_report_or_sbom

    if output and output_format != "json":
        raise click.ClickException("`report diff --output` requires `--format json`.")

    console = Console()

    baseline_data = load_report_or_sbom(Path(baseline))

    if current:
        current_path = Path(current)
        current_data = load_report_or_sbom(current_path)
    else:
        latest = latest_report()
        if not latest:
            console.print("[red]No saved scans in history. Run: agent-bom scan --save[/red]")
            sys.exit(1)
        current_path = latest
        current_data = load_report_or_sbom(current_path)

    diff = diff_reports(baseline_data, current_data)
    if output_format == "json":
        _write_cli_output(
            {
                "baseline_path": str(Path(baseline).resolve()),
                "current_path": str(current_path.resolve()),
                **diff,
            },
            output,
        )
    else:
        print_diff(diff, quiet=quiet)

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
      # ... apply fixes: agent-bom policy apply before.json  OR  pip install -U ...
      agent-bom report rescan before.json
      agent-bom report rescan before.json --output verification.json --md verification.md

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

    from agent_bom.package_utils import normalize_package_name

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


@click.command("compliance-narrative")
@click.argument("scan_file", type=click.Path(exists=True))
@click.option(
    "--framework",
    type=click.Choice(ALL_FRAMEWORK_SLUGS),
    default=None,
    help="Generate a single-framework narrative instead of the full set.",
)
@click.option("--format", "-f", "output_format", type=click.Choice(["json", "markdown"]), default="markdown", show_default=True)
@click.option("--output", "-o", type=str, default=None, help="Write the narrative to a file instead of stdout")
def compliance_narrative_cmd(scan_file: str, framework: Optional[str], output_format: str, output: Optional[str]) -> None:
    """Generate an auditor-facing compliance narrative from a saved scan report."""
    from agent_bom.output.compliance_narrative import generate_compliance_narrative

    console = Console()
    narrative = generate_compliance_narrative(
        cast("AIBOMReport", _report_from_json(_json.loads(Path(scan_file).read_text()))),
        framework=framework,
    )

    if output_format == "json":
        rendered = _json.dumps(asdict(narrative), indent=2)
    else:
        lines = ["# Compliance Narrative", "", narrative.executive_summary, ""]
        for fw in narrative.framework_narratives:
            lines.extend([f"## {fw.framework}", "", fw.narrative, "", f"Status: `{fw.status}` · Score: `{fw.score}/100`", ""])
            if fw.recommendations:
                lines.append("Recommendations:")
                for recommendation in fw.recommendations:
                    lines.append(f"- {recommendation}")
                lines.append("")
        if narrative.remediation_impact:
            lines.extend(["## Remediation Impact", ""])
            for impact in narrative.remediation_impact:
                lines.append(f"- {impact.narrative}")
        rendered = "\n".join(lines).rstrip() + "\n"

    if output:
        Path(output).write_text(rendered)
        console.print(f"[green]✓[/green] Compliance narrative: {output}")
    else:
        click.echo(rendered)
