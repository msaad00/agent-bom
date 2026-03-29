"""First-class skills command group for instruction/skill scanning."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from agent_bom.skills_service import scan_skill_targets, verify_skill_targets

_VERDICT_ORDER = {"benign": 0, "suspicious": 1, "malicious": 2}


def _display_path(path: str) -> str:
    """Render a concise path for console output."""
    p = Path(path)
    try:
        return str(p.relative_to(Path.cwd()))
    except ValueError:
        return p.name or str(p)


@click.group("skills", invoke_without_command=True)
@click.pass_context
def skills_group(ctx: click.Context) -> None:
    """Scan and verify AI instruction files, skills, and agent prompts.

    Covers `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `skills/*.md`,
    and other supported skill/instruction files.
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@skills_group.command("scan")
@click.argument("paths", nargs=-1, type=click.Path(exists=True, path_type=Path))
@click.option("-f", "--format", "output_format", type=click.Choice(["console", "json"]), default="console", show_default=True)
@click.option("-o", "--output", "output_path", type=click.Path(path_type=Path), help="Write output to this file")
@click.option(
    "--fail-on-verdict",
    type=click.Choice(["suspicious", "malicious"]),
    help="Exit 1 if any scanned file reaches this trust verdict or worse",
)
def skills_scan_cmd(paths: tuple[Path, ...], output_format: str, output_path: Path | None, fail_on_verdict: str | None) -> None:
    """Scan skill and instruction files for trust, risk, and provenance.

    \b
    Examples:
      agent-bom skills scan
      agent-bom skills scan CLAUDE.md .cursor/rules
      agent-bom skills scan . --fail-on-verdict suspicious -f json
    """
    report = scan_skill_targets(paths)
    payload = report.to_dict()

    if output_format == "json":
        rendered = json.dumps(payload, indent=2)
        if output_path:
            output_path.write_text(rendered)
        else:
            click.echo(rendered)
    else:
        console = Console()
        summary = payload["summary"]

        console.print("\n[bold]agent-bom skills scan[/bold]\n")
        if not report.files:
            console.print("  [yellow]⚠ No supported skill or instruction files found.[/yellow]\n")
            if output_path:
                output_path.write_text("")
            sys.exit(2)

        console.print(
            "  "
            f"[green]{summary['files_scanned']}[/green] file(s) · "
            f"[green]{summary['packages_found']}[/green] package ref(s) · "
            f"[green]{summary['servers_found']}[/green] server ref(s) · "
            f"[yellow]{summary['credential_env_vars']}[/yellow] credential var(s)\n"
        )

        files_table = Table(title="Instruction Surface", expand=True)
        files_table.add_column("File")
        files_table.add_column("Verdict", no_wrap=True)
        files_table.add_column("Prov.", no_wrap=True)
        files_table.add_column("Findings", justify="right", no_wrap=True)
        files_table.add_column("Refs", justify="right", no_wrap=True)

        verdict_style = {"benign": "green", "suspicious": "yellow", "malicious": "red"}
        prov_style = {"verified": "green", "unsigned": "yellow", "bundle_found_but_invalid": "red", "missing": "red"}

        for file_report in report.files:
            verdict = file_report.trust.verdict.value
            provenance = str(file_report.provenance.get("status", "unknown"))
            files_table.add_row(
                _display_path(str(file_report.path)),
                f"[{verdict_style.get(verdict, 'white')}]{verdict}[/{verdict_style.get(verdict, 'white')}]",
                f"[{prov_style.get(provenance, 'white')}]{provenance}[/{prov_style.get(provenance, 'white')}]",
                str(len(file_report.audit.findings)),
                str(len(file_report.scan.packages) + len(file_report.scan.servers)),
            )
        console.print(files_table)

        all_findings = [finding for file_report in report.files for finding in file_report.audit.findings]
        if all_findings:
            finding_table = Table(title="Top Findings", expand=True)
            finding_table.add_column("Sev", no_wrap=True)
            finding_table.add_column("File", no_wrap=True)
            finding_table.add_column("Category", no_wrap=True)
            finding_table.add_column("Title")
            sev_style = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "dim"}
            ordered = sorted(
                all_findings,
                key=lambda finding: ({"critical": 0, "high": 1, "medium": 2, "low": 3}.get(finding.severity, 4), finding.title.lower()),
            )
            for finding in ordered[:8]:
                style = sev_style.get(finding.severity, "white")
                finding_table.add_row(
                    f"[{style}]{finding.severity.upper()}[/{style}]",
                    _display_path(finding.source_file),
                    finding.category,
                    finding.title,
                )
            console.print()
            console.print(finding_table)

        recommendations = []
        seen_recommendations: set[str] = set()
        for file_report in report.files:
            for recommendation in file_report.trust.recommendations:
                if recommendation not in seen_recommendations:
                    seen_recommendations.add(recommendation)
                    recommendations.append(recommendation)

        if recommendations:
            console.print("\n[bold]Recommended next steps[/bold]")
            for recommendation in recommendations[:5]:
                console.print(f"  • {recommendation}")
        console.print()

        if output_path:
            output_path.write_text(json.dumps(payload, indent=2))

    if fail_on_verdict:
        threshold = _VERDICT_ORDER[fail_on_verdict]
        worst = max((_VERDICT_ORDER[file_report.trust.verdict.value] for file_report in report.files), default=0)
        if worst >= threshold:
            sys.exit(1)


@skills_group.command("verify")
@click.argument("paths", nargs=-1, type=click.Path(exists=True, path_type=Path))
@click.option("-f", "--format", "output_format", type=click.Choice(["console", "json"]), default="console", show_default=True)
@click.option("-o", "--output", "output_path", type=click.Path(path_type=Path), help="Write output to this file")
def skills_verify_cmd(paths: tuple[Path, ...], output_format: str, output_path: Path | None) -> None:
    """Verify Sigstore provenance for skill and instruction files.

    \b
    Examples:
      agent-bom skills verify
      agent-bom skills verify CLAUDE.md skills/
      agent-bom skills verify . -f json
    """
    results = verify_skill_targets(paths)

    if output_format == "json":
        rendered = json.dumps({"files": results}, indent=2)
        if output_path:
            output_path.write_text(rendered)
        else:
            click.echo(rendered)
    else:
        console = Console()
        console.print("\n[bold]agent-bom skills verify[/bold]\n")
        if not results:
            console.print("  [yellow]⚠ No supported skill or instruction files found.[/yellow]\n")
            if output_path:
                output_path.write_text("")
            sys.exit(2)

        table = Table(title="Instruction Provenance", expand=True)
        table.add_column("File")
        table.add_column("Status", no_wrap=True)
        table.add_column("Signer")
        table.add_column("Bundle", no_wrap=True)
        table.add_column("SHA-256", no_wrap=True)

        style_map = {"verified": "green", "unsigned": "yellow", "bundle_found_but_invalid": "red", "missing": "red"}

        for result in results:
            status = str(result["status"])
            style = style_map.get(status, "white")
            table.add_row(
                _display_path(str(result["path"])),
                f"[{style}]{status}[/{style}]",
                str(result.get("signer") or "—"),
                "yes" if result.get("has_sigstore_bundle") else "no",
                str(result.get("sha256", ""))[:16] + "..." if result.get("sha256") else "—",
            )
        console.print(table)
        console.print()

        if output_path:
            output_path.write_text(json.dumps({"files": results}, indent=2))

    if any(result["status"] != "verified" for result in results):
        sys.exit(1)
