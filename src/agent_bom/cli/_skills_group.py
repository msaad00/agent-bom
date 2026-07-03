"""First-class skills command group for instruction/skill scanning."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, cast

import click
from rich.console import Console
from rich.table import Table

from agent_bom.cli._grouped_help import SuggestingGroup
from agent_bom.skills_policy import SkillsPolicyError, evaluate_skills_policy, load_skills_policy
from agent_bom.skills_service import rescan_skill_catalog, scan_skill_targets, verify_skill_targets

_CI_DEFAULT_FAIL_VERDICT = "suspicious"


def _env_flag(name: str) -> bool:
    """Return True when an environment variable is set to a truthy value."""
    value = os.environ.get(name)
    return value is not None and value.strip().lower() in {"1", "true", "yes", "on"}


def _resolve_ci_fail_verdict(ci: bool, fail_on_verdict: str | None) -> str | None:
    """Resolve the effective content fail threshold for CI-friendly gating.

    Precedence: an explicit ``--fail-on-verdict`` always wins. Otherwise ``--ci``
    or the ``AGENT_BOM_SKILLS_CI`` env var enables a default ``suspicious`` gate so
    CI can block on suspicious/malicious skills without authoring a policy file.
    ``AGENT_BOM_SKILLS_FAIL_ON_VERDICT`` may override the default level.
    """
    if fail_on_verdict:
        return fail_on_verdict
    env_level = os.environ.get("AGENT_BOM_SKILLS_FAIL_ON_VERDICT")
    if env_level and env_level.strip().lower() in {"suspicious", "malicious"}:
        return env_level.strip().lower()
    if ci or _env_flag("AGENT_BOM_SKILLS_CI"):
        return _CI_DEFAULT_FAIL_VERDICT
    return None


def _display_path(path: str) -> str:
    """Render a concise path for console output."""
    p = Path(path)
    try:
        return str(p.relative_to(Path.cwd()))
    except ValueError:
        return p.name or str(p)


@click.group("skills", cls=SuggestingGroup, invoke_without_command=True)
@click.pass_context
def skills_group(ctx: click.Context) -> None:
    """Scan, verify, and rescan AI instruction files, skills, and agent prompts.

    Covers `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `skills/*.md`,
    and other supported skill/instruction files.
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@skills_group.command("scan")
@click.argument("paths", nargs=-1, type=click.Path(exists=True, path_type=Path))
@click.option("-f", "--format", "output_format", type=click.Choice(["console", "json", "sarif"]), default="console", show_default=True)
@click.option("-o", "--output", "output_path", type=click.Path(path_type=Path), help="Write output to this file")
@click.option(
    "--ci",
    is_flag=True,
    help="CI-friendly gate: exit 1 on suspicious/malicious skills without needing a policy file "
    "(equivalent to --fail-on-verdict suspicious; also enabled via AGENT_BOM_SKILLS_CI=1)",
)
@click.option(
    "--fail-on-verdict",
    type=click.Choice(["suspicious", "malicious"]),
    help="Exit 1 if any scanned file reaches this trust verdict or worse",
)
@click.option(
    "--warn-on-verdict",
    type=click.Choice(["suspicious", "malicious"]),
    help="Emit a non-blocking policy warning if content verdict reaches this level or worse",
)
@click.option(
    "--fail-on-review-verdict",
    type=click.Choice(["review", "high_risk", "blocked"]),
    help="Exit 1 if handling-oriented review verdict reaches this level or worse",
)
@click.option(
    "--warn-on-review-verdict",
    type=click.Choice(["review", "high_risk", "blocked"]),
    help="Emit a non-blocking policy warning if review verdict reaches this level or worse",
)
@click.option(
    "--policy",
    "policy_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to skills policy file (JSON/YAML) with warn/fail rules and suppressions",
)
@click.option("--intel-source", type=str, help="Optional local or remote JSON threat-intel feed for bundle hash lookups")
@click.option(
    "--catalog",
    "catalog_path",
    type=click.Path(path_type=Path),
    help="Path to the local skills catalog (defaults to ~/.agent-bom/skills/catalog.json)",
)
@click.option("--verbose", "-v", is_flag=True, help="Show all findings instead of only the default top findings summary")
@click.option("--no-color", is_flag=True, help="Disable colored output")
@click.option("--log-json", "log_json", is_flag=True, help="Emit structured JSON logs to stderr")
@click.option("--log-file", "log_file", type=click.Path(path_type=Path), default=None, help="Write JSON logs to file")
@click.option("--quiet", "-q", is_flag=True, help="Suppress headings, summaries, and recommendations in console output")
def skills_scan_cmd(
    paths: tuple[Path, ...],
    output_format: str,
    output_path: Path | None,
    ci: bool,
    fail_on_verdict: str | None,
    warn_on_verdict: str | None,
    fail_on_review_verdict: str | None,
    warn_on_review_verdict: str | None,
    policy_path: Path | None,
    intel_source: str | None,
    catalog_path: Path | None,
    verbose: bool,
    no_color: bool,
    log_json: bool,
    log_file: Path | None,
    quiet: bool,
) -> None:
    """Scan skill and instruction files for trust, risk, and provenance.

    \b
    Examples:
      agent-bom skills scan
      agent-bom skills scan CLAUDE.md .cursor/rules
      agent-bom skills scan . --ci -f json
      agent-bom skills scan . --fail-on-verdict suspicious -f json
    """
    from agent_bom.logging_config import setup_logging

    setup_logging(level="ERROR" if quiet else "INFO", json_output=log_json, log_file=str(log_file) if log_file else None)

    effective_fail_on_verdict = _resolve_ci_fail_verdict(ci, fail_on_verdict)

    report = scan_skill_targets(paths, intel_source=intel_source, catalog_path=catalog_path)
    payload = report.to_dict()
    try:
        policy = load_skills_policy(policy_path) if policy_path else None
        policy_result = evaluate_skills_policy(
            report,
            policy=policy,
            policy_path=policy_path,
            fail_on_verdict=effective_fail_on_verdict,
            warn_on_verdict=warn_on_verdict,
            fail_on_review_verdict=fail_on_review_verdict,
            warn_on_review_verdict=warn_on_review_verdict,
        )
    except SkillsPolicyError as exc:
        raise click.ClickException(str(exc)) from exc
    if policy or warn_on_verdict or fail_on_review_verdict or warn_on_review_verdict or effective_fail_on_verdict:
        payload["policy"] = policy_result.to_dict()

    if output_format in {"json", "sarif"}:
        if output_format == "sarif":
            from agent_bom.output.skills_sarif import skills_report_to_sarif

            rendered = json.dumps(skills_report_to_sarif(report), indent=2)
        else:
            rendered = json.dumps(payload, indent=2)
        if output_path:
            output_path.write_text(rendered)
        else:
            click.echo(rendered)
    else:
        console = Console(no_color=no_color)
        summary = payload["summary"]

        if not report.files:
            if not quiet:
                console.print("\n[bold]agent-bom skills scan[/bold]\n")
            console.print("  [yellow]⚠ No supported skill or instruction files found.[/yellow]\n")
            if output_path:
                output_path.write_text("")
            sys.exit(2)

        if not quiet:
            console.print("\n[bold]agent-bom skills scan[/bold]\n")
            console.print(
                "  "
                f"[green]{summary['files_scanned']}[/green] file(s) · "
                f"[green]{summary['packages_found']}[/green] package ref(s) · "
                f"[green]{summary['servers_found']}[/green] server ref(s) · "
                f"[yellow]{summary['credential_env_vars']}[/yellow] credential var(s)\n"
            )
            if report.catalog_path:
                console.print(f"  [dim]Catalog updated:[/dim] {report.catalog_path}\n")

        files_table = Table(title="Instruction Surface", expand=True)
        files_table.add_column("File")
        files_table.add_column("Status", no_wrap=True)
        files_table.add_column("Verdict", no_wrap=True)
        files_table.add_column("Review", no_wrap=True)
        files_table.add_column("Prov.", no_wrap=True)
        files_table.add_column("Findings", justify="right", no_wrap=True)
        files_table.add_column("Refs", justify="right", no_wrap=True)

        verdict_style = {"benign": "green", "suspicious": "yellow", "malicious": "red"}
        review_style = {"trusted": "green", "review": "yellow", "high_risk": "red", "blocked": "red bold"}
        prov_style = {"verified": "green", "unsigned": "yellow", "bundle_found_but_invalid": "red", "missing": "red"}
        status_style = {"clean": "green", "suspicious": "yellow", "malicious": "red", "pending": "cyan", "unavailable": "dim"}

        for file_report in report.files:
            verdict = file_report.trust.verdict.value
            review_verdict = file_report.trust.review_verdict.value
            provenance = str(file_report.provenance.get("status", "unknown"))
            status = file_report.status
            files_table.add_row(
                _display_path(str(file_report.path)),
                f"[{status_style.get(status, 'white')}]{status}[/{status_style.get(status, 'white')}]",
                f"[{verdict_style.get(verdict, 'white')}]{verdict}[/{verdict_style.get(verdict, 'white')}]",
                f"[{review_style.get(review_verdict, 'white')}]{review_verdict}[/{review_style.get(review_verdict, 'white')}]",
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
            for finding in ordered[: len(ordered) if verbose else 8]:
                style = sev_style.get(finding.severity, "white")
                finding_table.add_row(
                    f"[{style}]{finding.severity.upper()}[/{style}]",
                    _display_path(finding.source_file),
                    finding.category,
                    finding.title,
                )
            if not quiet:
                console.print()
            console.print(finding_table)

        family_totals: dict[str, int] = {}
        for file_report in report.files:
            families_obj = file_report.audit.behavioral_summary.get("families", {})
            families = families_obj if isinstance(families_obj, dict) else {}
            for family, count in families.items():
                family_totals[family] = family_totals.get(family, 0) + int(count)

        if family_totals and not quiet:
            behavior_table = Table(title="Behavior Profile", expand=True)
            behavior_table.add_column("Family")
            behavior_table.add_column("Signals", justify="right", no_wrap=True)
            for family, count in sorted(family_totals.items()):
                behavior_table.add_row(family.replace("_", " "), str(count))
            console.print()
            console.print(behavior_table)

        recommendations = []
        seen_recommendations: set[str] = set()
        for file_report in report.files:
            for recommendation in [*file_report.trust.reviewer_guidance, *file_report.trust.publisher_guidance]:
                if recommendation not in seen_recommendations:
                    seen_recommendations.add(recommendation)
                    recommendations.append(recommendation)

        if recommendations and not quiet:
            console.print("\n[bold]Recommended next steps[/bold]")
            for recommendation in recommendations[:5]:
                console.print(f"  • {recommendation}")
        if policy_result.status != "pass" and not quiet:
            console.print("\n[bold]Skills policy[/bold]")
            for decision in policy_result.violations[:5]:
                console.print(f"  [red]✗[/red] {decision.reason} — {_display_path(decision.path)}")
            for decision in policy_result.warnings[:5]:
                console.print(f"  [yellow]⚠[/yellow] {decision.reason} — {_display_path(decision.path)}")
        if not quiet:
            console.print()

        if output_path:
            output_path.write_text(json.dumps(payload, indent=2))

    if policy_result.failed:
        sys.exit(1)


@skills_group.command("rescan")
@click.option("-f", "--format", "output_format", type=click.Choice(["console", "json"]), default="console", show_default=True)
@click.option("-o", "--output", "output_path", type=click.Path(path_type=Path), help="Write output to this file")
@click.option("--intel-source", type=str, help="Optional local or remote JSON threat-intel feed for bundle hash lookups")
@click.option(
    "--catalog",
    "catalog_path",
    type=click.Path(path_type=Path),
    help="Path to the local skills catalog (defaults to ~/.agent-bom/skills/catalog.json)",
)
def skills_rescan_cmd(output_format: str, output_path: Path | None, intel_source: str | None, catalog_path: Path | None) -> None:
    """Re-scan previously seen skills from the local catalog."""
    report = rescan_skill_catalog(catalog_path=catalog_path, intel_source=intel_source)
    payload = report.to_dict()

    if output_format == "json":
        rendered = json.dumps(payload, indent=2)
        if output_path:
            output_path.write_text(rendered)
        else:
            click.echo(rendered)
        return

    console = Console()
    summary = cast(dict[str, Any], payload["summary"])
    entries = cast(list[dict[str, Any]], payload["entries"])
    console.print("\n[bold]agent-bom skills rescan[/bold]\n")
    console.print(
        "  "
        f"[green]{summary['rescanned']}[/green] rescanned · "
        f"[yellow]{summary['missing']}[/yellow] missing · "
        f"[green]{summary['clean']}[/green] clean · "
        f"[yellow]{summary['suspicious']}[/yellow] suspicious · "
        f"[red]{summary['malicious']}[/red] malicious · "
        f"[cyan]{summary['pending']}[/cyan] pending · "
        f"[dim]{summary['unavailable']}[/dim] unavailable\n"
    )
    console.print(f"  [dim]Catalog:[/dim] {payload['catalog_path']}\n")

    table = Table(title="Catalog Rescan", expand=True)
    table.add_column("Path")
    table.add_column("Status", no_wrap=True)
    table.add_column("Exists", no_wrap=True)
    table.add_column("Review", no_wrap=True)
    table.add_column("Findings", justify="right", no_wrap=True)
    status_style = {"clean": "green", "suspicious": "yellow", "malicious": "red", "pending": "cyan", "unavailable": "dim"}
    review_style = {"trusted": "green", "review": "yellow", "high_risk": "red", "blocked": "red bold", None: "dim"}

    for entry in entries:
        status = str(entry.get("status") or "unavailable")
        review = entry.get("review_verdict")
        table.add_row(
            _display_path(str(entry.get("path") or "—")),
            f"[{status_style.get(status, 'white')}]{status}[/{status_style.get(status, 'white')}]",
            "yes" if entry.get("exists") else "no",
            f"[{review_style.get(review, 'white')}]{review or '—'}[/{review_style.get(review, 'white')}]",
            str(entry.get("findings", 0)),
        )
    console.print(table)
    console.print()

    if output_path:
        output_path.write_text(json.dumps(payload, indent=2))


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
