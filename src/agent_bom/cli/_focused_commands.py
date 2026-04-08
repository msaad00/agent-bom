"""Focused scan commands — each command does one thing.

Each command is a focused, fast path for a specific scan type.
They all produce the same AIBOMReport model and support the same
output formats (--format, --output, --fail-on-severity).

Usage::

    agent-bom image nginx:latest          # container image scan
    agent-bom fs /mnt/snapshot            # filesystem / VM scan
    agent-bom iac Dockerfile k8s/         # IaC misconfiguration scan
    agent-bom sbom bom.json               # ingest + scan SBOM
    agent-bom secrets /path/to/project    # secret + PII scanning
    agent-bom code /path/to/project       # AST analysis (prompts, guardrails, tools)
"""

from __future__ import annotations

from typing import Optional

import click


@click.command("image")
@click.argument("image_ref")
@click.option("--platform", help="Target platform (e.g. linux/amd64)")
@click.option("-f", "--format", "output_format", default="console", help="Output format")
@click.option("-o", "--output", "output_path", help="Output file path")
@click.option("--fail-on-severity", type=click.Choice(["critical", "high", "medium", "low"]))
@click.option("--enrich", is_flag=True, help="Add NVD CVSS + EPSS + KEV enrichment")
@click.option("--offline", is_flag=True, help="Scan against local DB only")
@click.option("--quiet", "-q", is_flag=True, help="Minimal output")
@click.option("--fixable-only", "fixable_only", is_flag=True, default=False, help="Show only vulnerabilities with available fixes.")
def image_cmd(
    image_ref: str,
    platform: Optional[str],
    output_format: str,
    output_path: Optional[str],
    fail_on_severity: Optional[str],
    enrich: bool,
    offline: bool,
    quiet: bool,
    fixable_only: bool,
) -> None:
    """Scan a container image for vulnerabilities.

    \b
    Examples:
      agent-bom image nginx:latest
      agent-bom image myapp:v2.1 --enrich --fail-on-severity high
      agent-bom image ghcr.io/org/app:sha256-abc -f sarif -o results.sarif
    """
    from agent_bom.cli.agents import scan

    ctx = click.get_current_context()
    ctx.invoke(
        scan,
        images=(image_ref,),
        _image_only=True,
        image_platform=platform,
        output_format=output_format,
        output=output_path,
        fail_on_severity=fail_on_severity,
        enrich=enrich,
        offline=offline,
        quiet=quiet,
        fixable_only=fixable_only,
    )


@click.command("fs")
@click.argument("path")
@click.option("-f", "--format", "output_format", default="console", help="Output format")
@click.option("-o", "--output", "output_path", help="Output file path")
@click.option("--fail-on-severity", type=click.Choice(["critical", "high", "medium", "low"]))
@click.option("--enrich", is_flag=True, help="Add NVD CVSS + EPSS + KEV enrichment")
@click.option("--offline", is_flag=True, help="Scan against local DB only")
@click.option("--quiet", "-q", is_flag=True, help="Minimal output")
@click.option("--fixable-only", "fixable_only", is_flag=True, default=False, help="Show only vulnerabilities with available fixes.")
def fs_cmd(
    path: str,
    output_format: str,
    output_path: Optional[str],
    fail_on_severity: Optional[str],
    enrich: bool,
    offline: bool,
    quiet: bool,
    fixable_only: bool,
) -> None:
    """Scan a filesystem directory or mounted VM disk snapshot.

    \b
    Examples:
      agent-bom fs .
      agent-bom fs /mnt/vm-snapshot --offline
      agent-bom fs /app --fail-on-severity high -f sarif -o results.sarif
    """
    from agent_bom.cli.agents import scan

    ctx = click.get_current_context()
    ctx.invoke(
        scan,
        filesystem_paths=(path,),
        output_format=output_format,
        output=output_path,
        fail_on_severity=fail_on_severity,
        enrich=enrich,
        offline=offline,
        quiet=quiet,
        fixable_only=fixable_only,
    )


@click.command("iac")
@click.argument("paths", nargs=-1, required=True)
@click.option("-f", "--format", "output_format", default="console", help="Output format")
@click.option("-o", "--output", "output_path", help="Output file path")
@click.option("--fail-on-severity", type=click.Choice(["critical", "high", "medium", "low"]))
@click.option("--quiet", "-q", is_flag=True, help="Minimal output")
@click.option("--fixable-only", "fixable_only", is_flag=True, default=False, help="Show only vulnerabilities with available fixes.")
def iac_cmd(
    paths: tuple[str, ...],
    output_format: str,
    output_path: Optional[str],
    fail_on_severity: Optional[str],
    quiet: bool,
    fixable_only: bool,
) -> None:
    """Scan infrastructure-as-code files for misconfigurations.

    Supports: Dockerfile, Kubernetes YAML, Terraform (.tf), CloudFormation (.json/.yaml)

    \b
    Examples:
      agent-bom iac Dockerfile
      agent-bom iac Dockerfile k8s/ infra/main.tf
      agent-bom iac . -f sarif -o iac-results.sarif
    """
    from agent_bom.cli.agents import scan

    ctx = click.get_current_context()
    ctx.invoke(
        scan,
        iac_paths=paths,
        no_scan=True,  # IaC command: skip CVE scanning, package extraction, MCP agent discovery
        _iac_only=True,  # Internal: triggers IaC fast path (skip all discovery)
        output_format=output_format,
        output=output_path,
        fail_on_severity=fail_on_severity,
        quiet=quiet,
        fixable_only=fixable_only,
    )


@click.command("sbom")
@click.argument("path")
@click.option("--name", "sbom_name", help="Label for the SBOM resource")
@click.option("-f", "--format", "output_format", default="console", help="Output format")
@click.option("-o", "--output", "output_path", help="Output file path")
@click.option("--fail-on-severity", type=click.Choice(["critical", "high", "medium", "low"]))
@click.option("--enrich", is_flag=True, help="Add NVD CVSS + EPSS + KEV enrichment")
@click.option("--offline", is_flag=True, help="Scan against local DB only")
@click.option("--quiet", "-q", is_flag=True, help="Minimal output")
@click.option("--fixable-only", "fixable_only", is_flag=True, default=False, help="Show only vulnerabilities with available fixes.")
def sbom_cmd(
    path: str,
    sbom_name: Optional[str],
    output_format: str,
    output_path: Optional[str],
    fail_on_severity: Optional[str],
    enrich: bool,
    offline: bool,
    quiet: bool,
    fixable_only: bool,
) -> None:
    """Ingest an existing SBOM (CycloneDX/SPDX) and scan for vulnerabilities.

    \b
    Examples:
      agent-bom sbom vendor-bom.json
      agent-bom sbom bom.cdx.json --enrich --fail-on-severity critical
    """
    from agent_bom.cli.agents import scan

    ctx = click.get_current_context()
    ctx.invoke(
        scan,
        sbom_file=path,
        sbom_name=sbom_name,
        output_format=output_format,
        output=output_path,
        fail_on_severity=fail_on_severity,
        enrich=enrich,
        offline=offline,
        quiet=quiet,
        fixable_only=fixable_only,
    )


# ── Secret scanning ─────────────────────────────────────────────────────────


@click.command("secrets")
@click.argument("path", type=click.Path(exists=True))
@click.option("-f", "--format", "output_format", default="console", help="Output format (console or json)")
@click.option("-o", "--output", "output_path", help="Output file path")
@click.option("--quiet", "-q", is_flag=True)
def secrets_cmd(path: str, output_format: str, output_path: Optional[str], quiet: bool) -> None:
    """Scan a directory for hardcoded secrets and PII.

    Uses 34 credential patterns + 11 PII patterns + 4 file-specific
    patterns. Scans source code, config files, .env files, Dockerfiles,
    Terraform, and more.

    \b
    Examples:
      agent-bom secrets .                   # scan current directory
      agent-bom secrets /path/to/project    # scan specific project
      agent-bom secrets . --format json     # JSON output
    """
    import json as _json

    from rich.console import Console

    from agent_bom.secret_scanner import scan_secrets

    con = Console(stderr=True, quiet=quiet)
    result = scan_secrets(path)

    if output_format == "json":
        output = _json.dumps(result.to_dict(), indent=2)
        if output_path:
            from pathlib import Path as _Path

            _Path(output_path).write_text(output)
            con.print(f"[green]Secrets report written[/green] → {output_path}")
        else:
            click.echo(output)
        return

    # Console output
    con.print(f"\n[bold]Secret scan:[/bold] {result.files_scanned} files scanned\n")
    if not result.findings:
        con.print("[green]No secrets or PII found.[/green]")
        return

    for f in result.findings:
        sev_color = {"critical": "red", "high": "yellow", "medium": "blue"}.get(f.severity, "white")
        con.print(f"  [{sev_color}]{f.severity.upper()}[/{sev_color}]  {f.file_path}:{f.line_number}  {f.secret_type}")

    con.print(f"\n[bold]{result.total} findings[/bold] ({result.critical_count} critical)")


# ── Source code analysis ─────────────────────────────────────────────────────


@click.command("code")
@click.argument("path", type=click.Path(exists=True))
@click.option("-f", "--format", "output_format", default="console", help="Output format (console or json)")
@click.option("-o", "--output", "output_path", help="Output file path")
@click.option("--quiet", "-q", is_flag=True)
def code_cmd(path: str, output_format: str, output_path: Optional[str], quiet: bool) -> None:
    """Analyze source code for AI components — prompts, guardrails, tools.

    AST-based analysis of Python AI framework code. Extracts system
    prompts, detects guardrails, and maps tool signatures. Also reuses the
    multi-language AI component source scan to surface SDK/model usage across
    Python, JavaScript/TypeScript, Go, Java, Rust, and Ruby.

    \b
    Examples:
      agent-bom code .                      # analyze current project
      agent-bom code /path/to/agent-app     # analyze specific project
      agent-bom code . --format json        # JSON output
    """
    import json as _json

    from rich.console import Console

    from agent_bom.ai_components import scan_source
    from agent_bom.ast_analyzer import analyze_project

    con = Console(stderr=True, quiet=quiet)
    result = analyze_project(path)
    ai_report = scan_source(path)

    if output_format == "json":
        payload = result.to_dict()
        payload["ai_components"] = ai_report.to_dict()
        output = _json.dumps(payload, indent=2)
        if output_path:
            from pathlib import Path as _Path

            _Path(output_path).write_text(output)
            con.print(f"[green]Analysis written[/green] → {output_path}")
        else:
            click.echo(output)
        return

    # Console output
    con.print(f"\n[bold]Code analysis:[/bold] {result.files_analyzed} files analyzed\n")

    if result.prompts:
        con.print(f"[bold]System Prompts ({len(result.prompts)}):[/bold]")
        for p in result.prompts:
            risk = f" [red]⚠ {', '.join(p.risk_flags)}[/red]" if p.risk_flags else ""
            con.print(f"  {p.file_path}:{p.line_number}  [{p.prompt_type}] {p.variable_name}{risk}")
            con.print(f"    [dim]{p.text[:80]}...[/dim]")

    if result.guardrails:
        con.print(f"\n[bold]Guardrails ({len(result.guardrails)}):[/bold]")
        for g in result.guardrails:
            con.print(f"  {g.file_path}:{g.line_number}  [{g.guardrail_type}] {g.name}")

    if result.tools:
        con.print(f"\n[bold]Tool Signatures ({len(result.tools)}):[/bold]")
        for t in result.tools:
            params = ", ".join(f"{p['name']}: {p['type']}" for p in t.parameters)
            con.print(f"  {t.file_path}:{t.line_number}  {t.name}({params}) → {t.return_type}")

    if ai_report.total:
        con.print(f"\n[bold]AI Components ({ai_report.total} across {ai_report.files_scanned} files):[/bold]")
        for comp in ai_report.components[:12]:
            extra = " [yellow](shadow)[/yellow]" if comp.is_shadow else ""
            con.print(
                f"  {comp.file_path}:{comp.line_number}  [{comp.language}] {comp.component_type.value}  [bold]{comp.name}[/bold]{extra}"
            )
        if ai_report.total > 12:
            con.print(f"  [dim]... {ai_report.total - 12} more component finding(s)[/dim]")

    if ai_report.warnings:
        con.print("\n[yellow]Warnings:[/yellow]")
        for warning in ai_report.warnings:
            con.print(f"  [yellow]-[/yellow] {warning}")

    if result.flow_findings:
        con.print(f"\n[bold]Flow Findings ({len(result.flow_findings)}):[/bold]")
        for finding in result.flow_findings[:8]:
            path = " -> ".join(finding.call_path) if finding.call_path else finding.sink
            con.print(f"  {finding.file_path}:{finding.line_number}  [red]{finding.title}[/red]")
            con.print(f"    [dim]{path}[/dim]")

    stats = result.to_dict()["stats"]
    risky = stats["prompts_with_risks"]
    if risky:
        con.print(f"\n[red bold]{risky} prompt(s) with security risks[/red bold]")
