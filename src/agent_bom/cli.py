"""CLI entry point for agent-bom."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

from agent_bom import __version__
from agent_bom.discovery import discover_all
from agent_bom.models import AIBOMReport
from agent_bom.output import (
    export_cyclonedx,
    export_html,
    export_json,
    export_prometheus,
    export_sarif,
    export_spdx,
    print_agent_tree,
    print_blast_radius,
    print_diff,
    print_policy_results,
    print_remediation_plan,
    print_severity_chart,
    print_summary,
    push_otlp,
    push_to_gateway,
    to_cyclonedx,
    to_json,
    to_prometheus,
    to_sarif,
    to_spdx,
)
from agent_bom.parsers import extract_packages
from agent_bom.resolver import resolve_all_versions_sync
from agent_bom.scanners import scan_agents_sync

BANNER = r"""
   ___                    __     ____  ____  __  ___
  / _ | ___ ____ ___  ___/ /_   / __ )/ __ \/  |/  /
 / __ |/ _ `/ -_) _ \/ __/_  / / __  / / / / /|_/ /
/_/ |_/\_, /\__/_//_/\__/ /_/ /____/\____/_/  /_/
      /___/
  AI Bill of Materials for Agents & MCP Servers
"""

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}


def _make_console(quiet: bool = False, output_format: str = "console") -> Console:
    """Create a Console that routes output correctly.

    - quiet mode: suppress all output
    - json/cyclonedx format: route to stderr (keep stdout clean for piping)
    - console format: normal stdout
    """
    if quiet:
        return Console(stderr=True, quiet=True)
    if output_format != "console":
        return Console(stderr=True)
    return Console()


@click.group()
@click.version_option(version=__version__, prog_name="agent-bom")
def main():
    """agent-bom: Generate AI Bill of Materials for AI agents and MCP servers.

    Maps the full trust chain from agent → MCP server → packages → vulnerabilities,
    with blast radius analysis showing which agents are affected when a package is compromised.
    """
    pass


@main.command()
@click.option("--project", "-p", type=click.Path(exists=True), help="Project directory to scan")
@click.option("--config-dir", type=click.Path(exists=True), help="Custom agent config directory to scan")
@click.option("--inventory", type=click.Path(exists=True), help="Manual inventory JSON file")
@click.option("--output", "-o", type=str, help="Output file path (use '-' for stdout)")
@click.option(
    "--format", "-f", "output_format",
    type=click.Choice(["console", "json", "cyclonedx", "sarif", "spdx", "text", "html", "prometheus"]),
    default="console",
    help="Output format",
)
@click.option("--push-gateway", "push_gateway", default=None, metavar="URL",
              help="Prometheus Pushgateway URL to push metrics after scan (e.g. http://localhost:9091)")
@click.option("--otel-endpoint", "otel_endpoint", default=None, metavar="URL",
              help="OpenTelemetry OTLP/HTTP collector endpoint (e.g. http://localhost:4318). Requires pip install agent-bom[otel]")
@click.option("--no-scan", is_flag=True, help="Skip vulnerability scanning (inventory only)")
@click.option("--no-tree", is_flag=True, help="Skip dependency tree output")
@click.option("--transitive", is_flag=True, help="Resolve transitive dependencies for npx/uvx packages")
@click.option("--max-depth", type=int, default=3, help="Maximum depth for transitive dependency resolution")
@click.option("--enrich", is_flag=True, help="Enrich vulnerabilities with NVD, EPSS, and CISA KEV data")
@click.option("--nvd-api-key", envvar="NVD_API_KEY", help="NVD API key for higher rate limits")
@click.option("--quiet", "-q", is_flag=True, help="Suppress all output except results (for scripting)")
@click.option(
    "--fail-on-severity",
    type=click.Choice(["critical", "high", "medium", "low"]),
    help="Exit 1 if vulnerabilities of this severity or higher are found",
)
@click.option("--fail-on-kev", is_flag=True, help="Exit 1 if any finding appears in CISA KEV (must use --enrich)")
@click.option("--fail-if-ai-risk", is_flag=True, help="Exit 1 if an AI framework package with credentials has vulnerabilities")
@click.option("--save", "save_report", is_flag=True, help="Save this scan to ~/.agent-bom/history/ for future diffing")
@click.option("--baseline", type=click.Path(exists=True), help="Path to a baseline report JSON to diff against current scan")
@click.option("--policy", type=click.Path(exists=True), help="Policy file (JSON/YAML) with declarative security rules")
@click.option("--sbom", "sbom_file", type=click.Path(exists=True), help="Existing SBOM file to ingest (CycloneDX or SPDX JSON from Syft/Grype/Trivy)")
@click.option("--image", "images", multiple=True, metavar="IMAGE", help="Docker image to scan (e.g. nginx:1.25). Repeatable for multiple images.")
@click.option("--k8s", is_flag=True, help="Discover container images from a Kubernetes cluster via kubectl")
@click.option("--namespace", default="default", show_default=True, help="Kubernetes namespace (used with --k8s)")
@click.option("--all-namespaces", "-A", is_flag=True, help="Scan all Kubernetes namespaces (used with --k8s)")
@click.option("--context", "k8s_context", default=None, help="kubectl context to use (used with --k8s)")
def scan(
    project: Optional[str],
    config_dir: Optional[str],
    inventory: Optional[str],
    output: Optional[str],
    output_format: str,
    no_scan: bool,
    no_tree: bool,
    transitive: bool,
    max_depth: int,
    enrich: bool,
    nvd_api_key: Optional[str],
    quiet: bool,
    fail_on_severity: Optional[str],
    fail_on_kev: bool,
    fail_if_ai_risk: bool,
    save_report: bool,
    baseline: Optional[str],
    policy: Optional[str],
    sbom_file: Optional[str],
    images: tuple,
    k8s: bool,
    namespace: str,
    all_namespaces: bool,
    k8s_context: Optional[str],
    push_gateway: Optional[str],
    otel_endpoint: Optional[str],
):
    """Discover agents, extract dependencies, scan for vulnerabilities.

    \b
    Exit codes:
      0  Clean — no violations, no vulnerabilities at or above threshold
      1  Fail — policy failure, or vulnerabilities found at or above
                --fail-on-severity / --fail-on-kev / --fail-if-ai-risk
    """
    # Route console output based on flags
    is_stdout = output == "-"
    con = _make_console(quiet=quiet or is_stdout, output_format=output_format)

    # Also set the output module's console so print_summary etc. route correctly
    import agent_bom.output as _out
    _out.console = con

    con.print(BANNER, style="bold blue")

    # Step 1: Discovery
    if inventory:
        con.print(f"\n[bold blue]Loading inventory from {inventory}...[/bold blue]\n")
        from agent_bom.models import Agent, AgentType, MCPServer, MCPTool, Package, TransportType
        with open(inventory) as f:
            inventory_data = json.load(f)

        agents = []
        for agent_data in inventory_data.get("agents", []):
            mcp_servers = []
            for server_data in agent_data.get("mcp_servers", []):
                # Parse pre-populated tools (e.g. from Snowflake/cloud inventory)
                tools = []
                for tool_data in server_data.get("tools", []):
                    if isinstance(tool_data, str):
                        tools.append(MCPTool(name=tool_data, description=""))
                    elif isinstance(tool_data, dict):
                        tools.append(MCPTool(
                            name=tool_data.get("name", ""),
                            description=tool_data.get("description", ""),
                            input_schema=tool_data.get("input_schema"),
                        ))

                # Parse pre-known packages (e.g. from cloud asset scan)
                packages = []
                for pkg_data in server_data.get("packages", []):
                    if isinstance(pkg_data, str):
                        # Accept "name@version" shorthand
                        if "@" in pkg_data:
                            name, version = pkg_data.rsplit("@", 1)
                        else:
                            name, version = pkg_data, "unknown"
                        packages.append(Package(name=name, version=version, ecosystem="unknown"))
                    elif isinstance(pkg_data, dict):
                        packages.append(Package(
                            name=pkg_data.get("name", ""),
                            version=pkg_data.get("version", "unknown"),
                            ecosystem=pkg_data.get("ecosystem", "unknown"),
                            purl=pkg_data.get("purl"),
                        ))

                server = MCPServer(
                    name=server_data.get("name", ""),
                    command=server_data.get("command", ""),
                    args=server_data.get("args", []),
                    env=server_data.get("env", {}),
                    transport=TransportType(server_data.get("transport", "stdio")),
                    url=server_data.get("url"),
                    config_path=agent_data.get("config_path"),
                    working_dir=server_data.get("working_dir"),
                    mcp_version=server_data.get("mcp_version"),
                    tools=tools,
                    packages=packages,
                )
                mcp_servers.append(server)

            agent = Agent(
                name=agent_data.get("name", "unknown"),
                agent_type=AgentType(agent_data.get("agent_type", agent_data.get("type", "custom"))),
                config_path=agent_data.get("config_path", inventory),
                mcp_servers=mcp_servers,
                version=agent_data.get("version"),
                source=agent_data.get("source", inventory_data.get("source")),
            )
            agents.append(agent)

        con.print(f"  [green]✓[/green] Loaded {len(agents)} agent(s) from inventory")
    elif config_dir:
        con.print(f"\n[bold blue]Scanning config directory: {config_dir}...[/bold blue]\n")
        agents = discover_all(project_dir=config_dir)
    else:
        agents = discover_all(project_dir=project)

    if not agents and not images and not k8s:
        con.print("\n[yellow]No MCP configurations found.[/yellow]")
        con.print("  Use --project, --config-dir, --inventory, --image, or --k8s to specify a target.")
        sys.exit(0)

    # Step 1b: Load SBOM packages if provided
    sbom_packages: list = []
    if sbom_file:
        from agent_bom.sbom import load_sbom
        try:
            sbom_packages, sbom_fmt = load_sbom(sbom_file)
            con.print(
                f"\n[bold blue]Loaded SBOM ({sbom_fmt}): "
                f"{len(sbom_packages)} package(s) from {sbom_file}[/bold blue]\n"
            )
        except (FileNotFoundError, ValueError) as e:
            con.print(f"\n  [red]SBOM error: {e}[/red]")
            sys.exit(1)

    # Step 1c: Discover K8s container images (--k8s)
    if k8s:
        from agent_bom.k8s import K8sDiscoveryError, discover_images
        ns_label = "all namespaces" if all_namespaces else f"namespace '{namespace}'"
        con.print(f"\n[bold blue]Discovering container images from Kubernetes ({ns_label})...[/bold blue]\n")
        try:
            k8s_records = discover_images(
                namespace=namespace,
                all_namespaces=all_namespaces,
                context=k8s_context,
            )
            if k8s_records:
                con.print(f"  [green]✓[/green] Found {len(k8s_records)} unique image(s) across pods")
                extra_images = list(images) + [img for img, _pod, _ctr in k8s_records]
                images = tuple(dict.fromkeys(extra_images))  # deduplicate, preserve order
            else:
                con.print(f"  [dim]  No running pods found in {ns_label}[/dim]")
        except K8sDiscoveryError as e:
            con.print(f"\n  [red]K8s discovery error: {e}[/red]")
            sys.exit(1)

    # Step 1d: Scan Docker images (--image)
    if images:
        from agent_bom.image import ImageScanError, scan_image
        from agent_bom.models import Agent, AgentType, MCPServer, TransportType

        con.print(f"\n[bold blue]Scanning {len(images)} container image(s)...[/bold blue]\n")
        for image_ref in images:
            try:
                img_packages, strategy = scan_image(image_ref)
                con.print(
                    f"  [green]✓[/green] {image_ref}: {len(img_packages)} package(s) "
                    f"[dim](via {strategy})[/dim]"
                )
                # Represent the image as a synthetic agent → server
                server = MCPServer(
                    name=image_ref,
                    command="docker",
                    args=["run", image_ref],
                    transport=TransportType.STDIO,
                    packages=img_packages,
                )
                image_agent = Agent(
                    name=f"image:{image_ref}",
                    agent_type=AgentType.CUSTOM,
                    config_path=f"docker://{image_ref}",
                    mcp_servers=[server],
                )
                agents.append(image_agent)
            except ImageScanError as e:
                con.print(f"  [yellow]⚠[/yellow] {image_ref}: {e}")

    # Step 2: Extract packages
    con.print("\n[bold blue]Extracting package dependencies...[/bold blue]\n")
    if transitive:
        con.print(f"  [cyan]Transitive resolution enabled (max depth: {max_depth})[/cyan]\n")

    total_packages = 0
    for agent in agents:
        for server in agent.mcp_servers:
            # Keep pre-populated packages from inventory, merge with discovered ones
            pre_populated = list(server.packages)
            discovered = extract_packages(server, resolve_transitive=transitive, max_depth=max_depth)

            # Merge: discovered + pre-populated + SBOM packages (deduplicated)
            discovered_names = {(p.name, p.ecosystem) for p in discovered}
            merged = discovered + [p for p in pre_populated if (p.name, p.ecosystem) not in discovered_names]
            if sbom_packages:
                existing_names = {(p.name, p.ecosystem) for p in merged}
                merged += [p for p in sbom_packages if (p.name, p.ecosystem) not in existing_names]
                sbom_packages = []  # Attach to first server only, avoid duplication
            server.packages = merged

            total_packages += len(server.packages)
            if server.packages:
                direct_count = sum(1 for p in server.packages if p.is_direct)
                transitive_count = len(server.packages) - direct_count
                transitive_str = f" ({transitive_count} transitive)" if transitive_count > 0 else ""
                pre_str = f" ({len(pre_populated)} from inventory)" if pre_populated else ""
                con.print(
                    f"  [green]✓[/green] {server.name}: {len(server.packages)} package(s) "
                    f"({server.packages[0].ecosystem}){transitive_str}{pre_str}"
                )
            else:
                con.print(f"  [dim]  {server.name}: no local packages found[/dim]")

    con.print(f"\n  [bold]{total_packages} total packages.[/bold]")

    # Step 3: Resolve unknown versions
    all_packages = [p for a in agents for s in a.mcp_servers for p in s.packages]
    unresolved = [p for p in all_packages if p.version in ("latest", "unknown", "")]
    if unresolved:
        con.print(f"\n[bold blue]Resolving {len(unresolved)} package version(s)...[/bold blue]\n")
        resolved = resolve_all_versions_sync(all_packages)
        con.print(f"\n  [bold]Resolved {resolved}/{len(unresolved)} version(s).[/bold]")

    # Step 4: Vulnerability scan
    blast_radii = []
    if not no_scan and total_packages > 0:
        blast_radii = scan_agents_sync(agents, enable_enrichment=enrich, nvd_api_key=nvd_api_key)

    # Build report
    report = AIBOMReport(agents=agents, blast_radii=blast_radii)

    # Step 5: Output
    if is_stdout:
        # Pipe mode: write clean output to stdout
        if output_format == "cyclonedx":
            sys.stdout.write(json.dumps(to_cyclonedx(report), indent=2))
        elif output_format == "sarif":
            sys.stdout.write(json.dumps(to_sarif(report), indent=2))
        elif output_format == "spdx":
            sys.stdout.write(json.dumps(to_spdx(report), indent=2))
        elif output_format == "html":
            from agent_bom.output import to_html
            sys.stdout.write(to_html(report, blast_radii))
        elif output_format == "prometheus":
            sys.stdout.write(to_prometheus(report, blast_radii))
        else:
            sys.stdout.write(json.dumps(to_json(report), indent=2))
        sys.stdout.write("\n")
    elif output_format == "console" and not output:
        print_summary(report)
        if not no_tree:
            print_agent_tree(report)
        print_severity_chart(report)
        print_blast_radius(report)
        print_remediation_plan(blast_radii)
    elif output_format == "text" and not output:
        _print_text(report, blast_radii)
    elif output_format == "json":
        out_path = output or "agent-bom-report.json"
        export_json(report, out_path)
        con.print(f"\n  [green]✓[/green] JSON report: {out_path}")
    elif output_format == "cyclonedx":
        out_path = output or "agent-bom.cdx.json"
        export_cyclonedx(report, out_path)
        con.print(f"\n  [green]✓[/green] CycloneDX BOM: {out_path}")
    elif output_format == "sarif":
        out_path = output or "agent-bom.sarif"
        export_sarif(report, out_path)
        con.print(f"\n  [green]✓[/green] SARIF report: {out_path}")
    elif output_format == "spdx":
        out_path = output or "agent-bom.spdx.json"
        export_spdx(report, out_path)
        con.print(f"\n  [green]✓[/green] SPDX 3.0 BOM: {out_path}")
    elif output_format == "html":
        out_path = output or "agent-bom-report.html"
        export_html(report, out_path, blast_radii)
        con.print(f"\n  [green]✓[/green] HTML report: {out_path}")
        con.print(f"  [dim]Open with:[/dim] open {out_path}")
    elif output_format == "prometheus":
        out_path = output or "agent-bom-metrics.prom"
        export_prometheus(report, out_path, blast_radii)
        con.print(f"\n  [green]✓[/green] Prometheus metrics: {out_path}")
        con.print("  [dim]Scrape with node_exporter textfile or push via --push-gateway[/dim]")
    elif output_format == "text" and output:
        Path(output).write_text(_format_text(report, blast_radii))
        con.print(f"\n  [green]✓[/green] Text report: {output}")
    elif output:
        if output.endswith(".cdx.json"):
            export_cyclonedx(report, output)
        elif output.endswith(".sarif"):
            export_sarif(report, output)
        elif output.endswith(".spdx.json"):
            export_spdx(report, output)
        elif output.endswith(".html"):
            export_html(report, output, blast_radii)
        else:
            export_json(report, output)
        con.print(f"\n  [green]✓[/green] Report: {output}")

    # Step 5b: Push to Prometheus Pushgateway (if requested)
    if push_gateway:
        from agent_bom.output.prometheus import PushgatewayError
        try:
            push_to_gateway(push_gateway, report, blast_radii)
            con.print(f"\n  [green]✓[/green] Metrics pushed to Pushgateway: {push_gateway}")
        except PushgatewayError as e:
            con.print(f"\n  [yellow]⚠[/yellow] Pushgateway push failed: {e}")

    # Step 5c: OpenTelemetry OTLP export (if requested)
    if otel_endpoint:
        try:
            push_otlp(otel_endpoint, report, blast_radii)
            con.print(f"\n  [green]✓[/green] Metrics exported via OTLP: {otel_endpoint}")
        except ImportError as e:
            con.print(f"\n  [yellow]⚠[/yellow] OTel export skipped: {e}")
        except Exception as e:  # noqa: BLE001
            con.print(f"\n  [yellow]⚠[/yellow] OTLP export failed: {e}")

    # Step 6: Save report to history
    current_report_json = to_json(report)
    if save_report:
        from agent_bom.history import save_report as _save
        saved_path = _save(current_report_json)
        con.print(f"\n  [green]✓[/green] Report saved to history: {saved_path}")

    # Step 7: Diff against baseline
    if baseline:
        from agent_bom.history import diff_reports, load_report
        baseline_data = load_report(Path(baseline))
        diff = diff_reports(baseline_data, current_report_json)
        print_diff(diff)

    # Step 7b: Policy evaluation
    policy_passed = True
    if policy and blast_radii:
        from agent_bom.policy import evaluate_policy, load_policy
        try:
            policy_data = load_policy(policy)
            policy_result = evaluate_policy(policy_data, blast_radii)
            print_policy_results(policy_result)
            policy_passed = policy_result["passed"]
        except (FileNotFoundError, ValueError) as e:
            con.print(f"\n  [red]Policy error: {e}[/red]")
            sys.exit(1)

    # Step 8: Exit code based on policy flags
    exit_code = 0

    if fail_on_severity and blast_radii:
        threshold = SEVERITY_ORDER.get(fail_on_severity, 0)
        for br in blast_radii:
            sev = br.vulnerability.severity.value.lower()
            if SEVERITY_ORDER.get(sev, 0) >= threshold:
                if not quiet:
                    con.print(
                        f"\n  [red]Exiting with code 1: found {sev} vulnerability "
                        f"({br.vulnerability.id})[/red]"
                    )
                exit_code = 1
                break

    if fail_on_kev and blast_radii:
        kev_findings = [br for br in blast_radii if br.vulnerability.is_kev]
        if kev_findings:
            if not quiet:
                con.print(
                    f"\n  [red bold]Exiting with code 1: {len(kev_findings)} CISA KEV "
                    f"finding(s) found (use --enrich if not already)[/red bold]"
                )
            exit_code = 1

    if fail_if_ai_risk and blast_radii:
        ai_findings = [br for br in blast_radii if br.ai_risk_context and br.exposed_credentials]
        if ai_findings:
            if not quiet:
                con.print(
                    f"\n  [red bold]Exiting with code 1: {len(ai_findings)} AI framework "
                    f"package(s) with vulnerabilities and exposed credentials[/red bold]"
                )
            exit_code = 1

    if not policy_passed:
        exit_code = 1

    if exit_code:
        sys.exit(exit_code)


def _format_text(report: AIBOMReport, blast_radii: list) -> str:
    """Plain text output for piping to grep/awk."""
    lines = []
    lines.append(f"agent-bom {report.tool_version}")
    lines.append(f"agents={report.total_agents} servers={report.total_servers} "
                 f"packages={report.total_packages} vulnerabilities={report.total_vulnerabilities}")
    lines.append("")

    for agent in report.agents:
        for server in agent.mcp_servers:
            for pkg in server.packages:
                lines.append(f"{agent.name}\t{server.name}\t{pkg.ecosystem}\t{pkg.name}\t{pkg.version}")

    if blast_radii:
        lines.append("")
        lines.append("VULN_ID\tSEVERITY\tPACKAGE\tFIX\tAGENTS\tCREDENTIALS")
        for br in blast_radii:
            v = br.vulnerability
            lines.append(
                f"{v.id}\t{v.severity.value}\t{br.package.name}@{br.package.version}\t"
                f"{v.fixed_version or '-'}\t{len(br.affected_agents)}\t{len(br.exposed_credentials)}"
            )

    return "\n".join(lines) + "\n"


def _print_text(report: AIBOMReport, blast_radii: list) -> None:
    """Print plain text to stdout."""
    sys.stdout.write(_format_text(report, blast_radii))


@main.command()
@click.option("--config", "-c", type=click.Path(exists=True), help="Path to specific MCP config file")
@click.option("--project", "-p", type=click.Path(exists=True), help="Project directory to scan")
@click.option("--transitive", is_flag=True, help="Resolve transitive dependencies for npx/uvx packages")
@click.option("--max-depth", type=int, default=3, help="Maximum depth for transitive dependency resolution")
@click.option("--quiet", "-q", is_flag=True, help="Suppress all output except results")
def inventory(config: Optional[str], project: Optional[str], transitive: bool, max_depth: int, quiet: bool):
    """Show discovered agents and MCP servers (no vulnerability scan)."""
    con = _make_console(quiet=quiet)

    import agent_bom.output as _out
    _out.console = con

    con.print(BANNER, style="bold blue")

    if config:
        config_path = Path(config)
        try:
            config_data = json.loads(config_path.read_text())
            from agent_bom.discovery import parse_mcp_config
            from agent_bom.models import Agent, AgentType

            servers = parse_mcp_config(config_data, str(config_path))
            agents = [Agent(
                name=f"custom:{config_path.stem}",
                agent_type=AgentType.CUSTOM,
                config_path=str(config_path),
                mcp_servers=servers,
            )] if servers else []
        except Exception as e:
            con.print(f"[red]Error parsing config: {e}[/red]")
            sys.exit(1)
    else:
        agents = discover_all(project_dir=project)

    if not agents:
        con.print("\n[yellow]No MCP configurations found.[/yellow]")
        sys.exit(0)

    con.print("\n[bold blue]Extracting package dependencies...[/bold blue]\n")
    if transitive:
        con.print(f"  [cyan]Transitive resolution enabled (max depth: {max_depth})[/cyan]\n")

    for agent in agents:
        for server in agent.mcp_servers:
            server.packages = extract_packages(server, resolve_transitive=transitive, max_depth=max_depth)

    report = AIBOMReport(agents=agents)
    print_summary(report)
    print_agent_tree(report)


@main.command()
@click.argument("inventory_file", type=click.Path(exists=True))
def validate(inventory_file: str):
    """Validate an inventory file against the agent-bom schema.

    \b
    Exit codes:
      0  Valid — inventory matches the schema
      1  Invalid — schema violations found
    """
    console = Console()
    console.print(BANNER, style="bold blue")

    try:
        import jsonschema
    except ImportError:
        console.print("[red]jsonschema not installed. Run: pip install jsonschema[/red]")
        sys.exit(1)

    schema_path = Path(__file__).parent.parent.parent / "schemas" / "inventory.schema.json"
    if not schema_path.exists():
        # Fallback: look relative to installed package
        import importlib.resources
        try:
            schema_path = Path(str(importlib.resources.files("agent_bom"))) / ".." / ".." / "schemas" / "inventory.schema.json"
        except Exception:
            schema_path = None

    if not schema_path or not schema_path.exists():
        console.print("[red]Schema file not found. Run from the agent-bom repo root.[/red]")
        sys.exit(1)

    with open(schema_path) as f:
        schema = json.load(f)

    with open(inventory_file) as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            console.print(f"[red]JSON parse error: {e}[/red]")
            sys.exit(1)

    validator = jsonschema.Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.path))

    if not errors:
        agents = data.get("agents", [])
        total_servers = sum(len(a.get("mcp_servers", [])) for a in agents)
        total_packages = sum(
            len(s.get("packages", []))
            for a in agents
            for s in a.get("mcp_servers", [])
        )
        console.print(f"\n  [green]✓ Valid[/green] — {len(agents)} agent(s), {total_servers} server(s), {total_packages} package(s)")
        console.print(f"\n  [dim]Scan with:[/dim] agent-bom scan --inventory {inventory_file}")
    else:
        console.print(f"\n  [red]✗ Invalid — {len(errors)} error(s):[/red]\n")
        for err in errors:
            path = " → ".join(str(p) for p in err.path) or "(root)"
            console.print(f"  [red]•[/red] [bold]{path}[/bold]: {err.message}")
        console.print()
        sys.exit(1)


@main.command()
def where():
    """Show where agent-bom looks for MCP configurations."""
    console = Console()
    console.print(BANNER, style="bold blue")
    console.print("\n[bold]MCP Client Configuration Locations[/bold]\n")

    from agent_bom.discovery import CONFIG_LOCATIONS, PROJECT_CONFIG_FILES, expand_path, get_platform

    current_platform = get_platform()

    for agent_type, platforms in CONFIG_LOCATIONS.items():
        paths = platforms.get(current_platform, [])
        console.print(f"\n  [bold cyan]{agent_type.value}[/bold cyan]")
        for p in paths:
            expanded = expand_path(p)
            exists = "✓" if expanded.exists() else "✗"
            style = "green" if expanded.exists() else "dim"
            console.print(f"    [{style}]{exists} {expanded}[/{style}]")

    console.print("\n  [bold cyan]Project-level configs[/bold cyan]")
    for config_name in PROJECT_CONFIG_FILES:
        console.print(f"    [dim]  ./{config_name}[/dim]")


@main.command()
@click.argument("package_spec")
@click.option(
    "--ecosystem", "-e",
    type=click.Choice(["npm", "pypi", "go", "cargo", "maven", "nuget"]),
    help="Package ecosystem (inferred from name/command if omitted)",
)
@click.option("--quiet", "-q", is_flag=True, help="Only print vuln count, no details")
def check(package_spec: str, ecosystem: Optional[str], quiet: bool):
    """Check a package for known vulnerabilities before installing.

    \b
    Examples:
      agent-bom check express@4.18.2 --ecosystem npm
      agent-bom check requests@2.28.0 --ecosystem pypi
      agent-bom check "npx @modelcontextprotocol/server-filesystem"

    \b
    Exit codes:
      0  Clean — no known vulnerabilities
      1  Unsafe — vulnerabilities found
    """
    import asyncio

    console = Console()

    # Parse package spec: handle "npx package-name", "uvx package-name", or "name@version"
    spec = package_spec.strip()
    if spec.startswith("npx ") or spec.startswith("uvx "):
        parts = spec.split()
        # npx -y @scope/pkg → take last arg that looks like a package
        pkg_args = [p for p in parts[1:] if not p.startswith("-")]
        spec = pkg_args[0] if pkg_args else spec
        if not ecosystem:
            ecosystem = "pypi" if package_spec.startswith("uvx") else "npm"

    if "@" in spec and not spec.startswith("@"):
        name, version = spec.rsplit("@", 1)
    elif spec.startswith("@") and spec.count("@") > 1:
        # Scoped npm: @scope/pkg@version
        last_at = spec.rindex("@")
        name, version = spec[:last_at], spec[last_at + 1:]
    else:
        name, version = spec, "unknown"

    # Infer ecosystem from name if not provided
    if not ecosystem:
        if name.startswith("@") or "-" in name and "." not in name:
            ecosystem = "npm"
        else:
            ecosystem = "pypi"

    from agent_bom.models import Package
    from agent_bom.scanners import build_vulnerabilities, query_osv_batch

    pkg = Package(name=name, version=version, ecosystem=ecosystem)

    if version == "unknown":
        console.print(f"[yellow]⚠ No version specified for {name} — skipping OSV lookup.[/yellow]")
        console.print("  Provide a version: agent-bom check name@version --ecosystem ecosystem")
        sys.exit(0)

    console.print(f"\n[bold blue]🔍 Checking {name}@{version} ({ecosystem})[/bold blue]\n")

    results = asyncio.run(query_osv_batch([pkg]))
    key = f"{ecosystem}:{name}@{version}"
    vuln_data = results.get(key, [])

    if not vuln_data:
        console.print(f"  [green]✓ No known vulnerabilities in {name}@{version}[/green]\n")
        sys.exit(0)

    vulns = build_vulnerabilities(vuln_data, pkg)

    if not quiet:
        from rich.table import Table
        table = Table(title=f"{name}@{version} — {len(vulns)} vulnerability/ies found")
        table.add_column("ID", width=20)
        table.add_column("Severity", width=10)
        table.add_column("CVSS", width=6, justify="right")
        table.add_column("Fix", width=15)
        table.add_column("Summary", max_width=50)

        severity_styles = {
            "critical": "red bold", "high": "red",
            "medium": "yellow", "low": "dim",
        }
        for v in vulns:
            sev = v.severity.value.lower()
            style = severity_styles.get(sev, "white")
            table.add_row(
                v.id,
                f"[{style}]{v.severity.value}[/{style}]",
                f"{v.cvss_score:.1f}" if v.cvss_score else "—",
                v.fixed_version or "—",
                (v.summary or "")[:80],
            )
        console.print(table)
        console.print()

    console.print(f"  [red]✗ {len(vulns)} vulnerability/ies found — do not install without review.[/red]\n")
    sys.exit(1)


@main.command("history")
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

    console.print(f"\n[bold blue]📂 Scan History[/bold blue]  "
                  f"({len(reports)} total, showing {min(limit, len(reports))})\n")

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


@main.command("diff")
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


@main.command("policy-template")
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


if __name__ == "__main__":
    main()
