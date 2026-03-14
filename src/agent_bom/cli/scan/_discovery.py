"""Steps 1–1g4: local agent/package discovery."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from agent_bom.cli._common import _build_agents_from_inventory
from agent_bom.cli.scan._context import ScanContext
from agent_bom.discovery import discover_all as _discover_all_default


def run_local_discovery(
    ctx: ScanContext,
    *,
    project: Any,
    config_dir: Any,
    inventory: Any,
    skill_only: bool,
    dynamic_discovery: bool,
    dynamic_max_depth: int,
    include_processes: bool,
    include_containers: bool,
    introspect: bool,
    introspect_timeout: float,
    enforce: bool,
    health_check: bool,
    hc_timeout: float,
    k8s_mcp: bool,
    k8s_namespace: str,
    k8s_all_namespaces: bool,
    k8s_mcp_context: Any,
    no_skill: bool,
    skill_paths: tuple,
    skill_only_mode: bool,
    ai_enrich: bool,
    ai_model: str,
    sbom_file: Any,
    sbom_name: Any,
    external_scan_path: Any,
    k8s: bool,
    namespace: str,
    all_namespaces: bool,
    k8s_context: Any,
    registry_user: Any,
    registry_pass: Any,
    image_platform: Any,
    images: tuple,
    image_tars: tuple,
    filesystem_paths: tuple,
    code_paths: tuple,
    sast_config: str,
    tf_dirs: tuple,
    gha_path: Any,
    agent_projects: tuple,
    scan_prompts: bool,
    browser_extensions: bool,
    jupyter_dirs: tuple,
    iac_paths: tuple = (),
    verbose: bool = False,
    quiet: bool = False,
    smithery_token: Any = None,
    smithery_flag: bool = False,
    mcp_registry_flag: bool = False,
    os_packages: bool = False,
    _discover_all: Any = None,
    **kwargs: Any,
) -> None:
    """Steps 1–1g4: discover agents from local sources, SBOM, images, etc."""
    from rich.rule import Rule

    # Allow callers to inject discover_all (enables patch("agent_bom.cli.scan.discover_all"))
    _discover = _discover_all if _discover_all is not None else _discover_all_default
    con = ctx.con
    con.print(Rule("Discovery", style="blue"))

    # Step 1: Agent discovery
    if skill_only:
        ctx.agents = []  # skill-only: no agent discovery
    elif inventory:
        label = "stdin" if inventory == "-" else inventory
        con.print(f"\n[bold blue]Loading inventory from {label}...[/bold blue]\n")

        from agent_bom.inventory import load_inventory

        inventory_data = load_inventory(inventory)
        ctx.agents = _build_agents_from_inventory(inventory_data, inventory)
        con.print(f"  [green]✓[/green] Loaded {len(ctx.agents)} agent(s) from inventory")
    elif config_dir:
        con.print(f"\n[bold blue]Scanning config directory: {config_dir}...[/bold blue]\n")
        with con.status("[bold]Discovering agents and MCP servers...[/bold]", spinner="dots"):
            ctx.agents = _discover(
                project_dir=config_dir,
                dynamic=dynamic_discovery,
                dynamic_max_depth=dynamic_max_depth,
                include_processes=include_processes,
                include_containers=include_containers,
                include_k8s_mcp=k8s_mcp,
                k8s_namespace=k8s_namespace,
                k8s_all_namespaces=k8s_all_namespaces,
                k8s_context=k8s_mcp_context,
            )
    else:
        with con.status("[bold]Discovering agents and MCP servers...[/bold]", spinner="dots"):
            ctx.agents = _discover(
                project_dir=project,
                dynamic=dynamic_discovery,
                dynamic_max_depth=dynamic_max_depth,
                include_processes=include_processes,
                include_containers=include_containers,
                include_k8s_mcp=k8s_mcp,
                k8s_namespace=k8s_namespace,
                k8s_all_namespaces=k8s_all_namespaces,
                k8s_context=k8s_mcp_context,
            )

    any_cloud = kwargs.get("_any_cloud", False)
    if (
        not skill_only
        and not scan_prompts
        and not ctx.agents
        and not images
        and not k8s
        and not code_paths
        and not project  # --project: package scan fallback runs below
        and not sbom_file
        and not tf_dirs
        and not gha_path
        and not agent_projects
        and not jupyter_dirs
        and not any_cloud
    ):
        con.print("\n[bold yellow]No MCP configurations found on this machine.[/bold yellow]")
        con.print()
        con.print("  [bold]Quick start options:[/bold]")
        con.print("    [cyan]agent-bom scan --project .[/cyan]        scan all packages in current directory")
        con.print("    [cyan]agent-bom scan --image myapp:latest[/cyan] scan a Docker image")
        con.print("    [cyan]agent-bom scan --sbom sbom.json[/cyan]   ingest an existing SBOM (CycloneDX / SPDX)")
        con.print("    [cyan]agent-bom check requests@2.25.0[/cyan]   check a single package for CVEs")
        con.print("    [cyan]agent-bom scan --config-dir PATH[/cyan]  point to a directory with MCP configs")
        con.print()
        con.print("  [dim]Supported MCP clients: Claude Desktop, Cursor, VS Code, Windsurf, and 16 more.[/dim]")
        con.print("  [dim]Full options: agent-bom scan --help[/dim]")
        con.print("  [dim]Docs: https://github.com/msaad00/agent-bom[/dim]")
        con.print()
        sys.exit(0)

    # Step 1b: Load SBOM packages if provided
    if not skill_only and sbom_file:
        from agent_bom.models import Agent, AgentType, MCPServer, TransportType
        from agent_bom.sbom import load_sbom

        try:
            sbom_packages, sbom_fmt, sbom_detected_name = load_sbom(sbom_file)
            _resource_name = sbom_name or sbom_detected_name or Path(sbom_file).stem
            con.print(f"\n[bold blue]Loaded SBOM ({sbom_fmt}): {len(sbom_packages)} package(s) from '{_resource_name}'[/bold blue]\n")
            sbom_server = MCPServer(
                name=_resource_name,
                command="sbom",
                args=[sbom_file],
                transport=TransportType.STDIO,
                packages=sbom_packages,
            )
            sbom_agent = Agent(
                name=f"sbom:{_resource_name}",
                agent_type=AgentType.CUSTOM,
                config_path=sbom_file,
                source="sbom",
                mcp_servers=[sbom_server],
            )
            ctx.agents.append(sbom_agent)
        except (FileNotFoundError, ValueError) as e:
            con.print(f"\n  [red]SBOM error: {e}[/red]")
            sys.exit(1)

    # Step 1b2: Ingest external scanner report (--external-scan)
    if not skill_only and external_scan_path:
        import json as _json

        from agent_bom.models import Agent, AgentType, MCPServer, TransportType
        from agent_bom.parsers.external_scanners import detect_and_parse

        try:
            with open(external_scan_path) as _ext_f:
                _ext_data = _json.load(_ext_f)
            _ext_packages = detect_and_parse(_ext_data)
            _ext_resource_name = Path(external_scan_path).stem
            con.print(f"\n  [green]✓[/green] Ingested {len(_ext_packages)} packages from Trivy/Grype/Syft report\n")
            _ext_server = MCPServer(
                name=_ext_resource_name,
                command="external-scan",
                args=[external_scan_path],
                transport=TransportType.STDIO,
                packages=_ext_packages,
            )
            _ext_agent = Agent(
                name=f"external-scan:{_ext_resource_name}",
                agent_type=AgentType.CUSTOM,
                config_path=external_scan_path,
                source="external-scan",
                mcp_servers=[_ext_server],
            )
            ctx.agents.append(_ext_agent)
        except (FileNotFoundError, ValueError, _json.JSONDecodeError) as e:
            con.print(f"\n  [red]External scan error: {e}[/red]")
            sys.exit(1)

    # Step 1c: Discover K8s container images (--k8s)
    if not skill_only and k8s:
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
                kwargs["_images_updated"] = images
            else:
                con.print(f"  [dim]  No running pods found in {ns_label}[/dim]")
        except K8sDiscoveryError as e:
            con.print(f"\n  [red]K8s discovery error: {e}[/red]")
            sys.exit(1)

    # Step 1d: Scan Docker images (--image)
    if not skill_only and images:
        from agent_bom.image import ImageScanError, scan_image
        from agent_bom.models import Agent, AgentType, MCPServer, TransportType

        con.print(f"\n[bold blue]Scanning {len(images)} container image(s)...[/bold blue]\n")
        for image_ref in images:
            try:
                img_packages, strategy = scan_image(
                    image_ref,
                    registry_user=registry_user,
                    registry_pass=registry_pass,
                    platform=image_platform,
                )
                con.print(f"  [green]✓[/green] {image_ref}: {len(img_packages)} package(s) [dim](via {strategy})[/dim]")
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
                ctx.agents.append(image_agent)
            except ImageScanError as e:
                con.print(f"  [yellow]⚠[/yellow] {image_ref}: {e}")

    # Step 1d2: OCI tarball scan (--image-tar)
    if not skill_only and image_tars:
        from agent_bom.image import ImageScanError, scan_image_tar
        from agent_bom.models import Agent, AgentType, MCPServer, TransportType

        con.print(f"\n[bold blue]Scanning {len(image_tars)} OCI image tarball(s)...[/bold blue]\n")
        for tar_path in image_tars:
            try:
                tar_packages, tar_strategy = scan_image_tar(tar_path)
                tar_label = Path(tar_path).name
                con.print(f"  [green]✓[/green] {tar_label}: {len(tar_packages)} package(s) [dim](via {tar_strategy})[/dim]")
                server = MCPServer(
                    name=tar_label,
                    command="",
                    args=[],
                    transport=TransportType.STDIO,
                    packages=tar_packages,
                )
                tar_agent = Agent(
                    name=f"image-tar:{tar_label}",
                    agent_type=AgentType.CUSTOM,
                    config_path=f"oci-tar://{tar_path}",
                    mcp_servers=[server],
                )
                ctx.agents.append(tar_agent)
            except ImageScanError as e:
                con.print(f"  [yellow]⚠[/yellow] {tar_path}: {e}")

    # Step 1d3: Filesystem / disk snapshot scan (--filesystem)
    if not skill_only and filesystem_paths:
        from agent_bom.filesystem import FilesystemScanError, scan_filesystem
        from agent_bom.models import Agent, AgentType, MCPServer

        con.print(f"\n[bold blue]Scanning {len(filesystem_paths)} filesystem path(s) via Syft...[/bold blue]\n")
        for fs_path in filesystem_paths:
            try:
                fs_packages, fs_strategy = scan_filesystem(fs_path)
                con.print(f"  [green]v[/green] {fs_path}: {len(fs_packages)} package(s) [dim](via {fs_strategy})[/dim]")
                server = MCPServer(name=f"fs:{fs_path}")
                server.packages = fs_packages
                fs_agent = Agent(
                    name=f"filesystem:{Path(fs_path).name}",
                    agent_type=AgentType.CUSTOM,
                    config_path=fs_path,
                    source="filesystem",
                    mcp_servers=[server],
                )
                ctx.agents.append(fs_agent)
            except FilesystemScanError as e:
                con.print(f"  [yellow]![/yellow] {fs_path}: {e}")

    # Step 1d3a: Host OS package scan (--os-packages)
    if not skill_only and os_packages:
        from agent_bom.filesystem import scan_disk_path_native
        from agent_bom.models import Agent, AgentType, MCPServer

        con.print("\n[bold blue]Scanning host OS for installed system packages...[/bold blue]\n")
        os_pkgs = scan_disk_path_native(Path("/"))
        # Filter to only OS-level ecosystems (deb/rpm/apk)
        os_level_pkgs = [p for p in os_pkgs if p.ecosystem in ("deb", "rpm", "apk")]
        if os_level_pkgs:
            con.print(f"  [green]\u2713[/green] Found {len(os_level_pkgs)} OS package(s)")
            server = MCPServer(name="os-packages")
            server.packages = os_level_pkgs
            os_agent = Agent(
                name="os-packages",
                agent_type=AgentType.CUSTOM,
                config_path="/",
                source="os-packages",
                mcp_servers=[server],
            )
            ctx.agents.append(os_agent)
        else:
            con.print("  [dim]  No OS packages found (dpkg/rpm/apk)[/dim]")

    # Step 1d3: SAST code scan (--code)
    if not skill_only and code_paths:
        from agent_bom.models import Agent, AgentType, MCPServer
        from agent_bom.sast import SASTScanError, scan_code

        con.print(f"\n[bold blue]Running SAST scan on {len(code_paths)} path(s) via Semgrep...[/bold blue]\n")
        for code_path in code_paths:
            try:
                sast_packages, sast_result = scan_code(code_path, config=sast_config)
                con.print(
                    f"  [green]v[/green] {code_path}: {sast_result.total_findings} finding(s) "
                    f"in {sast_result.files_scanned} file(s) [dim]({sast_result.scan_time_seconds}s)[/dim]"
                )
                if sast_packages:
                    server = MCPServer(name=f"sast:{Path(code_path).name}")
                    server.packages = sast_packages
                    sast_agent = Agent(
                        name=f"code:{Path(code_path).name}",
                        agent_type=AgentType.CUSTOM,
                        config_path=code_path,
                        source="sast",
                        mcp_servers=[server],
                    )
                    ctx.agents.append(sast_agent)
                ctx.sast_data = sast_result.to_dict()
            except SASTScanError as e:
                con.print(f"  [yellow]![/yellow] {code_path}: {e}")

    # Step 1d3b: AI component source scan (--ai-inventory)
    ai_inventory_paths = kwargs.get("ai_inventory_paths", ())
    if not skill_only and ai_inventory_paths:
        from agent_bom.ai_components import scan_source
        from agent_bom.models import Agent, AgentType, MCPServer, Package

        # Collect manifest packages for shadow AI detection
        manifest_pkgs: set[str] = set()
        for ag in ctx.agents:
            for srv in ag.mcp_servers:
                for pkg in srv.packages:
                    manifest_pkgs.add(pkg.name)

        con.print(f"\n[bold blue]Scanning {len(ai_inventory_paths)} path(s) for AI components...[/bold blue]\n")
        ai_report = scan_source(*ai_inventory_paths, manifest_packages=manifest_pkgs)

        # Rich table for AI component findings (show critical/high/medium first, limit display)
        actionable = [c for c in ai_report.components if c.severity.value in ("critical", "high", "medium")]
        if actionable:
            from rich.panel import Panel as AiPanel
            from rich.table import Table as AiTable

            sev_colors = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "dim", "info": "dim"}
            sev_icons = {"critical": "\U0001f534", "high": "\U0001f7e0", "medium": "\U0001f7e1", "low": "\u26aa", "info": "\u26aa"}

            ai_table = AiTable(
                title=f"AI Component Inventory \u2014 {ai_report.total} components across {ai_report.files_scanned} files",
                expand=True,
                padding=(0, 1),
                title_style="bold cyan",
            )
            ai_table.add_column("Sev", justify="center", no_wrap=True, width=10)
            ai_table.add_column("Type", no_wrap=True, width=18)
            ai_table.add_column("Name", ratio=2)
            ai_table.add_column("File", ratio=2)
            ai_table.add_column("Lang", no_wrap=True, width=6)

            display_limit = 15
            for comp in actionable[:display_limit]:
                sev = comp.severity.value
                style = sev_colors.get(sev, "white")
                icon = sev_icons.get(sev, "\u26aa")
                sev_cell = f"{icon} [{style}]{sev.upper()}[/{style}]"
                type_label = comp.component_type.value.replace("_", " ")
                name_cell = f"[bold]{comp.name}[/bold]"
                if comp.is_shadow:
                    name_cell += " [yellow](shadow)[/yellow]"
                if comp.deprecated_replacement:
                    name_cell += f"\n[dim]\u2192 {comp.deprecated_replacement}[/dim]"
                file_cell = f"[dim]{comp.file_path}:{comp.line_number}[/dim]"
                ai_table.add_row(sev_cell, type_label, name_cell, file_cell, f"[cyan]{comp.language}[/cyan]")

            if len(actionable) > display_limit:
                ai_table.add_row("[dim]...[/dim]", "", f"[dim]+{len(actionable) - display_limit} more[/dim]", "", "")

            crit = sum(1 for c in ai_report.components if c.severity.value == "critical")
            high = sum(1 for c in ai_report.components if c.severity.value == "high")
            shadow = len(ai_report.shadow_ai)
            depr = len(ai_report.deprecated_models)
            keys = len(ai_report.api_keys)
            stats_parts = []
            if crit:
                stats_parts.append(f"[red bold]{crit} critical[/red bold]")
            if high:
                stats_parts.append(f"[red]{high} high[/red]")
            if shadow:
                stats_parts.append(f"[yellow]{shadow} shadow AI[/yellow]")
            if depr:
                stats_parts.append(f"{depr} deprecated")
            if keys:
                stats_parts.append(f"[red]{keys} hardcoded key(s)[/red]")
            stats = "[dim]" + " \u00b7 ".join(stats_parts) + "[/dim]" if stats_parts else ""
            con.print(AiPanel(ai_table, subtitle=stats, border_style="cyan"))
        else:
            sdks = sorted(ai_report.unique_sdks)
            models = sorted(ai_report.unique_models)
            sdk_str = ", ".join(sdks[:5]) + (f" +{len(sdks) - 5}" if len(sdks) > 5 else "") if sdks else "none"
            model_str = ", ".join(models[:4]) + (f" +{len(models) - 4}" if len(models) > 4 else "") if models else "none"
            con.print(
                f"  [green]\u2713[/green] {ai_report.files_scanned} files scanned \u2014 "
                f"[bold]{ai_report.total}[/bold] components, [green]all safe[/green]\n"
                f"    SDKs: [cyan]{sdk_str}[/cyan]\n"
                f"    Models: [cyan]{model_str}[/cyan]"
            )

        # Create synthetic packages for SDK components -> feed into CVE scanning
        ai_packages: list[Package] = []
        seen_pkgs: set[str] = set()
        for comp in ai_report.components:
            if comp.package_name and comp.ecosystem:
                pkg_key = f"{comp.ecosystem}:{comp.package_name}"
                if pkg_key not in seen_pkgs:
                    seen_pkgs.add(pkg_key)
                    ai_packages.append(Package(name=comp.package_name, version="latest", ecosystem=comp.ecosystem))

        if ai_packages:
            server = MCPServer(name="ai-inventory")
            server.packages = ai_packages
            ai_agent = Agent(
                name="ai-inventory",
                agent_type=AgentType.CUSTOM,
                config_path=str(ai_inventory_paths[0]),
                source="ai-inventory",
                mcp_servers=[server],
            )
            ctx.agents.append(ai_agent)

        ctx.ai_inventory_data = {
            "total_components": ai_report.total,
            "shadow_ai_count": len(ai_report.shadow_ai),
            "deprecated_models_count": len(ai_report.deprecated_models),
            "api_keys_count": len(ai_report.api_keys),
            "unique_sdks": sorted(ai_report.unique_sdks),
            "unique_models": sorted(ai_report.unique_models),
            "files_scanned": ai_report.files_scanned,
            "components": [
                {
                    "type": c.component_type.value,
                    # Redact credential fragments — never persist key material in report data
                    "name": "[REDACTED]" if c.component_type.value == "api_key" else c.name,
                    "language": c.language,
                    "file": c.file_path,
                    "line": c.line_number,
                    "severity": c.severity.value,
                    "is_shadow": c.is_shadow,
                    "package": c.package_name,
                    "ecosystem": c.ecosystem,
                    "description": c.description,
                    "deprecated_replacement": c.deprecated_replacement,
                }
                for c in ai_report.components
            ],
        }

    # Step 1d4: Project package scan fallback
    if not skill_only and project and not ctx.agents and not images and not code_paths and not sbom_file:
        from agent_bom.models import Agent, AgentType, MCPServer, TransportType
        from agent_bom.parsers import scan_project_directory

        proj_root = Path(project)
        con.print(f"\n[bold blue]Scanning project directory for package manifests: {proj_root.name}[/bold blue]\n")
        dir_map = scan_project_directory(proj_root)
        if dir_map:
            total_proj_pkgs = sum(len(v) for v in dir_map.values())
            con.print(f"  [green]✓[/green] {proj_root.name}: {total_proj_pkgs} package(s) across {len(dir_map)} manifest(s)")

            proj_servers: list[MCPServer] = []
            for manifest_dir, pkgs in dir_map.items():
                rel = manifest_dir.relative_to(proj_root) if manifest_dir != proj_root else Path(".")
                server_name = str(rel) if str(rel) != "." else proj_root.name
                proj_server = MCPServer(
                    name=server_name,
                    command="project",
                    args=[str(manifest_dir)],
                    transport=TransportType.STDIO,
                    packages=pkgs,
                )
                proj_servers.append(proj_server)

            proj_agent = Agent(
                name=f"project:{proj_root.name}",
                agent_type=AgentType.CUSTOM,
                config_path=str(proj_root),
                source="project",
                mcp_servers=proj_servers,
            )
            ctx.agents.append(proj_agent)
        else:
            con.print(f"  [dim]  No package manifests found in {proj_root}[/dim]")

    # Step 1e: Terraform scan (--tf-dir)
    if not skill_only and tf_dirs:
        from agent_bom.terraform import scan_terraform_dir

        con.print(f"\n[bold blue]Scanning {len(tf_dirs)} Terraform director{'ies' if len(tf_dirs) > 1 else 'y'}...[/bold blue]\n")
        for tf_dir in tf_dirs:
            tf_agents, tf_warnings = scan_terraform_dir(tf_dir)
            for w in tf_warnings:
                con.print(f"  [yellow]⚠[/yellow] {w}")
            if tf_agents:
                ai_resource_count = sum(len(a.mcp_servers) for a in tf_agents)
                pkg_count = sum(a.total_packages for a in tf_agents)
                con.print(
                    f"  [green]✓[/green] {tf_dir}: "
                    f"{len(tf_agents)} AI service(s), {ai_resource_count} server(s), "
                    f"{pkg_count} provider package(s)"
                )
                ctx.agents.extend(tf_agents)
            else:
                con.print(f"  [dim]  {tf_dir}: no AI resources or providers found[/dim]")

    # Step 1f: GitHub Actions scan (--gha)
    if not skill_only and gha_path:
        from agent_bom.github_actions import scan_github_actions

        con.print(f"\n[bold blue]Scanning GitHub Actions workflows in {gha_path}...[/bold blue]\n")
        gha_agents, gha_warnings = scan_github_actions(gha_path)
        for w in gha_warnings:
            con.print(f"  [yellow]⚠[/yellow] {w}")
        if gha_agents:
            cred_count = sum(len(s.credential_names) for a in gha_agents for s in a.mcp_servers)
            con.print(f"  [green]✓[/green] {len(gha_agents)} workflow(s) with AI usage, {cred_count} credential(s) detected")
            ctx.agents.extend(gha_agents)
        else:
            con.print("  [dim]  No AI-using workflows found[/dim]")

    # Step 1g: Python agent framework scan (--agent-project)
    if not skill_only and agent_projects:
        from agent_bom.python_agents import scan_python_agents

        for ap in agent_projects:
            con.print(f"\n[bold blue]Scanning Python agent project: {ap}...[/bold blue]\n")
            ap_agents, ap_warnings = scan_python_agents(ap)
            for w in ap_warnings:
                con.print(f"  [yellow]⚠[/yellow] {w}")
            if ap_agents:
                tool_count = sum(len(s.tools) for a in ap_agents for s in a.mcp_servers)
                pkg_count = sum(len(s.packages) for a in ap_agents for s in a.mcp_servers)
                con.print(f"  [green]✓[/green] {len(ap_agents)} agent(s) found, {tool_count} tool(s), {pkg_count} package(s) to scan")
                ctx.agents.extend(ap_agents)
            else:
                con.print("  [dim]  No agent framework usage detected[/dim]")

    # Step 1g2: Skill file scanning (--skill + auto-discovery)
    _skill_result_obj = None
    _skill_audit_obj = None

    if not no_skill:
        from agent_bom.parsers.skills import discover_skill_files, scan_skill_files

        skill_file_list: list[Path] = []
        for sp in skill_paths:
            p = Path(sp)
            if p.is_dir():
                skill_file_list.extend(discover_skill_files(p))
            else:
                skill_file_list.append(p)
        # Auto-discover skill files in project directory
        search_dir = Path(project) if project else Path.cwd()
        auto_skills = discover_skill_files(search_dir)
        for sf in auto_skills:
            if sf not in skill_file_list:
                skill_file_list.append(sf)

        if skill_file_list:
            skill_result = scan_skill_files(skill_file_list)
            if skill_result.servers or skill_result.packages or skill_result.credential_env_vars:
                con.print(f"\n[bold blue]Scanning {len(skill_file_list)} skill file(s)...[/bold blue]\n")
                if verbose:
                    for sf in skill_file_list:
                        con.print(f"  [dim]•[/dim] {sf.name}  [dim]{sf.parent}[/dim]")
                if skill_result.servers:
                    from agent_bom.models import Agent, AgentType

                    skill_agent = Agent(
                        name="skill-files",
                        agent_type=AgentType.CUSTOM,
                        config_path=str(skill_file_list[0]),
                        mcp_servers=skill_result.servers,
                    )
                    ctx.agents.append(skill_agent)
                    con.print(f"  [green]✓[/green] Found {len(skill_result.servers)} MCP server(s) in skill files")
                if skill_result.packages:
                    from agent_bom.models import Agent, AgentType
                    from agent_bom.models import MCPServer as _SkillSrv

                    skill_server = _SkillSrv(name="skill-packages", command="(from skill files)", packages=skill_result.packages)
                    skill_pkg_agent = Agent(
                        name="skill-packages",
                        agent_type=AgentType.CUSTOM,
                        config_path=", ".join(str(p) for p in skill_file_list[:3]),
                        mcp_servers=[skill_server],
                    )
                    ctx.agents.append(skill_pkg_agent)
                    con.print(f"  [green]✓[/green] Found {len(skill_result.packages)} package(s) referenced in skill files")
                if skill_result.credential_env_vars:
                    con.print(
                        f"  [yellow]⚠[/yellow] {len(skill_result.credential_env_vars)} credential env var(s) referenced in skill files"
                    )

                # Step 1g3: Skill security audit
                from agent_bom.parsers.skill_audit import audit_skill_result

                skill_audit = audit_skill_result(skill_result)
                _skill_result_obj = skill_result
                _skill_audit_obj = skill_audit
                ctx.skill_audit_data = {
                    "findings": [
                        {
                            "severity": f.severity,
                            "category": f.category,
                            "title": f.title,
                            "detail": f.detail,
                            "source_file": f.source_file,
                            "package": f.package,
                            "server": f.server,
                            "recommendation": f.recommendation,
                            "context": f.context,
                        }
                        for f in skill_audit.findings
                    ],
                    "packages_checked": skill_audit.packages_checked,
                    "servers_checked": skill_audit.servers_checked,
                    "credentials_checked": skill_audit.credentials_checked,
                    "passed": skill_audit.passed,
                }
                if skill_audit.findings:
                    from rich.panel import Panel
                    from rich.table import Table as RichTable

                    sev_colors = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "dim"}
                    sev_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}

                    audit_table = RichTable(
                        title=f"Skill Security Audit — {len(skill_audit.findings)} finding(s)",
                        expand=True,
                        padding=(0, 1),
                        title_style="bold yellow",
                    )
                    audit_table.add_column("Sev", justify="center", no_wrap=True, width=10)
                    audit_table.add_column("Category", no_wrap=True, width=20)
                    audit_table.add_column("Finding", ratio=3)
                    audit_table.add_column("Source", ratio=2, style="dim")

                    for finding in skill_audit.findings:
                        style = sev_colors.get(finding.severity, "white")
                        icon = sev_icons.get(finding.severity, "⚪")
                        sev_cell = f"{icon} [{style}]{finding.severity.upper()}[/{style}]"
                        cat_cell = f"[cyan]{finding.category}[/cyan]"
                        detail_parts = [f"[bold]{finding.title}[/bold]"]
                        detail_parts.append(f"[dim]{finding.detail}[/dim]")
                        if finding.recommendation:
                            detail_parts.append(f"[green]→ {finding.recommendation}[/green]")
                        detail_cell = "\n".join(detail_parts)
                        source_parts = []
                        if finding.source_file:
                            source_parts.append(Path(finding.source_file).name)
                        if finding.package:
                            source_parts.append(f"pkg:{finding.package}")
                        if finding.server:
                            source_parts.append(f"srv:{finding.server}")
                        source_cell = "\n".join(source_parts) if source_parts else "—"
                        audit_table.add_row(sev_cell, cat_cell, detail_cell, source_cell)

                    stats_line = (
                        f"[dim]Checked: {skill_audit.packages_checked} pkg(s) · "
                        f"{skill_audit.servers_checked} server(s) · "
                        f"{skill_audit.credentials_checked} credential(s) · "
                        f"{'[green]PASS[/green]' if skill_audit.passed else '[red]FAIL[/red]'}[/dim]"
                    )
                    con.print()
                    con.print(Panel(audit_table, subtitle=stats_line, border_style="yellow"))

    # Step 1g4: Trust assessment (ClawHub-style)
    if _skill_result_obj and _skill_audit_obj:
        from agent_bom.parsers.trust_assessment import TrustLevel, Verdict, assess_trust

        trust_result = assess_trust(_skill_result_obj, _skill_audit_obj)
        ctx.trust_assessment_data = trust_result.to_dict()

        verdict_styles = {
            Verdict.BENIGN: "green",
            Verdict.SUSPICIOUS: "yellow",
            Verdict.MALICIOUS: "red bold",
        }
        vstyle = verdict_styles.get(trust_result.verdict, "white")

        if verbose:
            from rich.panel import Panel as TrustPanel
            from rich.table import Table as TrustTable

            level_icons = {
                TrustLevel.PASS: "[green]✓[/green]",
                TrustLevel.INFO: "[blue]ℹ[/blue]",
                TrustLevel.WARN: "[yellow]⚠[/yellow]",
                TrustLevel.FAIL: "[red]✗[/red]",
            }
            trust_table = TrustTable(expand=True, padding=(0, 1), show_header=True)
            trust_table.add_column("", justify="center", no_wrap=True, width=3)
            trust_table.add_column("Category", no_wrap=True, width=24)
            trust_table.add_column("Summary", ratio=3)

            for cat in trust_result.categories:
                icon = level_icons.get(cat.level, "?")
                trust_table.add_row(icon, f"[bold]{cat.name}[/bold]", cat.summary)

            verdict_line = f"[{vstyle}]{trust_result.verdict.value.upper()}[/{vstyle}] ({trust_result.confidence.value} confidence)"
            con.print()
            con.print(
                TrustPanel(
                    trust_table,
                    title=f"[bold]Trust Assessment — {Path(trust_result.source_file).name}[/bold]",
                    subtitle=verdict_line,
                    border_style=vstyle,
                )
            )

            if trust_result.recommendations:
                for rec in trust_result.recommendations:
                    con.print(f"  [dim]→ {rec}[/dim]")
        else:
            fail_count = sum(1 for c in trust_result.categories if c.level == TrustLevel.FAIL)
            warn_count = sum(1 for c in trust_result.categories if c.level == TrustLevel.WARN)
            fname = Path(trust_result.source_file).name
            verdict_text = f"[{vstyle}]{trust_result.verdict.value.upper()}[/{vstyle}]"
            issues = []
            if fail_count:
                issues.append(f"[red]{fail_count} fail[/red]")
            if warn_count:
                issues.append(f"[yellow]{warn_count} warn[/yellow]")
            issues_str = f" ({', '.join(issues)})" if issues else ""
            con.print(f"  Trust: {fname} → {verdict_text}{issues_str}")

    # Preserve skill objects on context for AI enrichment later
    ctx._skill_result_obj = _skill_result_obj
    ctx._skill_audit_obj = _skill_audit_obj

    # Step 1g3b: Prompt template scanning (--scan-prompts)
    if scan_prompts:
        from agent_bom.parsers.prompt_scanner import scan_prompt_files

        search_dir = Path(project) if project else Path.cwd()
        prompt_result = scan_prompt_files(root=search_dir)
        if prompt_result.files_scanned > 0:
            con.print(f"\n[bold blue]Scanned {prompt_result.files_scanned} prompt template file(s)...[/bold blue]\n")
            for pf in prompt_result.prompt_files:
                con.print(f"  [dim]•[/dim] {Path(pf).name}")
            ctx.prompt_scan_data = {
                "files_scanned": prompt_result.files_scanned,
                "prompt_files": prompt_result.prompt_files,
                "findings": [
                    {
                        "severity": f.severity,
                        "category": f.category,
                        "title": f.title,
                        "detail": f.detail,
                        "source_file": f.source_file,
                        "line_number": f.line_number,
                        "matched_text": f.matched_text,
                        "recommendation": f.recommendation,
                    }
                    for f in prompt_result.findings
                ],
                "passed": prompt_result.passed,
            }
            if prompt_result.findings:
                from rich.panel import Panel
                from rich.table import Table as RichTable

                sev_colors = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "dim"}
                sev_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}

                prompt_table = RichTable(
                    title=f"Prompt Template Security Scan — {len(prompt_result.findings)} finding(s)",
                    expand=True,
                    padding=(0, 1),
                    title_style="bold magenta",
                )
                prompt_table.add_column("Sev", justify="center", no_wrap=True, width=10)
                prompt_table.add_column("Category", no_wrap=True, width=20)
                prompt_table.add_column("Finding", ratio=3)
                prompt_table.add_column("File", ratio=2, style="dim")

                for prompt_finding in prompt_result.findings:
                    style = sev_colors.get(prompt_finding.severity, "white")
                    icon = sev_icons.get(prompt_finding.severity, "⚪")
                    sev_cell = f"{icon} [{style}]{prompt_finding.severity.upper()}[/{style}]"
                    cat_cell = f"[cyan]{prompt_finding.category}[/cyan]"
                    detail_parts = [f"[bold]{prompt_finding.title}[/bold]"]
                    detail_parts.append(f"[dim]{prompt_finding.detail}[/dim]")
                    if prompt_finding.recommendation:
                        detail_parts.append(f"[green]→ {prompt_finding.recommendation}[/green]")
                    detail_cell = "\n".join(detail_parts)
                    file_info = Path(prompt_finding.source_file).name
                    if prompt_finding.line_number:
                        file_info += f":{prompt_finding.line_number}"
                    prompt_table.add_row(sev_cell, cat_cell, detail_cell, file_info)

                stats_line = (
                    f"[dim]{prompt_result.files_scanned} file(s) scanned · "
                    f"{'[green]PASS[/green]' if prompt_result.passed else '[red]FAIL[/red]'}[/dim]"
                )
                con.print()
                con.print(Panel(prompt_table, subtitle=stats_line, border_style="magenta"))
            else:
                con.print("  [green]✓[/green] No security issues found in prompt templates")

    # Step 1g3c: Browser extension scanning (--browser-extensions)
    if browser_extensions:
        from agent_bom.parsers.browser_extensions import discover_browser_extensions

        con.print("\n[bold blue]Scanning browser extensions...[/bold blue]\n")
        br_exts = discover_browser_extensions(include_low_risk=False)
        if br_exts:
            from rich.panel import Panel
            from rich.table import Table as RichTable

            sev_colors = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "dim"}
            sev_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}

            br_table = RichTable(
                title=f"Browser Extension Security Scan — {len(br_exts)} medium+ risk extension(s)",
                expand=True,
                padding=(0, 1),
                title_style="bold magenta",
            )
            br_table.add_column("Risk", justify="center", no_wrap=True, width=10)
            br_table.add_column("Browser", no_wrap=True, width=10)
            br_table.add_column("Extension", ratio=2)
            br_table.add_column("Findings", ratio=4)

            for ext in br_exts:
                style = sev_colors.get(ext.risk_level, "white")
                icon = sev_icons.get(ext.risk_level, "⚪")
                risk_cell = f"{icon} [{style}]{ext.risk_level.upper()}[/{style}]"
                browser_cell = f"[cyan]{ext.browser}[/cyan]"
                name_cell = f"[bold]{ext.name}[/bold]\n[dim]{ext.version}[/dim]"
                findings_cell = "\n".join(f"[dim]• {r}[/dim]" for r in ext.risk_reasons[:4])
                if len(ext.risk_reasons) > 4:
                    findings_cell += f"\n[dim]  (+{len(ext.risk_reasons) - 4} more)[/dim]"
                br_table.add_row(risk_cell, browser_cell, name_cell, findings_cell)

            crit_count = sum(1 for e in br_exts if e.risk_level == "critical")
            high_count = sum(1 for e in br_exts if e.risk_level == "high")
            stats = f"[dim]{crit_count} critical · {high_count} high · scan complete[/dim]"
            con.print(Panel(br_table, subtitle=stats, border_style="magenta"))
        else:
            con.print("  [green]✓[/green] No medium+ risk browser extensions found")

        ctx._browser_ext_results = {
            "extensions": [e.to_dict() for e in br_exts],
            "total": len(br_exts),
            "critical_count": sum(1 for e in br_exts if e.risk_level == "critical"),
            "high_count": sum(1 for e in br_exts if e.risk_level == "high"),
        }

    # Step 1g4: Jupyter notebook scan (--jupyter)
    if not skill_only and jupyter_dirs:
        from agent_bom.jupyter import scan_jupyter_notebooks

        for jdir in jupyter_dirs:
            con.print(f"\n[bold blue]Scanning Jupyter notebooks in {jdir}...[/bold blue]\n")
            j_agents, j_warnings = scan_jupyter_notebooks(jdir)
            for w in j_warnings:
                con.print(f"  [yellow]⚠[/yellow] {w}")
            if j_agents:
                pkg_count = sum(len(s.packages) for a in j_agents for s in a.mcp_servers)
                con.print(f"  [green]✓[/green] {len(j_agents)} notebook(s) with AI libraries found, {pkg_count} package(s) to scan")
                ctx.agents.extend(j_agents)
            else:
                con.print("  [dim]  No AI library usage detected in notebooks[/dim]")

    # Step 1g5: IaC misconfiguration scan (--iac)
    if not skill_only and iac_paths:
        from agent_bom.iac import scan_iac_directory

        con.print(f"\n[bold blue]Scanning {len(iac_paths)} path(s) for IaC misconfigurations...[/bold blue]\n")
        all_iac_findings: list = []
        for iac_path in iac_paths:
            iac_findings = scan_iac_directory(iac_path)
            all_iac_findings.extend(iac_findings)
            if iac_findings:
                by_sev: dict[str, int] = {}
                for f in iac_findings:
                    by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
                sev_parts = []
                for sev in ("critical", "high", "medium", "low"):
                    if sev in by_sev:
                        sev_colors = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "dim"}
                        style = sev_colors.get(sev, "white")
                        sev_parts.append(f"[{style}]{by_sev[sev]} {sev}[/{style}]")
                con.print(f"  [green]\u2713[/green] {iac_path}: {len(iac_findings)} finding(s) ({', '.join(sev_parts)})")
            else:
                con.print(f"  [dim]  {iac_path}: no misconfigurations found[/dim]")

        if all_iac_findings:
            from rich.panel import Panel
            from rich.table import Table as IaCTable

            sev_colors = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "dim"}
            sev_icons = {"critical": "\U0001f534", "high": "\U0001f7e0", "medium": "\U0001f7e1", "low": "\u26aa"}

            iac_table = IaCTable(
                title=f"IaC Misconfigurations \u2014 {len(all_iac_findings)} finding(s)",
                expand=True,
                padding=(0, 1),
                title_style="bold cyan",
            )
            iac_table.add_column("Sev", justify="center", no_wrap=True, width=10)
            iac_table.add_column("Rule", no_wrap=True, width=12)
            iac_table.add_column("Finding", ratio=3)
            iac_table.add_column("File", ratio=2, style="dim")

            display_limit = 20
            for iac_f in all_iac_findings[:display_limit]:
                sev = iac_f.severity
                style = sev_colors.get(sev, "white")
                icon = sev_icons.get(sev, "\u26aa")
                sev_cell = f"{icon} [{style}]{sev.upper()}[/{style}]"
                rule_cell = f"[cyan]{iac_f.rule_id}[/cyan]"
                detail_parts = [f"[bold]{iac_f.title}[/bold]"]
                detail_parts.append(f"[dim]{iac_f.message}[/dim]")
                detail_cell = "\n".join(detail_parts)
                file_cell = f"{Path(iac_f.file_path).name}:{iac_f.line_number}"
                iac_table.add_row(sev_cell, rule_cell, detail_cell, file_cell)

            if len(all_iac_findings) > display_limit:
                iac_table.add_row("[dim]...[/dim]", "", f"[dim]+{len(all_iac_findings) - display_limit} more[/dim]", "")

            crit = sum(1 for f in all_iac_findings if f.severity == "critical")
            high = sum(1 for f in all_iac_findings if f.severity == "high")
            stats = f"[dim]{crit} critical \u00b7 {high} high \u00b7 scan complete[/dim]"
            con.print()
            con.print(Panel(iac_table, subtitle=stats, border_style="cyan"))

        ctx.iac_findings_data = {
            "total": len(all_iac_findings),
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "title": f.title,
                    "message": f.message,
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "category": f.category,
                    "compliance": f.compliance,
                }
                for f in all_iac_findings
            ],
        }
