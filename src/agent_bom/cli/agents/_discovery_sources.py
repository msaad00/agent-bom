"""Discovery stages that turn local inputs (configs, SBOMs, images, paths) into agents."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import click
from rich.rule import Rule

from agent_bom.cli.agents._discovery_state import DiscoveryRun
from agent_bom.inventory import build_agents_from_inventory
from agent_bom.models import Agent, AgentType, MCPServer, ServerSurface, TransportType


def _inventory_label(inventory: str) -> str:
    if inventory == "-":
        return "stdin"
    if "agent-bom-demo-" in inventory:
        return "curated sample environment"
    if "agent-bom-self-scan" in inventory:
        return "self-scan"
    return inventory


def load_inventory_file(run: DiscoveryRun) -> None:
    """Preload ``--inventory`` so a bad file fails as a parameter error."""
    if not run.inventory:
        return
    run.inventory_label = _inventory_label(run.inventory)
    from agent_bom.inventory import load_inventory

    try:
        run.preloaded_inventory = load_inventory(run.inventory)
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        raise click.BadParameter(str(exc), param_hint="--inventory") from exc


def print_discovery_header(run: DiscoveryRun) -> None:
    run.con.print(Rule("Discovery", style="blue"))


def _discover_from(run: DiscoveryRun, project_dir: Any) -> Any:
    with run.con.status("[bold]Discovering agents and MCP servers...[/bold]", spinner="dots"):
        return run.discover(
            project_dir=project_dir,
            dynamic=run.dynamic_discovery,
            dynamic_max_depth=run.dynamic_max_depth,
            include_processes=run.include_processes,
            include_containers=run.include_containers,
            include_k8s_mcp=run.k8s_mcp,
            k8s_namespace=run.k8s_namespace,
            k8s_all_namespaces=run.k8s_all_namespaces,
            k8s_context=run.k8s_mcp_context,
        )


def discover_agents(run: DiscoveryRun) -> None:
    """Step 1: agents from inventory, a config directory, or ambient discovery."""
    ctx, con = run.ctx, run.con
    if run.skill_only:
        ctx.agents = []  # skill-only: no agent discovery
    elif run.inventory:
        ctx.agents = build_agents_from_inventory(run.preloaded_inventory or {"agents": []}, run.inventory)
        con.print(f"\n  [green]✓[/green] {len(ctx.agents)} agent(s) from {run.inventory_label or run.inventory}")
    elif run.no_discover and not run.config_dir:
        # --config-dir is an explicit artifact; it survives --no-discover.
        ctx.agents = []
    elif run.config_dir:
        con.print(f"\n[bold blue]Scanning config directory: {run.config_dir}...[/bold blue]\n")
        ctx.agents = _discover_from(run, run.config_dir)
    elif run.sbom_file or run.filesystem_paths or run.images:
        # Skip MCP auto-discovery when scanning a specific target
        # (SBOM, filesystem, or image) — saves ~3s startup
        ctx.agents = []
    else:
        ctx.agents = _discover_from(run, run.project)


def load_sbom(run: DiscoveryRun) -> None:
    """Step 1b: load SBOM packages if provided."""
    if run.skill_only or not run.sbom_file:
        return
    from agent_bom.parsers.sbom_context import load_sbom_agents

    con = run.con
    try:
        sbom_agents, sbom_fmt = load_sbom_agents(run.sbom_file, run.sbom_name)
        count = sum(len(server.packages) for agent in sbom_agents for server in agent.mcp_servers)
        target = run.sbom_name or Path(run.sbom_file).name
        con.print(f"\n[bold blue]Loaded SBOM ({sbom_fmt}): {count} package(s) from '{target}'[/bold blue]\n")
        run.ctx.agents.extend(sbom_agents)
    except json.JSONDecodeError:
        con.print("\n  [red]SBOM error: input is not valid JSON.[/red]")
        sys.exit(1)
    except (FileNotFoundError, ValueError) as e:
        con.print(f"\n  [red]SBOM error: {e}[/red]")
        sys.exit(1)


def ingest_external_scan(run: DiscoveryRun) -> None:
    """Step 1b2: ingest an external scanner report (--external-scan)."""
    if run.skill_only or not run.external_scan_path:
        return
    from agent_bom.parsers.external_import import build_external_agent
    from agent_bom.parsers.external_scanners import load_external_report

    con, ctx = run.con, run.ctx
    try:
        _ext_import = load_external_report(run.external_scan_path)
        con.print(
            f"\n  [green]✓[/green] Ingested external {_ext_import.format} report: "
            f"{len(_ext_import.packages)} package(s), {len(_ext_import.findings)} code/unresolved finding(s)\n"
        )
        for _notice in _ext_import.notices:
            con.print(f"  [yellow]![/yellow] {_notice}")
            ctx.scan_notices.append({"code": "external_scan_routed", "source": "external-scan", "message": _notice})
        ctx.agents.append(build_external_agent(_ext_import, run.external_scan_path))
        ctx.external_findings.extend(_ext_import.findings)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as e:
        con.print(f"\n  [red]External scan error: {e}[/red]")
        sys.exit(1)


def discover_k8s_images(run: DiscoveryRun) -> None:
    """Step 1c: discover container images running in Kubernetes (--k8s)."""
    if run.skill_only or not run.k8s:
        return
    from agent_bom.k8s import K8sDiscoveryError, discover_images

    con = run.con
    ns_label = "all namespaces" if run.all_namespaces else f"namespace '{run.namespace}'"
    con.print(f"\n[bold blue]Discovering container images from Kubernetes ({ns_label})...[/bold blue]\n")
    try:
        k8s_records = discover_images(
            namespace=run.namespace,
            all_namespaces=run.all_namespaces,
            context=run.k8s_context,
        )
        if k8s_records:
            con.print(f"  [green]✓[/green] Found {len(k8s_records)} unique image(s) across pods")
            extra_images = list(run.images) + [img for img, _pod, _ctr in k8s_records]
            run.images = tuple(dict.fromkeys(extra_images))  # deduplicate, preserve order
            run.extra["_images_updated"] = run.images
        else:
            con.print(f"  [dim]  No running pods found in {ns_label}[/dim]")
    except K8sDiscoveryError as e:
        con.print(f"\n  [red]K8s discovery error: {e}[/red]")
        sys.exit(1)


def scan_container_images(run: DiscoveryRun) -> None:
    """Step 1d: scan container images (--image)."""
    if run.skill_only or not run.images:
        return
    from agent_bom.image import ImageScanError, scan_image

    con = run.con
    con.print(f"\n[bold blue]Scanning {len(run.images)} container image(s)...[/bold blue]\n")
    image_successes = 0
    for image_ref in run.images:
        try:
            img_packages, strategy = scan_image(
                image_ref,
                registry_user=run.registry_user,
                registry_pass=run.registry_pass,
                platform=run.image_platform,
            )
            con.print(f"  [green]✓[/green] {image_ref}: {len(img_packages)} package(s) [dim](via {strategy})[/dim]")
            server = MCPServer(
                name=image_ref,
                command="docker",
                args=["run", image_ref],
                transport=TransportType.STDIO,
                packages=img_packages,
                surface=ServerSurface.CONTAINER_IMAGE,
            )
            image_agent = Agent(
                name=f"image:{image_ref}",
                agent_type=AgentType.CUSTOM,
                config_path=f"docker://{image_ref}",
                source="image",
                mcp_servers=[server],
            )
            run.ctx.agents.append(image_agent)
            image_successes += 1
        except ImageScanError as e:
            con.print(f"  [yellow]⚠[/yellow] {image_ref}: {e}")
    if run.extra.get("_image_only") and image_successes == 0:
        con.print("\n  [red]Image scan failed: native package extraction produced no usable inventory[/red]")
        sys.exit(1)


def scan_image_tarballs(run: DiscoveryRun) -> None:
    """Step 1d2: OCI tarball scan (--image-tar)."""
    if run.skill_only or not run.image_tars:
        return
    from agent_bom.image import ImageScanError, scan_image_tar

    con = run.con
    con.print(f"\n[bold blue]Scanning {len(run.image_tars)} OCI image tarball(s)...[/bold blue]\n")
    for tar_path in run.image_tars:
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
                surface=ServerSurface.OCI_TARBALL,
            )
            tar_agent = Agent(
                name=f"image-tar:{tar_label}",
                agent_type=AgentType.CUSTOM,
                config_path=f"oci-tar://{tar_path}",
                source="image-tar",
                mcp_servers=[server],
            )
            run.ctx.agents.append(tar_agent)
        except ImageScanError as e:
            con.print(f"  [yellow]⚠[/yellow] {tar_path}: {e}")


def _discover_filesystem_mcps(run: DiscoveryRun, fs_path: str) -> None:
    # Auto-discover MCP configs inside directory (VM snapshots, mounts)
    fs_dir = Path(fs_path)
    if fs_dir.is_dir() and not run.no_discover:
        from agent_bom.discovery import discover_filesystem_mcps

        fs_mcp_agents = discover_filesystem_mcps(fs_dir)
        if fs_mcp_agents:
            run.con.print(f"  [green]✓[/green] Discovered {len(fs_mcp_agents)} MCP agent(s) inside {fs_path}")
            run.ctx.agents.extend(fs_mcp_agents)


def scan_filesystems(run: DiscoveryRun) -> None:
    """Step 1d3: filesystem / disk snapshot scan (--filesystem)."""
    if run.skill_only or not run.filesystem_paths:
        return
    from agent_bom.filesystem import FilesystemScanError, scan_filesystem

    con = run.con
    con.print(f"\n[bold blue]Scanning {len(run.filesystem_paths)} filesystem path(s)...[/bold blue]\n")
    for fs_path in run.filesystem_paths:
        try:
            fs_packages, fs_strategy = scan_filesystem(fs_path)
            con.print(f"  [green]✓[/green] {fs_path}: {len(fs_packages)} package(s) [dim](via {fs_strategy})[/dim]")
            server = MCPServer(name=f"fs:{fs_path}", surface=ServerSurface.FILESYSTEM)
            server.packages = fs_packages
            fs_agent = Agent(
                name=f"filesystem:{Path(fs_path).name}",
                agent_type=AgentType.CUSTOM,
                config_path=fs_path,
                source="filesystem",
                mcp_servers=[server],
            )
            run.ctx.agents.append(fs_agent)
        except FilesystemScanError as e:
            con.print(f"  [yellow]![/yellow] {fs_path}: {e}")
        _discover_filesystem_mcps(run, fs_path)


def scan_host_os_packages(run: DiscoveryRun) -> None:
    """Step 1d3a: host OS package scan (--os-packages)."""
    if run.skill_only or not run.os_packages:
        return
    from agent_bom.parsers.os_parsers import scan_os_packages

    con = run.con
    con.print("\n[bold blue]Scanning host OS for installed system packages...[/bold blue]\n")
    # scan_os_packages: tries live commands (dpkg-query/rpm/apk) first, falls back to files
    os_level_pkgs = scan_os_packages(Path("/"))
    if os_level_pkgs:
        con.print(f"  [green]✓[/green] Found {len(os_level_pkgs)} OS package(s)")
        server = MCPServer(name="os-packages", surface=ServerSurface.OS_PACKAGES)
        server.packages = os_level_pkgs
        os_agent = Agent(
            name="os-packages",
            agent_type=AgentType.CUSTOM,
            config_path="/",
            source="os-packages",
            mcp_servers=[server],
        )
        run.ctx.agents.append(os_agent)
    else:
        con.print("  [dim]  No OS packages found (dpkg/rpm/apk)[/dim]")


def scan_terraform(run: DiscoveryRun) -> None:
    """Step 1e: Terraform scan (--tf-dir)."""
    if run.skill_only or not run.tf_dirs:
        return
    from agent_bom.terraform import scan_terraform_dir

    con, tf_dirs = run.con, run.tf_dirs
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
            run.ctx.agents.extend(tf_agents)
        else:
            con.print(f"  [dim]  {tf_dir}: no AI resources or providers found[/dim]")


def scan_github_actions(run: DiscoveryRun) -> None:
    """Step 1f: GitHub Actions scan (--gha)."""
    if run.skill_only or not run.gha_path:
        return
    from agent_bom.github_actions import attach_github_action_packages, discover_github_action_packages
    from agent_bom.github_actions import scan_github_actions as _scan_workflows

    con, gha_path = run.con, run.gha_path
    con.print(f"\n[bold blue]Scanning GitHub Actions workflows in {gha_path}...[/bold blue]\n")
    gha_agents, gha_warnings = _scan_workflows(gha_path)
    gha_packages = discover_github_action_packages(gha_path)
    for w in gha_warnings:
        con.print(f"  [yellow]⚠[/yellow] {w}")
    if gha_agents or gha_packages:
        cred_count = sum(len(s.credential_names) for a in gha_agents for s in a.mcp_servers)
        con.print(
            f"  [green]✓[/green] {len(gha_agents)} workflow(s) with AI usage, "
            f"{len(gha_packages)} action/reusable-workflow dependency(ies), "
            f"{cred_count} credential(s) detected"
        )
        run.ctx.agents.extend(gha_agents)
        attach_github_action_packages(run.ctx.agents, gha_path, gha_packages)
    else:
        con.print("  [dim]  No remote action dependencies or AI-using workflows found[/dim]")


def scan_agent_projects(run: DiscoveryRun) -> None:
    """Step 1g: Python agent framework scan (--agent-project)."""
    if run.skill_only or not run.agent_projects:
        return
    from agent_bom.python_agents import scan_python_agents

    con = run.con
    for ap in run.agent_projects:
        con.print(f"\n[bold blue]Scanning Python agent project: {ap}...[/bold blue]\n")
        ap_agents, ap_warnings = scan_python_agents(ap)
        for w in ap_warnings:
            con.print(f"  [yellow]⚠[/yellow] {w}")
        if ap_agents:
            tool_count = sum(len(s.tools) for a in ap_agents for s in a.mcp_servers)
            pkg_count = sum(len(s.packages) for a in ap_agents for s in a.mcp_servers)
            con.print(f"  [green]✓[/green] {len(ap_agents)} agent(s) found, {tool_count} tool(s), {pkg_count} package(s) to scan")
            run.ctx.agents.extend(ap_agents)
        else:
            con.print("  [dim]  No agent framework usage detected[/dim]")


def scan_jupyter(run: DiscoveryRun) -> None:
    """Step 1g4: Jupyter notebook scan (--jupyter)."""
    if run.skill_only or not run.jupyter_dirs:
        return
    from agent_bom.jupyter import scan_jupyter_notebooks

    con = run.con
    for jdir in run.jupyter_dirs:
        con.print(f"\n[bold blue]Scanning Jupyter notebooks in {jdir}...[/bold blue]\n")
        j_agents, j_warnings = scan_jupyter_notebooks(jdir)
        for w in j_warnings:
            con.print(f"  [yellow]⚠[/yellow] {w}")
        if j_agents:
            pkg_count = sum(len(s.packages) for a in j_agents for s in a.mcp_servers)
            con.print(f"  [green]✓[/green] {len(j_agents)} notebook(s) with AI libraries found, {pkg_count} package(s) to scan")
            run.ctx.agents.extend(j_agents)
        else:
            con.print("  [dim]  No AI library usage detected in notebooks[/dim]")
