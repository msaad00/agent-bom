"""Discovery stage for an explicitly named project directory (--project / --repo)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from agent_bom.cli.agents._discovery_state import DiscoveryRun
from agent_bom.models import Agent, AgentType, MCPServer, ServerSurface, TransportType


def _print_project_summary(run: DiscoveryRun, proj_label: str, project_inventory: dict[str, Any], total_proj_pkgs: int) -> None:
    run.con.print(
        f"  [green]✓[/green] {proj_label}: "
        f"{total_proj_pkgs} package(s) across {project_inventory['manifest_directories']} manifest director"
        f"{'ies' if project_inventory['manifest_directories'] != 1 else 'y'} "
        f"({project_inventory['manifest_files']} files, {project_inventory['lockfiles']} lockfile"
        f"{'s' if project_inventory['lockfiles'] != 1 else ''}, "
        f"{project_inventory['direct_packages']} direct / {project_inventory['transitive_packages']} transitive, "
        f"{project_inventory['lockfile_backed_packages']} lockfile-backed / "
        f"{project_inventory['declaration_only_packages']} declaration-only)"
    )


def _project_servers(dir_map: dict[Path, Any], proj_root_resolved: Path, proj_label: str) -> list[MCPServer]:
    proj_servers: list[MCPServer] = []
    for manifest_dir, pkgs in dir_map.items():
        manifest_dir_resolved = manifest_dir.resolve()
        try:
            rel = manifest_dir_resolved.relative_to(proj_root_resolved) if manifest_dir_resolved != proj_root_resolved else Path(".")
        except ValueError:
            rel = Path(manifest_dir_resolved.name)
        server_name = str(rel) if str(rel) != "." else proj_label
        proj_server = MCPServer(
            name=server_name,
            command="project",
            args=[str(manifest_dir_resolved)],
            transport=TransportType.STDIO,
            surface=ServerSurface.OTHER,
            packages=pkgs,
        )
        proj_servers.append(proj_server)
    return proj_servers


def scan_project(run: DiscoveryRun) -> None:
    """Step 1d4: project package scan.

    An explicitly-passed --project/-p (or --repo, which resolves into `project`)
    is an explicit input artifact, so it is scanned even under --no-discover —
    only ambient/cwd discovery is suppressed, never the target the user named.
    """
    if run.skill_only or not run.project or run.images or run.code_paths or run.sbom_file:
        return
    from agent_bom.parsers import scan_project_directory, summarize_project_inventory

    con = run.con
    proj_root = Path(run.project)
    proj_root_resolved = proj_root.resolve()
    # Label from the *resolved* path: `Path(".").name` is the empty string, so
    # the README's headline `agent-bom scan .` otherwise produced a nameless
    # `project:` agent and a nameless server across console, JSON, and SARIF.
    proj_label = proj_root_resolved.name or str(proj_root_resolved)
    is_synthetic_demo_project = proj_label.startswith("agent-bom-demo-dir-")
    if not is_synthetic_demo_project:
        con.print(f"\n[bold blue]Scanning project directory for package manifests: {proj_label}[/bold blue]\n")
    package_warnings: list[str] = []
    dir_map = scan_project_directory(proj_root, follow_symlinks=run.follow_symlinks, warnings=package_warnings)
    for warning in package_warnings:
        con.print(f"  [yellow]⚠[/yellow] {warning}")
    if dir_map:
        project_inventory = summarize_project_inventory(proj_root, dir_map)
        run.ctx.project_inventory_data = project_inventory
        total_proj_pkgs = sum(len(v) for v in dir_map.values())
        _print_project_summary(run, proj_label, project_inventory, total_proj_pkgs)
        proj_agent = Agent(
            name=f"project:{proj_label}",
            agent_type=AgentType.CUSTOM,
            config_path=str(proj_root),
            source="project",
            mcp_servers=_project_servers(dir_map, proj_root_resolved, proj_label),
        )
        run.ctx.agents.append(proj_agent)
    elif not is_synthetic_demo_project:
        con.print(f"  [dim]  No package manifests found in {proj_root}[/dim]")
