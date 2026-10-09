"""Steps 1–1g4: local agent/package discovery."""

from __future__ import annotations

import platform
import sys
from pathlib import Path
from typing import Any

from agent_bom.cli.agents._context import ScanContext
from agent_bom.cli.agents._discovery_ai import scan_ai_inventory
from agent_bom.cli.agents._discovery_project import scan_project
from agent_bom.cli.agents._discovery_reports import (
    iac_findings_data,
    iac_severity_summary,
    print_iac_findings,
    scan_browser_extensions,
    scan_prompt_templates,
)
from agent_bom.cli.agents._discovery_skills import assess_skill_trust, publish_skill_objects, scan_skills
from agent_bom.cli.agents._discovery_sources import (
    discover_agents,
    discover_k8s_images,
    ingest_external_scan,
    load_inventory_file,
    load_sbom,
    print_discovery_header,
    scan_agent_projects,
    scan_container_images,
    scan_filesystems,
    scan_github_actions,
    scan_host_os_packages,
    scan_image_tarballs,
    scan_jupyter,
    scan_terraform,
)
from agent_bom.cli.agents._discovery_state import DiscoveryRun, DiscoveryStage
from agent_bom.discovery import CONFIG_LOCATIONS
from agent_bom.discovery import discover_all as _discover_all_default
from agent_bom.models import Agent, AgentType, MCPServer, ServerSurface

# Severity ordering for the aggregate SAST summary across multiple --code paths.
# A failure or skip must outrank a clean/findings result so the summary never
# hides that a path could not be scanned. Kept module-level so it is unit-testable.
_SAST_STATUS_RANK = {"failed": 3, "skipped": 2, "findings": 1, "clean": 0}


def _aggregate_sast_path_results(path_results: list[dict]) -> dict:
    """Collapse per-``--code``-path SAST results into one honest summary.

    With multiple code paths, a failure in an *earlier* path must not be lost
    when a *later* path succeeds. Rank by execution status (failed/skipped
    outrank findings/clean) and keep the highest-ranked path; ties resolve to
    the first path at that rank, preserving the first failure's reason/detail.
    """
    return max(
        path_results,
        key=lambda result: _SAST_STATUS_RANK.get(str(result.get("execution_status")), 0),
    )


def _merge_unique_agents(primary: list[Any], additional: list[Any]) -> list[Any]:
    """Merge project and ambient discovery without duplicating identities."""

    merged = list(primary)
    seen = {str(getattr(agent, "canonical_id", "") or getattr(agent, "stable_id", "") or getattr(agent, "name", "")) for agent in merged}
    for agent in additional:
        identity = str(getattr(agent, "canonical_id", "") or getattr(agent, "stable_id", "") or getattr(agent, "name", ""))
        if identity in seen:
            continue
        seen.add(identity)
        merged.append(agent)
    return merged


def _first_run_hints() -> list[tuple[str, str]]:
    """Return concrete config locations for common MCP clients on this platform."""
    system = platform.system()
    hints: list[tuple[str, str]] = []
    seen: set[str] = set()
    for label, agent_type in (
        ("Claude Desktop", AgentType.CLAUDE_DESKTOP),
        ("Claude Code", AgentType.CLAUDE_CODE),
        ("Cursor", AgentType.CURSOR),
        ("Codex CLI", AgentType.CODEX_CLI),
        ("Cortex CoCo / Cortex Code", AgentType.CORTEX_CODE),
    ):
        for path in CONFIG_LOCATIONS.get(agent_type, {}).get(system, []):
            expanded = str(Path(path).expanduser())
            if expanded in seen:
                continue
            seen.add(expanded)
            hints.append((label, expanded))
            break
    return hints


def merge_workstation_agents(run: DiscoveryRun) -> None:
    """Workstation sweep: add ambient host discovery to a project-scoped run."""
    if not (run.workstation_sweep and not run.no_discover and (run.project or run.config_dir)):
        return
    # A project-scoped discovery intentionally skips ambient host surfaces.
    # Workstation mode needs both, so collect global configs plus the
    # opt-in MCP process/container evidence and merge by stable identity.
    ambient_agents = run.discover(
        project_dir=None,
        dynamic=run.dynamic_discovery,
        dynamic_max_depth=run.dynamic_max_depth,
        include_processes=run.include_processes,
        include_containers=run.include_containers,
        include_k8s_mcp=False,
        k8s_namespace=run.k8s_namespace,
        k8s_all_namespaces=False,
        k8s_context=None,
    )
    run.ctx.agents = _merge_unique_agents(run.ctx.agents, ambient_agents)


def _has_scan_input(run: DiscoveryRun) -> bool:
    return any(
        (
            run.skill_only,
            run.no_discover,
            run.scan_prompts,
            run.browser_extensions,
            run.ctx.agents,
            run.images,
            run.k8s,
            run.code_paths,
            run.project,
            run.sbom_file,
            run.tf_dirs,
            run.gha_path,
            run.agent_projects,
            run.jupyter_dirs,
            run.extra.get("_any_cloud", False),
            run.filesystem_paths,
            run.image_tars,
            run.os_packages,
        )
    )


def exit_when_nothing_to_scan(run: DiscoveryRun) -> None:
    """First run with nothing discovered: print where configs live, then exit 0."""
    if _has_scan_input(run):
        return
    con = run.con
    con.print(f"\n[dim]No MCP configs or scannable files found in {Path.cwd()}[/dim]")
    con.print()
    con.print("  [bold]Common MCP config locations checked on this machine:[/bold]")
    for label, config_path in _first_run_hints():
        con.print(f"    [cyan]{label:<28}[/cyan] {config_path}")
    con.print()
    con.print("  [bold]Quick start:[/bold]")
    con.print("    [cyan]agent-bom scan -p /path/to/project[/cyan]  scan a project with lockfiles or manifests")
    con.print("    [cyan]agent-bom mcp[/cyan]                        discover MCP agents on this machine")
    con.print("    [cyan]agent-bom image nginx[/cyan]                scan a container image")
    con.print("    [cyan]agent-bom fs /path[/cyan]                   scan a directory")
    con.print("    [cyan]agent-bom check pkg@ver[/cyan]              check a single package")
    con.print()
    con.print("  [dim]If you expected Claude, Cursor, Codex, or Cortex CoCo / Cortex Code to appear,")
    con.print("  [dim]create one of the config files above and re-run `agent-bom scan`.[/dim]")
    con.print()
    sys.exit(0)


_LOCKFILE_PATTERNS = (
    "requirements.txt",
    "Pipfile.lock",
    "poetry.lock",
    "uv.lock",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "go.sum",
    "Cargo.lock",
    "Gemfile.lock",
    "composer.lock",
    "Package.resolved",
    "packages.lock.json",
)


def autodetect_lockfiles(run: DiscoveryRun) -> None:
    """Auto-detect lockfiles in the cwd (always, not just when no MCP).

    Skipped when explicitly scanning images or an external SBOM — avoid mixing
    local CWD packages (e.g. uv.lock transitive deps) with the targeted scan surface.
    """
    filesystem_paths, inventory = run.filesystem_paths, run.inventory
    if (
        not filesystem_paths
        and not inventory
        and (not run.no_discover and not run.project and not run.skill_only and not run.images and not run.image_tars and not run.sbom_file)
    ):
        cwd = Path.cwd()
        if any((cwd / f).exists() for f in _LOCKFILE_PATTERNS):
            run.filesystem_paths = (str(cwd),)
            run.con.print(f"\n[bold blue]Auto-detected lockfiles in {cwd}[/bold blue]")


def _top_level_iac_files(cwd: Path) -> list[str]:
    _auto_iac: list[str] = []
    for name in ["Dockerfile", "docker-compose.yml", "docker-compose.yaml"]:
        if (cwd / name).exists():
            _auto_iac.append(str(cwd / name))
    for f in cwd.glob("*.tf"):
        _auto_iac.append(str(f))
    for f in cwd.glob("*.yaml"):
        try:
            head = f.read_text(errors="replace")[:200]
            if "apiVersion:" in head and "kind:" in head:
                _auto_iac.append(str(f))
        except OSError:
            pass
    return _auto_iac


def autodetect_iac(run: DiscoveryRun) -> None:
    """Fallback IaC detection for a bare ``agent-bom scan`` with no ``--project``.

    The scan root is the ambient cwd, which may be an arbitrarily large tree (a
    home directory), so detection stays a cheap top-level glob here. When the
    operator NAMES a root with ``--project``/``--repo``, the recursive detector in
    ``expand_project_scan_targets`` has already filled ``iac_paths`` with that
    root, so nested IaC under infra/, deploy/ or charts/ is covered there.
    """
    iac_paths, inventory = run.iac_paths, run.inventory
    explicit_target = run.no_discover or run.skill_only or run.images or run.image_tars or run.sbom_file
    if not iac_paths and not inventory and not explicit_target:
        _auto_iac = _top_level_iac_files(Path(run.project) if run.project else Path.cwd())
        if _auto_iac:
            run.iac_paths = tuple(_auto_iac)
            run.con.print(f"[bold blue]Auto-detected {len(_auto_iac)} IaC file(s)[/bold blue]")


_SAST_FAILURE_DETAIL = {
    "offline_remote_config": "Offline mode disallows registry-backed rules.",
    "offline_no_local_config": "Offline mode found no local Semgrep rule configuration.",
    "semgrep_unavailable": "Semgrep is unavailable; install it or import an existing SARIF report.",
}


def _scan_code_path(run: DiscoveryRun, code_path: str) -> dict:
    from agent_bom.sast import SASTResult, SASTScanError, scan_code

    con = run.con
    try:
        sast_packages, sast_result = scan_code(code_path, config=run.sast_config, offline=run.offline)
    except SASTScanError as exc:
        con.print(f"  [yellow]![/yellow] {code_path}: [{exc.execution_status.value}] {exc.reason_code}")
        return SASTResult(
            execution_status=exc.execution_status,
            status_reason=exc.reason_code,
            status_detail=_SAST_FAILURE_DETAIL.get(exc.reason_code, "SAST execution failed."),
        ).to_dict()
    outcome = sast_result.to_dict()["execution_status"]
    con.print(
        f"  [green]v[/green] {code_path}: [{outcome}] {sast_result.total_findings} finding(s) "
        f"in {sast_result.files_scanned} file(s) [dim]({sast_result.scan_time_seconds}s)[/dim]"
    )
    if sast_packages:
        server = MCPServer(name=f"sast:{Path(code_path).name}", surface=ServerSurface.SAST)
        server.packages = sast_packages
        sast_agent = Agent(
            name=f"code:{Path(code_path).name}",
            agent_type=AgentType.CUSTOM,
            config_path=code_path,
            source="sast",
            mcp_servers=[server],
        )
        run.ctx.agents.append(sast_agent)
    return sast_result.to_dict()


def scan_code_paths(run: DiscoveryRun) -> None:
    """Step 1d3: SAST code scan (--code)."""
    if run.skill_only or not run.code_paths:
        return
    run.con.print(f"\n[bold blue]Running SAST scan on {len(run.code_paths)} path(s) via Semgrep...[/bold blue]\n")
    sast_path_results = [_scan_code_path(run, code_path) for code_path in run.code_paths]
    if sast_path_results:
        run.ctx.sast_data = _aggregate_sast_path_results(sast_path_results)


def _iac_deployment_mode() -> str:
    """Detect deployment context: GitHub Actions, MCP, or standalone."""
    import os as _os

    if _os.environ.get("GITHUB_ACTIONS") == "true":
        return "github-action"
    if _os.environ.get("AGENT_BOM_MCP_MODE") == "1":
        return "mcp"
    return "standalone"


def scan_iac(run: DiscoveryRun) -> None:
    """Step 1g5: IaC misconfiguration scan (--iac)."""
    if run.skill_only or not run.iac_paths:
        return
    from agent_bom.cli.agents._preflight import _print_scanner_verdicts
    from agent_bom.iac import scan_iac_with_context
    from agent_bom.iac.models import ScanContext as IaCContext

    con, iac_paths = run.con, run.iac_paths
    iac_scan_ctx = IaCContext(deployment_mode=_iac_deployment_mode())
    all_iac_findings: list = []
    all_iac_verdicts: list = []
    printed_iac_heading = False
    for iac_path in iac_paths:
        is_synthetic_demo_iac = Path(iac_path).name.startswith("agent-bom-demo-dir-")
        result = scan_iac_with_context(iac_path, iac_scan_ctx)
        all_iac_findings.extend(result.findings)
        all_iac_verdicts.extend(result.verdicts)
        if not result.findings and is_synthetic_demo_iac:
            continue
        if not printed_iac_heading:
            con.print(f"\n[bold blue]Scanning {len(iac_paths)} path(s) for IaC misconfigurations...[/bold blue]\n")
            printed_iac_heading = True
        if result.findings:
            con.print(f"  [green]✓[/green] {iac_path}: {len(result.findings)} finding(s) ({iac_severity_summary(result.findings)})")
        else:
            con.print(f"  [dim]  {iac_path}: no misconfigurations found[/dim]")
    if run.verbose and all_iac_verdicts:
        _print_scanner_verdicts(con, all_iac_verdicts)
    if all_iac_findings:
        print_iac_findings(run, all_iac_findings)
    run.ctx.iac_findings_data = iac_findings_data(all_iac_findings)


def consolidate_agents(run: DiscoveryRun) -> None:
    from agent_bom.discovery.identity import consolidate_project_agents

    run.ctx.agents = consolidate_project_agents(run.ctx.agents)


# The one place the discovery order is defined. Later stages read what earlier
# ones produced: k8s widens ``images``; auto-detect fills ``filesystem_paths``
# and ``iac_paths``; skill scanning feeds the trust assessment.
DISCOVERY_STAGES: tuple[DiscoveryStage, ...] = (
    load_inventory_file,
    print_discovery_header,
    discover_agents,
    merge_workstation_agents,
    exit_when_nothing_to_scan,
    load_sbom,
    ingest_external_scan,
    discover_k8s_images,
    scan_container_images,
    scan_image_tarballs,
    autodetect_lockfiles,
    autodetect_iac,
    scan_filesystems,
    scan_host_os_packages,
    scan_code_paths,
    scan_ai_inventory,
    scan_project,
    scan_terraform,
    scan_github_actions,
    scan_agent_projects,
    scan_skills,
    assess_skill_trust,
    publish_skill_objects,
    scan_prompt_templates,
    scan_browser_extensions,
    scan_jupyter,
    scan_iac,
    consolidate_agents,
)


def run_local_discovery(
    ctx: ScanContext,
    *,
    project: Any,
    config_dir: Any,
    inventory: Any,
    skill_only: bool,
    no_discover: bool = False,
    follow_symlinks: bool = False,
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
    offline: bool = False,
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
    workstation_sweep: bool = False,
    _discover_all: Any = None,
    **kwargs: Any,
) -> None:
    """Steps 1–1g4: discover agents from local sources, SBOM, images, etc.

    Runs ``DISCOVERY_STAGES`` in order over one ``DiscoveryRun``.
    """
    params = dict(locals())
    # Allow callers to inject discover_all (enables patch("agent_bom.cli.agents.discover_all"))
    discover = _discover_all if _discover_all is not None else _discover_all_default
    run = DiscoveryRun.from_params(params, discover)
    for stage in DISCOVERY_STAGES:
        stage(run)
