"""Request preparation and discovery stages of the API scan pipeline."""

from __future__ import annotations

import logging
from typing import Any

from agent_bom.api.scan_context import ScanContext
from agent_bom.security import sanitize_error, sanitize_text

_logger = logging.getLogger("agent_bom.api.pipeline")


def prepare_request(ctx: ScanContext) -> bool:
    """Reset per-thread scanner state, clone a requested repository and validate paths."""
    from agent_bom.scanners import reset_scan_warnings
    from agent_bom.security import validate_path

    # Scan jobs reuse executor threads, and scanner warnings are thread-local.
    # Establish a clean request boundary even when this job intentionally
    # skips scan_agents_sync(), whose normal scan path performs its own reset.
    reset_scan_warnings()
    req = ctx.req
    if req.discover_host:
        from agent_bom.api.scan_boundary import require_host_discovery_for_tenant

        require_host_discovery_for_tenant(ctx.job.tenant_id)
    ctx.effective_agent_projects = list(req.agent_projects)
    ctx.effective_tf_dirs = list(req.tf_dirs)
    ctx.effective_gha_path = req.gha_path
    ctx.repo_url = (req.repo_url or "").strip()
    if ctx.repo_url:
        _clone_and_scan_repository(ctx)
        return False
    path_fields = (
        ([req.inventory] if req.inventory else [])
        + req.tf_dirs
        + ([req.gha_path] if req.gha_path else [])
        + req.agent_projects
        + req.jupyter_dirs
        + ([req.sbom] if req.sbom else [])
        + req.filesystem_paths
    )
    for p in path_fields:
        validate_path(p, must_exist=True)
    return False


def _clone_and_scan_repository(ctx: ScanContext) -> None:
    from agent_bom.repo_scan import RepoScanError, clone_repository, fetch_repo_trust

    repo_url = ctx.repo_url
    pipeline = ctx.pipeline
    pipeline.start_step("discovery", f"Cloning repository: {repo_url}")
    try:
        cloned_dir = ctx.repo_stack.enter_context(clone_repository(repo_url, token_env="AGENT_BOM_REPO_SCAN_TOKEN"))
    except RepoScanError as exc:
        raise RuntimeError(sanitize_error(exc, generic=True)) from exc
    cloned_path = str(cloned_dir)
    ctx.cloned_path = cloned_path
    ctx.effective_agent_projects = [cloned_path]
    ctx.effective_tf_dirs = [cloned_path]
    ctx.effective_gha_path = ctx.effective_gha_path or cloned_path
    ctx.extra_symbol_paths.append(cloned_path)
    pipeline.update_step("discovery", f"Repository cloned for static scan: {repo_url}")
    ctx.repo_trust_data = fetch_repo_trust(repo_url, token_env="AGENT_BOM_REPO_SCAN_TOKEN")
    from agent_bom.api.repo_tree_scan import scan_cloned_repo_tree

    repo_tree_result = scan_cloned_repo_tree(
        cloned_path,
        agents=ctx.agents,
        warnings=ctx.warnings_all,
        update_progress=lambda message: pipeline.update_step("discovery", message),
        offline=ctx.req.offline,
    )
    ctx.skill_audit_data = repo_tree_result.skill_audit_data
    ctx.iac_findings_data = repo_tree_result.iac_findings_data
    ctx.repo_ai_inventory_data = repo_tree_result.ai_inventory_data
    ctx.repo_sast_data = repo_tree_result.sast_data
    ctx.repo_codeowners = repo_tree_result.codeowners
    ctx.repo_scan_issues = repo_tree_result.scan_issues


def refresh_vulnerability_db(ctx: ScanContext) -> bool:
    req = ctx.req
    if not (req.auto_update_db and not req.offline and not req.no_scan):
        return False
    try:
        from agent_bom.db.schema import db_freshness_days
        from agent_bom.db.sync import sync_db

        source_list = [s.strip() for s in req.db_sources.split(",") if s.strip()] if req.db_sources else None
        freshness = db_freshness_days()
        if freshness is None or freshness >= 1 or source_list:
            sync_db(sources=source_list)
    except Exception as db_exc:  # noqa: BLE001
        _logger.warning("API auto DB refresh failed: %s", sanitize_text(sanitize_error(db_exc)))
        ctx.warnings_all.append(f"Auto DB refresh skipped: {sanitize_error(db_exc)}")
    return False


def _discover_mcp_configs(ctx: ScanContext) -> list[Any]:
    from agent_bom.discovery import discover_all

    req = ctx.req
    pipeline = ctx.pipeline
    if ctx.repo_url:
        pipeline.start_step("discovery", "Discovering MCP configs in cloned repository...")
        return discover_all(project_dir=ctx.cloned_path, dynamic=req.dynamic_discovery, dynamic_max_depth=req.dynamic_max_depth)
    # Scope discovery to the request's own project paths — the server
    # host is not the tenant's estate, so ambient host-wide discovery
    # (discover_all with no project_dir) would fold the server's own AI
    # clients into a tenant's scan. Host discovery is opt-in via
    # `discover_host` for self-hosted single-tenant deployments.
    local_agents: list[Any] = []
    for proj in ctx.effective_agent_projects:
        pipeline.update_step("discovery", f"Discovering MCP configs in {proj}...")
        local_agents.extend(discover_all(project_dir=str(proj), dynamic=req.dynamic_discovery, dynamic_max_depth=req.dynamic_max_depth))
    if req.discover_host:
        pipeline.update_step("discovery", "Discovering host ambient MCP configurations...")
        local_agents.extend(discover_all(dynamic=req.dynamic_discovery, dynamic_max_depth=req.dynamic_max_depth))
    if not ctx.effective_agent_projects and not req.discover_host:
        pipeline.update_step("discovery", "No local project scope; skipping ambient host discovery")
    return local_agents


def _discover_inventory(ctx: ScanContext) -> None:
    inventory = ctx.req.inventory
    if not inventory:
        return
    ctx.pipeline.update_step("discovery", f"Loading inventory: {inventory}")
    from agent_bom.inventory import build_agents_from_inventory, load_inventory

    try:
        inv_data = load_inventory(inventory)
    except (OSError, RuntimeError, ValueError) as parse_err:
        raise RuntimeError(f"Failed to load inventory file: {parse_err}") from parse_err
    ctx.agents.extend(build_agents_from_inventory(inv_data, inventory))


def _image_agent(image_ref: str, *, source: str) -> Any:
    from agent_bom.image import scan_image
    from agent_bom.models import Agent, AgentType, MCPServer, ServerSurface, TransportType

    img_packages, _strategy = scan_image(image_ref)
    return Agent(
        name=f"image:{image_ref}",
        agent_type=AgentType.CUSTOM,
        config_path=f"docker://{image_ref}",
        source=source,
        mcp_servers=[
            MCPServer(
                name=image_ref,
                command="docker",
                args=["run", image_ref],
                transport=TransportType.STDIO,
                packages=img_packages,
                surface=ServerSurface.CONTAINER_IMAGE,
            )
        ],
    )


def _discover_images(ctx: ScanContext) -> None:
    for image_ref in ctx.req.images:
        ctx.pipeline.update_step("discovery", f"Scanning image: {image_ref}")
        try:
            ctx.agents.append(_image_agent(image_ref, source="image"))
        except Exception as img_exc:  # noqa: BLE001
            ctx.record_coverage_warning(f"Image scan error for {image_ref}: {sanitize_error(img_exc)}")


def _discover_kubernetes(ctx: ScanContext) -> None:
    if not ctx.req.k8s:
        return
    ctx.pipeline.update_step("discovery", "Scanning Kubernetes pods...")
    from agent_bom.k8s import discover_images

    k8s_records = discover_images(namespace=ctx.req.k8s_namespace or "default")
    for img, _pod, _ctr in k8s_records:
        try:
            ctx.agents.append(_image_agent(img, source="kubernetes-image"))
        except Exception as img_exc:  # noqa: BLE001
            ctx.record_coverage_warning(f"Kubernetes image scan error for {img}: {sanitize_error(img_exc)}")


def _discover_iac_and_projects(ctx: ScanContext) -> None:
    pipeline = ctx.pipeline
    for tf_dir in ctx.effective_tf_dirs:
        pipeline.update_step("discovery", f"Scanning Terraform: {tf_dir}")
        from agent_bom.terraform import scan_terraform_dir

        tf_agents, tf_warnings = scan_terraform_dir(tf_dir)
        ctx.agents.extend(tf_agents)
        ctx.warnings_all.extend(tf_warnings)

    gha_path = ctx.effective_gha_path
    if gha_path:
        pipeline.update_step("discovery", f"Scanning GitHub Actions: {gha_path}")
        from agent_bom.github_actions import attach_github_action_packages, discover_github_action_packages, scan_github_actions

        gha_agents, gha_warnings = scan_github_actions(gha_path)
        ctx.agents.extend(gha_agents)
        attach_github_action_packages(ctx.agents, gha_path, discover_github_action_packages(gha_path))
        ctx.warnings_all.extend(gha_warnings)

    for ap in ctx.effective_agent_projects:
        pipeline.update_step("discovery", f"Scanning Python agent project: {ap}")
        from agent_bom.python_agents import scan_python_agents

        py_agents, py_warnings = scan_python_agents(ap)
        ctx.agents.extend(py_agents)
        ctx.warnings_all.extend(py_warnings)

    for jdir in ctx.req.jupyter_dirs:
        pipeline.update_step("discovery", f"Scanning Jupyter notebooks: {jdir}")
        from agent_bom.jupyter import scan_jupyter_notebooks

        j_agents, j_warnings = scan_jupyter_notebooks(jdir)
        ctx.agents.extend(j_agents)
        ctx.warnings_all.extend(j_warnings)


def _discover_sbom_and_external(ctx: ScanContext) -> None:
    req = ctx.req
    if req.sbom:
        ctx.pipeline.update_step("discovery", f"Ingesting SBOM: {req.sbom}")
        from agent_bom.parsers.sbom_context import load_sbom_agents

        sbom_agents, _fmt = load_sbom_agents(req.sbom)
        ctx.agents.extend(sbom_agents)

    if not req.external_scan:
        return
    ctx.pipeline.update_step("discovery", f"Ingesting external scan: {req.external_scan}")
    from pathlib import Path as _Path

    from agent_bom.parsers.external_import import build_external_agent
    from agent_bom.parsers.external_scanners import load_external_report

    try:
        # JSONDecodeError and the size-limit error are both ValueError.
        _ext_import = load_external_report(req.external_scan)
        ctx.agents.append(build_external_agent(_ext_import, str(_Path(req.external_scan))))
        ctx.external_findings.extend(_ext_import.findings)
        ctx.warnings_all.extend(_ext_import.notices)
    except (OSError, ValueError) as ext_exc:
        ctx.record_coverage_warning(f"External scan error: {sanitize_error(ext_exc)}")


def _discover_connectors(ctx: ScanContext) -> None:
    for connector_name in ctx.req.connectors:
        ctx.pipeline.update_step("discovery", f"Discovering from connector: {connector_name}")
        try:
            from agent_bom.connectors import discover_from_connector

            con_agents, con_warnings = discover_from_connector(connector_name)
            ctx.agents.extend(con_agents)
            ctx.warnings_all.extend(con_warnings)
            ctx.coverage_warning_messages.update(str(warning) for warning in con_warnings)
        except Exception as con_exc:  # noqa: BLE001
            ctx.record_coverage_warning(f"{connector_name} connector error: {sanitize_error(con_exc, generic=True)}")


def _discover_filesystems(ctx: ScanContext) -> None:
    for fs_path in ctx.req.filesystem_paths:
        ctx.pipeline.update_step("discovery", f"Scanning filesystem: {fs_path}")
        try:
            from agent_bom.filesystem import scan_filesystem
            from agent_bom.models import Agent, AgentType, MCPServer, ServerSurface

            fs_pkgs, fs_strat = scan_filesystem(fs_path)
            if fs_pkgs:
                from pathlib import Path as _Path

                fs_server = MCPServer(name=f"fs:{fs_path}", surface=ServerSurface.FILESYSTEM)
                fs_server.packages = fs_pkgs
                fs_agent = Agent(
                    name=f"filesystem:{_Path(fs_path).name}",
                    agent_type=AgentType.CUSTOM,
                    config_path=fs_path,
                    source="filesystem",
                    mcp_servers=[fs_server],
                )
                ctx.agents.append(fs_agent)
        except Exception as fs_exc:  # noqa: BLE001
            ctx.record_coverage_warning(f"Filesystem scan error: {sanitize_error(fs_exc, generic=True)}")


def _scan_local_secrets(ctx: ScanContext) -> None:
    if ctx.repo_url:
        return
    from pathlib import Path as _SecretRootPath

    secret_roots = [path for path in (*ctx.effective_agent_projects, *ctx.req.filesystem_paths) if path and _SecretRootPath(path).is_dir()]
    if not secret_roots:
        return
    ctx.pipeline.update_step("discovery", "Scanning for secrets, credentials, and PII")
    from agent_bom.api.repo_tree_scan import scan_path_secrets, secret_scan_warning

    secrets_block, secret_issues = scan_path_secrets(secret_roots, offline=ctx.req.offline)
    ctx.repo_ai_inventory_data = ctx.repo_ai_inventory_data or {}
    ctx.repo_ai_inventory_data["secrets"] = secrets_block
    ctx.repo_scan_issues = [*ctx.repo_scan_issues, *secret_issues]
    if secrets_block["total"] > 0:
        ctx.warnings_all.append(secret_scan_warning(secrets_block, location="project"))


def _apply_scope_filters(ctx: ScanContext) -> None:
    req = ctx.req
    if not (req.scope_agents or req.scope_servers or req.exclude_agents or req.exclude_servers):
        return
    import fnmatch

    def _matches(name: str, patterns: list[str]) -> bool:
        return any(fnmatch.fnmatch(name, pat) for pat in patterns)

    pre_filter = len(ctx.agents)
    if req.scope_agents:
        ctx.agents = [a for a in ctx.agents if _matches(a.name, req.scope_agents)]
    if req.exclude_agents:
        ctx.agents = [a for a in ctx.agents if not _matches(a.name, req.exclude_agents)]
    for agent in ctx.agents if (req.scope_servers or req.exclude_servers) else []:
        if req.scope_servers:
            agent.mcp_servers = [s for s in agent.mcp_servers if _matches(s.name, req.scope_servers)]
        if req.exclude_servers:
            agent.mcp_servers = [s for s in agent.mcp_servers if not _matches(s.name, req.exclude_servers)]
    filtered_count = pre_filter - len(ctx.agents)
    if filtered_count:
        ctx.pipeline.update_step("discovery", f"Scope filter removed {filtered_count} agent(s)")


def discover_agents(ctx: ScanContext) -> bool:
    """Run every requested collector, consolidate the estate and apply scope filters."""
    ctx.agents.extend(_discover_mcp_configs(ctx))
    _discover_inventory(ctx)
    _discover_images(ctx)
    _discover_kubernetes(ctx)
    _discover_iac_and_projects(ctx)
    _discover_sbom_and_external(ctx)
    _discover_connectors(ctx)
    _discover_filesystems(ctx)
    _scan_local_secrets(ctx)

    from agent_bom.discovery.identity import consolidate_project_agents

    ctx.agents = consolidate_project_agents(ctx.agents)
    ctx.pipeline.complete_step("discovery", f"Found {len(ctx.agents)} agent(s)", {"agents": len(ctx.agents)})
    _apply_scope_filters(ctx)
    return False


def flag_blocklisted_servers(ctx: ScanContext) -> bool:
    from agent_bom.mcp_blocklist import flag_blocklisted_mcp_servers

    blocked_servers = flag_blocklisted_mcp_servers(ctx.agents)
    if blocked_servers:
        ctx.pipeline.update_step("discovery", f"MCP blocklist flagged {blocked_servers} server(s)")
    return False
