"""Stage 3: build the scan context and discover agents, cloud estates and benchmarks."""

from __future__ import annotations

import time as _time

import click

from agent_bom.cli.agents._cloud import run_benchmarks, run_cloud_discovery
from agent_bom.cli.agents._context import ScanContext
from agent_bom.cli.agents._discovery import run_local_discovery
from agent_bom.cli.agents.scan_pipeline.helpers import _agents_patchable
from agent_bom.cli.agents.scan_pipeline.options import ScanOptions
from agent_bom.cli.agents.scan_pipeline.state import ScanState


def _create_context(opts: ScanOptions, st: ScanState) -> None:
    # Create shared context object
    st.ctx = ScanContext(con=st.con, quiet=opts.quiet, verbose=opts.verbose, target_scope=st.target_scope)
    st.ctx.step_timings.update(st.pre_scan_step_timings)
    if st.repo_trust_data:
        st.ctx.repo_trust_data = st.repo_trust_data
    try:
        from agent_bom.resolver import reset_performance_stats as _reset_resolver_performance
        from agent_bom.scanners import reset_scan_performance as _reset_scan_performance

        _reset_resolver_performance()
        _reset_scan_performance()
    except Exception:
        pass

    # Compute any_cloud for early no-agent check in _discovery
    st.any_cloud = (
        opts.aws
        or opts.azure_flag
        or opts.gcp_flag
        or opts.coreweave_flag
        or opts.databricks_flag
        or opts.snowflake_flag
        or opts.nebius_flag
        or opts.hf_flag
        or opts.wandb_flag
        or opts.mlflow_flag
        or opts.openai_flag
        or opts.ollama_flag
    )


def _guard_no_discover(opts: ScanOptions, st: ScanState) -> None:
    # ── --no-discover zero-artifact guard ────────────────────────────────────
    # --no-discover suppresses ambient discovery, so it MUST be paired with at
    # least one explicit input artifact. Without one there is nothing to scan;
    # exiting 0 "clean" here is a CI false-negative (a vulnerable target looks
    # green). Hard-fail as a usage error (exit 2) instead. `project` here already
    # absorbs --repo, the positional PATH, --self-scan, and --demo.
    if opts.no_discover:
        _has_explicit_artifact = bool(
            opts.project
            or opts.config_dir
            or opts.inventory
            or opts.sbom_file
            or opts.external_scan_path
            or opts.images
            or opts.image_tars
            or opts.filesystem_paths
            or opts.os_packages
            or opts.k8s
            or opts.k8s_mcp
            or opts.code_paths
            or opts.ai_inventory_paths
            or opts.tf_dirs
            or opts.gha_path
            or opts.agent_projects
            or opts.skill_paths
            or opts.jupyter_dirs
            or opts.iac_paths
            or opts.model_dirs
            or opts.dataset_dirs
            or opts.training_dirs
            or opts.hf_models
            or opts.scan_pii
            or opts.vector_db_scan
            or opts.gpu_scan_flag
            or opts.scan_prompts
            or opts.browser_extensions
            or st.any_cloud
        )
        if not _has_explicit_artifact:
            raise click.UsageError(
                "--no-discover requires at least one explicit input artifact to scan "
                "(e.g. --project/-p, --repo, --config-dir, --inventory, --sbom, "
                "--external-scan, --image, --image-tar, --filesystem, or --skill). None were "
                "provided, so there is nothing to scan."
            )


def _expand_project_targets(opts: ScanOptions, st: ScanState) -> None:
    # An imported external report adds evidence to the project scan; it never
    # replaces the project's own auto-detected surfaces.
    _explicit_target_flags = {
        "--inventory": opts.inventory,
        "--sbom": opts.sbom_file,
        "--image": opts.images,
        "--image-tar": opts.image_tars,
        "--filesystem": opts.filesystem_paths,
        "--k8s": opts.k8s,
    }
    _explicit_targets = [flag for flag, value in _explicit_target_flags.items() if value]
    # --demo/--self-scan synthesize their own project + inventory pair; only a
    # user-supplied project combined with an explicit target deserves a notice.
    if opts.project and not opts.skill_only and _explicit_targets and not (opts.demo or opts.self_scan):
        from agent_bom.repo_auto_detect import expand_project_scan_targets

        # Explicitly enabled surfaces are scanned even beside an inventory;
        # report only the remaining detected surfaces that were skipped.
        _skipped_surfaces = expand_project_scan_targets(
            opts.project,
            jupyter_dirs=opts.jupyter_dirs,
            code_paths=opts.code_paths,
            scan_prompts=opts.scan_prompts,
            tf_dirs=opts.tf_dirs,
            gha_path=opts.gha_path,
            agent_projects=opts.agent_projects,
            ai_inventory_paths=opts.ai_inventory_paths,
            iac_paths=opts.iac_paths,
        ).auto_enabled
        if _skipped_surfaces:
            _skip_notice = (
                f"Project surface auto-detection ({', '.join(_skipped_surfaces)}) was skipped for {opts.project} "
                f"because an explicit target was given ({', '.join(_explicit_targets)}); pass the matching surface flags "
                "(see `agent-bom scan --help`) to include them."
            )
            st.ctx.scan_notices.append({"code": "project_auto_detect_skipped", "source": "project", "message": _skip_notice})
            if not opts.quiet:
                st.con.print(f"[yellow]![/yellow] {_skip_notice}")
    # Named project expansion is bounded to the requested root, not ambient discovery.
    if opts.project and not opts.skill_only and not _explicit_targets:
        from agent_bom.repo_auto_detect import expand_project_scan_targets

        auto_targets = expand_project_scan_targets(
            opts.project,
            jupyter_dirs=opts.jupyter_dirs,
            code_paths=opts.code_paths,
            scan_prompts=opts.scan_prompts,
            tf_dirs=opts.tf_dirs,
            gha_path=opts.gha_path,
            agent_projects=opts.agent_projects,
            ai_inventory_paths=opts.ai_inventory_paths,
            iac_paths=opts.iac_paths,
        )
        if auto_targets.auto_enabled:
            opts.jupyter_dirs = auto_targets.jupyter_dirs
            opts.code_paths = auto_targets.code_paths
            opts.scan_prompts = auto_targets.scan_prompts
            opts.tf_dirs = auto_targets.tf_dirs
            opts.gha_path = auto_targets.gha_path
            opts.agent_projects = auto_targets.agent_projects
            opts.ai_inventory_paths = auto_targets.ai_inventory_paths
            opts.iac_paths = auto_targets.iac_paths
            if not opts.quiet:
                st.con.print(f"[dim]Auto-detected project scan surfaces: {', '.join(auto_targets.auto_enabled)}[/dim]")


def _discover_local(opts: ScanOptions, st: ScanState) -> None:
    # Step 1–1g4: Local discovery
    st.step_t0 = _time.monotonic()
    run_local_discovery(
        st.ctx,
        project=opts.project,
        config_dir=opts.config_dir,
        inventory=opts.inventory,
        skill_only=opts.skill_only,
        # Self-scan targets installed distributions, not incidental CWD skills.
        # Explicit --skill inputs remain handled by local discovery.
        no_discover=opts.no_discover or opts.self_scan,
        follow_symlinks=opts.follow_symlinks,
        dynamic_discovery=opts.dynamic_discovery,
        dynamic_max_depth=opts.dynamic_max_depth,
        include_processes=opts.include_processes,
        include_containers=opts.include_containers,
        introspect=opts.introspect,
        introspect_timeout=opts.introspect_timeout,
        enforce=opts.enforce,
        health_check=opts.health_check,
        hc_timeout=opts.hc_timeout,
        k8s_mcp=opts.k8s_mcp,
        k8s_namespace=opts.k8s_namespace,
        k8s_all_namespaces=opts.k8s_all_namespaces,
        k8s_mcp_context=opts.k8s_mcp_context,
        no_skill=opts.no_skill,
        skill_paths=opts.skill_paths,
        skill_only_mode=opts.skill_only,
        ai_enrich=opts.ai_enrich,
        ai_model=opts.ai_model,
        sbom_file=opts.sbom_file,
        sbom_name=opts.sbom_name,
        external_scan_path=opts.external_scan_path,
        k8s=opts.k8s,
        namespace=opts.namespace,
        all_namespaces=opts.all_namespaces,
        k8s_context=opts.k8s_context,
        registry_user=opts.registry_user,
        registry_pass=opts.registry_pass,
        image_platform=opts.image_platform,
        images=opts.images,
        image_tars=opts.image_tars,
        filesystem_paths=opts.filesystem_paths,
        code_paths=opts.code_paths,
        sast_config=opts.sast_config,
        offline=opts.offline,
        ai_inventory_paths=opts.ai_inventory_paths,
        tf_dirs=opts.tf_dirs,
        gha_path=opts.gha_path,
        agent_projects=opts.agent_projects,
        scan_prompts=opts.scan_prompts,
        browser_extensions=opts.browser_extensions,
        jupyter_dirs=opts.jupyter_dirs,
        verbose=opts.verbose,
        quiet=opts.quiet,
        smithery_token=opts.smithery_token,
        smithery_flag=opts.smithery_flag,
        mcp_registry_flag=opts.mcp_registry_flag,
        os_packages=opts.os_packages,
        workstation_sweep=opts.preset == "workstation",
        iac_paths=opts.iac_paths,
        _image_only=opts._image_only,
        _any_cloud=st.any_cloud,
        _discover_all=_agents_patchable("discover_all"),  # tests patch agent_bom.cli.agents.discover_all
    )

    st.ctx.step_timings["discovery"] = _time.monotonic() - st.step_t0

    # Re-bind the (possibly updated) agents list
    st.agents = st.ctx.agents


def _discover_cloud(opts: ScanOptions, st: ScanState) -> None:
    # Step 1h + 1y + 1z: Cloud discovery, SaaS connectors, correlation
    st.step_t0 = _time.monotonic()
    run_cloud_discovery(
        st.ctx,
        skill_only=opts.skill_only,
        aws=opts.aws,
        aws_region=opts.aws_region,
        aws_profile=opts.aws_profile,
        aws_include_lambda=not opts.no_aws_lambda,
        aws_include_eks=opts.aws_include_eks,
        aws_include_step_functions=opts.aws_include_step_functions,
        aws_include_ec2=opts.aws_include_ec2,
        aws_include_iam=opts.aws_include_iam,
        aws_ec2_tag=opts.aws_ec2_tag,
        azure_flag=opts.azure_flag,
        azure_subscription=opts.azure_subscription,
        gcp_flag=opts.gcp_flag,
        gcp_project=opts.gcp_project,
        coreweave_flag=opts.coreweave_flag,
        coreweave_context=opts.coreweave_context,
        coreweave_namespace=opts.coreweave_namespace,
        databricks_flag=opts.databricks_flag,
        snowflake_flag=opts.snowflake_flag,
        snowflake_authenticator=opts.snowflake_authenticator,
        nebius_flag=opts.nebius_flag,
        nebius_api_key=opts.nebius_api_key,
        nebius_project_id=opts.nebius_project_id,
        hf_flag=opts.hf_flag,
        hf_token=opts.hf_token,
        hf_username=opts.hf_username,
        hf_organization=opts.hf_organization,
        wandb_flag=opts.wandb_flag,
        wandb_api_key=opts.wandb_api_key,
        wandb_entity=opts.wandb_entity,
        wandb_project=opts.wandb_project,
        mlflow_flag=opts.mlflow_flag,
        mlflow_tracking_uri=opts.mlflow_tracking_uri,
        openai_flag=opts.openai_flag,
        openai_api_key=opts.openai_api_key,
        openai_org_id=opts.openai_org_id,
        ollama_flag=opts.ollama_flag,
        ollama_host=opts.ollama_host,
        jira_discover=opts.jira_discover,
        jira_url=opts.jira_url,
        jira_user=opts.jira_user,
        jira_token=opts.jira_token,
        servicenow_flag=opts.servicenow_flag,
        servicenow_instance=opts.servicenow_instance,
        servicenow_token=opts.servicenow_token,
        slack_discover=opts.slack_discover,
        slack_bot_token=opts.slack_bot_token,
    )


def _run_benchmarks(opts: ScanOptions, st: ScanState) -> None:
    # Steps 1x–1z: Benchmarks
    run_benchmarks(
        st.ctx,
        skill_only=opts.skill_only,
        verify_model_hashes=opts.verify_model_hashes,
        project=opts.project,
        hf_token=opts.hf_token,
        aws_cis_benchmark=opts.aws_cis_benchmark,
        aws_region=opts.aws_region,
        aws_profile=opts.aws_profile,
        snowflake_cis_benchmark=opts.snowflake_cis_benchmark,
        snowflake_authenticator=opts.snowflake_authenticator,
        azure_cis_benchmark=opts.azure_cis_benchmark,
        azure_subscription=opts.azure_subscription,
        gcp_cis_benchmark=opts.gcp_cis_benchmark,
        gcp_project=opts.gcp_project,
        databricks_security=opts.databricks_security,
        aisvs_flag=opts.aisvs_flag,
        vector_db_scan=opts.vector_db_scan,
        gpu_scan_flag=opts.gpu_scan_flag,
        gpu_k8s_context=opts.gpu_k8s_context,
        no_dcgm_probe=opts.no_dcgm_probe,
        smithery_flag=opts.smithery_flag,
        smithery_token=opts.smithery_token,
        mcp_registry_flag=opts.mcp_registry_flag,
        snyk_flag=opts.snyk_flag,
        snyk_token=opts.snyk_token,
        snyk_org=opts.snyk_org,
        cortex_observability=opts.cortex_observability,
        snowflake_flag=opts.snowflake_flag,
    )

    # Keep local reference up-to-date (cloud discovery may have extended agents)
    st.agents = st.ctx.agents
    st.ctx.step_timings["cloud"] = _time.monotonic() - st.step_t0

    from agent_bom.mcp_blocklist import flag_blocklisted_mcp_servers

    flag_blocklisted_mcp_servers(st.agents)


def run_discovery(opts: ScanOptions, st: ScanState) -> None:
    """Create the scan context and run local, cloud and benchmark discovery."""
    _create_context(opts, st)
    _guard_no_discover(opts, st)
    _expand_project_targets(opts, st)
    _discover_local(opts, st)
    _discover_cloud(opts, st)
    _run_benchmarks(opts, st)
