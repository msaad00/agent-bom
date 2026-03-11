"""Steps 1h, 1x–1z: cloud providers, benchmarks, SaaS connectors."""

from __future__ import annotations

from typing import Any

from agent_bom.cli.scan._context import ScanContext


def run_cloud_discovery(
    ctx: ScanContext,
    *,
    skill_only: bool,
    aws: bool,
    aws_region: Any,
    aws_profile: Any,
    aws_include_lambda: bool,
    aws_include_eks: bool,
    aws_include_step_functions: bool,
    aws_include_ec2: bool,
    aws_ec2_tag: Any,
    azure_flag: bool,
    azure_subscription: Any,
    gcp_flag: bool,
    gcp_project: Any,
    coreweave_flag: bool,
    coreweave_context: Any,
    coreweave_namespace: Any,
    databricks_flag: bool,
    snowflake_flag: bool,
    snowflake_authenticator: Any,
    nebius_flag: bool,
    nebius_api_key: Any,
    nebius_project_id: Any,
    hf_flag: bool,
    hf_token: Any,
    hf_username: Any,
    hf_organization: Any,
    wandb_flag: bool,
    wandb_api_key: Any,
    wandb_entity: Any,
    wandb_project: Any,
    mlflow_flag: bool,
    mlflow_tracking_uri: Any,
    openai_flag: bool,
    openai_api_key: Any,
    openai_org_id: Any,
    ollama_flag: bool,
    ollama_host: Any,
    jira_discover: bool = False,
    jira_url: Any = None,
    jira_user: Any = None,
    jira_token: Any = None,
    servicenow_flag: bool = False,
    servicenow_instance: Any = None,
    servicenow_user: Any = None,
    servicenow_password: Any = None,
    slack_discover: bool = False,
    slack_bot_token: Any = None,
    **kwargs: Any,
) -> None:
    """Step 1h: cloud provider discovery + Step 1y: SaaS connector discovery + Step 1z: multi-source correlation."""
    con = ctx.con

    # Step 1h: Cloud provider discovery
    cloud_providers: list[tuple[str, dict]] = []
    if not skill_only and aws:
        aws_kwargs: dict = {"region": aws_region, "profile": aws_profile}
        if aws_include_lambda:
            aws_kwargs["include_lambda"] = True
        if aws_include_eks:
            aws_kwargs["include_eks"] = True
        if aws_include_step_functions:
            aws_kwargs["include_step_functions"] = True
        if aws_include_ec2:
            aws_kwargs["include_ec2"] = True
            if aws_ec2_tag and "=" in aws_ec2_tag:
                k, v = aws_ec2_tag.split("=", 1)
                aws_kwargs["ec2_tag_filter"] = {k: v}
        cloud_providers.append(("aws", aws_kwargs))
    if not skill_only and azure_flag:
        cloud_providers.append(("azure", {"subscription_id": azure_subscription}))
    if not skill_only and gcp_flag:
        cloud_providers.append(("gcp", {"project_id": gcp_project}))
    if not skill_only and coreweave_flag:
        cloud_providers.append(("coreweave", {"context": coreweave_context, "namespace": coreweave_namespace}))
    if not skill_only and databricks_flag:
        cloud_providers.append(("databricks", {}))
    if not skill_only and snowflake_flag:
        cloud_providers.append(("snowflake", {"authenticator": snowflake_authenticator} if snowflake_authenticator else {}))
    if not skill_only and nebius_flag:
        cloud_providers.append(("nebius", {"api_key": nebius_api_key, "project_id": nebius_project_id}))
    if not skill_only and hf_flag:
        cloud_providers.append(("huggingface", {"token": hf_token, "username": hf_username, "organization": hf_organization}))
    if not skill_only and wandb_flag:
        cloud_providers.append(("wandb", {"api_key": wandb_api_key, "entity": wandb_entity, "project": wandb_project}))
    if not skill_only and mlflow_flag:
        cloud_providers.append(("mlflow", {"tracking_uri": mlflow_tracking_uri}))
    if not skill_only and openai_flag:
        cloud_providers.append(("openai", {"api_key": openai_api_key, "organization": openai_org_id}))
    if not skill_only and ollama_flag:
        cloud_providers.append(("ollama", {"host": ollama_host}))

    for provider_name, provider_kwargs in cloud_providers:
        from agent_bom.cloud import CloudDiscoveryError, discover_from_provider

        con.print(f"\n[bold blue]Discovering agents from {provider_name.upper()}...[/bold blue]\n")
        try:
            cloud_agents, cloud_warnings = discover_from_provider(provider_name, **provider_kwargs)
            for w in cloud_warnings:
                con.print(f"  [yellow]⚠[/yellow] {w}")
            if cloud_agents:
                pkg_count = sum(a.total_packages for a in cloud_agents)
                con.print(f"  [green]✓[/green] {len(cloud_agents)} agent(s) discovered, {pkg_count} package(s) to scan")
                ctx.agents.extend(cloud_agents)
            else:
                con.print(f"  [dim]  No AI agents found in {provider_name.upper()}[/dim]")
        except CloudDiscoveryError as exc:
            con.print(f"\n  [red]{provider_name.upper()} discovery error: {exc}[/red]")

    # Step 1y: SaaS connector discovery
    saas_connectors: list[tuple[str, dict]] = []
    if not skill_only and jira_discover:
        saas_connectors.append(("jira", {"jira_url": jira_url, "email": jira_user, "api_token": jira_token}))
    if not skill_only and servicenow_flag:
        saas_connectors.append(
            ("servicenow", {"instance_url": servicenow_instance, "username": servicenow_user, "password": servicenow_password})
        )
    if not skill_only and slack_discover:
        saas_connectors.append(("slack", {"bot_token": slack_bot_token}))

    for connector_name, connector_kwargs in saas_connectors:
        from agent_bom.connectors import ConnectorError, discover_from_connector

        con.print(f"\n[bold blue]Discovering agents from {connector_name.upper()} connector...[/bold blue]\n")
        try:
            con_agents, con_warnings = discover_from_connector(connector_name, **connector_kwargs)
            for w in con_warnings:
                con.print(f"  [yellow]![/yellow] {w}")
            if con_agents:
                con.print(f"  [green]v[/green] {len(con_agents)} agent(s) discovered from {connector_name.upper()}")
                ctx.agents.extend(con_agents)
            else:
                con.print(f"  [dim]  No AI agents found in {connector_name.upper()}[/dim]")
        except ConnectorError as exc:
            con.print(f"\n  [red]{connector_name.upper()} connector error: {exc}[/red]")

    # Step 1z: Multi-source correlation (dedup + merge across sources)
    if not skill_only and ctx.agents:
        sources = {a.source or "local" for a in ctx.agents}
        if len(sources) > 1:
            from agent_bom.correlate import correlate_agents

            ctx.agents, corr_result = correlate_agents(ctx.agents)
            if corr_result.cross_source_matches:
                con.print(
                    f"\n  [bold]Correlated:[/bold] {corr_result.cross_source_matches} package(s) "
                    f"merged across {len(corr_result.source_summary)} source(s)"
                )


def run_benchmarks(
    ctx: ScanContext,
    *,
    skill_only: bool,
    verify_model_hashes: bool,
    project: Any,
    hf_token: Any,
    aws_cis_benchmark: bool,
    aws_region: Any,
    aws_profile: Any,
    snowflake_cis_benchmark: bool,
    snowflake_authenticator: Any,
    azure_cis_benchmark: bool,
    azure_subscription: Any,
    gcp_cis_benchmark: bool,
    gcp_project: Any,
    databricks_security: bool,
    aisvs_flag: bool,
    vector_db_scan: bool,
    gpu_scan_flag: bool,
    gpu_k8s_context: Any,
    no_dcgm_probe: bool,
    smithery_flag: bool,
    smithery_token: Any,
    mcp_registry_flag: bool,
    snyk_flag: bool,
    snyk_token: Any,
    snyk_org: Any,
    cortex_observability: bool,
    snowflake_flag: bool = False,
    **kwargs: Any,
) -> None:
    """Steps 1x–1z: model hash, CIS benchmarks, AISVS, vector DB, GPU, SaaS connectors."""
    con = ctx.con

    # Step 1x: Model hash verification (supply chain integrity)
    if verify_model_hashes:
        from pathlib import Path

        from agent_bom.model_hash import verify_model_hashes as _verify_hashes

        _scan_roots = [Path(project)] if project else [Path.home()]
        for _root in _scan_roots:
            with con.status(f"[bold]Verifying model weight hashes under {_root.name}...[/bold]", spinner="dots"):
                _hash_report = _verify_hashes(str(_root), token=hf_token)
            if _hash_report.scanned == 0:
                con.print(f"  [dim]No model weight files found under {_root}[/dim]")
            elif _hash_report.has_tampering:
                con.print(
                    f"  [red]⚠ SUPPLY_CHAIN_TAMPERING[/red] {_hash_report.tampered} tampered file(s) out of {_hash_report.scanned} scanned"
                )
                for r in _hash_report.results:
                    if r.is_tampered:
                        con.print(
                            f"    [red]✗[/red] {r.filename}"
                            f"  expected={(r.expected_sha256 or '?')[:16]}…"
                            f"  got={r.actual_sha256[:16] if r.actual_sha256 else '?'}…"
                        )
            elif _hash_report.offline > 0:
                con.print(f"  [yellow]~[/yellow] {_hash_report.scanned} file(s) found — HuggingFace Hub unreachable, hashes unverified")
            else:
                con.print(
                    f"  [green]✓[/green] {_hash_report.verified} model file(s) verified, {_hash_report.unverified} unverified (not in Hub)"
                )

    # Step 1y: CIS AWS Foundations Benchmark
    if aws_cis_benchmark:
        from agent_bom.cloud import CloudDiscoveryError

        con.print("\n[bold blue]Running CIS AWS Foundations Benchmark v3.0...[/bold blue]\n")
        try:
            from agent_bom.cloud.aws_cis_benchmark import run_benchmark as run_cis

            ctx.cis_benchmark_report = run_cis(region=aws_region, profile=aws_profile)
            passed = ctx.cis_benchmark_report.passed
            failed = ctx.cis_benchmark_report.failed
            total = ctx.cis_benchmark_report.total
            rate = ctx.cis_benchmark_report.pass_rate
            con.print(f"  [green]✓[/green] {total} checks evaluated — {passed} passed, {failed} failed ({rate:.0f}% pass rate)")
            if failed > 0:
                from rich.table import Table

                tbl = Table(title="CIS AWS Foundations Benchmark v3.0", show_lines=False, padding=(0, 1))
                tbl.add_column("Check", style="cyan", width=6)
                tbl.add_column("Title", min_width=30)
                tbl.add_column("Status", width=6)
                tbl.add_column("Severity", width=8)
                tbl.add_column("Evidence", max_width=50)
                _status_style = {"pass": "[green]PASS[/]", "fail": "[red]FAIL[/]", "error": "[yellow]ERR[/]"}
                _sev_style = {"critical": "[red]critical[/]", "high": "[bright_red]high[/]", "medium": "[yellow]medium[/]"}
                for c in ctx.cis_benchmark_report.checks:
                    tbl.add_row(
                        c.check_id,
                        c.title,
                        _status_style.get(c.status.value, c.status.value),
                        _sev_style.get(c.severity, c.severity),
                        c.evidence,
                    )
                con.print()
                con.print(tbl)
        except CloudDiscoveryError as exc:
            con.print(f"  [red]CIS Benchmark error: {exc}[/red]")

    # Step 1x-sf: CIS Snowflake Benchmark
    if snowflake_cis_benchmark:
        from agent_bom.cloud import CloudDiscoveryError as _SFCISError

        con.print("\n[bold blue]Running CIS Snowflake Benchmark v1.0...[/bold blue]\n")
        try:
            from agent_bom.cloud.snowflake_cis_benchmark import run_benchmark as run_sf_cis

            ctx.sf_cis_benchmark_report = run_sf_cis()
            passed = ctx.sf_cis_benchmark_report.passed
            failed = ctx.sf_cis_benchmark_report.failed
            total = ctx.sf_cis_benchmark_report.total
            rate = ctx.sf_cis_benchmark_report.pass_rate
            con.print(f"  [green]✓[/green] {total} checks evaluated — {passed} passed, {failed} failed ({rate:.0f}% pass rate)")
            if failed > 0:
                from rich.table import Table

                tbl = Table(title="CIS Snowflake Benchmark v1.0", show_lines=False, padding=(0, 1))
                tbl.add_column("Check", style="cyan", width=6)
                tbl.add_column("Title", min_width=30)
                tbl.add_column("Status", width=6)
                tbl.add_column("Severity", width=8)
                tbl.add_column("Evidence", max_width=50)
                _sf_status_style = {"pass": "[green]PASS[/]", "fail": "[red]FAIL[/]", "error": "[yellow]ERR[/]"}
                _sf_sev_style = {"critical": "[red]critical[/]", "high": "[bright_red]high[/]", "medium": "[yellow]medium[/]"}
                for c in ctx.sf_cis_benchmark_report.checks:
                    tbl.add_row(
                        c.check_id,
                        c.title,
                        _sf_status_style.get(c.status.value, c.status.value),
                        _sf_sev_style.get(c.severity, c.severity),
                        c.evidence,
                    )
                con.print()
                con.print(tbl)
        except _SFCISError as exc:
            con.print(f"  [red]CIS Snowflake Benchmark error: {exc}[/red]")

    # Step 1x-az: CIS Azure Benchmark
    if azure_cis_benchmark:
        from agent_bom.cloud import CloudDiscoveryError as _AZCISError

        con.print("\n[bold blue]Running CIS Azure Security Benchmark v3.0...[/bold blue]\n")
        try:
            from agent_bom.cloud.azure_cis_benchmark import run_benchmark as run_az_cis

            ctx.azure_cis_benchmark_report = run_az_cis()
            passed = ctx.azure_cis_benchmark_report.passed
            failed = ctx.azure_cis_benchmark_report.failed
            total = ctx.azure_cis_benchmark_report.total
            rate = ctx.azure_cis_benchmark_report.pass_rate
            con.print(f"  [green]✓[/green] {total} checks evaluated — {passed} passed, {failed} failed ({rate:.0f}% pass rate)")
            if failed > 0:
                from rich.table import Table

                tbl = Table(title="CIS Azure Security Benchmark v3.0", show_lines=False, padding=(0, 1))
                tbl.add_column("Check", style="cyan", width=6)
                tbl.add_column("Title", min_width=30)
                tbl.add_column("Status", width=6)
                tbl.add_column("Severity", width=8)
                tbl.add_column("ATT&CK", width=20)
                tbl.add_column("Evidence", max_width=40)
                _az_status = {"pass": "[green]PASS[/]", "fail": "[red]FAIL[/]", "error": "[yellow]ERR[/]"}
                _az_sev = {"critical": "[red]critical[/]", "high": "[bright_red]high[/]", "medium": "[yellow]medium[/]"}
                from agent_bom.mitre_attack import tag_cis_check

                for c in ctx.azure_cis_benchmark_report.checks:
                    attack = ", ".join(tag_cis_check(c)) or "-"
                    tbl.add_row(
                        c.check_id,
                        c.title,
                        _az_status.get(c.status.value, c.status.value),
                        _az_sev.get(c.severity, c.severity),
                        attack,
                        c.evidence,
                    )
                con.print()
                con.print(tbl)
        except _AZCISError as exc:
            con.print(f"  [red]CIS Azure Benchmark error: {exc}[/red]")

    # Step 1x-gcp: CIS GCP Benchmark
    if gcp_cis_benchmark:
        from agent_bom.cloud import CloudDiscoveryError as _GCPCISError

        con.print("\n[bold blue]Running CIS GCP Foundation Benchmark v3.0...[/bold blue]\n")
        try:
            from agent_bom.cloud.gcp_cis_benchmark import run_benchmark as run_gcp_cis

            ctx.gcp_cis_benchmark_report = run_gcp_cis()
            passed = ctx.gcp_cis_benchmark_report.passed
            failed = ctx.gcp_cis_benchmark_report.failed
            total = ctx.gcp_cis_benchmark_report.total
            rate = ctx.gcp_cis_benchmark_report.pass_rate
            con.print(f"  [green]✓[/green] {total} checks evaluated — {passed} passed, {failed} failed ({rate:.0f}% pass rate)")
            if failed > 0:
                from rich.table import Table

                tbl = Table(title="CIS GCP Foundation Benchmark v3.0", show_lines=False, padding=(0, 1))
                tbl.add_column("Check", style="cyan", width=6)
                tbl.add_column("Title", min_width=30)
                tbl.add_column("Status", width=6)
                tbl.add_column("Severity", width=8)
                tbl.add_column("ATT&CK", width=20)
                tbl.add_column("Evidence", max_width=40)
                _gcp_status = {"pass": "[green]PASS[/]", "fail": "[red]FAIL[/]", "error": "[yellow]ERR[/]"}
                _gcp_sev = {"critical": "[red]critical[/]", "high": "[bright_red]high[/]", "medium": "[yellow]medium[/]"}
                from agent_bom.mitre_attack import tag_cis_check as _tag_gcp

                for c in ctx.gcp_cis_benchmark_report.checks:
                    attack = ", ".join(_tag_gcp(c)) or "-"
                    tbl.add_row(
                        c.check_id,
                        c.title,
                        _gcp_status.get(c.status.value, c.status.value),
                        _gcp_sev.get(c.severity, c.severity),
                        attack,
                        c.evidence,
                    )
                con.print()
                con.print(tbl)
        except _GCPCISError as exc:
            con.print(f"  [red]CIS GCP Benchmark error: {exc}[/red]")

    # Step 1x-db: Databricks Security Best Practices
    if databricks_security:
        from agent_bom.cloud import CloudDiscoveryError as _DBSecError

        con.print("\n[bold blue]Running Databricks Security Best Practices checks...[/bold blue]\n")
        try:
            import os

            from agent_bom.cloud.databricks_security import run_security_checks as run_db_sec

            _db_host = os.environ.get("DATABRICKS_HOST")
            _db_token = os.environ.get("DATABRICKS_TOKEN")
            ctx.databricks_security_report = run_db_sec(host=_db_host, token=_db_token)
            passed = ctx.databricks_security_report.passed
            failed = ctx.databricks_security_report.failed
            total = ctx.databricks_security_report.total
            rate = ctx.databricks_security_report.pass_rate
            con.print(f"  [green]✓[/green] {total} checks evaluated — {passed} passed, {failed} failed ({rate:.0f}% pass rate)")
            if failed > 0:
                from rich.table import Table

                tbl = Table(title="Databricks Security Best Practices", show_lines=False, padding=(0, 1))
                tbl.add_column("Check", style="cyan", width=6)
                tbl.add_column("Title", min_width=30)
                tbl.add_column("Status", width=6)
                tbl.add_column("Severity", width=8)
                tbl.add_column("ATT&CK", width=20)
                tbl.add_column("Evidence", max_width=40)
                _db_status = {"pass": "[green]PASS[/]", "fail": "[red]FAIL[/]", "error": "[yellow]ERR[/]"}
                _db_sev = {"critical": "[red]critical[/]", "high": "[bright_red]high[/]", "medium": "[yellow]medium[/]"}
                from agent_bom.mitre_attack import tag_cis_check as _tag_db

                for c in ctx.databricks_security_report.checks:
                    attack = ", ".join(_tag_db(c)) or "-"
                    tbl.add_row(
                        c.check_id,
                        c.title,
                        _db_status.get(c.status.value, c.status.value),
                        _db_sev.get(c.severity, c.severity),
                        attack,
                        c.evidence,
                    )
                con.print()
                con.print(tbl)
        except _DBSecError as exc:
            con.print(f"  [red]Databricks security check error: {exc}[/red]")

    # Step 1x-b: Vector DB scan
    if vector_db_scan:
        from rich.table import Table as _RTable

        con.print("\n[bold blue]Scanning for vector databases...[/bold blue]\n")
        try:
            from agent_bom.cloud.vector_db import discover_pinecone, discover_vector_dbs

            vector_db_results = discover_vector_dbs()
            pinecone_results = discover_pinecone()
            ctx.vector_db_results = vector_db_results
            if not vector_db_results and not pinecone_results:
                con.print("  [dim]No running vector databases found. Set PINECONE_API_KEY to scan Pinecone.[/dim]")
            else:
                total = len(vector_db_results) + len(pinecone_results)
                con.print(f"  Found [bold]{total}[/bold] vector database(s)")
                tbl = _RTable(title="Vector DB Security", show_lines=True)
                tbl.add_column("DB", width=10)
                tbl.add_column("Instance", width=20)
                tbl.add_column("Auth", width=8)
                tbl.add_column("Risk", width=10)
                tbl.add_column("Flags")
                _vdb_risk = {
                    "critical": "[red]critical[/]",
                    "high": "[bright_red]high[/]",
                    "medium": "[yellow]medium[/]",
                    "safe": "[green]safe[/]",
                }
                for vdb_r in vector_db_results:
                    tbl.add_row(
                        vdb_r.db_type,
                        f"{vdb_r.host}:{vdb_r.port}",
                        "[green]yes[/]" if vdb_r.requires_auth else "[red]NO[/]",
                        _vdb_risk.get(vdb_r.risk_level, vdb_r.risk_level),
                        ", ".join(vdb_r.risk_flags) or "-",
                    )
                for pine_r in pinecone_results:
                    tbl.add_row(
                        "pinecone",
                        pine_r.index_name,
                        "[green]API key[/]",
                        _vdb_risk.get(pine_r.risk_level, pine_r.risk_level),
                        ", ".join(pine_r.risk_flags) or "-",
                    )
                con.print()
                con.print(tbl)
        except Exception as exc:
            con.print(f"  [red]Vector DB scan error: {exc}[/red]")

    # Step 1x-b2: GPU infra scan
    if gpu_scan_flag:
        import asyncio as _asyncio

        from rich.table import Table as _RTable

        con.print("\n[bold blue]Scanning GPU/AI compute infrastructure...[/bold blue]\n")
        try:
            from agent_bom.cloud.gpu_infra import gpu_infra_to_agents, scan_gpu_infra

            with con.status("[bold]Probing Docker, K8s, and DCGM endpoints...[/bold]", spinner="dots"):
                ctx.gpu_infra_report = _asyncio.run(scan_gpu_infra(k8s_context=gpu_k8s_context, probe_dcgm=not no_dcgm_probe))
            for w in ctx.gpu_infra_report.warnings:
                con.print(f"  [yellow]⚠[/yellow] {w}")
            gpu_agents = gpu_infra_to_agents(ctx.gpu_infra_report)
            if gpu_agents:
                ctx.agents.extend(gpu_agents)
                con.print(
                    f"  [green]✓[/green] {ctx.gpu_infra_report.total_gpu_containers} GPU container(s), "
                    f"{len(ctx.gpu_infra_report.gpu_nodes)} K8s GPU node(s)"
                )
                if ctx.gpu_infra_report.unique_cuda_versions:
                    con.print(f"  CUDA versions: {', '.join(ctx.gpu_infra_report.unique_cuda_versions)}")
                if ctx.gpu_infra_report.unauthenticated_dcgm_count:
                    con.print(
                        f"  [red]⚠ {ctx.gpu_infra_report.unauthenticated_dcgm_count} unauthenticated DCGM exporter(s) — metrics leak[/red]"
                    )
                if ctx.gpu_infra_report.dcgm_endpoints:
                    tbl = _RTable(title="DCGM Endpoints", show_lines=False)
                    tbl.add_column("Host", width=20)
                    tbl.add_column("Port", width=8)
                    tbl.add_column("Auth", width=8)
                    tbl.add_column("GPUs", width=6)
                    for ep in ctx.gpu_infra_report.dcgm_endpoints:
                        tbl.add_row(
                            ep.host,
                            str(ep.port),
                            "[green]yes[/]" if ep.authenticated else "[red]NO[/]",
                            str(ep.gpu_count) if ep.gpu_count is not None else "?",
                        )
                    con.print()
                    con.print(tbl)
            else:
                con.print("  [dim]No GPU containers or K8s GPU nodes found[/dim]")
        except Exception as exc:
            con.print(f"  [red]GPU scan error: {exc}[/red]")

    # Step 1x-c: AISVS compliance benchmark
    if aisvs_flag:
        from rich.table import Table as _RTable

        con.print("\n[bold blue]Running AISVS v1.0 compliance checks...[/bold blue]\n")
        try:
            from agent_bom.cloud.aisvs_benchmark import run_benchmark as _run_aisvs

            ctx.aisvs_report = _run_aisvs()
            passed = ctx.aisvs_report.passed
            failed = ctx.aisvs_report.failed
            total = ctx.aisvs_report.total
            rate = ctx.aisvs_report.pass_rate
            con.print(
                f"  [bold]AISVS v1.0[/bold]: {passed}/{total} checks passed "
                f"([{'green' if rate >= 80 else 'yellow' if rate >= 50 else 'red'}]{rate:.1f}%[/])"
            )
            tbl = _RTable(title="AISVS Compliance", show_lines=True)
            tbl.add_column("Check", width=8)
            tbl.add_column("Title", max_width=45)
            tbl.add_column("Status", width=8)
            tbl.add_column("Sev", width=8)
            tbl.add_column("MAESTRO", width=22)
            tbl.add_column("Evidence", max_width=40)
            _aiv_status = {
                "pass": "[green]PASS[/]",
                "fail": "[red]FAIL[/]",
                "error": "[yellow]ERR[/]",
                "not_applicable": "[dim]N/A[/]",
            }
            from agent_bom.maestro import tag_aisvs_check as _maestro_tag

            for c in ctx.aisvs_report.checks:
                maestro = _maestro_tag(c.check_id).value
                tbl.add_row(
                    c.check_id,
                    c.title,
                    _aiv_status.get(c.status.value, c.status.value),
                    c.severity,
                    maestro,
                    c.evidence,
                )
            con.print()
            con.print(tbl)
        except Exception as exc:
            con.print(f"  [red]AISVS benchmark error: {exc}[/red]")
