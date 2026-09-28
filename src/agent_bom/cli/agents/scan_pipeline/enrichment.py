"""Stage 6: optional external enrichment of the matched inventory."""

from __future__ import annotations

from pathlib import Path

from agent_bom.cli.agents.scan_pipeline.options import ScanOptions
from agent_bom.cli.agents.scan_pipeline.state import ScanState


def _enrich_snyk(opts: ScanOptions, st: ScanState) -> None:
    # Step 4a: Snyk vulnerability enrichment (optional)
    if opts.snyk_flag and not opts.no_scan and st.total_packages > 0:
        all_pkgs_for_snyk = [p for a in st.agents for s in a.mcp_servers for p in s.packages]
        if opts.snyk_token:
            try:
                from agent_bom.snyk import enrich_with_snyk_sync

                st.con.print("\n[bold blue]Enriching with Snyk vulnerability data...[/bold blue]\n")
                with st.con.status("[bold]Querying Snyk...[/bold]", spinner="dots"):
                    snyk_count = enrich_with_snyk_sync(all_pkgs_for_snyk, token=opts.snyk_token, org_id=opts.snyk_org)
                if snyk_count:
                    st.con.print(f"  [green]✓[/green] Snyk: {snyk_count} additional vulnerability(ies) found")
                else:
                    st.con.print("  [dim]  Snyk: no additional vulnerabilities found[/dim]")
            except Exception as exc:
                st.con.print(f"  [yellow]⚠[/yellow] Snyk enrichment failed: {exc}")
        else:
            st.con.print("\n[yellow]  --snyk requires SNYK_TOKEN (set env var or use --snyk-token)[/yellow]")


def _enrich_scorecard(opts: ScanOptions, st: ScanState) -> None:
    # Step 4b: OpenSSF Scorecard enrichment (optional)
    if opts.scorecard_flag and opts.enrich and not opts.quiet:
        st.con.print("\n[dim]  OpenSSF Scorecard enrichment is already included in --enrich[/dim]")
    elif opts.scorecard_flag and not opts.no_scan:
        all_pkgs_for_sc = [p for a in st.agents for s in a.mcp_servers for p in s.packages]
        if all_pkgs_for_sc:
            import asyncio as _asyncio_sc

            from agent_bom.http_client import create_client as _scorecard_client
            from agent_bom.resolver import enrich_supply_chain_metadata as _scorecard_meta
            from agent_bom.scorecard import enrich_packages_with_scorecard_stats

            st.con.print("\n[bold blue]Enriching with OpenSSF Scorecard data...[/bold blue]\n")
            try:

                async def _do_scorecard():
                    async with _scorecard_client(timeout=15.0) as client:
                        await _scorecard_meta(all_pkgs_for_sc, client)
                    return await enrich_packages_with_scorecard_stats(all_pkgs_for_sc)

                sc_stats = _asyncio_sc.run(_do_scorecard())
                if sc_stats.enriched_packages:
                    st.con.print(
                        "  [green]✓[/green] "
                        f"Scorecard: enriched {sc_stats.enriched_packages}/{sc_stats.eligible_packages} eligible package(s)"
                    )
                elif sc_stats.eligible_packages == 0:
                    st.con.print("  [dim]  Scorecard: no packages with resolvable GitHub repos[/dim]")
                else:
                    detail = []
                    if getattr(sc_stats, "transient_failed_packages", 0):
                        detail.append(f"{sc_stats.transient_failed_packages} transient")
                    if getattr(sc_stats, "persistent_failed_packages", 0):
                        detail.append(f"{sc_stats.persistent_failed_packages} persistent")
                    failure_detail = ", ".join(detail) if detail else f"{sc_stats.failed_packages} lookup failures"
                    st.con.print(
                        f"  [yellow]⚠[/yellow] Scorecard: 0/{sc_stats.eligible_packages} eligible package(s) enriched ({failure_detail})"
                    )
            except Exception as exc:
                st.con.print(f"  [yellow]⚠[/yellow] Scorecard enrichment failed: {exc}")


def _verify_integrity(opts: ScanOptions, st: ScanState) -> None:
    # Step 4c: Integrity + provenance verification (optional)
    if opts.verify_integrity:
        import asyncio as _asyncio

        from agent_bom.http_client import create_client as _create_client
        from agent_bom.integrity import verify_packages

        all_pkgs = [pkg for agent in st.agents for srv in agent.mcp_servers for pkg in srv.packages]
        unique_pkgs = {f"{p.ecosystem}:{p.name}@{p.version}": p for p in all_pkgs if p.version not in ("latest", "unknown", "")}

        async def _verify_all():
            # The verdict is applied by the shared helper — the MCP path
            # calls the same one — so this only renders what it decided.
            async with _create_client(timeout=15.0) as client:
                for result in await verify_packages(all_pkgs, client):
                    pkg = result.package
                    if result.integrity is not None:
                        if pkg.integrity_verified:
                            st.con.print(f"  [green]✓[/green] {pkg.name}@{pkg.version} — integrity verified (SHA256/SRI)")
                        else:
                            st.con.print(f"  [yellow]⚠[/yellow] {pkg.name}@{pkg.version} — no integrity hash found")

                    if result.provenance is not None:
                        if pkg.provenance_attested:
                            st.con.print(f"  [green]✓[/green] {pkg.name}@{pkg.version} — SLSA provenance attested")
                        else:
                            prov_status = str(result.provenance.get("status") or "")
                            if prov_status == "unavailable":
                                st.con.print(f"  [yellow]⚠[/yellow] {pkg.name}@{pkg.version} — provenance service unavailable")
                            elif prov_status == "not_provenance":
                                st.con.print(
                                    f"  [dim]  {pkg.name}@{pkg.version} — attestations present, but none were SLSA provenance[/dim]"
                                )
                            else:
                                st.con.print(f"  [dim]  {pkg.name}@{pkg.version} — no SLSA provenance[/dim]")

        if unique_pkgs:
            st.con.print(f"\n[bold blue]🔐 Verifying integrity for {len(unique_pkgs)} package(s)...[/bold blue]\n")
            _asyncio.run(_verify_all())


def _verify_instructions(opts: ScanOptions, st: ScanState) -> None:
    # Step 4d: Instruction file provenance verification (optional)
    _instruction_provenance_data: list = []
    if opts.verify_instructions:
        from agent_bom.integrity import discover_instruction_files, verify_instruction_files_batch

        project_root = Path(opts.project or ".").resolve()
        instr_files = discover_instruction_files(project_root)
        if instr_files:
            st.con.print(f"\n[bold blue]🔏 Verifying instruction file provenance ({len(instr_files)} file(s))...[/bold blue]\n")
            instr_paths: list[str | Path] = list(instr_files)
            verifications = verify_instruction_files_batch(instr_paths)
            for verification in verifications:
                rel_path = (
                    str(Path(verification.file_path).relative_to(project_root))
                    if verification.file_path.startswith(str(project_root))
                    else verification.file_path
                )
                if verification.verified:
                    st.con.print(f"  [green]✓[/green] {rel_path} — provenance verified ({verification.reason})")
                elif verification.has_sigstore_bundle:
                    st.con.print(f"  [yellow]⚠[/yellow] {rel_path} — bundle found but invalid ({verification.reason})")
                else:
                    st.con.print(f"  [dim]  {rel_path} — unsigned (sha256: {verification.sha256[:12]}...)[/dim]")
                _instruction_provenance_data.append(
                    {
                        "file": rel_path,
                        "sha256": verification.sha256,
                        "verified": verification.verified,
                        "has_bundle": verification.has_sigstore_bundle,
                        "signer": verification.signer_identity,
                        "rekor_index": verification.rekor_log_index,
                        "reason": verification.reason,
                    }
                )
        else:
            st.con.print("\n  [dim]No instruction files found to verify.[/dim]")


def _fetch_cortex_telemetry(opts: ScanOptions, st: ScanState) -> None:
    # Step 4e: Cortex agent observability (optional)
    _cortex_telemetry_data = None
    if opts.cortex_observability and opts.snowflake_flag:
        try:
            from agent_bom.cloud.snowflake import _get_connection  # type: ignore[attr-defined]
            from agent_bom.cloud.snowflake_observability import get_cortex_telemetry

            st.con.print("\n[bold blue]📊 Fetching Cortex agent observability telemetry...[/bold blue]\n")
            sf_conn = _get_connection()
            _cortex_telemetry_data = get_cortex_telemetry(sf_conn, hours=24)
            sf_conn.close()

            agent_count = len(_cortex_telemetry_data.get("agents", []))
            if agent_count:
                st.con.print(f"  [green]✓[/green] {agent_count} Cortex agent(s) with telemetry")
                for ag in _cortex_telemetry_data["agents"]:
                    status_color = {"healthy": "green", "degraded": "yellow", "unhealthy": "red"}.get(ag["health"]["status"], "dim")
                    st.con.print(
                        f"    [{status_color}]●[/{status_color}] {ag['name']}: {ag['total_calls']} calls, {ag['health']['status']}"
                    )
            else:
                st.con.print("  [dim]No Cortex agent telemetry found.[/dim]")
        except Exception as exc:
            st.con.print(f"  [yellow]⚠[/yellow] Cortex observability failed: {exc}")


def run_enrichment(opts: ScanOptions, st: ScanState) -> None:
    """Optional Snyk, Scorecard, integrity, provenance and Cortex enrichment."""
    if opts.skill_only:
        return
    _enrich_snyk(opts, st)
    _enrich_scorecard(opts, st)
    _verify_integrity(opts, st)
    _verify_instructions(opts, st)
    _fetch_cortex_telemetry(opts, st)
