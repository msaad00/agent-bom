"""Stage 4: extract, resolve and annotate the package inventory."""

from __future__ import annotations

import sys
import time as _time
from contextlib import nullcontext as _nullcontext
from typing import Any

from agent_bom.cli.agents.scan_pipeline.helpers import _agents_patchable, _expand_docker_mcp_packages
from agent_bom.cli.agents.scan_pipeline.options import ScanOptions
from agent_bom.cli.agents.scan_pipeline.state import ScanState


def _begin_inventory(opts: ScanOptions, st: ScanState) -> None:
    # Step 2: Extract packages
    st.step_t0 = _time.monotonic()
    st.total_packages = 0
    # These enrichment results are consumed while building every report,
    # including the focused --skill-only path that skips package extraction.
    st.intro_report = None
    st.hc_results = None


def _extract_packages(opts: ScanOptions, st: ScanState) -> None:
    from rich.rule import Rule

    st.con.print()
    st.con.print(Rule("Package Extraction", style="blue"))
    st.con.print()
    if opts.transitive:
        st.con.print(f"  [cyan]Transitive resolution enabled (max depth: {opts.max_depth})[/cyan]\n")
    docker_image_cache: dict[str, list[Any]] = {}
    st.docker_image_failures = []

    for agent in st.agents:
        for server in agent.mcp_servers:
            if server.security_blocked:
                if not opts.quiet:
                    from agent_bom.security import sanitize_security_warnings

                    warnings = ", ".join(sanitize_security_warnings(server.security_warnings))
                    st.con.print(f"    [yellow]⚠ {server.name}: blocked — {warnings}[/yellow]")
                continue
            pre_populated = list(server.packages)
            if server.command == "external-scan":
                # An imported report is its own inventory; its path argument
                # is not a server directory whose manifests should be parsed.
                st.total_packages += len(server.packages)
                continue
            if (opts.self_scan or opts.demo) and pre_populated:
                server.packages = pre_populated
                st.total_packages += len(server.packages)
                if opts.verbose and server.packages:
                    inventory_label = "demo inventory" if opts.demo else "self-scan inventory"
                    st.con.print(
                        f"  [green]✓[/green] {server.name}: {len(server.packages)} package(s) "
                        f"({server.packages[0].ecosystem}) [dim]({inventory_label})[/dim]"
                    )
                continue
            _smithery_tok = opts.smithery_token if opts.smithery_flag else None
            if not opts.quiet:
                st.con.print(f"  [dim]Extracting packages from {agent.name}/{server.name}...[/dim]")
            discovered = _agents_patchable("extract_packages")(
                server,
                resolve_transitive=opts.transitive,
                max_depth=opts.max_depth,
                smithery_token=_smithery_tok,
                mcp_registry=opts.mcp_registry_flag,
            )
            from agent_bom.image import scan_image

            discovered, expansion_failures = _expand_docker_mcp_packages(
                server=server,
                discovered=discovered,
                docker_image_cache=docker_image_cache,
                scan_image_fn=scan_image,
                registry_user=opts.registry_user,
                registry_pass=opts.registry_pass,
                image_platform=opts.image_platform,
            )
            for failure in expansion_failures:
                if failure not in st.docker_image_failures:
                    st.docker_image_failures.append(failure)

            discovered_names = {(p.name, p.ecosystem) for p in discovered}
            merged = discovered + [p for p in pre_populated if (p.name, p.ecosystem) not in discovered_names]
            server.packages = merged

            st.total_packages += len(server.packages)
            if opts.verbose and server.packages:
                direct_count = sum(1 for p in server.packages if p.is_direct)
                transitive_count = len(server.packages) - direct_count
                transitive_str = f" ({transitive_count} transitive)" if transitive_count > 0 else ""
                pre_str = f" ({len(pre_populated)} from inventory)" if pre_populated else ""
                st.con.print(
                    f"  [green]✓[/green] {server.name}: {len(server.packages)} package(s) "
                    f"({server.packages[0].ecosystem}){transitive_str}{pre_str}"
                )


def _summarize_packages(opts: ScanOptions, st: ScanState) -> None:
    # Compact summary (non-verbose shows one line, verbose shows per-server)
    eco_counts: dict[str, int] = {}
    for a in st.ctx.agents:
        for s in a.mcp_servers:
            for p in s.packages:
                eco_counts[p.ecosystem] = eco_counts.get(p.ecosystem, 0) + 1
    eco_str = ", ".join(f"{c} {e}" for e, c in sorted(eco_counts.items(), key=lambda x: -x[1]))
    st.con.print(
        f"\n  [bold]{st.total_packages}[/bold] packages ({eco_str})" if eco_str else f"\n  [bold]{st.total_packages}[/bold] packages"
    )
    if st.docker_image_failures:
        for failure in st.docker_image_failures:
            st.con.print(f"  [yellow]⚠[/yellow] {failure}")
        st.con.print("  [red]Docker MCP image expansion failed; refusing to report a clean result from image stubs only.[/red]")
        sys.exit(2)


def _resolve_deps_dev(opts: ScanOptions, st: ScanState) -> None:
    # Step 2a: deps.dev transitive resolution + license enrichment (--deps-dev)
    if opts.deps_dev:
        import asyncio as _asyncio_dd

        from agent_bom.deps_dev import enrich_licenses_deps_dev, resolve_transitive_deps_dev

        all_pkgs = [pkg for agent in st.agents for server in agent.mcp_servers for pkg in server.packages]
        direct_pkgs = [p for p in all_pkgs if p.is_direct]
        if direct_pkgs:
            st.con.print("\n  [cyan]deps.dev: resolving transitive dependencies...[/cyan]")
            transitive_pkgs = _asyncio_dd.run(resolve_transitive_deps_dev(direct_pkgs, max_depth=opts.max_depth))
            if transitive_pkgs:
                pkg_parent_map: dict[str, list] = {}
                for tp in transitive_pkgs:
                    pkg_parent_map.setdefault(tp.parent_package or "", []).append(tp)
                for agent in st.agents:
                    for server in agent.mcp_servers:
                        existing_names = {(p.name, p.version, p.ecosystem) for p in server.packages}
                        for sp in server.packages:
                            if sp.is_direct and sp.name in pkg_parent_map:
                                for tp in pkg_parent_map[sp.name]:
                                    if (tp.name, tp.version, tp.ecosystem) not in existing_names:
                                        server.packages.append(tp)
                                        existing_names.add((tp.name, tp.version, tp.ecosystem))
                st.con.print(f"  [green]✓[/green] deps.dev: {len(transitive_pkgs)} transitive dependencies resolved")

            all_pkgs_updated = [pkg for agent in st.agents for server in agent.mcp_servers for pkg in server.packages]
            lic_count = _asyncio_dd.run(enrich_licenses_deps_dev(all_pkgs_updated))
            if lic_count:
                st.con.print(f"  [green]✓[/green] deps.dev: {lic_count} package license(s) enriched")

            try:
                from agent_bom.http_client import create_client as _sc_client
                from agent_bom.resolver import enrich_supply_chain_metadata as _sc_enrich

                async def _do_sc_enrich() -> int:
                    async with _sc_client(timeout=15.0) as client:
                        return await _sc_enrich(all_pkgs_updated, client)

                sc_count = _asyncio_dd.run(_do_sc_enrich())
                if sc_count:
                    st.con.print(f"  [green]✓[/green] supply chain: {sc_count} package metadata enriched")
            except Exception:  # noqa: BLE001
                pass


def _introspect_servers(opts: ScanOptions, st: ScanState) -> None:
    # Step 2b: MCP Runtime Introspection (--introspect)
    _enforcement_data: dict | None = None
    if opts.introspect:
        from agent_bom.mcp_introspect import IntrospectionError, enrich_servers, introspect_servers_sync

        all_servers = [s for a in st.agents for s in a.mcp_servers]
        st.con.print(f"\n[bold blue]Introspecting {len(all_servers)} MCP server(s)...[/bold blue]\n")
        try:
            intro_report = introspect_servers_sync(all_servers, timeout=opts.introspect_timeout)
            for w in intro_report.warnings:
                st.con.print(f"  [yellow]⚠[/yellow] {w}")
            for intro_r in intro_report.results:
                if intro_r.success:
                    drift_str = ""
                    if intro_r.has_drift:
                        parts = []
                        if intro_r.tools_added:
                            parts.append(f"+{len(intro_r.tools_added)} tools")
                        if intro_r.tools_removed:
                            parts.append(f"-{len(intro_r.tools_removed)} tools")
                        if intro_r.resources_added:
                            parts.append(f"+{len(intro_r.resources_added)} resources")
                        if intro_r.resources_removed:
                            parts.append(f"-{len(intro_r.resources_removed)} resources")
                        drift_str = f" [yellow]drift: {', '.join(parts)}[/yellow]"
                    st.con.print(
                        f"  [green]✓[/green] {intro_r.server_name}:"
                        f" {intro_r.tool_count} tools, {intro_r.resource_count} resources{drift_str}"
                    )
                else:
                    st.con.print(f"  [dim]  {intro_r.server_name}: {intro_r.error}[/dim]")
            enriched = enrich_servers(all_servers, intro_report)
            if enriched:
                st.con.print(f"\n  [bold]{enriched} server(s) enriched with runtime data.[/bold]")
            st.intro_report = intro_report
        except IntrospectionError as exc:
            st.con.print(f"  [yellow]⚠[/yellow] {exc}")


def _health_check_servers(opts: ScanOptions, st: ScanState) -> None:
    # Step 2b-hc: Post-discovery health checks (--health-check)
    if opts.health_check:
        from agent_bom.mcp_introspect import IntrospectionError as _HCError
        from agent_bom.mcp_introspect import health_check_servers_sync

        hc_servers = [s for a in st.agents for s in a.mcp_servers]
        st.con.print(f"\n[bold blue]Health-checking {len(hc_servers)} MCP server(s)...[/bold blue]\n")
        try:
            hc_results = health_check_servers_sync(hc_servers, timeout=opts.hc_timeout)
            reachable = sum(1 for h in hc_results if h.reachable)
            for h in hc_results:
                if h.reachable:
                    latency_str = f" {h.latency_ms:.0f}ms" if h.latency_ms is not None else ""
                    proto_str = f" [{h.protocol_version}]" if h.protocol_version else ""
                    st.con.print(f"  [green]✓[/green] {h.server_name}: {h.tool_count} tool(s){latency_str}{proto_str}")
                else:
                    st.con.print(f"  [red]✗[/red] {h.server_name}: {h.error or 'unreachable'}")
            st.con.print(f"\n  [bold]{reachable}/{len(hc_results)} server(s) reachable.[/bold]")
            st.hc_results = hc_results
        except _HCError as exc:
            st.con.print(f"  [yellow]⚠[/yellow] {exc}")


def _scan_descriptions_and_enforce(opts: ScanOptions, st: ScanState) -> None:
    # Step 2c: Passive tool/resource description poisoning detection.
    # These surfaces are already in the discovered config and require no
    # active connection or policy action, so their findings must not depend
    # on the broader --enforce mode.
    from agent_bom.enforcement import scan_description_surfaces

    _description_report = scan_description_surfaces([s for a in st.agents for s in a.mcp_servers])
    if _description_report.findings:
        _enforcement_data = _description_report.to_dict()
        st.ctx.enforcement_data = _enforcement_data

    # Step 2d: Full tool poisoning detection + enforcement (--enforce)
    if opts.enforce:
        from agent_bom.enforcement import run_enforcement

        all_enforce_servers = [s for a in st.agents for s in a.mcp_servers]
        st.con.print(f"\n[bold blue]Running enforcement checks on {len(all_enforce_servers)} server(s)...[/bold blue]\n")
        enforce_result = run_enforcement(
            servers=all_enforce_servers,
            introspection_report=st.intro_report,
        )
        _enforcement_data = enforce_result.to_dict()
        if enforce_result.findings:
            from rich.table import Table

            etable = Table(title="Enforcement Findings", show_lines=False)
            etable.add_column("Severity", width=10)
            etable.add_column("Category", width=16)
            etable.add_column("Server", width=20)
            etable.add_column("Tool", width=16)
            etable.add_column("Reason")
            sev_colors = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "dim"}
            for f in enforce_result.findings:
                etable.add_row(
                    f"[{sev_colors.get(f.severity, 'white')}]{f.severity.upper()}[/]",
                    f.category,
                    f.server_name,
                    f.tool_name or "—",
                    f.reason,
                )
            st.con.print(etable)
        status = "[green]PASS[/green]" if enforce_result.passed else "[red]FAIL[/red]"
        st.con.print(f"\n  Enforcement: {status} ({enforce_result.critical_count} critical, {enforce_result.high_count} high)")
        st.ctx.enforcement_data = _enforcement_data


def _fold_external_packages(opts: ScanOptions, st: ScanState) -> None:
    if opts.external_scan_path:
        # After extraction so native packages exist to fold external evidence onto.
        from agent_bom.parsers.external_import import fold_external_packages

        _pkg_count_before_fold = sum(len(s.packages) for a in st.agents for s in a.mcp_servers)
        for _notice in fold_external_packages(st.agents, findings=st.ctx.external_findings):
            st.ctx.scan_notices.append({"code": "external_package_unresolved", "source": "external-scan", "message": _notice})
            if not opts.quiet:
                st.con.print(f"  [yellow]![/yellow] {_notice}")
        st.total_packages -= _pkg_count_before_fold - sum(len(s.packages) for a in st.agents for s in a.mcp_servers)


def _resolve_versions(opts: ScanOptions, st: ScanState) -> None:
    # Step 3: Resolve unknown versions (skip in offline mode AND --no-scan)
    st.all_packages = [p for a in st.agents for s in a.mcp_servers for p in s.packages]
    st.unresolved = [p for p in st.all_packages if p.version in ("latest", "unknown", "")]
    if st.unresolved and not opts.offline and not opts.no_scan:
        if not opts.quiet:
            st.con.print(f"\n[bold blue]Resolving {len(st.unresolved)} package version(s)...[/bold blue]\n")
        with st.con.status("[bold]Querying package registries...[/bold]", spinner="dots") if not opts.quiet else _nullcontext():
            resolved = _agents_patchable("resolve_all_versions_sync")(
                st.all_packages,
                quiet=opts.quiet,
                enrich_license_metadata=opts.enrich,
            )
        if not opts.quiet:
            resolved_count = int(resolved or 0)
            fallback_count = sum(1 for p in st.unresolved if p.version_source == "registry_fallback")
            unresolved_after = sum(1 for p in st.unresolved if p.version in ("latest", "unknown", ""))
            live_count = max(resolved_count - fallback_count, 0)
            st.con.print(f"\n  [bold]Resolved {resolved_count}/{len(st.unresolved)} version(s).[/bold]")
            if live_count:
                st.con.print(f"  [green]✓[/green] {live_count} resolved from live registries")
            if fallback_count:
                st.con.print(f"  [yellow]↺[/yellow] {fallback_count} preserved via bundled registry fallback")
            if unresolved_after:
                st.con.print(
                    "  [yellow]⚠[/yellow] "
                    f"{unresolved_after} package(s) remain unresolved — "
                    "downstream scan coverage is partial for those packages"
                )
    elif st.unresolved and opts.offline:
        if not opts.quiet:
            st.con.print(
                "\n  [yellow]⚠[/yellow] Offline mode: skipped version resolution "
                f"for {len(st.unresolved)} package(s) — coverage stays partial for "
                "packages without pinned versions"
            )


def _autodiscover_and_drift(opts: ScanOptions, st: ScanState) -> None:
    # Step 3b: Auto-discover metadata for unknown packages
    unknown_pkgs = [
        p
        for p in st.all_packages
        if not p.resolved_from_registry
        and not getattr(p, "auto_risk_level", None)
        and p.version not in ("unknown", "latest", "")
        and p.ecosystem in ("npm", "pypi", "PyPI")
    ]
    if unknown_pkgs and not opts.no_scan and not opts.offline:
        import asyncio as _asyncio_ad

        from agent_bom.autodiscover import enrich_unknown_packages

        if not opts.quiet:
            st.con.print(f"\n[bold blue]Auto-discovering metadata for {len(unknown_pkgs)} package(s)...[/bold blue]\n")
        with st.con.status("[bold]Fetching package metadata...[/bold]", spinner="dots") if not opts.quiet else _nullcontext():
            enriched_count = _asyncio_ad.run(enrich_unknown_packages(unknown_pkgs))
        if not opts.quiet:
            st.con.print(f"  [green]✓[/green] Auto-discovered metadata for {enriched_count} package(s)")

    # Step 3c: Version drift detection
    registry_pkgs = [p for p in st.all_packages if p.resolved_from_registry]
    if registry_pkgs and not opts.quiet:
        from agent_bom.registry import detect_version_drift

        drift = detect_version_drift(registry_pkgs)
        outdated = [d for d in drift if d.status == "outdated"]
        if outdated:
            st.con.print(f"\n[bold yellow]  {len(outdated)} outdated package(s):[/bold yellow]")
            for d in outdated:
                st.con.print(f"    {d.package}: {d.installed} → {d.latest}")

    st.ctx.step_timings["extraction"] = _time.monotonic() - st.step_t0


def run_inventory(opts: ScanOptions, st: ScanState) -> None:
    """Extract and resolve packages for every discovered MCP server."""
    _begin_inventory(opts, st)
    if opts.skill_only:
        st.blast_radii = []
        return
    _extract_packages(opts, st)
    _summarize_packages(opts, st)
    _resolve_deps_dev(opts, st)
    _introspect_servers(opts, st)
    _health_check_servers(opts, st)
    _scan_descriptions_and_enforce(opts, st)
    _fold_external_packages(opts, st)
    _resolve_versions(opts, st)
    _autodiscover_and_drift(opts, st)
