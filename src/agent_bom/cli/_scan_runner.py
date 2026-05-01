"""Shared scan orchestration for CLI commands that consume scan results.

Both ``agents`` and ``remediate`` (and future scan-consuming commands) should
use ``run_default_scan()`` instead of duplicating the discovery → extraction →
scan → report pipeline.  The ``agents`` command retains its own orchestration
for advanced options (cloud, images, IaC, transitive, enrichment, etc.) — this
module covers the *simple* path used by commands that just need a ready-made
``AIBOMReport``.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from rich.console import Console

    from agent_bom.models import Agent, AIBOMReport, BlastRadius


@dataclass
class ScanConfig:
    """Inputs for a default scan invocation."""

    project: Optional[str] = None
    demo: bool = False
    offline: bool = False
    enrich: bool = False
    compliance: bool = False
    resolve_transitive: bool = False
    max_depth: int = 3
    blast_radius_depth: int = 2
    quiet: bool = False


@dataclass
class ScanResult:
    """Outputs from a completed scan pipeline."""

    agents: list["Agent"] = field(default_factory=list)
    blast_radii: list["BlastRadius"] = field(default_factory=list)
    report: Optional["AIBOMReport"] = None
    total_packages: int = 0


def run_default_scan(cfg: ScanConfig, con: "Console") -> ScanResult:
    """Execute the standard discovery → extraction → scan → report pipeline.

    This is the canonical "simple scan" entry point.  Commands that need the
    full option surface (cloud providers, image scanning, IaC, SAST, etc.)
    should still use the ``agents`` command's own orchestration.

    Returns a ``ScanResult`` with agents, blast radii, and a ready-made report.
    """
    import agent_bom.output as _out
    from agent_bom.cli.agents._context import ScanContext
    from agent_bom.cli.agents._discovery import run_local_discovery
    from agent_bom.discovery import discover_all
    from agent_bom.finding import blast_radius_to_finding
    from agent_bom.mcp_blocklist import blocklist_findings_for_agents, flag_blocklisted_mcp_servers
    from agent_bom.models import AIBOMReport
    from agent_bom.parsers import extract_packages
    from agent_bom.scanners import IncompleteScanError, scan_agents_sync

    _out.console = con

    # ── Demo mode ────────────────────────────────────────────────────
    project = cfg.project
    inventory: Optional[str] = None
    enrich = cfg.enrich
    compliance = cfg.compliance
    iac_paths: tuple = ()

    if cfg.demo:
        from agent_bom.demo import DEMO_INVENTORY

        _demo_fd, _demo_path = tempfile.mkstemp(suffix=".json", prefix="agent-bom-demo-")
        with os.fdopen(_demo_fd, "w") as _df:
            json.dump(DEMO_INVENTORY, _df)
        inventory = _demo_path
        enrich = True
        compliance = True
        if not project:
            project = tempfile.mkdtemp(prefix="agent-bom-demo-dir-")
        for agent_data in DEMO_INVENTORY.get("agents", []):
            agent_data.setdefault("config_path", f"~/.config/{agent_data.get('agent_type', 'agent')}/config.json")
        iac_paths = (project,)
        if not cfg.quiet:
            con.print("\n[bold yellow]Demo mode[/bold yellow] — curated agent + MCP sample with known-vulnerable packages.\n")

    # ── Offline mode ─────────────────────────────────────────────────
    previous_offline_mode: bool | None = None
    if cfg.offline:
        import agent_bom.scanners as _scanners
        from agent_bom.scanners import set_offline_mode

        previous_offline_mode = _scanners.offline_mode
        set_offline_mode(True)
        enrich = False
        if not cfg.quiet:
            con.print("[dim]Offline mode — local vulnerability DB only[/dim]")

    def _restore_offline_mode() -> None:
        if previous_offline_mode is not None:
            from agent_bom.scanners import set_offline_mode

            set_offline_mode(previous_offline_mode)

    try:
        # ── Discovery ────────────────────────────────────────────────────
        ctx = ScanContext(con=con)

        run_local_discovery(
            ctx,
            project=project,
            config_dir=None,
            inventory=inventory,
            skill_only=False,
            dynamic_discovery=False,
            dynamic_max_depth=3,
            include_processes=False,
            include_containers=False,
            introspect=False,
            introspect_timeout=10.0,
            enforce=False,
            health_check=False,
            hc_timeout=5.0,
            k8s_mcp=False,
            k8s_namespace="default",
            k8s_all_namespaces=False,
            k8s_mcp_context=None,
            no_skill=True,
            skill_paths=(),
            skill_only_mode=False,
            ai_enrich=False,
            ai_model="",
            sbom_file=None,
            sbom_name=None,
            external_scan_path=None,
            k8s=False,
            namespace="default",
            all_namespaces=False,
            k8s_context=None,
            registry_user=None,
            registry_pass=None,
            image_platform=None,
            images=(),
            image_tars=(),
            filesystem_paths=(),
            code_paths=(),
            sast_config="auto",
            ai_inventory_paths=(),
            tf_dirs=(),
            gha_path=None,
            agent_projects=(),
            scan_prompts=False,
            browser_extensions=False,
            jupyter_dirs=(),
            verbose=False,
            quiet=cfg.quiet,
            smithery_token=None,
            smithery_flag=False,
            mcp_registry_flag=False,
            os_packages=False,
            iac_paths=iac_paths,
            _image_only=False,
            _any_cloud=False,
            _discover_all=discover_all,
        )

        agents = ctx.agents
        flag_blocklisted_mcp_servers(agents)

        # ── Package extraction ───────────────────────────────────────────
        total_packages = 0
        for agent in agents:
            for server in agent.mcp_servers:
                if server.security_blocked:
                    continue
                discovered = extract_packages(
                    server,
                    resolve_transitive=cfg.resolve_transitive,
                    max_depth=cfg.max_depth,
                )
                discovered_names = {(p.name, p.ecosystem) for p in discovered}
                pre_populated = list(server.packages)
                merged = discovered + [p for p in pre_populated if (p.name, p.ecosystem) not in discovered_names]
                server.packages = merged
                total_packages += len(server.packages)

        # ── Vulnerability scan ───────────────────────────────────────────
        blast_radii: list[BlastRadius] = []
        if total_packages > 0:
            try:
                blast_radii = scan_agents_sync(
                    agents,
                    enable_enrichment=enrich,
                    blast_radius_depth=cfg.blast_radius_depth,
                    compliance_enabled=compliance,
                    resolve_transitive=cfg.resolve_transitive,
                    offline=cfg.offline,
                )
            except IncompleteScanError as exc:
                con.print(f"  [yellow]Warning:[/yellow] {exc}")
                raise SystemExit(1) from exc

        # ── Build report ─────────────────────────────────────────────────
        findings = [blast_radius_to_finding(br) for br in blast_radii]
        findings.extend(blocklist_findings_for_agents(agents))
        report = AIBOMReport(
            agents=agents,
            blast_radii=blast_radii,
            findings=findings,
            scan_sources=["agent_discovery"],
        )

        return ScanResult(
            agents=agents,
            blast_radii=blast_radii,
            report=report,
            total_packages=total_packages,
        )
    finally:
        _restore_offline_mode()
