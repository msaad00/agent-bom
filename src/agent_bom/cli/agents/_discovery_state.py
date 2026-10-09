"""Shared state threaded through the local-discovery stages."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, fields
from typing import Any

from agent_bom.cli.agents._context import ScanContext


@dataclass
class DiscoveryRun:
    """One ``run_local_discovery`` call: its inputs plus what earlier stages produced.

    ``images``, ``filesystem_paths`` and ``iac_paths`` are rebound by the k8s and
    auto-detect stages, and later stages read the rebound values.
    """

    ctx: ScanContext
    con: Any
    discover: Callable[..., Any]
    extra: dict[str, Any]
    project: Any
    config_dir: Any
    inventory: Any
    skill_only: bool
    no_discover: bool
    follow_symlinks: bool
    dynamic_discovery: bool
    dynamic_max_depth: int
    include_processes: bool
    include_containers: bool
    k8s_mcp: bool
    k8s_namespace: str
    k8s_all_namespaces: bool
    k8s_mcp_context: Any
    no_skill: bool
    skill_paths: tuple
    sbom_file: Any
    sbom_name: Any
    external_scan_path: Any
    k8s: bool
    namespace: str
    all_namespaces: bool
    k8s_context: Any
    registry_user: Any
    registry_pass: Any
    image_platform: Any
    images: tuple
    image_tars: tuple
    filesystem_paths: tuple
    code_paths: tuple
    sast_config: str
    offline: bool
    tf_dirs: tuple
    gha_path: Any
    agent_projects: tuple
    scan_prompts: bool
    browser_extensions: bool
    jupyter_dirs: tuple
    iac_paths: tuple
    verbose: bool
    os_packages: bool
    workstation_sweep: bool
    preloaded_inventory: dict[str, Any] | None = None
    inventory_label: str | None = None
    skill_result: Any = None
    skill_audit: Any = None

    @classmethod
    def from_params(cls, params: dict[str, Any], discover: Callable[..., Any]) -> DiscoveryRun:
        """Build the run from ``run_local_discovery``'s bound parameters."""
        names = {f.name for f in fields(cls) if f.init} - {"con", "discover", "extra"}
        values = {name: params[name] for name in names if name in params}
        return cls(con=params["ctx"].con, discover=discover, extra=params["kwargs"], **values)


DiscoveryStage = Callable[[DiscoveryRun], None]
