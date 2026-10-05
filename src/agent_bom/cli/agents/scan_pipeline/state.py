"""Values one scan stage hands to the next."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class StopScan(Exception):  # noqa: N818 - control-flow signal, not an error
    """Raised by a stage that fully handled the invocation (dry run, IaC-only, posture)."""


@dataclass
class ScanState:
    """Intermediate results carried between scan stages.

    ``ctx`` is the long-lived :class:`ScanContext` shared with the discovery,
    output and exit-code helpers; the remaining fields are the stage-to-stage
    values that previously lived as locals of one very large function.
    """

    agents: list[Any] = field(default_factory=list)
    all_packages: list[Any] = field(default_factory=list)
    any_cloud: bool = False
    ast_result_for_reach: Any = None
    blast_radii: list[Any] = field(default_factory=list)
    cloud_scopes: list[Any] = field(default_factory=list)
    con: Any = None
    coverage_warnings: list[dict] = field(default_factory=list)
    ctx: Any = None
    current_report_json: Any = None
    docker_image_failures: list[str] = field(default_factory=list)
    endpoint_inventory_data: Any = None
    findings: list[Any] = field(default_factory=list)
    hc_results: Any = None
    intro_report: Any = None
    pre_scan_step_timings: dict[str, float] = field(default_factory=dict)
    prefer_local_db: bool = False
    repo_trust_data: Any = None
    report: Any = None
    report_con: Any = None
    report_kwargs: dict[str, Any] = field(default_factory=dict)
    scan_graph_surface: Any = None
    scan_id: Any = None
    target_scope: str | None = None
    scan_issues: list[Any] = field(default_factory=list)
    scan_outcome: Any = None
    scan_sources: list[str] = field(default_factory=list)
    scan_start: float = 0.0
    scan_warnings: list[str] = field(default_factory=list)
    step_t0: float = 0.0
    total_packages: int = 0
    unresolved: list[Any] = field(default_factory=list)
    validated_ignore_entries: Any = None
    vuln_freshness: Any = None
    stage_timings: dict[str, float] = field(default_factory=dict)
