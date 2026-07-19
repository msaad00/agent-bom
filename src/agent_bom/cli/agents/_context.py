"""ScanContext dataclass — shared mutable state accumulated across scan phases."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class ScanContext:
    """Mutable state accumulated across scan phases."""

    con: Any  # rich Console
    quiet: bool = False
    verbose: bool = False
    agents: list = field(default_factory=list)
    blast_radii: list = field(default_factory=list)
    report: Any = None
    # benchmark reports
    cis_benchmark_report: Any = None
    sf_cis_benchmark_report: Any = None
    azure_cis_benchmark_report: Any = None
    gcp_cis_benchmark_report: Any = None
    databricks_security_report: Any = None
    aisvs_report: Any = None
    vector_db_results: list = field(default_factory=list)
    gpu_infra_report: Any = None
    # special scan data
    skill_audit_data: Any = None
    trust_assessment_data: Any = None
    prompt_scan_data: Any = None
    enforcement_data: Any = None
    sast_data: Any = None
    ai_inventory_data: Any = None
    project_inventory_data: Any = None
    model_hash_verification_data: Any = None
    model_supply_chain_data: Any = None
    iac_findings_data: Any = None
    delta_result: Any = None
    policy_passed: bool = True
    exit_code: int = 0
    # Cloud providers that were explicitly requested but hard-failed discovery or
    # benchmarking (missing SDK / absent / invalid credentials → CloudDiscoveryError).
    # Recorded per provider+stage; a non-empty list forces a non-zero exit so a
    # requested cloud silently passing in CI is impossible. One provider failing
    # never aborts the others — every requested provider is still attempted.
    cloud_provider_failures: list = field(default_factory=list)
    cloud_provider_successes: list = field(default_factory=list)
    cloud_provider_warnings: list = field(default_factory=list)
    # per-step timing breakdown (step_name → seconds)
    step_timings: dict = field(default_factory=dict)
    # internal references used for AI enrichment
    _skill_result_obj: Any = None
    _skill_audit_obj: Any = None
    _browser_ext_results: Optional[dict] = None
