"""Shared state threaded through the API scan pipeline stages.

``_run_scan_sync`` in :mod:`agent_bom.api.pipeline` runs an ordered tuple of
stages over one :class:`ScanContext`. Each stage reads what earlier stages
collected and records its own output on the context, so the stage order is the
only coupling between them.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from agent_bom.api.models import ScanJob, ScanRequest
from agent_bom.evidence.scan_run import ScanIssue, ScanOutcome, ScanRun

if TYPE_CHECKING:
    from agent_bom.api.pipeline import ScanPipeline


@dataclass
class ScanContext:
    job: ScanJob
    lock: threading.Lock
    pipeline: ScanPipeline
    repo_stack: ExitStack
    agents: list[Any] = field(default_factory=list)
    warnings_all: list[str] = field(default_factory=list)
    external_findings: list[Any] = field(default_factory=list)
    repo_scan_issues: list[ScanIssue] = field(default_factory=list)
    coverage_warning_messages: set[str] = field(default_factory=set)
    effective_agent_projects: list[str] = field(default_factory=list)
    effective_tf_dirs: list[str] = field(default_factory=list)
    effective_gha_path: str | None = None
    extra_symbol_paths: list[str] = field(default_factory=list)
    repo_url: str = ""
    cloned_path: str = ""
    skill_audit_data: dict | None = None
    iac_findings_data: dict | None = None
    repo_ai_inventory_data: dict | None = None
    repo_sast_data: dict | None = None
    repo_trust_data: dict | None = None
    repo_codeowners: dict[str, str] = field(default_factory=dict)
    all_packages: list[Any] = field(default_factory=list)
    blast_radii: list[Any] = field(default_factory=list)
    ast_for_reach: Any | None = None
    report: Any = None
    report_json: dict[str, Any] = field(default_factory=dict)

    @property
    def req(self) -> ScanRequest:
        return self.job.request

    @property
    def side_effects_enabled(self) -> bool:
        return not (self.req.dry_run or self.req.no_scan)

    @property
    def effective_enrich(self) -> bool:
        return bool(self.req.enrich and not self.req.offline)

    @property
    def tenant_or_default(self) -> str:
        return self.job.tenant_id or "default"

    def has_static_repo_evidence(self) -> bool:
        evidence = (self.skill_audit_data, self.iac_findings_data, self.repo_ai_inventory_data, self.repo_sast_data)
        return any(result is not None for result in evidence)

    def record_coverage_warning(self, message: str) -> None:
        self.warnings_all.append(message)
        self.coverage_warning_messages.add(message)

    def progress(self, message: str) -> None:
        with self.lock:
            self.job.progress.append(message)

    def build_scan_run(self, *, has_usable_evidence: bool) -> ScanRun:
        issues = [
            ScanIssue(
                code="collector_failed" if warning in self.coverage_warning_messages else "scan_warning",
                stage="scanning" if "CVE scanning" in warning else "discovery",
                source="api",
                message=warning,
                severity="error" if warning in self.coverage_warning_messages else "warning",
                affects_coverage=warning in self.coverage_warning_messages,
            )
            for warning in self.warnings_all
        ]
        outcome = ScanOutcome.FAILED if self.coverage_warning_messages and not has_usable_evidence else ScanOutcome.COMPLETE
        return ScanRun(outcome=outcome, issues=[*self.repo_scan_issues, *issues])


ScanStageFn = Callable[[ScanContext], bool]
"""A stage returns ``True`` when it finished the job and later stages must not run."""


@dataclass(frozen=True)
class ScanStage:
    name: str
    run: ScanStageFn
    check_cancelled: bool = False
