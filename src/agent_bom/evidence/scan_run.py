"""Canonical execution-quality contract for scan reports.

The execution outcome is deliberately independent from a policy or finding
gate. A scan can execute completely and still return a non-zero policy verdict.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Literal

from agent_bom.security import sanitize_text

if TYPE_CHECKING:
    from agent_bom.evidence.semantics import EvidenceCompletenessLedger, EvidenceStage


class ScanOutcome(str, Enum):
    """Quality of the evidence produced by a scan execution."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


class ScanScopeStatus(str, Enum):
    """Completeness of one explicitly requested scan scope."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    UNSUPPORTED = "unsupported"
    UNAVAILABLE = "unavailable"
    PERMISSION_DENIED = "permission_denied"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class ScanScope:
    """Bounded evidence status for one requested collection scope."""

    name: str
    status: ScanScopeStatus
    requested: bool = True
    item_count: int | None = None
    message: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", sanitize_text(self.name, max_len=100) or "unknown")
        if isinstance(self.status, str):
            object.__setattr__(self, "status", ScanScopeStatus(self.status))
        if self.item_count is not None:
            object.__setattr__(self, "item_count", max(0, int(self.item_count)))
        object.__setattr__(self, "message", sanitize_text(self.message, max_len=500))

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "requested": self.requested,
            "item_count": self.item_count,
            "message": self.message,
        }


@dataclass(frozen=True)
class ScanIssue:
    """One sanitized execution issue projected to every report surface."""

    code: str
    stage: str
    source: str
    message: str
    severity: Literal["warning", "error"] = "warning"
    affects_coverage: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "code", sanitize_text(self.code, max_len=100) or "scan_issue")
        object.__setattr__(self, "stage", sanitize_text(self.stage, max_len=100) or "scan")
        object.__setattr__(self, "source", sanitize_text(self.source, max_len=200) or "agent-bom")
        object.__setattr__(self, "message", sanitize_text(self.message, max_len=1000) or "Scan execution issue")
        if self.severity not in ("warning", "error"):
            object.__setattr__(self, "severity", "warning")

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "stage": self.stage,
            "source": self.source,
            "message": self.message,
            "severity": self.severity,
            "affects_coverage": self.affects_coverage,
        }


@dataclass
class ScanRun:
    """Canonical scan outcome plus bounded, structured execution issues."""

    outcome: ScanOutcome = ScanOutcome.COMPLETE
    issues: list[ScanIssue] = field(default_factory=list)
    scopes: list[ScanScope] = field(default_factory=list)

    def __post_init__(self) -> None:
        if isinstance(self.outcome, str):
            self.outcome = ScanOutcome(self.outcome)
        self.issues = self._dedupe(self.issues)
        self.scopes = self._dedupe_scopes(self.scopes)
        self._derive_partial()

    @staticmethod
    def _dedupe(issues: list[ScanIssue]) -> list[ScanIssue]:
        unique: list[ScanIssue] = []
        seen: set[tuple[str, str, str, str]] = set()
        for issue in issues[:100]:
            key = (issue.code, issue.stage, issue.source, issue.message)
            if key not in seen:
                unique.append(issue)
                seen.add(key)
        return unique

    def _derive_partial(self) -> None:
        scope_incomplete = any(
            scope.requested and scope.status not in {ScanScopeStatus.COMPLETE, ScanScopeStatus.SKIPPED} for scope in self.scopes
        )
        if self.outcome is ScanOutcome.COMPLETE and (any(issue.affects_coverage for issue in self.issues) or scope_incomplete):
            self.outcome = ScanOutcome.PARTIAL

    @staticmethod
    def _dedupe_scopes(scopes: list[ScanScope]) -> list[ScanScope]:
        unique: dict[str, ScanScope] = {}
        for scope in scopes[:100]:
            unique[scope.name] = scope
        return list(unique.values())

    def add_issue(self, issue: ScanIssue) -> None:
        self.issues = self._dedupe([*self.issues, issue])
        self._derive_partial()

    def set_scopes(self, scopes: list[ScanScope]) -> None:
        self.scopes = self._dedupe_scopes(scopes)
        self._derive_partial()

    def mark_failed(self) -> None:
        self.outcome = ScanOutcome.FAILED

    @property
    def warnings(self) -> list[str]:
        return [issue.message for issue in self.issues]

    def to_dict(self) -> dict[str, Any]:
        requested_scopes = [scope for scope in self.scopes if scope.requested]
        complete_scope_count = sum(scope.status is ScanScopeStatus.COMPLETE for scope in requested_scopes)
        return {
            "outcome": self.outcome.value,
            "issues": [issue.to_dict() for issue in self.issues],
            "warning_count": len(self.issues),
            "requested_scope_count": len(requested_scopes),
            "complete_scope_count": complete_scope_count,
            "incomplete_scope_count": len(requested_scopes) - complete_scope_count,
            "scopes": [scope.to_dict() for scope in self.scopes],
        }

    def to_evidence_ledger(self) -> EvidenceCompletenessLedger:
        """Project recorded scan scopes onto the canonical completeness model.

        This adapter is intentionally non-mutating and is not included in the
        legacy report serialization contract.
        """

        from agent_bom.evidence.semantics import (
            CompletenessEntry,
            EvidenceCompletenessLedger,
            EvidenceStage,
            EvidenceStatus,
        )

        status_map = {
            ScanScopeStatus.COMPLETE: EvidenceStatus.COMPLETE,
            ScanScopeStatus.PARTIAL: EvidenceStatus.PARTIAL,
            ScanScopeStatus.UNSUPPORTED: EvidenceStatus.UNAVAILABLE,
            ScanScopeStatus.UNAVAILABLE: EvidenceStatus.UNAVAILABLE,
            ScanScopeStatus.PERMISSION_DENIED: EvidenceStatus.UNAVAILABLE,
            ScanScopeStatus.SKIPPED: EvidenceStatus.UNAVAILABLE,
        }
        entries = [
            CompletenessEntry(
                stage=EvidenceStage.COLLECTION,
                component=_ledger_token(scope.name),
                status=status_map[scope.status],
                requested=scope.requested,
                affects_coverage=scope.requested and scope.status is not ScanScopeStatus.SKIPPED,
                returned_count=scope.item_count,
                reason_codes=() if scope.status is ScanScopeStatus.COMPLETE else (scope.status.value,),
            )
            for scope in self.scopes
        ]
        entries.extend(
            CompletenessEntry(
                stage=_ledger_stage(issue.stage),
                component=_ledger_token(issue.source),
                status=EvidenceStatus.FAILED
                if self.outcome is ScanOutcome.FAILED and issue.severity == "error"
                else EvidenceStatus.PARTIAL,
                affects_coverage=issue.affects_coverage,
                reason_codes=(_ledger_token(issue.code, max_len=64),),
            )
            for issue in self.issues
        )
        if self.outcome is not ScanOutcome.COMPLETE:
            entries.append(
                CompletenessEntry(
                    stage=EvidenceStage.COLLECTION,
                    component="scan-run",
                    status=EvidenceStatus.FAILED if self.outcome is ScanOutcome.FAILED else EvidenceStatus.PARTIAL,
                    reason_codes=("scan_failed" if self.outcome is ScanOutcome.FAILED else "scan_partial",),
                )
            )
        return EvidenceCompletenessLedger(entries=tuple(entries))


def effective_scan_run(report: Any) -> ScanRun:
    """Return the report's canonical run with legacy coverage gaps folded in."""
    raw = getattr(report, "scan_run", None)
    run = ScanRun(
        outcome=getattr(raw, "outcome", ScanOutcome.COMPLETE),
        issues=list(getattr(raw, "issues", []) or []),
        scopes=list(getattr(raw, "scopes", []) or []),
    )
    for warning in getattr(report, "coverage_warnings", []) or []:
        if not isinstance(warning, dict):
            continue
        source = str(warning.get("ecosystem") or "vulnerability-data")
        release = str(warning.get("release") or "unknown release")
        detail = str(warning.get("detail") or warning.get("reason") or "Vulnerability coverage is incomplete")
        issue_code = "scanner_coverage_gap" if source.startswith("ast-") else "vulnerability_coverage_gap"
        run.add_issue(
            ScanIssue(
                code=issue_code,
                stage="scanning",
                source=source,
                message=f"{release}: {detail}",
                affects_coverage=True,
            )
        )
    return run


def _ledger_token(value: str, *, max_len: int = 100) -> str:
    """Return a bounded structural identifier, never arbitrary diagnostic text."""

    token = re.sub(r"[^a-z0-9_.:-]+", "-", value.strip().lower()).strip("-._:")
    return (token or "unknown")[:max_len]


def _ledger_stage(value: str) -> EvidenceStage:
    from agent_bom.evidence.semantics import EvidenceStage

    normalized = value.strip().lower().replace("-", "_")
    aliases = {
        "enrichment": EvidenceStage.CATALOG_LOOKUP,
        "parsing": EvidenceStage.NORMALIZATION,
        "scanning": EvidenceStage.COLLECTION,
        "discovery": EvidenceStage.COLLECTION,
        "correlation": EvidenceStage.GRAPH_JOIN,
        "storage": EvidenceStage.PERSISTENCE,
    }
    try:
        return EvidenceStage(normalized)
    except ValueError:
        return aliases.get(normalized, EvidenceStage.COLLECTION)


# Issue codes that mean the VULNERABILITY lane specifically could not be fully
# evaluated. A failure in another lane (a cloud collector, a k8s collector) makes
# the run partial without invalidating the vulnerability verdict, so it must not
# blank the posture grade.
_VULN_COVERAGE_CODES = frozenset({"required_scanner_unavailable", "scanner_warning", "vulnerability_coverage_gap"})
_UNRESOLVED_PACKAGE_WARNING = re.compile(r"^(?P<count>\d+) package\(s\) skipped due to unresolved versions$")
_MAX_GRADEABLE_UNRESOLVED_RATIO = 0.05


def _gradeable_unresolved_package_gap(report: Any, issue: ScanIssue) -> tuple[int, int] | None:
    """Return ``(skipped, total)`` for a small, explicitly quantified gap.

    A handful of unresolved package versions must remain visible and keep the
    scan outcome partial, but it should not erase the evaluated posture of the
    rest of a large inventory. The exception is deliberately narrow: only the
    scanner's canonical warning is accepted, at least one package must have
    been evaluated, and no more than five percent may be unresolved.
    """
    if issue.source != "vulnerability-data" or issue.code != "scanner_warning":
        return None
    match = _UNRESOLVED_PACKAGE_WARNING.fullmatch(issue.message)
    if match is None:
        return None
    skipped = int(match.group("count"))
    total = max(0, int(getattr(report, "total_packages", 0) or 0))
    if skipped <= 0 or total <= skipped:
        return None
    if skipped / total > _MAX_GRADEABLE_UNRESOLVED_RATIO:
        return None
    return skipped, total


def vulnerability_coverage_caveat(report: Any) -> str | None:
    """Describe a small partial-version gap that remains gradeable."""
    run = effective_scan_run(report)
    gaps = [_gradeable_unresolved_package_gap(report, issue) for issue in run.issues if issue.affects_coverage]
    gradeable = [gap for gap in gaps if gap is not None]
    if not gradeable:
        return None
    skipped = sum(gap[0] for gap in gradeable)
    total = max(gap[1] for gap in gradeable)
    evaluated = max(0, total - skipped)
    coverage_pct = evaluated / total * 100
    noun = "package" if total == 1 else "packages"
    return (
        f"Partial vulnerability coverage: {evaluated}/{total} {noun} evaluated ({coverage_pct:.1f}%); "
        f"{skipped} of {total} {noun} unresolved"
    )


def vulnerability_coverage_incomplete(report: Any) -> bool:
    """True when the scan could not fully evaluate vulnerabilities.

    This is the single derivation shared by the posture grade and the console /
    compact renderers, so an "incomplete coverage" banner and an "A" grade can
    never appear on the same screen.

    Distinct from "we examined nothing": a scan can discover packages (making
    ``examined_artifacts`` non-zero) while the vulnerability database never
    answered. Discovery is not evaluability.
    """
    coverage = getattr(report, "scan_performance_data", None) or {}
    if isinstance(coverage, dict) and coverage.get("coverage_state") == "incomplete":
        return True
    run = effective_scan_run(report)
    if run.outcome is ScanOutcome.FAILED:
        return True
    for issue in run.issues:
        if not issue.affects_coverage:
            continue
        if _gradeable_unresolved_package_gap(report, issue) is not None:
            continue
        if issue.code in _VULN_COVERAGE_CODES or issue.source == "vulnerability-data":
            return True
    return False


__all__ = [
    "ScanIssue",
    "ScanOutcome",
    "ScanRun",
    "ScanScope",
    "ScanScopeStatus",
    "effective_scan_run",
    "vulnerability_coverage_caveat",
    "vulnerability_coverage_incomplete",
]
