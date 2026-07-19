"""Canonical execution-quality contract for scan reports.

The execution outcome is deliberately independent from a policy or finding
gate. A scan can execute completely and still return a non-zero policy verdict.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal

from agent_bom.security import sanitize_text


class ScanOutcome(str, Enum):
    """Quality of the evidence produced by a scan execution."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


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

    def __post_init__(self) -> None:
        if isinstance(self.outcome, str):
            self.outcome = ScanOutcome(self.outcome)
        self.issues = self._dedupe(self.issues)
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
        if self.outcome is ScanOutcome.COMPLETE and any(issue.affects_coverage for issue in self.issues):
            self.outcome = ScanOutcome.PARTIAL

    def add_issue(self, issue: ScanIssue) -> None:
        self.issues = self._dedupe([*self.issues, issue])
        self._derive_partial()

    def mark_failed(self) -> None:
        self.outcome = ScanOutcome.FAILED

    @property
    def warnings(self) -> list[str]:
        return [issue.message for issue in self.issues]

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "issues": [issue.to_dict() for issue in self.issues],
            "warning_count": len(self.issues),
        }


def effective_scan_run(report: Any) -> ScanRun:
    """Return the report's canonical run with legacy coverage gaps folded in."""
    raw = getattr(report, "scan_run", None)
    run = ScanRun(
        outcome=getattr(raw, "outcome", ScanOutcome.COMPLETE),
        issues=list(getattr(raw, "issues", []) or []),
    )
    for warning in getattr(report, "coverage_warnings", []) or []:
        if not isinstance(warning, dict):
            continue
        source = str(warning.get("ecosystem") or "vulnerability-data")
        release = str(warning.get("release") or "unknown release")
        detail = str(warning.get("detail") or warning.get("reason") or "Vulnerability coverage is incomplete")
        run.add_issue(
            ScanIssue(
                code="vulnerability_coverage_gap",
                stage="scanning",
                source=source,
                message=f"{release}: {detail}",
                affects_coverage=True,
            )
        )
    return run


__all__ = ["ScanIssue", "ScanOutcome", "ScanRun", "effective_scan_run"]
