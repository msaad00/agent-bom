"""Producer and target identity for pushed scan evidence."""

from types import SimpleNamespace
from typing import Any

from pydantic import BaseModel, Field, field_validator

from agent_bom.evidence.push_scope import TARGET_SCOPE_PATTERN
from agent_bom.evidence.scan_run import ScanIssue, ScanOutcome, ScanRun, ScanScope, ScanScopeStatus, effective_scan_run


class PushIdentityPayload(BaseModel):
    """Identity is separate from producer-controlled findings and summaries."""

    source_id: str = Field(default="", max_length=200)
    target_scope: str | None = Field(
        default=None, pattern=TARGET_SCOPE_PATTERN, description="Opaque versioned target identity for scoped replacement"
    )
    idempotency_key: str = ""

    @field_validator("source_id")
    @classmethod
    def normalize_source_id(cls, value: str) -> str:
        return value.strip()


def normalize_push_coverage(report: dict, *, source_id: str, target_scope: str | None) -> dict:
    """Normalize producer coverage and disclose an absent replacement scope."""

    def structured(warnings: list[dict | str]) -> list[dict]:
        return [dict(warning) if isinstance(warning, dict) else {"kind": "legacy_scan_warning", "detail": warning} for warning in warnings]

    supplied_coverage = structured(report.get("coverage_warnings") or [])
    combined_coverage = list(supplied_coverage)
    for warning in structured(report.get("warnings") or []):
        if warning not in combined_coverage:
            combined_coverage.append(warning)
    report["coverage_warnings"] = combined_coverage
    raw_scan_run_value = report.get("scan_run")
    raw_scan_run: dict[str, Any] = raw_scan_run_value if isinstance(raw_scan_run_value, dict) else {}
    issues: list[ScanIssue] = []
    for raw_issue in raw_scan_run.get("issues", []) or []:
        if not isinstance(raw_issue, dict):
            continue
        issues.append(
            ScanIssue(
                code=str(raw_issue.get("code") or "scan_issue"),
                stage=str(raw_issue.get("stage") or "scan"),
                source=str(raw_issue.get("source") or "push"),
                message=str(raw_issue.get("message") or "Scan execution issue"),
                severity="error" if raw_issue.get("severity") == "error" else "warning",
                affects_coverage=bool(raw_issue.get("affects_coverage", True)),
            )
        )
    existing_messages = {issue.message for issue in issues}
    for warning in report.get("warnings", []) or []:
        if isinstance(warning, dict):
            message = str(warning.get("message") or warning.get("detail") or "Scan warning")
        else:
            message = str(warning)
        issue = ScanIssue(
            code="legacy_scan_warning",
            stage="scan",
            source="push",
            message=message,
            affects_coverage=True,
        )
        if issue.message not in existing_messages:
            issues.append(issue)
            existing_messages.add(issue.message)
    raw_outcome = str(raw_scan_run.get("outcome") or "complete")
    outcome = ScanOutcome(raw_outcome)
    scopes: list[ScanScope] = []
    for raw_scope in raw_scan_run.get("scopes", []) or []:
        if not isinstance(raw_scope, dict):
            continue
        scopes.append(
            ScanScope(
                name=str(raw_scope.get("name") or "unknown"),
                status=ScanScopeStatus(str(raw_scope.get("status") or "skipped")),
                requested=bool(raw_scope.get("requested", True)),
                item_count=raw_scope.get("item_count") if isinstance(raw_scope.get("item_count"), int) else None,
                message=str(raw_scope.get("message") or ""),
            )
        )
    report["replacement_scope_status"] = "identified" if source_id and target_scope else "unscoped"
    if report["replacement_scope_status"] == "unscoped":
        issues.append(
            ScanIssue(
                code="push_target_unscoped",
                stage="ingest",
                source="push",
                affects_coverage=False,
                message="Target identity unavailable; this push retains independent evidence and cannot replace earlier scans.",
            )
        )
    scan_run = effective_scan_run(
        SimpleNamespace(
            scan_run=ScanRun(outcome=outcome, issues=issues, scopes=scopes),
            coverage_warnings=supplied_coverage,
            agents=[],
        )
    )
    report["scan_run"] = {**raw_scan_run, **scan_run.to_dict()}
    report["warnings"] = scan_run.warnings
    return report
