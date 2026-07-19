from __future__ import annotations

from agent_bom.evidence.scan_run import ScanIssue, ScanOutcome, ScanRun
from agent_bom.models import AIBOMReport
from agent_bom.output.json_fmt import to_json
from agent_bom.output.sarif import to_sarif


def test_scan_run_defaults_to_complete_and_projects_to_json_and_sarif() -> None:
    report = AIBOMReport(scan_id="scan-complete")

    json_report = to_json(report)
    sarif_run = to_sarif(report)["runs"][0]

    assert json_report["scan_run"]["outcome"] == "complete"
    assert json_report["scan_run"]["issues"] == []
    assert json_report["warnings"] == []
    assert sarif_run["properties"]["scan_outcome"] == "complete"
    assert sarif_run["invocations"] == [{"executionSuccessful": True, "toolExecutionNotifications": []}]


def test_coverage_issue_marks_report_partial_and_preserves_warning_everywhere() -> None:
    issue = ScanIssue(
        code="collector_unavailable",
        stage="discovery",
        source="azure",
        message="Azure collector unavailable",
        severity="error",
        affects_coverage=True,
    )
    report = AIBOMReport(scan_id="scan-partial", scan_run=ScanRun(issues=[issue]))

    json_report = to_json(report)
    sarif_run = to_sarif(report)["runs"][0]

    assert json_report["scan_run"]["outcome"] == "partial"
    assert json_report["scan_run"]["issues"] == [issue.to_dict()]
    assert json_report["scan_run"]["warning_count"] == 1
    assert json_report["warnings"] == ["Azure collector unavailable"]
    assert sarif_run["properties"]["scan_outcome"] == "partial"
    assert sarif_run["invocations"][0]["executionSuccessful"] is True
    assert sarif_run["invocations"][0]["toolExecutionNotifications"][0]["descriptor"]["id"] == "collector_unavailable"


def test_failed_scan_is_distinct_from_partial_and_sarif_execution_fails() -> None:
    report = AIBOMReport(
        scan_id="scan-failed",
        scan_run=ScanRun(
            outcome=ScanOutcome.FAILED,
            issues=[
                ScanIssue(
                    code="required_scanner_failed",
                    stage="scanning",
                    source="osv",
                    message="Required vulnerability scanner failed",
                    severity="error",
                )
            ],
        ),
    )

    json_report = to_json(report)
    sarif_run = to_sarif(report)["runs"][0]

    assert json_report["scan_run"]["outcome"] == "failed"
    assert sarif_run["properties"]["scan_outcome"] == "failed"
    assert sarif_run["invocations"][0]["executionSuccessful"] is False


def test_noncoverage_warning_does_not_downgrade_complete_scan() -> None:
    report = AIBOMReport(
        scan_run=ScanRun(
            issues=[
                ScanIssue(
                    code="optional_enrichment_skipped",
                    stage="enrichment",
                    source="epss",
                    message="Optional enrichment skipped",
                    affects_coverage=False,
                )
            ]
        )
    )

    assert to_json(report)["scan_run"]["outcome"] == "complete"


def test_push_normalization_sanitizes_warning_and_infers_partial() -> None:
    from agent_bom.api.models import PushPayload
    from agent_bom.api.routes.observability import _normalize_pushed_report

    secret = "ghp_" + "A" * 36
    result = _normalize_pushed_report(
        PushPayload(source_id="collector", warnings=[f"collector failed token={secret}"]),
        fallback_scan_id="push-1",
    )

    assert result["scan_run"]["outcome"] == "partial"
    assert result["scan_run"]["warning_count"] == 1
    assert secret not in result["warnings"][0]


def test_push_payload_rejects_noncanonical_outcome() -> None:
    import pytest
    from pydantic import ValidationError

    from agent_bom.api.models import PushPayload

    with pytest.raises(ValidationError):
        PushPayload.model_validate({"agents": [], "scan_run": {"outcome": "done"}})
