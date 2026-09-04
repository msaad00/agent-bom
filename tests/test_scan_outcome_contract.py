from __future__ import annotations

from agent_bom.evidence.scan_run import ScanIssue, ScanOutcome, ScanRun, ScanScope, ScanScopeStatus
from agent_bom.evidence.semantics import EvidenceStage, EvidenceStatus
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


def test_scan_run_projects_requested_scopes_to_completeness_ledger() -> None:
    run = ScanRun(
        scopes=[
            ScanScope(name="repository", status=ScanScopeStatus.COMPLETE, item_count=4),
            ScanScope(name="azure", status=ScanScopeStatus.PERMISSION_DENIED, message="denied"),
            ScanScope(name="optional-intel", status=ScanScopeStatus.SKIPPED, requested=False),
        ]
    )

    ledger = run.to_evidence_ledger()
    by_component = {entry.component: entry for entry in ledger.entries}

    assert by_component["repository"].stage is EvidenceStage.COLLECTION
    assert by_component["repository"].status is EvidenceStatus.COMPLETE
    assert by_component["azure"].status is EvidenceStatus.UNAVAILABLE
    assert by_component["azure"].reason_codes == ("permission_denied",)
    assert by_component["optional-intel"].affects_coverage is False
    assert ledger.overall_status is EvidenceStatus.PARTIAL


def test_scan_run_without_recorded_scopes_does_not_invent_complete_ledger() -> None:
    ledger = ScanRun().to_evidence_ledger()

    assert ledger.entries == ()
    assert ledger.overall_status is EvidenceStatus.UNAVAILABLE


def test_failed_scan_without_scopes_remains_failed_in_ledger() -> None:
    ledger = ScanRun(outcome=ScanOutcome.FAILED).to_evidence_ledger()

    assert ledger.overall_status is EvidenceStatus.FAILED
    assert ledger.entries[0].reason_codes == ("scan_failed",)


def test_scan_run_outcome_cannot_be_hidden_by_a_complete_scope() -> None:
    partial = ScanRun(
        scopes=[ScanScope(name="repository", status=ScanScopeStatus.COMPLETE)],
        issues=[
            ScanIssue(
                code="catalog_timeout",
                stage="enrichment",
                source="vulnerability-data",
                message="bounded lookup timed out",
            )
        ],
    ).to_evidence_ledger()
    failed = ScanRun(
        outcome=ScanOutcome.FAILED,
        scopes=[ScanScope(name="repository", status=ScanScopeStatus.COMPLETE)],
    ).to_evidence_ledger()

    assert partial.overall_status is EvidenceStatus.PARTIAL
    assert failed.overall_status is EvidenceStatus.FAILED


def test_only_unrequested_scopes_do_not_create_complete_evidence() -> None:
    ledger = ScanRun(scopes=[ScanScope(name="optional-intel", status=ScanScopeStatus.SKIPPED, requested=False)]).to_evidence_ledger()

    assert ledger.overall_status is EvidenceStatus.UNAVAILABLE
