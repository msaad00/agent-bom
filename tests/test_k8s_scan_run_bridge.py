"""KSPM → canonical ScanRun bridge (issue #4134 stage 3).

A live Kubernetes posture run carries per-collector execution state. These
tests pin the projection of that state onto the shared :class:`ScanRun`
execution-quality contract so a denied/partial read is reported as PARTIAL with
a coverage-affecting issue and can never be laundered into a clean pass.
"""

from __future__ import annotations

from agent_bom.evidence.scan_run import ScanOutcome, ScanRun
from agent_bom.k8s import (
    CollectorState,
    K8sCollectorEvidence,
    K8sPostureResult,
    K8sPostureStatus,
)


def _collector(collector_id: str, state: CollectorState, **kwargs: object) -> K8sCollectorEvidence:
    return K8sCollectorEvidence(collector_id=collector_id, state=state, **kwargs)


def test_all_executed_maps_to_complete_with_no_issues() -> None:
    result = K8sPostureResult(
        collectors=[
            _collector("pods", CollectorState.EXECUTED),
            _collector("clusterroles", CollectorState.EXECUTED),
        ],
        status=K8sPostureStatus.COMPLETE,
        transport="in_cluster",
    )

    run = result.to_scan_run()

    assert isinstance(run, ScanRun)
    assert run.outcome is ScanOutcome.COMPLETE
    assert run.issues == []


def test_denied_collector_maps_to_partial_with_coverage_issue() -> None:
    # A 403-denied collector is UNEVALUABLE. It must surface a coverage-affecting
    # warning and force the run to PARTIAL — never a clean COMPLETE pass.
    result = K8sPostureResult(
        collectors=[
            _collector("pods", CollectorState.EXECUTED),
            _collector(
                "networkpolicies",
                CollectorState.UNEVALUABLE,
                message="forbidden: cannot list networkpolicies",
            ),
        ],
        status=K8sPostureStatus.PARTIAL,
        transport="in_cluster",
    )

    run = result.to_scan_run()

    assert run.outcome is ScanOutcome.PARTIAL
    assert len(run.issues) == 1
    issue = run.issues[0]
    assert issue.code == "k8s_collector_unevaluable"
    assert issue.stage == "kubernetes-posture"
    assert issue.source == "networkpolicies"
    assert issue.severity == "warning"
    assert issue.affects_coverage is True
    assert "forbidden" in issue.message


def test_failed_collector_is_error_severity() -> None:
    result = K8sPostureResult(
        collectors=[
            _collector("pods", CollectorState.EXECUTED),
            _collector("nodes", CollectorState.FAILED, message="connection reset"),
        ],
        status=K8sPostureStatus.PARTIAL,
        transport="in_cluster",
    )

    run = result.to_scan_run()

    issue = next(i for i in run.issues if i.source == "nodes")
    assert issue.code == "k8s_collector_failed"
    assert issue.severity == "error"
    assert issue.affects_coverage is True
    assert run.outcome is ScanOutcome.PARTIAL


def test_total_failure_maps_to_failed_outcome() -> None:
    result = K8sPostureResult(
        collectors=[
            _collector("pods", CollectorState.FAILED, message="transport unavailable"),
        ],
        status=K8sPostureStatus.FAILED,
        transport="unavailable",
    )

    run = result.to_scan_run()

    assert run.outcome is ScanOutcome.FAILED
    assert any(i.code == "k8s_collector_failed" for i in run.issues)


def test_truncated_collector_surfaces_a_coverage_issue() -> None:
    # A bounded/truncated read completed but did not see everything, so coverage
    # is incomplete even though the collector state is EXECUTED.
    result = K8sPostureResult(
        collectors=[
            _collector(
                "pods",
                CollectorState.EXECUTED,
                truncated=True,
                object_count=5000,
                message="collection reached its configured bound",
            ),
        ],
        status=K8sPostureStatus.PARTIAL,
        transport="in_cluster",
    )

    run = result.to_scan_run()

    assert run.outcome is ScanOutcome.PARTIAL
    issue = next(i for i in run.issues if i.source == "pods")
    assert issue.code == "k8s_collector_truncated"
    assert issue.affects_coverage is True


def test_skipped_collector_does_not_emit_an_issue() -> None:
    # An opt-in collector deliberately skipped is not a coverage gap.
    result = K8sPostureResult(
        collectors=[
            _collector("pods", CollectorState.EXECUTED),
            _collector(
                "kubelet_configz",
                CollectorState.SKIPPED,
                message="nodes/configz collection is opt-in and disabled",
            ),
        ],
        status=K8sPostureStatus.COMPLETE,
        transport="in_cluster",
    )

    run = result.to_scan_run()

    assert run.outcome is ScanOutcome.COMPLETE
    assert run.issues == []
