from __future__ import annotations

from agent_bom.api.trend_recording import trend_point_from_scan_result


def test_trend_point_uses_canonical_scan_result_and_vulnerability_counts() -> None:
    point = trend_point_from_scan_result(
        {
            "scan_id": "scan-123",
            "generated_at": "2026-08-20T12:00:00Z",
            "posture_scorecard": {"grade": "C", "score": 72.5, "no_data": False},
            "packages": [
                {
                    "name": "alpha",
                    "version": "1.0.0",
                    "vulnerabilities": [
                        {"id": "CVE-1", "severity": "critical"},
                        {"id": "CVE-2", "severity": "high"},
                    ],
                },
                {
                    "name": "beta",
                    "version": "2.0.0",
                    "vulnerabilities": [
                        {"id": "CVE-3", "severity": "medium"},
                        {"id": "CVE-4", "severity": "low"},
                    ],
                },
            ],
        },
        tenant_id="tenant-a",
    )

    assert point is not None
    assert point.idempotency_key == "tenant-a:scan-123"
    assert point.total_vulns == 4
    assert (point.critical, point.high, point.medium, point.low) == (1, 1, 1, 1)
    assert point.posture_score == 72.5


def test_trend_point_rejects_ungraded_or_identity_free_results() -> None:
    assert (
        trend_point_from_scan_result(
            {"scan_id": "scan-123", "posture_scorecard": {"grade": "N/A", "score": 0, "no_data": True}},
            tenant_id="tenant-a",
        )
        is None
    )
    assert (
        trend_point_from_scan_result(
            {"posture_scorecard": {"grade": "A", "score": 95, "no_data": False}},
            tenant_id="tenant-a",
        )
        is None
    )
