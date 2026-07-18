from __future__ import annotations

import pytest

from agent_bom.api import metrics


@pytest.fixture(autouse=True)
def _reset_metrics() -> None:
    metrics.reset_for_tests()


def test_authorization_evidence_metrics_are_bounded_and_secret_safe() -> None:
    metrics.record_authorization_evidence(
        provider="azure",
        status="partial",
        reason_codes=("access_denied", "Bearer secret"),
    )

    text = "\n".join(metrics.render_prometheus_lines())
    assert 'agent_bom_authorization_evidence_total{provider="azure",status="partial"} 1' in text
    assert 'agent_bom_authorization_evidence_gaps_total{provider="azure",reason="access_denied"} 1' in text
    assert "Bearer secret" not in text


def test_authorization_evidence_metrics_normalize_unknown_labels() -> None:
    metrics.record_authorization_evidence(provider="future-cloud", status="broken", reason_codes=("new-gap",))

    text = "\n".join(metrics.render_prometheus_lines())
    assert 'agent_bom_authorization_evidence_total{provider="unknown",status="indeterminate"} 1' in text
    assert 'agent_bom_authorization_evidence_gaps_total{provider="unknown",reason="unknown"} 1' in text


def test_cloud_connection_summary_records_partial_authorization_health() -> None:
    from agent_bom.mcp_tools.posture import _summarize_inventory_payload

    _summarize_inventory_payload(
        "gcp",
        {
            "authorization_evidence": {
                "required_sources": ["allow", "deny"],
                "sources": [
                    {"name": "allow", "state": "complete"},
                    {"name": "deny", "state": "truncated"},
                ],
            }
        },
    )

    text = "\n".join(metrics.render_prometheus_lines())
    assert 'agent_bom_authorization_evidence_total{provider="gcp",status="partial"} 1' in text
    assert 'agent_bom_authorization_evidence_gaps_total{provider="gcp",reason="truncated"} 1' in text
