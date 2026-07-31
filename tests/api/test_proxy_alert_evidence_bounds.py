"""The JSONL evidence read is bounded per caller, not globally shrunk to the feed's cap.

PR #4558 replaced a whole-file scan with a newest-first tail read — a genuine
improvement — but carried the cap from 50,000 down to 1,000 for every caller of
``_load_proxy_alerts``. Five non-feed evidence surfaces (finding runtime
evidence, the runtime production index, the showcase gateway, ``/v1/proxy/alerts``
and the compliance ``has_proxy`` summary) silently began seeing 50x less
evidence with no ``partial`` signal. The feed keeps its small cap; evidence
readers get the evidence bound back.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_bom.api.routes import proxy as proxy_routes

TENANT = "tenant-evidence-bounds"


def _write_alert_log(path: Path, count: int, *, tenant_id: str = TENANT) -> None:
    # ``event_id`` is the identity that survives the SAFE_TO_STORE redaction the
    # read applies; ``message`` is stripped as free text.
    with open(path, "w", encoding="utf-8") as handle:
        for index in range(count):
            handle.write(
                json.dumps(
                    {
                        "type": "runtime_alert",
                        "tenant_id": tenant_id,
                        "detector": "credential_leak",
                        "severity": "high",
                        "event_id": f"log-{index:05d}",
                        "ts": f"2026-07-{(index % 28) + 1:02d}T00:00:00+00:00",
                    }
                )
                + "\n"
            )


@pytest.fixture
def alert_log(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    proxy_routes._reset_proxy_runtime_for_tests()
    log_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("AGENT_BOM_LOG", str(log_path))
    try:
        yield log_path
    finally:
        proxy_routes._reset_proxy_runtime_for_tests()


def _ids(alerts: list[dict]) -> list[str]:
    return [str(alert.get("event_id", "")) for alert in alerts]


def test_evidence_cap_is_the_evidence_bound_not_the_feed_bound() -> None:
    assert proxy_routes._MAX_EVIDENCE_LOG_LINES == 50_000
    assert proxy_routes._MAX_FEED_LOG_LINES == 1_000


def test_evidence_callers_see_far_more_than_the_feed_cap(alert_log: Path) -> None:
    """5,000 records must not be silently truncated to 1,000 for evidence readers."""
    _write_alert_log(alert_log, 5_000)

    alerts = proxy_routes._load_proxy_alerts(TENANT)

    assert len(alerts) == 5_000, len(alerts)
    # The oldest record is retained, not dropped off the front.
    assert "log-00000" in _ids(alerts)


def test_feed_caller_keeps_its_small_bounded_read(alert_log: Path) -> None:
    from agent_bom.api.routes.gateway_feed import _load_tenant_alerts

    _write_alert_log(alert_log, 5_000)

    alerts = _load_tenant_alerts(TENANT)

    assert len(alerts) == proxy_routes._MAX_FEED_LOG_LINES, len(alerts)
    # Newest-first tail read from #4558 is preserved: the tail is what is kept.
    assert "log-04999" in _ids(alerts)
    assert "log-00000" not in _ids(alerts)


def test_tail_read_still_keeps_the_newest_when_the_evidence_cap_is_exceeded(alert_log: Path, monkeypatch) -> None:
    """Past the bound, the read is still newest-first — never the oldest N."""
    monkeypatch.setattr(proxy_routes, "_MAX_EVIDENCE_LOG_LINES", 100)
    _write_alert_log(alert_log, 250)

    alerts = proxy_routes._load_proxy_alerts(TENANT)

    assert len(alerts) == 100, len(alerts)
    event_ids = _ids(alerts)
    assert "log-00249" in event_ids
    assert "log-00000" not in event_ids


def test_explicit_limit_overrides_the_default(alert_log: Path) -> None:
    _write_alert_log(alert_log, 300)

    assert len(proxy_routes._load_proxy_alerts(TENANT, limit=50)) == 50
    assert len(proxy_routes._load_proxy_alerts(TENANT)) == 300


def test_tenant_scoping_still_applies_to_the_widened_read(alert_log: Path) -> None:
    """A bigger bound must not widen tenant visibility."""
    with open(alert_log, "w", encoding="utf-8") as handle:
        for index in range(100):
            handle.write(json.dumps({"type": "runtime_alert", "tenant_id": "tenant-other", "event_id": f"other-{index}"}) + "\n")
        for index in range(10):
            handle.write(json.dumps({"type": "runtime_alert", "tenant_id": TENANT, "event_id": f"mine-{index}"}) + "\n")

    alerts = proxy_routes._load_proxy_alerts(TENANT)

    assert len(alerts) == 10, len(alerts)
    assert all(event_id.startswith("mine-") for event_id in _ids(alerts))


def test_proxy_status_metrics_read_uses_the_evidence_bound(alert_log: Path) -> None:
    """The proxy_summary scan is an evidence read too — it was cut 50x alongside."""
    with open(alert_log, "w", encoding="utf-8") as handle:
        handle.write(json.dumps({"type": "proxy_summary", "tenant_id": TENANT, "requests": 1}) + "\n")
        for index in range(3_000):
            handle.write(json.dumps({"type": "runtime_alert", "tenant_id": TENANT, "event_id": f"pad-{index}"}) + "\n")
        handle.write(json.dumps({"type": "proxy_summary", "tenant_id": TENANT, "requests": 99}) + "\n")

    summary = proxy_routes._read_metrics_from_log(alert_log, TENANT)

    # The last summary in the file wins; at a 1,000-line bound it was unreachable.
    assert summary is not None
    assert summary["requests"] == 99, summary
