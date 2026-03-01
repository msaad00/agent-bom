"""Tests for alert pipeline — dispatcher, channels, and scan alert generation."""

import asyncio

from agent_bom.alerts.dispatcher import (
    AlertDispatcher,
    InMemoryChannel,
    WebhookChannel,
    _build_slack_payload,
)
from agent_bom.alerts.scan_alerts import alerts_from_scan_result

# ─── InMemoryChannel ─────────────────────────────────────────────────────────


def test_in_memory_channel_stores_alerts():
    ch = InMemoryChannel()
    asyncio.run(ch.send({"severity": "high", "message": "test"}))
    assert ch.count() == 1
    alerts = ch.list_alerts()
    assert alerts[0]["message"] == "test"


def test_in_memory_channel_bounded():
    ch = InMemoryChannel(max_size=3)
    for i in range(5):
        asyncio.run(ch.send({"severity": "low", "message": f"m{i}"}))
    assert ch.count() == 3
    # Most recent first
    assert ch.list_alerts()[0]["message"] == "m4"


def test_in_memory_channel_filter_severity():
    ch = InMemoryChannel()
    asyncio.run(ch.send({"severity": "high", "message": "h1"}))
    asyncio.run(ch.send({"severity": "low", "message": "l1"}))
    asyncio.run(ch.send({"severity": "high", "message": "h2"}))
    high = ch.list_alerts(severity="high")
    assert len(high) == 2
    assert all(a["severity"] == "high" for a in high)


def test_in_memory_channel_filter_detector():
    ch = InMemoryChannel()
    asyncio.run(ch.send({"detector": "scan_cve", "message": "a"}))
    asyncio.run(ch.send({"detector": "runtime", "message": "b"}))
    scan = ch.list_alerts(detector="scan_cve")
    assert len(scan) == 1


def test_in_memory_channel_pagination():
    ch = InMemoryChannel()
    for i in range(10):
        asyncio.run(ch.send({"severity": "low", "message": f"m{i}"}))
    page = ch.list_alerts(limit=3, offset=2)
    assert len(page) == 3
    assert page[0]["message"] == "m7"  # offset 2 from most-recent-first


def test_in_memory_channel_stats():
    ch = InMemoryChannel()
    asyncio.run(ch.send({"severity": "critical", "detector": "scan_kev"}))
    asyncio.run(ch.send({"severity": "high", "detector": "scan_cve"}))
    asyncio.run(ch.send({"severity": "high", "detector": "scan_cve"}))
    stats = ch.stats()
    assert stats["total"] == 3
    assert stats["by_severity"]["high"] == 2
    assert stats["by_detector"]["scan_cve"] == 2


# ─── Slack Payload ────────────────────────────────────────────────────────────


def test_slack_payload_format():
    payload = _build_slack_payload(
        {
            "severity": "critical",
            "message": "Test alert",
            "detector": "scan_kev",
            "ts": "2026-01-01T00:00:00Z",
        }
    )
    assert "blocks" in payload
    assert "CRITICAL" in payload["blocks"][0]["text"]["text"]
    assert "Test alert" in payload["blocks"][0]["text"]["text"]


# ─── WebhookChannel ──────────────────────────────────────────────────────────


def test_webhook_channel_init():
    ch = WebhookChannel("https://example.com/hook", headers={"X-Token": "abc"})
    assert ch.url == "https://example.com/hook"
    assert ch.headers["X-Token"] == "abc"


# ─── AlertDispatcher ─────────────────────────────────────────────────────────


def test_dispatcher_init_has_in_memory():
    d = AlertDispatcher()
    assert d.alert_count() == 0
    assert d.stats()["channels_registered"] == 1


def test_dispatcher_dispatch_stores_in_memory():
    d = AlertDispatcher()
    count = asyncio.run(d.dispatch({"severity": "high", "message": "test"}))
    assert count == 1
    assert d.alert_count() == 1
    assert d.list_alerts()[0]["message"] == "test"


def test_dispatcher_dispatch_adds_timestamp():
    d = AlertDispatcher()
    asyncio.run(d.dispatch({"severity": "low", "message": "no ts"}))
    alert = d.list_alerts()[0]
    assert "ts" in alert


def test_dispatcher_dispatch_alert_object():
    """Dispatcher accepts Alert dataclass objects via to_dict()."""
    from agent_bom.runtime.detectors import Alert, AlertSeverity

    d = AlertDispatcher()
    alert = Alert(detector="test", severity=AlertSeverity.HIGH, message="from detector")
    count = asyncio.run(d.dispatch(alert))
    assert count == 1
    stored = d.list_alerts()[0]
    assert stored["detector"] == "test"
    assert stored["severity"] == "high"


def test_dispatcher_add_webhook():
    d = AlertDispatcher()
    d.add_webhook("https://example.com/hook")
    assert d.stats()["webhook_count"] == 1
    assert d.stats()["channels_registered"] == 2


def test_dispatcher_remove_webhooks():
    d = AlertDispatcher()
    d.add_webhook("https://a.com")
    d.add_webhook("https://b.com")
    assert d.stats()["webhook_count"] == 2
    removed = d.remove_webhooks()
    assert removed == 2
    assert d.stats()["webhook_count"] == 0


def test_dispatcher_stats():
    d = AlertDispatcher()
    asyncio.run(d.dispatch({"severity": "critical", "detector": "scan_kev", "message": "a"}))
    asyncio.run(d.dispatch({"severity": "high", "detector": "scan_cve", "message": "b"}))
    stats = d.stats()
    assert stats["total_dispatched"] == 2
    assert stats["total"] == 2
    assert stats["by_severity"]["critical"] == 1


def test_dispatcher_list_alerts_filter():
    d = AlertDispatcher()
    asyncio.run(d.dispatch({"severity": "critical", "message": "c1"}))
    asyncio.run(d.dispatch({"severity": "low", "message": "l1"}))
    crit = d.list_alerts(severity="critical")
    assert len(crit) == 1


def test_dispatcher_handles_channel_failure():
    """Dispatcher continues when a channel raises."""

    class FailChannel:
        async def send(self, alert: dict) -> bool:
            raise RuntimeError("boom")

    d = AlertDispatcher()
    d.add_channel(FailChannel())
    # Should not raise — failure is logged
    count = asyncio.run(d.dispatch({"severity": "low", "message": "test"}))
    # InMemory succeeds, FailChannel fails
    assert count == 1
    assert d.stats()["total_channel_failures"] == 1


# ─── Scan Alert Generation ───────────────────────────────────────────────────


def test_alerts_from_scan_critical_cve():
    report = {
        "blast_radius": [
            {
                "vulnerability_id": "CVE-2024-1234",
                "severity": "critical",
                "package": {"name": "langchain"},
                "risk_score": 9.2,
            }
        ],
        "agents": [],
    }
    alerts = alerts_from_scan_result(report)
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "critical"
    assert "CVE-2024-1234" in alerts[0]["message"]


def test_alerts_from_scan_kev():
    report = {
        "blast_radius": [
            {
                "vulnerability_id": "CVE-2024-5678",
                "severity": "high",
                "is_kev": True,
                "package": {"name": "express"},
                "risk_score": 8.5,
            }
        ],
        "agents": [],
    }
    alerts = alerts_from_scan_result(report)
    assert len(alerts) == 1
    assert alerts[0]["detector"] == "scan_kev"
    assert "CISA KEV" in alerts[0]["message"]


def test_alerts_from_scan_malicious():
    report = {
        "blast_radius": [],
        "agents": [
            {"mcp_servers": [{"packages": [{"name": "mal-pkg", "version": "1.0", "is_malicious": True, "malicious_reason": "typosquat"}]}]}
        ],
    }
    alerts = alerts_from_scan_result(report)
    assert len(alerts) == 1
    assert alerts[0]["detector"] == "scan_malicious"
    assert alerts[0]["severity"] == "critical"


def test_alerts_from_scan_policy_violation():
    report = {
        "blast_radius": [],
        "agents": [],
        "policy_results": {
            "passed": False,
            "violations": [{"rule": "max_critical", "severity": "high", "message": "Too many critical CVEs"}],
        },
    }
    alerts = alerts_from_scan_result(report)
    assert len(alerts) == 1
    assert alerts[0]["detector"] == "scan_policy"


def test_alerts_from_scan_no_findings():
    report = {"blast_radius": [], "agents": []}
    alerts = alerts_from_scan_result(report)
    assert len(alerts) == 0


def test_alerts_from_scan_low_severity_ignored():
    report = {
        "blast_radius": [
            {
                "vulnerability_id": "CVE-2024-0001",
                "severity": "low",
                "package": {"name": "foo"},
                "risk_score": 2.0,
            }
        ],
        "agents": [],
    }
    alerts = alerts_from_scan_result(report)
    assert len(alerts) == 0
