"""Tests for API proxy status/alerts and scorecard endpoints."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from starlette.testclient import TestClient

from agent_bom.api.server import (
    app,
    push_proxy_alert,
    push_proxy_metrics,
)

# ── /v1/proxy/status ───────────────────────────────────────────────────────


def test_proxy_status_no_session():
    """Returns no_proxy_session when no proxy has run."""
    import agent_bom.api.server as srv

    # Reset state
    srv._proxy_metrics = None
    old = os.environ.pop("AGENT_BOM_LOG", None)
    try:
        client = TestClient(app)
        resp = client.get("/v1/proxy/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "no_proxy_session"
    finally:
        if old is not None:
            os.environ["AGENT_BOM_LOG"] = old


def test_proxy_status_with_metrics():
    """Returns metrics when push_proxy_metrics has been called."""
    import agent_bom.api.server as srv

    metrics = {
        "type": "proxy_summary",
        "uptime_seconds": 120.5,
        "total_tool_calls": 42,
        "total_blocked": 3,
    }
    push_proxy_metrics(metrics)

    client = TestClient(app)
    resp = client.get("/v1/proxy/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_tool_calls"] == 42
    assert data["total_blocked"] == 3

    # Cleanup
    srv._proxy_metrics = None


def test_proxy_status_from_log():
    """Reads metrics from a JSONL audit log file via AGENT_BOM_LOG env."""
    import agent_bom.api.server as srv

    srv._proxy_metrics = None

    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        f.write(json.dumps({"type": "tools/call", "tool": "read"}) + "\n")
        f.write(json.dumps({"type": "proxy_summary", "total_tool_calls": 10, "total_blocked": 1}) + "\n")
        log_path = f.name

    old = os.environ.get("AGENT_BOM_LOG")
    os.environ["AGENT_BOM_LOG"] = log_path
    try:
        client = TestClient(app)
        resp = client.get("/v1/proxy/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_tool_calls"] == 10
    finally:
        if old is not None:
            os.environ["AGENT_BOM_LOG"] = old
        else:
            os.environ.pop("AGENT_BOM_LOG", None)
        Path(log_path).unlink(missing_ok=True)


def test_proxy_status_from_log_no_summary():
    """Returns no_proxy_session when log file has no proxy_summary."""
    import agent_bom.api.server as srv

    srv._proxy_metrics = None

    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        f.write(json.dumps({"type": "tools/call", "tool": "read"}) + "\n")
        log_path = f.name

    old = os.environ.get("AGENT_BOM_LOG")
    os.environ["AGENT_BOM_LOG"] = log_path
    try:
        client = TestClient(app)
        resp = client.get("/v1/proxy/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "no_proxy_session"
    finally:
        if old is not None:
            os.environ["AGENT_BOM_LOG"] = old
        else:
            os.environ.pop("AGENT_BOM_LOG", None)
        Path(log_path).unlink(missing_ok=True)


# ── /v1/proxy/alerts ──────────────────────────────────────────────────────


def test_proxy_alerts_empty():
    """Returns empty list when no alerts."""
    import agent_bom.api.server as srv

    srv._proxy_alerts.clear()
    old = os.environ.pop("AGENT_BOM_LOG", None)
    try:
        client = TestClient(app)
        resp = client.get("/v1/proxy/alerts")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 0
        assert data["alerts"] == []
    finally:
        if old is not None:
            os.environ["AGENT_BOM_LOG"] = old


def test_proxy_alerts_with_data():
    """Returns alerts pushed via push_proxy_alert."""
    import agent_bom.api.server as srv

    srv._proxy_alerts.clear()
    push_proxy_alert({
        "type": "runtime_alert",
        "detector": "credential_leak",
        "severity": "critical",
        "message": "AWS key in response",
    })
    push_proxy_alert({
        "type": "runtime_alert",
        "detector": "argument_analyzer",
        "severity": "high",
        "message": "Path traversal detected",
    })

    client = TestClient(app)
    resp = client.get("/v1/proxy/alerts")
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] == 2

    # Cleanup
    srv._proxy_alerts.clear()


def test_proxy_alerts_filter_severity():
    """Filters alerts by severity query param."""
    import agent_bom.api.server as srv

    srv._proxy_alerts.clear()
    push_proxy_alert({"type": "runtime_alert", "detector": "cred", "severity": "critical", "message": "a"})
    push_proxy_alert({"type": "runtime_alert", "detector": "arg", "severity": "high", "message": "b"})
    push_proxy_alert({"type": "runtime_alert", "detector": "cred2", "severity": "critical", "message": "c"})

    client = TestClient(app)
    resp = client.get("/v1/proxy/alerts?severity=critical")
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] == 2
    for alert in data["alerts"]:
        assert alert["severity"] == "critical"

    srv._proxy_alerts.clear()


def test_proxy_alerts_filter_detector():
    """Filters alerts by detector query param."""
    import agent_bom.api.server as srv

    srv._proxy_alerts.clear()
    push_proxy_alert({"type": "runtime_alert", "detector": "credential_leak", "severity": "critical", "message": "a"})
    push_proxy_alert({"type": "runtime_alert", "detector": "argument_analyzer", "severity": "high", "message": "b"})

    client = TestClient(app)
    resp = client.get("/v1/proxy/alerts?detector=credential_leak")
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] == 1
    assert data["alerts"][0]["detector"] == "credential_leak"

    srv._proxy_alerts.clear()


def test_proxy_alerts_from_log():
    """Reads alerts from a JSONL audit log file via AGENT_BOM_LOG env."""
    import agent_bom.api.server as srv

    srv._proxy_alerts.clear()

    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        f.write(json.dumps({"type": "tools/call", "tool": "read"}) + "\n")
        f.write(json.dumps({"type": "runtime_alert", "detector": "cred", "severity": "critical", "message": "leak"}) + "\n")
        f.write(json.dumps({"type": "runtime_alert", "detector": "seq", "severity": "high", "message": "exfil"}) + "\n")
        log_path = f.name

    old = os.environ.get("AGENT_BOM_LOG")
    os.environ["AGENT_BOM_LOG"] = log_path
    try:
        client = TestClient(app)
        resp = client.get("/v1/proxy/alerts")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 2
    finally:
        if old is not None:
            os.environ["AGENT_BOM_LOG"] = old
        else:
            os.environ.pop("AGENT_BOM_LOG", None)
        Path(log_path).unlink(missing_ok=True)


def test_proxy_alerts_limit():
    """Respects the limit query param."""
    import agent_bom.api.server as srv

    srv._proxy_alerts.clear()
    for i in range(10):
        push_proxy_alert({"type": "runtime_alert", "detector": f"d{i}", "severity": "high", "message": f"m{i}"})

    client = TestClient(app)
    resp = client.get("/v1/proxy/alerts?limit=3")
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] == 3

    srv._proxy_alerts.clear()


# ── /v1/scorecard ─────────────────────────────────────────────────────────


def test_scorecard_no_repo():
    """Returns error when package can't be resolved to a repo."""
    client = TestClient(app)
    resp = client.get("/v1/scorecard/pypi/some-unknown-package")
    assert resp.status_code == 200
    data = resp.json()
    assert data["scorecard"] is None
    assert "error" in data


def test_scorecard_github_direct():
    """Accepts GitHub owner/repo path directly."""
    client = TestClient(app)
    from unittest.mock import AsyncMock, patch

    mock_data = {
        "score": 7.5,
        "date": "2026-02-20",
        "repo": "expressjs/express",
        "checks": {"Code-Review": 8, "Maintained": 10},
    }
    with patch("agent_bom.scorecard.fetch_scorecard", new_callable=AsyncMock, return_value=mock_data):
        resp = client.get("/v1/scorecard/npm/expressjs/express")
        assert resp.status_code == 200
        data = resp.json()
        assert data["scorecard"]["score"] == 7.5
        assert data["repo"] == "expressjs/express"


# ── Proxy webhook (_send_webhook) ─────────────────────────────────────────


def test_send_webhook():
    """_send_webhook makes a POST request to the given URL."""
    import asyncio
    from unittest.mock import AsyncMock, patch

    from agent_bom.proxy import _send_webhook

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        payload = {"type": "runtime_alert", "severity": "critical", "message": "test"}
        asyncio.run(_send_webhook("https://hooks.example.com/test", payload))

        mock_client.post.assert_called_once_with(
            "https://hooks.example.com/test",
            json=payload,
        )


def test_send_webhook_failure_silent():
    """_send_webhook silently handles failures."""
    import asyncio
    from unittest.mock import AsyncMock, patch

    from agent_bom.proxy import _send_webhook

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.post.side_effect = Exception("connection failed")
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        # Should not raise
        asyncio.run(_send_webhook("https://hooks.example.com/test", {"test": True}))


# ── Proxy CLI --alert-webhook flag ────────────────────────────────────────


def test_proxy_cli_alert_webhook_flag():
    """'agent-bom proxy --help' mentions alert-webhook."""
    from click.testing import CliRunner

    from agent_bom.cli import main

    runner = CliRunner()
    result = runner.invoke(main, ["proxy", "--help"])
    assert result.exit_code == 0
    assert "--alert-webhook" in result.output


# ── HTTP client log sanitization ──────────────────────────────────────────


def test_sanitize_for_log():
    """Log sanitizer strips newlines."""
    from agent_bom.http_client import _sanitize_for_log

    assert _sanitize_for_log("normal") == "normal"
    assert "\\n" in _sanitize_for_log("line1\nline2")
    assert "\\r" in _sanitize_for_log("line1\rline2")


# ── Scorecard repo validation ────────────────────────────────────────────


def test_scorecard_rejects_invalid_package():
    """Scorecard endpoint rejects packages with invalid chars."""
    client = TestClient(app)
    # Pipe is not in the [A-Za-z0-9._@/:-] allowlist
    resp = client.get("/v1/scorecard/npm/foo|bar")
    assert resp.status_code == 400
