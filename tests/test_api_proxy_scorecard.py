"""Tests for API proxy status/alerts and scorecard endpoints."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from agent_bom.api.server import (
    app,
    push_proxy_alert,
    push_proxy_metrics,
)
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

# ── /v1/proxy/status ───────────────────────────────────────────────────────


def test_proxy_status_no_session():
    """Returns no_proxy_session when no proxy has run."""
    import agent_bom.api.routes.proxy as proxy_mod

    # Reset state
    proxy_mod._proxy_metrics = None
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
    import agent_bom.api.routes.proxy as proxy_mod

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
    assert data["alert_summary"]["total_alerts"] == 0
    assert data["recent_alerts"] == []

    # Cleanup
    proxy_mod._proxy_metrics = None


def test_proxy_metrics_websocket_rejects_query_token(monkeypatch):
    """WebSocket auth must not accept API keys in URL query strings."""
    monkeypatch.setenv("AGENT_BOM_API_KEY", "ws-secret")
    client = TestClient(app)

    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/ws/proxy/metrics?token=ws-secret"):
            pass

    assert exc.value.code == 4001


def test_proxy_metrics_websocket_first_message_auth(monkeypatch):
    """Browser WebSocket clients authenticate with a first-message handshake."""
    import agent_bom.api.routes.proxy as proxy_mod

    monkeypatch.setenv("AGENT_BOM_API_KEY", "ws-secret")
    push_proxy_metrics({"type": "proxy_summary", "total_tool_calls": 2, "total_blocked": 1})
    client = TestClient(app)

    with client.websocket_connect("/ws/proxy/metrics") as websocket:
        websocket.send_json({"type": "auth", "token": "ws-secret"})
        assert websocket.receive_json() == {"type": "auth", "status": "ok"}
        data = websocket.receive_json()
        assert data["total_tool_calls"] == 2
        assert data["total_blocked"] == 1

    proxy_mod._proxy_metrics = None


def test_proxy_status_from_log():
    """Reads metrics from a JSONL audit log file via AGENT_BOM_LOG env."""
    import agent_bom.api.routes.proxy as proxy_mod

    proxy_mod._proxy_metrics = None

    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        f.write(json.dumps({"type": "tools/call", "tool": "read"}) + "\n")
        f.write(json.dumps({"type": "proxy_summary", "total_tool_calls": 10, "total_blocked": 1}) + "\n")
        f.write(
            json.dumps(
                {"type": "runtime_alert", "detector": "cred", "severity": "critical", "message": "leak", "ts": "2026-03-24T10:00:00+00:00"}
            )
            + "\n"
        )
        log_path = f.name

    old = os.environ.get("AGENT_BOM_LOG")
    os.environ["AGENT_BOM_LOG"] = log_path
    try:
        client = TestClient(app)
        resp = client.get("/v1/proxy/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_tool_calls"] == 10
        assert data["alert_summary"]["total_alerts"] == 1
        assert data["alert_summary"]["alerts_by_severity"]["critical"] == 1
    finally:
        if old is not None:
            os.environ["AGENT_BOM_LOG"] = old
        else:
            os.environ.pop("AGENT_BOM_LOG", None)
        Path(log_path).unlink(missing_ok=True)


def test_proxy_status_from_log_no_summary():
    """Returns no_proxy_session when log file has no proxy_summary."""
    import agent_bom.api.routes.proxy as proxy_mod

    proxy_mod._proxy_metrics = None

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
    import agent_bom.api.routes.proxy as proxy_mod

    proxy_mod._proxy_alerts.clear()
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
    import agent_bom.api.routes.proxy as proxy_mod

    proxy_mod._proxy_alerts.clear()
    push_proxy_alert(
        {
            "type": "runtime_alert",
            "detector": "credential_leak",
            "severity": "critical",
            "message": "AWS key in response",
        }
    )
    push_proxy_alert(
        {
            "type": "runtime_alert",
            "detector": "argument_analyzer",
            "severity": "high",
            "message": "Path traversal detected",
        }
    )

    client = TestClient(app)
    resp = client.get("/v1/proxy/alerts")
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] == 2
    assert data["summary"]["total_alerts"] == 2
    assert data["summary"]["alerts_by_severity"]["critical"] == 1

    # Cleanup
    proxy_mod._proxy_alerts.clear()


def test_proxy_audit_ingest_updates_alerts_and_status():
    import agent_bom.api.routes.proxy as proxy_mod

    proxy_mod._proxy_alerts.clear()
    proxy_mod._proxy_metrics = None


def test_proxy_alert_api_redacts_runtime_alert_details():
    import agent_bom.api.routes.proxy as proxy_mod

    proxy_mod._proxy_alerts.clear()
    github_token = "ghp_" + "abcdefghijklmnopqrstuvwxyz" + "123456"
    api_key = "sk-" + "live-" + "abcdefghijklmnopqrstuvwxyz"
    push_proxy_alert(
        {
            "type": "runtime_alert",
            "detector": "argument_analyzer",
            "severity": "high",
            "message": "danger",
            "details": {
                "url": f"https://user:pass@example.com/callback?token={github_token}",
                "value_preview": api_key,
                "path": "/Users/alice/prod-secrets/openai-key.env",
            },
        }
    )

    data = TestClient(app).get("/v1/proxy/alerts").json()
    encoded = json.dumps(data)
    assert "user:pass" not in encoded
    assert "token=" not in encoded
    assert "sk-live" not in encoded
    assert "/Users/alice" not in encoded
    assert "prod-secrets" not in encoded
    proxy_mod._proxy_alerts.clear()


def test_proxy_alerts_are_tenant_scoped_for_http_reads():
    import agent_bom.api.routes.proxy as proxy_mod
    from agent_bom.api.server import configure_api

    enable_trusted_proxy_env()
    configure_api(api_key=None)
    proxy_mod._proxy_alerts.clear()
    proxy_mod._proxy_metrics = None
    try:
        client = TestClient(app)
        alpha_headers = proxy_headers(role="admin", tenant="tenant-alpha")
        beta_headers = proxy_headers(role="admin", tenant="tenant-beta")

        assert (
            client.post(
                "/v1/proxy/audit",
                headers=alpha_headers,
                json={
                    "source_id": "alpha-laptop",
                    "session_id": "alpha-session",
                    "alerts": [{"type": "runtime_alert", "detector": "cred", "severity": "critical", "message": "alpha-only"}],
                    "summary": {"type": "proxy_summary", "total_tool_calls": 7, "total_blocked": 1},
                },
            ).status_code
            == 200
        )
        assert (
            client.post(
                "/v1/proxy/audit",
                headers=beta_headers,
                json={
                    "source_id": "beta-laptop",
                    "session_id": "beta-session",
                    "alerts": [{"type": "runtime_alert", "detector": "arg", "severity": "high", "message": "beta-only"}],
                    "summary": {"type": "proxy_summary", "total_tool_calls": 3, "total_blocked": 0},
                },
            ).status_code
            == 200
        )

        alpha_alerts = client.get("/v1/proxy/alerts", headers=alpha_headers).json()
        beta_alerts = client.get("/v1/proxy/alerts", headers=beta_headers).json()
        assert alpha_alerts["count"] == 1
        assert beta_alerts["count"] == 1
        assert alpha_alerts["alerts"][0]["source_id"] == "alpha-laptop"
        assert beta_alerts["alerts"][0]["source_id"] == "beta-laptop"
        assert "beta-laptop" not in json.dumps(alpha_alerts)
        assert "alpha-laptop" not in json.dumps(beta_alerts)

        alpha_status = client.get("/v1/proxy/status", headers=alpha_headers).json()
        beta_status = client.get("/v1/proxy/status", headers=beta_headers).json()
        assert alpha_status["source_id"] == "alpha-laptop"
        assert beta_status["source_id"] == "beta-laptop"
        assert alpha_status["alert_summary"]["total_alerts"] == 1
        assert beta_status["alert_summary"]["total_alerts"] == 1
    finally:
        proxy_mod._proxy_alerts.clear()
        proxy_mod._proxy_metrics = None
        proxy_mod._proxy_metrics_by_tenant.clear()
        disable_trusted_proxy_env()
        configure_api(api_key=None)


def test_proxy_alerts_drop_tier_b_replay_only_fields():
    import agent_bom.api.routes.proxy as proxy_mod

    proxy_mod._proxy_alerts.clear()
    proxy_mod._proxy_metrics = None
    try:
        payload = {
            "source_id": "laptop-1",
            "session_id": "sess-1",
            "alerts": [
                {
                    "type": "runtime_alert",
                    "detector": "argument_analyzer",
                    "severity": "critical",
                    "message": "raw prompt copied from workspace",
                    "tool_name": "shell.exec",
                    "details": {
                        "prompt": "summarize /Users/alice/customer-contract.txt",
                        "tool_output": "customer secret output",
                        "args": ["cat", "/Users/alice/customer-contract.txt"],
                        "url": "https://example.com/full/path?token=secret",
                        "hostname": "mcp.internal.example",
                        "status_code": 403,
                    },
                }
            ],
        }
        resp = TestClient(app).post("/v1/proxy/audit", json=payload)
        assert resp.status_code == 200

        data = TestClient(app).get("/v1/proxy/alerts").json()
        encoded = json.dumps(data)
        assert "shell.exec" in encoded
        assert "mcp.internal.example" in encoded
        assert "403" in encoded
        assert "prompt" not in encoded
        assert "tool_output" not in encoded
        assert "customer-contract" not in encoded
        assert "token=secret" not in encoded
        assert "raw prompt copied" not in encoded
    finally:
        proxy_mod._proxy_alerts.clear()
        proxy_mod._proxy_metrics = None
        proxy_mod._proxy_metrics_by_tenant.clear()


def test_proxy_audit_ingest_is_idempotent():
    import agent_bom.api.routes.proxy as proxy_mod

    proxy_mod._proxy_alerts.clear()
    proxy_mod._proxy_metrics = None


@pytest.mark.asyncio
async def test_proxy_audit_ingest_records_analytics_with_session_trace_context(monkeypatch):
    import agent_bom.api.routes.proxy as proxy_mod
    from agent_bom.api.models import ProxyAuditIngestRequest

    proxy_mod._proxy_alerts.clear()
    proxy_mod._proxy_metrics = None

    class _Analytics:
        def __init__(self):
            self.events = []
            self.tenants = []

        def record_events(self, events, *, tenant_id="default"):
            self.events.extend(events)
            self.tenants.append(tenant_id)

    analytics = _Analytics()
    monkeypatch.setattr("agent_bom.api.stores._get_analytics_store", lambda: analytics)
    request = SimpleNamespace(
        state=SimpleNamespace(
            api_key_name="tenant-analyst",
            tenant_id="tenant-alpha",
            request_id="req-1",
            trace_id="0123456789abcdef0123456789abcdef",
        )
    )
    payload = ProxyAuditIngestRequest(
        source_id="laptop-1",
        session_id="sess-1",
        alerts=[
            {
                "type": "runtime_alert",
                "detector": "credential_leak",
                "severity": "critical",
                "message": "AWS key copied from /Users/alice/prod",
                "details": {"prompt": "raw user prompt", "url": "https://example.com?token=secret"},
            }
        ],
    )
    resp = await proxy_mod.ingest_proxy_audit(request, payload)
    assert resp["ingested"] is True
    assert analytics.tenants == ["tenant-alpha"]
    assert analytics.events[0]["session_id"] == "sess-1"
    assert analytics.events[0]["source_id"] == "laptop-1"
    assert analytics.events[0]["request_id"] == "req-1"
    assert analytics.events[0]["trace_id"] == "0123456789abcdef0123456789abcdef"
    assert "message" not in analytics.events[0]
    assert "details" not in analytics.events[0]

    proxy_mod._proxy_alerts.clear()
    proxy_mod._proxy_metrics = None

    client = TestClient(app)
    payload = {
        "source_id": "laptop-1",
        "session_id": "sess-1",
        "idempotency_key": "proxy-audit-1",
        "alerts": [{"type": "runtime_alert", "detector": "credential_leak", "severity": "critical", "message": "AWS key"}],
        "summary": {"type": "proxy_summary", "total_tool_calls": 7, "total_blocked": 2},
    }
    first = client.post("/v1/proxy/audit", json=payload)
    second = client.post("/v1/proxy/audit", json=payload)
    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json()["idempotent_replay"] is True

    alerts = client.get("/v1/proxy/alerts")
    assert alerts.json()["count"] == 1

    proxy_mod._proxy_alerts.clear()
    proxy_mod._proxy_metrics = None

    client = TestClient(app)
    ingest = client.post(
        "/v1/proxy/audit",
        json={
            "source_id": "laptop-1",
            "session_id": "sess-1",
            "alerts": [{"type": "runtime_alert", "detector": "credential_leak", "severity": "critical", "message": "AWS key"}],
            "summary": {"type": "proxy_summary", "total_tool_calls": 7, "total_blocked": 2},
        },
    )
    assert ingest.status_code == 200
    assert ingest.json()["alert_count"] == 1

    alerts = client.get("/v1/proxy/alerts")
    assert alerts.status_code == 200
    assert alerts.json()["count"] == 1
    assert alerts.json()["alerts"][0]["source_id"] == "laptop-1"

    status = client.get("/v1/proxy/status")
    assert status.status_code == 200
    assert status.json()["total_tool_calls"] == 7
    assert status.json()["source_id"] == "laptop-1"

    proxy_mod._proxy_alerts.clear()
    proxy_mod._proxy_metrics = None


def test_proxy_alerts_filter_severity():
    """Filters alerts by severity query param."""
    import agent_bom.api.routes.proxy as proxy_mod

    proxy_mod._proxy_alerts.clear()
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

    proxy_mod._proxy_alerts.clear()


def test_proxy_alerts_filter_detector():
    """Filters alerts by detector query param."""
    import agent_bom.api.routes.proxy as proxy_mod

    proxy_mod._proxy_alerts.clear()
    push_proxy_alert({"type": "runtime_alert", "detector": "credential_leak", "severity": "critical", "message": "a"})
    push_proxy_alert({"type": "runtime_alert", "detector": "argument_analyzer", "severity": "high", "message": "b"})

    client = TestClient(app)
    resp = client.get("/v1/proxy/alerts?detector=credential_leak")
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] == 1
    assert data["alerts"][0]["detector"] == "credential_leak"

    proxy_mod._proxy_alerts.clear()


def test_proxy_alerts_from_log():
    """Reads alerts from a JSONL audit log file via AGENT_BOM_LOG env."""
    import agent_bom.api.routes.proxy as proxy_mod

    proxy_mod._proxy_alerts.clear()

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
    import agent_bom.api.routes.proxy as proxy_mod

    proxy_mod._proxy_alerts.clear()
    for i in range(10):
        push_proxy_alert({"type": "runtime_alert", "detector": f"d{i}", "severity": "high", "message": f"m{i}"})

    client = TestClient(app)
    resp = client.get("/v1/proxy/alerts?limit=3")
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] == 3

    proxy_mod._proxy_alerts.clear()


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

    with patch("agent_bom.security.validate_url"), patch("httpx.AsyncClient") as mock_client_cls:
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

    with patch("agent_bom.security.validate_url"), patch("httpx.AsyncClient") as mock_client_cls:
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
