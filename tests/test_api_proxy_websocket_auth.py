"""Regression tests for proxy WebSocket authentication edges."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from agent_bom.api.server import app


def test_proxy_metrics_websocket_rejects_invalid_first_message_token(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_API_KEY", "ws-secret")
    client = TestClient(app)

    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/ws/proxy/metrics") as websocket:
            websocket.send_json({"type": "auth", "token": "wrong-secret"})
            websocket.receive_json()

    assert exc.value.code == 4001


def test_proxy_alerts_websocket_rejects_query_token(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_API_KEY", "ws-secret")
    client = TestClient(app)

    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/ws/proxy/alerts?token=ws-secret"):
            pass

    assert exc.value.code == 4001
