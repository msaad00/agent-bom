"""Tests for runtime/server.py — coverage expansion for dispatch and HTTP routing."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from agent_bom.runtime.server import _dispatch, _route_http, _runtime_metrics_text


class TestDispatch:
    @pytest.mark.asyncio
    async def test_tool_call_default(self):
        engine = AsyncMock()
        engine.process_tool_call.return_value = [{"alert": "test"}]
        data = {"tool_name": "read_file", "arguments": {"path": "/tmp"}}
        result = await _dispatch(engine, data)
        assert result == [{"alert": "test"}]
        engine.process_tool_call.assert_called_once_with("read_file", {"path": "/tmp"})

    @pytest.mark.asyncio
    async def test_response_type(self):
        engine = AsyncMock()
        engine.process_tool_response.return_value = []
        data = {"type": "response", "tool_name": "write", "text": "done"}
        result = await _dispatch(engine, data)
        assert result == []
        engine.process_tool_response.assert_called_once_with("write", "done")

    @pytest.mark.asyncio
    async def test_drift_type(self):
        engine = AsyncMock()
        engine.check_tool_drift.return_value = [{"drift": True}]
        data = {"type": "drift", "tools": ["read", "write"]}
        result = await _dispatch(engine, data)
        assert result == [{"drift": True}]
        engine.check_tool_drift.assert_called_once_with(["read", "write"])

    @pytest.mark.asyncio
    async def test_default_tool_name(self):
        engine = AsyncMock()
        engine.process_tool_call.return_value = []
        data = {}
        await _dispatch(engine, data)
        engine.process_tool_call.assert_called_once_with("unknown", {})


class TestRouteHttp:
    @pytest.mark.asyncio
    async def test_get_status(self):
        engine = MagicMock()
        engine.status.return_value = {"active": True}
        status, body = await _route_http(engine, "GET", "/status", b"")
        assert status == "200 OK"
        assert body["active"] is True

    def test_runtime_metrics_text(self):
        engine = MagicMock()
        engine.status.return_value = {
            "active": True,
            "traces_processed": 3,
            "tool_calls_analyzed": 4,
            "alerts_generated": 2,
            "detectors_active": 8,
            "session_graph": {"node_count": 5, "edge_count": 6, "timeline_event_count": 7},
            "shield": {"active": True, "blocked": False, "escalations": 1, "blocks": 0, "alerts_in_window": 2, "threat_level": "high"},
        }
        metrics = _runtime_metrics_text(engine)
        assert "agent_bom_runtime_active 1" in metrics
        assert "agent_bom_runtime_tool_calls_analyzed_total 4" in metrics
        assert 'agent_bom_runtime_shield_threat_level{level="high"} 1' in metrics

    @pytest.mark.asyncio
    async def test_post_tool_call(self):
        engine = AsyncMock()
        engine.process_tool_call.return_value = [{"alert": "test"}]
        body = json.dumps({"tool_name": "read", "arguments": {"p": 1}}).encode()
        status, resp = await _route_http(engine, "POST", "/tool-call", body)
        assert status == "200 OK"
        assert resp["alerts"] == [{"alert": "test"}]

    @pytest.mark.asyncio
    async def test_post_tool_response(self):
        engine = AsyncMock()
        engine.process_tool_response.return_value = []
        body = json.dumps({"tool_name": "write", "text": "result"}).encode()
        status, resp = await _route_http(engine, "POST", "/tool-response", body)
        assert status == "200 OK"
        assert resp["alerts"] == []

    @pytest.mark.asyncio
    async def test_post_drift_check(self):
        engine = AsyncMock()
        engine.check_tool_drift.return_value = []
        body = json.dumps({"tools": ["a", "b"]}).encode()
        status, resp = await _route_http(engine, "POST", "/drift-check", body)
        assert status == "200 OK"

    @pytest.mark.asyncio
    async def test_method_not_allowed(self):
        engine = MagicMock()
        status, resp = await _route_http(engine, "DELETE", "/tool-call", b"")
        assert "405" in status

    @pytest.mark.asyncio
    async def test_unknown_path(self):
        engine = MagicMock()
        body = json.dumps({}).encode()
        status, resp = await _route_http(engine, "POST", "/unknown", body)
        assert "404" in status

    @pytest.mark.asyncio
    async def test_invalid_json_body(self):
        engine = MagicMock()
        status, resp = await _route_http(engine, "POST", "/tool-call", b"invalid json")
        assert "400" in status

    @pytest.mark.asyncio
    async def test_empty_body(self):
        engine = AsyncMock()
        engine.process_tool_call.return_value = []
        status, resp = await _route_http(engine, "POST", "/tool-call", b"")
        assert status == "200 OK"
