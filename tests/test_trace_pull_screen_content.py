"""Trace-connector pull honors an explicit ``screen_content`` opt-out (bug-fix).

``POST /v1/traces/connectors/{provider}/pull`` collapsed the tri-state
``screen_content`` body flag with ``bool(...) or None``, turning an explicit
``false`` into ``None`` and letting the deployment default
(``AGENT_BOM_TRACE_CONTENT_SCREENING``) override a caller's explicit opt-out. The
push path already threads the tri-state through correctly; the pull path must
match: ``false`` respected, absent → default, ``true`` → screened.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

import agent_bom.api.routes.observability as obs


def _request() -> SimpleNamespace:
    return SimpleNamespace(state=SimpleNamespace(tenant_id="default"))


def _call_pull(monkeypatch: Any, body: dict, *, default_on: bool) -> dict:
    monkeypatch.setattr(obs, "_tenant_id", lambda request: "default")
    monkeypatch.setattr(obs, "_blast_radius_views_for_tenant", lambda tenant_id: [])
    monkeypatch.setattr(obs, "_nhi_by_credential_for_tenant", lambda tenant_id: {})
    # Deployment default for content screening.
    monkeypatch.setattr(
        "agent_bom.config.trace_content_screening_enabled", lambda: default_on
    )
    # Stub the connector fetch + screening so we observe only the resolved flag.
    monkeypatch.setattr("agent_bom.trace_connectors.fetch_traces", lambda *a, **k: {"spans": []})
    monkeypatch.setattr(obs, "_screen_trace_content_events", lambda body, *, tenant_id: [{"detector": "x"}])
    return asyncio.run(obs.pull_trace_connector(_request(), "langfuse", body))


def test_pull_screen_content_false_respected_when_default_on(monkeypatch: Any) -> None:
    result = _call_pull(monkeypatch, {"credentials": {"k": "v"}, "screen_content": False}, default_on=True)
    assert result["content_screened"] is False
    assert result["content_findings"] == []


def test_pull_screen_content_absent_uses_default_on(monkeypatch: Any) -> None:
    result = _call_pull(monkeypatch, {"credentials": {"k": "v"}}, default_on=True)
    assert result["content_screened"] is True
    assert result["content_findings"]


def test_pull_screen_content_absent_uses_default_off(monkeypatch: Any) -> None:
    result = _call_pull(monkeypatch, {"credentials": {"k": "v"}}, default_on=False)
    assert result["content_screened"] is False


def test_pull_screen_content_true_screens_when_default_off(monkeypatch: Any) -> None:
    result = _call_pull(monkeypatch, {"credentials": {"k": "v"}, "screen_content": True}, default_on=False)
    assert result["content_screened"] is True
    assert result["content_findings"]
