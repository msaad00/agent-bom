"""Tests for trace explorer correlation (#3608)."""

from __future__ import annotations

from agent_bom.api.trace_explorer import build_trace_explorer_payload, correlate_findings


def test_correlate_findings_matches_agent_and_tool() -> None:
    findings = [
        {
            "id": "CVE-2024-1:pkg",
            "vulnerability_id": "CVE-2024-1",
            "affected_agents": ["dev-agent"],
            "exposed_tools": ["run_shell"],
            "framework_tags": ["owasp_llm:LLM05"],
            "runtime_evidence": {"state": "blocked"},
        }
    ]
    matched = correlate_findings(agent="dev-agent", tool="run_shell", findings=findings)
    assert matched[0]["vulnerability_id"] == "CVE-2024-1"
    assert "owasp_llm:LLM05" in matched[0]["framework_tags"]


def test_build_trace_explorer_payload_groups_blocked_span_with_findings() -> None:
    payload = build_trace_explorer_payload(
        tenant_id="tenant-a",
        feed_events=[
            {
                "ts": "2026-07-06T12:00:00Z",
                "agent": "dev-agent",
                "action_type": "tool_call_blocked",
                "target": "run_shell",
                "detail": "policy",
                "shadow": False,
                "source": "proxy",
            }
        ],
        findings=[
            {
                "vulnerability_id": "CVE-2024-9",
                "affected_agents": ["dev-agent"],
                "exposed_tools": ["run_shell"],
                "framework_tags": ["nist_csf:ID.RA-01"],
            }
        ],
        sessions=[],
        observations=[],
        limit=10,
    )
    assert payload["blocked_count"] == 1
    session = payload["sessions"][0]
    span = session["spans"][0]
    assert span["verdict"] == "blocked"
    assert span["linked_findings"][0]["vulnerability_id"] == "CVE-2024-9"
    assert "nist_csf:ID.RA-01" in span["compliance_controls"]


# ── Event-loop offload + limit bounding (pre-release scale hardening) ─────────


def test_trace_explorer_handler_offloads_to_thread(monkeypatch) -> None:
    """The /runtime/trace-explorer handler must never build its payload on the loop."""
    import asyncio

    from agent_bom.api.routes import observability

    monkeypatch.setattr(observability, "_tenant_id", lambda request: "tenant-x")

    calls: dict[str, object] = {}

    async def _fake_to_thread(func, /, *args, **kwargs):
        calls["func"] = func
        calls["args"] = args
        calls["kwargs"] = kwargs
        return {"offloaded": True}

    monkeypatch.setattr(observability.asyncio, "to_thread", _fake_to_thread)

    result = asyncio.run(observability.trace_explorer(request=object(), limit=500))

    assert result == {"offloaded": True}
    assert calls["func"] is observability._build_trace_explorer_payload_sync
    assert calls["args"] == ("tenant-x",)
    # limit is bounded to <= 200 before offload
    assert calls["kwargs"]["limit"] == 200


def test_build_trace_explorer_payload_sync_bounds_findings(monkeypatch) -> None:
    """Findings iteration is capped at the request limit, not the whole estate."""
    from agent_bom.api import trace_explorer as trace_explorer_mod
    from agent_bom.api.routes import gateway_feed, observability, scan
    from agent_bom.api.routes.scan import _completed_jobs_for_tenant  # noqa: F401

    monkeypatch.setattr(gateway_feed, "_load_tenant_alerts", lambda tenant_id: [])
    monkeypatch.setattr(gateway_feed, "build_gateway_feed", lambda **kwargs: {"events": []})

    class _FakeCostStore:
        def list_records(self, tenant_id, limit):
            return []

    monkeypatch.setattr("agent_bom.api.cost_store.get_cost_store", lambda: _FakeCostStore())

    # 50 jobs, each yielding 100 findings → 5000 findings if unbounded.
    monkeypatch.setattr(scan, "_completed_jobs_for_tenant", lambda tenant_id: list(range(50)))
    monkeypatch.setattr(scan, "_iter_scan_findings", lambda job: [{"vulnerability_id": f"CVE-{job}-{i}"} for i in range(100)])

    class _FakeRuntimeStore:
        def list_sessions(self, tenant_id, limit, offset):
            return []

        def list_observations(self, tenant_id, limit, offset):
            return []

    monkeypatch.setattr(observability, "get_runtime_event_store", lambda: _FakeRuntimeStore())

    captured: dict[str, object] = {}

    def _capture_payload(**kwargs):
        captured["findings_len"] = len(kwargs["findings"])
        return {"ok": True}

    monkeypatch.setattr(trace_explorer_mod, "build_trace_explorer_payload", _capture_payload)

    result = observability._build_trace_explorer_payload_sync("tenant-x", limit=25)

    assert result == {"ok": True}
    assert captured["findings_len"] == 25
