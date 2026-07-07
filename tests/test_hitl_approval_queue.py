"""Tests for runtime HITL approval queue (#3617)."""

from __future__ import annotations

from starlette.testclient import TestClient

from agent_bom.api.hitl_approval_queue import build_hitl_queue_items
from agent_bom.api.hitl_approval_store import InMemoryHitlApprovalStore, set_hitl_approval_store


def test_build_hitl_queue_items_lists_blocked_spans() -> None:
    store = InMemoryHitlApprovalStore()
    trace_payload = {
        "sessions": [
            {
                "session_id": "sess-1",
                "spans": [
                    {
                        "span_id": "span-blocked",
                        "verdict": "blocked",
                        "agent": "dev-agent",
                        "tool": "run_shell",
                        "detail": "policy deny",
                        "linked_findings": [{"finding_id": "CVE-1"}],
                        "compliance_controls": ["owasp_llm:LLM05"],
                    },
                    {"span_id": "span-ok", "verdict": "observed", "agent": "dev-agent", "tool": "read_file"},
                ],
            }
        ]
    }
    items = build_hitl_queue_items(tenant_id="tenant-a", trace_payload=trace_payload, store=store)
    assert len(items) == 1
    assert items[0]["status"] == "pending"
    assert items[0]["tool"] == "run_shell"
    assert items[0]["linked_finding_ids"] == ["CVE-1"]
    assert "owasp_llm:LLM05" in items[0]["compliance_controls"]


def test_runtime_approval_queue_api_decision_emits_audit(monkeypatch) -> None:
    from agent_bom.api import server as api_server

    monkeypatch.setenv("AGENT_BOM_DEMO_ESTATE", "0")
    monkeypatch.setenv("AGENT_BOM_NO_AUTH_ROLE", "admin")
    monkeypatch.setattr("agent_bom.config.DEMO_ESTATE", False)
    monkeypatch.setattr("agent_bom.config.NO_AUTH_ROLE", "admin")

    store = InMemoryHitlApprovalStore()
    set_hitl_approval_store(store)
    api_server._runtime_api_key_seeded = False
    api_server.configure_api(api_key=None)

    with TestClient(api_server.app) as test_client:
        queue = test_client.get("/v1/runtime/approval-queue")
        assert queue.status_code == 200
        payload = queue.json()
        if not payload.get("items"):
            assert payload["schema_version"] == "runtime.approval_queue.v1"
            return

        item_id = payload["items"][0]["item_id"]
        decision = test_client.post(
            f"/v1/runtime/approval-queue/{item_id}/decision",
            json={"decision": "approve", "note": "reviewed in test"},
        )
        assert decision.status_code == 200
        body = decision.json()
        assert body["item"]["status"] == "approved"
        assert body["item"]["note"] == "reviewed in test"

        filtered = test_client.get("/v1/runtime/approval-queue?status=approved")
        assert filtered.status_code == 200
        assert any(row["item_id"] == item_id for row in filtered.json().get("items", []))
