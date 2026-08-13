from __future__ import annotations

import asyncio
import json

import pytest

import agent_bom.api.routes.enterprise as enterprise
from agent_bom.api.exception_store import InMemoryExceptionStore
from agent_bom.mcp_tools.triage import findings_triage_impl


def _truncate(text: str) -> str:
    return text


@pytest.fixture
def isolated_store(monkeypatch) -> InMemoryExceptionStore:
    store = InMemoryExceptionStore()
    monkeypatch.setattr(enterprise, "_get_exception_store", lambda: store)
    return store


def _run(**kwargs) -> dict:
    out = asyncio.run(findings_triage_impl(_truncate_response=_truncate, **kwargs))
    return json.loads(out)


def test_findings_triage_records_decision_to_store(isolated_store, monkeypatch) -> None:
    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", "tenant-a")
    result = _run(
        vulnerability_id="CVE-2024-9",
        package="left-pad",
        assignee="secops@example.com",
        queue_state="assigned",
        decision="under_investigation",
        _authenticated_actor="operator-1",
    )
    assert result["vulnerability_id"] == "CVE-2024-9"
    assert result["package"] == "left-pad"
    assert result["queue_state"] == "assigned"
    assert result["assignee"] == "secops@example.com"
    # The entry is durably in the exception store, tenant-scoped.
    entries = isolated_store.list_all(tenant_id="tenant-a")
    assert len(entries) == 1
    assert entries[0].vuln_id == "CVE-2024-9"
    assert entries[0].requested_by == "operator-1"


def test_findings_triage_not_affected_requires_justification(isolated_store, monkeypatch) -> None:
    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", "tenant-a")
    result = _run(vulnerability_id="CVE-2024-9", decision="not_affected")
    assert result["status"] == "rejected"
    assert "justification" in json.dumps(result).lower()
    assert isolated_store.list_all(tenant_id="tenant-a") == []


def test_findings_triage_not_affected_with_justification_is_vex_eligible(isolated_store, monkeypatch) -> None:
    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", "tenant-a")
    result = _run(
        vulnerability_id="CVE-2024-9",
        decision="not_affected",
        justification="vulnerable_code_not_present",
    )
    assert result["decision"] == "not_affected"
    assert result["vex_eligible"] is True
    assert result["queue_state"] == "decided"


def test_findings_triage_requires_vulnerability_id(isolated_store) -> None:
    result = _run(vulnerability_id="")
    assert result["status"] == "rejected"
    assert isolated_store.list_all(tenant_id="default") == []


def test_findings_triage_rejects_invalid_decision(isolated_store, monkeypatch) -> None:
    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", "tenant-a")
    result = _run(vulnerability_id="CVE-2024-9", decision="totally_bogus")
    assert result["status"] == "rejected"
    assert isolated_store.list_all(tenant_id="tenant-a") == []


def test_findings_triage_advertised_on_server_card_and_registered() -> None:
    from agent_bom.mcp_server_metadata import (
        _TOOL_CAPABILITY_CLASSES,
        registered_mcp_tool_decorator_names,
        server_card_tool_names,
    )

    assert "findings_triage" in server_card_tool_names()
    assert "findings_triage" in registered_mcp_tool_decorator_names()
    assert "findings_triage" in _TOOL_CAPABILITY_CLASSES
