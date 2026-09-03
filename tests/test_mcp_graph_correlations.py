from __future__ import annotations

import asyncio
import builtins
import json
from datetime import datetime, timezone
from typing import Any

from agent_bom.api import stores as api_stores
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.graph import EntityType, UnifiedGraph, UnifiedNode
from agent_bom.graph.correlation import CorrelationRunStatus, GraphCorrelationRun
from agent_bom.mcp_server import create_mcp_server
from agent_bom.mcp_tenant import MCP_TENANT_ENV_VAR
from agent_bom.mcp_tools.graph import graph_correlate_impl, graph_correlation_status_impl


def _run() -> GraphCorrelationRun:
    return GraphCorrelationRun(
        correlation_id="corr-1",
        tenant_id="tenant-a",
        idempotency_key="idem-1",
        name="proof",
        status=CorrelationRunStatus.PENDING,
        max_age_hours=168,
        allow_stale=False,
        input_manifest=[{"scan_id": "image"}, {"scan_id": "runtime"}],
    )


class _Service:
    def __init__(self) -> None:
        self.request: Any = None

    async def submit(self, request: Any) -> GraphCorrelationRun:
        self.request = request
        return _run()


class _Store:
    def get_correlation_run(self, *, tenant_id: str, correlation_id: str) -> GraphCorrelationRun | None:
        if tenant_id == "tenant-a" and correlation_id == "corr-1":
            return _run()
        return None


def test_graph_correlate_uses_same_service_contract(monkeypatch) -> None:
    from agent_bom.api import audit_log

    monkeypatch.setenv(MCP_TENANT_ENV_VAR, "tenant-a")
    service = _Service()
    audited: list[tuple[str, str, dict[str, object]]] = []
    monkeypatch.setattr(
        audit_log,
        "log_action",
        lambda action, actor="system", resource="", **details: audited.append((action, actor, {"resource": resource, **details})),
    )

    raw = asyncio.run(
        graph_correlate_impl(
            name="proof",
            scan_ids=["image", "runtime"],
            max_age_hours=168,
            idempotency_key="idem-1",
            reason="Investigate exact evidence receipts",
            tenant_id="tenant-a",
            _service=service,
            _authenticated_actor="operator-a",
        )
    )

    payload = json.loads(raw)
    assert payload["correlation_id"] == "corr-1"
    assert payload["receipt_verification"]["status"] == "legacy_hash_bound"
    assert service.request.scan_ids == ("image", "runtime")
    assert service.request.tenant_id == "tenant-a"
    assert service.request.idempotency_key == "idem-1"
    assert audited == [
        (
            "graph.correlation.create",
            "operator-a",
            {
                "resource": "graph/correlation/corr-1",
                "tenant_id": "tenant-a",
                "source_count": 2,
                "max_age_hours": 168,
                "allow_stale": False,
                "reason_provided": True,
            },
        )
    ]


def test_graph_correlate_default_service_does_not_import_fastapi_route(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv(MCP_TENANT_ENV_VAR, "tenant-a")
    store = SQLiteGraphStore(tmp_path / "graph.db")
    for scan_id in ("image", "runtime"):
        graph = UnifiedGraph(scan_id=scan_id, tenant_id="tenant-a", created_at=datetime.now(timezone.utc).isoformat())
        graph.add_node(UnifiedNode(id=f"package:{scan_id}", entity_type=EntityType.PACKAGE, label=scan_id))
        store.save_graph(graph)
    monkeypatch.setattr(api_stores, "_graph_store", store)
    original_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name == "agent_bom.api.routes.graph_correlations":
            raise AssertionError("MCP correlation must not import the optional FastAPI route surface")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    payload = json.loads(
        asyncio.run(
            graph_correlate_impl(
                name="proof",
                scan_ids=["image", "runtime"],
                max_age_hours=168,
                idempotency_key="idem-no-fastapi-route",
                reason="Investigate exact evidence receipts",
                tenant_id="tenant-a",
            )
        )
    )

    assert payload["status"] == "pending"
    assert payload["tenant_id"] == "tenant-a"


def test_graph_correlate_requires_idempotency_and_distinct_snapshots(monkeypatch) -> None:
    monkeypatch.setenv(MCP_TENANT_ENV_VAR, "tenant-a")
    missing_key = json.loads(
        asyncio.run(
            graph_correlate_impl(
                name="proof",
                scan_ids=["image", "runtime"],
                max_age_hours=168,
                idempotency_key="",
                reason="Investigate exact evidence receipts",
                tenant_id="tenant-a",
                _service=_Service(),
            )
        )
    )
    duplicate = json.loads(
        asyncio.run(
            graph_correlate_impl(
                name="proof",
                scan_ids=["image", "image"],
                max_age_hours=168,
                idempotency_key="idem-1",
                reason="Investigate exact evidence receipts",
                tenant_id="tenant-a",
                _service=_Service(),
            )
        )
    )
    short_reason = json.loads(
        asyncio.run(
            graph_correlate_impl(
                name="proof",
                scan_ids=["image", "runtime"],
                max_age_hours=168,
                idempotency_key="idem-2",
                reason="short",
                tenant_id="tenant-a",
                _service=_Service(),
            )
        )
    )

    assert missing_key["error"]["code"] == "AGENTBOM_MCP_VALIDATION_MISSING_REQUIRED"
    assert duplicate["error"]["code"] == "AGENTBOM_MCP_VALIDATION_INVALID_ARGUMENT"
    assert short_reason["error"]["code"] == "AGENTBOM_MCP_VALIDATION_INVALID_ARGUMENT"


def test_graph_correlation_status_is_tenant_scoped(monkeypatch) -> None:
    monkeypatch.setenv(MCP_TENANT_ENV_VAR, "tenant-a")
    payload = json.loads(asyncio.run(graph_correlation_status_impl("corr-1", tenant_id="tenant-a", _get_graph_store=lambda: _Store())))
    missing = json.loads(asyncio.run(graph_correlation_status_impl("corr-1", tenant_id="tenant-b", _get_graph_store=lambda: _Store())))

    assert payload["correlation_id"] == "corr-1"
    assert payload["receipt_verification"]["status"] == "legacy_hash_bound"
    assert missing["tenant_id"] == "tenant-a"


def test_live_graph_correlation_tool_annotations_are_truthful() -> None:
    server = create_mcp_server(profile="full")
    tools = {tool.name: tool for tool in asyncio.run(server.list_tools())}

    create = tools["graph_correlate"]
    status = tools["graph_correlation_status"]
    assert create.annotations.readOnlyHint is False
    assert create.annotations.destructiveHint is False
    assert create.annotations.idempotentHint is True
    assert "reason" in create.inputSchema["required"]
    assert status.annotations.readOnlyHint is True
    assert create.inputSchema["additionalProperties"] is False
    assert status.inputSchema["additionalProperties"] is False
