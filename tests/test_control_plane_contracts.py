"""Cross-component control-plane contract tests.

These guard the higher-value seams together instead of in isolation:

- scan result -> persisted graph snapshot
- tenant-scoped control-plane discovery and graph reads
- gateway policy block -> audit event
- gateway forward -> upstream call + metrics
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores as _stores
from agent_bom.api.metrics import reset_for_tests as reset_metrics
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.pipeline import _persist_graph_snapshot
from agent_bom.api.server import app
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import set_graph_store, set_job_store
from agent_bom.gateway_server import GatewaySettings, create_gateway_app
from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry
from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _cp_client(tenant: str) -> TestClient:
    client = TestClient(app)
    client.headers.update({"X-Agent-Bom-Role": "admin", "X-Agent-Bom-Tenant-ID": tenant})
    return client


def _seed_scan_job(store: InMemoryJobStore, tenant: str, servers: list[dict[str, str]]) -> ScanJob:
    job = ScanJob(
        job_id=f"{tenant}-scan",
        tenant_id=tenant,
        status=JobStatus.DONE,
        created_at=_now(),
        completed_at=_now(),
        request=ScanRequest(),
    )
    job.result = {
        "scan_id": f"{tenant}-scan",
        "agents": [{"name": f"{tenant}-agent", "servers": servers}],
    }
    store.put(job)
    return job


def _tenant_graph(tenant: str) -> UnifiedGraph:
    graph = UnifiedGraph(scan_id=f"{tenant}-scan", tenant_id=tenant)
    graph.add_node(
        UnifiedNode(
            id=f"agent:{tenant}",
            entity_type=EntityType.AGENT,
            label=f"{tenant} agent",
        )
    )
    graph.add_node(
        UnifiedNode(
            id=f"server:{tenant}:jira",
            entity_type=EntityType.SERVER,
            label=f"{tenant} jira",
        )
    )
    graph.add_edge(
        UnifiedEdge(
            source=f"agent:{tenant}",
            target=f"server:{tenant}:jira",
            relationship=RelationshipType.USES,
        )
    )
    return graph


@pytest.fixture
def control_plane_contracts(tmp_path, monkeypatch):
    job_store = InMemoryJobStore()
    graph_store = _stores._graph_store
    job_store_prev = _stores._store

    set_job_store(job_store)
    from agent_bom.api.graph_store import SQLiteGraphStore

    sqlite_graph = SQLiteGraphStore(tmp_path / "graph.db")
    set_graph_store(sqlite_graph)
    monkeypatch.setattr("agent_bom.api.routes.graph._get_graph_store_or_503", lambda: sqlite_graph)
    monkeypatch.setattr(
        "agent_bom.api.routes.graph._tenant",
        lambda request: getattr(getattr(request, "state", None), "tenant_id", None)
        or request.headers.get("X-Agent-Bom-Tenant-ID", "default"),
    )

    async def _direct_graph_store_call(fn, /, *args, **kwargs):
        return fn(*args, **kwargs)

    monkeypatch.setattr("agent_bom.api.routes.graph._graph_store_call", _direct_graph_store_call)
    reset_metrics()

    alpha_job = _seed_scan_job(
        job_store,
        "tenant-alpha",
        servers=[
            {"name": "jira", "url": "https://alpha-jira.example.com/mcp", "transport": "http"},
            {"name": "internal", "url": "http://alpha-internal.svc.cluster.local:8100", "transport": "http"},
        ],
    )
    beta_job = _seed_scan_job(
        job_store,
        "tenant-beta",
        servers=[{"name": "jira", "url": "https://beta-jira.example.com/mcp", "transport": "http"}],
    )

    graphs = {
        "tenant-alpha-scan": _tenant_graph("tenant-alpha"),
        "tenant-beta-scan": _tenant_graph("tenant-beta"),
    }

    monkeypatch.setattr(
        "agent_bom.graph.builder.build_unified_graph_from_report",
        lambda report_json, scan_id, tenant_id: graphs[scan_id],
    )
    monkeypatch.setattr("agent_bom.graph.webhooks.compute_delta_alerts", lambda previous, current: [])
    monkeypatch.setattr("agent_bom.graph.webhooks.dispatch_delta_alerts", lambda alerts, product_version=None: None)

    _persist_graph_snapshot(alpha_job, {"scan_id": "tenant-alpha-scan"})
    _persist_graph_snapshot(beta_job, {"scan_id": "tenant-beta-scan"})

    try:
        yield {"job_store": job_store, "graph_store": sqlite_graph}
    finally:
        _stores._store = job_store_prev
        _stores._graph_store = graph_store


def test_control_plane_contract_scan_graph_policy_audit_flow(control_plane_contracts, monkeypatch) -> None:
    cp = _cp_client("tenant-alpha")

    discovery = cp.get("/v1/gateway/upstreams/discovered")
    assert discovery.status_code == 200
    discovery_body = discovery.json()
    assert discovery_body["tenant_id"] == "tenant-alpha"
    assert sorted(item["name"] for item in discovery_body["upstreams"]) == ["internal", "jira"]
    assert not any(item["name"] == "beta-only" for item in discovery_body["upstreams"])

    graph_store = control_plane_contracts["graph_store"]
    effective_scan_id, _created_at, nodes, total, next_cursor = graph_store.page_nodes(
        tenant_id="tenant-alpha",
        scan_id="tenant-alpha-scan",
        entity_types={"agent", "server"},
        min_severity_rank=0,
        cursor=None,
        offset=0,
        limit=10,
    )
    assert effective_scan_id == "tenant-alpha-scan"
    assert {node.id for node in nodes} == {"agent:tenant-alpha", "server:tenant-alpha:jira"}
    assert total == 2
    assert next_cursor is None

    discovered = UpstreamRegistry.from_discovery_response(discovery_body)
    monkeypatch.setenv("TENANT_ALPHA_JIRA_TOKEN", "tenant-alpha-token")
    overlay = UpstreamRegistry(
        [
            UpstreamConfig(
                name="jira",
                tenant_id="tenant-alpha",
                url="https://alpha-jira.example.com/mcp",
                auth="bearer",
                token_env="TENANT_ALPHA_JIRA_TOKEN",
            )
        ]
    )
    registry = discovered.merged_with(overlay)

    audit_events: list[dict[str, Any]] = []
    upstream_calls: list[dict[str, Any]] = []

    async def audit_sink(event: dict[str, Any]) -> None:
        audit_events.append(event)

    async def fake_upstream_caller(upstream, message, extra_headers):
        resolved_headers = await upstream.resolve_auth_headers()
        upstream_calls.append(
            {
                "upstream": upstream.name,
                "tenant_id": upstream.tenant_id,
                "tool": message.get("params", {}).get("name"),
                "headers": {**resolved_headers, **dict(extra_headers)},
            }
        )
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}

    class _FakeKeyStore:
        def has_keys(self) -> bool:
            return True

        def verify(self, raw_key: str):
            if raw_key == "tenant-alpha-key":
                return type("ApiKey", (), {"tenant_id": "tenant-alpha"})()
            return None

    monkeypatch.setattr("agent_bom.gateway_server.get_key_store", lambda: _FakeKeyStore())

    gw = TestClient(
        create_gateway_app(
            GatewaySettings(
                registry=registry,
                policy={"rules": [{"id": "no-shell", "action": "block", "block_tools": ["run_shell"]}]},
                audit_sink=audit_sink,
                upstream_caller=fake_upstream_caller,
            )
        )
    )

    blocked = gw.post(
        "/mcp/jira",
        headers={"X-API-Key": "tenant-alpha-key"},
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "run_shell", "arguments": {"command": "whoami"}},
        },
    )
    assert blocked.status_code == 200
    assert blocked.json()["error"]["code"] == -32001
    assert upstream_calls == []
    assert any(event["action"] == "gateway.tool_call_blocked" for event in audit_events)
    assert audit_events[-1]["tenant_id"] == "tenant-alpha"

    allowed = gw.post(
        "/mcp/jira",
        headers={"X-API-Key": "tenant-alpha-key"},
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "query_issues", "arguments": {"jql": "project = ACME"}},
        },
    )
    assert allowed.status_code == 200
    assert allowed.json()["result"]["ok"] is True
    assert len(upstream_calls) == 1
    assert upstream_calls[0]["tenant_id"] == "tenant-alpha"
    assert upstream_calls[0]["headers"]["Authorization"] == "Bearer tenant-alpha-token"

    metrics = gw.get("/metrics")
    assert metrics.status_code == 200
    assert 'agent_bom_gateway_relays_total{upstream="jira",outcome="blocked"} 1' in metrics.text
    assert 'agent_bom_gateway_relays_total{upstream="jira",outcome="forwarded"} 1' in metrics.text


def test_control_plane_contract_tenant_scoping_survives_discovery_and_persisted_graph_reads(control_plane_contracts) -> None:
    alpha = _cp_client("tenant-alpha")
    beta = _cp_client("tenant-beta")

    alpha_discovery = alpha.get("/v1/gateway/upstreams/discovered")
    beta_discovery = beta.get("/v1/gateway/upstreams/discovered")
    assert alpha_discovery.status_code == 200
    assert beta_discovery.status_code == 200
    assert {item["url"] for item in alpha_discovery.json()["upstreams"]} == {
        "https://alpha-jira.example.com/mcp",
        "http://alpha-internal.svc.cluster.local:8100",
    }
    assert {item["url"] for item in beta_discovery.json()["upstreams"]} == {"https://beta-jira.example.com/mcp"}

    graph_store = control_plane_contracts["graph_store"]
    _scan_alpha, _created_alpha, alpha_nodes, alpha_total, _cursor_alpha = graph_store.page_nodes(
        tenant_id="tenant-alpha",
        scan_id="tenant-alpha-scan",
        entity_types={"agent", "server"},
        min_severity_rank=0,
        cursor=None,
        offset=0,
        limit=10,
    )
    _scan_beta, _created_beta, beta_nodes, beta_total, _cursor_beta = graph_store.page_nodes(
        tenant_id="tenant-beta",
        scan_id="tenant-beta-scan",
        entity_types={"agent", "server"},
        min_severity_rank=0,
        cursor=None,
        offset=0,
        limit=10,
    )

    alpha_ids = {node.id for node in alpha_nodes}
    beta_ids = {node.id for node in beta_nodes}
    assert alpha_ids == {"agent:tenant-alpha", "server:tenant-alpha:jira"}
    assert beta_ids == {"agent:tenant-beta", "server:tenant-beta:jira"}
    assert alpha_ids.isdisjoint(beta_ids)
    assert alpha_total == 2
    assert beta_total == 2
