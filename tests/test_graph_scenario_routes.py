"""API contracts for snapshot-pinned current/proposed graph comparisons."""

from __future__ import annotations

import inspect
import sys
import types
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

import pytest
from starlette.testclient import TestClient

from agent_bom.api import middleware, stores
from agent_bom.api.graph_scenario_store import InMemoryGraphScenarioStore
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.server import app
from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode


def _graph(scan_id: str, *, extra_node: bool = False) -> UnifiedGraph:
    graph = UnifiedGraph(scan_id=scan_id, tenant_id="default")
    graph.created_at = "2026-08-25T00:00:02+00:00" if scan_id == "snapshot-latest" else "2026-08-25T00:00:01+00:00"
    graph.add_node(
        UnifiedNode(
            id="cloud:api",
            entity_type=EntityType.CLOUD_RESOURCE,
            label="public-api",
            risk_score=8.8,
            attributes={"environment": "production", "owner": "platform"},
        )
    )
    graph.add_node(UnifiedNode(id="role:app", entity_type=EntityType.ROLE, label="application-role", risk_score=5.0))
    graph.add_node(UnifiedNode(id="db:orders", entity_type=EntityType.DATA_STORE, label="orders", risk_score=7.0))
    graph.add_edge(UnifiedEdge(source="role:app", target="cloud:api", relationship=RelationshipType.CAN_ACCESS))
    graph.add_edge(UnifiedEdge(source="cloud:api", target="db:orders", relationship=RelationshipType.CAN_ACCESS))
    if extra_node:
        graph.add_node(UnifiedNode(id="cloud:new", entity_type=EntityType.CLOUD_RESOURCE, label="new-resource"))
    return graph


@pytest.fixture
def scenario_client(tmp_path: Path) -> Iterator[tuple[TestClient, SQLiteGraphStore, InMemoryGraphScenarioStore]]:
    graph_store = SQLiteGraphStore(tmp_path / "graph.db")
    graph_store.save_graph(_graph("snapshot-old"))
    graph_store.save_graph(_graph("snapshot-latest", extra_node=True))
    scenario_store = InMemoryGraphScenarioStore()
    previous_graph = stores._graph_store
    previous_scenarios = stores._graph_scenario_store
    stores.set_graph_store(graph_store)
    stores.set_graph_scenario_store(scenario_store)
    try:
        yield TestClient(app), graph_store, scenario_store
    finally:
        stores.set_graph_store(previous_graph)
        stores.set_graph_scenario_store(previous_scenarios)


def _create_body(*, scan_id: str = "snapshot-old", changes: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "name": "Private endpoint design",
        "description": "Operator-authored proposal, not deployed state.",
        "base_scan_id": scan_id,
        "changes": changes
        if changes is not None
        else [
            {
                "kind": "patch_node",
                "node_id": "cloud:api",
                "patch": {"risk_score": 2.5, "attributes": {"owner": "security-platform"}},
            }
        ],
        "assumptions": ["Private traffic control is deployed as designed"],
    }


def _create(client: TestClient, **kwargs: Any) -> dict[str, Any]:
    response = client.post("/v1/graph/scenarios", json=_create_body(**kwargs))
    assert response.status_code == 201, response.text
    return response.json()["scenario"]


def test_crud_revision_conflicts_and_server_owned_identity(scenario_client: tuple[TestClient, Any, Any]) -> None:
    client, _graph_store, _scenario_store = scenario_client
    scenario = _create(client)
    scenario_id = scenario["scenario_id"]
    assert scenario["revision"] == 1
    assert scenario["base_scan_id"] == "snapshot-old"
    assert scenario["provenance"]["kind"] == "proposed"
    assert scenario["provenance"]["observed"] is False
    assert scenario["provenance"]["deployed"] is False
    assert scenario["provenance"]["scenario_id"] == scenario_id

    assert client.get("/v1/graph/scenarios").json()["count"] == 1
    assert client.get(f"/v1/graph/scenarios/{scenario_id}").json()["scenario"] == scenario

    update = {
        "scenario_id": scenario_id,
        "expected_revision": 1,
        "name": "Private endpoint design v2",
        "description": "Revised proposal",
        "changes": [{"kind": "patch_node", "node_id": "cloud:api", "patch": {"risk_score": 1.5}}],
        "assumptions": ["WAF and private endpoint both active"],
    }
    updated = client.put(f"/v1/graph/scenarios/{scenario_id}", json=update)
    assert updated.status_code == 200, updated.text
    updated_scenario = updated.json()["scenario"]
    assert updated_scenario["revision"] == 2
    assert updated_scenario["base_scan_id"] == "snapshot-old"
    assert updated_scenario["provenance"] == scenario["provenance"]

    stale = client.put(f"/v1/graph/scenarios/{scenario_id}", json=update)
    assert stale.status_code == 409
    wrong_path = client.put(f"/v1/graph/scenarios/not-{scenario_id}", json={**update, "expected_revision": 2})
    assert wrong_path.status_code == 409
    assert client.delete(f"/v1/graph/scenarios/{scenario_id}", params={"expected_revision": 1}).status_code == 409
    assert client.delete(f"/v1/graph/scenarios/{scenario_id}", params={"expected_revision": 2}).status_code == 204
    assert client.get(f"/v1/graph/scenarios/{scenario_id}").status_code == 404


def test_create_requires_the_exact_named_snapshot_and_never_falls_back_to_latest(
    scenario_client: tuple[TestClient, SQLiteGraphStore, Any],
) -> None:
    client, graph_store, _scenario_store = scenario_client
    assert graph_store.latest_snapshot_id(tenant_id="default") == "snapshot-latest"

    old = _create(client, scan_id="snapshot-old")
    comparison = client.get(
        f"/v1/graph/scenarios/{old['scenario_id']}/comparison",
        params={"scan_id": "snapshot-old"},
    )
    assert comparison.status_code == 200, comparison.text
    body = comparison.json()
    assert body["available"] is True
    assert body["base_status"] == "stale"
    assert body["stale"] is True
    assert body["current"]["scan_id"] == "snapshot-old"
    assert body["current"]["base_status"] == "stale"
    assert body["current"]["latest_scan_id"] == "snapshot-latest"
    assert body["current"]["node_count"] == 3

    mismatch = client.get(
        f"/v1/graph/scenarios/{old['scenario_id']}/comparison",
        params={"scan_id": "snapshot-latest"},
    )
    assert mismatch.status_code == 200
    assert mismatch.json()["available"] is False
    assert mismatch.json()["unavailable_reason"] == "selected_snapshot_mismatch"
    missing = client.post("/v1/graph/scenarios", json=_create_body(scan_id="missing-snapshot"))
    assert missing.status_code == 409
    assert missing.json()["detail"] == "Base graph snapshot is unavailable"


def test_comparison_is_deterministic_and_never_mutates_observed_graph(
    scenario_client: tuple[TestClient, SQLiteGraphStore, Any],
) -> None:
    client, graph_store, _scenario_store = scenario_client
    observed_before = graph_store.load_graph(tenant_id="default", scan_id="snapshot-old").to_dict()
    scenario = _create(
        client,
        changes=[
            {
                "kind": "add_edge",
                "source": "proposal:waf",
                "target": "cloud:api",
                "relationship": "protects",
                "rationale": "blocks public traffic",
            },
            {"kind": "add_node", "key": "waf", "entity_type": "policy", "label": "edge-waf", "assumption": "managed policy enabled"},
            {"kind": "patch_node", "node_id": "cloud:api", "patch": {"risk_score": 2.0}},
        ],
    )
    url = f"/v1/graph/scenarios/{scenario['scenario_id']}/comparison"
    first = client.get(url, params={"scan_id": "snapshot-old"})
    second = client.get(url, params={"scan_id": "snapshot-old"})
    assert first.status_code == second.status_code == 200
    assert first.json() == second.json()

    body = first.json()
    proposal_id = f"proposal:{scenario['scenario_id']}:waf"
    assert body["available"] is True
    assert body["difference"]["nodes_added"] == [proposal_id]
    assert body["difference"]["nodes_changed"] == ["cloud:api"]
    assert body["difference"]["edges_added"] == [f"protects:{proposal_id}:cloud:api"]
    assert body["proposed"]["modeled"] is True
    assert graph_store.load_graph(tenant_id="default", scan_id="snapshot-old").to_dict() == observed_before


def test_removed_node_counts_all_incident_edges_even_when_the_base_load_is_bounded(tmp_path: Path) -> None:
    graph_store = SQLiteGraphStore(tmp_path / "bounded.db")
    graph = UnifiedGraph(scan_id="bounded", tenant_id="default")
    for index in range(2_002):
        graph.add_node(
            UnifiedNode(
                id=f"asset:{index}",
                entity_type=EntityType.CLOUD_RESOURCE,
                label=f"asset-{index}",
                risk_score=0.0 if index == 0 else 9.0,
            )
        )
    graph.add_edge(UnifiedEdge(source="asset:0", target="asset:1", relationship=RelationshipType.CAN_ACCESS))
    graph.add_edge(UnifiedEdge(source="asset:2", target="asset:0", relationship=RelationshipType.DEPENDS_ON))
    graph_store.save_graph(graph)
    scenario_store = InMemoryGraphScenarioStore()
    previous_graph = stores._graph_store
    previous_scenarios = stores._graph_scenario_store
    stores.set_graph_store(graph_store)
    stores.set_graph_scenario_store(scenario_store)
    try:
        client = TestClient(app)
        scenario = _create(client, scan_id="bounded", changes=[{"kind": "remove_node", "node_id": "asset:0"}])
        response = client.get(
            f"/v1/graph/scenarios/{scenario['scenario_id']}/comparison",
            params={"scan_id": "bounded"},
        )
    finally:
        stores.set_graph_store(previous_graph)
        stores.set_graph_scenario_store(previous_scenarios)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["current"]["node_count"] == 2_002
    assert body["current"]["edge_count"] == 2
    assert body["current"]["completeness"]["truncated"] is True
    assert body["proposed"]["node_count"] == 2_001
    assert body["proposed"]["edge_count"] == 0
    assert body["proposed"]["completeness"]["truncated"] is True
    assert body["proposed"]["completeness"]["edge_total"] == 0
    assert body["difference"]["edges_removed"] == [
        "can_access:asset:0:asset:1",
        "depends_on:asset:2:asset:0",
    ]


def test_invalid_stored_operation_returns_unavailable_without_partial_application(
    scenario_client: tuple[TestClient, Any, InMemoryGraphScenarioStore],
) -> None:
    client, _graph_store, scenario_store = scenario_client
    record = {
        "id": "invalid",
        "tenant_id": "default",
        "base_scan_id": "snapshot-old",
        "revision": 1,
        "name": "Invalid historical row",
        "description": "",
        "operations": [{"kind": "remove_node", "node_id": "missing-node"}],
        "assumptions": [],
        "created_by": "analyst",
        "provenance": {
            "kind": "proposed",
            "modeled": True,
            "evidence_state": "proposed",
            "observed": False,
            "deployed": False,
            "scenario_id": "invalid",
            "base_scan_id": "snapshot-old",
            "authority": "operator_authored_scenario",
            "created_by": "analyst",
        },
        "created_at": "2026-08-25T00:00:00+00:00",
        "updated_at": "2026-08-25T00:00:00+00:00",
    }
    scenario_store.create("default", record)
    response = client.get("/v1/graph/scenarios/invalid/comparison", params={"scan_id": "snapshot-old"})
    assert response.status_code == 200
    body = response.json()
    assert body["available"] is False
    assert body["proposed"]["nodes"] == [] and body["proposed"]["edges"] == []
    assert body["difference"]["nodes_removed"] == []
    assert "missing-node" in body["unavailable_reason"]


def test_payload_cap_extra_fields_and_managed_trial_read_only(
    scenario_client: tuple[TestClient, Any, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _graph_store, _scenario_store = scenario_client
    extra = client.post("/v1/graph/scenarios", json={**_create_body(), "authority": "observed"})
    assert extra.status_code == 422

    oversized = _create_body(
        changes=[
            {
                "kind": "add_node",
                "key": f"proposed-{index}",
                "entity_type": "policy",
                "label": f"policy-{index}",
                "rationale": "x" * 2_000,
            }
            for index in range(500)
        ]
    )
    assert client.post("/v1/graph/scenarios", json=oversized).status_code == 413

    scenario = _create(client)
    scenario_id = scenario["scenario_id"]
    monkeypatch.setenv("AGENT_BOM_MANAGED_TRIAL_MODE", "1")
    assert client.get("/v1/graph/scenarios").status_code == 200
    assert client.get(f"/v1/graph/scenarios/{scenario_id}").status_code == 200
    assert client.get(f"/v1/graph/scenarios/{scenario_id}/comparison", params={"scan_id": "snapshot-old"}).status_code == 200
    denied = client.post("/v1/graph/scenarios", json=_create_body())
    assert denied.status_code == 403
    assert "managed trial" in denied.json()["detail"].lower()
    update = {
        "scenario_id": scenario_id,
        "expected_revision": 1,
        "name": "denied",
        "changes": [],
    }
    assert client.put(f"/v1/graph/scenarios/{scenario_id}", json=update).status_code == 403
    assert client.delete(f"/v1/graph/scenarios/{scenario_id}", params={"expected_revision": 1}).status_code == 403


def test_backend_failures_are_sanitized(
    scenario_client: tuple[TestClient, SQLiteGraphStore, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, graph_store, _scenario_store = scenario_client
    secret = "postgresql://admin:super-secret@internal/scenarios"

    def explode(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError(secret)

    monkeypatch.setattr(graph_store, "list_snapshots", explode)
    response = client.post("/v1/graph/scenarios", json=_create_body())
    assert response.status_code == 503
    assert secret not in response.text
    assert "super-secret" not in response.text


@pytest.mark.parametrize(
    ("method", "path", "role", "scope"),
    [
        ("GET", "/v1/graph/scenarios", "viewer", "graph:read"),
        ("GET", "/v1/graph/scenarios/id/comparison", "viewer", "graph:read"),
        ("POST", "/v1/graph/scenarios", "analyst", "scan:write"),
        ("PUT", "/v1/graph/scenarios/id", "analyst", "scan:write"),
        ("DELETE", "/v1/graph/scenarios/id", "admin", "config:write"),
    ],
)
def test_auth_contract_is_read_viewer_write_analyst_delete_admin(
    method: str,
    path: str,
    role: str,
    scope: str,
) -> None:
    policy = object.__new__(middleware.APIKeyMiddleware)
    assert policy._required_role(method, path) == role
    assert policy._required_scope(method, path) == scope


def test_postgres_scenario_schema_is_migration_owned_tenant_rls() -> None:
    from agent_bom.api.postgres_graph_scenario import PostgresGraphScenarioStore
    from agent_bom.api.storage_schema import CONTROL_PLANE_SCHEMA_COMPONENTS

    root = Path(__file__).resolve().parents[1]
    init_sql = (root / "deploy/supabase/postgres/init.sql").read_text()
    runtime_sql = (root / "deploy/supabase/postgres/runtime-schema.sql").read_text()
    migration_sql = (root / "deploy/supabase/postgres/alembic/versions/20260825_01_graph_scenarios.py").read_text()
    assert "CREATE TABLE IF NOT EXISTS graph_scenarios" in init_sql
    assert "ALTER TABLE graph_scenarios ENABLE ROW LEVEL SECURITY" in init_sql
    assert "ALTER TABLE graph_scenarios FORCE ROW LEVEL SECURITY" in init_sql
    assert "graph_scenarios_tenant_isolation" in init_sql
    assert "graph_scenarios" in runtime_sql
    assert migration_sql.index("CREATE TABLE IF NOT EXISTS control_plane_schema_versions") < migration_sql.index(
        "INSERT INTO control_plane_schema_versions"
    )
    component = next(item for item in CONTROL_PLANE_SCHEMA_COMPONENTS if item.component == "graph_scenarios")
    assert component.backend == "sqlite/postgres" and component.tenant_scoped is True

    source = inspect.getsource(PostgresGraphScenarioStore)
    assert 'ensure_postgres_schema_version(conn, "graph_scenarios")' in source
    assert '_ensure_tenant_rls(conn, "graph_scenarios", "tenant_id")' in source
    assert "with _tenant_connection(self._pool)" in source
    assert "revision = %s" in source and "expected_revision" in source


def test_configured_postgres_runtime_validates_migration_without_ddl(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.api.postgres_graph_scenario import PostgresGraphScenarioStore

    class Cursor:
        def fetchone(self) -> tuple[int]:
            return (1,)

    class Connection:
        def __init__(self) -> None:
            self.sql: list[str] = []

        def execute(self, sql: str, params: Any = None) -> Cursor:
            self.sql.append(sql)
            return Cursor()

    connection = Connection()

    class Pool:
        @contextmanager
        def connection(self) -> Iterator[Connection]:
            yield connection

    monkeypatch.setenv("AGENT_BOM_DB", "postgresql://example.invalid/agent_bom")
    PostgresGraphScenarioStore(pool=Pool())  # type: ignore[arg-type]
    normalized = " ".join(connection.sql)
    assert "SELECT version FROM control_plane_schema_versions" in normalized
    assert "CREATE TABLE" not in normalized
    assert "ALTER TABLE" not in normalized


def test_agent_bom_db_postgres_selects_shared_scenario_store(monkeypatch: pytest.MonkeyPatch) -> None:
    sentinel = object()
    fake_module = types.SimpleNamespace(PostgresGraphScenarioStore=lambda: sentinel)
    monkeypatch.setitem(sys.modules, "agent_bom.api.postgres_graph_scenario", fake_module)
    monkeypatch.setenv("AGENT_BOM_DB", "postgresql://example.invalid/agent_bom")
    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    monkeypatch.setattr(stores, "_graph_scenario_store", None)
    assert stores._get_graph_scenario_store() is sentinel
