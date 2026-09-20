"""Recorded authority remains inspectable without becoming current permission."""

import json

import pytest

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.graph import AttackPath, EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.path_evidence import annotate_attack_path_evidence
from tests.test_exposure_path_evidence_parity import _serialize_both


def _decision(action="storage.objects.get", **extra):
    return {
        "source": "authorization-evidence",
        "provider": "gcp",
        "principal_id": "reader@example.test",
        "decision": "allow",
        "action": action,
        "resource": "projects/_/buckets/example",
        "binding_ids": [f"grant:{action}"],
        "observed_at": "2026-09-20T12:00:00+00:00",
        **extra,
    }


def _graph(evidence, relationship=RelationshipType.CAN_ACCESS):
    graph = UnifiedGraph(scan_id="authority-snapshot")
    graph.add_node(UnifiedNode(id="principal:reader", entity_type=EntityType.SERVICE_ACCOUNT, label="reader"))
    graph.add_node(UnifiedNode(id="data:example", entity_type=EntityType.DATA_STORE, label="example"))
    graph.add_edge(UnifiedEdge(source="principal:reader", target="data:example", relationship=relationship, evidence=evidence))
    path = AttackPath(
        source="principal:reader", target="data:example", hops=["principal:reader", "data:example"], edges=[relationship.value]
    )
    graph.attack_paths = [annotate_attack_path_evidence(path, graph)]
    return graph


def test_action_binding_pairs_survive_restart_and_both_hop_surfaces(tmp_path):
    graph = _graph({"authorization_decisions": [_decision(), _decision("storage.objects.create", token="secret-body")]})
    db = tmp_path / "authority.db"
    SQLiteGraphStore(db).save_graph(graph)
    restored = SQLiteGraphStore(db).load_graph(scan_id=graph.scan_id)
    assert restored is not None
    payloads = _serialize_both(restored.attack_paths[0], nodes=list(restored.nodes.values()), edges=restored.edges)
    assert payloads[0]["hopEvidence"] == payloads[1]["hopEvidence"]
    for payload in payloads:
        authority = payload["hopEvidence"][0]["authority"]
        assert authority["status"] == "recorded"
        assert [(item["action"], item["binding_ids"]) for item in authority["decisions"]] == [
            ("storage.objects.get", ["grant:storage.objects.get"]),
            ("storage.objects.create", ["grant:storage.objects.create"]),
        ]
        assert payload["hopEvidence"][0]["runtime_outcome"] == "unknown"
        assert payload["reachability"] == "unknown"
        assert "secret-body" not in json.dumps(payload)


@pytest.mark.parametrize("bad", [{"action": "invented"}, "untrusted", {**_decision(), "action": False}])
def test_invalid_authority_record_is_a_gap_without_discarding_other_receipts(bad):
    graph = _graph({"authorization_decisions": [_decision(), bad]})
    authority = graph.attack_paths[0].hop_evidence[0]["authority"]
    assert authority["status"] == "partial"
    assert len(authority["decisions"]) == 1
    assert "invalid_authorization_receipt" in authority["reason_codes"]


def test_authority_projection_is_bounded_and_reports_omissions():
    graph = _graph({"authorization_decisions": [_decision(f"action:{i}") for i in range(100)]})
    authority = graph.attack_paths[0].hop_evidence[0]["authority"]
    assert len(authority["decisions"]) == 16
    assert authority["status"] == "partial"
    assert "authorization_receipt_limit" in authority["reason_codes"]


def test_permission_witness_retains_source_ids_without_inventing_actions():
    derivation = {
        "basis": "recorded_graph_connections",
        "source_scan_id": "authority-snapshot",
        "path_selection": "one_shortest_path_per_grant_and_access",
        "truncated": True,
        "paths": [
            {
                "access": "group",
                "grant_principal_id": "group:reader",
                "grant_edge_id": "edge:grant",
                "source_edge_ids": ["edge:membership", "edge:grant"],
                "raw_policy": "secret-body",
            }
        ],
    }
    graph = _graph({"permission_derivation": derivation}, RelationshipType.HAS_PERMISSION)
    authority = graph.attack_paths[0].hop_evidence[0]["authority"]
    assert authority["decisions"] == []
    assert authority["status"] == "partial"
    assert "permission_witnesses_limited" in authority["reason_codes"]
    assert authority["derivation"]["paths"][0]["source_edge_ids"] == ["edge:membership", "edge:grant"]
    assert "secret-body" not in json.dumps(authority)


def test_legacy_authority_keeps_missing_principal_and_time_unknown():
    graph = _graph({"source": "authorization-evidence", "provider": "gcp", "action": "storage.objects.get", "decision": "allow"})
    authority = graph.attack_paths[0].hop_evidence[0]["authority"]
    assert authority["decisions"][0]["principal_id"] is None
    assert authority["decisions"][0]["observed_at"] is None
    assert authority["decisions"][0]["resource"] is None


def test_plain_relationship_has_no_authority_projection():
    graph = _graph({"access": "direct"})
    assert graph.attack_paths[0].hop_evidence[0].get("authority") is None


@pytest.mark.asyncio
async def test_persisted_authority_reaches_mcp_and_python_client(tmp_path):
    import httpx

    from agent_bom import AgentBomClient
    from agent_bom.mcp_tools.graph import exposure_paths_impl

    graph = _graph({"authorization_decisions": [_decision()]})
    db = tmp_path / "transport.db"
    SQLiteGraphStore(db).save_graph(graph)
    store = SQLiteGraphStore(db)
    mcp = json.loads(await exposure_paths_impl(scan_id=graph.scan_id, _get_graph_store=lambda: store))
    restored = store.load_graph(scan_id=graph.scan_id)
    api = _serialize_both(restored.attack_paths[0], nodes=list(restored.nodes.values()), edges=restored.edges)[1]
    # The SDK must retain the server's projection, including qualifications.
    with AgentBomClient(
        base_url="https://example.test", transport=httpx.MockTransport(lambda request: httpx.Response(200, json={"paths": [api]}))
    ) as client:
        result = client.exposure_paths(scan_id=graph.scan_id)
    assert result["paths"][0]["hopEvidence"] == mcp["paths"][0]["hopEvidence"]
    assert result["paths"][0]["hopEvidence"][0]["authority"]["decisions"][0]["binding_ids"] == ["grant:storage.objects.get"]


def test_exposure_authority_matches_embedded_openapi_schema():
    import jsonschema

    from agent_bom.api.routes.graph import _EXPOSURE_PATH_OPENAPI_SCHEMA

    graph = _graph({"authorization_decisions": [_decision()]})
    api = _serialize_both(graph.attack_paths[0], nodes=list(graph.nodes.values()), edges=graph.edges)[1]
    schema = _EXPOSURE_PATH_OPENAPI_SCHEMA["properties"]["hopEvidence"]
    assert "$ref" not in json.dumps(schema)
    jsonschema.validate(api["hopEvidence"], schema)


def test_api_and_cli_preserve_same_authority_and_tenant_boundary(tmp_path, monkeypatch):
    from click.testing import CliRunner
    from starlette.testclient import TestClient

    from agent_bom.api.routes import graph as graph_routes
    from agent_bom.api.server import app
    from agent_bom.cli import main
    from tests.test_cli_graph_paths import FakeGraphClient

    graph = _graph({"authorization_decisions": [_decision()]})
    db = tmp_path / "route.db"
    SQLiteGraphStore(db).save_graph(graph)
    monkeypatch.setattr(graph_routes, "_get_graph_store", lambda: SQLiteGraphStore(db))
    client = TestClient(app)
    response = client.get("/v1/graph/exposure-paths", params={"scan_id": graph.scan_id})
    assert response.status_code == 200
    payload = response.json()
    authority = payload["paths"][0]["hopEvidence"][0]["authority"]
    assert authority["decisions"][0]["action"] == "storage.objects.get"
    foreign = client.get(
        "/v1/graph/exposure-paths", params={"scan_id": graph.scan_id, "tenant_id": "default"}, headers={"x-agent-bom-tenant-id": "foreign"}
    )
    assert "reader@example.test" not in foreign.text
    assert not foreign.json().get("paths")

    class Client(FakeGraphClient):
        def exposure_paths(self, **kwargs):
            return payload

    monkeypatch.setattr("agent_bom.cli._findings_group.AgentBomClient", Client)
    result = CliRunner().invoke(main, ["graph-paths", "exposure", "--scan-id", graph.scan_id, "--format", "json"])
    assert result.exit_code == 0
    assert json.loads(result.output)["paths"][0]["hopEvidence"][0]["authority"] == authority
