"""A scan's job id addresses its graph snapshot on every graph read.

``POST /v1/results/push`` answers with a ``job_id``; the pushed report keeps its
own ``scan_id``, which is what the graph snapshot is stored under. Passing the
job id to ``/v1/graph/exposure-paths`` (or the MCP ``exposure_paths`` tool)
therefore read an empty snapshot and reported "No exposure paths were recorded"
while the scan itself held credentialed agent -> server -> package -> CVE chains.
"""

from __future__ import annotations

import json

import pytest

pytest.importorskip("fastapi", reason="fastapi not installed")

from fastapi.testclient import TestClient

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.server import app
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import set_graph_store, set_job_store
from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.mcp_tools.graph import exposure_paths_for_tenant
from tests._clock_helpers import recent

GRAPH_SCAN_ID = "cli-report-scan-id"


def _credentialed_chain(scan_id: str, tenant_id: str = "default") -> UnifiedGraph:
    graph = UnifiedGraph(scan_id=scan_id, tenant_id=tenant_id)
    graph.add_node(UnifiedNode(id="agent:project:sampleapp", entity_type=EntityType.AGENT, label="project:sampleapp"))
    graph.add_node(UnifiedNode(id="server:project:sampleapp:github", entity_type=EntityType.SERVER, label="github"))
    graph.add_node(
        UnifiedNode(id="cred:GITHUB_PERSONAL_ACCESS_TOKEN", entity_type=EntityType.CREDENTIAL, label="GITHUB_PERSONAL_ACCESS_TOKEN")
    )
    graph.add_node(UnifiedNode(id="pkg:npm:form-data@4.0.0", entity_type=EntityType.PACKAGE, label="form-data@4.0.0"))
    graph.add_node(
        UnifiedNode(
            id="vuln:CVE-2025-7783",
            entity_type=EntityType.VULNERABILITY,
            label="CVE-2025-7783",
            severity="critical",
            risk_score=9.3,
        )
    )
    graph.add_edge(
        UnifiedEdge(source="agent:project:sampleapp", target="server:project:sampleapp:github", relationship=RelationshipType.USES)
    )
    graph.add_edge(
        UnifiedEdge(
            source="server:project:sampleapp:github",
            target="cred:GITHUB_PERSONAL_ACCESS_TOKEN",
            relationship=RelationshipType.EXPOSES_CRED,
        )
    )
    graph.add_edge(
        UnifiedEdge(source="server:project:sampleapp:github", target="pkg:npm:form-data@4.0.0", relationship=RelationshipType.DEPENDS_ON)
    )
    graph.add_edge(UnifiedEdge(source="pkg:npm:form-data@4.0.0", target="vuln:CVE-2025-7783", relationship=RelationshipType.VULNERABLE_TO))
    return graph


def _job(job_id: str, tenant_id: str) -> ScanJob:
    return ScanJob(
        job_id=job_id,
        tenant_id=tenant_id,
        status=JobStatus.DONE,
        created_at=recent("2026-07-01T00:00:00Z"),
        completed_at=recent("2026-07-01T00:01:00Z"),
        request=ScanRequest(offline=True),
        result={"scan_id": GRAPH_SCAN_ID, "agents": []},
    )


@pytest.fixture()
def stores(tmp_path):
    graph_store = SQLiteGraphStore(tmp_path / "graph.db")
    graph_store.save_graph(_credentialed_chain(GRAPH_SCAN_ID))
    job_store = InMemoryJobStore()
    job_store.put(_job("push-job-id", "default"))
    job_store.put(_job("other-tenant-job", "tenant-b"))
    set_graph_store(graph_store)
    set_job_store(job_store)
    yield graph_store
    set_graph_store(None)


def _hop_labels(path: dict) -> list[str]:
    return [hop["label"] for hop in path["hops"]]


def test_exposure_paths_accept_the_push_job_id(stores) -> None:
    body = TestClient(app).get("/v1/graph/exposure-paths", params={"scan_id": "push-job-id", "limit": 10}).json()

    assert body["scan_id"] == GRAPH_SCAN_ID
    assert body["total"] > 0
    chain = next(path for path in body["paths"] if "form-data@4.0.0" in _hop_labels(path))
    assert _hop_labels(chain)[0] == "project:sampleapp"
    assert "github" in _hop_labels(chain)
    assert chain["exposedCredentials"] == ["GITHUB_PERSONAL_ACCESS_TOKEN"]


def test_graph_reads_accept_the_push_job_id(stores) -> None:
    client = TestClient(app)

    graph = client.get("/v1/graph", params={"scan_id": "push-job-id"}).json()
    rollup = client.get("/v1/graph/rollup", params={"scan_id": "push-job-id"}).json()

    assert graph["scan_id"] == GRAPH_SCAN_ID
    assert len(graph["nodes"]) == 5
    assert rollup["scan_id"] == GRAPH_SCAN_ID
    assert rollup["summary"]["total_nodes"] == 5


def test_another_tenants_job_id_never_resolves(stores) -> None:
    body = TestClient(app).get("/v1/graph/exposure-paths", params={"scan_id": "other-tenant-job"}).json()

    assert body["total"] == 0
    assert body["scan_id"] != GRAPH_SCAN_ID


@pytest.mark.asyncio
async def test_mcp_exposure_paths_accept_the_push_job_id(stores) -> None:
    payload = json.loads(
        await exposure_paths_for_tenant(tenant_id="default", scan_id="push-job-id", limit=10, _get_graph_store=lambda: stores)
    )

    assert payload["scan_id"] == GRAPH_SCAN_ID
    assert payload["total"] > 0
