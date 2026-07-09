"""API-surface regressions for the 0.94.3 fix pass.

1. ``/v1/findings`` default view must dedupe by finding id (latest scan wins) so
   ``total`` does not inflate one full copy per re-scan against the in-memory
   store (Postgres reads the already-deduped ``hub_findings_current``).
2. The shared ``graph`` backpressure controller must not false-trip its p99
   cooldown on a cold full build's honest latency (~2.6s), 429-storming every
   ``/v1/graph*`` route.
3. Invalid ``sort`` / ``severity`` on ``/v1/findings`` must 422, not silently
   fall back (wrong order) or return an empty 200 (reads as "no findings").
4. ``/v1/results/push`` must reject junk payloads with 422 instead of minting an
   empty ScanJob.
"""

from __future__ import annotations

import uuid

import pytest
from starlette.testclient import TestClient

from agent_bom.api.compliance_hub_store import (
    InMemoryComplianceHubStore,
    set_compliance_hub_store,
)
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.server import app
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import set_graph_store, set_job_store
from agent_bom.backpressure import _controller_for, reset_backpressure_for_tests

TENANT = "default"


def _make_findings(count: int) -> list[dict]:
    return [
        {
            "id": f"CVE-2025-{i:04d}:pkg{i}",
            "vulnerability_id": f"CVE-2025-{i:04d}",
            "package": f"pkg{i}",
            "severity": ("critical", "high", "medium", "low")[i % 4],
            "cvss_score": float(i % 10),
        }
        for i in range(count)
    ]


def _seed_repeated_scans(store: InMemoryJobStore, *, scans: int, findings: list[dict]) -> str:
    """Simulate re-scanning the same project ``scans`` times."""
    last_scan_id = ""
    for n in range(scans):
        job_id = str(uuid.uuid4())
        last_scan_id = job_id
        store.put(
            ScanJob(
                job_id=job_id,
                tenant_id=TENANT,
                status=JobStatus.DONE,
                created_at=f"2026-07-{n + 1:02d}T00:00:00Z",
                completed_at=f"2026-07-{n + 1:02d}T00:01:00Z",
                request=ScanRequest(agent_projects=["/tmp/proj"], offline=True),
                result={"findings": [dict(f) for f in findings]},
            )
        )
    return last_scan_id


@pytest.fixture
def client_with_scans():
    job_store = InMemoryJobStore()
    set_job_store(job_store)
    set_compliance_hub_store(InMemoryComplianceHubStore())
    findings = _make_findings(106)
    last_scan_id = _seed_repeated_scans(job_store, scans=6, findings=findings)
    yield TestClient(app), last_scan_id, len(findings)


# ── Fix 1: default findings view dedupes across re-scans ─────────────────────


def test_default_findings_view_dedupes_across_rescans(client_with_scans) -> None:
    client, _last_scan_id, unique = client_with_scans

    resp = client.get("/v1/findings?limit=1000")

    assert resp.status_code == 200
    body = resp.json()
    ids = [f["id"] for f in body["findings"]]
    assert len(ids) == len(set(ids)), "default view leaked duplicate finding ids across scans"
    assert len(ids) == unique
    assert body["total"] == unique
    assert body["count"] == unique


def test_scan_id_filter_still_returns_that_scan(client_with_scans) -> None:
    client, last_scan_id, unique = client_with_scans

    resp = client.get(f"/v1/findings?limit=1000&scan_id={last_scan_id}")

    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == unique
    assert body["count"] == unique
    assert body["scan_id"] == last_scan_id


# ── Fix 3: invalid sort / severity are rejected ──────────────────────────────


def test_invalid_sort_is_rejected(client_with_scans) -> None:
    client, _last, _unique = client_with_scans

    resp = client.get("/v1/findings?sort=not_a_field")

    assert resp.status_code == 422
    assert "not_a_field" in resp.json()["detail"]
    assert "effective_reach" in resp.json()["detail"]


def test_invalid_severity_is_rejected(client_with_scans) -> None:
    client, _last, _unique = client_with_scans

    resp = client.get("/v1/findings?severity=BOGUS")

    assert resp.status_code == 422
    assert "BOGUS" in resp.json()["detail"]


@pytest.mark.parametrize("sort", ["effective_reach", "cvss", "severity"])
def test_valid_sorts_still_pass(client_with_scans, sort) -> None:
    client, _last, unique = client_with_scans
    resp = client.get(f"/v1/findings?sort={sort}")
    assert resp.status_code == 200
    assert resp.json()["sort"] == sort
    assert resp.json()["total"] == unique


@pytest.mark.parametrize("severity", ["critical", "HIGH", "medium", "low"])
def test_valid_severities_still_pass(client_with_scans, severity) -> None:
    client, _last, _unique = client_with_scans
    resp = client.get(f"/v1/findings?severity={severity}")
    assert resp.status_code == 200
    normalized = severity.lower()
    assert all(f["severity"].lower() == normalized for f in resp.json()["findings"])


# ── Fix 4: /v1/results/push rejects junk ─────────────────────────────────────


def test_results_push_junk_is_rejected() -> None:
    set_job_store(InMemoryJobStore())
    client = TestClient(app)

    resp = client.post("/v1/results/push", json={"garbage": "value", "foo": 123})

    assert resp.status_code == 422


def test_results_push_empty_object_is_rejected() -> None:
    set_job_store(InMemoryJobStore())
    client = TestClient(app)

    resp = client.post("/v1/results/push", json={})

    assert resp.status_code == 422


@pytest.mark.parametrize(
    "payload",
    [
        {"source_id": "collector-1", "agents": []},
        {"agents": []},
        {"scan_id": "s-1", "blast_radius": []},
        {"summary": {"total_packages": 3}},
    ],
)
def test_results_push_real_payloads_accepted(payload) -> None:
    set_job_store(InMemoryJobStore())
    client = TestClient(app)

    resp = client.post("/v1/results/push", json=payload)

    assert resp.status_code == 201
    assert resp.json()["status"] == "stored"


# ── Fix 2: graph backpressure does not false-trip on cold build latency ──────


@pytest.fixture
def _reset_bp(monkeypatch):
    for suffix in ("CONCURRENCY", "P99_MS", "COOLDOWN_SECONDS", "MIN_SAMPLES"):
        monkeypatch.delenv(f"AGENT_BOM_BACKPRESSURE_GRAPH_{suffix}", raising=False)
    monkeypatch.delenv("AGENT_BOM_BACKPRESSURE_ENABLED", raising=False)
    reset_backpressure_for_tests()
    yield
    reset_backpressure_for_tests()


def test_graph_controller_threshold_clears_honest_build_latency(_reset_bp) -> None:
    controller = _controller_for("graph")

    # Honest cold full build ~2.6s must sit below the p99 cooldown threshold.
    assert controller.p99_threshold_ms >= 2600


def test_cold_graph_full_builds_do_not_trip_cooldown(_reset_bp) -> None:
    controller = _controller_for("graph")

    # Replay several cold /v1/graph requests: each fans out into cheap store
    # reads plus one ~2.6s full-build compute sample. Under the old 2500ms
    # default this tripped the shared cooldown after ~3 requests and 429'd every
    # graph route; the raised threshold must keep the controller closed.
    for _ in range(8):
        for _ in range(7):
            controller.try_enter()
            controller.exit(5.0)
        controller.try_enter()
        controller.exit(2600.0)

    posture = controller.describe()
    assert posture["state"] == "closed"
    assert posture["rejected"] == 0


def test_graph_cold_sweep_and_burst_no_429(_reset_bp, tmp_path) -> None:
    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.graph import (
        EntityType,
        RelationshipType,
        UnifiedEdge,
        UnifiedGraph,
        UnifiedNode,
    )

    store = SQLiteGraphStore(tmp_path / "graph.db")
    graph = UnifiedGraph(scan_id="cold-scan", tenant_id=TENANT)
    graph.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="agent-a"))
    graph.add_node(UnifiedNode(id="server:a:fs", entity_type=EntityType.SERVER, label="mcp-fs"))
    graph.add_node(
        UnifiedNode(
            id="vuln:CVE-2024-1",
            entity_type=EntityType.VULNERABILITY,
            label="CVE-2024-1",
            severity="critical",
            risk_score=9.0,
        )
    )
    graph.add_edge(UnifiedEdge(source="agent:a", target="server:a:fs", relationship=RelationshipType.USES))
    graph.add_edge(
        UnifiedEdge(
            source="server:a:fs",
            target="vuln:CVE-2024-1",
            relationship=RelationshipType.VULNERABLE_TO,
            weight=8.0,
        )
    )
    store.save_graph(graph)
    set_graph_store(store)

    # Prime the shared controller with honest cold-build latencies (~2.6s each),
    # as real full builds would record. The sweep and burst below must still
    # return 200, proving normal graph latency no longer sheds cheap reads.
    controller = _controller_for("graph")
    for _ in range(controller.min_samples):
        controller.try_enter()
        controller.exit(2600.0)

    client = TestClient(app)

    sweep = [
        "/v1/graph",
        "/v1/graph/agents",
        "/v1/graph/snapshots",
        "/v1/graph",
        "/v1/graph/agents",
    ]
    for path in sweep:
        assert client.get(path).status_code != 429, f"cold sweep 429'd on {path}"

    burst = [client.get("/v1/graph") for _ in range(8)]
    assert all(r.status_code != 429 for r in burst), "modest graph burst 429'd"
