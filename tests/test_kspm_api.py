"""First-class KSPM cluster-posture REST route (issue #4134 stage 3).

The route exposes live Kubernetes posture as a resource DISTINCT from k8s image
discovery: it persists and returns the evidence envelope (benchmark provenance +
per-collector executed/skipped/unevaluable/failed state + the canonical ScanRun
outcome), so a denied/partial read is reported partial and NEVER as a clean pass.
"""

from __future__ import annotations

from starlette.testclient import TestClient

import agent_bom.api.routes.kspm as kspm_route
from agent_bom.api.kspm_posture_store import InMemoryKspmPostureStore, set_kspm_posture_store
from agent_bom.api.server import app
from agent_bom.k8s import (
    CollectorState,
    K8sCollectorEvidence,
    K8sPostureResult,
    K8sPostureStatus,
)
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

_SCAN = proxy_headers(role="admin", tenant="default")
_READ = proxy_headers(role="viewer", tenant="default")


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()
    set_kspm_posture_store(InMemoryKspmPostureStore())


def _partial_result() -> K8sPostureResult:
    # pods executed, networkpolicies denied (403 → unevaluable).
    return K8sPostureResult(
        findings=[],
        collectors=[
            K8sCollectorEvidence(collector_id="pods", state=CollectorState.EXECUTED, object_count=3),
            K8sCollectorEvidence(
                collector_id="networkpolicies",
                state=CollectorState.UNEVALUABLE,
                message="forbidden: cannot list networkpolicies",
            ),
        ],
        status=K8sPostureStatus.PARTIAL,
        transport="in_cluster",
    )


def test_post_posture_persists_and_returns_honest_partial(monkeypatch) -> None:
    set_kspm_posture_store(InMemoryKspmPostureStore())
    monkeypatch.setattr(kspm_route, "_collect_posture", lambda **_kw: _partial_result())

    client = TestClient(app)
    resp = client.post("/v1/kspm/clusters/posture", json={"namespace": "prod"}, headers=_SCAN)
    assert resp.status_code == 200, resp.text
    body = resp.json()

    # Distinct posture resource: benchmark provenance + honest collector states
    # + canonical ScanRun outcome — NOT an image inventory.
    assert body["schema_version"] == "kspm.cluster.posture.v1"
    assert "images" not in body
    assert body["resource"] == "cluster_posture"
    assert body["benchmark"]["benchmark_name"] == "CIS Kubernetes Benchmark"
    assert body["benchmark"]["benchmark_version"]

    states = {c["collector_id"]: c["state"] for c in body["collectors"]}
    assert states["pods"] == "executed"
    assert states["networkpolicies"] == "unevaluable"

    # A denied collector must render partial with a coverage-affecting issue —
    # never a clean pass.
    assert body["status"] == "partial"
    assert body["scan_run"]["outcome"] == "partial"
    codes = {i["code"] for i in body["scan_run"]["issues"]}
    assert "k8s_collector_unevaluable" in codes
    assert all(i["affects_coverage"] for i in body["scan_run"]["issues"])


def test_get_returns_latest_persisted_run(monkeypatch) -> None:
    set_kspm_posture_store(InMemoryKspmPostureStore())
    monkeypatch.setattr(kspm_route, "_collect_posture", lambda **_kw: _partial_result())

    client = TestClient(app)
    post = client.post("/v1/kspm/clusters/posture", json={"namespace": "prod"}, headers=_SCAN)
    run_id = post.json()["run_id"]

    got = client.get("/v1/kspm/clusters/posture", headers=_READ)
    assert got.status_code == 200, got.text
    body = got.json()
    assert body["run_id"] == run_id
    assert body["status"] == "partial"
    assert body["scan_run"]["outcome"] == "partial"


def test_get_without_a_run_is_honest_empty() -> None:
    set_kspm_posture_store(InMemoryKspmPostureStore())
    client = TestClient(app)
    got = client.get("/v1/kspm/clusters/posture", headers=_READ)
    assert got.status_code == 200, got.text
    body = got.json()
    assert body["status"] == "no_data"
    assert body["run_id"] is None
    assert body["collectors"] == []


def test_post_requires_scan_permission() -> None:
    set_kspm_posture_store(InMemoryKspmPostureStore())
    client = TestClient(app)
    resp = client.post("/v1/kspm/clusters/posture", json={"namespace": "prod"}, headers=_READ)
    assert resp.status_code == 403, resp.text
