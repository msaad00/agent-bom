"""Tests for evaluation run registry routes."""

from __future__ import annotations

from starlette.testclient import TestClient

from agent_bom.api.dataset_version_store import reset_dataset_version_store
from agent_bom.api.evaluation_store import reset_evaluation_run_store
from agent_bom.api.server import app
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()


def setup_function() -> None:
    reset_dataset_version_store()
    reset_evaluation_run_store()


def teardown_function() -> None:
    reset_dataset_version_store()
    reset_evaluation_run_store()


def _client(tenant: str = "tenant-alpha", role: str = "analyst") -> TestClient:
    client = TestClient(app)
    client.headers.update(proxy_headers(role=role, tenant=tenant))
    return client


def test_register_evaluation_run_links_dataset_version_and_uses_request_tenant() -> None:
    client = _client()
    dataset = client.post("/v1/datasets/hf-corpus/versions", json={"version_id": "v1", "source": "ci"})
    assert dataset.status_code == 201, dataset.text

    response = client.post(
        "/v1/evaluations",
        json={
            "evaluation_id": "eval-2026-05-25",
            "name": "regression suite",
            "dataset_id": "hf-corpus",
            "dataset_version_id": "v1",
            "trace_id": "trace-abc",
            "model": "gpt-4.1-mini",
            "prompt_hash": "sha256:prompt",
            "source": "eval-harness",
            "scores": {"faithfulness": 0.92, "safety": 1.0},
            "cases": [
                {
                    "case_id": "case-1",
                    "input_ref": "s3://bucket/evals/case-1/input.json",
                    "output_ref": "s3://bucket/evals/case-1/output.json",
                    "scores": {"safety": 1.0},
                    "findings": [{"id": "finding-1", "severity": "low"}],
                }
            ],
            "metadata": {"owner": "platform"},
            "tenant_id": "tenant-beta",
        },
    )

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["schema_version"] == "evals.runs.v1"
    assert body["warnings"] == ["tenant_id in body ignored; request tenant scope is authoritative"]
    evaluation = body["evaluation"]
    assert evaluation["tenant_id"] == "tenant-alpha"
    assert evaluation["evaluation_id"] == "eval-2026-05-25"
    assert evaluation["dataset_id"] == "hf-corpus"
    assert evaluation["dataset_version_id"] == "v1"
    assert evaluation["trace_id"] == "trace-abc"
    assert evaluation["scores"] == {"faithfulness": 0.92, "safety": 1.0}
    assert evaluation["cases"][0]["case_id"] == "case-1"


def test_evaluation_runs_are_listed_and_tenant_scoped() -> None:
    tenant_a = _client(tenant="tenant-alpha")
    tenant_b = _client(tenant="tenant-beta")
    tenant_a.post("/v1/evaluations", json={"evaluation_id": "eval-a", "dataset_id": "data-prod"})
    tenant_a.post("/v1/evaluations", json={"evaluation_id": "eval-b", "dataset_id": "other-data"})
    tenant_b.post("/v1/evaluations", json={"evaluation_id": "eval-c", "dataset_id": "data-prod"})

    listed_a = tenant_a.get("/v1/evaluations", params={"dataset_id": "data-prod"}).json()
    listed_b = tenant_b.get("/v1/evaluations", params={"dataset_id": "data-prod"}).json()

    assert listed_a["count"] == 1
    assert listed_a["evaluations"][0]["evaluation_id"] == "eval-a"
    assert listed_b["count"] == 1
    assert listed_b["evaluations"][0]["evaluation_id"] == "eval-c"


def test_get_evaluation_run_returns_404_for_other_tenant() -> None:
    tenant_a = _client(tenant="tenant-alpha")
    tenant_b = _client(tenant="tenant-beta")
    tenant_a.post("/v1/evaluations", json={"evaluation_id": "eval-a"})

    assert tenant_a.get("/v1/evaluations/eval-a").status_code == 200
    assert tenant_b.get("/v1/evaluations/eval-a").status_code == 404


def test_evaluation_run_rejects_missing_dataset_version_link() -> None:
    response = _client().post(
        "/v1/evaluations",
        json={"evaluation_id": "eval-a", "dataset_id": "hf-corpus", "dataset_version_id": "v1"},
    )

    assert response.status_code == 404


def test_evaluation_run_requires_analyst_role() -> None:
    response = _client(role="viewer").post("/v1/evaluations", json={"evaluation_id": "eval-a"})

    assert response.status_code == 403
