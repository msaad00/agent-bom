"""Tests for dataset version registry routes."""

from __future__ import annotations

from starlette.testclient import TestClient

from agent_bom.api.dataset_version_store import reset_dataset_version_store
from agent_bom.api.server import app
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()


def setup_function() -> None:
    reset_dataset_version_store()


def teardown_function() -> None:
    reset_dataset_version_store()


def _client(tenant: str = "tenant-alpha", role: str = "analyst") -> TestClient:
    client = TestClient(app)
    client.headers.update(proxy_headers(role=role, tenant=tenant))
    return client


def test_register_dataset_version_uses_request_tenant() -> None:
    response = _client().post(
        "/v1/datasets/hf-corpus/versions",
        json={
            "version_id": "2026-05-17",
            "artifact_uri": "s3://customer-bucket/datasets/hf-corpus",
            "digest": "sha256:abc123",
            "source": "training-agent",
            "metadata": {"license": "apache-2.0"},
            "tenant_id": "tenant-beta",
        },
    )

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["schema_version"] == "v1"
    assert body["warnings"] == ["tenant_id in body ignored; request tenant scope is authoritative"]
    dataset = body["dataset"]
    assert dataset["tenant_id"] == "tenant-alpha"
    assert dataset["dataset_id"] == "hf-corpus"
    assert dataset["version_id"] == "2026-05-17"
    assert dataset["source"] == "training-agent"
    assert dataset["metadata"] == {"license": "apache-2.0"}


def test_dataset_versions_are_listed_and_tenant_scoped() -> None:
    tenant_a = _client(tenant="tenant-alpha")
    tenant_b = _client(tenant="tenant-beta")
    tenant_a.post("/v1/datasets/data-prod/versions", json={"version_id": "v1", "source": "ci"})
    tenant_a.post("/v1/datasets/data-prod/versions", json={"version_id": "v2", "source": "ci"})

    listed_a = tenant_a.get("/v1/datasets/data-prod/versions").json()
    listed_b = tenant_b.get("/v1/datasets/data-prod/versions").json()

    assert listed_a["count"] == 2
    assert {item["version_id"] for item in listed_a["versions"]} == {"v1", "v2"}
    assert listed_b["count"] == 0


def test_get_dataset_version_returns_404_for_other_tenant() -> None:
    tenant_a = _client(tenant="tenant-alpha")
    tenant_b = _client(tenant="tenant-beta")
    tenant_a.post("/v1/datasets/shared-data/versions", json={"version_id": "v1"})

    assert tenant_a.get("/v1/datasets/shared-data/versions/v1").status_code == 200
    assert tenant_b.get("/v1/datasets/shared-data/versions/v1").status_code == 404


def test_dataset_version_rejects_unstable_ids() -> None:
    response = _client().post("/v1/datasets/bad$id/versions", json={"version_id": "v1"})

    assert response.status_code == 422


def test_dataset_version_requires_analyst_role() -> None:
    response = _client(role="viewer").post("/v1/datasets/data-prod/versions", json={"version_id": "v1"})

    assert response.status_code == 403
