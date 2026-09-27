"""Cloud accounts reflect pushed/scanned cloud scopes, tenant-scoped."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from agent_bom.api.connection_store import (
    CloudConnectionRecord,
    InMemoryConnectionStore,
    get_connection_store,
    set_connection_store,
)
from agent_bom.api.server import app, set_job_store
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import _get_graph_store, _get_store, set_graph_store
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

TENANT_A = "cloud-scope-alpha"
TENANT_B = "cloud-scope-beta"


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()
    set_job_store(InMemoryJobStore())
    set_connection_store(InMemoryConnectionStore())


@pytest.fixture(autouse=True)
def _fresh_stores(tmp_path):
    from agent_bom.api.graph_store import SQLiteGraphStore

    original_graph = _get_graph_store()
    set_graph_store(SQLiteGraphStore(tmp_path / "graph.db"))
    set_job_store(InMemoryJobStore())
    set_connection_store(InMemoryConnectionStore())
    try:
        yield
    finally:
        set_graph_store(original_graph)


def _aws_cloud_report(account_id: str) -> dict:
    return {
        "agents": [],
        "scan_sources": ["aws"],
        "cis_benchmark": {
            "benchmark": "CIS AWS Foundations",
            "account_id": account_id,
            "accounts_scanned": [account_id],
            "passed": 1,
            "failed": 1,
            "total": 2,
            "checks": [],
        },
        "findings": [
            {
                "id": f"cis-{account_id}-1.4",
                "severity": "high",
                "security_domain": "cspm",
                "provider": "aws",
                "account_ref": f"aws:{account_id}",
            }
        ],
    }


def _azure_cloud_report(subscription_id: str) -> dict:
    return {
        "agents": [],
        "scan_sources": ["azure"],
        "azure_cis_benchmark": {
            "benchmark": "CIS Azure Foundations",
            "subscription_id": subscription_id,
            "subscriptions_scanned": [subscription_id],
            "checks": [],
        },
    }


def _push(client: TestClient, tenant: str, report: dict) -> None:
    response = client.post("/v1/results/push", json=report, headers=proxy_headers(role="analyst", tenant=tenant))
    assert response.status_code == 201, response.text


def _cloud_service(client: TestClient, tenant: str) -> dict:
    body = client.get("/v1/posture/counts", headers=proxy_headers(role="viewer", tenant=tenant)).json()
    return body["services"]["cloud_accounts"]


def test_pushed_cloud_scans_count_distinct_scopes_per_tenant() -> None:
    client = TestClient(app)
    _push(client, TENANT_A, _aws_cloud_report("111111111111"))
    _push(client, TENANT_A, _aws_cloud_report("111111111111"))
    _push(client, TENANT_A, _azure_cloud_report("sub-0001"))

    service = _cloud_service(client, TENANT_A)
    assert service["state"] == "live"
    assert service["count"] == 2
    assert service["detail"] == "aws,azure"
    completed = sorted(job.completed_at for job in _get_store().list_all(tenant_id=TENANT_A))
    assert service["last_scan_at"] == completed[-1]

    other = _cloud_service(client, TENANT_B)
    assert other["state"] == "locked"
    assert other["count"] == 0
    assert other.get("last_scan_at") is None


def test_connection_and_pushed_scan_of_same_account_count_once() -> None:
    get_connection_store().put(
        CloudConnectionRecord(
            id="conn-aws",
            tenant_id=TENANT_A,
            provider="aws",
            display_name="prod",
            role_ref="arn:aws:iam::111111111111:role/read",
            external_id_encrypted="cipher",
            status="active",
        )
    )
    client = TestClient(app)
    _push(client, TENANT_A, _aws_cloud_report("111111111111"))

    service = _cloud_service(client, TENANT_A)
    assert service["count"] == 1
    assert service["state"] == "live"


def test_non_cloud_push_does_not_unlock_cloud_accounts() -> None:
    client = TestClient(app)
    _push(client, TENANT_A, {"agents": [], "findings": [{"id": "pkg-1", "severity": "low", "security_domain": "vuln"}]})
    service = _cloud_service(client, TENANT_A)
    assert service["state"] == "locked"
    assert service["count"] == 0


def test_overview_cloud_tile_matches_registry_count() -> None:
    client = TestClient(app)
    _push(client, TENANT_A, _aws_cloud_report("222222222222"))
    overview = client.get("/v1/overview", headers=proxy_headers(role="viewer", tenant=TENANT_A)).json()
    assert overview["domains"]["cloud"]["metric"] == 1
    assert overview["domains"]["cloud"]["metric"] == _cloud_service(client, TENANT_A)["count"]
