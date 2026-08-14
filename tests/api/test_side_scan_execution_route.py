"""Contract tests for the CWPP side-scan execution REST surface (#4158 Wave 2).

The shipped cross-cloud (Azure/GCP) ``run_provider_side_scan`` executor ran only
from the CLI. These tests pin the REST door that exposes it consistently: an
admin-gated, tenant-scoped POST trigger that runs the executor off the event
loop and reads back honest terminal state from the SAME durable lifecycle store
the CLI uses, plus tenant-scoped status/list reads. Credentials are never
accepted here; the executor resolves read-only creds from the provider chain.

The executor itself is faked at the module seam so the route's orchestration
(gating, tenancy, off-loop offload, durable-store read, honest disabled/
unavailable envelopes) is what is under test — not live cloud calls.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from agent_bom.api.routes import cloud as cloud_routes
from agent_bom.api.server import app, configure_api
from agent_bom.cloud.side_scan_lifecycle import (
    CleanupStatus,
    ExecutionStatus,
    SQLiteSideScanStateStore,
    new_side_scan_execution,
)
from agent_bom.cloud.side_scan_targets import (
    SIDE_SCAN_STATE_DB_ENV,
    CloudSideScanExecutionResult,
    side_scan_state_db_path,
)

PROXY_SECRET = "test-proxy-secret-with-32-plus-bytes"
TENANT = "tenant-alpha"


def _headers(role: str = "admin", tenant: str = TENANT) -> dict[str, str]:
    return {
        "X-Agent-Bom-Role": role,
        "X-Agent-Bom-Tenant-ID": tenant,
        "X-Agent-Bom-Proxy-Secret": PROXY_SECRET,
    }


def setup_module() -> None:
    os.environ["AGENT_BOM_TRUST_PROXY_AUTH"] = "1"
    os.environ["AGENT_BOM_TRUST_PROXY_AUTH_SECRET"] = PROXY_SECRET
    configure_api(api_key=None)


def teardown_module() -> None:
    os.environ.pop("AGENT_BOM_TRUST_PROXY_AUTH", None)
    os.environ.pop("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", None)


@pytest.fixture()
def state_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    db = tmp_path / "side_scan_state.db"
    monkeypatch.setenv(SIDE_SCAN_STATE_DB_ENV, str(db))
    return db


def _valid_body(provider: str = "gcp") -> dict:
    body = {
        "provider": provider,
        "target_id": "projects/proj/zones/us-central1-a/disks/os",
        "account_id": "proj",
        "location": "us-central1-a",
        "collector_id": "collector-vm",
    }
    if provider == "azure":
        body["target_id"] = "/subscriptions/SUB/resourceGroups/RG/providers/Microsoft.Compute/disks/os"
        body["account_id"] = "SUB"
        body["location"] = "eastus"
        body["collector_resource_group"] = "collectors"
    return body


def _fake_complete_executor(**kwargs) -> list[CloudSideScanExecutionResult]:
    """Persist a realistic completed record to the shared store, then return a result.

    Mirrors what the real adapter does: drives the durable lifecycle record to
    ``scan_complete`` + cleanup ``complete`` so the route can read honest terminal
    state back by execution_id.
    """
    store = SQLiteSideScanStateStore(side_scan_state_db_path())
    record = store.create_or_get(
        new_side_scan_execution(
            tenant_id=kwargs["tenant_id"],
            provider=kwargs["provider"],
            account_id=kwargs["account_id"],
            target_id=kwargs["target_id"],
            collector_id=kwargs["collector_id"],
            idempotency_key=kwargs["idempotency_key"],
        )
    )
    running = record.transition(status=ExecutionStatus.RUNNING, phase="scanning")
    store.save(running, expected_version=record.state_version)
    complete = running.transition(
        status=ExecutionStatus.SCAN_COMPLETE,
        phase="finished",
        cleanup_status=CleanupStatus.COMPLETE,
        package_count=42,
        vulnerability_count=3,
        secret_count=1,
    )
    store.save(complete, expected_version=running.state_version)
    return [
        CloudSideScanExecutionResult(
            provider=kwargs["provider"],
            target_type="persistent_disk",
            target_id=kwargs["target_id"],
            account_id=kwargs["account_id"],
            location=kwargs["location"],
            snapshot_id="snap-1",
            scan_disk_id="scan-disk-1",
            vulnerability_count=3,
            cleaned_up=True,
        )
    ]


def test_trigger_runs_executor_and_reads_durable_record(state_db, monkeypatch) -> None:
    monkeypatch.setattr(cloud_routes, "_run_provider_side_scan_sync", _fake_complete_executor)
    client = TestClient(app)
    resp = client.post("/v1/cloud/side-scan", headers=_headers(), json=_valid_body())
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "scan_complete"
    assert body["provider"] == "gcp"
    assert body["tenant_id"] == TENANT
    assert body["execution_id"]
    # Honest evidence — never a clean-workload assertion.
    assert body["evidence"]["clean_workload_assertion"] is False
    assert body["execution"]["counts"]["vulnerability_count"] == 3
    assert body["result"]["cleaned_up"] is True

    # Durable state is readable by execution_id from the SAME store.
    execution_id = body["execution_id"]
    status_resp = client.get(f"/v1/cloud/side-scan/{execution_id}", headers=_headers())
    assert status_resp.status_code == 200, status_resp.text
    assert status_resp.json()["status"] == "scan_complete"


def test_trigger_disabled_returns_honest_envelope(state_db, monkeypatch) -> None:
    from agent_bom.cloud.side_scan import SideScanDisabledError

    def _raise(**kwargs):
        raise SideScanDisabledError("Disk side-scan is opt-in and currently OFF.")

    monkeypatch.setattr(cloud_routes, "_run_provider_side_scan_sync", _raise)
    client = TestClient(app)
    resp = client.post("/v1/cloud/side-scan", headers=_headers(), json=_valid_body())
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "disabled"
    # Never a false clean: no scan_complete, no evidence block claiming cleanliness.
    assert "evidence" not in body
    assert "AGENT_BOM_SIDESCAN" in body["enable"]


def test_trigger_unavailable_on_config_error(state_db, monkeypatch) -> None:
    from agent_bom.cloud.side_scan import SideScanConfigError

    def _raise(**kwargs):
        raise SideScanConfigError("GCP Persistent Disk side-scan requires the gcp extra.")

    monkeypatch.setattr(cloud_routes, "_run_provider_side_scan_sync", _raise)
    client = TestClient(app)
    resp = client.post("/v1/cloud/side-scan", headers=_headers(), json=_valid_body())
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "unavailable"
    # The specific config cause ("gcp extra") is logged server-side, never
    # surfaced to the caller (CodeQL: information-exposure-through-an-exception).
    assert "gcp extra" not in body["reason"]
    assert "unavailable" in body["reason"]


def test_azure_requires_collector_resource_group(state_db, monkeypatch) -> None:
    # No executor call should happen; the route rejects before running.
    called = {"n": 0}

    def _spy(**kwargs):
        called["n"] += 1
        return []

    monkeypatch.setattr(cloud_routes, "_run_provider_side_scan_sync", _spy)
    body = _valid_body("azure")
    body.pop("collector_resource_group")
    client = TestClient(app)
    resp = client.post("/v1/cloud/side-scan", headers=_headers(), json=body)
    assert resp.status_code == 400
    assert called["n"] == 0


def test_trigger_rejects_credentials_field(state_db) -> None:
    # extra="forbid": no per-action credential may ever be posted.
    client = TestClient(app)
    body = _valid_body()
    body["secret"] = "should-not-be-accepted"
    resp = client.post("/v1/cloud/side-scan", headers=_headers(), json=body)
    assert resp.status_code == 422


def test_trigger_rejects_aws_provider(state_db) -> None:
    # AWS EBS keeps its own CLI entrypoint (not persisted to this store).
    client = TestClient(app)
    body = _valid_body()
    body["provider"] = "aws"
    resp = client.post("/v1/cloud/side-scan", headers=_headers(), json=body)
    assert resp.status_code == 422


def test_trigger_requires_admin(state_db, monkeypatch) -> None:
    monkeypatch.setattr(cloud_routes, "_run_provider_side_scan_sync", _fake_complete_executor)
    client = TestClient(app)
    resp = client.post("/v1/cloud/side-scan", headers=_headers(role="analyst"), json=_valid_body())
    assert resp.status_code == 403


def test_trigger_requires_auth(state_db) -> None:
    monkey = os.environ.pop("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", None)
    try:
        configure_api(api_key=None)
        client = TestClient(app)
        resp = client.post("/v1/cloud/side-scan", json=_valid_body())
        assert resp.status_code == 401
    finally:
        if monkey is not None:
            os.environ["AGENT_BOM_ALLOW_UNAUTHENTICATED_API"] = monkey
        configure_api(api_key=None)


def test_status_unknown_execution_is_404(state_db) -> None:
    client = TestClient(app)
    resp = client.get("/v1/cloud/side-scan/does-not-exist", headers=_headers())
    assert resp.status_code == 404


def test_status_cross_tenant_isolation(state_db, monkeypatch) -> None:
    # A record created under tenant-alpha must be invisible to tenant-beta.
    monkeypatch.setattr(cloud_routes, "_run_provider_side_scan_sync", _fake_complete_executor)
    client = TestClient(app)
    created = client.post("/v1/cloud/side-scan", headers=_headers(tenant="tenant-alpha"), json=_valid_body())
    execution_id = created.json()["execution_id"]
    leaked = client.get(f"/v1/cloud/side-scan/{execution_id}", headers=_headers(tenant="tenant-beta"))
    assert leaked.status_code == 404


def test_list_returns_executions_and_capabilities(state_db, monkeypatch) -> None:
    monkeypatch.setattr(cloud_routes, "_run_provider_side_scan_sync", _fake_complete_executor)
    client = TestClient(app)
    client.post("/v1/cloud/side-scan", headers=_headers(), json=_valid_body())
    resp = client.get("/v1/cloud/side-scan", headers=_headers())
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["tenant_id"] == TENANT
    assert len(body["executions"]) == 1
    assert body["executions"][0]["status"] == "scan_complete"
    # Honest capability surface — no live smoke claimed.
    assert body["credentialed_smoke"] is False
    providers = {cap["provider"] for cap in body["capabilities"]}
    assert {"aws", "azure", "gcp"} <= providers


def test_list_is_tenant_scoped(state_db, monkeypatch) -> None:
    monkeypatch.setattr(cloud_routes, "_run_provider_side_scan_sync", _fake_complete_executor)
    client = TestClient(app)
    client.post("/v1/cloud/side-scan", headers=_headers(tenant="tenant-alpha"), json=_valid_body())
    resp = client.get("/v1/cloud/side-scan", headers=_headers(tenant="tenant-beta"))
    assert resp.status_code == 200
    assert resp.json()["executions"] == []
