"""Tests for hosted-product source registry routes."""

from __future__ import annotations

import asyncio
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Event, Thread
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import HTTPException
from starlette.testclient import TestClient

from agent_bom.api import stores as _stores
from agent_bom.api.credential_store import InMemoryCredentialRefStore
from agent_bom.api.idempotency_store import InMemoryIdempotencyStore, idempotency_request_fingerprint
from agent_bom.api.models import (
    CredentialRefRecord,
    CredentialRefStatus,
    ScanJob,
    SourceCohortRunRequest,
    SourceKind,
    SourceRecord,
)
from agent_bom.api.routes.scan import correlation_cohort_id, correlation_cohort_parent_job_id
from agent_bom.api.schedule_store import InMemoryScheduleStore, ScanSchedule
from agent_bom.api.server import app, configure_api
from agent_bom.api.source_store import InMemorySourceStore
from agent_bom.api.store import InMemoryJobStore
from agent_bom.connectors.base import ConnectorHealthState, ConnectorStatus
from tests.auth_helpers import PROXY_SECRET

ADMIN_HEADERS = {
    "X-Agent-Bom-Role": "admin",
    "X-Agent-Bom-Tenant-ID": "tenant-alpha",
    "X-Agent-Bom-Proxy-Secret": PROXY_SECRET,
}
ANALYST_HEADERS = {
    "X-Agent-Bom-Role": "analyst",
    "X-Agent-Bom-Tenant-ID": "tenant-alpha",
    "X-Agent-Bom-Proxy-Secret": PROXY_SECRET,
}
VIEWER_HEADERS = {
    "X-Agent-Bom-Role": "viewer",
    "X-Agent-Bom-Tenant-ID": "tenant-alpha",
    "X-Agent-Bom-Proxy-Secret": PROXY_SECRET,
}
OTHER_TENANT_HEADERS = {
    "X-Agent-Bom-Role": "viewer",
    "X-Agent-Bom-Tenant-ID": "tenant-beta",
    "X-Agent-Bom-Proxy-Secret": PROXY_SECRET,
}
OTHER_TENANT_ANALYST_HEADERS = {
    "X-Agent-Bom-Role": "analyst",
    "X-Agent-Bom-Tenant-ID": "tenant-beta",
    "X-Agent-Bom-Proxy-Secret": PROXY_SECRET,
}


def _nested_encoded_github_ref(depth: int) -> tuple[str, str]:
    token = "ghp_" + "A" * 36
    encoded = "".join(f"%{ord(char):02X}" for char in token)
    for _ in range(depth - 1):
        encoded = encoded.replace("%", "%25")
    return token, f"vault://team/{encoded}"


@pytest.fixture
def source_client(monkeypatch: pytest.MonkeyPatch):
    old_source_store = _stores._source_store
    old_credential_store = _stores._credential_ref_store
    old_job_store = _stores._store
    old_idempotency_store = _stores._idempotency_store
    old_schedule_store = _stores._schedule_store

    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", PROXY_SECRET)
    configure_api(api_key=None)
    _stores.set_source_store(InMemorySourceStore())
    _stores.set_credential_ref_store(InMemoryCredentialRefStore())
    _stores.set_job_store(InMemoryJobStore())
    _stores.set_idempotency_store(InMemoryIdempotencyStore())
    _stores.set_schedule_store(InMemoryScheduleStore())

    try:
        with TestClient(app) as client:
            yield client
    finally:
        monkeypatch.delenv("AGENT_BOM_TRUST_PROXY_AUTH", raising=False)
        configure_api(api_key=None)
        _stores._source_store = old_source_store
        _stores._credential_ref_store = old_credential_store
        _stores._store = old_job_store
        _stores._idempotency_store = old_idempotency_store
        _stores._schedule_store = old_schedule_store


def test_source_crud_and_role_enforcement(source_client: TestClient) -> None:
    create = source_client.post(
        "/v1/sources",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "AWS production account",
            "kind": "connector.cloud_read_only",
            "owner": "platform-security",
            "connector_name": "jira",
            "credential_mode": "none",
            "description": "Read-only cloud discovery source",
        },
    )
    assert create.status_code == 201
    body = create.json()
    source_id = body["source_id"]
    assert body["tenant_id"] == "tenant-alpha"
    assert body["status"] == "configured"

    listed = source_client.get("/v1/sources", headers=VIEWER_HEADERS)
    assert listed.status_code == 200
    listed_body = listed.json()
    assert listed_body["count"] == 1
    assert listed_body["sources"][0]["source_id"] == source_id

    updated = source_client.put(
        f"/v1/sources/{source_id}",
        headers=ANALYST_HEADERS,
        json={"description": "Updated source description", "owner": "security-engineering"},
    )
    assert updated.status_code == 200
    assert updated.json()["owner"] == "security-engineering"

    other_tenant = source_client.get(f"/v1/sources/{source_id}", headers=OTHER_TENANT_HEADERS)
    assert other_tenant.status_code == 404

    delete_forbidden = source_client.delete(f"/v1/sources/{source_id}", headers=ANALYST_HEADERS)
    assert delete_forbidden.status_code == 403

    deleted = source_client.delete(f"/v1/sources/{source_id}", headers=ADMIN_HEADERS)
    assert deleted.status_code == 204
    assert source_client.get("/v1/sources", headers=VIEWER_HEADERS).json()["count"] == 0


def test_source_cohort_run_is_exact_tenant_bound_and_idempotent(
    source_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("agent_bom.api.routes.scan.dispatch_scan_job", lambda job: None)
    source_ids: list[str] = []
    for payload in (
        {
            "display_name": "Repository",
            "kind": "scan.repo",
            "config": {"scan_request": {"repo_url": "https://github.com/example/app"}},
        },
        {
            "display_name": "Digest-pinned image",
            "kind": "scan.image",
            "config": {"scan_request": {"images": ["example/app@sha256:" + "a" * 64]}},
        },
    ):
        created = source_client.post("/v1/sources", headers=ANALYST_HEADERS, json=payload)
        assert created.status_code == 201
        source_ids.append(created.json()["source_id"])

    headers = {**ANALYST_HEADERS, "Idempotency-Key": "deploy-2026-09-03"}
    first = source_client.post(
        "/v1/sources/run-cohort",
        headers=headers,
        json={"source_ids": list(reversed(source_ids)), "max_age_hours": 24},
    )

    assert first.status_code == 202
    body = first.json()
    assert body["source_ids"] == sorted(source_ids)
    assert body["correlation_cohort_id"]
    assert body["cohort_manifest_hash"]
    assert body["max_age_hours"] == 24
    assert body["auto_correlation"]["cohort_basis"] == "correlation_cohort_id"
    assert body["auto_correlation"]["status"] == "skipped"
    assert body["auto_correlation"]["reason"] == "durable_job_store_required"

    replay = source_client.post(
        "/v1/sources/run-cohort",
        headers=headers,
        json={"source_ids": source_ids, "max_age_hours": 24},
    )
    assert replay.status_code == 202
    assert replay.json() == body

    changed = source_client.post(
        "/v1/sources/run-cohort",
        headers=headers,
        json={"source_ids": source_ids, "max_age_hours": 48},
    )
    assert changed.status_code == 409

    cross_tenant = source_client.post(
        "/v1/sources/run-cohort",
        headers={**OTHER_TENANT_ANALYST_HEADERS, "Idempotency-Key": "deploy-2026-09-03"},
        json={"source_ids": source_ids, "max_age_hours": 24},
    )
    assert cross_tenant.status_code == 404


def test_source_cohort_same_key_dispatches_each_child_once(
    source_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_ids: list[str] = []
    for name in ("z-repository", "a-repository"):
        created = source_client.post(
            "/v1/sources",
            headers=ANALYST_HEADERS,
            json={
                "display_name": name,
                "kind": "scan.repo",
                "config": {"scan_request": {"repo_url": f"https://github.com/example/{name}"}},
            },
        )
        assert created.status_code == 201
        source_ids.append(created.json()["source_id"])

    idempotency = _stores._get_idempotency_store()
    original_get = idempotency.get
    barrier = threading.Barrier(2)

    def _racing_get(*args, **kwargs):
        value = original_get(*args, **kwargs)
        if args[0] == "/v1/sources/run-cohort" and value is None:
            barrier.wait(timeout=2)
        return value

    monkeypatch.setattr(idempotency, "get", _racing_get)
    dispatched: list[str] = []
    monkeypatch.setattr("agent_bom.api.routes.scan.dispatch_scan_job", lambda job: dispatched.append(job.job_id))
    headers = {**ANALYST_HEADERS, "Idempotency-Key": "concurrent-deploy"}
    payload = {"source_ids": list(reversed(source_ids)), "max_age_hours": 24}

    def _post() -> tuple[int, dict[str, Any]]:
        response = TestClient(app, raise_server_exceptions=False).post(
            "/v1/sources/run-cohort",
            headers=headers,
            json=payload,
        )
        return response.status_code, response.json()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _index: _post(), range(2)))

    assert {status for status, _body in results} == {202}
    assert results[0][1] == results[1][1]
    assert sorted(dispatched) == sorted(results[0][1]["child_job_ids"])
    for source_id in source_ids:
        source = _stores._get_source_store().get(source_id)
        assert source is not None
        child = _stores._get_store().get(source.last_job_id or "", tenant_id="tenant-alpha")
        assert child is not None and child.source_id == source_id


def test_source_cohort_reconciles_durable_parent_after_receipt_failure(
    source_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_ids: list[str] = []
    for name in ("repo-one", "repo-two"):
        created = source_client.post(
            "/v1/sources",
            headers=ANALYST_HEADERS,
            json={
                "display_name": name,
                "kind": "scan.repo",
                "config": {"scan_request": {"repo_url": f"https://github.com/example/{name}"}},
            },
        )
        source_ids.append(created.json()["source_id"])

    class _FailCommittedReceiptOnce(InMemoryIdempotencyStore):
        failed = False

        def put(self, *args, **kwargs) -> None:
            response = args[4]
            if args[0] == "/v1/sources/run-cohort" and response.get("committed") is True and not self.failed:
                self.failed = True
                raise RuntimeError("receipt backend interrupted")
            super().put(*args, **kwargs)

    idempotency = _FailCommittedReceiptOnce()
    _stores.set_idempotency_store(idempotency)
    dispatched: list[str] = []
    monkeypatch.setattr("agent_bom.api.routes.scan.dispatch_scan_job", lambda job: dispatched.append(job.job_id))
    headers = {**ANALYST_HEADERS, "Idempotency-Key": "durable-before-receipt"}
    payload = {"source_ids": source_ids, "max_age_hours": 24}

    failed = source_client.post("/v1/sources/run-cohort", headers=headers, json=payload)
    replay = source_client.post("/v1/sources/run-cohort", headers=headers, json=payload)

    assert failed.status_code == 503
    assert replay.status_code == 202
    assert len(dispatched) == 2
    receipt = idempotency.get(
        "/v1/sources/run-cohort",
        "tenant-alpha",
        "source-cohort",
        "durable-before-receipt",
    )
    assert receipt is not None and receipt["committed"] is True
    assert receipt["response"] == replay.json()


def test_source_cohort_stops_heartbeat_when_post_enqueue_projection_raises(
    source_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agent_bom.api.routes import sources as source_routes

    source_ids: list[str] = []
    for name in ("heartbeat-one", "heartbeat-two"):
        created = source_client.post(
            "/v1/sources",
            headers=ANALYST_HEADERS,
            json={
                "display_name": name,
                "kind": "scan.repo",
                "config": {"scan_request": {"repo_url": f"https://github.com/example/{name}"}},
            },
        )
        source_ids.append(created.json()["source_id"])

    exits: list[bool] = []
    original_heartbeat = source_routes.IdempotencyReservationHeartbeat

    class _TrackingHeartbeat(original_heartbeat):
        def __exit__(self, *args: object) -> None:
            exits.append(True)
            super().__exit__(*args)

    monkeypatch.setattr(source_routes, "IdempotencyReservationHeartbeat", _TrackingHeartbeat)
    monkeypatch.setattr(source_routes, "_update_cohort_sources", lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("injected")))
    monkeypatch.setattr("agent_bom.api.routes.scan.dispatch_scan_job", lambda _job: None)

    with pytest.raises(RuntimeError, match="injected"):
        source_client.post(
            "/v1/sources/run-cohort",
            headers={**ANALYST_HEADERS, "Idempotency-Key": "heartbeat-cleanup"},
            json={"source_ids": source_ids, "max_age_hours": 24},
        )

    assert exits == [True]


def test_source_cohort_reclaims_expired_claim_before_any_dispatch(
    source_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_ids: list[str] = []
    for name in ("expired-one", "expired-two"):
        created = source_client.post(
            "/v1/sources",
            headers=ANALYST_HEADERS,
            json={
                "display_name": name,
                "kind": "scan.repo",
                "config": {"scan_request": {"repo_url": f"https://github.com/example/{name}"}},
            },
        )
        source_ids.append(created.json()["source_id"])
    request = SourceCohortRunRequest(source_ids=source_ids, max_age_hours=24)
    request_hash = idempotency_request_fingerprint(request)
    cohort_id = correlation_cohort_id(tenant_id="tenant-alpha", idempotency_key="expired-cohort")
    parent_id = correlation_cohort_parent_job_id(tenant_id="tenant-alpha", correlation_cohort_id=cohort_id)
    idempotency = _stores._get_idempotency_store()
    key = ("/v1/sources/run-cohort", "tenant-alpha", "source-cohort", "expired-cohort")
    idempotency.claim(
        *key,
        {"parent_job_id": parent_id, "committed": False},
        request_hash=request_hash,
    )
    idempotency._records[key].created_at = (datetime.now(timezone.utc) - timedelta(seconds=31)).isoformat()  # type: ignore[attr-defined]  # noqa: SLF001
    monkeypatch.setenv("AGENT_BOM_IDEMPOTENCY_RESERVATION_LEASE_SECONDS", "30")
    dispatched: list[str] = []
    monkeypatch.setattr("agent_bom.api.routes.scan.dispatch_scan_job", lambda job: dispatched.append(job.job_id))

    response = source_client.post(
        "/v1/sources/run-cohort",
        headers={**ANALYST_HEADERS, "Idempotency-Key": "expired-cohort"},
        json=request.model_dump(mode="json"),
    )

    assert response.status_code == 202
    assert response.json()["parent_job_id"] == parent_id
    assert sorted(dispatched) == sorted(response.json()["child_job_ids"])


def test_source_cohort_run_rejects_duplicate_or_multi_target_members(
    source_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("agent_bom.api.routes.scan.dispatch_scan_job", lambda job: None)
    repo = source_client.post(
        "/v1/sources",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "Repository",
            "kind": "scan.repo",
            "config": {"scan_request": {"repo_url": "https://github.com/example/app"}},
        },
    ).json()
    multi_image = source_client.post(
        "/v1/sources",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "Two images",
            "kind": "scan.image",
            "config": {
                "scan_request": {
                    "images": [
                        "example/app@sha256:" + "a" * 64,
                        "example/worker@sha256:" + "b" * 64,
                    ]
                }
            },
        },
    ).json()
    headers = {**ANALYST_HEADERS, "Idempotency-Key": "invalid-cohort"}

    duplicate = source_client.post(
        "/v1/sources/run-cohort",
        headers=headers,
        json={"source_ids": [repo["source_id"], repo["source_id"]], "max_age_hours": 168},
    )
    assert duplicate.status_code == 422

    multi_target = source_client.post(
        "/v1/sources/run-cohort",
        headers={**ANALYST_HEADERS, "Idempotency-Key": "multi-target-cohort"},
        json={"source_ids": [repo["source_id"], multi_image["source_id"]], "max_age_hours": 168},
    )
    assert multi_target.status_code == 422


def test_source_create_rejects_mismatched_tenant(source_client: TestClient) -> None:
    resp = source_client.post(
        "/v1/sources",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "Wrong tenant source",
            "kind": "scan.repo",
            "tenant_id": "tenant-beta",
        },
    )
    assert resp.status_code == 403
    assert "tenant_id in the request body must match the authenticated tenant" in resp.json()["detail"]


@pytest.mark.parametrize(
    ("kind", "expected_target"),
    [
        ("scan.repo", "repo_url, agent_projects, gha_path, sbom, or filesystem_paths"),
        ("scan.image", "images"),
        ("scan.iac", "repo_url, tf_dirs, or k8s"),
        ("scan.cloud", "connectors or inventory"),
        ("scan.mcp_config", "repo_url, inventory, agent_projects, or discover_host"),
        ("ingest.artifact_import", "inventory, sbom, external_scan, or vex"),
    ],
)
def test_runnable_source_create_rejects_empty_scan_target(
    source_client: TestClient,
    kind: str,
    expected_target: str,
) -> None:
    response = source_client.post(
        "/v1/sources",
        headers=ANALYST_HEADERS,
        json={"display_name": f"Empty {kind}", "kind": kind},
    )

    assert response.status_code == 422
    assert f"{kind} source requires {expected_target}" in response.json()["detail"]


def test_legacy_empty_runnable_source_cannot_test_or_enqueue(
    source_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = SourceRecord(
        source_id="legacy-empty-repo",
        tenant_id="tenant-alpha",
        display_name="Legacy empty repo",
        kind=SourceKind.SCAN_REPO,
    )
    _stores._source_store.put(source)

    def _must_not_enqueue(**kwargs):
        raise AssertionError("an empty source must not enqueue an all-default scan")

    monkeypatch.setattr("agent_bom.api.routes.sources.enqueue_scan_job", _must_not_enqueue)

    tested = source_client.post(f"/v1/sources/{source.source_id}/test", headers=ANALYST_HEADERS)
    run = source_client.post(f"/v1/sources/{source.source_id}/run", headers=ANALYST_HEADERS)

    assert tested.status_code == 422
    assert run.status_code == 422
    assert "scan.repo source requires repo_url, agent_projects, gha_path, sbom, or filesystem_paths" in tested.json()["detail"]
    assert "scan.repo source requires repo_url, agent_projects, gha_path, sbom, or filesystem_paths" in run.json()["detail"]


def test_source_config_uses_the_api_local_path_jail(
    source_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENT_BOM_API_LOCAL_PATH_SCANS", "disabled")

    response = source_client.post(
        "/v1/sources",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "Unsafe local IaC source",
            "kind": "scan.iac",
            "config": {"scan_request": {"tf_dirs": ["/private/tenant-secret"]}},
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Local filesystem scans are disabled"
    assert "/private/tenant-secret" not in response.text


def test_source_repo_target_rejects_embedded_credentials_without_persisting(source_client: TestClient) -> None:
    response = source_client.post(
        "/v1/sources",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "Unsafe repository",
            "kind": "scan.repo",
            "config": {"scan_request": {"repo_url": "https://operator:secret-value@example.com/repo"}},
        },
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "repo_url must be an HTTP(S) URL without embedded credentials"
    assert "secret-value" not in response.text
    assert source_client.get("/v1/sources", headers=VIEWER_HEADERS).json()["count"] == 0


def test_credential_reference_crud_and_tenant_isolation(source_client: TestClient) -> None:
    create = source_client.post(
        "/v1/credentials",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "AWS prod read-only role",
            "provider": "aws",
            "mode": "role_arn",
            "external_ref": "arn:aws:iam::123456789012:role/agent-bom-readonly",
            "owner": "platform-security",
            "scopes": ["iam:GetRole", "iam:ListAttachedRolePolicies"],
        },
    )
    assert create.status_code == 201
    body = create.json()
    credential_ref_id = body["credential_ref_id"]
    assert body["tenant_id"] == "tenant-alpha"
    assert "secret" not in body

    listed = source_client.get("/v1/credentials", headers=VIEWER_HEADERS)
    assert listed.status_code == 200
    assert listed.json()["credentials"][0]["credential_ref_id"] == credential_ref_id

    other_tenant = source_client.get(f"/v1/credentials/{credential_ref_id}", headers=OTHER_TENANT_HEADERS)
    assert other_tenant.status_code == 404

    delete_forbidden = source_client.delete(f"/v1/credentials/{credential_ref_id}", headers=ANALYST_HEADERS)
    assert delete_forbidden.status_code == 403

    deleted = source_client.delete(f"/v1/credentials/{credential_ref_id}", headers=ADMIN_HEADERS)
    assert deleted.status_code == 204
    retired = source_client.get(f"/v1/credentials/{credential_ref_id}", headers=VIEWER_HEADERS)
    assert retired.status_code == 200
    assert retired.json()["status"] == "retired"
    assert retired.json()["enabled"] is False


def test_credential_rotation_posture_flags_stale_and_expiring_refs(source_client: TestClient) -> None:
    stale = source_client.post(
        "/v1/credentials",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "AWS stale automation key",
            "provider": "aws",
            "mode": "secret_manager",
            "external_ref": "aws-secretsmanager://prod/agent-bom/stale",
            "owner": "platform-security",
            "credential_class": "api_key",
            "last_rotated_at": "2026-01-01T00:00:00+00:00",
            "rotation_interval_days": 30,
            "max_age_days": 60,
        },
    )
    assert stale.status_code == 201

    near_expiry_at = (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()
    expiring = source_client.post(
        "/v1/credentials",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "ServiceNow near-expiry token",
            "provider": "servicenow",
            "mode": "secret_manager",
            "external_ref": "vault://servicenow/token",
            "owner": "it-operations",
            "credential_class": "service_account",
            "last_rotated_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": near_expiry_at,
            "expiry_warning_days": 14,
        },
    )
    assert expiring.status_code == 201

    posture = source_client.get("/v1/credentials/posture", headers=VIEWER_HEADERS)
    assert posture.status_code == 200
    body = posture.json()
    assert body["schema_version"] == "credential.rotation_governance.v1"
    assert body["tenant_id"] == "tenant-alpha"
    assert body["summary"]["total"] == 2
    assert body["summary"]["max_age_exceeded"] == 1
    assert body["summary"]["near_expiry"] == 1
    assert body["summary"]["findings"] == 2

    statuses = {row["display_name"]: row["rotation_status"] for row in body["credentials"]}
    assert statuses == {
        "AWS stale automation key": "max_age_exceeded",
        "ServiceNow near-expiry token": "near_expiry",
    }
    assert all("external_ref" not in row for row in body["credentials"])
    assert "aws-secretsmanager://prod/agent-bom/stale" not in posture.text
    assert "vault://servicenow/token" not in posture.text
    assert all(finding["type"] == "credential_rotation" for finding in body["findings"])

    other_tenant = source_client.get("/v1/credentials/posture", headers=OTHER_TENANT_HEADERS)
    assert other_tenant.status_code == 200
    assert other_tenant.json()["summary"]["total"] == 0


def test_posture_credentials_includes_rotation_governance_without_scan(source_client: TestClient) -> None:
    created = source_client.post(
        "/v1/credentials",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "Unknown rotation ref",
            "provider": "azure",
            "mode": "secret_manager",
            "external_ref": "keyvault://agent-bom/prod",
            "credential_class": "service_account",
        },
    )
    assert created.status_code == 201

    posture = source_client.get("/v1/posture/credentials", headers=VIEWER_HEADERS)
    assert posture.status_code == 200
    body = posture.json()
    assert body["credentials"] == []
    assert body["count"] == 0
    assert body["rotation_governance"]["summary"]["unknown_age"] == 1
    assert body["rotation_governance"]["findings"][0]["status"] == "unknown_age"
    assert "keyvault://agent-bom/prod" not in posture.text


def test_credential_reference_rejects_secret_material(source_client: TestClient) -> None:
    create = source_client.post(
        "/v1/credentials",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "Unsafe credential",
            "provider": "aws",
            "external_ref": "secret-manager://agent-bom/prod",
            "secret_value": "AKIA...",
        },
    )
    assert create.status_code == 422


def test_credential_reference_rejects_secret_shaped_external_ref_without_echo_or_persist(
    source_client: TestClient,
) -> None:
    secret = "ghp_" + "A" * 36

    create = source_client.post(
        "/v1/credentials",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "Unsafe credential",
            "provider": "github",
            "external_ref": secret,
        },
    )

    assert create.status_code == 422
    assert secret not in create.text
    listed = source_client.get("/v1/credentials", headers=VIEWER_HEADERS)
    assert listed.json()["count"] == 0
    assert secret not in listed.text


def test_credential_reference_rejects_opaque_secret_inside_reference_path_without_persisting(
    source_client: TestClient,
) -> None:
    secret = "".join(("aZ9k", "Lm2N", "pQr7", "StUv", "Wx3Y", "z8Ab", "CdEf", "GhJk", "LmNo", "PqRs"))
    external_ref = f"vault://production/{secret}"

    create = source_client.post(
        "/v1/credentials",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "Unsafe opaque credential",
            "provider": "vault",
            "external_ref": external_ref,
        },
    )

    assert create.status_code == 422
    assert secret not in create.text
    assert _stores._credential_ref_store.list_all(tenant_id="tenant-alpha") == []


@pytest.mark.parametrize("depth", range(1, 7))
def test_credential_reference_rejects_nested_encoded_secret_without_echo_or_persistence(
    source_client: TestClient,
    depth: int,
) -> None:
    token, external_ref = _nested_encoded_github_ref(depth)

    create = source_client.post(
        "/v1/credentials",
        headers=ANALYST_HEADERS,
        json={
            "display_name": f"Nested encoded credential {depth}",
            "provider": "vault",
            "external_ref": external_ref,
        },
    )

    assert create.status_code == 422
    assert token not in create.text
    assert external_ref not in create.text
    assert _stores._credential_ref_store.list_all(tenant_id="tenant-alpha") == []


@pytest.mark.parametrize(
    "external_ref",
    [
        "vault://team/agent-bom/production",
        "keyvault://prod-vault/agent-bom-reader",
        "aws-secretsmanager://production/agent-bom",
        "gcp-secretmanager://projects/acme-prod/secrets/agent-bom-reader",
        "secret-manager://platform/agent-bom",
    ],
)
def test_credential_reference_accepts_and_persists_legitimate_reference(
    source_client: TestClient,
    external_ref: str,
) -> None:
    create = source_client.post(
        "/v1/credentials",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "Managed credential reference",
            "provider": "vault",
            "external_ref": external_ref,
        },
    )

    assert create.status_code == 201
    assert create.json()["external_ref"] == external_ref
    credential_ref_id = create.json()["credential_ref_id"]
    persisted = _stores._credential_ref_store.get(credential_ref_id, tenant_id="tenant-alpha")
    assert persisted is not None
    assert persisted.external_ref == external_ref


def test_credential_reference_rejects_secret_shaped_update_without_mutating_existing_ref(
    source_client: TestClient,
) -> None:
    created = source_client.post(
        "/v1/credentials",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "GitHub producer identity",
            "provider": "github",
            "external_ref": "vault://github/agent-bom",
        },
    )
    credential_ref_id = created.json()["credential_ref_id"]
    secret = "ghp_" + "B" * 36

    update = source_client.put(
        f"/v1/credentials/{credential_ref_id}",
        headers=ANALYST_HEADERS,
        json={"external_ref": secret},
    )

    assert update.status_code == 422
    assert secret not in update.text
    fetched = source_client.get(f"/v1/credentials/{credential_ref_id}", headers=VIEWER_HEADERS)
    assert fetched.json()["external_ref"] == "vault://github/agent-bom"
    assert secret not in fetched.text


def test_credential_retirement_is_terminal_and_cannot_be_rewritten_or_tested_by_analyst(
    source_client: TestClient,
) -> None:
    created = source_client.post(
        "/v1/credentials",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "Retired producer identity",
            "provider": "github",
            "external_ref": "vault://github/retired",
        },
    )
    credential_ref_id = created.json()["credential_ref_id"]
    assert source_client.delete(f"/v1/credentials/{credential_ref_id}", headers=ADMIN_HEADERS).status_code == 204

    revived = source_client.put(
        f"/v1/credentials/{credential_ref_id}",
        headers=ANALYST_HEADERS,
        json={"enabled": True, "status": "configured"},
    )
    tested = source_client.post(f"/v1/credentials/{credential_ref_id}/test", headers=ANALYST_HEADERS)

    assert revived.status_code == 409
    assert tested.status_code == 409
    fetched = source_client.get(f"/v1/credentials/{credential_ref_id}", headers=VIEWER_HEADERS)
    assert fetched.json()["enabled"] is False
    assert fetched.json()["status"] == "retired"


def test_credential_update_explicit_null_clears_nullable_lifecycle_fields(source_client: TestClient) -> None:
    created = source_client.post(
        "/v1/credentials",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "Rotating producer identity",
            "provider": "github",
            "external_ref": "vault://github/rotating",
            "last_rotated_at": "2026-01-01T00:00:00+00:00",
            "expires_at": "2027-01-01T00:00:00+00:00",
            "rotation_interval_days": 30,
            "max_age_days": 60,
            "expiry_warning_days": 14,
        },
    )
    credential_ref_id = created.json()["credential_ref_id"]

    cleared = source_client.put(
        f"/v1/credentials/{credential_ref_id}",
        headers=ANALYST_HEADERS,
        json={
            "last_rotated_at": None,
            "expires_at": None,
            "rotation_interval_days": None,
            "max_age_days": None,
            "expiry_warning_days": None,
        },
    )

    assert cleared.status_code == 200
    for field in (
        "last_rotated_at",
        "expires_at",
        "rotation_interval_days",
        "max_age_days",
        "expiry_warning_days",
    ):
        assert cleared.json()[field] is None


def test_credential_update_explicit_null_purges_legacy_secret_reference(source_client: TestClient) -> None:
    legacy = CredentialRefRecord(
        credential_ref_id="legacy-secret-reference",
        tenant_id="tenant-alpha",
        display_name="Legacy credential",
        provider="github",
        external_ref="ghp_" + "abcdefghijklmnopqrstuvwxyz1234567890",
        created_at="2026-08-27T00:00:00+00:00",
        updated_at="2026-08-27T00:00:00+00:00",
    )
    _stores._credential_ref_store.put(legacy)

    cleared = source_client.put(
        "/v1/credentials/legacy-secret-reference",
        headers=ANALYST_HEADERS,
        json={"external_ref": None},
    )

    assert cleared.status_code == 200
    assert cleared.json()["external_ref"] is None
    persisted = _stores._credential_ref_store.get("legacy-secret-reference", tenant_id="tenant-alpha")
    assert persisted is not None
    assert persisted.external_ref is None


def test_credential_retirement_purges_legacy_secret_reference_at_rest(source_client: TestClient) -> None:
    secret = "ghp_" + "abcdefghijklmnopqrstuvwxyz1234567890"
    legacy = CredentialRefRecord(
        credential_ref_id="legacy-secret-retire",
        tenant_id="tenant-alpha",
        display_name="Legacy credential",
        provider="github",
        external_ref=secret,
        created_at="2026-08-27T00:00:00+00:00",
        updated_at="2026-08-27T00:00:00+00:00",
    )
    _stores._credential_ref_store.put(legacy)

    retired = source_client.delete(
        "/v1/credentials/legacy-secret-retire",
        headers=ADMIN_HEADERS,
    )

    assert retired.status_code == 204
    persisted = _stores._credential_ref_store.get("legacy-secret-retire", tenant_id="tenant-alpha")
    assert persisted is not None
    assert persisted.status.value == "retired"
    assert persisted.external_ref is None
    fetched = source_client.get("/v1/credentials/legacy-secret-retire", headers=VIEWER_HEADERS)
    assert fetched.status_code == 200
    assert fetched.json()["external_ref"] is None
    assert secret not in fetched.text


@pytest.mark.parametrize("credential_store_backend", ["memory", "sqlite"])
def test_repeated_credential_retirement_purges_legacy_secret_reference_at_rest_and_audits_once(
    source_client: TestClient,
    credential_store_backend: str,
    tmp_path,
) -> None:
    from agent_bom.api.audit_log import InMemoryAuditLog, get_audit_log, set_audit_log
    from agent_bom.api.credential_store import SQLiteCredentialRefStore

    credential_store = (
        InMemoryCredentialRefStore()
        if credential_store_backend == "memory"
        else SQLiteCredentialRefStore(str(tmp_path / "credential-purge.db"))
    )
    _stores.set_credential_ref_store(credential_store)
    original_audit_log = get_audit_log()
    audit_log = InMemoryAuditLog()
    set_audit_log(audit_log)
    secret = "ghp_" + "abcdefghijklmnopqrstuvwxyz1234567890"
    legacy = CredentialRefRecord(
        credential_ref_id="legacy-secret-already-retired",
        tenant_id="tenant-alpha",
        display_name="Legacy retired credential",
        provider="github",
        external_ref=secret,
        enabled=False,
        status=CredentialRefStatus.RETIRED,
        created_at="2026-08-27T00:00:00+00:00",
        updated_at="2026-08-27T00:00:00+00:00",
    )
    credential_store.put(legacy)

    try:
        retired = source_client.delete(
            "/v1/credentials/legacy-secret-already-retired",
            headers=ADMIN_HEADERS,
        )
        repeated = source_client.delete(
            "/v1/credentials/legacy-secret-already-retired",
            headers=ADMIN_HEADERS,
        )

        assert retired.status_code == 204
        assert repeated.status_code == 204
        persisted = credential_store.get(
            "legacy-secret-already-retired",
            tenant_id="tenant-alpha",
        )
        assert persisted is not None
        assert persisted.status == CredentialRefStatus.RETIRED
        assert persisted.external_ref is None
        entries = audit_log.list_entries(
            action="credential_ref.retired_legacy_secret_purge",
            tenant_id="tenant-alpha",
        )
        assert len(entries) == 1
        assert entries[0].resource == "credential/legacy-secret-already-retired"
        assert entries[0].details == {
            "provider": "github",
            "tenant_id": "tenant-alpha",
        }
        assert secret not in json.dumps(entries[0].to_dict())
        assert (
            secret
            not in source_client.get(
                "/v1/credentials/legacy-secret-already-retired",
                headers=VIEWER_HEADERS,
            ).text
        )
    finally:
        set_audit_log(original_audit_log)


@pytest.mark.parametrize("depth", range(1, 7))
def test_credential_retirement_purges_nested_encoded_legacy_secret_at_rest(
    source_client: TestClient,
    depth: int,
) -> None:
    token, external_ref = _nested_encoded_github_ref(depth)
    credential_ref_id = f"legacy-nested-secret-{depth}"
    _stores._credential_ref_store.put(
        CredentialRefRecord(
            credential_ref_id=credential_ref_id,
            tenant_id="tenant-alpha",
            display_name="Legacy nested credential",
            provider="vault",
            external_ref=external_ref,
            created_at="2026-08-27T00:00:00+00:00",
            updated_at="2026-08-27T00:00:00+00:00",
        )
    )

    retired = source_client.delete(f"/v1/credentials/{credential_ref_id}", headers=ADMIN_HEADERS)

    assert retired.status_code == 204
    persisted = _stores._credential_ref_store.get(credential_ref_id, tenant_id="tenant-alpha")
    assert persisted is not None
    assert persisted.status.value == "retired"
    assert persisted.external_ref is None
    fetched = source_client.get(f"/v1/credentials/{credential_ref_id}", headers=VIEWER_HEADERS)
    assert fetched.status_code == 200
    assert token not in fetched.text
    assert external_ref not in fetched.text


def test_runnable_source_rejects_missing_or_metadata_only_credential_reference(source_client: TestClient) -> None:
    missing_ref = source_client.post(
        "/v1/sources",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "AWS source with missing credential",
            "kind": "scan.cloud",
            "credential_mode": "reference",
            "credential_ref": "missing-ref",
        },
    )
    assert missing_ref.status_code == 409

    credential = source_client.post(
        "/v1/credentials",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "AWS prod read-only role",
            "provider": "aws",
            "mode": "role_arn",
            "external_ref": "arn:aws:iam::123456789012:role/agent-bom-readonly",
        },
    )
    credential_ref_id = credential.json()["credential_ref_id"]

    create = source_client.post(
        "/v1/sources",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "AWS source",
            "kind": "scan.cloud",
            "credential_mode": " credential_ref ",
            "credential_ref": credential_ref_id,
            "config": {"scan_request": {"connectors": ["jira"], "format": "json"}},
        },
    )
    assert create.status_code == 409
    assert create.json()["detail"] == (
        "credential_ref is governance metadata and is not an executable credential binding; "
        "use a brokered cloud connection or server-configured connector credentials"
    )


def test_source_credential_mode_is_canonical_and_cannot_bypass_reference_validation(
    source_client: TestClient,
) -> None:
    aliased_reference = source_client.post(
        "/v1/sources",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "Legacy credential mode",
            "kind": "connector.cloud_read_only",
            "connector_name": "jira",
            "credential_mode": " credential_ref ",
        },
    )
    assert aliased_reference.status_code == 422
    assert aliased_reference.json()["detail"] == "credential_mode=reference requires credential_ref"

    unknown_mode = source_client.post(
        "/v1/sources",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "Unknown credential mode",
            "kind": "connector.cloud_read_only",
            "connector_name": "jira",
            "credential_mode": "secret_manager",
        },
    )
    assert unknown_mode.status_code == 422


def test_source_credential_reference_rejects_cross_tenant_attachment(source_client: TestClient) -> None:
    credential = source_client.post(
        "/v1/credentials",
        headers=OTHER_TENANT_ANALYST_HEADERS,
        json={
            "display_name": "Tenant beta producer",
            "provider": "generic",
            "external_ref": "workload-identity/tenant-beta",
            "tenant_id": "tenant-beta",
        },
    )
    assert credential.status_code == 201

    source = source_client.post(
        "/v1/sources",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "Tenant alpha trace producer",
            "kind": "ingest.trace_push",
            "credential_mode": "reference",
            "credential_ref": credential.json()["credential_ref_id"],
        },
    )
    assert source.status_code == 409
    assert source.json()["detail"] == "Source credential_ref is not available in this tenant"


def test_source_rejects_reference_mode_without_reference(source_client: TestClient) -> None:
    create = source_client.post(
        "/v1/sources",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "Jira source",
            "kind": "connector.registry",
            "connector_name": "jira",
            "credential_mode": "reference",
            "config": {"scan_request": {"format": "json"}},
        },
    )

    assert create.status_code == 422
    assert create.json()["detail"] == "credential_mode=reference requires credential_ref"


def test_push_source_may_retain_metadata_only_credential_reference(source_client: TestClient) -> None:
    credential = source_client.post(
        "/v1/credentials",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "Producer workload identity",
            "provider": "generic",
            "mode": "external_ref",
            "external_ref": "workload-identity/producer",
        },
    )
    credential_ref_id = credential.json()["credential_ref_id"]

    create = source_client.post(
        "/v1/sources",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "Trace producer",
            "kind": "ingest.trace_push",
            "credential_mode": " credential_ref ",
            "credential_ref": credential_ref_id,
        },
    )

    assert create.status_code == 201
    assert create.json()["credential_mode"] == "reference"
    assert create.json()["credential_ref"] == credential_ref_id

    referenced_delete = source_client.delete(f"/v1/credentials/{credential_ref_id}", headers=ADMIN_HEADERS)
    assert referenced_delete.status_code == 409
    assert referenced_delete.json()["detail"] == ("Credential reference is attached to 1 source; detach it before retiring the reference")

    source_id = create.json()["source_id"]
    cleared = source_client.put(
        f"/v1/sources/{source_id}",
        headers=ANALYST_HEADERS,
        json={"credential_mode": "none", "credential_ref": None},
    )
    assert cleared.status_code == 200
    assert cleared.json()["credential_mode"] == "none"
    assert cleared.json()["credential_ref"] is None

    retired = source_client.delete(f"/v1/credentials/{credential_ref_id}", headers=ADMIN_HEADERS)
    assert retired.status_code == 204
    credential_after_retire = source_client.get(f"/v1/credentials/{credential_ref_id}", headers=VIEWER_HEADERS)
    assert credential_after_retire.status_code == 200
    assert credential_after_retire.json()["status"] == "retired"


def test_credential_retire_serializes_with_source_attachment(source_client: TestClient) -> None:
    created = source_client.post(
        "/v1/credentials",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "Producer workload",
            "provider": "github",
            "external_ref": "workload-identity/producer",
        },
    )
    credential_ref_id = created.json()["credential_ref_id"]
    base_store = _stores._credential_ref_store
    retirement_reached_put = Event()
    release_retirement = Event()

    class BlockingCredentialStore:
        def put(self, credential):
            if credential.status.value == "retired":
                retirement_reached_put.set()
                assert release_retirement.wait(timeout=5)
            return base_store.put(credential)

        def get(self, credential_ref_id, *, tenant_id):
            credential = base_store.get(credential_ref_id, tenant_id=tenant_id)
            return credential.model_copy(deep=True) if credential is not None else None

        def delete(self, credential_ref_id, *, tenant_id):
            return base_store.delete(credential_ref_id, tenant_id=tenant_id)

        def list_all(self, tenant_id=None):
            return base_store.list_all(tenant_id=tenant_id)

    _stores.set_credential_ref_store(BlockingCredentialStore())
    responses: dict[str, Any] = {}

    def retire() -> None:
        responses["retire"] = source_client.delete(
            f"/v1/credentials/{credential_ref_id}",
            headers=ADMIN_HEADERS,
        )

    def attach() -> None:
        responses["attach"] = source_client.post(
            "/v1/sources",
            headers=ANALYST_HEADERS,
            json={
                "display_name": "Result producer",
                "kind": "ingest.result_push",
                "credential_mode": "reference",
                "credential_ref": credential_ref_id,
            },
        )

    retire_thread = Thread(target=retire)
    attach_thread = Thread(target=attach)
    retire_thread.start()
    assert retirement_reached_put.wait(timeout=5)
    attach_thread.start()
    attach_thread.join(timeout=0.2)
    attachment_waited = attach_thread.is_alive()
    release_retirement.set()
    retire_thread.join(timeout=5)
    attach_thread.join(timeout=5)

    assert attachment_waited, "attachment must wait for the retirement decision"
    assert responses["retire"].status_code == 204
    assert responses["attach"].status_code == 409
    assert source_client.get("/v1/sources", headers=VIEWER_HEADERS).json()["count"] == 0


def test_legacy_runnable_source_can_clear_reference_before_test_and_run(
    source_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credential = source_client.post(
        "/v1/credentials",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "Legacy Jira credential",
            "provider": "jira",
            "external_ref": "vault/jira/legacy",
        },
    )
    credential_ref_id = credential.json()["credential_ref_id"]
    legacy = SourceRecord(
        source_id="legacy-jira-source",
        tenant_id="tenant-alpha",
        display_name="Legacy Jira source",
        kind=SourceKind.CONNECTOR_CLOUD_READ_ONLY,
        connector_name="jira",
        credential_mode="credential_ref",
        credential_ref=credential_ref_id,
    )
    _stores._source_store.put(legacy)

    blocked_test = source_client.post(f"/v1/sources/{legacy.source_id}/test", headers=ANALYST_HEADERS)
    blocked_run = source_client.post(f"/v1/sources/{legacy.source_id}/run", headers=ANALYST_HEADERS)
    assert blocked_test.status_code == 409
    assert blocked_run.status_code == 409

    cleared = source_client.put(
        f"/v1/sources/{legacy.source_id}",
        headers=ANALYST_HEADERS,
        json={"credential_mode": "none", "credential_ref": None, "description": None},
    )
    assert cleared.status_code == 200
    assert cleared.json()["credential_ref"] is None
    assert cleared.json()["description"] == ""

    monkeypatch.setattr(
        "agent_bom.connectors.check_connector_health",
        lambda connector_name: ConnectorStatus(
            connector=connector_name,
            state=ConnectorHealthState.HEALTHY,
            message="Connector can authenticate",
            api_version=None,
        ),
    )
    assert source_client.post(f"/v1/sources/{legacy.source_id}/test", headers=ANALYST_HEADERS).status_code == 200
    monkeypatch.setattr(
        "agent_bom.api.routes.sources.enqueue_scan_job",
        lambda **kwargs: ScanJob(
            job_id="legacy-source-job",
            tenant_id=kwargs["tenant_id"],
            source_id=kwargs["source_id"],
            triggered_by=kwargs["triggered_by"],
            created_at="2026-08-27T00:00:00+00:00",
            request=kwargs["request_body"],
        ),
    )
    assert source_client.post(f"/v1/sources/{legacy.source_id}/run", headers=ANALYST_HEADERS).status_code == 202


def test_connector_source_test_updates_health(source_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "agent_bom.connectors.check_connector_health",
        lambda connector_name: ConnectorStatus(
            connector=connector_name,
            state=ConnectorHealthState.HEALTHY,
            message="Connector can authenticate",
            api_version="2026-04",
        ),
    )

    create = source_client.post(
        "/v1/sources",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "Snowflake lake",
            "kind": "connector.warehouse",
            "connector_name": "slack",
            "credential_mode": "none",
        },
    )
    source_id = create.json()["source_id"]

    tested = source_client.post(f"/v1/sources/{source_id}/test", headers=ANALYST_HEADERS)
    assert tested.status_code == 200
    tested_body = tested.json()
    assert tested_body["status"] == "healthy"
    assert tested_body["message"] == "Connector can authenticate"

    fetched = source_client.get(f"/v1/sources/{source_id}", headers=VIEWER_HEADERS)
    assert fetched.status_code == 200
    fetched_body = fetched.json()
    assert fetched_body["last_test_status"] == "healthy"
    assert fetched_body["status"] == "healthy"


def test_connector_source_health_runs_outside_the_api_event_loop(
    source_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sync connector adapters may call asyncio.run and must therefore be off-loop."""
    created = source_client.post(
        "/v1/sources",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "Jira async bridge",
            "kind": "connector.registry",
            "connector_name": "jira",
        },
    )
    source_id = created.json()["source_id"]

    def _health(connector_name: str) -> ConnectorStatus:
        asyncio.run(asyncio.sleep(0))
        return ConnectorStatus(connector=connector_name, state=ConnectorHealthState.HEALTHY, message="Connected")

    monkeypatch.setattr("agent_bom.connectors.check_connector_health", _health)
    tested = source_client.post(f"/v1/sources/{source_id}/test", headers=ANALYST_HEADERS)

    assert tested.status_code == 200
    assert tested.json()["status"] == "healthy"


def test_connector_source_test_sanitizes_health_message_before_response_and_persistence(
    source_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created = source_client.post(
        "/v1/sources",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "Jira source",
            "kind": "connector.cloud_read_only",
            "connector_name": "jira",
            "credential_mode": "none",
        },
    )
    source_id = created.json()["source_id"]
    leaked = "postgresql://operator:secret-token@db.example/app"
    monkeypatch.setattr(
        "agent_bom.connectors.check_connector_health",
        lambda _connector_name: ConnectorStatus(
            connector="jira",
            state=ConnectorHealthState.UNREACHABLE,
            message=leaked,
            api_version=None,
        ),
    )

    tested = source_client.post(f"/v1/sources/{source_id}/test", headers=ANALYST_HEADERS)
    fetched = source_client.get(f"/v1/sources/{source_id}", headers=VIEWER_HEADERS)

    assert tested.status_code == 200
    assert leaked not in tested.text
    assert "secret-token" not in tested.text
    assert leaked not in fetched.text
    assert "secret-token" not in fetched.text


def test_source_test_cannot_resurrect_source_deleted_during_health_probe(
    source_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created = source_client.post(
        "/v1/sources",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "Jira health race",
            "kind": "connector.registry",
            "connector_name": "jira",
        },
    )
    source_id = created.json()["source_id"]
    health_started = Event()
    release_health = Event()
    outcomes: dict[str, Any] = {}
    from agent_bom.api.routes import sources as source_routes

    request = SimpleNamespace(state=SimpleNamespace(tenant_id="tenant-alpha", api_key_name="replica"))

    def _blocking_health(connector_name):
        health_started.set()
        assert release_health.wait(timeout=5)
        return ConnectorStatus(
            connector=connector_name,
            state=ConnectorHealthState.HEALTHY,
            message="Connected",
        )

    def _test_source() -> None:
        try:
            outcomes["test"] = asyncio.run(source_routes.test_source(request, source_id))
        except HTTPException as exc:
            outcomes["test_error"] = exc

    monkeypatch.setattr("agent_bom.connectors.check_connector_health", _blocking_health)
    test_thread = Thread(target=_test_source)
    test_thread.start()
    assert health_started.wait(timeout=5)
    asyncio.run(source_routes.delete_source(request, source_id))
    release_health.set()
    test_thread.join(timeout=5)

    assert outcomes["test_error"].status_code == 404
    assert _stores._source_store.get(source_id) is None


def test_source_run_cannot_enqueue_or_resurrect_after_concurrent_delete(
    source_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created = source_client.post(
        "/v1/sources",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "Repository run race",
            "kind": "scan.repo",
            "config": {"scan_request": {"repo_url": "https://example.com/acme/repo"}},
        },
    )
    source_id = created.json()["source_id"]
    request_started = Event()
    release_request = Event()
    outcomes: dict[str, Any] = {}
    enqueued: list[str] = []
    from agent_bom.api.routes import sources as source_routes

    request = SimpleNamespace(state=SimpleNamespace(tenant_id="tenant-alpha", api_key_name="replica"))
    original_request = source_routes._request_for_source
    first_call = True

    def _blocking_request(source):
        nonlocal first_call
        request_body = original_request(source)
        if first_call:
            first_call = False
            request_started.set()
            assert release_request.wait(timeout=5)
        return request_body

    def _fake_enqueue(**kwargs):
        enqueued.append(kwargs["source_id"])
        return ScanJob(
            job_id="stale-run-job",
            tenant_id=kwargs["tenant_id"],
            source_id=kwargs["source_id"],
            triggered_by=kwargs["triggered_by"],
            created_at="2026-08-27T00:00:00+00:00",
            request=kwargs["request_body"],
        )

    def _run_source() -> None:
        try:
            outcomes["run"] = asyncio.run(source_routes.run_source(request, source_id))
        except HTTPException as exc:
            outcomes["run_error"] = exc

    monkeypatch.setattr(source_routes, "_request_for_source", _blocking_request)
    monkeypatch.setattr(source_routes, "enqueue_scan_job", _fake_enqueue)
    run_thread = Thread(target=_run_source)
    run_thread.start()
    assert request_started.wait(timeout=5)
    asyncio.run(source_routes.delete_source(request, source_id))
    release_request.set()
    run_thread.join(timeout=5)

    assert outcomes["run_error"].status_code == 404
    assert enqueued == []
    assert _stores._source_store.get(source_id) is None


def test_source_delete_removes_linked_schedules_for_same_tenant_only(source_client: TestClient) -> None:
    created = source_client.post(
        "/v1/sources",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "Scheduled repo",
            "kind": "scan.repo",
            "config": {"scan_request": {"repo_url": "https://example.com/acme/repo"}},
        },
    )
    source_id = created.json()["source_id"]
    _stores._schedule_store.put(
        ScanSchedule(
            schedule_id="source-schedule",
            tenant_id="tenant-alpha",
            name="Scheduled repo recurring run",
            cron_expression="0 * * * *",
            scan_config={"source_id": source_id},
            enabled=True,
            next_run="2026-08-27T00:00:00+00:00",
        )
    )
    _stores._schedule_store.put(
        ScanSchedule(
            schedule_id="other-tenant-schedule",
            tenant_id="tenant-beta",
            name="Other tenant",
            cron_expression="0 * * * *",
            scan_config={"source_id": source_id},
            enabled=True,
            next_run="2026-08-27T00:00:00+00:00",
        )
    )

    deleted = source_client.delete(f"/v1/sources/{source_id}", headers=ADMIN_HEADERS)

    assert deleted.status_code == 204
    assert _stores._schedule_store.get("source-schedule", tenant_id="tenant-alpha") is None
    assert _stores._schedule_store.get("other-tenant-schedule", tenant_id="tenant-beta") is not None


def test_viewer_cannot_test_or_run_sources(source_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    def _must_not_check_connector_health(connector_name: str):
        raise AssertionError("viewer must not reach connector health checks")

    def _must_not_enqueue_scan_job(**kwargs):
        raise AssertionError("viewer must not enqueue source scans")

    monkeypatch.setattr("agent_bom.connectors.check_connector_health", _must_not_check_connector_health)
    monkeypatch.setattr("agent_bom.api.routes.sources.enqueue_scan_job", _must_not_enqueue_scan_job)

    created = source_client.post(
        "/v1/sources",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "Repo scan source",
            "kind": "scan.repo",
            "config": {"scan_request": {"repo_url": "https://github.com/example/repo", "format": "json"}},
        },
    )
    source_id = created.json()["source_id"]

    test_resp = source_client.post(f"/v1/sources/{source_id}/test", headers=VIEWER_HEADERS)
    run_resp = source_client.post(f"/v1/sources/{source_id}/run", headers=VIEWER_HEADERS)

    assert test_resp.status_code == 403
    assert run_resp.status_code == 403


def test_running_source_queues_source_linked_job(source_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.api.models import ScanJob
    from agent_bom.api.stores import _get_store, _jobs_put

    def _fake_enqueue(
        *,
        tenant_id: str,
        triggered_by: str,
        request_body,
        source_id: str | None = None,
        quota_guarded: bool = False,
    ) -> ScanJob:
        assert quota_guarded is True
        job = ScanJob(
            job_id="job-source-1",
            tenant_id=tenant_id,
            source_id=source_id,
            triggered_by=triggered_by,
            created_at="2026-04-20T00:00:00+00:00",
            request=request_body,
        )
        _get_store().put(job)
        _jobs_put(job.job_id, job)
        return job

    monkeypatch.setattr("agent_bom.api.routes.sources.enqueue_scan_job", _fake_enqueue)

    created = source_client.post(
        "/v1/sources",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "Repo scan source",
            "kind": "scan.repo",
            "config": {"scan_request": {"repo_url": "https://github.com/example/repo", "format": "json"}},
        },
    )
    source_id = created.json()["source_id"]

    run = source_client.post(f"/v1/sources/{source_id}/run", headers=ANALYST_HEADERS)
    assert run.status_code == 202
    run_body = run.json()
    assert run_body["source_id"] == source_id
    assert run_body["status"] == "pending"

    job = _stores._store.get(run_body["job_id"], tenant_id="tenant-alpha")
    assert job is not None
    assert job.request.repo_url == "https://github.com/example/repo"

    source = source_client.get(f"/v1/sources/{source_id}", headers=VIEWER_HEADERS).json()
    assert source["last_job_id"] == run_body["job_id"]
    assert source["last_run_status"] == "pending"

    jobs = source_client.get(f"/v1/sources/{source_id}/jobs", headers=VIEWER_HEADERS)
    assert jobs.status_code == 200
    jobs_body = jobs.json()
    assert jobs_body["count"] == 1
    assert jobs_body["jobs"][0]["job_id"] == run_body["job_id"]
    assert jobs_body["jobs"][0]["source_id"] == source_id


def test_source_run_rejects_unknown_scan_request_fields(source_client: TestClient) -> None:
    response = source_client.post(
        "/v1/sources",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "Typoed repo source",
            "kind": "scan.repo",
            "config": {"scan_request": {"project_path": "."}},
        },
    )
    assert response.status_code == 422
    body = response.json()
    assert "project_path" in str(body)
    assert "extra_forbidden" in str(body)


def test_push_and_runtime_sources_reject_run_now(source_client: TestClient) -> None:
    for kind in ("ingest.trace_push", "runtime.gateway"):
        created = source_client.post(
            "/v1/sources",
            headers=ANALYST_HEADERS,
            json={
                "display_name": f"Source for {kind}",
                "kind": kind,
            },
        )
        source_id = created.json()["source_id"]
        resp = source_client.post(f"/v1/sources/{source_id}/run", headers=ANALYST_HEADERS)
        assert resp.status_code == 409
