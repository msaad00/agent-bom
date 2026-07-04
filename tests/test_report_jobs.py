"""Tests for async findings report export jobs."""

from __future__ import annotations

import gzip
import json
import time
from pathlib import Path
from uuid import uuid4

import pytest
from starlette.testclient import TestClient

from agent_bom.api.compliance_hub_store import SQLiteComplianceHubStore, reset_compliance_hub_store, set_compliance_hub_store
from agent_bom.api.report_job_store import reset_report_job_store
from agent_bom.api.report_worker import _run_report_job_sync
from agent_bom.api.server import app
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers


@pytest.fixture(autouse=True)
def _reset_stores():
    reset_compliance_hub_store()
    reset_report_job_store()
    yield
    reset_compliance_hub_store()
    reset_report_job_store()


@pytest.fixture(scope="module", autouse=True)
def _trusted_proxy_env():
    enable_trusted_proxy_env()
    yield
    disable_trusted_proxy_env()


def _client(tenant: str = "tenant-alpha") -> TestClient:
    client = TestClient(app)
    client.headers.update(proxy_headers(role="analyst", tenant=tenant))
    return client


def _seed_hub(tmp_path: Path, tenant_id: str, count: int = 3) -> None:
    store = SQLiteComplianceHubStore(str(tmp_path / "hub.db"))
    set_compliance_hub_store(store)
    observed_at = "2026-07-04T00:00:00Z"
    for idx in range(count):
        store.upsert_current_batch(
            tenant_id,
            [
                {
                    "id": f"{tenant_id}:finding-{idx}",
                    "canonical_id": f"{tenant_id}:finding-{idx}",
                    "title": f"Finding {idx}",
                    "severity": "high",
                    "effective_reach_score": float(count - idx),
                }
            ],
            observed_at=observed_at,
            batch_id=f"batch-{idx}",
            source="test",
        )


def test_report_job_streams_findings_to_gzip_artifact(monkeypatch, tmp_path: Path) -> None:
    tenant_id = f"report-{uuid4().hex}"
    monkeypatch.setenv("AGENT_BOM_REPORT_ARTIFACT_DIR", str(tmp_path))
    monkeypatch.setattr("agent_bom.api.routes.reports.submit_report_job", _run_report_job_sync)
    _seed_hub(tmp_path, tenant_id, count=4)
    client = _client(tenant=tenant_id)

    created = client.post("/v1/reports", json={"format": "ndjson", "sort": "effective_reach"})
    assert created.status_code == 202, created.text
    job_id = created.json()["job_id"]

    deadline = time.time() + 5
    body = {}
    while time.time() < deadline:
        polled = client.get(f"/v1/reports/{job_id}")
        assert polled.status_code == 200
        body = polled.json()
        if body["status"] == "done":
            break
        time.sleep(0.05)
    assert body["status"] == "done"
    assert body["row_count"] == 4
    assert body["byte_count"] > 0
    assert "download_url" in body

    download_url = body["download_url"]
    assert "/download?token=" in download_url
    downloaded = client.get(download_url)
    assert downloaded.status_code == 200
    rows = [json.loads(line) for line in gzip.decompress(downloaded.content).decode().splitlines() if line.strip()]
    assert len(rows) == 4
    assert rows[0]["canonical_id"] == f"{tenant_id}:finding-0"
    assert rows[-1]["id"] == f"{tenant_id}:finding-3"


def test_report_job_is_tenant_scoped(tmp_path: Path) -> None:
    tenant_a = f"report-a-{uuid4().hex}"
    tenant_b = f"report-b-{uuid4().hex}"
    _seed_hub(tmp_path, tenant_a, count=1)
    client_a = _client(tenant=tenant_a)
    client_b = _client(tenant=tenant_b)

    created = client_a.post("/v1/reports", json={})
    assert created.status_code == 202
    job_id = created.json()["job_id"]
    assert client_b.get(f"/v1/reports/{job_id}").status_code == 404
