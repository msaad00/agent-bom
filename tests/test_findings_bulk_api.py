"""Tests for normalized bulk finding ingest."""

from __future__ import annotations

import sqlite3
from uuid import uuid4

from starlette.testclient import TestClient

from agent_bom.api.compliance_hub_store import SQLiteComplianceHubStore, reset_compliance_hub_store
from agent_bom.api.server import app
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()


def setup_function() -> None:
    reset_compliance_hub_store()


def teardown_function() -> None:
    reset_compliance_hub_store()


def _client(tenant: str = "tenant-alpha", role: str = "analyst") -> TestClient:
    client = TestClient(app)
    client.headers.update(proxy_headers(role=role, tenant=tenant))
    return client


def test_bulk_findings_ingest_returns_agent_native_envelope() -> None:
    tenant_id = f"bulk-ingest-{uuid4().hex}"
    client = _client(tenant=tenant_id)

    resp = client.post(
        "/v1/findings/bulk",
        json={
            "source": "agent-runtime",
            "schema_version": "v1",
            "tenant_id": "tenant-beta",
            "findings": [
                {
                    "id": "agent-runtime:finding-1",
                    "title": "Tool can reach production secret",
                    "severity": "high",
                    "applicable_frameworks": ["soc2", "iso-27001"],
                    "evidence": {"summary": "safe tier-A evidence"},
                }
            ],
        },
    )

    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["schema_version"] == "v1"
    assert body["ingested"] == 1
    assert body["tenant_total"] == 1
    assert body["tenant_id"] == tenant_id
    assert body["source"] == "agent-runtime"
    assert body["warnings"] == ["tenant_id in body ignored; request tenant scope is authoritative"]
    assert body["batch_id"]


def test_bulk_findings_are_listed_and_tenant_scoped() -> None:
    tenant_a_id = f"bulk-list-a-{uuid4().hex}"
    tenant_b_id = f"bulk-list-b-{uuid4().hex}"
    tenant_a = _client(tenant=tenant_a_id)
    tenant_b = _client(tenant=tenant_b_id)

    created = tenant_a.post(
        "/v1/findings/bulk",
        json={
            "source": "external-agent",
            "findings": [
                {
                    "id": "finding-alpha",
                    "title": "Reachable risky MCP tool",
                    "severity": "critical",
                    "cvss_score": 9.8,
                }
            ],
        },
    )
    assert created.status_code == 201, created.text

    listed_a = tenant_a.get("/v1/findings").json()
    listed_b = tenant_b.get("/v1/findings").json()

    assert listed_a["total"] == 1
    finding = listed_a["findings"][0]
    assert finding["id"] == "finding-alpha"
    assert finding["origin"] == "bulk_ingest"
    assert finding["source"] == "external-agent"
    assert finding["batch_id"] == created.json()["batch_id"]
    assert listed_b["total"] == 0


def test_bulk_findings_list_paginates_and_reports_total() -> None:
    tenant_id = f"bulk-page-{uuid4().hex}"
    client = _client(tenant=tenant_id)

    created = client.post(
        "/v1/findings/bulk",
        json={
            "source": "external-agent",
            "findings": [
                {
                    "id": f"finding-{i:04d}",
                    "severity": "high",
                    "cvss_score": 5.0,
                    "effective_reach_score": float(i),
                }
                for i in range(120)
            ],
        },
    )
    assert created.status_code == 201, created.text

    listed = client.get("/v1/findings", params={"limit": 10, "offset": 0}).json()
    assert listed["total"] == 120
    assert listed["count"] == 10
    assert len(listed["findings"]) == 10
    # Default sort is effective_reach DESC — highest reach seeded is 119.
    assert listed["findings"][0]["id"] == "finding-0119"

    # A deep page still returns the correct slice + total.
    page2 = client.get("/v1/findings", params={"limit": 10, "offset": 10}).json()
    assert page2["total"] == 120
    first_ids = {f["id"] for f in listed["findings"]}
    second_ids = {f["id"] for f in page2["findings"]}
    assert not (first_ids & second_ids)


def test_bulk_findings_rejects_empty_batches() -> None:
    resp = _client().post("/v1/findings/bulk", json={"findings": []})

    assert resp.status_code == 422


def test_bulk_findings_requires_analyst_role() -> None:
    resp = _client(role="viewer").post(
        "/v1/findings/bulk",
        json={"findings": [{"id": "viewer-finding", "severity": "low"}]},
    )

    assert resp.status_code == 403


def test_sqlite_store_replaces_pre_origin_scale_index(tmp_path) -> None:
    """Existing SQLite DBs must not keep the pre-origin read-scale index.

    ``CREATE INDEX IF NOT EXISTS`` does not update index definitions, so a
    migrated DB with ``idx_hub_findings_tenant_reach`` would otherwise keep
    scanning every tenant row for ``origin='bulk_ingest'``.
    """
    db_path = tmp_path / "hub.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE compliance_hub_findings (
                tenant_id TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                ingested_at TEXT NOT NULL,
                source TEXT NOT NULL,
                applicable_frameworks_csv TEXT NOT NULL DEFAULT '',
                payload TEXT NOT NULL,
                ordinal INTEGER NOT NULL,
                effective_reach_score REAL NOT NULL DEFAULT 0,
                origin TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (tenant_id, finding_id, ordinal)
            )
            """
        )
        conn.execute(
            "CREATE INDEX idx_hub_findings_tenant_reach ON compliance_hub_findings(tenant_id, effective_reach_score DESC, ordinal)"
        )

    SQLiteComplianceHubStore(str(db_path))

    with sqlite3.connect(db_path) as conn:
        indexes = {
            row[0]: row[1]
            for row in conn.execute("SELECT name, sql FROM sqlite_master WHERE type = 'index' AND tbl_name = 'compliance_hub_findings'")
        }

    assert "idx_hub_findings_tenant_reach" not in indexes
    assert "idx_hub_findings_tenant_origin_reach" in indexes
    assert "tenant_id, origin, effective_reach_score DESC, ordinal" in indexes["idx_hub_findings_tenant_origin_reach"]
