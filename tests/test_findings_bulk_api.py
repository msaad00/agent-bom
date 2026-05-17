"""Tests for normalized bulk finding ingest."""

from __future__ import annotations

from starlette.testclient import TestClient

from agent_bom.api.compliance_hub_store import reset_compliance_hub_store
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
    client = _client()

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
    assert body["tenant_id"] == "tenant-alpha"
    assert body["source"] == "agent-runtime"
    assert body["warnings"] == ["tenant_id in body ignored; request tenant scope is authoritative"]
    assert body["batch_id"]


def test_bulk_findings_are_listed_and_tenant_scoped() -> None:
    tenant_a = _client(tenant="tenant-alpha")
    tenant_b = _client(tenant="tenant-beta")

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


def test_bulk_findings_rejects_empty_batches() -> None:
    resp = _client().post("/v1/findings/bulk", json={"findings": []})

    assert resp.status_code == 422


def test_bulk_findings_requires_analyst_role() -> None:
    resp = _client(role="viewer").post(
        "/v1/findings/bulk",
        json={"findings": [{"id": "viewer-finding", "severity": "low"}]},
    )

    assert resp.status_code == 403
