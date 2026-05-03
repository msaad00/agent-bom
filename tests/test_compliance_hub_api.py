"""Tests for the Compliance Hub API endpoints (#1044 PR C).

Covers:
- POST /v1/compliance/ingest (SARIF / CycloneDX / CSV / JSON)
- GET /v1/compliance/hub/findings
- GET /v1/compliance/hub/posture
- DELETE /v1/compliance/hub/findings
- Tenant isolation: tenant A's hub findings must never appear for tenant B

The store is process-wide and in-memory (PR C scope), so tests reset it
between cases to avoid cross-test bleed.
"""

from __future__ import annotations

import json

import pytest
from starlette.testclient import TestClient

from agent_bom.api.compliance_hub_store import reset_compliance_hub_store
from agent_bom.api.server import app
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()


@pytest.fixture(autouse=True)
def _reset_store():
    reset_compliance_hub_store()
    yield
    reset_compliance_hub_store()


def _client(tenant: str = "tenant-alpha", role: str = "admin") -> TestClient:
    client = TestClient(app)
    client.headers.update(proxy_headers(role=role, tenant=tenant))
    return client


def _sarif_doc() -> dict:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "external-secrets",
                        "rules": [
                            {
                                "id": "SECRET-AWS-ACCESS-KEY",
                                "shortDescription": {"text": "AWS access key"},
                                "properties": {"tags": ["secret", "CWE-798"]},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "SECRET-AWS-ACCESS-KEY",
                        "level": "error",
                        "message": {"text": "Hardcoded AWS access key"},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/cfg.py"}}}],
                        "properties": {"security-severity": "9.5"},
                    }
                ],
            }
        ],
    }


# ─── POST /v1/compliance/ingest ──────────────────────────────────────────────


def test_ingest_sarif_returns_count_plus_framework_breakdown():
    resp = _client().post(
        "/v1/compliance/ingest",
        json={"format": "sarif", "content": json.dumps(_sarif_doc())},
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["ingested"] == 1
    assert body["tenant_total"] == 1
    assert body["format"] == "sarif"
    # SECRET rule -> CREDENTIAL_EXPOSURE -> hub adds enterprise audit frameworks
    assert "soc2" in body["framework_hits"]
    assert "iso-27001" in body["framework_hits"]
    assert "nist-csf" in body["framework_hits"]


def test_ingest_invalid_format_returns_400():
    resp = _client().post(
        "/v1/compliance/ingest",
        json={"format": "xml", "content": "<x/>"},
    )
    assert resp.status_code == 400


def test_ingest_empty_content_returns_400():
    resp = _client().post(
        "/v1/compliance/ingest",
        json={"format": "sarif", "content": ""},
    )
    assert resp.status_code == 400


def test_ingest_unparseable_sarif_returns_422():
    resp = _client().post(
        "/v1/compliance/ingest",
        json={"format": "sarif", "content": json.dumps({"version": "2.1.0", "runs": []})},
    )
    assert resp.status_code == 422


def test_ingest_csv_classifies_cve_rows():
    csv = "Title,Severity,CVE\nlodash CVE,High,CVE-2021-23337\n"
    resp = _client().post(
        "/v1/compliance/ingest",
        json={"format": "csv", "content": csv},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["ingested"] == 1


# ─── GET /v1/compliance/hub/findings ─────────────────────────────────────────


def test_list_hub_findings_returns_what_we_ingested():
    client = _client()
    client.post(
        "/v1/compliance/ingest",
        json={"format": "sarif", "content": json.dumps(_sarif_doc())},
    )
    resp = client.get("/v1/compliance/hub/findings")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["count"] == 1
    assert body["findings"][0]["source"] == "EXTERNAL"


def test_list_hub_findings_pagination():
    client = _client()
    csv_rows = "Title,Severity\n" + "\n".join(f"row-{i},low" for i in range(50))
    client.post("/v1/compliance/ingest", json={"format": "csv", "content": csv_rows})

    resp = client.get("/v1/compliance/hub/findings?limit=10&offset=20")
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 10
    assert body["total"] == 50
    assert body["offset"] == 20


# ─── Tenant isolation ────────────────────────────────────────────────────────


def test_hub_findings_are_tenant_scoped():
    """Tenant A's ingest must not appear under tenant B's hub findings."""
    a = _client(tenant="tenant-alpha")
    b = _client(tenant="tenant-beta")

    a.post("/v1/compliance/ingest", json={"format": "sarif", "content": json.dumps(_sarif_doc())})

    a_list = a.get("/v1/compliance/hub/findings").json()
    b_list = b.get("/v1/compliance/hub/findings").json()

    assert a_list["total"] == 1
    assert b_list["total"] == 0


# ─── GET /v1/compliance/hub/posture ──────────────────────────────────────────


def test_hub_posture_aggregates_hub_findings_per_framework():
    client = _client()
    client.post(
        "/v1/compliance/ingest",
        json={"format": "sarif", "content": json.dumps(_sarif_doc())},
    )

    resp = client.get("/v1/compliance/hub/posture")
    assert resp.status_code == 200
    body = resp.json()

    assert body["totals"]["hub"] == 1
    assert body["totals"]["combined"] >= 1
    # SECRET rule -> CREDENTIAL_EXPOSURE adds SOC 2
    assert body["framework_counts"]["hub"].get("soc2", 0) >= 1
    assert body["hub_severity_breakdown"]["critical"] == 1


def test_hub_posture_with_no_findings_returns_zeros():
    body = _client().get("/v1/compliance/hub/posture").json()
    assert body["totals"]["hub"] == 0
    assert body["framework_counts"]["hub"] == {}


# ─── DELETE /v1/compliance/hub/findings ──────────────────────────────────────


def test_clear_hub_findings_resets_store_for_tenant():
    client = _client()
    client.post(
        "/v1/compliance/ingest",
        json={"format": "sarif", "content": json.dumps(_sarif_doc())},
    )
    delete = client.delete("/v1/compliance/hub/findings")
    assert delete.status_code == 200
    assert delete.json()["removed"] == 1

    after = client.get("/v1/compliance/hub/findings").json()
    assert after["total"] == 0


def test_clear_hub_findings_does_not_affect_other_tenant():
    a = _client(tenant="tenant-alpha")
    b = _client(tenant="tenant-beta")
    a.post("/v1/compliance/ingest", json={"format": "sarif", "content": json.dumps(_sarif_doc())})
    b.post("/v1/compliance/ingest", json={"format": "sarif", "content": json.dumps(_sarif_doc())})

    a.delete("/v1/compliance/hub/findings")

    assert a.get("/v1/compliance/hub/findings").json()["total"] == 0
    assert b.get("/v1/compliance/hub/findings").json()["total"] == 1


def test_clear_requires_write_permission():
    """Read-only role cannot clear the hub store."""
    reader = TestClient(app)
    reader.headers.update(proxy_headers(role="viewer", tenant="tenant-alpha"))
    resp = reader.delete("/v1/compliance/hub/findings")
    assert resp.status_code in (401, 403), f"viewer should be denied (got {resp.status_code})"
