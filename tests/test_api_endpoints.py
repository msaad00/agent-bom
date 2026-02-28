"""Tests for core REST API endpoints — health, version, scan CRUD, middleware headers."""

from __future__ import annotations

import uuid

from starlette.testclient import TestClient

from agent_bom import __version__
from agent_bom.api.server import _jobs, app, set_job_store
from agent_bom.api.store import InMemoryJobStore

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _fresh_client():
    """Return a clean TestClient + InMemoryJobStore with no leftover state."""
    store = InMemoryJobStore()
    set_job_store(store)
    _jobs.clear()
    return TestClient(app, raise_server_exceptions=False), store


# ---------------------------------------------------------------------------
# 1. Health endpoint
# ---------------------------------------------------------------------------


def test_health_endpoint():
    """GET /health returns 200 with status='ok'."""
    client, _ = _fresh_client()
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert "version" in body


# ---------------------------------------------------------------------------
# 2. Version endpoint
# ---------------------------------------------------------------------------


def test_version_endpoint():
    """GET /version returns 200 with version, api_version, python_package."""
    client, _ = _fresh_client()
    resp = client.get("/version")
    assert resp.status_code == 200
    body = resp.json()
    assert body["version"] == __version__
    assert body["api_version"] == "v1"
    assert body["python_package"] == "agent-bom"


# ---------------------------------------------------------------------------
# 3. Root redirect
# ---------------------------------------------------------------------------


def test_root_redirects():
    """GET / returns a 307 redirect (RedirectResponse default for TestClient)."""
    client, _ = _fresh_client()
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code == 307
    assert "/docs" in resp.headers.get("location", "")


# ---------------------------------------------------------------------------
# 4. Create scan — 202
# ---------------------------------------------------------------------------


def test_create_scan_returns_202():
    """POST /v1/scan with empty body returns 202 Accepted."""
    client, _ = _fresh_client()
    resp = client.post("/v1/scan", json={})
    assert resp.status_code == 202
    body = resp.json()
    assert "job_id" in body
    # Background thread may mutate the shared job object before serialisation,
    # so the status can be either "pending" or "running" by the time we read it.
    assert body["status"] in ("pending", "running")


# ---------------------------------------------------------------------------
# 5. Create scan with options
# ---------------------------------------------------------------------------


def test_create_scan_with_options():
    """POST /v1/scan with inventory/enrich fields returns a proper job."""
    client, _ = _fresh_client()
    resp = client.post(
        "/v1/scan",
        json={
            "inventory": "/tmp/agents.json",
            "enrich": True,
            "format": "cyclonedx",
        },
    )
    assert resp.status_code == 202
    body = resp.json()
    assert body["request"]["inventory"] == "/tmp/agents.json"
    assert body["request"]["enrich"] is True
    assert body["request"]["format"] == "cyclonedx"


# ---------------------------------------------------------------------------
# 6. GET scan — not found
# ---------------------------------------------------------------------------


def test_get_scan_not_found():
    """GET /v1/scan/nonexistent returns 404."""
    client, _ = _fresh_client()
    resp = client.get("/v1/scan/nonexistent")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 7. GET scan after create
# ---------------------------------------------------------------------------


def test_get_scan_after_create():
    """Create a scan then GET it by job_id — should return the same job."""
    client, _ = _fresh_client()
    create_resp = client.post("/v1/scan", json={})
    assert create_resp.status_code == 202
    job_id = create_resp.json()["job_id"]

    get_resp = client.get(f"/v1/scan/{job_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["job_id"] == job_id


# ---------------------------------------------------------------------------
# 8. DELETE scan
# ---------------------------------------------------------------------------


def test_delete_scan():
    """Create a scan then DELETE it — should return 204."""
    client, _ = _fresh_client()
    create_resp = client.post("/v1/scan", json={})
    job_id = create_resp.json()["job_id"]

    del_resp = client.delete(f"/v1/scan/{job_id}")
    assert del_resp.status_code == 204

    # Confirm it's gone
    get_resp = client.get(f"/v1/scan/{job_id}")
    assert get_resp.status_code == 404


# ---------------------------------------------------------------------------
# 9. DELETE scan — not found
# ---------------------------------------------------------------------------


def test_delete_scan_not_found():
    """DELETE /v1/scan/nonexistent returns 404."""
    client, _ = _fresh_client()
    resp = client.delete("/v1/scan/nonexistent")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 10. Trust headers present
# ---------------------------------------------------------------------------


def test_trust_headers_present():
    """Every response should include X-Agent-Bom-Read-Only header."""
    client, _ = _fresh_client()
    resp = client.get("/health")
    assert resp.headers.get("x-agent-bom-read-only") == "true"
    assert resp.headers.get("x-agent-bom-no-credential-storage") == "true"


# ---------------------------------------------------------------------------
# 11. Version header present
# ---------------------------------------------------------------------------


def test_version_header_present():
    """Every response should include X-Agent-Bom-Version header."""
    client, _ = _fresh_client()
    resp = client.get("/health")
    assert resp.headers.get("x-agent-bom-version") == __version__


# ---------------------------------------------------------------------------
# 12. Scan job starts as pending
# ---------------------------------------------------------------------------


def test_scan_job_has_pending_status():
    """Newly created scan job should start as 'pending' (or 'running' if the
    background executor is fast enough to mutate before serialisation)."""
    client, _ = _fresh_client()
    resp = client.post("/v1/scan", json={})
    assert resp.status_code == 202
    assert resp.json()["status"] in ("pending", "running")


# ---------------------------------------------------------------------------
# 13. Scan job has valid UUID job_id
# ---------------------------------------------------------------------------


def test_scan_job_has_job_id():
    """Created job should have a valid UUID4 job_id."""
    client, _ = _fresh_client()
    resp = client.post("/v1/scan", json={})
    job_id = resp.json()["job_id"]
    # Validate it's a proper UUID
    parsed = uuid.UUID(job_id, version=4)
    assert str(parsed) == job_id


# ---------------------------------------------------------------------------
# 14. Health version matches __version__
# ---------------------------------------------------------------------------


def test_health_version_matches():
    """Health endpoint version should match the package __version__."""
    client, _ = _fresh_client()
    resp = client.get("/health")
    assert resp.json()["version"] == __version__


# ---------------------------------------------------------------------------
# 15. OpenAPI schema available
# ---------------------------------------------------------------------------


def test_openapi_schema_available():
    """GET /openapi.json should return 200 with a valid OpenAPI schema."""
    client, _ = _fresh_client()
    resp = client.get("/openapi.json")
    assert resp.status_code == 200
    body = resp.json()
    assert "openapi" in body
    assert "paths" in body
    assert body["info"]["title"] == "agent-bom API"
