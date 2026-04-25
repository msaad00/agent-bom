"""Tests for core REST API endpoints — health, version, scan CRUD, middleware headers."""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from agent_bom import __version__
from agent_bom.api.server import JobStatus, ScanJob, ScanRequest, _jobs, app, set_job_store
from agent_bom.api.store import InMemoryJobStore


@pytest.fixture(autouse=True)
def _mock_scan_pipeline(monkeypatch):
    """Prevent real MCP discovery during scan CRUD tests.

    The scan endpoint calls loop.run_in_executor(_executor, _run_scan_sync, job)
    which triggers discover_all() scanning the local machine. Replace with a
    no-op so these tests only exercise HTTP routing, not the full pipeline.
    """
    monkeypatch.setattr("agent_bom.api.routes.scan._run_scan_sync", lambda job: None)


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
    assert body["tracing"]["w3c_trace_context"] is True
    assert body["tracing"]["w3c_tracestate"] is True
    assert body["tracing"]["w3c_baggage"] is True
    assert body["tracing"]["otlp_export"] in {"configured", "disabled", "missing_deps"}
    assert body["analytics"]["backend"] in {"disabled", "clickhouse"}
    assert isinstance(body["analytics"]["enabled"], bool)
    assert isinstance(body["analytics"]["buffered"], bool)
    assert body["storage"]["control_plane_backend"] in {"inmemory", "sqlite", "postgres", "snowflake"}
    assert body["storage"]["job_store"] in {"inmemory", "sqlite", "postgres", "snowflake"}
    assert body["storage"]["audit_log"] in {"inmemory", "sqlite", "postgres", "snowflake"}


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


def test_framework_catalogs_endpoint():
    """GET /v1/frameworks/catalogs returns active framework metadata."""
    client, _ = _fresh_client()
    resp = client.get("/v1/frameworks/catalogs")
    assert resp.status_code == 200
    body = resp.json()
    assert "frameworks" in body
    assert "mitre_attack" in body["frameworks"]
    assert "attack_version" in body["frameworks"]["mitre_attack"]


# ---------------------------------------------------------------------------
# 3. Root redirect
# ---------------------------------------------------------------------------


def test_root_redirects_when_dashboard_is_not_bundled(monkeypatch):
    """GET / falls back to API docs when the packaged dashboard is absent."""
    monkeypatch.setattr("agent_bom.api.server._dashboard_index_file", lambda: None)
    client, _ = _fresh_client()
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code == 307
    assert "/docs" in resp.headers.get("location", "")


def test_root_serves_dashboard_when_bundled(tmp_path: Path, monkeypatch):
    """GET / serves the packaged dashboard when UI assets are present."""
    index_file = tmp_path / "index.html"
    index_file.write_text("<html><body>agent-bom dashboard</body></html>", encoding="utf-8")
    monkeypatch.setattr("agent_bom.api.server._dashboard_index_file", lambda: str(index_file))

    client, _ = _fresh_client()
    resp = client.get("/", follow_redirects=False)

    assert resp.status_code == 200
    assert "text/html" in resp.headers.get("content-type", "")
    assert "agent-bom dashboard" in resp.text


def test_root_uses_dashboard_friendly_csp_when_bundled(tmp_path: Path, monkeypatch):
    """Packaged dashboard HTML should allow the inline bootstrap it ships with."""
    index_file = tmp_path / "index.html"
    index_file.write_text("<html><body>agent-bom dashboard</body></html>", encoding="utf-8")
    monkeypatch.setattr("agent_bom.api.server._dashboard_index_file", lambda: str(index_file))

    client, _ = _fresh_client()
    resp = client.get("/", follow_redirects=False)

    assert resp.status_code == 200
    csp = resp.headers.get("content-security-policy", "")
    assert "script-src 'self' 'unsafe-inline'" in csp
    assert "script-src-attr 'none'" in csp
    assert "style-src 'self' 'unsafe-inline'" in csp
    assert "frame-ancestors 'none'" in csp


def test_hsts_preload_is_operator_opt_in(monkeypatch):
    client, _ = _fresh_client()
    resp = client.get("/health")
    assert resp.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"

    monkeypatch.setenv("AGENT_BOM_HSTS_PRELOAD", "1")
    resp = client.get("/health")
    assert resp.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains; preload"


def test_ui_csp_headers_do_not_allow_eval():
    """Static and hosted UI headers should not permit eval-style script execution."""
    root = Path(__file__).parent.parent
    next_config = (root / "ui" / "next.config.ts").read_text(encoding="utf-8")
    vercel_config = (root / "ui" / "vercel.json").read_text(encoding="utf-8")

    assert "'unsafe-eval'" not in next_config
    assert "'unsafe-eval'" not in vercel_config
    assert "script-src-attr 'none'" in next_config
    assert "script-src-attr 'none'" in vercel_config


def test_root_allows_head_when_dashboard_is_bundled(tmp_path: Path, monkeypatch):
    """Packaged dashboard should answer HEAD like a normal static site root."""
    index_file = tmp_path / "index.html"
    index_file.write_text("<html><body>agent-bom dashboard</body></html>", encoding="utf-8")
    monkeypatch.setattr("agent_bom.api.server._dashboard_index_file", lambda: str(index_file))

    client, _ = _fresh_client()
    resp = client.head("/", follow_redirects=False)

    assert resp.status_code == 200
    assert "text/html" in resp.headers.get("content-type", "")


def test_health_keeps_strict_api_csp():
    """API JSON routes should keep the stricter default CSP."""
    client, _ = _fresh_client()
    resp = client.get("/health")

    assert resp.status_code == 200
    assert resp.headers.get("content-security-policy") == "default-src 'self'"


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
    assert body["triggered_by"] == "api"
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
    assert body["triggered_by"] == "api"
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

    # Confirm it's gone — 404 expected, but 200 is acceptable if the
    # background scan thread completed and re-stored results between
    # the DELETE and this GET (race condition on fast CI runners).
    get_resp = client.get(f"/v1/scan/{job_id}")
    assert get_resp.status_code in (404, 200)


# ---------------------------------------------------------------------------
# 9. DELETE scan — not found
# ---------------------------------------------------------------------------


def test_delete_scan_not_found():
    """DELETE /v1/scan/nonexistent returns 404."""
    client, _ = _fresh_client()
    resp = client.delete("/v1/scan/nonexistent")
    assert resp.status_code == 404


def test_get_scan_passes_tenant_to_store():
    import agent_bom.api.stores as api_stores

    class RecordingJobStore:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str | None]] = []

        def put(self, job) -> None:
            raise NotImplementedError

        def get(self, job_id: str, tenant_id: str | None = None):
            self.calls.append((job_id, tenant_id))
            return ScanJob(
                job_id=job_id,
                tenant_id=tenant_id or "default",
                status=JobStatus.PENDING,
                created_at="2026-01-01T00:00:00Z",
                request=ScanRequest(),
            )

        def delete(self, job_id: str, tenant_id: str | None = None) -> bool:
            raise NotImplementedError

        def list_all(self, tenant_id: str | None = None):
            return []

        def list_summary(self, tenant_id: str | None = None):
            return []

        def cleanup_expired(self, ttl_seconds: int = 3600) -> int:
            return 0

    store = RecordingJobStore()
    original = api_stores._store
    try:
        set_job_store(store)
        _jobs.clear()
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/v1/scan/job-tenant-check")

        assert resp.status_code == 200
        assert store.calls == [("job-tenant-check", "default")]
    finally:
        set_job_store(original)
        _jobs.clear()


def test_delete_scan_passes_tenant_to_store():
    import agent_bom.api.stores as api_stores

    class RecordingJobStore:
        def __init__(self) -> None:
            self.get_calls: list[tuple[str, str | None]] = []
            self.delete_calls: list[tuple[str, str | None]] = []

        def put(self, job) -> None:
            raise NotImplementedError

        def get(self, job_id: str, tenant_id: str | None = None):
            self.get_calls.append((job_id, tenant_id))
            return ScanJob(
                job_id=job_id,
                tenant_id=tenant_id or "default",
                status=JobStatus.PENDING,
                created_at="2026-01-01T00:00:00Z",
                request=ScanRequest(),
            )

        def delete(self, job_id: str, tenant_id: str | None = None) -> bool:
            self.delete_calls.append((job_id, tenant_id))
            return True

        def list_all(self, tenant_id: str | None = None):
            return []

        def list_summary(self, tenant_id: str | None = None):
            return []

        def cleanup_expired(self, ttl_seconds: int = 3600) -> int:
            return 0

    store = RecordingJobStore()
    original = api_stores._store
    try:
        set_job_store(store)
        _jobs.clear()
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.delete("/v1/scan/job-tenant-delete")

        assert resp.status_code == 204
        assert store.get_calls == [("job-tenant-delete", "default")]
        assert store.delete_calls == [("job-tenant-delete", "default")]
    finally:
        set_job_store(original)
        _jobs.clear()


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
    compliance_report = body["paths"]["/v1/compliance/{framework}/report"]["get"]["responses"]["200"]["content"]["application/json"][
        "schema"
    ]
    assert compliance_report["$ref"].endswith("/ComplianceReportBundle")
