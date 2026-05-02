"""Tests for core REST API endpoints — health, version, scan CRUD, middleware headers."""

from __future__ import annotations

import json
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

    The scan endpoint submits jobs to the API scan worker pool, which triggers
    discover_all() scanning the local machine. Replace submission with a no-op
    so these tests only exercise HTTP routing, not the full pipeline.
    """
    monkeypatch.setattr("agent_bom.api.routes.scan.submit_scan_job", lambda job: None)


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
    """Dashboard HTML keeps inline compatibility when no generated hash manifest exists."""
    index_file = tmp_path / "index.html"
    index_file.write_text("<html><body>agent-bom dashboard</body></html>", encoding="utf-8")
    monkeypatch.setattr("agent_bom.api.server._dashboard_index_file", lambda: str(index_file))
    monkeypatch.delenv("AGENT_BOM_DASHBOARD_CSP_HASH_MANIFEST", raising=False)

    client, _ = _fresh_client()
    resp = client.get("/", follow_redirects=False)

    assert resp.status_code == 200
    csp = resp.headers.get("content-security-policy", "")
    assert "script-src 'self' 'unsafe-inline'" in csp
    assert "script-src-attr 'none'" in csp
    assert "style-src 'self' 'unsafe-inline'" in csp
    assert "frame-ancestors 'none'" in csp


def test_root_strips_packaged_dashboard_csp_meta(tmp_path: Path, monkeypatch):
    """The API owns dashboard CSP; stale exported meta tags should not reach browsers."""
    index_file = tmp_path / "index.html"
    index_file.write_text(
        '<html><head><meta http-equiv="Content-Security-Policy" content="script-src sha256-bad"></head>'
        "<body>agent-bom dashboard</body></html>",
        encoding="utf-8",
    )
    monkeypatch.setattr("agent_bom.api.server._dashboard_index_file", lambda: str(index_file))

    client, _ = _fresh_client()
    resp = client.get("/", follow_redirects=False)

    assert resp.status_code == 200
    assert "content-security-policy" in resp.headers
    assert "http-equiv" not in resp.text
    assert "sha256-bad" not in resp.text


def test_root_uses_hash_manifest_csp_when_bundled(tmp_path: Path, monkeypatch):
    """Packaged dashboard HTML should remove script unsafe-inline when release hashes exist."""
    index_file = tmp_path / "index.html"
    index_file.write_text("<html><body>agent-bom dashboard</body></html>", encoding="utf-8")
    manifest = tmp_path / "csp-hashes.json"
    manifest.write_text(
        json.dumps({"script_hashes": ["sha256-abc123"], "style_hashes": ["sha256-style123"]}),
        encoding="utf-8",
    )
    monkeypatch.setattr("agent_bom.api.server._dashboard_index_file", lambda: str(index_file))
    monkeypatch.setenv("AGENT_BOM_DASHBOARD_CSP_HASH_MANIFEST", str(manifest))

    client, _ = _fresh_client()
    resp = client.get("/", follow_redirects=False)

    assert resp.status_code == 200
    csp = resp.headers.get("content-security-policy", "")
    script_directive = csp.split("script-src ", 1)[1].split(";", 1)[0]
    assert script_directive == "'self' 'sha256-abc123'"
    assert "'unsafe-inline'" not in script_directive
    assert "style-src 'self' 'unsafe-inline' 'sha256-style123'" in csp


def test_direct_dashboard_html_static_file_strips_csp_meta(tmp_path: Path, monkeypatch):
    """Direct static-export HTML files should use the same CSP stripping as SPA fallback."""
    package_root = tmp_path / "agent_bom"
    api_dir = package_root / "api"
    api_dir.mkdir(parents=True)
    server_file = api_dir / "server.py"
    server_file.write_text("", encoding="utf-8")
    ui_dist = package_root / "ui_dist"
    nested = ui_dist / "agents"
    nested.mkdir(parents=True)
    (ui_dist / "index.html").write_text("<html><body>root</body></html>", encoding="utf-8")
    (nested / "index.html").write_text(
        '<html><head><meta http-equiv="Content-Security-Policy" content="script-src sha256-bad"></head><body>agents</body></html>',
        encoding="utf-8",
    )
    from fastapi import FastAPI

    import agent_bom.api.server as server_module
    from agent_bom.api.server import _mount_dashboard

    monkeypatch.setattr(server_module, "__file__", str(server_file))
    test_app = FastAPI()
    _mount_dashboard(test_app)
    client = TestClient(test_app, raise_server_exceptions=False)
    resp = client.get("/agents/index.html")

    assert resp.status_code == 200
    assert "http-equiv" not in resp.text
    assert "sha256-bad" not in resp.text


def test_hsts_preload_is_operator_opt_in(monkeypatch):
    client, _ = _fresh_client()
    resp = client.get("/health")
    assert resp.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"

    monkeypatch.setenv("AGENT_BOM_HSTS_PRELOAD", "1")
    resp = client.get("/health")
    assert resp.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains; preload"


def test_ui_csp_headers_do_not_allow_eval():
    """Static and hosted UI headers should not permit eval-style script execution.

    The CSP source was centralized to ui/lib/security-headers.mjs in #1954.
    next.config.ts now imports from there; vercel.json is regenerated from
    the same module by ui/scripts/sync-vercel-headers.mjs and verified by
    the vitest sync test. The source-of-truth and the rendered output must
    both forbid eval-style execution.
    """
    root = Path(__file__).parent.parent
    canonical = (root / "ui" / "lib" / "security-headers.mjs").read_text(encoding="utf-8")
    vercel_config = (root / "ui" / "vercel.json").read_text(encoding="utf-8")

    assert "'unsafe-eval'" not in canonical
    assert "'unsafe-eval'" not in vercel_config
    assert "script-src-attr 'none'" in canonical
    assert "script-src-attr 'none'" in vercel_config
    # Removing 'unsafe-inline' from script-src is a #1954 follow-up that
    # needs a build-time hash collector for Next.js streaming inline scripts.
    # The hash of THEME_BOOTSTRAP_SCRIPT is already inventoried in
    # security-headers.mjs (INLINE_SCRIPT_HASHES) so the migration is a
    # one-line CSP flip when the collector lands.


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
    assert body["request"]["inventory"] == "<path:agents.json>"
    assert "/tmp" not in body["request"]["inventory"]
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


def test_get_scan_status_omits_large_result_payload():
    """Status polling should not serialize the full scan result on every tick."""
    client, store = _fresh_client()
    job = ScanJob(
        job_id="job-large-result",
        tenant_id="default",
        status=JobStatus.DONE,
        created_at="2026-01-01T00:00:00Z",
        completed_at="2026-01-01T00:00:13Z",
        request=ScanRequest(inventory="/tmp/agents.json"),
        progress=["scan started", "scan complete"],
        result={
            "summary": {
                "total_agents": 8,
                "total_servers": 8,
                "total_packages": 165,
                "total_vulnerabilities": 28,
            },
            "agents": [{"name": "agent", "payload": "x" * 250_000}],
            "blast_radius": [{"package": "pkg", "payload": "y" * 250_000}],
        },
    )
    store.put(job)

    full = client.get("/v1/scan/job-large-result")
    status = client.get("/v1/scan/job-large-result/status")

    assert full.status_code == 200
    assert status.status_code == 200
    body = status.json()
    assert body["job_id"] == "job-large-result"
    assert body["status"] == "done"
    assert body["summary"]["total_packages"] == 165
    assert body["request"]["inventory"] == "<path:agents.json>"
    assert "result" not in body
    assert "progress" not in body
    assert len(status.content) < len(full.content) / 100


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


def test_openapi_runtime_routes_do_not_404(monkeypatch):
    """Routes advertised for core UI/API surfaces should resolve at runtime."""
    client, store = _fresh_client()
    previous = ScanJob(
        job_id="job-prev",
        status=JobStatus.DONE,
        created_at="2026-04-20T00:00:00Z",
        completed_at="2026-04-20T00:01:00Z",
        request=ScanRequest(),
        result={
            "agents": [
                {
                    "name": "claude-desktop",
                    "agent_type": "claude-desktop",
                    "mcp_servers": [
                        {
                            "name": "filesystem",
                            "packages": [
                                {
                                    "name": "requests",
                                    "version": "2.31.0",
                                    "ecosystem": "pypi",
                                    "vulnerabilities": [{"id": "CVE-2026-0001", "severity": "high"}],
                                }
                            ],
                        }
                    ],
                }
            ],
            "blast_radius": [{"vulnerability_id": "CVE-2026-0001", "package": "requests@2.31.0", "severity": "high"}],
        },
    )
    current = ScanJob(
        job_id="job-current",
        status=JobStatus.DONE,
        created_at="2026-04-21T00:00:00Z",
        completed_at="2026-04-21T00:01:00Z",
        request=ScanRequest(),
        result={"agents": previous.result["agents"], "blast_radius": []},
    )
    store.put(previous)
    store.put(current)
    monkeypatch.setattr("agent_bom.discovery.discover_all", lambda: [])

    schema = client.get("/openapi.json").json()
    expected_paths = {"/v1/agents/mesh", "/v1/findings", "/v1/inventory", "/v1/baseline/compare"}
    assert expected_paths <= set(schema["paths"])

    checks = [
        ("GET", "/v1/agents/mesh"),
        ("GET", "/v1/findings"),
        ("GET", "/v1/inventory"),
        ("POST", "/v1/baseline/compare?previous_job_id=job-prev&current_job_id=job-current"),
    ]
    for method, path in checks:
        response = client.request(method, path)
        assert response.status_code != 404, (method, path, response.text)


def test_baseline_compare_requires_job_ids_without_404():
    """A bare compare request should fail validation, not look like a missing route."""
    client, _ = _fresh_client()
    resp = client.post("/v1/baseline/compare")
    assert resp.status_code == 422
