"""The remediation queue follows current tenant/target findings, not the newest job."""

from starlette.testclient import TestClient

from agent_bom.api.server import app
from tests.api.test_push_replacement_scope import pushed
from tests.api.test_scan_job_sla_history import scan_store  # noqa: F401
from tests.auth_helpers import proxy_headers


def _plan(tenant="history-tenant"):
    with TestClient(app) as client:
        client.headers.update(proxy_headers(role="analyst", tenant=tenant))
        response = client.get("/v1/findings/remediation")
    assert response.status_code == 200, response.text
    return response.json()


def test_current_remediation_keeps_other_repo_after_latest_clean_push(scan_store):  # noqa: F811
    earlier = pushed(8, scope="v1:" + "a" * 64)
    earlier.result["findings"][0].update(package="demo-lib", package_version="1.0.0", ecosystem="pypi", fixed_version="2.0.0")
    scan_store.put(earlier)
    scan_store.put(pushed(9, scope="v1:" + "b" * 64, empty=True))
    body = _plan()
    assert body["remediation_plan"][0]["package"] == "demo-lib"
    assert body["remediation_plan"][0]["fixed_version"] == "2.0.0"
    assert _plan("another-tenant")["remediation_plan"] == []
    scan_store.put(pushed(10, scope="v1:" + "a" * 64, empty=True))
    assert _plan()["remediation_plan"] == []


def test_current_suppression_is_visible_and_remediation_tracks_expiry(scan_store, monkeypatch):  # noqa: F811
    from agent_bom.api import stores
    from agent_bom.api.exception_store import InMemoryExceptionStore, VulnException
    from agent_bom.api.suppression_approval import activate_suppression
    from tests.api.test_scan_job_sla_history import get_rows

    exceptions = InMemoryExceptionStore()
    monkeypatch.setattr(stores, "_exception_store", exceptions)
    row = pushed(8, scope="v1:" + "a" * 64)
    row.result["findings"][0].update(package="demo-lib", package_version="1.0.0", fixed_version="2.0.0")
    scan_store.put(row)
    exc = VulnException(vuln_id="CVE-2026-4242", package_name="demo-lib", tenant_id="history-tenant", expires_at="2099-01-01T00:00:00Z")
    exceptions.put(exc, tenant_id="history-tenant")
    assert _plan()["remediation_plan"]
    activate_suppression(exc, actor="admin")
    exceptions.put(exc, tenant_id="history-tenant")
    finding = get_rows()[0]
    assert finding["suppressed"] is True
    assert finding["suppression_id"] == exc.exception_id
    assert finding["status"] == "suppressed"
    assert [row["canonical_id"] for row in get_rows(status="suppressed")] == [finding["canonical_id"]]
    assert _plan()["remediation_plan"] == []
    exc.expires_at = "2020-01-01T00:00:00Z"
    exceptions.put(exc, tenant_id="history-tenant")
    assert not get_rows()[0].get("suppressed", False)
    assert get_rows(status="suppressed") == []
    assert _plan()["remediation_plan"]


def test_current_remediation_requires_finding_read_scope(monkeypatch):
    from agent_bom.api.auth import KeyStore, Role, create_api_key, get_key_store, set_key_store
    from agent_bom.api.server import configure_api
    from tests.auth_helpers import disable_trusted_proxy_env

    disable_trusted_proxy_env()
    old = get_key_store()
    keys = KeyStore()
    raw, key = create_api_key(name="scan-only", role=Role.ADMIN, scopes=["scan:write"], tenant_id="default")
    keys.add(key)
    set_key_store(keys)
    monkeypatch.delenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", raising=False)
    configure_api(api_key=None, allow_unauthenticated=False)
    try:
        with TestClient(app) as client:
            assert client.get("/v1/findings/remediation").status_code in (401, 403)
            assert client.get("/v1/findings/remediation", headers={"X-API-Key": raw}).status_code == 403
    finally:
        set_key_store(old)
        configure_api(api_key=None)


def test_remediation_reads_retained_jobs_once_and_does_not_query_graph(scan_store, monkeypatch):  # noqa: F811
    from unittest.mock import Mock

    from agent_bom.api.routes import scan

    row = pushed(8, scope="v1:" + "a" * 64)
    template = row.result["findings"][0]
    row.result["findings"] = [
        {
            **template,
            "id": f"finding-{i}",
            "canonical_id": f"finding-{i}",
            "package": f"package-{i}",
            "package_version": "1.0",
            "fixed_version": "2.0",
        }
        for i in range(1001)
    ]
    scan_store.put(row)
    with TestClient(app) as client:
        client.headers.update(proxy_headers(role="analyst", tenant="history-tenant"))
        reads = Mock(wraps=scan_store.list_all)
        monkeypatch.setattr(scan_store, "list_all", reads)
        graph_reads = Mock(wraps=scan._project_findings_reachability)
        monkeypatch.setattr(scan, "_project_findings_reachability", graph_reads)
        response = client.get("/v1/findings/remediation")
        assert response.status_code == 200
        assert response.json()["source_findings"] == 1001
        assert reads.call_count == 1
        assert graph_reads.call_count == 0
    scan_store.put(pushed(9, scope="v1:" + "a" * 64, empty=True))
    assert _plan()["source_findings"] == 0


def test_grouped_findings_and_facets_share_one_current_evidence_fold(scan_store, monkeypatch):  # noqa: F811
    from unittest.mock import Mock

    from agent_bom.api import findings_current

    scan_store.put(pushed(8, scope="v1:" + "a" * 64))
    folds = Mock(wraps=findings_current.current_scan_findings)
    monkeypatch.setattr("agent_bom.api.findings_current.current_scan_findings", folds)
    with TestClient(app) as client:
        client.headers.update(proxy_headers(role="analyst", tenant="history-tenant"))
        response = client.get("/v1/findings?group_occurrences=true&include_facets=true")
    assert response.status_code == 200
    assert response.json()["findings"]
    assert folds.call_count == 1


def test_collect_shared_advisory_uses_bounded_asset_identity_lookups(monkeypatch):
    from unittest.mock import Mock

    from agent_bom.api.finding_collection import collect_scan_findings
    from agent_bom.api.routes import scan

    row = pushed(8, scope="v1:" + "a" * 64)
    template = row.result["findings"][0]
    count = 200
    row.result["findings"] = [
        {**template, "id": f"finding-{i}", "canonical_id": f"finding-{i}", "package": "shared-lib", "asset": {"stable_id": f"asset-{i}"}}
        for i in range(count)
    ]
    reads = Mock(wraps=scan._row_asset_key)
    monkeypatch.setattr(scan, "_row_asset_key", reads)
    findings = collect_scan_findings(row)
    assert len(findings) == count
    assert reads.call_count <= count * 8
