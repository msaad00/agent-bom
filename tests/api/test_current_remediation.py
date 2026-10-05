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
