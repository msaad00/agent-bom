"""Type validation for /v1/findings/bulk (wave-2 #2).

Bulk ingest used to accept garbage ``severity`` / ``cvss_score`` types with a
201 and materialise rows that leak the value verbatim and can never match the
severity/cvss filters. These tests pin the fail-closed contract: a non-string
severity or a non-numeric / out-of-range cvss_score is rejected with 422, an
unknown severity STRING is mapped to ``unknown`` explicitly, and the valid path
still 201s and stores canonical values.
"""

from __future__ import annotations

from uuid import uuid4

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


def _client(tenant: str) -> TestClient:
    client = TestClient(app)
    client.headers.update(proxy_headers(role="analyst", tenant=tenant))
    return client


def _post(client: TestClient, finding: dict) -> object:
    return client.post(
        "/v1/findings/bulk",
        json={"source": "connector", "findings": [finding]},
    )


def test_nested_severity_rejected_422():
    client = _client(f"bulk-val-{uuid4().hex}")
    resp = _post(client, {"id": "f-1", "severity": {"nested": True}})
    assert resp.status_code == 422, resp.text
    assert "severity" in resp.text.lower()


def test_numeric_severity_rejected_422():
    client = _client(f"bulk-val-{uuid4().hex}")
    resp = _post(client, {"id": "f-1", "severity": 5})
    assert resp.status_code == 422, resp.text


def test_non_numeric_cvss_string_rejected_422():
    client = _client(f"bulk-val-{uuid4().hex}")
    resp = _post(client, {"id": "f-1", "severity": "high", "cvss_score": "NaNstring"})
    assert resp.status_code == 422, resp.text
    assert "cvss" in resp.text.lower()


def test_out_of_range_cvss_rejected_422():
    client = _client(f"bulk-val-{uuid4().hex}")
    resp = _post(client, {"id": "f-1", "severity": "high", "cvss_score": 42})
    assert resp.status_code == 422, resp.text


def test_nan_cvss_rejected_422():
    client = _client(f"bulk-val-{uuid4().hex}")
    resp = _post(client, {"id": "f-1", "severity": "high", "cvss_score": "NaN"})
    assert resp.status_code == 422, resp.text


def test_dict_cvss_rejected_422():
    client = _client(f"bulk-val-{uuid4().hex}")
    resp = _post(client, {"id": "f-1", "severity": "high", "cvss_score": {"score": 7.0}})
    assert resp.status_code == 422, resp.text


def test_unknown_severity_string_mapped_to_unknown():
    tenant = f"bulk-val-{uuid4().hex}"
    client = _client(tenant)
    resp = _post(client, {"id": "f-1", "severity": "totally-bogus"})
    assert resp.status_code == 201, resp.text
    # The stored row must be filterable as unknown, never leaking the raw label.
    listed = client.get("/v1/findings?severity=unknown&window_days=0")
    assert listed.status_code == 200, listed.text
    ids = {f.get("id") for f in listed.json().get("findings", [])}
    assert "f-1" in ids


def test_valid_severity_and_cvss_still_201_and_stored():
    tenant = f"bulk-val-{uuid4().hex}"
    client = _client(tenant)
    resp = client.post(
        "/v1/findings/bulk",
        json={
            "source": "connector",
            "findings": [
                {"id": "f-crit", "severity": "critical", "cvss_score": 9.8},
                {"id": "f-num-str", "severity": "high", "cvss_score": "7.5"},
                {"id": "f-null", "severity": "low", "cvss_score": None},
            ],
        },
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["ingested"] == 3

    listed = client.get("/v1/findings?severity=critical&window_days=0")
    assert listed.status_code == 200, listed.text
    ids = {f.get("id") for f in listed.json().get("findings", [])}
    assert "f-crit" in ids
