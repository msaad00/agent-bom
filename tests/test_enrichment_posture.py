from __future__ import annotations

from starlette.testclient import TestClient

from agent_bom.api.server import app
from agent_bom.enrichment_posture import (
    describe_enrichment_posture,
    record_enrichment_source,
    reset_enrichment_posture_for_tests,
)
from tests.auth_helpers import enable_trusted_proxy_env, proxy_headers


def test_enrichment_posture_reports_unknown_by_default() -> None:
    reset_enrichment_posture_for_tests()

    posture = describe_enrichment_posture()

    assert posture["status"] == "unknown"
    sources = {source["source"]: source for source in posture["sources"]}
    assert {"osv", "nvd", "epss", "cisa_kev", "ghsa"} <= set(sources)
    assert sources["osv"]["status"] == "unknown"


def test_enrichment_posture_tracks_success_and_failure() -> None:
    reset_enrichment_posture_for_tests()

    record_enrichment_source("osv", "success")
    record_enrichment_source("epss", "failure", error="HTTP 503\nretry later")
    posture = describe_enrichment_posture()

    sources = {source["source"]: source for source in posture["sources"]}
    assert posture["status"] == "degraded"
    assert sources["osv"]["status"] == "ok"
    assert sources["epss"]["status"] == "degraded"
    assert sources["epss"]["message"] == "HTTP 503 retry later"


def test_enrichment_posture_endpoint() -> None:
    reset_enrichment_posture_for_tests()
    record_enrichment_source("cisa_kev", "cache")
    enable_trusted_proxy_env()

    client = TestClient(app)
    resp = client.get("/v1/posture/enrichment", headers=proxy_headers(role="viewer"))

    assert resp.status_code == 200
    body = resp.json()
    assert any(source["source"] == "cisa_kev" for source in body["sources"])
