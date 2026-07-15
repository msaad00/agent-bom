"""API surface for per-span attack-path correlation + trace connectors (#3898/#3899)."""

from __future__ import annotations

from starlette.testclient import TestClient

from agent_bom.api.server import app
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()


def setup_function() -> None:
    from agent_bom.api.server import set_job_store
    from agent_bom.api.store import InMemoryJobStore

    set_job_store(InMemoryJobStore())


def _push_scan(client: TestClient, headers: dict[str, str]) -> None:
    report = {
        "source_id": "unit",
        "blast_radius": [
            {
                "vulnerability_id": "CVE-2025-1234",
                "severity": "critical",
                "cvss_score": 9.8,
                "epss_score": 0.7,
                "is_kev": True,
                "package": "requests@2.0.0",
                "affected_servers": ["shell-mcp"],
                "affected_agents": ["ci-agent"],
                "exposed_tools": ["run_shell"],
                "exposed_credentials": ["AWS_SECRET_ACCESS_KEY"],
                "risk_score": 9.1,
            }
        ],
    }
    resp = client.post("/v1/results/push", json=report, headers=headers)
    assert resp.status_code == 201, resp.text


def test_attack_paths_endpoint_resolves_exact_span() -> None:
    client = TestClient(app)
    admin = proxy_headers(role="admin")
    _push_scan(client, admin)

    trace = {
        "spans": [
            {
                "traceId": "trace-1",
                "spanId": "abc123",
                "name": "adk.tool.run_shell",
                "attributes": [{"key": "mcp.server", "value": {"stringValue": "shell-mcp"}}],
            }
        ]
    }
    resp = client.post("/v1/traces/attack-paths", json=trace, headers=proxy_headers(role="viewer"))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["count"] == 1
    path = body["attack_paths"][0]
    assert path["span_id"] == "abc123"
    assert path["vulnerability_id"] == "CVE-2025-1234"
    assert "AWS_SECRET_ACCESS_KEY" in path["exposed_credentials"]


def test_trace_content_screening_off_by_default() -> None:
    client = TestClient(app)
    trace = {
        "spans": [
            {
                "traceId": "t",
                "spanId": "s",
                "name": "adk.tool.read_file",
                "attributes": [{"key": "tool.output", "value": {"stringValue": "key AKIAIOSFODNN7EXAMPLE"}}],
            }
        ]
    }
    resp = client.post("/v1/traces", json=trace, headers=proxy_headers(role="admin"))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["content_screened"] is False
    assert body["content_findings"] == []


def test_trace_content_screening_opt_in_surfaces_redacted_findings() -> None:
    client = TestClient(app)
    trace = {
        "spans": [
            {
                "traceId": "t",
                "spanId": "s",
                "name": "adk.tool.read_file",
                "attributes": [{"key": "tool.output", "value": {"stringValue": "key AKIAIOSFODNN7EXAMPLE leaked"}}],
            }
        ]
    }
    resp = client.post("/v1/traces?screen_content=true", json=trace, headers=proxy_headers(role="admin"))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["content_screened"] is True
    assert body["content_findings"], "opt-in screening should surface the credential leak"
    for finding in body["content_findings"]:
        assert "AKIAIOSFODNN7EXAMPLE" not in finding["message"]


def test_list_trace_connectors_route() -> None:
    client = TestClient(app)
    resp = client.get("/v1/traces/connectors", headers=proxy_headers(role="viewer"))
    assert resp.status_code == 200, resp.text
    names = {c["name"] for c in resp.json()["connectors"]}
    assert {"langfuse", "langsmith"} <= names


def test_pull_connector_rejects_ssrf_host_with_400() -> None:
    # A runtime_ingest caller must not be able to point the control plane at a
    # cloud-metadata endpoint (SSRF). The guard rejects it as a client error
    # (400), not a 500/502, and never echoes the raw URL back.
    client = TestClient(app)
    body = {"credentials": {"host": "http://169.254.169.254/latest/meta-data", "public_key": "pk", "secret_key": "sk"}}
    resp = client.post("/v1/traces/connectors/langfuse/pull", json=body, headers=proxy_headers(role="admin"))
    assert resp.status_code == 400, resp.text
    assert "169.254.169.254" not in resp.text
