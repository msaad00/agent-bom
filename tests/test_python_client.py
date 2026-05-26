"""Tests for the Python control-plane client."""

from __future__ import annotations

import json

import httpx
import pytest

from agent_bom import AgentBomApiError, AgentBomClient


def _client(handler):
    transport = httpx.MockTransport(handler)
    return AgentBomClient(base_url="https://agent-bom.example.com/", api_key="secret", tenant_id="tenant-a", transport=transport)


def test_client_sets_auth_headers_and_strips_none_body_fields() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["headers"] = dict(request.headers)
        captured["body"] = json.loads(request.content.decode("utf-8"))
        return httpx.Response(200, json={"decision": "allow"})

    client = _client(handler)

    result = client.should_i_deploy(candidate="flask@2.0.0", block_risk=80, context=None)

    assert result["decision"] == "allow"
    assert captured["url"] == "https://agent-bom.example.com/v1/graph/should-i-deploy"
    headers = captured["headers"]
    assert isinstance(headers, dict)
    assert headers["x-api-key"] == "secret"
    assert headers["x-agent-bom-tenant-id"] == "tenant-a"
    assert headers["content-type"] == "application/json"
    assert captured["body"] == {"candidate": "flask@2.0.0", "tenant_id": "tenant-a", "block_risk": 80}


def test_client_accepts_positional_deploy_candidate() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content.decode("utf-8"))
        return httpx.Response(200, json={"decision": "warn"})

    client = _client(handler)

    result = client.should_i_deploy("flask@2.0.0", block_risk=60)

    assert result["decision"] == "warn"
    assert captured["body"] == {"candidate": "flask@2.0.0", "tenant_id": "tenant-a", "block_risk": 60}


def test_client_builds_query_params() -> None:
    urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        urls.append(str(request.url))
        return httpx.Response(200, json={"paths": []})

    client = _client(handler)

    client.exposure_paths(limit=5, min_risk=70)

    assert urls == ["https://agent-bom.example.com/v1/graph/exposure-paths?tenant_id=tenant-a&limit=5&min_risk=70"]


def test_client_exposes_v0871_headline_routes() -> None:
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path))
        return httpx.Response(200, json={"ok": True})

    client = _client(handler)

    client.agent_manifest()
    client.runtime_production_index()
    client.intel_lookup("GHSA-xxxx-yyyy-zzzz")
    client.intel_match(ecosystem="pypi", name="requests", version="2.31.0")
    client.intel_sources()

    assert seen == [
        ("GET", "/v1/agent-bom/manifest"),
        ("GET", "/v1/runtime/production-index"),
        ("GET", "/v1/intel/advisories/GHSA-xxxx-yyyy-zzzz"),
        ("POST", "/v1/intel/match"),
        ("GET", "/v1/intel/sources"),
    ]


def test_client_exposes_findings_and_dataset_loop() -> None:
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path))
        return httpx.Response(200, json={"ok": True})

    client = _client(handler)

    client.list_findings(severity="high", limit=10)
    client.ingest_findings(findings=[{"id": "finding-1", "severity": "high"}], source="sdk-test")
    client.register_dataset_version("dataset-a", version_id="v1")
    client.dataset_versions("dataset-a")
    client.dataset_version("dataset-a", "v1")
    client.register_evaluation_run(evaluation_id="eval-a", dataset_id="dataset-a", dataset_version_id="v1")
    client.evaluation_runs(dataset_id="dataset-a", limit=10)
    client.evaluation_run("eval-a")

    assert seen == [
        ("GET", "/v1/findings"),
        ("POST", "/v1/findings/bulk"),
        ("POST", "/v1/datasets/dataset-a/versions"),
        ("GET", "/v1/datasets/dataset-a/versions"),
        ("GET", "/v1/datasets/dataset-a/versions/v1"),
        ("POST", "/v1/evaluations"),
        ("GET", "/v1/evaluations"),
        ("GET", "/v1/evaluations/eval-a"),
    ]


def test_client_accepts_positional_findings_payload() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content.decode("utf-8"))
        return httpx.Response(201, json={"ingested": 1})

    client = _client(handler)

    result = client.ingest_findings([{"id": "finding-1", "severity": "high"}], source="sdk-test")

    assert result["ingested"] == 1
    assert captured["body"] == {
        "findings": [{"id": "finding-1", "severity": "high"}],
        "source": "sdk-test",
        "tenant_id": "tenant-a",
    }


def test_client_rejects_ambiguous_auth() -> None:
    with pytest.raises(ValueError, match="either api_key or bearer_token"):
        AgentBomClient(base_url="https://agent-bom.example.com", api_key="a", bearer_token="b")


def test_client_raises_api_error_with_body() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text='{"detail":"forbidden"}')

    client = AgentBomClient(base_url="https://agent-bom.example.com", bearer_token="token", transport=httpx.MockTransport(handler))

    with pytest.raises(AgentBomApiError) as exc:
        client.health()

    assert exc.value.status_code == 403
    assert exc.value.body == '{"detail":"forbidden"}'
