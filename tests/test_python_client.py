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
    client.list_finding_triage(queue_state="open", decision="under_investigation")
    client.create_finding_triage(
        "CVE-2026-0101",
        package="requests",
        assignee="secops@example.com",
        decision_reason="needs owner",
    )
    client.update_finding_triage_decision(
        "triage-1",
        decision="not_affected",
        justification="vulnerable_code_not_in_execute_path",
        decision_reason="not reachable",
    )
    client.export_finding_triage_vex()
    client.ingest_finding_triage_vex({"@context": "https://openvex.dev/ns/v0.2.0", "statements": []})
    client.ingest_findings(findings=[{"id": "finding-1", "severity": "high"}], source="sdk-test")
    client.register_dataset_version("dataset-a", version_id="v1")
    client.dataset_versions("dataset-a")
    client.dataset_version("dataset-a", "v1")
    client.register_evaluation_run(evaluation_id="eval-a", dataset_id="dataset-a", dataset_version_id="v1")
    client.evaluation_runs(dataset_id="dataset-a", limit=10)
    client.evaluation_run("eval-a")

    assert seen == [
        ("GET", "/v1/findings"),
        ("GET", "/v1/findings/triage"),
        ("POST", "/v1/findings/triage"),
        ("PUT", "/v1/findings/triage/triage-1/decision"),
        ("GET", "/v1/findings/triage/vex"),
        ("POST", "/v1/findings/triage/vex/ingest"),
        ("POST", "/v1/findings/bulk"),
        ("POST", "/v1/datasets/dataset-a/versions"),
        ("GET", "/v1/datasets/dataset-a/versions"),
        ("GET", "/v1/datasets/dataset-a/versions/v1"),
        ("POST", "/v1/evaluations"),
        ("GET", "/v1/evaluations"),
        ("GET", "/v1/evaluations/eval-a"),
    ]


def test_client_exposes_runtime_event_sessions() -> None:
    seen: list[tuple[str, str]] = []
    bodies: list[dict[str, object]] = []
    urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path))
        urls.append(str(request.url))
        if request.content:
            bodies.append(json.loads(request.content.decode("utf-8")))
        return httpx.Response(200, json={"ok": True})

    client = _client(handler)

    client.ingest_runtime_events([{"session_id": "sess-a", "event_type": "tool_call"}])
    client.runtime_sessions(limit=10)
    client.runtime_observations(session_id="sess-a", limit=20)
    client.runtime_session_observations("sess-a", offset=5)

    assert seen == [
        ("POST", "/v1/runtime/events"),
        ("GET", "/v1/runtime/sessions"),
        ("GET", "/v1/runtime/observations"),
        ("GET", "/v1/runtime/sessions/sess-a/observations"),
    ]
    assert bodies == [{"events": [{"session_id": "sess-a", "event_type": "tool_call"}], "tenant_id": "tenant-a"}]
    assert urls[1:] == [
        "https://agent-bom.example.com/v1/runtime/sessions?tenant_id=tenant-a&limit=10",
        "https://agent-bom.example.com/v1/runtime/observations?tenant_id=tenant-a&session_id=sess-a&limit=20",
        "https://agent-bom.example.com/v1/runtime/sessions/sess-a/observations?tenant_id=tenant-a&offset=5",
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


def test_client_ingest_findings_lifecycle_fields() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content.decode("utf-8"))
        captured["headers"] = dict(request.headers)
        return httpx.Response(201, json={"ingested": 1, "reconciled": 1})

    client = _client(handler)

    result = client.ingest_findings(
        [{"id": "finding-1", "severity": "high"}],
        source="sdk-test",
        observed_at="2026-07-08T12:00:00Z",
        reconcile_absent=True,
        idempotency_key="scan-batch-42",
    )

    assert result["reconciled"] == 1
    headers = captured["headers"]
    assert isinstance(headers, dict)
    assert headers["idempotency-key"] == "scan-batch-42"
    assert captured["body"] == {
        "findings": [{"id": "finding-1", "severity": "high"}],
        "source": "sdk-test",
        "tenant_id": "tenant-a",
        "observed_at": "2026-07-08T12:00:00Z",
        "reconcile_absent": True,
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
