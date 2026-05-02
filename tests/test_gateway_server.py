"""End-to-end tests for the multi-MCP gateway server.

Uses TestClient(create_gateway_app(settings)) with an injected
UpstreamCaller so we exercise:
- the full FastAPI route layer (not just the handler)
- real policy evaluation via check_policy
- audit sink capture
- happy path + blocked-by-policy + unknown-upstream + upstream error

No real network. The injected caller simulates both success + failure
paths a pilot team would actually run into.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from starlette.testclient import TestClient

from agent_bom.api.auth import Role
from agent_bom.api.tracing import parse_traceparent
from agent_bom.gateway_server import GatewaySettings, GatewayUpstreamRelay, create_gateway_app
from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry


def _simple_registry() -> UpstreamRegistry:
    return UpstreamRegistry(
        [
            UpstreamConfig(name="filesystem", url="http://fs.local:8100"),
            UpstreamConfig(name="jira", url="http://jira.local:8200"),
        ]
    )


def _json_rpc(method: str, **params: Any) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    }


def _gateway_api_key(tenant_id: str, *, role: Role = Role.ANALYST, scopes: list[str] | None = None) -> SimpleNamespace:
    allowed_scopes = scopes if scopes is not None else ["gateway:relay"]
    return SimpleNamespace(
        tenant_id=tenant_id,
        role=role,
        scopes=allowed_scopes,
        has_scope=lambda required: not allowed_scopes or required in allowed_scopes or "*" in allowed_scopes,
    )


# ─── Happy path: relay returns upstream response verbatim ──────────────────


def test_healthz_lists_configured_upstreams() -> None:
    settings = GatewaySettings(registry=_simple_registry(), policy={})
    client = TestClient(create_gateway_app(settings))
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {
        "status": "ok",
        "upstreams": ["filesystem", "jira"],
        "auth": {"incoming_token_required": False},
        "upstream_runtime": {
            "pooled_http_client": True,
            "circuit_breaker_enabled": True,
            "failure_threshold": 3,
            "cooldown_seconds": 30.0,
            "max_connections": 100,
            "max_keepalive_connections": 20,
        },
        "rate_limit_runtime": {
            "enabled": False,
            "limit_per_tenant_per_minute": 0,
            "backend": "disabled",
            "postgres_configured": False,
            "configured_gateway_replicas": 1,
            "shared_required": False,
            "shared_across_replicas": False,
            "fail_closed": False,
            "message": "Gateway runtime rate limiting disabled.",
        },
        "policy_runtime": {
            "source": "inline",
            "source_kind": "inline",
            "reload_enabled": False,
            "reload_interval_seconds": 0,
            "last_loaded_at": None,
            "last_error": None,
            "rollout_mode": "disabled",
            "summary": "No runtime policy rules configured.",
            "total_rules": 0,
            "blocking_rules": 0,
            "advisory_rules": 0,
            "allowlist_rules": 0,
            "default_deny_rules": 0,
            "read_only_rules": 0,
            "secret_path_rules": 0,
            "unknown_egress_rules": 0,
            "denied_tool_classes": [],
            "blocks_requests": False,
            "advisory_only": False,
            "default_deny": False,
            "protects_secret_paths": False,
            "restricts_unknown_egress": False,
        },
        "firewall_runtime": {
            "source": "default-allow",
            "source_kind": "default-allow",
            "reload_enabled": False,
            "reload_interval_seconds": 0,
            "last_loaded_at": None,
            "last_error": None,
            "rule_count": 0,
            "default_decision": "allow",
            "enforcement_mode": "enforce",
            "tenant_id": None,
        },
    }


def test_healthz_reports_policy_reload_runtime(tmp_path: Path) -> None:
    policy_path = tmp_path / "gateway-policy.json"
    policy_path.write_text('{"rules":[]}')
    settings = GatewaySettings(
        registry=_simple_registry(),
        policy={},
        policy_path=policy_path,
        policy_reload_interval_seconds=2,
    )
    with TestClient(create_gateway_app(settings)) as client:
        resp = client.get("/healthz")
        assert resp.status_code == 200
        runtime = resp.json()["policy_runtime"]
        assert runtime["source"] == str(policy_path)
        assert runtime["source_kind"] == "file"
        assert runtime["reload_enabled"] is True
        assert runtime["reload_interval_seconds"] == 2
        assert runtime["last_loaded_at"] is not None
        assert runtime["last_error"] is None
        assert runtime["rollout_mode"] == "disabled"


def test_healthz_reports_policy_rollout_summary_for_advisory_rules() -> None:
    settings = GatewaySettings(
        registry=_simple_registry(),
        policy={"rules": [{"id": "warn-secret", "block_secret_paths": True}]},
    )
    client = TestClient(create_gateway_app(settings))
    resp = client.get("/healthz")
    runtime = resp.json()["policy_runtime"]
    assert runtime["rollout_mode"] == "advisory_only"
    assert runtime["blocks_requests"] is False
    assert runtime["advisory_only"] is True
    assert runtime["protects_secret_paths"] is True


def test_healthz_reports_policy_rollout_summary_for_default_deny() -> None:
    settings = GatewaySettings(
        registry=_simple_registry(),
        policy={"rules": [{"id": "allow-read", "mode": "allowlist", "action": "block", "allow_tools": ["read_file"]}]},
    )
    client = TestClient(create_gateway_app(settings))
    resp = client.get("/healthz")
    runtime = resp.json()["policy_runtime"]
    assert runtime["rollout_mode"] == "default_deny"
    assert runtime["blocks_requests"] is True
    assert runtime["default_deny"] is True
    assert runtime["allowlist_rules"] == 1


def test_healthz_reports_visual_leak_readiness_when_enabled(monkeypatch) -> None:
    monkeypatch.setattr(
        "agent_bom.runtime.visual_leak_detector.visual_leak_runtime_health",
        lambda: {"enabled": True, "ready": True, "mode": "enforcing", "reason": None},
    )
    settings = GatewaySettings(
        registry=_simple_registry(),
        policy={},
        enable_visual_leak_detection=True,
        require_visual_leak_detection_ready=False,
    )
    client = TestClient(create_gateway_app(settings))
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["visual_leak_detection"] == {
        "enabled": True,
        "ready": True,
        "mode": "enforcing",
        "reason": None,
        "required": False,
    }


def test_metrics_endpoint_returns_prometheus_text_format() -> None:
    """Guard: /metrics must be plain Prometheus exposition, not a JSON-quoted string.

    Prometheus scrapers fail on a JSON-wrapped body ("# HELP..." — quoted
    string with escaped \\n). Must be raw text starting with `# HELP`.
    """
    settings = GatewaySettings(registry=_simple_registry(), policy={})
    client = TestClient(create_gateway_app(settings))
    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    body = resp.text
    # Raw text — never a JSON-quoted string
    assert not body.startswith('"'), "body is JSON-quoted; Prometheus scrapers will reject"
    assert body.startswith("# HELP"), f"expected Prometheus exposition, got: {body[:80]!r}"
    # Contains the gateway-specific series
    assert "agent_bom_gateway_relays_total" in body


def test_relay_forwards_to_upstream_and_returns_response() -> None:
    upstream_calls: list[dict[str, Any]] = []

    async def fake_caller(upstream, message, extra_headers):
        upstream_calls.append({"name": upstream.name, "url": upstream.url, "message": message})
        return {
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {"content": [{"type": "text", "text": "ok"}]},
        }

    settings = GatewaySettings(
        registry=_simple_registry(),
        policy={},
        upstream_caller=fake_caller,
    )
    client = TestClient(create_gateway_app(settings))
    resp = client.post(
        "/mcp/filesystem",
        json=_json_rpc("tools/call", name="read_file", arguments={"path": "/etc/hosts"}),
    )
    assert resp.status_code == 200
    assert resp.json()["result"]["content"][0]["text"] == "ok"
    assert upstream_calls[0]["name"] == "filesystem"
    assert upstream_calls[0]["url"] == "http://fs.local:8100"


def test_relay_propagates_trace_context_to_headers_and_jsonrpc_meta() -> None:
    upstream_calls: list[dict[str, Any]] = []

    async def fake_caller(upstream, message, extra_headers):
        upstream_calls.append({"message": message, "headers": dict(extra_headers)})
        return {
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {"content": [{"type": "text", "text": "ok"}]},
        }

    settings = GatewaySettings(
        registry=_simple_registry(),
        policy={},
        upstream_caller=fake_caller,
    )
    client = TestClient(create_gateway_app(settings))
    resp = client.post(
        "/mcp/filesystem",
        headers={
            "traceparent": "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
            "tracestate": "vendor-a=foo",
            "baggage": "tenant=acme",
        },
        json=_json_rpc("tools/call", name="read_file", arguments={"path": "/etc/hosts"}),
    )

    assert resp.status_code == 200
    call = upstream_calls[0]
    assert call["headers"]["traceparent"].startswith("00-0123456789abcdef0123456789abcdef-")
    assert call["headers"]["traceparent"] != "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"
    assert call["headers"]["tracestate"] == "vendor-a=foo"
    assert call["headers"]["baggage"] == "tenant=acme"
    assert call["message"]["_meta"]["traceparent"] == call["headers"]["traceparent"]
    assert call["message"]["_meta"]["tracestate"] == "vendor-a=foo"
    assert call["message"]["_meta"]["baggage"] == "tenant=acme"
    parsed = parse_traceparent(resp.headers["traceparent"])
    assert parsed is not None
    assert parsed["trace_id"] == "0123456789abcdef0123456789abcdef"
    assert resp.headers["tracestate"] == "vendor-a=foo"
    assert resp.headers["baggage"] == "tenant=acme"


def test_relay_preserves_existing_jsonrpc_meta_fields_when_stitching_trace_context() -> None:
    upstream_calls: list[dict[str, Any]] = []

    async def fake_caller(upstream, message, extra_headers):
        upstream_calls.append({"message": message, "headers": dict(extra_headers)})
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}

    settings = GatewaySettings(registry=_simple_registry(), policy={}, upstream_caller=fake_caller)
    client = TestClient(create_gateway_app(settings))
    resp = client.post(
        "/mcp/filesystem",
        headers={"traceparent": "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"},
        json={
            **_json_rpc("tools/list"),
            "_meta": {"client": "cursor", "traceparent": "old"},
        },
    )

    assert resp.status_code == 200
    meta = upstream_calls[0]["message"]["_meta"]
    assert meta["client"] == "cursor"
    assert meta["traceparent"].startswith("00-0123456789abcdef0123456789abcdef-")
    assert meta["traceparent"] != "old"


def test_relay_requires_gateway_token_when_configured() -> None:
    async def fake_caller(upstream, message, extra_headers):
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}

    settings = GatewaySettings(
        registry=_simple_registry(),
        policy={},
        upstream_caller=fake_caller,
        bearer_token="gw-secret",
    )
    client = TestClient(create_gateway_app(settings))
    denied = client.post(
        "/mcp/filesystem",
        json=_json_rpc("tools/call", name="read_file", arguments={"path": "/etc/hosts"}),
    )
    assert denied.status_code == 401
    assert "authentication required" in denied.json()["detail"]

    allowed = client.post(
        "/mcp/filesystem",
        headers={"Authorization": "Bearer gw-secret"},
        json=_json_rpc("tools/call", name="read_file", arguments={"path": "/etc/hosts"}),
    )
    assert allowed.status_code == 200
    assert allowed.json()["result"]["ok"] is True


def test_relay_accepts_control_plane_api_key_and_applies_tenant(monkeypatch) -> None:
    audit_events: list[dict[str, Any]] = []

    async def fake_caller(upstream, message, extra_headers):
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}

    async def audit_sink(event):
        audit_events.append(event)

    class _FakeKeyStore:
        def has_keys(self) -> bool:
            return True

        def verify(self, raw_key: str):
            if raw_key == "tenant-alpha-key":
                return _gateway_api_key("tenant-alpha")
            return None

    monkeypatch.setattr("agent_bom.gateway_server.get_key_store", lambda: _FakeKeyStore())

    settings = GatewaySettings(
        registry=_simple_registry(),
        policy={},
        upstream_caller=fake_caller,
        audit_sink=audit_sink,
    )
    client = TestClient(create_gateway_app(settings))

    denied = client.post(
        "/mcp/filesystem",
        json=_json_rpc("tools/call", name="read_file", arguments={"path": "/etc/hosts"}),
    )
    assert denied.status_code == 401

    allowed = client.post(
        "/mcp/filesystem",
        headers={"X-API-Key": "tenant-alpha-key"},
        json=_json_rpc("tools/call", name="read_file", arguments={"path": "/etc/hosts"}),
    )
    assert allowed.status_code == 200
    assert allowed.json()["result"]["ok"] is True
    assert audit_events[-1]["tenant_id"] == "tenant-alpha"


def test_relay_fails_closed_when_api_key_store_verification_errors(monkeypatch) -> None:
    upstream_calls: list[dict[str, Any]] = []

    async def fake_caller(upstream, message, extra_headers):
        upstream_calls.append(message)
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}

    class _FakeKeyStore:
        def has_keys(self) -> bool:
            return True

        def verify(self, raw_key: str):
            raise RuntimeError("key store unavailable")

    monkeypatch.setattr("agent_bom.gateway_server.get_key_store", lambda: _FakeKeyStore())

    settings = GatewaySettings(registry=_simple_registry(), policy={}, upstream_caller=fake_caller)
    client = TestClient(create_gateway_app(settings))
    resp = client.post(
        "/mcp/filesystem",
        headers={"X-API-Key": "tenant-alpha-key"},
        json=_json_rpc("tools/call", name="read_file", arguments={"path": "/tmp/x"}),
    )

    assert resp.status_code == 503
    assert resp.json()["detail"] == "gateway authentication unavailable"
    assert upstream_calls == []


def test_relay_rejects_viewer_api_key_before_forwarding(monkeypatch) -> None:
    upstream_calls: list[dict[str, Any]] = []

    async def fake_caller(upstream, message, extra_headers):
        upstream_calls.append(message)
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}

    class _FakeKeyStore:
        def has_keys(self) -> bool:
            return True

        def verify(self, raw_key: str):
            if raw_key == "viewer-key":
                return _gateway_api_key("tenant-alpha", role=Role.VIEWER)
            return None

    monkeypatch.setattr("agent_bom.gateway_server.get_key_store", lambda: _FakeKeyStore())

    settings = GatewaySettings(registry=_simple_registry(), policy={}, upstream_caller=fake_caller)
    client = TestClient(create_gateway_app(settings))
    resp = client.post(
        "/mcp/filesystem",
        headers={"X-API-Key": "viewer-key"},
        json=_json_rpc("tools/call", name="write_file", arguments={"path": "/tmp/x"}),
    )
    assert resp.status_code == 403
    assert "requires analyst role" in resp.json()["detail"]
    assert upstream_calls == []


def test_relay_rejects_api_key_without_gateway_scope(monkeypatch) -> None:
    upstream_calls: list[dict[str, Any]] = []

    async def fake_caller(upstream, message, extra_headers):
        upstream_calls.append(message)
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}

    class _FakeKeyStore:
        def has_keys(self) -> bool:
            return True

        def verify(self, raw_key: str):
            if raw_key == "analyst-no-gateway":
                return SimpleNamespace(
                    tenant_id="tenant-alpha",
                    role=Role.ANALYST,
                    scopes=["scan:read"],
                    has_scope=lambda required: required == "scan:read",
                )
            return None

    monkeypatch.setattr("agent_bom.gateway_server.get_key_store", lambda: _FakeKeyStore())

    settings = GatewaySettings(registry=_simple_registry(), policy={}, upstream_caller=fake_caller)
    client = TestClient(create_gateway_app(settings))
    resp = client.post(
        "/mcp/filesystem",
        headers={"X-API-Key": "analyst-no-gateway"},
        json=_json_rpc("tools/call", name="read_file", arguments={"path": "/tmp/x"}),
    )
    assert resp.status_code == 403
    assert "gateway:relay" in resp.json()["detail"]
    assert upstream_calls == []


def test_relay_routes_same_upstream_name_by_authenticated_tenant(monkeypatch) -> None:
    upstream_calls: list[dict[str, Any]] = []

    async def fake_caller(upstream, message, extra_headers):
        upstream_calls.append({"tenant_id": upstream.tenant_id, "url": upstream.url, "name": upstream.name})
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}

    class _FakeKeyStore:
        def has_keys(self) -> bool:
            return True

        def verify(self, raw_key: str):
            if raw_key == "tenant-alpha-key":
                return _gateway_api_key("tenant-alpha")
            if raw_key == "tenant-beta-key":
                return _gateway_api_key("tenant-beta")
            return None

    monkeypatch.setattr("agent_bom.gateway_server.get_key_store", lambda: _FakeKeyStore())
    registry = UpstreamRegistry(
        [
            UpstreamConfig(name="jira", tenant_id="tenant-alpha", url="https://alpha.example.com/mcp"),
            UpstreamConfig(name="jira", tenant_id="tenant-beta", url="https://beta.example.com/mcp"),
        ]
    )
    settings = GatewaySettings(registry=registry, policy={}, upstream_caller=fake_caller)
    client = TestClient(create_gateway_app(settings))

    alpha = client.post(
        "/mcp/jira",
        headers={"X-API-Key": "tenant-alpha-key"},
        json=_json_rpc("tools/call", name="query_issues", arguments={"jql": "project = ALPHA"}),
    )
    beta = client.post(
        "/mcp/jira",
        headers={"X-API-Key": "tenant-beta-key"},
        json=_json_rpc("tools/call", name="query_issues", arguments={"jql": "project = BETA"}),
    )

    assert alpha.status_code == 200
    assert beta.status_code == 200
    assert upstream_calls == [
        {"tenant_id": "tenant-alpha", "url": "https://alpha.example.com/mcp", "name": "jira"},
        {"tenant_id": "tenant-beta", "url": "https://beta.example.com/mcp", "name": "jira"},
    ]


def test_relay_fails_closed_when_tenant_has_no_matching_upstream(monkeypatch) -> None:
    async def fake_caller(upstream, message, extra_headers):
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}

    class _FakeKeyStore:
        def has_keys(self) -> bool:
            return True

        def verify(self, raw_key: str):
            if raw_key == "tenant-beta-key":
                return _gateway_api_key("tenant-beta")
            return None

    monkeypatch.setattr("agent_bom.gateway_server.get_key_store", lambda: _FakeKeyStore())
    registry = UpstreamRegistry(
        [
            UpstreamConfig(name="jira", tenant_id="tenant-alpha", url="https://alpha.example.com/mcp"),
            UpstreamConfig(name="jira", url="https://legacy-global.example.com/mcp"),
        ]
    )
    settings = GatewaySettings(registry=registry, policy={}, upstream_caller=fake_caller)
    client = TestClient(create_gateway_app(settings))

    denied = client.post(
        "/mcp/jira",
        headers={"X-API-Key": "tenant-beta-key"},
        json=_json_rpc("tools/call", name="query_issues", arguments={"jql": "project = BETA"}),
    )
    assert denied.status_code == 404
    assert denied.json()["detail"] == "unknown upstream 'jira'"


def test_gateway_rate_limit_is_tenant_scoped(monkeypatch) -> None:
    class _FakeKeyStore:
        def has_keys(self) -> bool:
            return True

        def verify(self, raw_key: str):
            if raw_key == "tenant-alpha-key":
                return _gateway_api_key("tenant-alpha")
            if raw_key == "tenant-beta-key":
                return _gateway_api_key("tenant-beta")
            return None

    monkeypatch.setattr("agent_bom.gateway_server.get_key_store", lambda: _FakeKeyStore())

    async def fake_caller(upstream, message, extra_headers):
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}

    settings = GatewaySettings(
        registry=_simple_registry(),
        policy={},
        upstream_caller=fake_caller,
        runtime_rate_limit_per_tenant_per_minute=1,
    )
    client = TestClient(create_gateway_app(settings))

    first = client.post(
        "/mcp/filesystem",
        headers={"X-API-Key": "tenant-alpha-key"},
        json=_json_rpc("tools/call", name="read_file", arguments={"path": "/etc/hosts"}),
    )
    assert first.status_code == 200
    assert first.headers["X-RateLimit-Limit"] == "1"

    second = client.post(
        "/mcp/filesystem",
        headers={"X-API-Key": "tenant-alpha-key"},
        json=_json_rpc("tools/call", name="read_file", arguments={"path": "/etc/hosts"}),
    )
    assert second.status_code == 429
    assert second.json()["detail"] == "Gateway tenant rate limit exceeded"

    other_tenant = client.post(
        "/mcp/filesystem",
        headers={"X-API-Key": "tenant-beta-key"},
        json=_json_rpc("tools/call", name="read_file", arguments={"path": "/etc/hosts"}),
    )
    assert other_tenant.status_code == 200


def test_gateway_rate_limit_shared_store_holds_under_concurrency(monkeypatch) -> None:
    class _FakeKeyStore:
        def has_keys(self) -> bool:
            return True

        def verify(self, raw_key: str):
            if raw_key == "tenant-alpha-key":
                return _gateway_api_key("tenant-alpha")
            return None

    class _ConcurrentSharedStore:
        def __init__(self) -> None:
            self._lock = threading.Lock()
            self._counts: dict[str, int] = {}
            self._arrivals = 0
            self._ready = threading.Event()

        def hit(self, bucket: str, now: float) -> tuple[int, float]:
            with self._lock:
                self._arrivals += 1
                if self._arrivals >= 2:
                    self._ready.set()
            self._ready.wait(timeout=0.5)
            with self._lock:
                count = self._counts.get(bucket, 0) + 1
                self._counts[bucket] = count
            return count, now + 60

        @property
        def counts(self) -> dict[str, int]:
            with self._lock:
                return dict(self._counts)

    monkeypatch.setattr("agent_bom.gateway_server.get_key_store", lambda: _FakeKeyStore())
    shared_store = _ConcurrentSharedStore()
    monkeypatch.setattr("agent_bom.gateway_server._build_gateway_rate_limit_store", lambda _settings: shared_store)

    async def fake_caller(upstream, message, extra_headers):
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}

    settings = GatewaySettings(
        registry=_simple_registry(),
        policy={},
        upstream_caller=fake_caller,
        runtime_rate_limit_per_tenant_per_minute=1,
    )
    with TestClient(create_gateway_app(settings)) as client:

        def _post() -> int:
            response = client.post(
                "/mcp/filesystem",
                headers={"X-API-Key": "tenant-alpha-key"},
                json=_json_rpc("tools/call", name="read_file", arguments={"path": "/etc/hosts"}),
            )
            return response.status_code

        with ThreadPoolExecutor(max_workers=2) as executor:
            statuses = list(executor.map(lambda _idx: _post(), range(2)))

    assert sorted(statuses) == [200, 429]
    assert shared_store.counts == {"gateway:tenant:tenant-alpha": 2}


def test_gateway_rate_limit_can_require_shared_backend(monkeypatch) -> None:
    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    monkeypatch.setenv("AGENT_BOM_GATEWAY_REPLICAS", "2")

    settings = GatewaySettings(
        registry=_simple_registry(),
        policy={},
        runtime_rate_limit_per_tenant_per_minute=10,
    )
    try:
        try:
            create_gateway_app(settings)
        except RuntimeError as exc:
            assert "Shared gateway rate limiting is required" in str(exc)
        else:
            raise AssertionError("expected create_gateway_app to fail closed without shared backend")
    finally:
        monkeypatch.delenv("AGENT_BOM_GATEWAY_REPLICAS", raising=False)


# ─── Policy block ─────────────────────────────────────────────────────────


def test_relay_blocks_tool_by_policy() -> None:
    upstream_calls: list[dict[str, Any]] = []
    audit_events: list[dict[str, Any]] = []

    async def fake_caller(upstream, message, extra_headers):
        upstream_calls.append(message)
        return {}

    async def audit_sink(event):
        audit_events.append(event)

    # block_tools rule — the exact shape proxy.check_policy understands
    policy = {
        "rules": [
            {
                "id": "no-shell",
                "action": "block",
                "block_tools": ["run_shell"],
            }
        ]
    }
    settings = GatewaySettings(
        registry=_simple_registry(),
        policy=policy,
        upstream_caller=fake_caller,
        audit_sink=audit_sink,
    )
    client = TestClient(create_gateway_app(settings))
    resp = client.post(
        "/mcp/filesystem",
        json=_json_rpc("tools/call", name="run_shell", arguments={"command": "rm -rf /"}),
    )

    assert resp.status_code == 200
    body = resp.json()
    assert "error" in body
    assert body["error"]["code"] == -32001
    assert "Blocked by agent-bom gateway policy" in body["error"]["message"]
    # Blocked tool must NOT reach the upstream
    assert upstream_calls == []
    # And the audit trail must record the block with the tool name + reason
    assert len(audit_events) == 1
    assert audit_events[0]["action"] == "gateway.policy_blocked"
    assert audit_events[0]["method"] == "tools/call"
    assert audit_events[0]["tool"] == "run_shell"
    assert "no-shell" in (audit_events[0]["reason"] or "")


def test_relay_allows_tool_not_in_blocklist() -> None:
    async def fake_caller(upstream, message, extra_headers):
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}

    policy = {
        "rules": [
            {"id": "no-shell", "action": "block", "block_tools": ["run_shell"]},
        ]
    }
    settings = GatewaySettings(
        registry=_simple_registry(),
        policy=policy,
        upstream_caller=fake_caller,
    )
    client = TestClient(create_gateway_app(settings))
    resp = client.post(
        "/mcp/jira",
        json=_json_rpc("tools/call", name="query_issues", arguments={"jql": "project = ACME"}),
    )
    assert resp.status_code == 200


def test_gateway_hot_reload_updates_policy_without_restart(tmp_path: Path) -> None:
    policy_path = tmp_path / "gateway-policy.json"
    policy_path.write_text(json.dumps({"rules": [{"id": "no-shell", "action": "block", "block_tools": ["run_shell"]}]}))

    async def fake_caller(upstream, message, extra_headers):
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}

    settings = GatewaySettings(
        registry=_simple_registry(),
        policy={},
        upstream_caller=fake_caller,
        policy_path=policy_path,
        policy_reload_interval_seconds=1,
    )
    with TestClient(create_gateway_app(settings)) as client:
        blocked = client.post(
            "/mcp/filesystem",
            json=_json_rpc("tools/call", name="run_shell", arguments={"command": "whoami"}),
        )
        assert blocked.status_code == 200
        assert blocked.json()["error"]["code"] == -32001

        time.sleep(1.1)
        policy_path.write_text(json.dumps({"rules": []}))
        time.sleep(1.2)

        allowed = client.post(
            "/mcp/filesystem",
            json=_json_rpc("tools/call", name="run_shell", arguments={"command": "whoami"}),
        )
        assert allowed.status_code == 200
        assert allowed.json()["result"]["ok"] is True


def test_gateway_hot_reload_tolerates_policy_file_removed_mid_reload(tmp_path: Path) -> None:
    policy_path = tmp_path / "gateway-policy.json"
    policy_path.write_text(json.dumps({"rules": []}))

    async def fake_caller(upstream, message, extra_headers):
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}

    settings = GatewaySettings(
        registry=_simple_registry(),
        policy={},
        upstream_caller=fake_caller,
        policy_path=policy_path,
        policy_reload_interval_seconds=1,
    )
    with TestClient(create_gateway_app(settings)) as client:
        healthy = client.get("/healthz")
        assert healthy.status_code == 200
        assert healthy.json()["policy_runtime"]["last_error"] is None

        policy_path.unlink()
        time.sleep(1.2)

        reloaded = client.get("/healthz")
        assert reloaded.status_code == 200
        assert "No such file or directory" in (reloaded.json()["policy_runtime"]["last_error"] or "")


# ─── Error cases ──────────────────────────────────────────────────────────


def test_relay_unknown_upstream_returns_404() -> None:
    settings = GatewaySettings(registry=_simple_registry(), policy={})
    client = TestClient(create_gateway_app(settings))
    resp = client.post(
        "/mcp/nonexistent",
        json=_json_rpc("tools/call", name="x", arguments={}),
    )
    assert resp.status_code == 404
    assert "unknown upstream 'nonexistent'" in resp.json()["detail"]


def test_relay_non_json_rpc_body_returns_400() -> None:
    settings = GatewaySettings(registry=_simple_registry(), policy={})
    client = TestClient(create_gateway_app(settings))
    resp = client.post(
        "/mcp/filesystem",
        json={"hello": "world"},  # no jsonrpc envelope
    )
    assert resp.status_code == 400


def test_relay_upstream_error_surfaces_as_502_and_is_audited() -> None:
    audit_events: list[dict[str, Any]] = []

    async def failing_caller(upstream, message, extra_headers):
        raise RuntimeError("boom")

    async def audit_sink(event):
        audit_events.append(event)

    settings = GatewaySettings(
        registry=_simple_registry(),
        policy={},
        upstream_caller=failing_caller,
        audit_sink=audit_sink,
    )
    client = TestClient(create_gateway_app(settings))
    resp = client.post(
        "/mcp/filesystem",
        json=_json_rpc("tools/call", name="read_file", arguments={"path": "/tmp/x"}),
    )
    assert resp.status_code == 502
    assert "boom" in resp.json()["detail"]
    assert any(e["action"] == "gateway.upstream_error" for e in audit_events)


def test_relay_upstream_timeout_surfaces_as_502_and_is_audited() -> None:
    audit_events: list[dict[str, Any]] = []

    async def timing_out_caller(upstream, message, extra_headers):
        raise asyncio.TimeoutError()

    async def audit_sink(event):
        audit_events.append(event)

    settings = GatewaySettings(
        registry=_simple_registry(),
        policy={},
        upstream_caller=timing_out_caller,
        audit_sink=audit_sink,
    )
    client = TestClient(create_gateway_app(settings))
    resp = client.post(
        "/mcp/filesystem",
        json=_json_rpc("tools/call", name="read_file", arguments={"path": "/tmp/x"}),
    )
    assert resp.status_code == 502
    assert resp.json()["detail"] == "upstream error: timeout"
    assert audit_events == [
        {
            "action": "gateway.upstream_error",
            "upstream": "filesystem",
            "tenant_id": "default",
            "error": "timeout",
            "reason": "timeout",
        }
    ]


def test_managed_upstream_relay_opens_circuit_after_repeated_failures() -> None:
    class _FailingResponse:
        content = b'{"error":"boom"}'
        headers = {"content-type": "application/json"}

        def raise_for_status(self) -> None:
            raise RuntimeError("upstream down")

    class _FakeClient:
        def __init__(self) -> None:
            self.posts = 0

        async def post(self, *_args, **_kwargs):
            self.posts += 1
            return _FailingResponse()

        async def aclose(self) -> None:
            pass

    async def _exercise() -> int:
        relay = GatewayUpstreamRelay(
            GatewaySettings(
                registry=_simple_registry(),
                policy={},
                upstream_failure_threshold=2,
                upstream_circuit_cooldown_seconds=30,
            )
        )
        fake_client = _FakeClient()
        relay._client = fake_client
        upstream = UpstreamConfig(name="filesystem", url="http://fs.local:8100")
        message = _json_rpc("tools/call", name="read_file", arguments={"path": "/tmp/a"})

        for _ in range(2):
            try:
                await relay(upstream, message, {})
            except RuntimeError:
                pass
        try:
            await relay(upstream, message, {})
        except Exception as exc:  # noqa: BLE001
            assert "circuit open" in str(exc)
        return fake_client.posts

    assert asyncio.run(_exercise()) == 2


def test_relay_returns_503_when_managed_circuit_is_open() -> None:
    async def circuit_open_caller(upstream, message, extra_headers):
        from agent_bom.gateway_server import GatewayCircuitOpenError

        raise GatewayCircuitOpenError(upstream.name, 12)

    audit_events: list[dict[str, Any]] = []

    async def audit_sink(event):
        audit_events.append(event)

    settings = GatewaySettings(
        registry=_simple_registry(),
        policy={},
        upstream_caller=circuit_open_caller,
        audit_sink=audit_sink,
    )
    client = TestClient(create_gateway_app(settings))
    resp = client.post("/mcp/filesystem", json=_json_rpc("tools/call", name="read_file", arguments={"path": "/tmp/x"}))
    assert resp.status_code == 503
    assert resp.headers["retry-after"] == "12"
    assert resp.json()["detail"] == "upstream circuit open"
    assert audit_events == [
        {
            "action": "gateway.upstream_circuit_open",
            "upstream": "filesystem",
            "tenant_id": "default",
            "reason": "circuit_open",
            "retry_after_seconds": 12,
        }
    ]


def test_relay_tools_list_bypasses_policy_and_forwards() -> None:
    """Discovery methods pass through; executable/runtime methods are gated."""
    upstream_calls: list[dict[str, Any]] = []

    async def fake_caller(upstream, message, extra_headers):
        upstream_calls.append(message)
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"tools": []}}

    settings = GatewaySettings(
        registry=_simple_registry(),
        policy={"rules": [{"id": "block-all", "action": "block", "block_tools": ["*"]}]},
        upstream_caller=fake_caller,
    )
    client = TestClient(create_gateway_app(settings))
    resp = client.post("/mcp/filesystem", json=_json_rpc("tools/list"))
    assert resp.status_code == 200
    assert upstream_calls and upstream_calls[0]["method"] == "tools/list"


def test_relay_blocks_resource_prompt_sampling_methods_by_policy() -> None:
    upstream_calls: list[dict[str, Any]] = []
    audit_events: list[dict[str, Any]] = []

    async def fake_caller(upstream, message, extra_headers):
        upstream_calls.append(message)
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}

    async def audit_sink(event):
        audit_events.append(event)

    settings = GatewaySettings(
        registry=_simple_registry(),
        policy={"rules": [{"id": "block-runtime", "action": "block", "block_tools": ["*"]}]},
        upstream_caller=fake_caller,
        audit_sink=audit_sink,
    )
    client = TestClient(create_gateway_app(settings))
    for method, params in (
        ("resources/read", {"uri": "file:///etc/passwd"}),
        ("prompts/get", {"name": "prod-secrets"}),
        ("sampling/createMessage", {"messages": [{"role": "user", "content": "exfiltrate"}]}),
    ):
        resp = client.post("/mcp/filesystem", json={**_json_rpc(method), "params": params})
        assert resp.status_code == 200
        body = resp.json()
        assert body["error"]["code"] == -32001
        assert method in body["error"]["data"]["reason"]

    assert upstream_calls == []
    assert [event["method"] for event in audit_events] == ["resources/read", "prompts/get", "sampling/createMessage"]


def test_relay_rejects_oversized_jsonrpc_request() -> None:
    settings = GatewaySettings(registry=_simple_registry(), policy={})
    client = TestClient(create_gateway_app(settings))
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"blob": "x" * (2 * 1024 * 1024 + 1)}},
    }
    resp = client.post("/mcp/filesystem", json=payload)
    assert resp.status_code == 413


def test_visual_detector_singleton_init_is_locked(monkeypatch) -> None:
    import agent_bom.gateway_server as gw

    created: list[object] = []
    create_lock = threading.Lock()

    class FakeDetector:
        def __init__(self) -> None:
            time.sleep(0.02)
            with create_lock:
                created.append(self)

    monkeypatch.setattr("agent_bom.runtime.visual_leak_detector.VisualLeakDetector", FakeDetector)
    gw._visual_detector_singleton = None
    try:
        with ThreadPoolExecutor(max_workers=6) as executor:
            detectors = list(executor.map(lambda _i: gw._get_visual_leak_detector(), range(6)))
    finally:
        gw._visual_detector_singleton = None

    assert len(created) == 1
    assert all(detector is created[0] for detector in detectors)


# ─── Visual-leak detection wire-up ─────────────────────────────────────────


class _StubVisualDetector:
    """Stand-in for VisualLeakDetector that avoids pulling OCR deps in CI.

    The real detector is exercised in tests/test_visual_leak_detector.py;
    here we only need to prove the gateway calls ``check`` + ``redact`` on
    the response content when the feature flag is on.
    """

    def __init__(self, alert: object | None) -> None:
        self._alert = alert
        self.check_calls: list[tuple[str, list]] = []
        self.redact_calls: list[list] = []
        self.enabled = True

    def check(self, tool_name, content_blocks):
        self.check_calls.append((tool_name, content_blocks))
        return [self._alert] if self._alert is not None else []

    def redact(self, content_blocks):
        self.redact_calls.append(content_blocks)
        return [{"type": "image", "data": "REDACTED", "mimeType": "image/png"}]


def test_visual_leak_detection_off_by_default_no_scan() -> None:
    """Feature flag is opt-in — default deploys must not invoke the detector."""
    import agent_bom.gateway_server as gw

    detector = _StubVisualDetector(alert=None)
    # If the gateway calls _get_visual_leak_detector when the flag is off,
    # the stub gets populated — assert that does not happen.
    gw._visual_detector_singleton = detector

    async def fake_caller(upstream, message, extra_headers):
        return {
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {"content": [{"type": "image", "data": "AAA", "mimeType": "image/png"}]},
        }

    try:
        settings = GatewaySettings(registry=_simple_registry(), policy={}, upstream_caller=fake_caller)
        client = TestClient(create_gateway_app(settings))
        resp = client.post(
            "/mcp/filesystem",
            json=_json_rpc("tools/call", name="take_screenshot", arguments={}),
        )
        assert resp.status_code == 200
        assert detector.check_calls == []
        assert detector.redact_calls == []
    finally:
        gw._visual_detector_singleton = None


def test_visual_leak_detection_scans_and_redacts_image_content() -> None:
    """With the flag on and alerts found, the response must be redacted + audited."""
    import agent_bom.gateway_server as gw
    from agent_bom.runtime.detectors import Alert, AlertSeverity

    alert = Alert(
        detector="visual_credential_leak",
        severity=AlertSeverity.CRITICAL,
        message="visual AWS key",
        details={"leak_type": "AWS Access Key", "bbox": [0, 0, 10, 10]},
    )
    detector = _StubVisualDetector(alert=alert)
    gw._visual_detector_singleton = detector

    audit_events: list[dict] = []

    async def audit_sink(event):
        audit_events.append(event)

    async def fake_caller(upstream, message, extra_headers):
        return {
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {
                "content": [{"type": "image", "data": "ORIGINAL", "mimeType": "image/png"}],
            },
        }

    try:
        settings = GatewaySettings(
            registry=_simple_registry(),
            policy={},
            upstream_caller=fake_caller,
            audit_sink=audit_sink,
            enable_visual_leak_detection=True,
        )
        client = TestClient(create_gateway_app(settings))
        resp = client.post(
            "/mcp/filesystem",
            json=_json_rpc("tools/call", name="take_screenshot", arguments={}),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["result"]["content"][0]["data"] == "REDACTED"
        assert detector.check_calls and detector.check_calls[0][0] == "take_screenshot"
        assert detector.redact_calls, "redact must fire when alerts are present"

        leak_events = [e for e in audit_events if e["action"] == "gateway.visual_leak_blocked"]
        assert leak_events, "audit sink must receive a gateway.visual_leak_blocked event"
        assert leak_events[0]["tool"] == "take_screenshot"
        assert leak_events[0]["alert_count"] == 1
    finally:
        gw._visual_detector_singleton = None


def test_visual_leak_detection_clean_response_passes_through() -> None:
    """Clean scans must not redact the response or emit a leak audit event."""
    import agent_bom.gateway_server as gw

    detector = _StubVisualDetector(alert=None)
    gw._visual_detector_singleton = detector

    audit_events: list[dict] = []

    async def audit_sink(event):
        audit_events.append(event)

    async def fake_caller(upstream, message, extra_headers):
        return {
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {"content": [{"type": "image", "data": "CLEAN", "mimeType": "image/png"}]},
        }

    try:
        settings = GatewaySettings(
            registry=_simple_registry(),
            policy={},
            upstream_caller=fake_caller,
            audit_sink=audit_sink,
            enable_visual_leak_detection=True,
        )
        client = TestClient(create_gateway_app(settings))
        resp = client.post(
            "/mcp/filesystem",
            json=_json_rpc("tools/call", name="take_screenshot", arguments={}),
        )
        assert resp.status_code == 200
        body = resp.json()
        # Clean content passes through unchanged (no redact call)
        assert body["result"]["content"][0]["data"] == "CLEAN"
        assert detector.check_calls, "check must fire when the flag is on"
        assert detector.redact_calls == [], "redact must not fire without alerts"
        assert not any(e["action"] == "gateway.visual_leak_blocked" for e in audit_events)
    finally:
        gw._visual_detector_singleton = None


def test_visual_leak_detection_timeout_fails_open_without_blocking_response(monkeypatch) -> None:
    import agent_bom.gateway_server as gw

    class _SlowDetector:
        enabled = True

        def check(self, tool_name, content_blocks):
            time.sleep(0.05)
            return []

        def redact(self, content_blocks):
            return content_blocks

    detector = _SlowDetector()
    gw._visual_detector_singleton = detector
    monkeypatch.setenv("AGENT_BOM_VISUAL_LEAK_TIMEOUT_SECONDS", "0.001")

    async def fake_caller(upstream, message, extra_headers):
        return {
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {"content": [{"type": "image", "data": "CLEAN", "mimeType": "image/png"}]},
        }

    try:
        settings = GatewaySettings(
            registry=_simple_registry(),
            policy={},
            upstream_caller=fake_caller,
            enable_visual_leak_detection=True,
        )
        client = TestClient(create_gateway_app(settings))
        resp = client.post(
            "/mcp/filesystem",
            json=_json_rpc("tools/call", name="take_screenshot", arguments={}),
        )
        assert resp.status_code == 200
        assert resp.json()["result"]["content"][0]["data"] == "CLEAN"
    finally:
        gw._visual_detector_singleton = None
