"""Gateway firewall evaluator + audit integration (#982 PR 2)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from agent_bom.gateway_server import GatewaySettings, create_gateway_app
from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry


def _registry() -> UpstreamRegistry:
    return UpstreamRegistry(
        [
            UpstreamConfig(name="filesystem", url="http://fs.local:8100"),
            UpstreamConfig(name="jira", url="http://jira.local:8200"),
        ]
    )


def _write_policy(path: Path, **overrides: Any) -> Path:
    payload: dict[str, Any] = {
        "version": 1,
        "rules": [],
    }
    payload.update(overrides)
    path.write_text(json.dumps(payload))
    return path


class _AuditCapture:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    async def __call__(self, event: dict[str, Any]) -> None:
        self.events.append(event)


def test_firewall_check_default_allows_when_no_policy_loaded() -> None:
    settings = GatewaySettings(registry=_registry(), policy={})
    audit = _AuditCapture()
    settings = GatewaySettings(registry=_registry(), policy={}, audit_sink=audit)
    with TestClient(create_gateway_app(settings)) as client:
        resp = client.post(
            "/v1/firewall/check",
            json={"source_agent": "cursor", "target_agent": "claude-desktop"},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "allow"
    assert body["effective_decision"] == "allow"
    assert body["matched_rule"] is None
    assert body["policy"]["source"] == "default-allow"
    # Allow path emits no audit event.
    assert audit.events == []


def test_firewall_check_loads_file_and_denies(tmp_path: Path) -> None:
    policy_path = _write_policy(
        tmp_path / "fw.json",
        rules=[
            {
                "source": "cursor",
                "target": "snowflake-cli",
                "decision": "deny",
                "description": "no direct DB",
            }
        ],
    )
    audit = _AuditCapture()
    settings = GatewaySettings(
        registry=_registry(),
        policy={},
        firewall_policy_path=policy_path,
        audit_sink=audit,
    )
    with TestClient(create_gateway_app(settings)) as client:
        resp = client.post(
            "/v1/firewall/check",
            json={"source_agent": "cursor", "target_agent": "snowflake-cli"},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "deny"
    assert body["effective_decision"] == "deny"
    assert body["matched_rule"]["description"] == "no direct DB"
    assert body["policy"]["source"] == str(policy_path)

    # Audit event emitted for non-allow decision.
    assert len(audit.events) == 1
    event = audit.events[0]
    assert event["action"] == "gateway.firewall_decision"
    assert event["decision"] == "deny"
    assert event["effective_decision"] == "deny"
    assert event["source_agent"] == "cursor"
    assert event["target_agent"] == "snowflake-cli"


def test_firewall_check_dry_run_downgrades_deny_to_warn(tmp_path: Path) -> None:
    policy_path = _write_policy(
        tmp_path / "fw.json",
        enforcement_mode="dry_run",
        rules=[
            {"source": "cursor", "target": "snowflake-cli", "decision": "deny"},
        ],
    )
    audit = _AuditCapture()
    settings = GatewaySettings(
        registry=_registry(),
        policy={},
        firewall_policy_path=policy_path,
        audit_sink=audit,
    )
    with TestClient(create_gateway_app(settings)) as client:
        resp = client.post(
            "/v1/firewall/check",
            json={"source_agent": "cursor", "target_agent": "snowflake-cli"},
        )
    assert resp.status_code == 200
    body = resp.json()
    # Matched decision stays as authored; effective drops to warn under dry-run.
    assert body["decision"] == "deny"
    assert body["effective_decision"] == "warn"
    # Audit fires on any non-allow effective decision.
    assert len(audit.events) == 1
    assert audit.events[0]["effective_decision"] == "warn"
    assert audit.events[0]["enforcement_mode"] == "dry_run"


def test_firewall_check_role_tags_match(tmp_path: Path) -> None:
    policy_path = _write_policy(
        tmp_path / "fw.json",
        rules=[
            {"source": "role:trusted", "target": "role:data-plane", "decision": "allow"},
            {"source": "*", "target": "role:data-plane", "decision": "deny"},
        ],
    )
    settings = GatewaySettings(
        registry=_registry(),
        policy={},
        firewall_policy_path=policy_path,
    )
    with TestClient(create_gateway_app(settings)) as client:
        # Trusted source -> data-plane -> allow (more specific role wins).
        resp = client.post(
            "/v1/firewall/check",
            json={
                "source_agent": "cursor",
                "target_agent": "snowflake-cli",
                "source_roles": ["trusted"],
                "target_roles": ["data-plane"],
            },
        )
        assert resp.json()["effective_decision"] == "allow"

        # Untrusted source -> data-plane -> deny via wildcard rule.
        resp = client.post(
            "/v1/firewall/check",
            json={
                "source_agent": "untrusted-bot",
                "target_agent": "snowflake-cli",
                "target_roles": ["data-plane"],
            },
        )
        assert resp.json()["effective_decision"] == "deny"


def test_firewall_check_warn_decision_emits_audit_without_blocking(tmp_path: Path) -> None:
    policy_path = _write_policy(
        tmp_path / "fw.json",
        rules=[
            {"source": "cursor", "target": "claude-desktop", "decision": "warn"},
        ],
    )
    audit = _AuditCapture()
    settings = GatewaySettings(
        registry=_registry(),
        policy={},
        firewall_policy_path=policy_path,
        audit_sink=audit,
    )
    with TestClient(create_gateway_app(settings)) as client:
        resp = client.post(
            "/v1/firewall/check",
            json={"source_agent": "cursor", "target_agent": "claude-desktop"},
        )
    assert resp.status_code == 200
    assert resp.json()["effective_decision"] == "warn"
    assert len(audit.events) == 1


def test_firewall_check_invalid_payload() -> None:
    settings = GatewaySettings(registry=_registry(), policy={})
    with TestClient(create_gateway_app(settings)) as client:
        resp = client.post("/v1/firewall/check", json={"source_agent": "cursor"})
    assert resp.status_code == 400
    assert "target_agent" in resp.json()["detail"]


def test_firewall_check_invalid_role_types() -> None:
    settings = GatewaySettings(registry=_registry(), policy={})
    with TestClient(create_gateway_app(settings)) as client:
        resp = client.post(
            "/v1/firewall/check",
            json={
                "source_agent": "a",
                "target_agent": "b",
                "source_roles": [1, 2],
            },
        )
    assert resp.status_code == 400
    assert "source_roles" in resp.json()["detail"]


def test_healthz_surfaces_firewall_runtime_when_file_loaded(tmp_path: Path) -> None:
    policy_path = _write_policy(
        tmp_path / "fw.json",
        tenant_id="acme",
        enforcement_mode="dry_run",
        rules=[{"source": "*", "target": "role:data-plane", "decision": "deny"}],
    )
    settings = GatewaySettings(
        registry=_registry(),
        policy={},
        firewall_policy_path=policy_path,
        firewall_policy_reload_interval_seconds=2,
    )
    with TestClient(create_gateway_app(settings)) as client:
        resp = client.get("/healthz")
        runtime = resp.json()["firewall_runtime"]
    assert runtime["source"] == str(policy_path)
    assert runtime["source_kind"] == "file"
    assert runtime["reload_enabled"] is True
    assert runtime["reload_interval_seconds"] == 2
    assert runtime["last_loaded_at"] is not None
    assert runtime["last_error"] is None
    assert runtime["rule_count"] == 1
    assert runtime["enforcement_mode"] == "dry_run"
    assert runtime["tenant_id"] == "acme"


def test_firewall_invalid_policy_file_keeps_default_allow(tmp_path: Path) -> None:
    # File present but malformed -> gateway must not crash; it falls back to
    # the default-allow policy (already initialised) and surfaces last_error.
    policy_path = tmp_path / "fw.json"
    policy_path.write_text("{not json")
    settings = GatewaySettings(
        registry=_registry(),
        policy={},
        firewall_policy_path=policy_path,
    )
    with TestClient(create_gateway_app(settings)) as client:
        resp = client.get("/healthz")
        runtime = resp.json()["firewall_runtime"]
        assert runtime["last_error"] is not None
        assert runtime["rule_count"] == 0

        # Decision endpoint still works — falls through to default allow.
        decision = client.post(
            "/v1/firewall/check",
            json={"source_agent": "a", "target_agent": "b"},
        )
        assert decision.status_code == 200
        assert decision.json()["effective_decision"] == "allow"


def test_firewall_check_invalid_json_body() -> None:
    settings = GatewaySettings(registry=_registry(), policy={})
    with TestClient(create_gateway_app(settings)) as client:
        resp = client.post("/v1/firewall/check", content=b"{not json", headers={"content-type": "application/json"})
    assert resp.status_code == 400


# ── P1-20 v0.86.5 audit: bearer token gates /v1/firewall/check + /metrics ──────


def test_p1_20_firewall_check_requires_bearer_when_configured() -> None:
    settings = GatewaySettings(registry=_registry(), policy={}, bearer_token="s3cr3t")  # noqa: S106
    with TestClient(create_gateway_app(settings)) as client:
        # Missing auth -> 401 envelope from the gateway.
        unauth = client.post(
            "/v1/firewall/check",
            json={"source_agent": "cursor", "target_agent": "claude-desktop"},
        )
        assert unauth.status_code == 401

        # Wrong bearer -> 401.
        bad = client.post(
            "/v1/firewall/check",
            json={"source_agent": "cursor", "target_agent": "claude-desktop"},
            headers={"Authorization": "Bearer wrong"},
        )
        assert bad.status_code == 401

        # Correct bearer -> 200.
        ok = client.post(
            "/v1/firewall/check",
            json={"source_agent": "cursor", "target_agent": "claude-desktop"},
            headers={"Authorization": "Bearer s3cr3t"},
        )
        assert ok.status_code == 200


def test_p1_20_metrics_requires_bearer_when_configured() -> None:
    settings = GatewaySettings(registry=_registry(), policy={}, bearer_token="s3cr3t")  # noqa: S106
    with TestClient(create_gateway_app(settings)) as client:
        unauth = client.get("/metrics")
        assert unauth.status_code == 401
        ok = client.get("/metrics", headers={"Authorization": "Bearer s3cr3t"})
        assert ok.status_code == 200
        assert ok.headers["content-type"].startswith("text/plain")


def test_p1_20_metrics_remains_open_when_no_auth_configured() -> None:
    """When no bearer token + no API key store, /metrics stays open (loopback)."""
    settings = GatewaySettings(registry=_registry(), policy={})
    with TestClient(create_gateway_app(settings)) as client:
        resp = client.get("/metrics")
    assert resp.status_code == 200


# ── #982 PR 2: firewall enforced IN the /mcp relay data path (not just check) ──


def _relay_message() -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {"path": "/etc/hosts"},
            "_meta": {"agent_identity": "tok-cursor"},
        },
    }


def _relay_settings(policy_path: Path | None, audit: _AuditCapture) -> GatewaySettings:
    async def ok_caller(upstream, message, extra_headers):  # type: ignore[no-untyped-def]
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}

    return GatewaySettings(
        registry=_registry(),
        # Map the identity token to an agent_id so the firewall sees a real source.
        policy={"agent_tokens": {"tok-cursor": "cursor"}},
        firewall_policy_path=policy_path,
        upstream_caller=ok_caller,
        audit_sink=audit,
    )


def test_relay_firewall_denies_in_data_path(tmp_path: Path) -> None:
    # A deny rule for cursor -> filesystem must block the relay itself, not
    # merely the advisory /v1/firewall/check endpoint.
    policy_path = _write_policy(
        tmp_path / "fw.json",
        rules=[{"source": "cursor", "target": "filesystem", "decision": "deny", "description": "no fs"}],
    )
    audit = _AuditCapture()
    with TestClient(create_gateway_app(_relay_settings(policy_path, audit))) as client:
        resp = client.post("/mcp/filesystem", json=_relay_message())
    assert resp.status_code == 200
    body = resp.json()
    # Fails closed as a JSON-RPC error — upstream never reached (caller returns result).
    assert "result" not in body
    assert body["error"]["code"] == -32001
    assert body["error"]["message"] == "Blocked by agent-bom gateway inter-agent firewall"
    assert body["error"]["data"]["policy_source"] == "firewall"
    blocked = [e for e in audit.events if e["action"] == "gateway.firewall_blocked"]
    assert len(blocked) == 1
    assert blocked[0]["source_agent"] == "cursor"
    assert blocked[0]["target_agent"] == "filesystem"
    assert blocked[0]["effective_decision"] == "deny"


def test_relay_firewall_allows_non_matching_target(tmp_path: Path) -> None:
    # Deny rule targets filesystem; a call to jira must pass (default allow).
    policy_path = _write_policy(
        tmp_path / "fw.json",
        rules=[{"source": "cursor", "target": "filesystem", "decision": "deny"}],
    )
    audit = _AuditCapture()
    with TestClient(create_gateway_app(_relay_settings(policy_path, audit))) as client:
        resp = client.post("/mcp/jira", json=_relay_message())
    assert resp.status_code == 200
    assert resp.json()["result"] == {"ok": True}
    assert [e for e in audit.events if e["action"].startswith("gateway.firewall")] == []


def test_relay_firewall_no_policy_configured_is_no_op(tmp_path: Path) -> None:
    # No firewall_policy_path => firewall is never consulted in the relay.
    audit = _AuditCapture()
    with TestClient(create_gateway_app(_relay_settings(None, audit))) as client:
        resp = client.post("/mcp/filesystem", json=_relay_message())
    assert resp.status_code == 200
    assert resp.json()["result"] == {"ok": True}
    assert [e for e in audit.events if e["action"].startswith("gateway.firewall")] == []


def test_relay_firewall_dry_run_warns_without_blocking(tmp_path: Path) -> None:
    # dry_run downgrades deny -> warn: relay proceeds but audits the warning.
    policy_path = _write_policy(
        tmp_path / "fw.json",
        enforcement_mode="dry_run",
        rules=[{"source": "cursor", "target": "filesystem", "decision": "deny"}],
    )
    audit = _AuditCapture()
    with TestClient(create_gateway_app(_relay_settings(policy_path, audit))) as client:
        resp = client.post("/mcp/filesystem", json=_relay_message())
    assert resp.status_code == 200
    assert resp.json()["result"] == {"ok": True}
    warned = [e for e in audit.events if e["action"] == "gateway.firewall_warned"]
    assert len(warned) == 1
    assert warned[0]["effective_decision"] == "warn"
    assert not [e for e in audit.events if e["action"] == "gateway.firewall_blocked"]
