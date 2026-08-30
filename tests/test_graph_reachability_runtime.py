"""Graph-derived reachability → runtime gateway enforcement (consume direction).

The unified graph statically detects agents that reach a credential /
privileged-tool node (the ``AGENT_REACHES_PRIVILEGED`` toxic-combination rule).
That signal was advisory-only — the runtime gateway never consumed it. These
tests cover the consume direction:

* the loader parses a scan-report's reachability findings into a fail-safe map
  (top-level ``findings`` block and the standalone ``toxic_combinations_graph``
  block), and treats absent / malformed reports as a no-op,
* ``enforce`` blocks an over-reaching agent's FIRST call against one of its
  reachable privileged tools (pre-emptive, before any runtime correlation),
* a benign agent — and a benign tool for an over-reaching agent — is allowed,
* ``warn`` audits without blocking,
* absent reachability data / ``off`` mode is a no-op,
* the block emits the audit + governance-shaped event.
"""

from __future__ import annotations

import hmac
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from starlette.testclient import TestClient

from agent_bom.gateway_server import GatewaySettings, create_gateway_app
from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry
from agent_bom.runtime.correlation_facts import RuntimeFactsBundleError, create_runtime_facts_bundle
from agent_bom.runtime.graph_reachability import (
    REACHABILITY_RULE_ID,
    AgentReachability,
    ReachabilityMap,
    load_reachability_map,
    reachability_map_from_report_data,
)

# ── Synthetic scan-report fixtures ────────────────────────────────────────────


def _reachability_finding(agent: str, *, tool: str = "read_secret", node_id: str = "cred:prod-db") -> dict[str, Any]:
    """A finding shaped like Finding.to_dict() for the AGENT_REACHES_PRIVILEGED rule."""
    return {
        "finding_type": "combination",
        "source": "graph_analysis",
        "asset": {"name": agent, "asset_type": "agent", "identifier": agent},
        "severity": "high",
        "title": f"AI agent can reach a credential or privileged tool: {agent}",
        "evidence": {
            "rule_id": REACHABILITY_RULE_ID,
            "toxic_combination": REACHABILITY_RULE_ID,
            "node_ids": [f"agent:{agent}", node_id],
            "participating_nodes": [
                {"id": f"agent:{agent}", "label": agent, "entity_type": "agent"},
                {"id": node_id, "label": tool, "entity_type": "credential"},
            ],
            "detail": f"Agent {agent} can reach credential/privileged tool node(s).",
        },
    }


def _report_with_top_level(agent: str, **kw: Any) -> dict[str, Any]:
    return {"findings": [_reachability_finding(agent, **kw)]}


def _report_with_graph_block(agent: str, **kw: Any) -> dict[str, Any]:
    return {
        "toxic_combinations_graph": {
            "schema_version": "1",
            "source": "graph-toxic-combination",
            "count": 1,
            "findings": [_reachability_finding(agent, **kw)],
        }
    }


# ── Loader unit tests ─────────────────────────────────────────────────────────


def test_loader_parses_top_level_findings():
    rmap = reachability_map_from_report_data(_report_with_top_level("agent-a"))
    facts = rmap.lookup("agent-a")
    assert facts is not None
    # Reachable by node id and by tool label; agent's own node excluded.
    assert facts.reaches("cred:prod-db")
    assert facts.reaches("read_secret")
    assert not facts.reaches("agent:agent-a")
    assert facts.rule_id == REACHABILITY_RULE_ID


def test_loader_parses_standalone_graph_block():
    rmap = reachability_map_from_report_data(_report_with_graph_block("agent-a"))
    assert rmap.reaches_privileged("agent-a", "read_secret") is not None


def test_loader_is_case_insensitive_on_agent_and_target():
    rmap = reachability_map_from_report_data(_report_with_top_level("Agent-A"))
    assert rmap.reaches_privileged("agent-a", "READ_SECRET") is not None


def test_loader_ignores_non_reachability_findings():
    payload = {
        "findings": [
            {
                "asset": {"name": "agent-a"},
                "severity": "high",
                "evidence": {"rule_id": "PUBLIC_EXPOSED_VULNERABLE", "participating_nodes": []},
            }
        ]
    }
    assert not reachability_map_from_report_data(payload)


def test_loader_merges_multiple_findings_for_same_agent():
    payload = {
        "findings": [
            _reachability_finding("agent-a", tool="read_secret", node_id="cred:a"),
            _reachability_finding("agent-a", tool="dump_keys", node_id="cred:b"),
        ]
    }
    rmap = reachability_map_from_report_data(payload)
    facts = rmap.lookup("agent-a")
    assert facts is not None
    assert facts.reaches("read_secret") and facts.reaches("dump_keys")


def test_loader_missing_file_is_noop(tmp_path: Path):
    assert not load_reachability_map(tmp_path / "does-not-exist.json")
    assert not load_reachability_map(None)


def test_loader_malformed_json_is_noop(tmp_path: Path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert not load_reachability_map(bad)


def test_loader_reads_real_file(tmp_path: Path):
    report = tmp_path / "report.json"
    report.write_text(json.dumps(_report_with_top_level("agent-a")))
    rmap = load_reachability_map(report)
    assert rmap.reaches_privileged("agent-a", "read_secret") is not None


# ── Gateway enforcement harness (mirrors test_gateway_drift_enforcement) ──────


def _registry() -> UpstreamRegistry:
    return UpstreamRegistry([UpstreamConfig(name="filesystem", url="http://fs.local:8100")])


def _call(token: str = "token-a", tool: str = "read_secret") -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": {}, "_meta": {"agent_identity": token}},
    }


async def _ok_caller(upstream, message, extra_headers):
    return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}


def _settings(
    mode: str,
    facts_path: Path | None,
    audit: list[dict[str, Any]] | None = None,
) -> GatewaySettings:
    async def _sink(event: dict[str, Any]) -> None:
        if audit is not None:
            audit.append(event)

    return GatewaySettings(
        registry=_registry(),
        policy={"agent_tokens": {"token-a": "agent-a", "token-b": "agent-b"}},
        upstream_caller=_ok_caller,
        audit_sink=_sink if audit is not None else None,
        graph_reachability_path=facts_path,
        graph_reachability_enforcement_mode=mode,
    )


def _write_facts(tmp_path: Path, agent: str = "agent-a", **kw: Any) -> Path:
    report = tmp_path / "facts.json"
    report.write_text(json.dumps(_report_with_top_level(agent, **kw)))
    return report


def _is_blocked(resp) -> bool:
    body = resp.json()
    return resp.status_code == 200 and isinstance(body.get("error"), dict) and body["error"].get("code") == -32001


def _is_allowed(resp) -> bool:
    return resp.status_code == 200 and resp.json().get("result") == {"ok": True}


def test_enforce_blocks_privileged_reach_on_first_attempt(tmp_path: Path):
    audit: list[dict[str, Any]] = []
    facts = _write_facts(tmp_path)
    client = TestClient(create_gateway_app(_settings("enforce", facts, audit=audit)))
    resp = client.post("/mcp/filesystem", json=_call(tool="read_secret"))
    assert _is_blocked(resp), resp.text
    assert resp.json()["error"]["data"] == {
        "reason": "Graph reachability policy blocked this request",
        "policy_source": "graph_reachability",
    }
    # First attempt blocked — no prior runtime correlation required.
    assert any(e.get("action") == "gateway.graph_reachability_blocked" for e in audit)
    blocked = next(e for e in audit if e.get("action") == "gateway.graph_reachability_blocked")
    assert blocked["source_agent"] == "agent-a"
    assert blocked["tool"] == "read_secret"
    assert blocked["rule_id"] == REACHABILITY_RULE_ID


def test_enforce_allows_benign_tool_for_overreaching_agent(tmp_path: Path):
    # agent-a reaches read_secret only; a different tool is not a privileged target.
    facts = _write_facts(tmp_path)
    client = TestClient(create_gateway_app(_settings("enforce", facts)))
    resp = client.post("/mcp/filesystem", json=_call(tool="list_files"))
    assert _is_allowed(resp), resp.text


def test_enforce_allows_benign_agent(tmp_path: Path):
    # Only agent-a has reachability facts; agent-b is benign for the same tool.
    facts = _write_facts(tmp_path, agent="agent-a")
    client = TestClient(create_gateway_app(_settings("enforce", facts)))
    resp = client.post("/mcp/filesystem", json=_call(token="token-b", tool="read_secret"))
    assert _is_allowed(resp), resp.text


def test_warn_audits_but_does_not_block(tmp_path: Path):
    audit: list[dict[str, Any]] = []
    facts = _write_facts(tmp_path)
    client = TestClient(create_gateway_app(_settings("warn", facts, audit=audit)))
    resp = client.post("/mcp/filesystem", json=_call(tool="read_secret"))
    assert _is_allowed(resp), resp.text
    assert any(e.get("action") == "gateway.graph_reachability_warned" for e in audit)


def test_off_is_noop_even_with_facts(tmp_path: Path):
    facts = _write_facts(tmp_path)
    client = TestClient(create_gateway_app(_settings("off", facts)))
    resp = client.post("/mcp/filesystem", json=_call(tool="read_secret"))
    assert _is_allowed(resp), resp.text


def test_absent_facts_is_noop_in_enforce_mode():
    # enforce mode but no facts path -> empty map -> default-allow, never crashes.
    client = TestClient(create_gateway_app(_settings("enforce", None)))
    resp = client.post("/mcp/filesystem", json=_call(tool="read_secret"))
    assert _is_allowed(resp), resp.text


def test_malformed_facts_file_is_noop(tmp_path: Path):
    bad = tmp_path / "bad.json"
    bad.write_text("{ broken")
    client = TestClient(create_gateway_app(_settings("enforce", bad)))
    resp = client.post("/mcp/filesystem", json=_call(tool="read_secret"))
    assert _is_allowed(resp), resp.text


def _signed_bundle(
    *,
    tenant_id: str = "default",
    tool: str = "read_secret",
    analysis_bounds: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reachability = ReachabilityMap(
        by_agent={
            "agent-a": AgentReachability(
                agent_id="agent-a",
                node_ids=frozenset({f"tool:{tool}"}),
                node_labels=frozenset({tool}),
            )
        }
    )
    return create_runtime_facts_bundle(
        correlation_id="corr-runtime-proof",
        tenant_id=tenant_id,
        manifest_sha256="sha256:" + "a" * 64,
        reachability=reachability,
        signing_key=b"runtime-facts-signing-key-32-bytes!!",
        ttl_seconds=300,
        now=datetime.now(timezone.utc),
        key_id="lab-key",
        analysis_bounds=analysis_bounds,
    )


def _bundle_settings(
    fetcher,
    *,
    mode: str = "enforce",
    failure_mode: str = "allow",
    poll_seconds: float = 0,
    audit: list[dict[str, Any]] | None = None,
    tenant_id: str = "default",
) -> GatewaySettings:
    settings = _settings(mode, None, audit=audit)
    settings.graph_reachability_bundle_fetcher = fetcher
    settings.graph_reachability_bundle_signing_key = b"runtime-facts-signing-key-32-bytes!!"
    settings.graph_reachability_bundle_tenant_id = tenant_id
    settings.graph_reachability_bundle_poll_interval_seconds = poll_seconds
    settings.graph_reachability_failure_mode = failure_mode
    return settings


def _resign_runtime_bundle(bundle: dict[str, Any]) -> None:
    signature_input = {
        "algorithm": bundle["signature"]["algorithm"],
        "key_id": bundle["signature"]["key_id"],
        "payload": bundle["payload"],
    }
    encoded = json.dumps(signature_input, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    bundle["signature"]["value"] = hmac.digest(
        b"runtime-facts-signing-key-32-bytes!!",
        encoded,
        "sha256",
    ).hex()


def test_signed_bundle_blocks_first_jsonrpc_tool_call():
    async def _fetch():
        return _signed_bundle()

    audit: list[dict[str, Any]] = []
    with TestClient(create_gateway_app(_bundle_settings(_fetch, audit=audit))) as client:
        resp = client.post("/mcp/filesystem", json=_call(tool="read_secret"))

    assert _is_blocked(resp), resp.text
    blocked = next(event for event in audit if event.get("action") == "gateway.graph_reachability_blocked")
    assert blocked["correlation_id"] == "corr-runtime-proof"
    assert blocked["manifest_sha256"] == "sha256:" + "a" * 64
    assert blocked["evidence_source"] == "correlation_bundle"
    assert blocked["evidence_freshness"] == "fresh"


def test_bundle_hot_refresh_replaces_reachability_without_restart():
    calls = 0

    async def _fetch():
        nonlocal calls
        calls += 1
        return _signed_bundle(tool="read_secret" if calls == 1 else "rotate_keys")

    with TestClient(create_gateway_app(_bundle_settings(_fetch, poll_seconds=0.01))) as client:
        assert _is_blocked(client.post("/mcp/filesystem", json=_call(tool="read_secret")))
        deadline = time.monotonic() + 1
        while calls < 2 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert calls >= 2
        assert _is_allowed(client.post("/mcp/filesystem", json=_call(tool="read_secret")))
        assert _is_blocked(client.post("/mcp/filesystem", json=_call(tool="rotate_keys")))


def test_bundle_outage_preserves_legacy_allow_behavior():
    async def _fetch():
        raise RuntimeError("secret upstream detail")

    audit: list[dict[str, Any]] = []
    with TestClient(create_gateway_app(_bundle_settings(_fetch, audit=audit))) as client:
        resp = client.post("/mcp/filesystem", json=_call())

    assert _is_allowed(resp), resp.text
    unavailable = next(event for event in audit if event.get("action") == "gateway.graph_reachability_evidence_unavailable")
    assert unavailable["failure_mode"] == "allow"
    assert unavailable["reason_code"] == "bundle_fetch_failed"
    assert "secret upstream detail" not in json.dumps(unavailable)


def test_explicit_deny_blocks_when_bundle_is_unavailable():
    async def _fetch():
        raise RuntimeError("do not expose")

    audit: list[dict[str, Any]] = []
    with TestClient(create_gateway_app(_bundle_settings(_fetch, failure_mode="deny", audit=audit))) as client:
        resp = client.post("/mcp/filesystem", json=_call())

    assert _is_blocked(resp), resp.text
    assert resp.json()["error"]["data"] == {
        "reason": "Graph reachability evidence unavailable and strict mode is active",
        "policy_source": "graph_reachability_evidence",
    }
    assert any(event.get("action") == "gateway.graph_reachability_evidence_unavailable" for event in audit)


def test_strict_gateway_fails_closed_when_signed_input_receipts_age_out() -> None:
    issued_at = datetime.now(timezone.utc) - timedelta(minutes=61)
    bundle = _signed_bundle(tool="rotate_keys")
    bundle["payload"]["issued_at"] = issued_at.isoformat()
    bundle["payload"]["expires_at"] = (issued_at + timedelta(hours=2)).isoformat()
    bundle["payload"]["input_freshness"] = {
        "max_age_hours": 1,
        "allow_stale": False,
        "snapshots": [
            {"scan_id": "repo", "created_at": issued_at.isoformat()},
            {"scan_id": "runtime", "created_at": issued_at.isoformat()},
        ],
    }
    _resign_runtime_bundle(bundle)

    async def _fetch():
        return bundle

    audit: list[dict[str, Any]] = []
    with TestClient(create_gateway_app(_bundle_settings(_fetch, failure_mode="deny", audit=audit))) as client:
        response = client.post("/mcp/filesystem", json=_call(tool="read_secret"))

    assert _is_blocked(response), response.text
    unavailable = next(event for event in audit if event.get("action") == "gateway.graph_reachability_evidence_unavailable")
    assert unavailable["reason_code"] == "correlation_inputs_stale"


def test_explicit_deny_does_not_fall_back_to_static_facts_when_configured_bundle_is_unavailable(tmp_path: Path):
    async def _fetch():
        raise RuntimeError("do not expose")

    facts = _write_facts(tmp_path, tool="different_tool")
    settings = _bundle_settings(_fetch, failure_mode="deny")
    settings.graph_reachability_path = facts
    with TestClient(create_gateway_app(settings)) as client:
        resp = client.post("/mcp/filesystem", json=_call(tool="read_secret"))

    assert _is_blocked(resp), resp.text
    assert resp.json()["error"]["data"]["policy_source"] == "graph_reachability_evidence"


def test_explicit_deny_blocks_when_signed_analysis_is_incomplete():
    async def _fetch():
        return _signed_bundle(
            analysis_bounds={
                "status": "limited",
                "complete": False,
                "depth_limit": 6,
                "visited_node_limit": 5000,
                "limit_reasons": ["depth_cap_reached"],
            }
        )

    audit: list[dict[str, Any]] = []
    with TestClient(create_gateway_app(_bundle_settings(_fetch, failure_mode="deny", audit=audit))) as client:
        resp = client.post("/mcp/filesystem", json=_call(tool="list_files"))

    assert _is_blocked(resp), resp.text
    unavailable = next(event for event in audit if event.get("action") == "gateway.graph_reachability_evidence_unavailable")
    assert unavailable["reason_code"] == "analysis_incomplete"


def test_explicit_deny_revokes_cached_bundle_after_output_is_purged():
    calls = 0

    async def _fetch():
        nonlocal calls
        calls += 1
        if calls == 1:
            return _signed_bundle()
        raise RuntimeFactsBundleError("correlation_output_unavailable")

    audit: list[dict[str, Any]] = []
    with TestClient(create_gateway_app(_bundle_settings(_fetch, failure_mode="deny", poll_seconds=0.01, audit=audit))) as client:
        assert _is_allowed(client.post("/mcp/filesystem", json=_call(tool="list_files")))
        deadline = time.monotonic() + 1
        while calls < 2 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert calls >= 2
        resp = client.post("/mcp/filesystem", json=_call(tool="list_files"))

    assert _is_blocked(resp), resp.text
    unavailable = [event for event in audit if event.get("action") == "gateway.graph_reachability_evidence_unavailable"][-1]
    assert unavailable["reason_code"] == "correlation_output_unavailable"


def test_tenant_mismatched_bundle_is_not_accepted():
    async def _fetch():
        return _signed_bundle(tenant_id="other-tenant")

    audit: list[dict[str, Any]] = []
    with TestClient(create_gateway_app(_bundle_settings(_fetch, audit=audit))) as client:
        resp = client.post("/mcp/filesystem", json=_call())

    assert _is_allowed(resp), resp.text
    unavailable = next(event for event in audit if event.get("action") == "gateway.graph_reachability_evidence_unavailable")
    assert unavailable["reason_code"] == "tenant_mismatch"


def test_global_off_ignores_valid_bundle():
    async def _fetch():
        return _signed_bundle()

    with TestClient(create_gateway_app(_bundle_settings(_fetch, mode="off", failure_mode="deny"))) as client:
        resp = client.post("/mcp/filesystem", json=_call())

    assert _is_allowed(resp), resp.text


def test_strict_deny_blocks_when_no_evidence_source_is_configured():
    settings = _settings("enforce", None)
    settings.graph_reachability_failure_mode = "deny"

    with TestClient(create_gateway_app(settings)) as client:
        resp = client.post("/mcp/filesystem", json=_call())

    assert _is_blocked(resp), resp.text
    assert resp.json()["error"]["data"]["policy_source"] == "graph_reachability_evidence"


def test_bundle_tenant_must_match_authenticated_request_tenant():
    async def _fetch():
        return _signed_bundle(tenant_id="tenant-a")

    audit: list[dict[str, Any]] = []
    settings = _bundle_settings(_fetch, audit=audit, tenant_id="tenant-a")
    with TestClient(create_gateway_app(settings)) as client:
        resp = client.post("/mcp/filesystem", json=_call())

    assert _is_allowed(resp), resp.text
    unavailable = next(event for event in audit if event.get("action") == "gateway.graph_reachability_evidence_unavailable")
    assert unavailable["reason_code"] == "request_tenant_mismatch"
