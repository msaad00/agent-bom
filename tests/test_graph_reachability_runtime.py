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

import json
from pathlib import Path
from typing import Any

from starlette.testclient import TestClient

from agent_bom.gateway_server import GatewaySettings, create_gateway_app
from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry
from agent_bom.runtime.graph_reachability import (
    REACHABILITY_RULE_ID,
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
