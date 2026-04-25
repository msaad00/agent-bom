"""End-to-end integration: auth + tenant + fleet discovery + gateway relay + audit.

The scenario a pilot team actually walks through:

1. An operator on **tenant-alpha** authenticates with the control plane
   via the trusted-proxy headers (``X-Agent-Bom-Role`` +
   ``X-Agent-Bom-Tenant-ID``) — same RBAC path the gateway auto-discovery
   endpoint uses.
2. That tenant's fleet scans have surfaced two remote MCPs:
   - ``jira`` (SaaS, bearer auth)
   - ``internal`` (in-cluster, no auth)
3. The operator hits ``/v1/gateway/upstreams/discovered`` and gets ONLY
   their tenant's upstreams — no cross-tenant leakage.
4. The gateway is configured with an overlay that adds bearer auth to
   ``jira`` on top of what discovery returned.
5. A client calls ``POST /mcp/jira`` on the gateway with a policy-blocked
   tool name. The gateway blocks BEFORE the upstream is touched, records
   a ``gateway.tool_call_blocked`` audit event via the sink, bumps the
   ``agent_bom_gateway_relays_total{outcome="blocked"}`` metric, and
   returns the JSON-RPC error envelope.
6. A second call with an allowed tool makes it through to the (fake)
   upstream, returns the response, and bumps the ``forwarded`` metric.

Regression-guards every seam that matters for pilot day 1: RBAC,
tenant scoping, discovery-driven upstreams, overlay auth injection,
policy evaluation, audit trail, and metrics.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores as _stores
from agent_bom.api.metrics import reset_for_tests as reset_metrics
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.server import app
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import set_job_store
from agent_bom.gateway_server import GatewaySettings, create_gateway_app
from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry

PROXY_SECRET = "test-proxy-secret"


def setup_module() -> None:
    import os

    os.environ["AGENT_BOM_TRUST_PROXY_AUTH"] = "1"
    os.environ["AGENT_BOM_TRUST_PROXY_AUTH_SECRET"] = PROXY_SECRET


def teardown_module() -> None:
    import os

    os.environ.pop("AGENT_BOM_TRUST_PROXY_AUTH", None)
    os.environ.pop("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", None)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _seed_fleet_for_tenant(store: InMemoryJobStore, tenant: str, servers: list[dict]) -> None:
    """Seed one scan job per tenant with the given remote MCPs surfaced."""
    job = ScanJob(
        job_id=f"{tenant}-scan",
        tenant_id=tenant,
        status=JobStatus.DONE,
        created_at=_now(),
        completed_at=_now(),
        request=ScanRequest(),
    )
    job.result = {
        "scan_id": f"{tenant}-scan",
        "agents": [{"name": f"{tenant}-laptop-1", "servers": servers}],
    }
    store.put(job)


@pytest.fixture
def pilot_fleet():
    """Two tenants, each with their own fleet of remote MCPs."""
    store = InMemoryJobStore()
    _seed_fleet_for_tenant(
        store,
        "tenant-alpha",
        servers=[
            {"name": "jira", "url": "https://mcp.jira.example.com/sse", "transport": "sse"},
            {"name": "internal", "url": "http://mcp.internal.svc.cluster.local:8100", "transport": "http"},
        ],
    )
    _seed_fleet_for_tenant(
        store,
        "tenant-beta",
        servers=[
            {"name": "beta-only-mcp", "url": "https://beta.example.com/mcp", "transport": "http"},
        ],
    )
    prev = _stores._store
    set_job_store(store)
    reset_metrics()
    try:
        yield store
    finally:
        _stores._store = prev


def _cp_client(tenant: str) -> TestClient:
    """TestClient for the agent-bom control-plane API authed as `tenant`."""
    c = TestClient(app)
    c.headers.update(
        {
            "X-Agent-Bom-Role": "admin",
            "X-Agent-Bom-Tenant-ID": tenant,
            "X-Agent-Bom-Proxy-Secret": PROXY_SECRET,
        }
    )
    return c


def test_full_pilot_flow_auth_tenant_discovery_relay_policy_audit_metrics(pilot_fleet, monkeypatch) -> None:
    """Walk the entire pilot flow — every seam guarded in one test."""

    # ── Stage 1: operator on tenant-alpha hits discovery, sees ONLY their MCPs
    cp = _cp_client("tenant-alpha")
    discovery = cp.get("/v1/gateway/upstreams/discovered")
    assert discovery.status_code == 200
    body = discovery.json()
    assert body["tenant_id"] == "tenant-alpha"
    names = sorted(u["name"] for u in body["upstreams"])
    assert names == ["internal", "jira"], f"discovery leaked or dropped: {names}"
    # Cross-tenant check: tenant-beta's MCP must not appear.
    assert not any("beta-only-mcp" in u["name"] for u in body["upstreams"])

    # ── Stage 2: gateway boots from that discovery + operator overlay
    # Discovery returns auth='none' (it can't see tokens). Operator overlay
    # adds bearer auth to jira with a pinned env-var name.
    discovered = UpstreamRegistry.from_discovery_response(body)
    import os

    os.environ["JIRA_MCP_TOKEN"] = "pilot-test-token"  # noqa: SIM117 — test-setup env var
    try:
        overlay = UpstreamRegistry(
            [
                UpstreamConfig(
                    name="jira",
                    url="https://mcp.jira.example.com/sse",
                    auth="bearer",
                    token_env="JIRA_MCP_TOKEN",
                )
            ]
        )
        registry = discovered.merged_with(overlay)

        # Pinpoint what the gateway will actually route to.
        assert registry.get("jira").auth == "bearer"
        assert registry.get("internal").auth == "none"
        # Bearer header resolves from env — the gateway will inject it.
        assert registry.get("jira").resolved_static_headers()["Authorization"] == "Bearer pilot-test-token"

        # ── Stage 3: build the gateway with a policy that blocks `run_shell`
        policy = {"rules": [{"id": "no-shell", "action": "block", "block_tools": ["run_shell"]}]}
        audit: list[dict[str, Any]] = []

        async def audit_sink(event: dict[str, Any]) -> None:
            audit.append(event)

        upstream_calls: list[dict[str, Any]] = []

        async def fake_upstream_caller(upstream, message, extra_headers):
            upstream_calls.append({"upstream": upstream.name, "tool": message.get("params", {}).get("name"), "headers": extra_headers})
            return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}

        class _FakeKeyStore:
            def has_keys(self) -> bool:
                return True

            def verify(self, raw_key: str):
                if raw_key == "tenant-alpha-gateway-key":
                    return type("ApiKey", (), {"tenant_id": "tenant-alpha"})()
                return None

        monkeypatch.setattr("agent_bom.gateway_server.get_key_store", lambda: _FakeKeyStore())

        gw_settings = GatewaySettings(
            registry=registry,
            policy=policy,
            audit_sink=audit_sink,
            upstream_caller=fake_upstream_caller,
        )
        gw = TestClient(create_gateway_app(gw_settings))

        # ── Stage 4: policy-blocked tool call — upstream must NOT be hit
        blocked = gw.post(
            "/mcp/jira",
            headers={"X-API-Key": "tenant-alpha-gateway-key"},
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "run_shell", "arguments": {"command": "rm -rf /"}},
            },
        )
        assert blocked.status_code == 200
        err = blocked.json()["error"]
        assert err["code"] == -32001
        assert "Blocked" in err["message"]
        assert upstream_calls == [], "blocked call reached upstream"
        blocked_events = [e for e in audit if e["action"] == "gateway.tool_call_blocked"]
        assert len(blocked_events) == 1
        assert blocked_events[0]["upstream"] == "jira"
        assert blocked_events[0]["tool"] == "run_shell"

        # ── Stage 5: allowed tool call — upstream hit, response returned
        allowed = gw.post(
            "/mcp/jira",
            headers={"X-API-Key": "tenant-alpha-gateway-key"},
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "query_issues", "arguments": {"jql": "project = ACME"}},
            },
        )
        assert allowed.status_code == 200
        assert allowed.json()["result"]["ok"] is True
        assert len(upstream_calls) == 1
        assert upstream_calls[0]["upstream"] == "jira"
        assert upstream_calls[0]["tool"] == "query_issues"

        # ── Stage 6: metrics reflect both outcomes
        metrics_resp = gw.get("/metrics")
        assert metrics_resp.status_code == 200
        body_text = metrics_resp.text
        assert body_text.startswith("# HELP"), "not Prometheus exposition"
        assert 'agent_bom_gateway_relays_total{upstream="jira",outcome="blocked"} 1' in body_text
        assert 'agent_bom_gateway_relays_total{upstream="jira",outcome="forwarded"} 1' in body_text
    finally:
        os.environ.pop("JIRA_MCP_TOKEN", None)


def test_gateway_metrics_are_plain_text_not_json(pilot_fleet) -> None:
    """Extra guard for the /metrics wire-format regression fixed in #1554.

    A JSONResponse would break every Prometheus scraper; this test lives
    alongside the full e2e so it runs under the same CI stage.
    """
    registry = UpstreamRegistry([UpstreamConfig(name="x", url="http://x.example.com")])
    gw = TestClient(create_gateway_app(GatewaySettings(registry=registry, policy={})))
    r = gw.get("/metrics")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")
    assert not r.text.startswith('"'), "JSON-quoted — would break Prometheus scrapers"
    assert "agent_bom_gateway_relays_total" in r.text
