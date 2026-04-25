"""Integration test for GET /v1/gateway/upstreams/discovered.

The gateway auto-discovery path — pilot teams don't hand-author a blank
upstreams.yaml; they let fleet scans surface remote MCPs and the gateway
pulls them from this endpoint. This test seeds real ScanJob results
with mixed local (stdio) + remote (HTTP/SSE) MCPs and verifies that:

- Only HTTP/SSE servers come back (stdio excluded — those are per-MCP
  sidecar territory).
- Each discovered upstream reports the agents that surfaced it.
- Tenant scoping holds — tenant-alpha never sees tenant-beta's
  discoveries.
- auth is always 'none' from discovery (credentials live in Secrets,
  not scan data — operators overlay via upstreams.yaml).
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores as _stores
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.server import app
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import set_job_store
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _seed_scan_with_servers(store: InMemoryJobStore, tenant: str, agent_name: str, servers: list[dict]) -> None:
    job = ScanJob(
        job_id=f"{tenant}-{agent_name}-scan",
        tenant_id=tenant,
        status=JobStatus.DONE,
        created_at=_now(),
        completed_at=_now(),
        request=ScanRequest(),
    )
    job.result = {
        "scan_id": f"{tenant}-{agent_name}-scan",
        "agents": [{"name": agent_name, "servers": servers}],
    }
    store.put(job)


@pytest.fixture
def fleet_seeded():
    """Seed two tenants with a mix of local + remote MCPs across multiple agents."""
    store = InMemoryJobStore()

    # Tenant alpha — two different agents both surface the same remote jira MCP,
    # plus a stdio filesystem MCP on one agent. Only jira should come through.
    _seed_scan_with_servers(
        store,
        "tenant-alpha",
        agent_name="mac-laptop-1",
        servers=[
            {"name": "jira", "url": "https://snowflake.example.internal/mcp/jira", "transport": "sse"},
            {"name": "filesystem", "url": None, "transport": "stdio"},  # stdio — excluded
        ],
    )
    _seed_scan_with_servers(
        store,
        "tenant-alpha",
        agent_name="windows-laptop-3",
        servers=[
            {"name": "jira", "url": "https://snowflake.example.internal/mcp/jira", "transport": "sse"},
            {"name": "github", "url": "https://mcp.github.example.com/sse", "transport": "sse"},
        ],
    )

    # Tenant beta — different MCPs that must NOT leak into alpha.
    _seed_scan_with_servers(
        store,
        "tenant-beta",
        agent_name="tenant-beta-laptop",
        servers=[
            {"name": "beta-only-jira", "url": "https://beta.example.com/mcp", "transport": "http"},
        ],
    )

    prev = _stores._store
    set_job_store(store)
    try:
        yield
    finally:
        _stores._store = prev


def _client_for(tenant: str) -> TestClient:
    c = TestClient(app)
    c.headers.update(proxy_headers(role="admin", tenant=tenant))
    return c


def test_discovered_upstreams_returns_remote_mcps_only(fleet_seeded) -> None:
    resp = _client_for("tenant-alpha").get("/v1/gateway/upstreams/discovered")
    assert resp.status_code == 200
    body = resp.json()
    assert body["tenant_id"] == "tenant-alpha"
    assert body["source"] == "fleet_scan_aggregate"
    names = [u["name"] for u in body["upstreams"]]
    assert sorted(names) == ["github", "jira"]  # filesystem (stdio) excluded
    for u in body["upstreams"]:
        assert u["url"].startswith(("http://", "https://"))
        assert u["auth"] == "none"


def test_discovered_upstreams_aggregates_source_agents(fleet_seeded) -> None:
    """A remote MCP used by multiple laptops lists every agent that reported it."""
    resp = _client_for("tenant-alpha").get("/v1/gateway/upstreams/discovered")
    jira = next(u for u in resp.json()["upstreams"] if u["name"] == "jira")
    assert sorted(jira["source_agents"]) == ["mac-laptop-1", "windows-laptop-3"]


def test_discovered_upstreams_is_tenant_scoped(fleet_seeded) -> None:
    """Tenant alpha must never see tenant beta's discoveries."""
    alpha = _client_for("tenant-alpha").get("/v1/gateway/upstreams/discovered").json()
    beta = _client_for("tenant-beta").get("/v1/gateway/upstreams/discovered").json()

    alpha_names = {u["name"] for u in alpha["upstreams"]}
    beta_names = {u["name"] for u in beta["upstreams"]}
    assert alpha_names == {"jira", "github"}
    assert beta_names == {"beta-only-jira"}
    assert alpha_names & beta_names == set(), "discovery endpoint leaks across tenants"


def test_discovered_upstreams_reports_name_collisions_and_renames(monkeypatch: pytest.MonkeyPatch) -> None:
    """Two MCPs with the same `name` but different URLs must NOT silently collapse.

    Real-world case: team A's 'jira' points at SaaS Jira, team B's 'jira' is
    an in-cluster Jira. Before this guard they'd both collapse to the first
    URL the aggregator saw; now the route:
      - keeps the first URL on the bare name,
      - renames subsequent URLs (`jira-1`, `jira-2`, …),
      - surfaces a `conflicts` array so the operator sees it.
    """
    store = InMemoryJobStore()
    _seed_scan_with_servers(
        store,
        "tenant-alpha",
        agent_name="team-a-laptop",
        servers=[{"name": "jira", "url": "https://mcp.jira.example.com/sse", "transport": "sse"}],
    )
    _seed_scan_with_servers(
        store,
        "tenant-alpha",
        agent_name="team-b-laptop",
        servers=[{"name": "jira", "url": "http://jira-internal.svc.cluster.local:8100", "transport": "http"}],
    )
    prev = _stores._store
    set_job_store(store)
    try:
        resp = _client_for("tenant-alpha").get("/v1/gateway/upstreams/discovered")
        assert resp.status_code == 200
        body = resp.json()
        # Both URLs surface as separate upstreams — no silent collapse.
        assert len(body["upstreams"]) == 2
        names = sorted(u["name"] for u in body["upstreams"])
        assert names == ["jira", "jira-1"], f"expected bare-name + suffix rename, got {names}"
        # The renamed entry preserves the original_name for operator mapping.
        renamed = next(u for u in body["upstreams"] if u["name"] == "jira-1")
        assert renamed["original_name"] == "jira"
        # URLs are preserved per record — no mixing.
        urls = {u["name"]: u["url"] for u in body["upstreams"]}
        assert urls["jira"] != urls["jira-1"]
        # Operator-visible conflict report.
        assert body["conflicts"]
        jira_conflict = next(c for c in body["conflicts"] if c["name"] == "jira")
        assert len(jira_conflict["urls"]) == 2
    finally:
        _stores._store = prev


def test_discovered_upstreams_returns_empty_when_fleet_has_no_remote_mcps() -> None:
    """A tenant whose fleet only has stdio MCPs gets an empty upstream list (no error)."""
    store = InMemoryJobStore()
    _seed_scan_with_servers(
        store,
        "tenant-stdio-only",
        agent_name="laptop",
        servers=[{"name": "filesystem", "url": None, "transport": "stdio"}],
    )
    prev = _stores._store
    set_job_store(store)
    try:
        resp = _client_for("tenant-stdio-only").get("/v1/gateway/upstreams/discovered")
        assert resp.status_code == 200
        assert resp.json()["upstreams"] == []
    finally:
        _stores._store = prev
