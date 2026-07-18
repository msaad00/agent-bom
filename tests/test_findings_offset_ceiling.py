"""Offset ceiling on GET /v1/findings (P3).

The sibling hub list route caps ``offset`` at a compatibility ceiling and steers
deep walks to cursor pagination; ``/v1/findings`` declared ``offset`` unbounded,
so a deep ``?offset=`` scanned linearly with no bound. It now mirrors the hub
route: a clean 400 past the ceiling, cursor pagination stays the unbounded path.
"""

from __future__ import annotations

import tempfile

from starlette.testclient import TestClient

from agent_bom.api.compliance_hub_store import (
    InMemoryComplianceHubStore,
    SQLiteComplianceHubStore,
    set_compliance_hub_store,
)
from agent_bom.api.finding_list_envelope import HUB_LIST_OFFSET_CEILING
from agent_bom.api.server import app, set_job_store
from agent_bom.api.store import InMemoryJobStore
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

_AUTH = proxy_headers(tenant="default")


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()
    set_job_store(InMemoryJobStore())
    set_compliance_hub_store(InMemoryComplianceHubStore())


def _seed() -> None:
    tmp = tempfile.mkdtemp()
    store = SQLiteComplianceHubStore(f"{tmp}/offset.db")
    findings = [
        {
            "id": f"f-{i:04d}",
            "severity": "high",
            "effective_reach_score": float(i % 10),
            "origin": "bulk_ingest",
            "source": "test",
            "batch_id": "b",
        }
        for i in range(30)
    ]
    store.add("default", findings)
    store.upsert_current_batch("default", findings, observed_at="2026-07-18T00:00:00Z", batch_id="b", source="test")
    set_compliance_hub_store(store)
    set_job_store(InMemoryJobStore())


def test_offset_above_ceiling_returns_400() -> None:
    _seed()
    client = TestClient(app)
    resp = client.get(f"/v1/findings?offset={HUB_LIST_OFFSET_CEILING + 1}", headers=_AUTH)
    assert resp.status_code == 400, resp.text
    body = resp.text.lower()
    assert "offset" in body and "cursor" in body, "400 should explain the ceiling + steer to cursor"


def test_offset_at_ceiling_still_works() -> None:
    _seed()
    client = TestClient(app)
    resp = client.get(f"/v1/findings?offset={HUB_LIST_OFFSET_CEILING}", headers=_AUTH)
    assert resp.status_code == 200, resp.text
    # Deep offset past the data returns an empty page, not an error.
    assert resp.json()["findings"] == []


def test_cursor_remains_unbounded_depth_path() -> None:
    _seed()
    client = TestClient(app)
    # Page once to obtain a cursor, then continue by cursor — never rejected by
    # the offset ceiling (cursor is the intended unbounded-depth contract).
    first = client.get("/v1/findings?limit=5", headers=_AUTH)
    assert first.status_code == 200
    cursor = first.json().get("next_cursor")
    assert cursor
    nxt = client.get(f"/v1/findings?limit=5&cursor={cursor}", headers=_AUTH)
    assert nxt.status_code == 200, nxt.text
