"""Monotone current-state finding lifecycle (#3465 L1)."""

from __future__ import annotations

from uuid import uuid4

import pytest

from agent_bom.api.compliance_hub_store import (
    InMemoryComplianceHubStore,
    SQLiteComplianceHubStore,
    reset_compliance_hub_store,
    set_compliance_hub_store,
)
from agent_bom.api.finding_lifecycle import resolve_canonical_id
from agent_bom.api.server import app
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

MON = "2026-07-07T12:00:00Z"
TUE = "2026-07-08T12:00:00Z"


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()


@pytest.fixture(params=["memory", "sqlite"])
def hub_store(request: pytest.FixtureRequest, tmp_path):
    if request.param == "memory":
        return InMemoryComplianceHubStore()
    return SQLiteComplianceHubStore(str(tmp_path / "lifecycle.db"))


def _sample_finding() -> dict:
    return {
        "id": "finding-lifecycle-1",
        "title": "Reachable secret in MCP tool",
        "severity": "high",
        "source": "agent-runtime",
        "origin": "bulk_ingest",
    }


def test_monotone_merge_timestamps(hub_store) -> None:
    tenant = f"lifecycle-{uuid4().hex}"
    finding = _sample_finding()
    canonical = resolve_canonical_id(finding)

    hub_store.upsert_current_batch(tenant, [finding], observed_at=MON, batch_id="batch-mon-1")
    row = hub_store.get_current(tenant, canonical)
    assert row is not None
    assert row["first_seen"] == MON
    assert row["last_seen"] == MON
    assert row["scan_count"] == 1
    assert row["status"] == "open"

    hub_store.upsert_current_batch(tenant, [finding], observed_at=MON, batch_id="batch-mon-2")
    retry = hub_store.get_current(tenant, canonical)
    assert retry is not None
    assert retry["first_seen"] == MON
    assert retry["last_seen"] == MON
    assert retry["scan_count"] == 1

    hub_store.upsert_current_batch(tenant, [finding], observed_at=TUE, batch_id="batch-tue-1")
    advanced = hub_store.get_current(tenant, canonical)
    assert advanced is not None
    assert advanced["first_seen"] == MON
    assert advanced["last_seen"] == TUE
    assert advanced["scan_count"] == 2

    hub_store.upsert_current_batch(tenant, [finding], observed_at=TUE, batch_id="batch-tue-2")
    retry_tue = hub_store.get_current(tenant, canonical)
    assert retry_tue is not None
    assert retry_tue["first_seen"] == MON
    assert retry_tue["last_seen"] == TUE
    assert retry_tue["scan_count"] == 2


def test_bulk_ingest_carries_observed_at() -> None:
    from starlette.testclient import TestClient

    tenant = f"bulk-observed-{uuid4().hex}"
    store = InMemoryComplianceHubStore()
    set_compliance_hub_store(store)
    client = TestClient(app)
    client.headers.update(proxy_headers(role="analyst", tenant=tenant))

    resp = client.post(
        "/v1/findings/bulk",
        json={
            "source": "agent-runtime",
            "observed_at": MON,
            "findings": [_sample_finding()],
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["observed_at"] == MON

    canonical = resolve_canonical_id(_sample_finding())
    row = store.get_current(tenant, canonical)
    assert row is not None
    assert row["first_seen"] == MON
    assert row["last_seen"] == MON

    reset_compliance_hub_store()


def _mark_resolved(store, tenant: str, canonical: str, resolved_at: str) -> None:
    if isinstance(store, InMemoryComplianceHubStore):
        row = store.get_current(tenant, canonical)
        assert row is not None
        row = dict(row)
        row["status"] = "resolved"
        row["resolved_at"] = resolved_at
        store._current[tenant][canonical] = row
        return
    row = store.get_current(tenant, canonical)
    assert row is not None
    store._conn.execute(
        """
        UPDATE hub_findings_current
        SET status = 'resolved', resolved_at = ?
        WHERE tenant_id = ? AND canonical_id = ?
        """,
        (resolved_at, tenant, canonical),
    )
    store._conn.commit()


def test_reopen_on_resolved_observation(hub_store) -> None:
    tenant = f"reopen-{uuid4().hex}"
    finding = _sample_finding()
    canonical = resolve_canonical_id(finding)

    hub_store.upsert_current_batch(tenant, [finding], observed_at=MON, batch_id="batch-mon")
    _mark_resolved(hub_store, tenant, canonical, MON)

    hub_store.upsert_current_batch(tenant, [finding], observed_at=TUE, batch_id="batch-tue")
    reopened = hub_store.get_current(tenant, canonical)
    assert reopened is not None
    assert reopened["status"] == "reopened"
    assert reopened["reopened_at"] == TUE
    assert reopened["last_seen"] == TUE
