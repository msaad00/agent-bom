"""Regression tests for current-state payload dedup (#3487)."""

from __future__ import annotations

import json
from uuid import uuid4

import pytest

from agent_bom.api.compliance_hub_store import (
    InMemoryComplianceHubStore,
    SQLiteComplianceHubStore,
)
from agent_bom.api.finding_lifecycle import resolve_canonical_id


def _large_finding(finding_id: str) -> dict:
    return {
        "id": finding_id,
        "title": "Reachable secret in MCP tool",
        "severity": "high",
        "source": "agent-runtime",
        "origin": "bulk_ingest",
        "batch_id": "batch-dedup",
        "description": "x" * 1200,
        "evidence": {"blob": "y" * 800},
    }


@pytest.mark.parametrize("store_factory", ["memory", "sqlite"])
def test_current_state_stores_overlay_and_hydrates_from_ledger(
    store_factory: str,
    tmp_path,
) -> None:
    if store_factory == "memory":
        store = InMemoryComplianceHubStore()
    else:
        store = SQLiteComplianceHubStore(str(tmp_path / "dedup.db"))

    tenant = f"dedup-{uuid4().hex}"
    finding = _large_finding("finding-dedup-1")
    store.add(tenant, [finding])
    store.upsert_current_batch(
        tenant,
        [finding],
        observed_at="2026-07-04T00:00:00Z",
        batch_id="batch-dedup",
        source="agent-runtime",
    )

    canonical = resolve_canonical_id(finding, source="agent-runtime")
    current = store.get_current(tenant, canonical)
    assert current is not None
    assert current["payload"]["title"] == finding["title"]

    if store_factory == "sqlite":
        row = store._conn.execute(
            """
            SELECT payload, ledger_finding_id
            FROM hub_findings_current
            WHERE tenant_id = ? AND canonical_id = ?
            """,
            (tenant, canonical),
        ).fetchone()
        assert row is not None
        assert row[1] == finding["id"]
        overlay = json.loads(row[0])
        assert "description" not in overlay
        assert overlay["origin"] == "bulk_ingest"
        ledger_payload = store._conn.execute(
            "SELECT payload FROM compliance_hub_findings WHERE tenant_id = ? AND finding_id = ?",
            (tenant, finding["id"]),
        ).fetchone()[0]
        assert len(row[0]) < len(ledger_payload)

    listed, total = store.list_current_page(tenant, limit=10)
    assert total == 1
    assert listed[0]["title"] == finding["title"]
    assert listed[0]["severity"] == finding["severity"]
