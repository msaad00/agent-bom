"""Regression: reconcile_absent must not build unbounded NOT IN bind lists (#3689)."""

from __future__ import annotations

from uuid import uuid4

import pytest

from agent_bom.api.compliance_hub_store import RECONCILE_ABSENT_CHUNK, SQLiteComplianceHubStore
from agent_bom.api.finding_lifecycle import resolve_canonical_id


@pytest.fixture
def hub_store(tmp_path):
    return SQLiteComplianceHubStore(str(tmp_path / "reconcile-chunk.db"))


def _finding_with_id(finding_id: str) -> dict:
    return {
        "id": finding_id,
        "finding_type": "CVE",
        "severity": "high",
        "title": finding_id,
        "asset": {"name": "pkg", "asset_type": "package", "identifier": f"pkg:pypi/{finding_id}@1.0.0"},
        "package_name": "pkg",
        "package_version": "1.0.0",
        "ecosystem": "pypi",
        "source": "agent-runtime",
    }


def test_reconcile_absent_large_present_set_does_not_overflow(hub_store) -> None:
    tenant = f"reconcile-chunk-{uuid4().hex}"
    batch_size = RECONCILE_ABSENT_CHUNK + 50
    present = [_finding_with_id(f"present-{i}") for i in range(batch_size)]
    stale = _finding_with_id("stale-open")

    hub_store.upsert_current_batch(tenant, present + [stale], observed_at="2026-01-01T00:00:00Z", batch_id="b1")
    present_ids = {resolve_canonical_id(f) for f in present}

    reconciled = hub_store.reconcile_current_absent(
        tenant,
        present_canonical_ids=present_ids,
        observed_at="2026-01-02T00:00:00Z",
        scope_source="agent-runtime",
    )
    assert reconciled == 1

    stale_row = hub_store.get_current(tenant, resolve_canonical_id(stale))
    assert stale_row is not None
    assert stale_row["status"] == "resolved"

    kept_row = hub_store.get_current(tenant, resolve_canonical_id(present[0]))
    assert kept_row is not None
    assert kept_row["status"] == "open"
