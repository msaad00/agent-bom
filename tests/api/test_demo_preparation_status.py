"""A legitimate demo baseline is pending evidence, not operator-data contamination."""

from types import SimpleNamespace

import pytest

from agent_bom.api import stores
from agent_bom.api.routes.demo_estate import _build_demo_estate_status
from agent_bom.demo_estate.showcase_graph import SHOWCASE_BASELINE_SCAN_ID, SHOWCASE_SCAN_ID


@pytest.mark.parametrize(
    ("owner", "expected", "reason"),
    [
        (SHOWCASE_BASELINE_SCAN_ID, "unavailable", "showcase_preparation_incomplete"),
        (SHOWCASE_SCAN_ID, "aligned", None),
        ("operator-snapshot", "blocked", "non_demo_snapshot_present"),
        ("", "unavailable", "no_graph_snapshot"),
    ],
)
def test_demo_status_distinguishes_preparation_from_non_demo_data(monkeypatch, owner, expected, reason):
    def latest_snapshot_id(*, tenant_id, snapshot_kind):
        assert tenant_id == "sample-tenant"
        assert snapshot_kind == "scan"
        return owner

    monkeypatch.setattr(
        stores,
        "_get_graph_store",
        lambda: SimpleNamespace(
            latest_snapshot_id=latest_snapshot_id,
            snapshot_stats=lambda **kwargs: {"total_nodes": 0},
        ),
    )
    status = _build_demo_estate_status("sample-tenant")
    assert status.graph_alignment == expected
    assert status.reason == reason
    assert status.graph_owner_scan_id == (SHOWCASE_SCAN_ID if expected == "aligned" else None)
