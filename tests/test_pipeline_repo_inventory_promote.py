"""Promote nested API dependency inventory for graph overlay parity."""

from __future__ import annotations

from types import SimpleNamespace

from agent_bom.api.pipeline import _promote_repo_dependency_inventory


def test_promote_repo_dependency_inventory_lifts_nested_dict() -> None:
    report = SimpleNamespace(project_inventory_data=None)
    _promote_repo_dependency_inventory(
        report,
        {"dependency_inventory": {"directories": [{"path": "src"}], "package_count": 3}},
    )
    assert report.project_inventory_data["package_count"] == 3


def test_promote_repo_dependency_inventory_keeps_existing_top_level() -> None:
    report = SimpleNamespace(project_inventory_data={"package_count": 9})
    _promote_repo_dependency_inventory(
        report,
        {"dependency_inventory": {"package_count": 1}},
    )
    assert report.project_inventory_data["package_count"] == 9
