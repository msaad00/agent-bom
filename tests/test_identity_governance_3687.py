"""Regression tests for identity/SCIM governance (#3687)."""

from __future__ import annotations

from agent_bom.api.routes.scim import SCIMGroup, _apply_group_patch


def test_scim_group_remove_members_value_list_subtracts_only_named() -> None:
    group = SCIMGroup(
        group_id="g1",
        tenant_id="default",
        display_name="ops",
        members=[
            {"value": "u1", "display": "alice"},
            {"value": "u2", "display": "bob"},
            {"value": "u3", "display": "carol"},
        ],
    )
    updated = _apply_group_patch(
        group,
        {
            "Operations": [
                {
                    "op": "remove",
                    "path": "members",
                    "value": [{"value": "u2", "display": "bob"}],
                }
            ]
        },
    )
    assert {m["value"] for m in updated.members} == {"u1", "u3"}


def test_scim_group_add_members_implicit_path_appends() -> None:
    group = SCIMGroup(
        group_id="g1",
        tenant_id="default",
        display_name="ops",
        members=[{"value": "u1", "display": "alice"}],
    )
    updated = _apply_group_patch(
        group,
        {"Operations": [{"op": "add", "value": {"members": [{"value": "u2", "display": "bob"}]}}]},
    )
    assert {m["value"] for m in updated.members} == {"u1", "u2"}
