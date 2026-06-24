"""Azure multi-subscription fan-out — enumerate every sub in the tenant, scan each."""

from __future__ import annotations

from agent_bom.cloud import azure_inventory as az


def test_subscription_ids_extracted_from_mg_tree() -> None:
    mgs = [
        {
            "name": "root",
            "children": [
                {"name": "mg-prod", "type": "Microsoft.Management/managementGroups"},
                {"name": "11111111-1111-1111-1111-111111111111", "type": "Microsoft.Management/managementGroups/subscriptions"},
            ],
        },
        {
            "name": "mg-prod",
            "children": [
                {"name": "22222222-2222-2222-2222-222222222222", "type": ".../subscriptions"},
                {"name": "22222222-2222-2222-2222-222222222222", "type": ".../subscriptions"},  # dup
            ],
        },
    ]
    subs = az._subscription_ids_from_mg_tree(mgs)
    assert subs == ["11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"]


def test_fan_out_scans_each_subscription(monkeypatch) -> None:
    # Stub the credential + MG discovery + per-sub inventory.
    import types

    azid = types.ModuleType("azure.identity")
    azid.DefaultAzureCredential = lambda **_k: object()
    import sys

    monkeypatch.setitem(sys.modules, "azure", sys.modules.get("azure") or types.ModuleType("azure"))
    monkeypatch.setitem(sys.modules, "azure.identity", azid)

    monkeypatch.setattr(
        az,
        "_discover_management_groups",
        lambda cred: (
            [
                {
                    "name": "root",
                    "children": [
                        {"name": "sub-a", "type": ".../subscriptions"},
                        {"name": "sub-b", "type": ".../subscriptions"},
                    ],
                }
            ],
            [],
        ),
    )
    scanned: list[str] = []

    def _fake_inventory(subscription_id=None, credential=None, force=False, **_k):
        scanned.append(subscription_id)
        return {"provider": "azure", "status": "ok", "account_id": subscription_id, "instances": []}

    monkeypatch.setattr(az, "discover_inventory", _fake_inventory)
    out = az.discover_all_subscription_inventories(credential=object(), force=True)
    assert scanned == ["sub-a", "sub-b"]
    assert [p["account_id"] for p in out] == ["sub-a", "sub-b"]


def test_falls_back_to_single_sub_when_no_mg(monkeypatch) -> None:
    import sys
    import types

    azid = types.ModuleType("azure.identity")
    azid.DefaultAzureCredential = lambda **_k: object()
    monkeypatch.setitem(sys.modules, "azure.identity", azid)
    monkeypatch.setattr(az, "_discover_management_groups", lambda cred: ([], []))
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "solo-sub")
    monkeypatch.setattr(az, "discover_inventory", lambda subscription_id=None, **_k: {"account_id": subscription_id, "status": "ok"})
    out = az.discover_all_subscription_inventories(credential=object(), force=True)
    assert [p["account_id"] for p in out] == ["solo-sub"]
