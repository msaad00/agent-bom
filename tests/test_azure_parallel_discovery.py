"""Azure inventory discovers services concurrently, preserving results + warnings."""

from __future__ import annotations

import sys
import time
import types

import pytest

from agent_bom.cloud import azure_inventory as azinv


@pytest.fixture(autouse=True)
def _stub_azure_sdk(monkeypatch):
    """Let ``discover_inventory`` past its ``from azure.identity import ...`` gate.

    CI's base test env does not install the optional ``azure`` extra, so without
    this the function returns ``status="sdk_missing"`` before any discovery runs.
    """
    azure_mod = sys.modules.get("azure") or types.ModuleType("azure")
    identity_mod = types.ModuleType("azure.identity")
    identity_mod.DefaultAzureCredential = object  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "azure", azure_mod)
    monkeypatch.setitem(sys.modules, "azure.identity", identity_mod)


_SERVICES = [
    "_discover_storage_accounts",
    "_discover_vms",
    "_discover_aks_clusters",
    "_discover_nsgs",
    "_discover_managed_identities",
    "_discover_role_assignments",
    "_discover_key_vaults",
    "_discover_container_registries",
    "_discover_databases",
    "_discover_virtual_networks",
    "_discover_public_ips",
    "_discover_load_balancers",
    "_discover_managed_disks",
    "_discover_app_services",
    "_discover_event_hubs",
    "_discover_service_bus",
    "_discover_redis_caches",
    "_discover_application_gateways",
    "_discover_front_doors",
    "_discover_api_management",
]


def _slow_stub(label: str, delay: float = 0.15):
    def fn(cred, sub, *, warnings):
        time.sleep(delay)
        warnings.append(f"warn-{label}")
        return [{"name": f"{label}-1", "id": f"/id/{label}"}]

    return fn


def test_discovery_runs_concurrently(monkeypatch) -> None:
    for name in _SERVICES:
        monkeypatch.setattr(azinv, name, _slow_stub(name))
    start = time.time()
    inv = azinv.discover_inventory("sub-1", credential=object(), include_hierarchy=False, force=True)
    elapsed = time.time() - start
    # 16 × 0.15s sequential = 2.4s; concurrent should be well under half that.
    assert elapsed < 0.75, f"discovery not parallel (took {elapsed:.2f}s)"
    assert inv["status"] == "ok"
    for collection in ("storage_accounts", "container_clusters", "key_vaults", "databases", "public_ips", "load_balancers"):
        assert len(inv[collection]) == 1


def test_warnings_preserved_in_deterministic_order(monkeypatch) -> None:
    for name in _SERVICES:
        monkeypatch.setattr(azinv, name, _slow_stub(name, delay=0.0))
    inv = azinv.discover_inventory("sub-1", credential=object(), include_hierarchy=False, force=True)
    assert len(inv["warnings"]) == len(_SERVICES)
    # storage is the first task → its warning is first regardless of completion order
    assert inv["warnings"][0] == "warn-_discover_storage_accounts"


def test_one_service_failing_does_not_sink_others(monkeypatch) -> None:
    def boom(cred, sub, *, warnings):
        raise RuntimeError("simulated ARM failure")

    for name in _SERVICES:
        monkeypatch.setattr(azinv, name, _slow_stub(name, delay=0.0))
    monkeypatch.setattr(azinv, "_discover_key_vaults", boom)
    inv = azinv.discover_inventory("sub-1", credential=object(), include_hierarchy=False, force=True)
    assert inv["status"] == "ok"
    assert inv["key_vaults"] == []  # failed service is empty
    assert len(inv["storage_accounts"]) == 1  # others unaffected
    assert any("simulated ARM failure" in w for w in inv["warnings"])
