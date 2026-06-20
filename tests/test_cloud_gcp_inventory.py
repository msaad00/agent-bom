"""Tests for agent_bom.cloud.gcp_inventory — estate-wide GCP asset inventory.

The google-cloud SDKs are not hard dependencies, so these tests inject fake
``google.cloud.*`` modules (no live calls) and exercise: enumeration → payload,
the flag-off no-op path, the sdk-missing path, the no-project path, and the
graph-builder integration that turns the payload into nodes the CNAPP /
effective-permissions overlays consume.

Authentication is token / Application Default Credentials only — the tests pass
``credentials=None`` (ADC) or inject a fake credential, never a password.
"""

from __future__ import annotations

import sys
import types
from typing import Any
from unittest.mock import patch

import pytest

from agent_bom.cloud import gcp_inventory

# ---------------------------------------------------------------------------
# Fake google-cloud SDK objects
# ---------------------------------------------------------------------------


class _Obj:
    def __init__(self, **kwargs: Any) -> None:
        for key, value in kwargs.items():
            setattr(self, key, value)


class _FakeBucket:
    def __init__(self, name: str, location: str, public: bool, labels: dict[str, str]) -> None:
        self.name = name
        self.location = location
        self.labels = labels
        self._public = public

    def get_iam_policy(self) -> Any:
        members = ["allUsers"] if self._public else ["user:alice@example.com"]
        return _Obj(bindings=[{"role": "roles/storage.objectViewer", "members": members}])


class _FakeStorageClient:
    def __init__(self, project: str | None = None, credentials: Any = None) -> None:
        self.project = project

    def list_buckets(self) -> list[Any]:
        return [
            _FakeBucket("public-lake", "US", True, {"classification": "pii"}),
            _FakeBucket("private-logs", "EU", False, {}),
        ]


class _FakeStorageModule(types.ModuleType):
    Client = _FakeStorageClient


class _FakeInstancesClient:
    def __init__(self, credentials: Any = None) -> None:
        pass

    def aggregated_list(self, project: str) -> list[Any]:
        instance = _Obj(
            id="123",
            name="web-1",
            machine_type="https://www.googleapis.com/compute/v1/projects/p/zones/us-central1-a/machineTypes/e2-medium",
            zone="https://www.googleapis.com/compute/v1/projects/p/zones/us-central1-a",
            status="RUNNING",
            network_interfaces=[
                _Obj(network_i_p="10.0.0.5", access_configs=[_Obj(nat_i_p="203.0.113.7")]),
            ],
            service_accounts=[_Obj(email="vm-sa@p.iam.gserviceaccount.com")],
            tags=_Obj(items=["http-server"]),
            labels={"app": "web"},
        )
        return [("zones/us-central1-a", _Obj(instances=[instance]))]


class _FakeFirewallsClient:
    def __init__(self, credentials: Any = None) -> None:
        pass

    def list(self, project: str) -> list[Any]:
        return [
            _Obj(
                name="allow-ssh",
                network="https://www.googleapis.com/compute/v1/projects/p/global/networks/default",
                direction="INGRESS",
                source_ranges=["0.0.0.0/0"],
                allowed=[_Obj(I_p_protocol="tcp", ports=["22"])],
            ),
            _Obj(
                name="internal-https",
                network="https://www.googleapis.com/compute/v1/projects/p/global/networks/default",
                direction="INGRESS",
                source_ranges=["10.0.0.0/8"],
                allowed=[_Obj(I_p_protocol="tcp", ports=["443"])],
            ),
        ]


class _FakeComputeModule(types.ModuleType):
    InstancesClient = _FakeInstancesClient
    FirewallsClient = _FakeFirewallsClient


class _FakeServiceAccount:
    def __init__(self, email: str, display_name: str, unique_id: str) -> None:
        self.email = email
        self.display_name = display_name
        self.unique_id = unique_id
        self.disabled = False


class _FakeIAMClient:
    def __init__(self, credentials: Any = None) -> None:
        pass

    def list_service_accounts(self, request: Any) -> list[Any]:
        return [_FakeServiceAccount("svc@p.iam.gserviceaccount.com", "Service Bot", "sa-unique-1")]


class _FakeListSARequest:
    def __init__(self, name: str) -> None:
        self.name = name


class _FakeIAMAdminModule(types.ModuleType):
    IAMClient = _FakeIAMClient
    ListServiceAccountsRequest = _FakeListSARequest


def _install_fake_gcp() -> Any:
    """Return a patch.dict context installing fake google-cloud SDK modules."""
    google_mod = types.ModuleType("google")
    cloud_mod = types.ModuleType("google.cloud")
    storage_mod = _FakeStorageModule("google.cloud.storage")
    compute_mod = _FakeComputeModule("google.cloud.compute_v1")
    iam_mod = _FakeIAMAdminModule("google.cloud.iam_admin_v1")
    return patch.dict(
        sys.modules,
        {
            "google": google_mod,
            "google.cloud": cloud_mod,
            "google.cloud.storage": storage_mod,
            "google.cloud.compute_v1": compute_mod,
            "google.cloud.iam_admin_v1": iam_mod,
        },
    )


# ---------------------------------------------------------------------------
# Flag gating
# ---------------------------------------------------------------------------


def test_inventory_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(gcp_inventory.INVENTORY_ENV_FLAG, raising=False)
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "proj-1")
    assert gcp_inventory.inventory_enabled() is False
    payload = gcp_inventory.discover_inventory()
    assert payload["status"] == "disabled"
    assert payload["buckets"] == []
    assert payload["service_accounts"] == []


def test_inventory_flag_enables(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(gcp_inventory.INVENTORY_ENV_FLAG, "true")
    assert gcp_inventory.inventory_enabled() is True


def test_inventory_flag_off_short_circuits_before_sdk(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(gcp_inventory.INVENTORY_ENV_FLAG, raising=False)
    with patch.dict(sys.modules, {"google.cloud.storage": None}):
        payload = gcp_inventory.discover_inventory()
    assert payload["status"] == "disabled"


# ---------------------------------------------------------------------------
# Degraded paths
# ---------------------------------------------------------------------------


def test_inventory_sdk_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(gcp_inventory.INVENTORY_ENV_FLAG, "1")
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "proj-1")
    import builtins

    original = builtins.__import__

    def _no_gcp(name: str, *args: Any, **kwargs: Any) -> Any:
        # The module imports `from google.cloud import storage`.
        if name == "google.cloud" and "storage" in (args[2] if len(args) > 2 and args[2] else kwargs.get("fromlist", ())):
            raise ImportError("mocked")
        return original(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=_no_gcp):
        payload = gcp_inventory.discover_inventory()
    assert payload["status"] == "sdk_missing"
    assert payload["buckets"] == []
    assert payload["warnings"]


def test_inventory_no_project(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(gcp_inventory.INVENTORY_ENV_FLAG, "1")
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    with _install_fake_gcp():
        payload = gcp_inventory.discover_inventory()
    assert payload["status"] == "no_project"
    assert payload["warnings"]


# ---------------------------------------------------------------------------
# Enumeration
# ---------------------------------------------------------------------------


def test_inventory_enumerates_all_three_classes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(gcp_inventory.INVENTORY_ENV_FLAG, "1")
    with _install_fake_gcp():
        payload = gcp_inventory.discover_inventory(project_id="proj-1")

    assert payload["status"] == "ok"
    assert payload["project_id"] == "proj-1"

    # GCS buckets: estate-wide, public posture from IAM policy only.
    buckets = {b["name"]: b for b in payload["buckets"]}
    assert set(buckets) == {"public-lake", "private-logs"}
    assert buckets["public-lake"]["publicly_accessible"] is True
    assert buckets["public-lake"]["tags"] == {"classification": "pii"}
    assert buckets["private-logs"]["publicly_accessible"] is False

    # Compute instances (NOT label-filtered).
    assert len(payload["instances"]) == 1
    inst = payload["instances"][0]
    assert inst["name"] == "web-1"
    assert inst["instance_type"] == "e2-medium"
    assert inst["public_ip"] == "203.0.113.7"
    assert inst["service_accounts"] == ["vm-sa@p.iam.gserviceaccount.com"]

    # Firewall rules with structured exposure.
    firewalls = {f["name"]: f for f in payload["firewalls"]}
    assert firewalls["allow-ssh"]["internet_exposed"] is True
    assert firewalls["allow-ssh"]["network_exposure"][0]["from_port"] == 22
    assert firewalls["internal-https"]["internet_exposed"] is False

    # Service accounts as principals.
    accounts = {a["arn"]: a for a in payload["service_accounts"]}
    sa = accounts["svc@p.iam.gserviceaccount.com"]
    assert sa["principal_type"] == "service-account"
    assert sa["principal_id"] == "sa-unique-1"
    assert sa["privilege_level"] == "unknown"

    # Per-run trust contract.
    env = payload["discovery_envelope"]
    assert env["scan_mode"] == "cloud_read_only"
    assert "storage.buckets.list" in env["permissions_used"]
    assert "gcp:project/proj-1" in env["discovery_scope"]


def test_inventory_force_bypasses_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(gcp_inventory.INVENTORY_ENV_FLAG, raising=False)
    with _install_fake_gcp():
        payload = gcp_inventory.discover_inventory(project_id="proj-1", force=True)
    assert payload["status"] == "ok"
    assert payload["buckets"]


def test_inventory_selective_classes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(gcp_inventory.INVENTORY_ENV_FLAG, "1")
    with _install_fake_gcp():
        payload = gcp_inventory.discover_inventory(project_id="proj-1", include_compute=False, include_iam=False)
    assert payload["buckets"]
    assert payload["instances"] == []
    assert payload["service_accounts"] == []
    env = payload["discovery_envelope"]
    assert "compute.instances.list" not in env["permissions_used"]
    assert "iam.serviceAccounts.list" not in env["permissions_used"]


# ---------------------------------------------------------------------------
# Graph-builder integration
# ---------------------------------------------------------------------------


def _build_graph_from_inventory(payload: dict[str, Any]) -> Any:
    from agent_bom.graph.builder import build_unified_graph_from_report

    return build_unified_graph_from_report({"agents": [], "cloud_inventory": payload})


def test_graph_emits_inventory_nodes_and_overlays(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(gcp_inventory.INVENTORY_ENV_FLAG, "1")
    with _install_fake_gcp():
        payload = gcp_inventory.discover_inventory(project_id="proj-1")

    graph = _build_graph_from_inventory(payload)
    from agent_bom.graph.types import EntityType

    nodes = graph.nodes
    # GCS bucket → CLOUD_RESOURCE, with a DATA_STORE companion from CNAPP.
    bucket_id = "cloud_resource:gcp:gcs:bucket:public-lake"
    assert bucket_id in nodes
    assert nodes[bucket_id].attributes["internet_exposed"] is True
    assert f"data_store:{bucket_id}" in nodes
    assert nodes[f"data_store:{bucket_id}"].entity_type == EntityType.DATA_STORE

    # Compute instance + firewall present.
    inst_id = "cloud_resource:gcp:compute:instance:123"
    fw_id = "cloud_resource:gcp:compute:firewall:allow-ssh"
    assert inst_id in nodes
    assert fw_id in nodes
    assert nodes[fw_id].attributes["internet_exposed"] is True

    # Service account as a SERVICE_ACCOUNT principal node.
    sa_id = "service_account:gcp:svc@p.iam.gserviceaccount.com"
    assert sa_id in nodes
    assert nodes[sa_id].entity_type == EntityType.SERVICE_ACCOUNT


def test_graph_multiple_provider_inventories() -> None:
    """The builder accepts a list of per-provider payloads."""
    from agent_bom.graph.builder import build_unified_graph_from_report

    aws_payload = {
        "provider": "aws",
        "status": "ok",
        "account_id": "111122223333",
        "region": "us-east-1",
        "buckets": [{"name": "aws-bucket", "arn": "arn:aws:s3:::aws-bucket", "publicly_accessible": False}],
        "instances": [],
        "security_groups": [],
        "roles": [],
        "users": [],
    }
    gcp_payload = {
        "provider": "gcp",
        "status": "ok",
        "project_id": "proj-1",
        "buckets": [{"name": "gcp-bucket", "publicly_accessible": False}],
        "instances": [],
        "firewalls": [],
        "service_accounts": [],
    }
    graph = build_unified_graph_from_report({"agents": [], "cloud_inventory": [aws_payload, gcp_payload]})
    assert "cloud_resource:aws:s3:bucket:aws-bucket" in graph.nodes
    assert "cloud_resource:gcp:gcs:bucket:gcp-bucket" in graph.nodes


def test_graph_inventory_noop_when_not_ok() -> None:
    graph = _build_graph_from_inventory({"provider": "gcp", "status": "disabled", "buckets": [], "instances": [], "firewalls": []})
    assert not any(nid.startswith("cloud_resource:gcp:") for nid in graph.nodes)
