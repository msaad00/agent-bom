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
                _Obj(
                    network_i_p="10.0.0.5",
                    network="https://www.googleapis.com/compute/v1/projects/p/global/networks/default",
                    access_configs=[_Obj(nat_i_p="203.0.113.7")],
                ),
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


class _FakeNetworksClient:
    def __init__(self, credentials: Any = None) -> None:
        pass

    def list(self, project: str) -> list[Any]:
        return [
            _Obj(
                name="default",
                id="net-1",
                self_link="https://www.googleapis.com/compute/v1/projects/p/global/networks/default",
                auto_create_subnetworks=True,
            ),
        ]


class _FakeSubnetworksClient:
    def __init__(self, credentials: Any = None) -> None:
        pass

    def aggregated_list(self, project: str) -> list[Any]:
        subnet = _Obj(
            name="default-sub",
            region="https://www.googleapis.com/compute/v1/projects/p/regions/us-central1",
            ip_cidr_range="10.0.0.0/20",
            network="https://www.googleapis.com/compute/v1/projects/p/global/networks/default",
            enable_flow_logs=True,
        )
        return [("regions/us-central1", _Obj(subnetworks=[subnet]))]


class _FakeDisksClient:
    def __init__(self, credentials: Any = None) -> None:
        pass

    def aggregated_list(self, project: str) -> list[Any]:
        disk = _Obj(
            name="web-disk",
            id="disk-1",
            zone="https://www.googleapis.com/compute/v1/projects/p/zones/us-central1-a",
            size_gb=50,
            disk_encryption_key=_Obj(kms_key_name="projects/p/locations/us/keyRings/r/cryptoKeys/k"),
            source_image="https://www.googleapis.com/compute/v1/projects/debian-cloud/global/images/debian-12",
            labels={"app": "web"},
        )
        return [("zones/us-central1-a", _Obj(disks=[disk]))]


class _FakeComputeModule(types.ModuleType):
    InstancesClient = _FakeInstancesClient
    FirewallsClient = _FakeFirewallsClient
    NetworksClient = _FakeNetworksClient
    SubnetworksClient = _FakeSubnetworksClient
    DisksClient = _FakeDisksClient


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
        return [
            _FakeServiceAccount("svc@p.iam.gserviceaccount.com", "Service Bot", "sa-unique-1"),
            _FakeServiceAccount("overperm@p.iam.gserviceaccount.com", "Over-Permissioned", "sa-unique-2"),
            _FakeServiceAccount("reader@p.iam.gserviceaccount.com", "Read Only", "sa-unique-3"),
        ]


class _FakeListSARequest:
    def __init__(self, name: str) -> None:
        self.name = name


class _FakeIAMAdminModule(types.ModuleType):
    IAMClient = _FakeIAMClient
    ListServiceAccountsRequest = _FakeListSARequest


# Project IAM policy: editor-bound SA → write, viewer-bound SA → read.
class _FakeProjectsClient:
    def __init__(self, credentials: Any = None) -> None:
        pass

    def get_iam_policy(self, request: Any) -> Any:
        return _Obj(
            bindings=[
                {"role": "roles/editor", "members": ["serviceAccount:overperm@p.iam.gserviceaccount.com"]},
                {"role": "roles/viewer", "members": ["serviceAccount:reader@p.iam.gserviceaccount.com"]},
            ]
        )


class _FakeResourceManagerModule(types.ModuleType):
    ProjectsClient = _FakeProjectsClient


class _FakeGetIamPolicyRequest:
    def __init__(self, resource: str) -> None:
        self.resource = resource


class _FakeIamPolicyPb2Module(types.ModuleType):
    GetIamPolicyRequest = _FakeGetIamPolicyRequest


# --- GKE clusters -----------------------------------------------------------
class _FakeClusterManagerClient:
    def __init__(self, credentials: Any = None) -> None:
        pass

    def list_clusters(self, parent: str) -> Any:
        public = _Obj(
            name="public-gke",
            id="c-1",
            location="us-central1",
            endpoint="35.1.2.3",
            current_node_count=3,
            current_master_version="1.29",
            resource_labels={"env": "prod"},
            private_cluster_config=_Obj(enable_private_endpoint=False, enable_private_nodes=False),
        )
        private = _Obj(
            name="private-gke",
            id="c-2",
            location="us-east1",
            endpoint="10.0.0.2",
            current_node_count=2,
            current_master_version="1.29",
            resource_labels={},
            private_cluster_config=_Obj(enable_private_endpoint=True, enable_private_nodes=True),
        )
        return _Obj(clusters=[public, private])


class _FakeContainerModule(types.ModuleType):
    ClusterManagerClient = _FakeClusterManagerClient


# --- Cloud Run --------------------------------------------------------------
class _FakeRunServicesClient:
    def __init__(self, credentials: Any = None) -> None:
        pass

    def list_services(self, request: Any) -> list[Any]:
        return [
            _Obj(
                name="projects/proj-1/locations/us-central1/services/public-api",
                uri="https://public-api-abc.run.app",
                ingress="INGRESS_TRAFFIC_ALL",
                labels={"team": "x"},
            ),
            _Obj(
                name="projects/proj-1/locations/us-central1/services/internal-api",
                uri="https://internal-api-abc.run.app",
                ingress="INGRESS_TRAFFIC_INTERNAL_ONLY",
                labels={},
            ),
        ]


class _FakeRunListServicesRequest:
    def __init__(self, parent: str) -> None:
        self.parent = parent


class _FakeRunModule(types.ModuleType):
    ServicesClient = _FakeRunServicesClient
    ListServicesRequest = _FakeRunListServicesRequest


# --- Cloud Functions --------------------------------------------------------
class _FakeFunctionServiceClient:
    def __init__(self, credentials: Any = None) -> None:
        pass

    def list_functions(self, request: Any) -> list[Any]:
        return [
            _Obj(
                name="projects/proj-1/locations/us-central1/functions/ingest",
                service_config=_Obj(ingress_settings="ALLOW_ALL"),
                event_trigger=None,
                labels={},
            ),
        ]


class _FakeFunctionsListRequest:
    def __init__(self, parent: str) -> None:
        self.parent = parent


class _FakeFunctionsModule(types.ModuleType):
    FunctionServiceClient = _FakeFunctionServiceClient
    ListFunctionsRequest = _FakeFunctionsListRequest


# --- Pub/Sub ----------------------------------------------------------------
class _FakePublisherClient:
    def __init__(self, credentials: Any = None) -> None:
        pass

    def list_topics(self, request: Any) -> list[Any]:
        return [_Obj(name="projects/proj-1/topics/abom-demo-topic", labels={})]


class _FakePubsubModule(types.ModuleType):
    PublisherClient = _FakePublisherClient


# --- Cloud SQL (googleapiclient discovery) ----------------------------------
class _FakeSqlInstances:
    def list(self, project: str) -> Any:
        return _FakeSqlExecute(
            {
                "items": [
                    {
                        "name": "public-db",
                        "selfLink": "https://.../public-db",
                        "region": "us-central1",
                        "databaseVersion": "POSTGRES_15",
                        "ipAddresses": [{"type": "PRIMARY", "ipAddress": "34.10.20.30"}],
                        "settings": {"ipConfiguration": {"ipv4Enabled": True, "authorizedNetworks": []}},
                        "diskEncryptionConfiguration": {},
                    },
                    {
                        "name": "private-db",
                        "selfLink": "https://.../private-db",
                        "region": "us-east1",
                        "databaseVersion": "MYSQL_8_0",
                        "ipAddresses": [{"type": "PRIVATE", "ipAddress": "10.1.2.3"}],
                        "settings": {"ipConfiguration": {"ipv4Enabled": False, "authorizedNetworks": []}},
                        "diskEncryptionConfiguration": {"kmsKeyName": "projects/p/.../k"},
                    },
                ]
            }
        )


class _FakeSqlExecute:
    def __init__(self, result: dict[str, Any]) -> None:
        self._result = result

    def execute(self) -> dict[str, Any]:
        return self._result


class _FakeSqlService:
    def instances(self) -> _FakeSqlInstances:
        return _FakeSqlInstances()


def _fake_discovery_build(*args: Any, **kwargs: Any) -> Any:
    """Stand-in for googleapiclient.discovery.build("sqladmin", ...)."""
    return _FakeSqlService()


def _install_fake_gcp() -> Any:
    """Return a patch.dict context installing fake google-cloud SDK modules."""
    google_mod = types.ModuleType("google")
    cloud_mod = types.ModuleType("google.cloud")
    storage_mod = _FakeStorageModule("google.cloud.storage")
    compute_mod = _FakeComputeModule("google.cloud.compute_v1")
    iam_mod = _FakeIAMAdminModule("google.cloud.iam_admin_v1")
    rm_mod = _FakeResourceManagerModule("google.cloud.resourcemanager_v3")
    iam_v1_mod = types.ModuleType("google.iam")
    iam_v1_sub = types.ModuleType("google.iam.v1")
    iam_policy_mod = _FakeIamPolicyPb2Module("google.iam.v1.iam_policy_pb2")
    container_mod = _FakeContainerModule("google.cloud.container_v1")
    run_mod = _FakeRunModule("google.cloud.run_v2")
    functions_mod = _FakeFunctionsModule("google.cloud.functions_v2")
    pubsub_mod = _FakePubsubModule("google.cloud.pubsub_v1")
    apiclient_mod = types.ModuleType("googleapiclient")
    discovery_mod = types.ModuleType("googleapiclient.discovery")
    discovery_mod.build = _fake_discovery_build  # type: ignore[attr-defined]
    return patch.dict(
        sys.modules,
        {
            "google": google_mod,
            "google.cloud": cloud_mod,
            "google.cloud.storage": storage_mod,
            "google.cloud.compute_v1": compute_mod,
            "google.cloud.iam_admin_v1": iam_mod,
            "google.cloud.resourcemanager_v3": rm_mod,
            "google.iam": iam_v1_mod,
            "google.iam.v1": iam_v1_sub,
            "google.iam.v1.iam_policy_pb2": iam_policy_mod,
            "google.cloud.container_v1": container_mod,
            "google.cloud.run_v2": run_mod,
            "google.cloud.functions_v2": functions_mod,
            "google.cloud.pubsub_v1": pubsub_mod,
            "googleapiclient": apiclient_mod,
            "googleapiclient.discovery": discovery_mod,
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

    # Service accounts as principals, privilege classified from project IAM bindings.
    accounts = {a["arn"]: a for a in payload["service_accounts"]}
    sa = accounts["svc@p.iam.gserviceaccount.com"]
    assert sa["principal_type"] == "service-account"
    assert sa["principal_id"] == "sa-unique-1"
    # No project binding for svc → unknown (never inflated).
    assert sa["privilege_level"] == "unknown"
    # roles/editor → write; roles/viewer → read.
    assert accounts["overperm@p.iam.gserviceaccount.com"]["privilege_level"] == "write"
    assert accounts["overperm@p.iam.gserviceaccount.com"]["roles"] == ["roles/editor"]
    assert accounts["reader@p.iam.gserviceaccount.com"]["privilege_level"] == "read"

    # Instance carries its network + structured firewall-join fields.
    assert inst["network"] == "default"
    # Permissive 0.0.0.0/0 firewall captures its source ranges + target scope.
    assert firewalls["allow-ssh"]["source_ranges"] == ["0.0.0.0/0"]
    assert firewalls["allow-ssh"]["target_tags"] == []

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


# ---------------------------------------------------------------------------
# Privilege classification (mirror AWS IAM privilege levels)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("role", "expected"),
    [
        ("roles/owner", "admin"),
        ("roles/editor", "write"),
        ("roles/viewer", "read"),
        ("roles/storage.admin", "admin"),
        ("roles/compute.admin", "admin"),
        ("roles/storage.objectViewer", "read"),
        ("roles/bigquery.dataViewer", "read"),
        ("roles/logging.viewer", "read"),
        ("roles/run.invoker", "unknown"),
        ("", "unknown"),
    ],
)
def test_classify_role_privilege(role: str, expected: str) -> None:
    assert gcp_inventory._classify_role_privilege(role) == expected


def test_highest_privilege_takes_max() -> None:
    assert gcp_inventory._highest_privilege(["roles/viewer", "roles/editor"]) == "write"
    assert gcp_inventory._highest_privilege(["roles/viewer", "roles/owner"]) == "admin"
    assert gcp_inventory._highest_privilege([]) == "unknown"


def test_editor_service_account_classifies_as_write(monkeypatch: pytest.MonkeyPatch) -> None:
    """An roles/editor-bound SA must classify as write so CIEM reasoning fires."""
    monkeypatch.setenv(gcp_inventory.INVENTORY_ENV_FLAG, "1")
    with _install_fake_gcp():
        payload = gcp_inventory.discover_inventory(project_id="proj-1")
    accounts = {a["arn"]: a for a in payload["service_accounts"]}
    overperm = accounts["overperm@p.iam.gserviceaccount.com"]
    assert overperm["privilege_level"] == "write"
    # The bound role becomes a classified policy entry the graph promotes to POLICY.
    assert overperm["policies"][0]["policy_name"] == "roles/editor"
    assert overperm["policies"][0]["privilege_level"] == "write"


def test_graph_promotes_editor_sa_privilege(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(gcp_inventory.INVENTORY_ENV_FLAG, "1")
    with _install_fake_gcp():
        payload = gcp_inventory.discover_inventory(project_id="proj-1")
    graph = _build_graph_from_inventory(payload)
    sa_id = "service_account:gcp:overperm@p.iam.gserviceaccount.com"
    assert sa_id in graph.nodes
    assert graph.nodes[sa_id].attributes["privilege_level"] == "write"


# ---------------------------------------------------------------------------
# Compute internet-exposure (mirror AWS EC2 + security groups)
# ---------------------------------------------------------------------------


def test_graph_marks_instance_exposed_with_edge(monkeypatch: pytest.MonkeyPatch) -> None:
    """An external-IP instance + a 0.0.0.0/0 firewall on its network is exposed."""
    monkeypatch.setenv(gcp_inventory.INVENTORY_ENV_FLAG, "1")
    with _install_fake_gcp():
        payload = gcp_inventory.discover_inventory(project_id="proj-1")
    graph = _build_graph_from_inventory(payload)
    from agent_bom.graph.types import RelationshipType

    inst_id = "cloud_resource:gcp:compute:instance:123"
    fw_id = "cloud_resource:gcp:compute:firewall:allow-ssh"
    assert graph.nodes[inst_id].attributes["internet_exposed"] is True
    exposed_edges = [e for e in graph.edges if e.relationship == RelationshipType.EXPOSED_TO and e.source == fw_id and e.target == inst_id]
    assert len(exposed_edges) == 1
    assert exposed_edges[0].evidence.get("reason") == "permissive_firewall_external_ip"


def test_no_exposure_without_external_ip() -> None:
    """An instance with NO public IP is not exposed even under a 0.0.0.0/0 rule."""
    payload = {
        "provider": "gcp",
        "status": "ok",
        "project_id": "proj-1",
        "buckets": [],
        "instances": [
            {"instance_id": "i-private", "name": "private-1", "public_ip": "", "network": "default", "network_tags": []},
        ],
        "firewalls": [
            {
                "group_id": "allow-all",
                "name": "allow-all",
                "network": "default",
                "internet_exposed": True,
                "network_exposure": [{"scope": "internet", "from_port": 22, "to_port": 22, "protocol": "tcp"}],
                "source_ranges": ["0.0.0.0/0"],
                "target_tags": [],
                "target_service_accounts": [],
            }
        ],
        "service_accounts": [],
    }
    graph = _build_graph_from_inventory(payload)
    from agent_bom.graph.types import RelationshipType

    inst_id = "cloud_resource:gcp:compute:instance:i-private"
    assert not graph.nodes[inst_id].attributes.get("internet_exposed")
    assert not any(e.relationship == RelationshipType.EXPOSED_TO and e.target == inst_id for e in graph.edges)


def test_target_tag_scopes_firewall_to_matching_instance() -> None:
    """A target-tagged firewall exposes only instances carrying that tag."""
    payload = {
        "provider": "gcp",
        "status": "ok",
        "project_id": "proj-1",
        "buckets": [],
        "instances": [
            {"instance_id": "i-web", "name": "web", "public_ip": "34.46.45.57", "network": "default", "network_tags": ["http-server"]},
            {"instance_id": "i-db", "name": "db", "public_ip": "34.46.45.99", "network": "default", "network_tags": ["db"]},
        ],
        "firewalls": [
            {
                "group_id": "allow-http",
                "name": "allow-http",
                "network": "default",
                "internet_exposed": True,
                "network_exposure": [{"scope": "internet", "from_port": 80, "to_port": 80, "protocol": "tcp"}],
                "source_ranges": ["0.0.0.0/0"],
                "target_tags": ["http-server"],
                "target_service_accounts": [],
            }
        ],
        "service_accounts": [],
    }
    graph = _build_graph_from_inventory(payload)
    web_id = "cloud_resource:gcp:compute:instance:i-web"
    db_id = "cloud_resource:gcp:compute:instance:i-db"
    assert graph.nodes[web_id].attributes["internet_exposed"] is True
    # The db instance does not carry the http-server tag → not exposed by this rule.
    assert not graph.nodes[db_id].attributes.get("internet_exposed")


# ---------------------------------------------------------------------------
# Estate breadth: GKE / Cloud Run / Functions / Cloud SQL / VPC / disks / Pub/Sub
# ---------------------------------------------------------------------------


def test_inventory_enumerates_estate_breadth(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(gcp_inventory.INVENTORY_ENV_FLAG, "1")
    with _install_fake_gcp():
        payload = gcp_inventory.discover_inventory(project_id="proj-1")

    assert payload["status"] == "ok"

    # GKE: public-endpoint cluster exposed, private not.
    gke = {c["name"]: c for c in payload["gke_clusters"]}
    assert set(gke) == {"public-gke", "private-gke"}
    assert gke["public-gke"]["internet_exposed"] is True
    assert gke["public-gke"]["node_count"] == 3
    assert gke["private-gke"]["internet_exposed"] is False

    # Cloud Run: all-ingress public, internal-only private.
    run = {s["name"]: s for s in payload["cloud_run_services"]}
    assert run["public-api"]["internet_exposed"] is True
    assert run["public-api"]["location"] == "us-central1"
    assert run["public-api"]["url"] == "https://public-api-abc.run.app"
    assert run["internal-api"]["internet_exposed"] is False

    # Cloud Functions: ALLOW_ALL ingress is public.
    funcs = {f["name"]: f for f in payload["cloud_functions"]}
    assert funcs["ingest"]["internet_exposed"] is True
    assert funcs["ingest"]["trigger"] == "https"
    assert funcs["ingest"]["location"] == "us-central1"

    # Cloud SQL: public-IP instance exposed; private instance not; encryption read.
    sql = {i["name"]: i for i in payload["cloud_sql_instances"]}
    assert sql["public-db"]["internet_exposed"] is True
    assert sql["public-db"]["publicly_accessible"] is True
    assert sql["public-db"]["database_version"] == "POSTGRES_15"
    assert sql["private-db"]["internet_exposed"] is False
    assert sql["private-db"]["encrypted"] is True

    # VPC network + subnet (CIDR + flow logs).
    nets = {n["name"]: n for n in payload["vpc_networks"]}
    assert nets["default"]["auto_create_subnetworks"] is True
    assert nets["default"]["subnets"][0]["cidr"] == "10.0.0.0/20"
    assert nets["default"]["subnets"][0]["flow_logs"] is True

    # Persistent disk (size, encryption, source image).
    disks = {d["name"]: d for d in payload["disks"]}
    assert disks["web-disk"]["size_gb"] == 50
    assert disks["web-disk"]["encrypted"] is True
    assert disks["web-disk"]["source_image"] == "debian-12"

    # Pub/Sub topic.
    topics = {t["name"]: t for t in payload["pubsub_topics"]}
    assert "abom-demo-topic" in topics

    # Per-run trust contract picks up the estate permissions.
    env = payload["discovery_envelope"]
    assert "container.clusters.list" in env["permissions_used"]
    assert "cloudsql.instances.list" in env["permissions_used"]
    assert "pubsub.topics.list" in env["permissions_used"]


def test_estate_discoverers_degrade_on_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """An exception in any estate discoverer becomes a warning, never a crash."""
    monkeypatch.setenv(gcp_inventory.INVENTORY_ENV_FLAG, "1")

    class _BoomContainer(types.ModuleType):
        class ClusterManagerClient:  # noqa: D106
            def __init__(self, credentials: Any = None) -> None:
                raise RuntimeError("API disabled")

    with _install_fake_gcp(), patch.dict(sys.modules, {"google.cloud.container_v1": _BoomContainer("google.cloud.container_v1")}):
        payload = gcp_inventory.discover_inventory(project_id="proj-1")
    assert payload["status"] == "ok"
    assert payload["gke_clusters"] == []
    assert any("GKE" in w for w in payload["warnings"])


def test_estate_selective_classes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(gcp_inventory.INVENTORY_ENV_FLAG, "1")
    with _install_fake_gcp():
        payload = gcp_inventory.discover_inventory(
            project_id="proj-1",
            include_containers=False,
            include_databases=False,
            include_messaging=False,
        )
    assert payload["gke_clusters"] == []
    assert payload["cloud_sql_instances"] == []
    assert payload["pubsub_topics"] == []
    # Others still enumerate.
    assert payload["cloud_run_services"]
    assert payload["disks"]
    env = payload["discovery_envelope"]
    assert "container.clusters.list" not in env["permissions_used"]
    assert "pubsub.topics.list" not in env["permissions_used"]


def test_graph_emits_estate_nodes_and_owns_edges(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(gcp_inventory.INVENTORY_ENV_FLAG, "1")
    with _install_fake_gcp():
        payload = gcp_inventory.discover_inventory(project_id="proj-1")
    graph = _build_graph_from_inventory(payload)
    from agent_bom.graph.types import EntityType, RelationshipType

    nodes = graph.nodes
    account_id = "account:gcp:proj-1"

    # GKE cluster → CLOUD_RESOURCE, public endpoint exposed.
    gke_id = "cloud_resource:gcp:gke:container_cluster:c-1"
    assert gke_id in nodes
    assert nodes[gke_id].entity_type == EntityType.CLOUD_RESOURCE
    assert nodes[gke_id].attributes["internet_exposed"] is True

    # Cloud Run public service exposed.
    run_id = "cloud_resource:gcp:run:function:public-api"
    assert run_id in nodes
    assert nodes[run_id].attributes["internet_exposed"] is True

    # Cloud SQL → DATA_STORE, public IP exposed (feeds CNAPP/attack-paths).
    sql_id = "cloud_resource:gcp:cloudsql:database:public-db"
    assert sql_id in nodes
    assert nodes[sql_id].entity_type == EntityType.DATA_STORE
    assert nodes[sql_id].attributes["internet_exposed"] is True

    # VPC, disk, Pub/Sub topic present.
    assert "cloud_resource:gcp:compute:virtual_network:default" in nodes
    assert "cloud_resource:gcp:compute:storage:web-disk" in nodes
    assert "cloud_resource:gcp:pubsub:messaging:abom-demo-topic" in nodes

    # Every estate node is OWNS-linked from the project/account node.
    owns_targets = {e.target for e in graph.edges if e.relationship == RelationshipType.OWNS and e.source == account_id}
    assert gke_id in owns_targets
    assert sql_id in owns_targets
    assert "cloud_resource:gcp:pubsub:messaging:abom-demo-topic" in owns_targets


# ---------------------------------------------------------------------------
# Partial-permission tolerance: a single failing discoverer must degrade to a
# warning (and, for access errors, an actionable missing_permissions entry)
# without aborting the rest of the scan.
# ---------------------------------------------------------------------------


class PermissionDenied(Exception):  # noqa: N818 — name must match the real google-api-core SDK type the classifier keys on
    """Stand-in for google.api_core.exceptions.PermissionDenied (403 / code 7).

    Named to match the real SDK exception so the access-error classifier keys off
    the type name without importing the heavy google-api-core dependency.
    """

    def __init__(self) -> None:
        super().__init__("403 Permission 'container.clusters.list' denied on project 'proj-1'.")
        self.code = 403


def test_gcp_discoverer_exception_does_not_abort_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    # Patch the SDK call INSIDE the bucket discoverer so the genuine
    # try/except degrade path runs (not a stubbed discoverer).
    monkeypatch.setenv(gcp_inventory.INVENTORY_ENV_FLAG, "1")

    def _boom(self: Any) -> list[Any]:
        raise RuntimeError("transient 500 from the GCS list endpoint")

    monkeypatch.setattr(_FakeStorageClient, "list_buckets", _boom)
    with _install_fake_gcp():
        payload = gcp_inventory.discover_inventory(project_id="proj-1")

    # The overall call still returns ok and the OTHER resource types are present.
    assert payload["status"] == "ok"
    assert payload["buckets"] == []  # the failed type degrades to empty…
    assert {c["name"] for c in payload["gke_clusters"]} == {"public-gke", "private-gke"}  # …others survive
    # …but the skipped type still produced a clear warning (no silent drop).
    assert any("transient 500" in w for w in payload["warnings"])
    # A generic (non-access) failure produces NO missing_permissions entry.
    assert payload["missing_permissions"] == []


def test_gcp_permission_denied_degrades_with_guidance(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(gcp_inventory.INVENTORY_ENV_FLAG, "1")

    def _denied(self: Any, parent: str) -> Any:
        raise PermissionDenied()

    monkeypatch.setattr(_FakeClusterManagerClient, "list_clusters", _denied)
    with _install_fake_gcp():
        payload = gcp_inventory.discover_inventory(project_id="proj-1")

    assert payload["status"] == "ok"
    # Other resource types still discovered — no silent total failure.
    assert {b["name"] for b in payload["buckets"]} == {"public-lake", "private-logs"}
    assert payload["gke_clusters"] == []
    # The access error yields an ACTIONABLE warning naming the missing permission.
    actionable = [w for w in payload["warnings"] if "role lacks" in w and "GKE clusters" in w]
    assert actionable, payload["warnings"]
    assert "container.clusters.list" in actionable[0]
    assert "add it to the read-only policy" in actionable[0]
    # And a structured missing_permissions entry the product can render.
    entries = [e for e in payload["missing_permissions"] if e["resource_type"] == "GKE clusters"]
    assert entries == [{"cloud": "gcp", "permission": "container.clusters.list", "resource_type": "GKE clusters"}]


def test_gcp_missing_permissions_are_sorted_and_deduped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(gcp_inventory.INVENTORY_ENV_FLAG, "1")

    def _denied_clusters(self: Any, parent: str) -> Any:
        raise PermissionDenied()

    def _denied_buckets(self: Any) -> list[Any]:
        raise PermissionDenied()

    monkeypatch.setattr(_FakeClusterManagerClient, "list_clusters", _denied_clusters)
    monkeypatch.setattr(_FakeStorageClient, "list_buckets", _denied_buckets)
    with _install_fake_gcp():
        payload = gcp_inventory.discover_inventory(project_id="proj-1")

    perms = payload["missing_permissions"]
    # Sorted by (cloud, resource_type, permission) → GCS buckets before GKE clusters.
    assert [e["resource_type"] for e in perms] == ["GCS buckets", "GKE clusters"]
    # Idempotent: re-deduping the same list is a no-op.
    assert gcp_inventory.dedupe_missing_permissions(perms + perms) == perms
