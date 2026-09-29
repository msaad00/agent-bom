"""Characterization golden for ``agent_bom.cloud.gcp_inventory`` discovery.

Drives ``discover_inventory`` and ``discover_all_project_inventories`` against a
fully faked google SDK surface (no network) and pins the COMPLETE returned
payloads, the ordered SDK call log, and the emitted ``agent_bom`` log records.
Every resource family is covered on the happy path plus every failure branch the
discoverers share: PermissionDenied, HTTP 403, API disabled, billing disabled,
throttled (429 / ResourceExhausted), generic errors, empty results, SDK absence,
and Cloud SQL pagination.

Regenerate the golden with ``UPDATE_CLOUD_GOLDEN=1``.

Normalized values: timestamps produced by the real authorization collector
(``_ISO_TS``) become ``<ts>``; multi-project payloads are sorted by
``project_id`` because ``as_completed`` yields in completion order.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import types
from pathlib import Path
from typing import Any

import pytest

from agent_bom.cloud import gcp_inventory, gcp_organizations
from tests._sdk_stub_helpers import patch_sdk_namespace

GOLDEN = Path(__file__).parent / "fixtures" / "cloud_characterization" / "gcp_inventory.json"
_ISO_TS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(\+00:00|Z)?")

CL = "https://www.googleapis.com/compute/v1/projects/p"


# ---------------------------------------------------------------------------
# Fake exceptions (names match the SDK types the classifiers key on)
# ---------------------------------------------------------------------------


class PermissionDenied(Exception):  # noqa: N818
    pass


class Forbidden(Exception):  # noqa: N818
    status_code = 403


class ResourceExhausted(Exception):  # noqa: N818
    status_code = 429


class ServiceDisabled(Exception):  # noqa: N818
    reason = "SERVICE_DISABLED"


class BillingDisabled(Exception):  # noqa: N818
    reason = "BILLING_DISABLED"


_FAILURES = {
    "denied": lambda key: PermissionDenied(f"caller lacks permission for {key}"),
    "forbidden": lambda key: Forbidden(f"403 forbidden {key}"),
    "throttled": lambda key: ResourceExhausted(f"429 Quota exceeded for {key}"),
    "api_disabled": lambda key: ServiceDisabled(f"API not usable for {key}"),
    "billing": lambda key: BillingDisabled(f"billing problem for {key}"),
    "boom": lambda key: RuntimeError(f"transient 500 from {key}"),
}


class _Obj:
    def __init__(self, **kwargs: Any) -> None:
        self.__dict__.update(kwargs)


class _Estate:
    """Per-scenario behaviour: ``mode[key]`` in ok / empty / a ``_FAILURES`` key."""

    def __init__(self, default: str = "ok", **overrides: str) -> None:
        self.default = default
        self.overrides = overrides
        self.calls: list[list[Any]] = []

    def mode(self, key: str) -> str:
        return self.overrides.get(key, self.default)

    def run(self, key: str, credentials: Any, data: Any, empty: Any = None, **kwargs: Any) -> Any:
        self.calls.append([key, _cred_label(credentials), {k: str(v) for k, v in sorted(kwargs.items())}])
        mode = self.mode(key)
        if mode == "empty":
            return [] if empty is None else empty
        if mode in _FAILURES:
            raise _FAILURES[mode](key)
        return data


def _cred_label(credentials: Any) -> Any:
    if credentials is None:
        return None
    return getattr(credentials, "label", type(credentials).__name__)


ESTATE = _Estate()


# ---------------------------------------------------------------------------
# Fake data
# ---------------------------------------------------------------------------


class _Bucket:
    def __init__(self, name: str, members: list[str] | None, labels: Any, policy_error: bool = False) -> None:
        self.name = name
        self.location = "US"
        self.labels = labels
        self._members = members
        self._policy_error = policy_error

    def get_iam_policy(self) -> Any:
        if self._policy_error:
            raise PermissionDenied("bucket policy read denied")
        return {"bindings": [{"role": "roles/storage.objectViewer", "members": self._members}]}


def _buckets() -> list[Any]:
    plain = _Obj(name="no-policy-method", location="EU", labels=None)
    return [
        _Bucket("public-lake", ["allUsers"], {"classification": "pii", None: "dropped"}),
        _Bucket("auth-lake", ["allAuthenticatedUsers:x"], {}),
        _Bucket("private-logs", ["user:alice@example.com"], "not-a-dict"),
        _Bucket("policy-denied", None, {}, policy_error=True),
        _Bucket("", ["allUsers"], {}),
        plain,
    ]


def _instances() -> list[Any]:
    web = _Obj(
        id="123",
        name="web-1",
        machine_type=f"{CL}/zones/us-central1-a/machineTypes/e2-medium",
        zone=f"{CL}/zones/us-central1-a",
        status="RUNNING",
        network_interfaces=[
            _Obj(network_i_p="10.0.0.5", network=f"{CL}/global/networks/default", access_configs=[_Obj(nat_i_p="203.0.113.7")]),
            _Obj(network_ip="10.1.0.5", network=f"{CL}/global/networks/default", access_configs=[]),
            _Obj(network_i_p="", network=f"{CL}/global/networks/backend", access_configs=[_Obj(nat_ip="198.51.100.9")]),
        ],
        service_accounts=[_Obj(email="vm-sa@p.iam.gserviceaccount.com"), _Obj(email="")],
        tags=_Obj(items=["http-server"]),
        labels={"app": "web"},
    )
    static = _Obj(
        id="",
        name="static-ip-vm",
        machine_type="",
        zone=f"{CL}/zones/us-east1-b",
        status="TERMINATED",
        network_interfaces=[
            _Obj(network_i_p="10.0.0.6", network=f"{CL}/global/networks/default", access_configs=[_Obj(nat_i_p="34.1.1.1")])
        ],
        service_accounts=None,
        tags=None,
        labels=None,
    )
    return [
        ("zones/us-central1-a", _Obj(instances=[web, _Obj(name="")])),
        ("zones/us-east1-b", _Obj(instances=[static])),
        ("zones/x", _Obj()),
    ]


def _firewalls() -> list[Any]:
    net = f"{CL}/global/networks/default"
    return [
        _Obj(
            name="allow-ssh",
            network=net,
            direction="INGRESS",
            source_ranges=["0.0.0.0/0", ""],
            allowed=[_Obj(I_p_protocol="TCP", ports=["22", "8000-8080", "", "x-y"]), _Obj(ip_protocol="icmp", ports=[])],
            target_tags=["http-server"],
            target_service_accounts=["vm-sa@p.iam.gserviceaccount.com"],
        ),
        _Obj(name="ipv6-all", network=net, direction="", source_ranges=["::/0"], allowed=[_Obj(ports=None)]),
        _Obj(name="egress", network=net, direction="EGRESS", source_ranges=["0.0.0.0/0"], allowed=[_Obj(I_p_protocol="tcp")]),
        _Obj(name="deny-only", network=net, direction="INGRESS", source_ranges=["0.0.0.0/0"], allowed=[]),
        _Obj(
            name="internal",
            network=net,
            direction="INGRESS",
            source_ranges=["10.0.0.0/8"],
            allowed=[_Obj(I_p_protocol="tcp", ports=["443"])],
        ),
        _Obj(name=""),
    ]


def _iam_policy() -> Any:
    return _Obj(
        bindings=[
            _Obj(role="roles/owner", members=["user:Owner@Example.com", "group:admins@example.com"]),
            _Obj(role="roles/editor", members=["serviceAccount:App@p.iam.gserviceaccount.com", "domain:example.com"]),
            _Obj(
                role="projects/p/roles/customReader",
                members=["serviceAccount:app@p.iam.gserviceaccount.com", "group:admins@example.com", "bare-member", ":"],
            ),
            _Obj(role="roles/editor", members=["serviceAccount:app@p.iam.gserviceaccount.com"]),
            _Obj(role="", members=["user:ignored@example.com"]),
            _Obj(
                role="roles/storage.objectViewer", members=["serviceAccount:reader@p.iam.gserviceaccount.com", "group:readers@example.com"]
            ),
        ]
    )


_ROLE_PERMISSIONS = {
    "roles/owner": ["resourcemanager.projects.delete", "iam.roles.create"],
    "roles/editor": ["storage.buckets.update"],
    "projects/p/roles/customReader": ["storage.objects.get", "storage.objects.list"],
}


def _service_accounts() -> list[Any]:
    return [
        _Obj(email="app@p.iam.gserviceaccount.com", display_name="App SA", unique_id="111", disabled=False),
        _Obj(email="reader@p.iam.gserviceaccount.com", display_name="", unique_id="", disabled=True),
        _Obj(email="unbound@p.iam.gserviceaccount.com", display_name="Unbound", unique_id="333"),
        _Obj(email="nonmap@p.iam.gserviceaccount.com", display_name="NonMap", unique_id="444"),
        _Obj(email=""),
    ]


def _usage_resolver(email: str, roles: list[str]) -> Any:
    if email.startswith("unbound"):
        raise RuntimeError("usage backend down")
    if email.startswith("nonmap"):
        return ["not", "a", "mapping"]
    if email.startswith("reader"):
        return {"state": "", "diagnostic": "", "records": "bad"}
    return {"state": "available", "diagnostic": "policy-analyzer", "records": [{"role": r, "last_used": "2026-01-01"} for r in roles]}


def _clusters() -> Any:
    return _Obj(
        clusters=[
            _Obj(
                name="public-gke",
                id="c1",
                location="us-central1",
                endpoint="34.2.2.2",
                private_cluster_config=None,
                current_node_count=3,
                current_master_version="1.29",
                resource_labels={"env": "prod"},
            ),
            _Obj(
                name="private-gke",
                id="",
                location="europe-west1-b",
                endpoint="10.9.9.9",
                private_cluster_config=_Obj(enable_private_endpoint=True, enable_private_nodes=True),
                current_node_count="bad",
            ),
            _Obj(name="nodes-only", private_cluster_config=_Obj(enable_private_endpoint=False, enable_private_nodes=True)),
            _Obj(name=""),
        ]
    )


def _run_services() -> list[Any]:
    return [
        _Obj(
            name="projects/p/locations/us-central1/services/api",
            uri="https://api.run.app",
            ingress="INGRESS_TRAFFIC_ALL",
            labels={"t": "1"},
        ),
        _Obj(name="projects/p/locations/europe-west1/services/internal", ingress="INGRESS_TRAFFIC_INTERNAL_ONLY"),
        _Obj(name=""),
    ]


def _functions() -> list[Any]:
    return [
        _Obj(
            name="projects/p/locations/us-central1/functions/hook",
            service_config=_Obj(ingress_settings="ALLOW_ALL"),
            event_trigger=None,
            labels={"k": "v"},
        ),
        _Obj(name="projects/p/locations/us-east1/functions/worker", service_config=None, event_trigger=_Obj(event_type="pubsub")),
        _Obj(name="projects/p/locations/us-east1/functions/internal", service_config=_Obj(ingress_settings="ALLOW_INTERNAL_ONLY")),
        _Obj(name=""),
    ]


_SQL_PAGES: dict[str | None, dict[str, Any]] = {
    None: {
        "items": [
            {
                "name": "pg-public",
                "selfLink": "https://sqladmin/pg-public",
                "region": "us-central1",
                "databaseVersion": "POSTGRES_15",
                "ipAddresses": [{"ipAddress": "35.3.3.3"}, "junk"],
                "settings": {"ipConfiguration": {"ipv4Enabled": True, "authorizedNetworks": [{"value": "10.0.0.0/8"}, "junk"]}},
                "diskEncryptionConfiguration": {"kmsKeyName": "projects/p/keys/k"},
            },
            "not-a-dict",
            {"name": ""},
        ],
        "nextPageToken": "page-2",
    },
    "page-2": {
        "items": [
            {
                "name": "mysql-open",
                "region": "europe-west1",
                "settings": {"ipConfiguration": {"ipv4Enabled": False, "authorizedNetworks": [{"value": "0.0.0.0/0"}]}},
            },
            {"name": "private-sql", "ipAddresses": [], "settings": {"ipConfiguration": {"ipv4Enabled": True}}},
        ],
    },
}


def _networks() -> list[Any]:
    return [
        _Obj(name="default", id="net-1", self_link=f"{CL}/global/networks/default", auto_create_subnetworks=True),
        _Obj(name="backend", id="", self_link="", auto_create_subnetworks=False),
        _Obj(name="isolated", id="net-3", self_link=f"{CL}/global/networks/isolated"),
        _Obj(name=""),
    ]


def _subnets() -> list[Any]:
    return [
        (
            "regions/us-central1",
            _Obj(
                subnetworks=[
                    _Obj(
                        name="default-sub",
                        self_link=f"{CL}/regions/us-central1/subnetworks/default-sub",
                        region=f"{CL}/regions/us-central1",
                        ip_cidr_range="10.0.0.0/20",
                        network=f"{CL}/global/networks/default",
                        enable_flow_logs=True,
                    ),
                    _Obj(name="backend-sub", id="s-2", region="", ip_cidr_range="10.2.0.0/24", network=f"{CL}/global/networks/backend"),
                ]
            ),
        ),
        ("regions/empty", _Obj(subnetworks=None)),
        ("regions/europe-west1", _Obj(subnetworks=[_Obj(name="", id="", network="", enable_flow_logs=False)])),
    ]


def _backend_services() -> list[Any]:
    return [
        (
            "global",
            _Obj(
                backend_services=[
                    _Obj(
                        name="web-backend",
                        id="b1",
                        load_balancing_scheme="external_managed",
                        security_policy=f"{CL}/global/securityPolicies/edge-waf",
                    ),
                    _Obj(
                        name="int-backend", id="", load_balancing_scheme="INTERNAL", region=f"{CL}/regions/us-central1", security_policy=""
                    ),
                    _Obj(name="api-backend", id="b3", load_balancing_scheme="EXTERNAL", security_policy="edge-waf"),
                    _Obj(name=""),
                ]
            ),
        ),
        ("regions/x", _Obj()),
    ]


def _url_maps() -> list[Any]:
    return [_Obj(name="web-map", id="u1"), _Obj(name="regional-map", id="", region=f"{CL}/regions/us-east1"), _Obj(name="")]


def _forwarding_rules() -> list[Any]:
    return [
        ("global", _Obj(forwarding_rules=[_Obj(name="web-fr", id="f1", load_balancing_scheme="EXTERNAL"), _Obj(name="")])),
        (
            "regions/us-central1",
            _Obj(forwarding_rules=[_Obj(name="ilb-fr", load_balancing_scheme="INTERNAL", region=f"{CL}/regions/us-central1")]),
        ),
    ]


def _http_proxies() -> list[Any]:
    return [_Obj(name="http-proxy", id="hp1"), _Obj(name="")]


def _https_proxies() -> list[Any]:
    return [_Obj(name="https-proxy", id=""), _Obj(name="")]


def _security_policies() -> list[Any]:
    return [_Obj(name="edge-waf", id="sp1"), _Obj(name="unused-waf", id=""), _Obj(name="")]


def _gateways() -> list[Any]:
    return [
        _Obj(
            name="projects/p/locations/us-central1/gateways/gw1",
            default_hostname="gw1.uc.gateway.dev",
            api_config="projects/p/locations/global/apis/a/configs/cfg-1",
        ),
        _Obj(name="projects/p/locations/europe-west1/gateways/gw2", api_config=""),
        _Obj(name=""),
    ]


def _routers() -> list[Any]:
    return [
        (
            "regions/us-central1",
            _Obj(
                routers=[
                    _Obj(
                        name="nat-router",
                        id="r1",
                        network=f"{CL}/global/networks/default",
                        region=f"{CL}/regions/us-central1",
                        nats=[_Obj(name="egress-nat"), _Obj(name="")],
                    ),
                    _Obj(name="plain-router", id="", network=f"{CL}/global/networks/backend", region="", nats=None),
                    _Obj(name=""),
                ]
            ),
        ),
        ("regions/y", _Obj()),
    ]


def _addresses() -> list[Any]:
    return [
        (
            "regions/us-east1",
            _Obj(
                addresses=[
                    _Obj(address="34.1.1.1", users=[f"{CL}/zones/us-east1-b/instances/static-ip-vm"], region=f"{CL}/regions/us-east1"),
                    _Obj(address="35.9.9.9", users=None),
                    _Obj(address=""),
                ]
            ),
        ),
        ("global", _Obj()),
    ]


def _disks() -> list[Any]:
    return [
        (
            "zones/us-central1-a",
            _Obj(
                disks=[
                    _Obj(
                        name="web-boot",
                        id="d1",
                        zone=f"{CL}/zones/us-central1-a",
                        size_gb=50,
                        disk_encryption_key=_Obj(kms_key_name="projects/p/keys/disk"),
                        source_image=f"{CL}/global/images/debian-12",
                        labels={"app": "web"},
                    ),
                    _Obj(name="data", id="", zone="", size_gb="huge", disk_encryption_key=_Obj(kms_key_name=""), labels=None),
                    _Obj(name="scratch", disk_encryption_key=None),
                    _Obj(name=""),
                ]
            ),
        ),
        ("zones/empty", _Obj(disks=None)),
    ]


def _topics() -> list[Any]:
    return [_Obj(name="projects/p/topics/events", labels={"team": "data"}), _Obj(name="projects/p/topics/audit"), _Obj(name="")]


# ---------------------------------------------------------------------------
# Fake SDK modules
# ---------------------------------------------------------------------------


def _client(prefix: str, methods: dict[str, tuple[str, Any, Any]]) -> type:
    def __init__(self: Any, project: Any = None, credentials: Any = None) -> None:  # noqa: N807
        self._credentials = credentials
        ESTATE.calls.append([f"{prefix}.__init__", _cred_label(credentials), {"project": str(project)}])

    namespace: dict[str, Any] = {"__init__": __init__}
    for method, (key, factory, empty) in methods.items():

        def call(self: Any, *args: Any, _key: str = key, _factory: Any = factory, _empty: Any = empty, **kwargs: Any) -> Any:
            if args:
                kwargs["_args"] = args
            return ESTATE.run(_key, self._credentials, _factory(), _empty, **kwargs)

        namespace[method] = call
    return type(prefix, (), namespace)


class _Request:
    def __init__(self, **kwargs: Any) -> None:
        self.__dict__.update(kwargs)

    def __str__(self) -> str:
        return f"{type(self).__name__}({', '.join(f'{k}={v}' for k, v in sorted(self.__dict__.items()))})"


class _IAMClient:
    def __init__(self, credentials: Any = None) -> None:
        self._credentials = credentials
        ESTATE.calls.append(["iam.__init__", _cred_label(credentials), {}])

    def list_service_accounts(self, request: Any) -> Any:
        return ESTATE.run("iam.list_service_accounts", self._credentials, _service_accounts(), request=request)

    def get_role(self, request: Any) -> Any:
        name = request.name
        if name == "roles/storage.objectViewer":
            ESTATE.calls.append(["iam.get_role", _cred_label(self._credentials), {"request": str(request)}])
            raise PermissionDenied(f"iam.roles.get denied for {name}")
        return ESTATE.run("iam.get_role", self._credentials, _Obj(included_permissions=_ROLE_PERMISSIONS.get(name, [])), request=request)


class _SqlInstances:
    def list(self, project: str, pageToken: str | None = None) -> Any:  # noqa: N803
        return _Obj(
            execute=lambda: ESTATE.run(
                "sql.instances.list", None, _SQL_PAGES[pageToken], {"items": []}, project=project, pageToken=pageToken
            )
        )


class _SqlService:
    def instances(self) -> _SqlInstances:
        return _SqlInstances()


def _build(service: str, version: str, credentials: Any = None, cache_discovery: bool = True) -> Any:
    ESTATE.calls.append(
        ["discovery.build", _cred_label(credentials), {"service": service, "version": version, "cache": str(cache_discovery)}]
    )
    return _SqlService()


def _module(name: str, **attrs: Any) -> types.ModuleType:
    module = types.ModuleType(name)
    for key, value in attrs.items():
        setattr(module, key, value)
    return module


def _sdk_modules() -> dict[str, types.ModuleType]:
    compute = _module(
        "google.cloud.compute_v1",
        InstancesClient=_client("compute.instances", {"aggregated_list": ("compute.instances", _instances, None)}),
        FirewallsClient=_client("compute.firewalls", {"list": ("compute.firewalls", _firewalls, None)}),
        NetworksClient=_client("compute.networks", {"list": ("compute.networks", _networks, None)}),
        SubnetworksClient=_client("compute.subnetworks", {"aggregated_list": ("compute.subnetworks", _subnets, None)}),
        BackendServicesClient=_client(
            "compute.backend_services", {"aggregated_list": ("compute.backend_services", _backend_services, None)}
        ),
        UrlMapsClient=_client("compute.url_maps", {"list": ("compute.url_maps", _url_maps, None)}),
        ForwardingRulesClient=_client(
            "compute.forwarding_rules", {"aggregated_list": ("compute.forwarding_rules", _forwarding_rules, None)}
        ),
        TargetHttpProxiesClient=_client("compute.http_proxies", {"list": ("compute.http_proxies", _http_proxies, None)}),
        TargetHttpsProxiesClient=_client("compute.https_proxies", {"list": ("compute.https_proxies", _https_proxies, None)}),
        SecurityPoliciesClient=_client("compute.security_policies", {"list": ("compute.security_policies", _security_policies, None)}),
        RoutersClient=_client("compute.routers", {"aggregated_list": ("compute.routers", _routers, None)}),
        AddressesClient=_client("compute.addresses", {"aggregated_list": ("compute.addresses", _addresses, None)}),
        DisksClient=_client("compute.disks", {"aggregated_list": ("compute.disks", _disks, None)}),
    )
    discovery = _module("googleapiclient.discovery", build=_build)
    return {
        "google": _module("google"),
        "google.cloud": _module("google.cloud"),
        "google.cloud.storage": _module(
            "google.cloud.storage", Client=_client("storage", {"list_buckets": ("storage.list_buckets", _buckets, None)})
        ),
        "google.cloud.compute_v1": compute,
        "google.cloud.iam_admin_v1": _module(
            "google.cloud.iam_admin_v1",
            IAMClient=_IAMClient,
            ListServiceAccountsRequest=type("ListServiceAccountsRequest", (_Request,), {}),
            GetRoleRequest=type("GetRoleRequest", (_Request,), {}),
        ),
        "google.cloud.resourcemanager_v3": _module(
            "google.cloud.resourcemanager_v3",
            ProjectsClient=_client("rm.projects", {"get_iam_policy": ("rm.get_iam_policy", _iam_policy, _Obj(bindings=[]))}),
        ),
        "google.iam": _module("google.iam"),
        "google.iam.v1": _module("google.iam.v1"),
        "google.iam.v1.iam_policy_pb2": _module(
            "google.iam.v1.iam_policy_pb2", GetIamPolicyRequest=type("GetIamPolicyRequest", (_Request,), {})
        ),
        "google.cloud.container_v1": _module(
            "google.cloud.container_v1",
            ClusterManagerClient=_client("container", {"list_clusters": ("container.list_clusters", _clusters, _Obj(clusters=[]))}),
        ),
        "google.cloud.run_v2": _module(
            "google.cloud.run_v2",
            ServicesClient=_client("run", {"list_services": ("run.list_services", _run_services, None)}),
            ListServicesRequest=type("ListServicesRequest", (_Request,), {}),
        ),
        "google.cloud.functions_v2": _module(
            "google.cloud.functions_v2",
            FunctionServiceClient=_client("functions", {"list_functions": ("functions.list_functions", _functions, None)}),
            ListFunctionsRequest=type("ListFunctionsRequest", (_Request,), {}),
        ),
        "google.cloud.pubsub_v1": _module(
            "google.cloud.pubsub_v1",
            PublisherClient=_client("pubsub", {"list_topics": ("pubsub.list_topics", _topics, None)}),
        ),
        "google.cloud.apigateway_v1": _module(
            "google.cloud.apigateway_v1",
            ApiGatewayServiceClient=_client("apigateway", {"list_gateways": ("apigateway.list_gateways", _gateways, None)}),
            ListGatewaysRequest=type("ListGatewaysRequest", (_Request,), {}),
        ),
        "googleapiclient": _module("googleapiclient"),
        "googleapiclient.discovery": discovery,
    }


def _install(*, drop: tuple[str, ...] = (), extra: dict[str, types.ModuleType] | None = None) -> Any:
    modules = {name: mod for name, mod in _sdk_modules().items() if name not in drop}
    modules.update(extra or {})
    return patch_sdk_namespace(modules, "google", "googleapiclient")


class _Creds:
    def __init__(self, label: str) -> None:
        self.label = label


def _fake_authorization(credentials: Any, project_id: str, *, warnings: list[str], missing: list[dict[str, str]]) -> dict[str, Any]:
    ESTATE.calls.append(["collect_gcp_authorization", _cred_label(credentials), {"project_id": project_id}])
    warnings.append(f"authorization collector ran for {project_id}")
    return {
        "iam_observed_at": "2026-07-17T12:00:00+00:00",
        "iam_hierarchy": [f"projects/{project_id}"],
        "allow_policies": [
            {
                "resource": f"projects/{project_id}",
                "version": 3,
                "bindings": [
                    {"id": "b-1", "role": "roles/viewer", "members": ["serviceAccount:reader@p.iam.gserviceaccount.com"], "condition": None}
                ],
            }
        ],
        "role_definitions": [{"id": "roles/viewer", "permissions": ["storage.objects.get"], "completeness": "complete"}],
        "deny_policies": [],
        "pab_policies": [],
        "pab_bindings": [],
        "iam_sources": [],
    }


# ---------------------------------------------------------------------------
# Scenario runner
# ---------------------------------------------------------------------------


def _normalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _normalize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize(v) for v in value]
    if isinstance(value, str):
        return _ISO_TS.sub("<ts>", value)
    return value


def _logs(caplog: pytest.LogCaptureFixture) -> list[list[str]]:
    return [[r.levelname, r.name, r.getMessage()] for r in caplog.records if r.name.startswith("agent_bom")]


_ENV_KEYS = (
    gcp_inventory.INVENTORY_ENV_FLAG,
    "GOOGLE_CLOUD_PROJECT",
    "AGENT_BOM_GCP_IMPERSONATE_SA",
    "AGENT_BOM_DSPM_GCS_SAMPLING",
    gcp_inventory.ALL_PROJECTS_ENV_FLAG,
)


@pytest.fixture
def estate(monkeypatch: pytest.MonkeyPatch) -> Any:
    for key in _ENV_KEYS:
        monkeypatch.delenv(key, raising=False)

    def make(default: str = "ok", **overrides: str) -> _Estate:
        global ESTATE
        ESTATE = _Estate(default, **overrides)
        return ESTATE

    make()
    yield make


def _inventory_scenarios() -> dict[str, dict[str, Any]]:
    scenarios: dict[str, dict[str, Any]] = {
        "full_ok": {"usage_resolver": True},
        "full_ok_no_usage_resolver": {},
        "all_empty": {"mode": "empty"},
        "partial_mixed_failures": {
            "overrides": {
                "compute.url_maps": "denied",
                "compute.https_proxies": "throttled",
                "compute.subnetworks": "api_disabled",
                "iam.get_role": "boom",
                "sql.instances.list": "billing",
            }
        },
        "selective_none": {
            "kwargs": dict.fromkeys(
                [
                    "include_storage",
                    "include_compute",
                    "include_iam",
                    "include_containers",
                    "include_serverless",
                    "include_databases",
                    "include_networks",
                    "include_disks",
                    "include_messaging",
                ],
                False,
            )
        },
        "selective_networks_only": {
            "kwargs": {
                "include_storage": False,
                "include_compute": False,
                "include_iam": False,
                "include_containers": False,
                "include_serverless": False,
                "include_databases": False,
                "include_disks": False,
                "include_messaging": False,
            }
        },
        "sdks_missing_except_storage": {
            "drop": (
                "google.cloud.compute_v1",
                "google.cloud.iam_admin_v1",
                "google.cloud.resourcemanager_v3",
                "google.cloud.container_v1",
                "google.cloud.run_v2",
                "google.cloud.functions_v2",
                "google.cloud.pubsub_v1",
                "google.cloud.apigateway_v1",
                "googleapiclient.discovery",
            )
        },
        "explicit_credentials": {"credentials": "explicit"},
    }
    for failure in _FAILURES:
        scenarios[f"all_{failure}"] = {"mode": failure}
    return scenarios


INVENTORY_SCENARIOS = _inventory_scenarios()


def _run_inventory(name: str, estate: Any, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> dict[str, Any]:
    spec = INVENTORY_SCENARIOS[name]
    state = estate(spec.get("mode", "ok"), **spec.get("overrides", {}))
    monkeypatch.setattr(gcp_inventory, "collect_gcp_authorization", _fake_authorization)
    monkeypatch.setenv(gcp_inventory.INVENTORY_ENV_FLAG, "1")
    kwargs = dict(spec.get("kwargs", {}))
    if spec.get("usage_resolver"):
        kwargs["usage_resolver"] = _usage_resolver
    if spec.get("credentials"):
        kwargs["credentials"] = _Creds(spec["credentials"])
    with caplog.at_level(logging.DEBUG), _install(drop=spec.get("drop", ())):
        result = gcp_inventory.discover_inventory(project_id="proj-1", **kwargs)
    return {"result": _normalize(result), "calls": state.calls, "logs": _logs(caplog)}


def _google_auth(
    project: Any = "adc-proj", *, default_raises: bool = False, impersonation_raises: bool = False
) -> dict[str, types.ModuleType]:
    def default() -> Any:
        if default_raises:
            raise RuntimeError("could not find default credentials")
        return _Creds("adc"), project

    class Credentials:
        def __init__(self, *, source_credentials: Any, target_principal: str, target_scopes: list[str]) -> None:
            if impersonation_raises:
                raise RuntimeError("iamcredentials denied")
            self.label = f"impersonated:{target_principal}:{_cred_label(source_credentials)}:{','.join(target_scopes)}"

    auth = _module("google.auth", default=default)
    imp = _module("google.auth.impersonated_credentials", Credentials=Credentials)
    auth.impersonated_credentials = imp  # type: ignore[attr-defined]
    return {"google.auth": auth, "google.auth.impersonated_credentials": imp}


def _status_scenarios(estate: Any, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> dict[str, Any]:
    out: dict[str, Any] = {}
    monkeypatch.setattr(gcp_inventory, "collect_gcp_authorization", _fake_authorization)
    kinds = {
        "flag_off": ({}, {}, {}, False),
        "flag_off_forced": ({}, {"include_iam": False}, {}, True),
        "sdk_missing": ({"drop": ("google.cloud.storage",)}, {}, {}, False),
        "no_project_adc_none": ({"extra": _google_auth(project=None)}, {}, {}, False),
        "no_project_adc_error": ({"extra": _google_auth(default_raises=True)}, {}, {}, False),
        "no_project_auth_missing": ({}, {}, {}, False),
        "derived_project": ({"extra": _google_auth()}, {"include_iam": False}, {}, False),
        "env_project": ({}, {"include_iam": False}, {"GOOGLE_CLOUD_PROJECT": "env-proj"}, False),
        "impersonation_ok": (
            {"extra": _google_auth()},
            {"include_storage": False},
            {"AGENT_BOM_GCP_IMPERSONATE_SA": "abom-scanner@proj.iam.gserviceaccount.com"},
            False,
        ),
        "impersonation_fails": (
            {"extra": _google_auth(impersonation_raises=True)},
            {"include_storage": False, "include_iam": False},
            {"AGENT_BOM_GCP_IMPERSONATE_SA": "abom-scanner@proj.iam.gserviceaccount.com"},
            False,
        ),
        "impersonation_auth_missing": (
            {},
            {"include_iam": False},
            {"AGENT_BOM_GCP_IMPERSONATE_SA": "abom-scanner@proj.iam.gserviceaccount.com"},
            False,
        ),
    }
    for name, (install, kwargs, env, forced) in kinds.items():
        state = estate()
        caplog.clear()
        with monkeypatch.context() as m:
            for key, value in env.items():
                m.setenv(key, value)
            if name not in ("flag_off", "flag_off_forced"):
                m.setenv(gcp_inventory.INVENTORY_ENV_FLAG, "1")
            project = "proj-1" if name in ("flag_off", "flag_off_forced", "sdk_missing") or name.startswith("impersonation") else None
            with caplog.at_level(logging.DEBUG), _install(**install):
                result = gcp_inventory.discover_inventory(project_id=project, force=forced, **kwargs)
        out[name] = {"result": _normalize(result), "calls": state.calls, "logs": _logs(caplog)}
    return out


def _gcs_sampling(estate: Any, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> dict[str, Any]:
    from agent_bom.cloud import gcs_data_classifier

    state = estate()

    def classify(client: Any, name: str) -> Any:
        if name == "auth-lake":
            raise RuntimeError("object sample read denied")
        return _Obj(to_dict=lambda: {"bucket": name, "labels": ["pii"], "project": client._credentials})

    monkeypatch.setattr(gcs_data_classifier, "gcs_sampling_enabled", lambda: True)
    monkeypatch.setattr(gcs_data_classifier, "classify_gcs_bucket", classify)
    warnings: list[str] = []
    missing: list[dict[str, str]] = []
    caplog.clear()
    with caplog.at_level(logging.DEBUG), _install():
        buckets = gcp_inventory._discover_buckets("proj-1", credentials=None, warnings=warnings, missing=missing)
    return {"buckets": _normalize(buckets), "warnings": warnings, "missing": missing, "calls": state.calls, "logs": _logs(caplog)}


def _all_projects(estate: Any, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> dict[str, Any]:
    out: dict[str, Any] = {}
    monkeypatch.setattr(gcp_inventory, "collect_gcp_authorization", _fake_authorization)
    subset = {
        "include_compute": False,
        "include_iam": False,
        "include_containers": False,
        "include_serverless": False,
        "include_databases": False,
        "include_networks": False,
        "include_disks": False,
    }
    real = gcp_inventory.discover_inventory

    def narrowed(project_id: str | None = None, **kwargs: Any) -> dict[str, Any]:
        if project_id == "proj-bad":
            raise RuntimeError("project inventory exploded")
        return real(project_id=project_id, **kwargs, **subset)

    def listing(ids: Any) -> Any:
        def list_project_ids(credentials: Any, *, force: bool = False) -> list[str]:
            if isinstance(ids, Exception):
                raise ids
            return list(ids)

        return list_project_ids

    cases = {
        "flag_off": (None, False, {}, None, False),
        "org_three_projects_one_fails": (["proj-b", "proj-a", "proj-bad"], True, {}, None, False),
        "org_error_falls_back_to_env": (RuntimeError("org read denied"), True, {"GOOGLE_CLOUD_PROJECT": "env-proj"}, None, False),
        "org_empty_no_env": ([], True, {}, None, False),
        "org_capped": (["proj-c", "proj-a", "proj-b"], True, {}, 2, False),
        "forced_with_flag_off": (["proj-a"], False, {}, None, True),
    }
    for name, (ids, flag, env, cap, force) in cases.items():
        estate()
        caplog.clear()
        with monkeypatch.context() as m:
            m.setattr(gcp_inventory, "discover_inventory", narrowed)
            m.setattr(gcp_organizations, "list_project_ids", listing(ids if ids is not None else []))
            if cap is not None:
                m.setattr(gcp_inventory, "_MAX_PROJECTS", cap)
            if flag:
                m.setenv(gcp_inventory.INVENTORY_ENV_FLAG, "1")
            for key, value in env.items():
                m.setenv(key, value)
            with caplog.at_level(logging.DEBUG), _install():
                payloads = gcp_inventory.discover_all_project_inventories(_Creds("fanout"), force=force)
        payloads = sorted(payloads, key=lambda p: p["project_id"])
        out[name] = {"payloads": _normalize(payloads), "logs": _logs(caplog)}
    return out


def _real_collector(estate: Any, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> dict[str, Any]:
    state = estate()
    monkeypatch.setenv(gcp_inventory.INVENTORY_ENV_FLAG, "1")
    caplog.clear()
    with caplog.at_level(logging.DEBUG), _install():
        result = gcp_inventory.discover_inventory(
            project_id="proj-1",
            include_storage=False,
            include_compute=False,
            include_containers=False,
            include_serverless=False,
            include_databases=False,
            include_networks=False,
            include_disks=False,
            include_messaging=False,
        )
    return {"result": _normalize(result), "calls": state.calls, "logs": _logs(caplog)}


def _helpers() -> dict[str, Any]:
    roles = ["roles/owner", "roles/editor", "roles/viewer", "roles/browser", "roles/compute.admin", "roles/iam.securityAdmin"]
    roles += ["roles/resourcemanager.projectOwner", "roles/storage.objectWriter", "roles/pubsub.editor", "roles/logging.write"]
    roles += ["roles/storage.objectViewer", "roles/bigquery.dataReader", "roles/logging.read", "roles/run.invoker", "", "  "]
    resolver = lambda role: [f"perm.for.{role}"]  # noqa: E731
    bindings = {"admins@example.com": ["roles/owner"], "svc@p": ["roles/viewer"], "empty@example.com": []}
    kinds = {"admins@example.com": "group", "svc@p": "serviceaccount", "empty@example.com": "group"}
    return {
        "classify": {role: gcp_inventory._classify_role_privilege(role) for role in roles},
        "highest": [gcp_inventory._highest_privilege(r) for r in ([], ["roles/viewer", "roles/editor"], ["roles/run.invoker"], roles)],
        "policy_bindings": [
            gcp_inventory._policy_bindings(p)
            for p in (None, {"bindings": [{"role": "r", "members": ["m"]}]}, _Obj(bindings=[_Obj(role="r2", members=None)]), {})
        ],
        "groups": gcp_inventory._build_iam_group_principals(bindings, kinds, project_id="proj-1", role_resolver=resolver),
        "groups_no_resolver": gcp_inventory._build_iam_group_principals(bindings, kinds, project_id="proj-1", role_resolver=None),
    }


def _build_golden(estate: Any, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> dict[str, Any]:
    golden: dict[str, Any] = {"inventory": {}}
    for name in INVENTORY_SCENARIOS:
        caplog.clear()
        with monkeypatch.context() as m:
            golden["inventory"][name] = _run_inventory(name, estate, m, caplog)
    with monkeypatch.context() as m:
        golden["status"] = _status_scenarios(estate, m, caplog)
    with monkeypatch.context() as m:
        golden["gcs_sampling"] = _gcs_sampling(estate, m, caplog)
    with monkeypatch.context() as m:
        golden["all_projects"] = _all_projects(estate, m, caplog)
    with monkeypatch.context() as m:
        golden["real_authorization_collector"] = _real_collector(estate, m, caplog)
    golden["helpers"] = _normalize(_helpers())
    golden["exports"] = sorted(gcp_inventory.__all__)
    return golden


def test_gcp_inventory_matches_golden(estate: Any, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    actual = json.loads(json.dumps(_build_golden(estate, monkeypatch, caplog), sort_keys=True, default=str))
    if os.environ.get("UPDATE_CLOUD_GOLDEN") == "1":
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN.write_text(json.dumps(actual, indent=2, sort_keys=True) + "\n")
    expected = json.loads(GOLDEN.read_text())
    assert actual == expected


def test_golden_covers_every_resource_family() -> None:
    golden = json.loads(GOLDEN.read_text())
    full = golden["inventory"]["full_ok"]["result"]
    for key in (
        "buckets",
        "instances",
        "firewalls",
        "service_accounts",
        "groups",
        "gke_clusters",
        "cloud_run_services",
        "cloud_functions",
        "cloud_sql_instances",
        "vpc_networks",
        "subnets",
        "load_balancers",
        "web_acls",
        "api_gateways",
        "nat_gateways",
        "route_tables",
        "ip_addresses",
        "disks",
        "pubsub_topics",
        "side_scan_targets",
    ):
        assert full[key], key
    for failure in _FAILURES:
        assert golden["inventory"][f"all_{failure}"]["result"]["warnings"], failure
    assert {e["resource_type"] for e in golden["inventory"]["all_denied"]["result"]["missing_permissions"]} >= {
        "GCS buckets",
        "GKE clusters",
    }
    sql_pages = [c for c in golden["inventory"]["full_ok"]["calls"] if c[0] == "sql.instances.list"]
    assert [c[2]["pageToken"] for c in sql_pages] == ["None", "page-2"]


# ---------------------------------------------------------------------------
# Patch points: attributes patched on the façade must steer the code paths that
# read them, wherever those paths live.
# ---------------------------------------------------------------------------


_PATCH_POINTS = [
    ("collect_gcp_authorization", "discover_inventory"),
    ("_resolve_impersonation", "discover_inventory"),
    ("_resolve_impersonation", "discover_all_project_inventories"),
    ("inventory_enabled", "discover_inventory"),
    ("inventory_enabled", "discover_all_project_inventories"),
    ("discover_inventory", "discover_all_project_inventories"),
    ("_derive_default_project", "discover_inventory"),
]


@pytest.mark.parametrize(("target", "entry"), _PATCH_POINTS)
def test_facade_patch_points_steer_behaviour(target: str, entry: str, estate: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []
    monkeypatch.setenv(gcp_inventory.INVENTORY_ENV_FLAG, "1")
    monkeypatch.setattr(gcp_inventory, "collect_gcp_authorization", _fake_authorization)
    monkeypatch.setattr(gcp_organizations, "list_project_ids", lambda credentials, *, force=False: ["proj-x"])
    none = {k: False for k in ("include_storage", "include_compute", "include_iam", "include_containers", "include_serverless")}
    none.update({k: False for k in ("include_databases", "include_networks", "include_disks", "include_messaging")})

    if target == "collect_gcp_authorization":

        def collector(credentials: Any, project_id: str, *, warnings: list[str], missing: list[dict[str, str]]) -> dict[str, Any]:
            seen.append(project_id)
            return {"iam_hierarchy": ["patched"]}

        monkeypatch.setattr(gcp_inventory, target, collector)
    elif target == "_resolve_impersonation":
        monkeypatch.setattr(gcp_inventory, target, lambda creds, warnings: seen.append("resolved") or _Creds("patched"))
    elif target == "inventory_enabled":
        monkeypatch.setattr(gcp_inventory, target, lambda: seen.append("gate") or False)
    elif target == "discover_inventory":
        monkeypatch.setattr(
            gcp_inventory, target, lambda **kw: seen.append(kw["project_id"]) or {"project_id": kw["project_id"], "patched": True}
        )
    elif target == "_derive_default_project":
        monkeypatch.setattr(gcp_inventory, target, lambda: seen.append("derived") or ("patched-proj", ""))

    with _install():
        if entry == "discover_inventory":
            kwargs = dict(none)
            if target == "collect_gcp_authorization":
                kwargs["include_iam"] = True
            result: Any = gcp_inventory.discover_inventory(project_id=None if target == "_derive_default_project" else "proj-1", **kwargs)
        else:
            result = gcp_inventory.discover_all_project_inventories()

    assert seen, f"patched {target} was not consulted by {entry}"
    if target == "collect_gcp_authorization":
        assert result["iam_hierarchy"] == ["patched"]
    elif target == "inventory_enabled":
        assert result == [] if entry == "discover_all_project_inventories" else result["status"] == "disabled"
    elif target == "discover_inventory":
        assert result == [{"project_id": "proj-x", "patched": True}]
    elif target == "_derive_default_project":
        assert result["project_id"] == "patched-proj"


def test_facade_reexports_every_externally_used_name() -> None:
    names = [
        "_GCP_IAM_PERMISSIONS",
        "INVENTORY_ENV_FLAG",
        "ALL_PROJECTS_ENV_FLAG",
        "_build_iam_group_principals",
        "_classify_role_privilege",
        "_derive_default_project",
        "_discover_buckets",
        "_discover_project_iam_bindings",
        "_discover_service_accounts",
        "_highest_privilege",
        "_make_role_resolver",
        "_policy_bindings",
        "_resolve_impersonation",
        "all_projects_enabled",
        "collect_gcp_authorization",
        "dedupe_missing_permissions",
        "discover_all_project_inventories",
        "discover_inventory",
        "inventory_enabled",
    ]
    missing = [name for name in names if not hasattr(gcp_inventory, name)]
    assert missing == []
    assert "agent_bom.cloud.gcp_inventory" in sys.modules
