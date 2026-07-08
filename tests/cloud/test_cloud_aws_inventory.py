# ruff: noqa: N803  — fake boto3 client methods mirror boto3's PascalCase kwargs (Bucket=).
"""Tests for agent_bom.cloud.aws_inventory — estate-wide AWS asset inventory.

Boto3 is not a hard dependency, so these tests inject a fake ``boto3`` module
(no moto) and exercise: enumeration → payload, the flag-off no-op path, the
boto3-missing path, the no-credentials path, and the graph-builder integration
that turns the payload into nodes the CNAPP / effective-permissions overlays
consume.
"""

from __future__ import annotations

import datetime
import sys
from typing import Any
from unittest.mock import patch

import pytest

from agent_bom.cloud import aws_inventory

# ---------------------------------------------------------------------------
# Fake boto3 clients
# ---------------------------------------------------------------------------


class _FakePaginator:
    def __init__(self, pages: list[dict[str, Any]]) -> None:
        self._pages = pages

    def paginate(self, **_kwargs: Any) -> list[dict[str, Any]]:
        return self._pages


class _FakeS3:
    def list_buckets(self) -> dict[str, Any]:
        return {
            "Buckets": [
                {"Name": "public-data-lake", "CreationDate": datetime.datetime(2026, 1, 1)},
                {"Name": "private-logs", "CreationDate": datetime.datetime(2026, 1, 2)},
            ]
        }

    def get_bucket_location(self, Bucket: str) -> dict[str, Any]:  # noqa: N803 — boto3 API kwarg
        return {"LocationConstraint": None if Bucket == "public-data-lake" else "eu-west-1"}

    def get_bucket_policy_status(self, Bucket: str) -> dict[str, Any]:
        return {"PolicyStatus": {"IsPublic": Bucket == "public-data-lake"}}

    def get_public_access_block(self, Bucket: str) -> dict[str, Any]:
        if Bucket == "public-data-lake":
            return {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False,
                }
            }
        return {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }

    def get_bucket_tagging(self, Bucket: str) -> dict[str, Any]:
        if Bucket == "public-data-lake":
            return {"TagSet": [{"Key": "classification", "Value": "pii"}]}
        return {"TagSet": []}


class _FakeEC2:
    def get_paginator(self, op: str) -> _FakePaginator:
        if op == "describe_instances":
            return _FakePaginator(
                [
                    {
                        "Reservations": [
                            {
                                "Instances": [
                                    {
                                        "InstanceId": "i-abc123",
                                        "InstanceType": "t3.large",
                                        "ImageId": "ami-1",
                                        "State": {"Name": "running"},
                                        "VpcId": "vpc-1",
                                        "SubnetId": "subnet-1",
                                        "PublicIpAddress": "203.0.113.5",
                                        "PrivateIpAddress": "10.0.0.5",
                                        "IamInstanceProfile": {"Arn": "arn:aws:iam::111122223333:instance-profile/web"},
                                        "SecurityGroups": [{"GroupId": "sg-open"}],
                                        "Tags": [{"Key": "Name", "Value": "web-1"}],
                                        "LaunchTime": datetime.datetime(2026, 1, 3),
                                    }
                                ]
                            }
                        ]
                    }
                ]
            )
        return _FakePaginator(
            [
                {
                    "SecurityGroups": [
                        {
                            "GroupId": "sg-open",
                            "GroupName": "web-sg",
                            "Description": "web",
                            "VpcId": "vpc-1",
                            "IpPermissions": [{"FromPort": 22, "ToPort": 22, "IpProtocol": "tcp", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
                        },
                        {
                            "GroupId": "sg-closed",
                            "GroupName": "internal-sg",
                            "Description": "internal",
                            "VpcId": "vpc-1",
                            "IpPermissions": [
                                {"FromPort": 443, "ToPort": 443, "IpProtocol": "tcp", "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}
                            ],
                        },
                    ]
                }
            ]
        )


class _FakeIAM:
    def get_paginator(self, op: str) -> _FakePaginator:
        if op == "list_roles":
            return _FakePaginator(
                [
                    {
                        "Roles": [
                            {
                                "RoleName": "admin-role",
                                "Arn": "arn:aws:iam::111122223333:role/admin-role",
                                "Path": "/",
                                "CreateDate": datetime.datetime(2026, 1, 1),
                                "AssumeRolePolicyDocument": {
                                    "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}}]
                                },
                            }
                        ]
                    }
                ]
            )
        if op == "list_users":
            return _FakePaginator(
                [
                    {
                        "Users": [
                            {
                                "UserName": "alice",
                                "Arn": "arn:aws:iam::111122223333:user/alice",
                                "Path": "/",
                                "CreateDate": datetime.datetime(2026, 1, 1),
                            }
                        ]
                    }
                ]
            )
        if op == "list_attached_role_policies":
            return _FakePaginator(
                [{"AttachedPolicies": [{"PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess", "PolicyName": "AdministratorAccess"}]}]
            )
        # list_attached_user_policies
        return _FakePaginator(
            [{"AttachedPolicies": [{"PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess", "PolicyName": "ReadOnlyAccess"}]}]
        )


class _FakeSTS:
    def get_caller_identity(self) -> dict[str, Any]:
        return {"Account": "111122223333"}


class _FakeSession:
    region_name = "us-east-1"

    def __init__(self, **_kwargs: Any) -> None:
        pass

    def client(self, name: str, **_kwargs: Any) -> Any:
        return {"s3": _FakeS3(), "ec2": _FakeEC2(), "iam": _FakeIAM(), "sts": _FakeSTS()}[name]


def _install_fake_boto3() -> Any:
    """Return a patch.dict context installing a fake boto3 + botocore.exceptions."""
    import types

    boto3_mod = types.ModuleType("boto3")
    boto3_mod.Session = _FakeSession  # type: ignore[attr-defined]
    botocore_mod = types.ModuleType("botocore")
    exc_mod = types.ModuleType("botocore.exceptions")
    exc_mod.NoCredentialsError = type("NoCredentialsError", (Exception,), {})  # type: ignore[attr-defined]
    exc_mod.ClientError = type("ClientError", (Exception,), {})  # type: ignore[attr-defined]
    botocore_mod.exceptions = exc_mod  # type: ignore[attr-defined]
    return patch.dict(sys.modules, {"boto3": boto3_mod, "botocore": botocore_mod, "botocore.exceptions": exc_mod})


# ---------------------------------------------------------------------------
# Flag gating
# ---------------------------------------------------------------------------


def test_inventory_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(aws_inventory.INVENTORY_ENV_FLAG, raising=False)
    monkeypatch.delenv(aws_inventory.INVENTORY_ENV_FLAG_LEGACY, raising=False)
    assert aws_inventory.inventory_enabled() is False
    payload = aws_inventory.discover_inventory()
    assert payload["status"] == "disabled"
    assert payload["buckets"] == []
    assert payload["roles"] == []


def test_inventory_flag_enables(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(aws_inventory.INVENTORY_ENV_FLAG, "true")
    assert aws_inventory.inventory_enabled() is True


def test_inventory_legacy_flag_still_enables(monkeypatch: pytest.MonkeyPatch) -> None:
    """The deprecated AGENT_BOM_CLOUD_INVENTORY name keeps working (with a warning)."""
    monkeypatch.delenv(aws_inventory.INVENTORY_ENV_FLAG, raising=False)
    monkeypatch.setenv(aws_inventory.INVENTORY_ENV_FLAG_LEGACY, "1")
    assert aws_inventory.INVENTORY_ENV_FLAG == "AGENT_BOM_AWS_INVENTORY"
    assert aws_inventory.INVENTORY_ENV_FLAG_LEGACY == "AGENT_BOM_CLOUD_INVENTORY"
    assert aws_inventory.inventory_enabled() is True


def test_inventory_flag_off_short_circuits_before_boto3(monkeypatch: pytest.MonkeyPatch) -> None:
    """With the flag off we must not even attempt to import boto3."""
    monkeypatch.delenv(aws_inventory.INVENTORY_ENV_FLAG, raising=False)
    with patch.dict(sys.modules, {"boto3": None}):
        payload = aws_inventory.discover_inventory()
    assert payload["status"] == "disabled"


# ---------------------------------------------------------------------------
# Degraded paths
# ---------------------------------------------------------------------------


def test_inventory_boto3_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(aws_inventory.INVENTORY_ENV_FLAG, "1")
    import builtins

    original = builtins.__import__

    def _no_boto3(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "boto3":
            raise ImportError("mocked")
        return original(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=_no_boto3):
        payload = aws_inventory.discover_inventory()
    assert payload["status"] == "boto3_missing"
    assert payload["buckets"] == []
    assert payload["warnings"]


def test_inventory_no_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(aws_inventory.INVENTORY_ENV_FLAG, "1")

    class _BoomSession:
        def __init__(self, **_kwargs: Any) -> None:
            raise RuntimeError("could not load credentials")

    import types

    boto3_mod = types.ModuleType("boto3")
    boto3_mod.Session = _BoomSession  # type: ignore[attr-defined]
    exc_mod = types.ModuleType("botocore.exceptions")
    exc_mod.NoCredentialsError = type("NoCredentialsError", (Exception,), {})  # type: ignore[attr-defined]
    with patch.dict(sys.modules, {"boto3": boto3_mod, "botocore.exceptions": exc_mod}):
        payload = aws_inventory.discover_inventory()
    assert payload["status"] == "no_credentials"
    assert payload["warnings"]


# ---------------------------------------------------------------------------
# Enumeration
# ---------------------------------------------------------------------------


def test_inventory_enumerates_all_three_classes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(aws_inventory.INVENTORY_ENV_FLAG, "1")
    with _install_fake_boto3():
        payload = aws_inventory.discover_inventory(region="us-east-1")

    assert payload["status"] == "ok"
    assert payload["account_id"] == "111122223333"

    # S3: estate-wide, public posture + tags read from posture APIs only.
    names = {b["name"]: b for b in payload["buckets"]}
    assert set(names) == {"public-data-lake", "private-logs"}
    assert names["public-data-lake"]["publicly_accessible"] is True
    assert names["public-data-lake"]["location"] == "us-east-1"
    assert names["public-data-lake"]["tags"] == {"classification": "pii"}
    assert names["private-logs"]["publicly_accessible"] is False
    assert names["private-logs"]["location"] == "eu-west-1"

    # EC2 instances + security groups (NOT tag-filtered).
    assert len(payload["instances"]) == 1
    inst = payload["instances"][0]
    assert inst["instance_id"] == "i-abc123"
    assert inst["public_ip"] == "203.0.113.5"
    assert inst["security_group_ids"] == ["sg-open"]

    sgs = {g["group_id"]: g for g in payload["security_groups"]}
    assert sgs["sg-open"]["internet_exposed"] is True
    assert sgs["sg-open"]["network_exposure"][0]["scope"] == "internet"
    assert sgs["sg-closed"]["internet_exposed"] is False

    # IAM roles + users with classified privilege.
    roles = {r["name"]: r for r in payload["roles"]}
    assert roles["admin-role"]["privilege_level"] == "admin"
    assert roles["admin-role"]["trust_principals"][0]["principal_type"] == "service-principal"
    users = {u["name"]: u for u in payload["users"]}
    assert users["alice"]["privilege_level"] == "read"

    # Per-run trust contract.
    env = payload["discovery_envelope"]
    assert env["scan_mode"] == "cloud_read_only"
    assert "iam:ListRoles" in env["permissions_used"]
    assert "s3:ListAllMyBuckets" in env["permissions_used"]
    assert "aws:account/111122223333" in env["discovery_scope"]


def test_inventory_force_bypasses_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    """force=True runs enumeration even with the flag off (used by callers that
    already gated the decision)."""
    monkeypatch.delenv(aws_inventory.INVENTORY_ENV_FLAG, raising=False)
    with _install_fake_boto3():
        payload = aws_inventory.discover_inventory(force=True)
    assert payload["status"] == "ok"
    assert payload["buckets"]


def test_inventory_selective_classes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(aws_inventory.INVENTORY_ENV_FLAG, "1")
    with _install_fake_boto3():
        payload = aws_inventory.discover_inventory(include_ec2=False, include_iam=False)
    assert payload["buckets"]
    assert payload["instances"] == []
    assert payload["roles"] == []
    env = payload["discovery_envelope"]
    assert "ec2:DescribeInstances" not in env["permissions_used"]
    assert "iam:ListRoles" not in env["permissions_used"]


# ---------------------------------------------------------------------------
# Graph-builder integration
# ---------------------------------------------------------------------------


def _build_graph_from_inventory(payload: dict[str, Any]) -> Any:
    from agent_bom.graph.builder import build_unified_graph_from_report

    return build_unified_graph_from_report({"agents": [], "cloud_inventory": payload})


def test_graph_emits_inventory_nodes_and_overlays(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(aws_inventory.INVENTORY_ENV_FLAG, "1")
    with _install_fake_boto3():
        payload = aws_inventory.discover_inventory(region="us-east-1")

    graph = _build_graph_from_inventory(payload)
    from agent_bom.graph.types import EntityType, RelationshipType

    nodes = graph.nodes
    # S3 bucket → CLOUD_RESOURCE, and CNAPP overlay built a DATA_STORE companion.
    bucket_id = "cloud_resource:aws:s3:bucket:public-data-lake"
    assert bucket_id in nodes
    assert nodes[bucket_id].attributes["internet_exposed"] is True
    assert f"data_store:{bucket_id}" in nodes
    assert nodes[f"data_store:{bucket_id}"].entity_type == EntityType.DATA_STORE

    # EC2 instance + security group present; instance EXPOSED_TO open SG.
    instance_id = "cloud_resource:aws:ec2:instance:i-abc123"
    sg_id = "cloud_resource:aws:ec2:security-group:sg-open"
    assert instance_id in nodes and sg_id in nodes
    exposed = [e for e in graph.edges if e.relationship == RelationshipType.EXPOSED_TO and e.source == sg_id and e.target == instance_id]
    assert exposed

    # IAM principals as identity nodes.
    role_node = "role:aws:arn:aws:iam::111122223333:role/admin-role"
    user_node = "user:aws:arn:aws:iam::111122223333:user/alice"
    assert role_node in nodes
    assert user_node in nodes
    assert nodes[role_node].entity_type == EntityType.ROLE

    # Effective-permissions overlay turned the admin role's CAN_ACCESS into
    # HAS_PERMISSION edges over the inventoried resources.
    has_perm = [e for e in graph.edges if e.relationship == RelationshipType.HAS_PERMISSION and e.source == role_node]
    assert has_perm


def test_graph_inventory_noop_when_not_ok() -> None:
    """A disabled / empty inventory payload adds no inventory nodes."""
    graph = _build_graph_from_inventory(
        {"status": "disabled", "buckets": [], "instances": [], "security_groups": [], "roles": [], "users": []}
    )
    assert not any(nid.startswith("cloud_resource:aws:s3:") for nid in graph.nodes)


def test_graph_inventory_ignores_missing_section() -> None:
    from agent_bom.graph.builder import build_unified_graph_from_report

    graph = build_unified_graph_from_report({"agents": []})
    assert not any(nid.startswith("cloud_resource:aws:") for nid in graph.nodes)


# ---------------------------------------------------------------------------
# Inline IAM policy enumeration (inline policies never appear in list_attached_*)
# ---------------------------------------------------------------------------


class _InlinePaginator:
    def __init__(self, names: list[str]) -> None:
        self._names = names

    def paginate(self, **_kwargs: Any) -> list[dict[str, Any]]:
        return [{"PolicyNames": self._names}]


class _FakeIAMInline:
    """Minimal IAM whose role carries a single admin INLINE policy."""

    def get_paginator(self, op: str) -> Any:
        return _InlinePaginator(["AdminInline"] if op == "list_role_policies" else [])

    def get_role_policy(self, RoleName: str, PolicyName: str) -> dict[str, Any]:  # noqa: N803
        return {
            "RoleName": RoleName,
            "PolicyName": PolicyName,
            "PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
        }


def test_inline_policies_enumerated_and_classified() -> None:
    pols = aws_inventory._inline_policies(_FakeIAMInline(), "role", "app-role", warnings=[])
    assert len(pols) == 1
    p = pols[0]
    assert p["attachment_type"] == "inline"
    assert p["policy_name"] == "AdminInline"
    assert p["privilege_level"] == "admin"  # Action "*" → admin, even though inline


def test_inline_policies_missing_method_degrades_to_warning() -> None:
    class _NoInline:
        def get_paginator(self, op: str) -> Any:
            raise RuntimeError("no inline support")

    warns: list[str] = []
    pols = aws_inventory._inline_policies(_NoInline(), "role", "app-role", warnings=warns)
    assert pols == []
    assert warns and "inline policy" in warns[0].lower()


# ---------------------------------------------------------------------------
# Multi-region fan-out (discover_inventory_all_regions)
# ---------------------------------------------------------------------------


class _RegionEC2:
    """Region-aware EC2 fake: one instance per region + describe_regions."""

    def __init__(self, region: str, *, enabled_regions: list[str]) -> None:
        self._region = region
        self._enabled = enabled_regions

    def describe_regions(self, **_kwargs: Any) -> dict[str, Any]:
        return {"Regions": [{"RegionName": r} for r in self._enabled]}

    def describe_vpcs(self, **_kwargs: Any) -> dict[str, Any]:
        return {"Vpcs": [{"VpcId": f"vpc-{self._region}", "CidrBlock": "10.0.0.0/16", "IsDefault": True, "Tags": []}]}

    def get_paginator(self, op: str) -> _FakePaginator:
        if op == "describe_instances":
            return _FakePaginator(
                [
                    {
                        "Reservations": [
                            {
                                "Instances": [
                                    {
                                        "InstanceId": f"i-{self._region}",
                                        "InstanceType": "t3.micro",
                                        "State": {"Name": "running"},
                                        "SecurityGroups": [],
                                        "Tags": [{"Key": "Name", "Value": f"host-{self._region}"}],
                                    }
                                ]
                            }
                        ]
                    }
                ]
            )
        return _FakePaginator([{"SecurityGroups": []}])


class _MultiRegionSession:
    """Fake session whose region-scoped clients vary by region; globals are stable."""

    def __init__(self, *, enabled_regions: list[str], boom_regions: set[str] | None = None, **kwargs: Any) -> None:
        # Mirror boto3: Session(region_name=...) sets the session's region_name.
        self.region_name = str(kwargs.get("region_name") or "us-east-1")
        self._enabled = enabled_regions
        self._boom = boom_regions or set()

    def client(self, name: str, **kwargs: Any) -> Any:
        region = str(kwargs.get("region_name") or self.region_name)
        if region in self._boom:
            # Every client in a "bad" region raises so the whole region degrades.
            raise RuntimeError(f"region {region} unreachable")
        if name == "ec2":
            return _RegionEC2(region, enabled_regions=self._enabled)
        if name == "s3":
            return _FakeS3()
        if name == "iam":
            return _FakeIAM()
        if name == "sts":
            return _FakeSTS()
        # Region-scoped services with no resources (paginator-driven, empty pages).

        class _Empty:
            def get_paginator(self, _op: str) -> _FakePaginator:
                return _FakePaginator([{}])

        return _Empty()


def _install_multiregion_boto3(session_factory: Any) -> Any:
    import types

    boto3_mod = types.ModuleType("boto3")
    boto3_mod.Session = session_factory  # type: ignore[attr-defined]
    botocore_mod = types.ModuleType("botocore")
    exc_mod = types.ModuleType("botocore.exceptions")
    exc_mod.NoCredentialsError = type("NoCredentialsError", (Exception,), {})  # type: ignore[attr-defined]
    exc_mod.ClientError = type("ClientError", (Exception,), {})  # type: ignore[attr-defined]
    botocore_mod.exceptions = exc_mod  # type: ignore[attr-defined]
    return patch.dict(sys.modules, {"boto3": boto3_mod, "botocore": botocore_mod, "botocore.exceptions": exc_mod})


def test_all_regions_flag_default_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(aws_inventory.ALL_REGIONS_ENV_FLAG, raising=False)
    assert aws_inventory.all_regions_enabled() is False
    monkeypatch.setenv(aws_inventory.ALL_REGIONS_ENV_FLAG, "1")
    assert aws_inventory.all_regions_enabled() is True


def test_multiregion_merges_region_scoped_and_dedupes_globals(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(aws_inventory.INVENTORY_ENV_FLAG, "1")
    monkeypatch.setenv(aws_inventory.REGIONS_ENV_VAR, "us-east-1,eu-west-1")

    def _factory(**kwargs: Any) -> _MultiRegionSession:
        return _MultiRegionSession(enabled_regions=["us-east-1", "eu-west-1"], **kwargs)

    with _install_multiregion_boto3(_factory):
        payload = aws_inventory.discover_inventory_all_regions()

    assert payload["status"] == "ok"
    assert payload["region"].startswith("multi:")
    assert set(payload["regions"]) == {"us-east-1", "eu-west-1"}

    # Region-scoped EC2 instances concatenated: one per region, each carrying its region.
    instance_ids = {i["instance_id"] for i in payload["instances"]}
    assert instance_ids == {"i-us-east-1", "i-eu-west-1"}
    regions_on_instances = {i["region"] for i in payload["instances"]}
    assert regions_on_instances == {"us-east-1", "eu-west-1"}
    # VPCs concatenated per region too.
    assert {v["vpc_id"] for v in payload["vpcs"]} == {"vpc-us-east-1", "vpc-eu-west-1"}

    # GLOBAL S3 buckets enumerated ONCE — not duplicated per region.
    assert sorted(b["name"] for b in payload["buckets"]) == ["private-logs", "public-data-lake"]
    # GLOBAL IAM enumerated ONCE — one admin role, one user, no duplication.
    assert [r["name"] for r in payload["roles"]] == ["admin-role"]
    assert [u["name"] for u in payload["users"]] == ["alice"]

    # Trust contract spans both regions.
    scope = payload["discovery_envelope"]["discovery_scope"]
    assert "aws:region/us-east-1" in scope
    assert "aws:region/eu-west-1" in scope


def test_multiregion_failing_region_degrades_to_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(aws_inventory.INVENTORY_ENV_FLAG, "1")
    monkeypatch.setenv(aws_inventory.REGIONS_ENV_VAR, "us-east-1,eu-west-1")

    def _factory(**kwargs: Any) -> _MultiRegionSession:
        return _MultiRegionSession(enabled_regions=["us-east-1", "eu-west-1"], boom_regions={"eu-west-1"}, **kwargs)

    with _install_multiregion_boto3(_factory):
        payload = aws_inventory.discover_inventory_all_regions()

    # The scan survives: status ok, the healthy region's resources are present.
    assert payload["status"] == "ok"
    assert {i["instance_id"] for i in payload["instances"]} == {"i-us-east-1"}
    # The bad region surfaced a warning rather than sinking the scan.
    assert any("eu-west-1" in w for w in payload["warnings"])


def test_multiregion_disabled_without_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(aws_inventory.INVENTORY_ENV_FLAG, raising=False)
    monkeypatch.delenv(aws_inventory.INVENTORY_ENV_FLAG_LEGACY, raising=False)
    payload = aws_inventory.discover_inventory_all_regions()
    assert payload["status"] == "disabled"
    assert payload["instances"] == []


def test_multiregion_enumerates_enabled_regions_when_no_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(aws_inventory.INVENTORY_ENV_FLAG, "1")
    monkeypatch.delenv(aws_inventory.REGIONS_ENV_VAR, raising=False)

    def _factory(**kwargs: Any) -> _MultiRegionSession:
        return _MultiRegionSession(enabled_regions=["us-east-1", "ap-south-1"], **kwargs)

    with _install_multiregion_boto3(_factory):
        payload = aws_inventory.discover_inventory_all_regions(force=True)

    # describe_regions drove the region set when no explicit override was given.
    assert set(payload["regions"]) == {"us-east-1", "ap-south-1"}


# ---------------------------------------------------------------------------
# Partial-permission tolerance: the shared degrade-don't-crash helpers and the
# AWS discoverer path that produces actionable missing_permissions guidance.
# ---------------------------------------------------------------------------


class _ClientError(Exception):
    """Stand-in for botocore.exceptions.ClientError carrying an Error.Code."""

    def __init__(self, code: str, status: int = 403) -> None:
        super().__init__(f"An error occurred ({code}) when calling the API.")
        self.response = {"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": status}}


def test_is_access_denied_error_detects_each_cloud_shape() -> None:
    # AWS error-code, Azure 403 status, GCP type-name + message.
    assert aws_inventory.is_access_denied_error(_ClientError("AccessDenied")) is True
    assert aws_inventory.is_access_denied_error(_ClientError("UnauthorizedOperation")) is True

    class _AzureAuth(Exception):  # noqa: N818 — emulates azure HttpResponseError (no Error suffix)
        def __init__(self) -> None:
            super().__init__("AuthorizationFailed")
            self.status_code = 403

    assert aws_inventory.is_access_denied_error(_AzureAuth()) is True

    class PermissionDenied(Exception):  # noqa: N818 — name matches the real GCP SDK type the classifier keys on
        pass

    assert aws_inventory.is_access_denied_error(PermissionDenied("403 denied")) is True
    # A non-access error is NOT misclassified.
    assert aws_inventory.is_access_denied_error(RuntimeError("transient 500")) is False


def test_record_discovery_failure_branches_on_access_vs_generic() -> None:
    warnings: list[str] = []
    missing: list[dict[str, str]] = []

    # Access error → actionable warning + missing_permissions entry.
    aws_inventory.record_discovery_failure(
        exc=_ClientError("AccessDenied"),
        resource_type="EC2 instances",
        permission="ec2:DescribeInstances",
        cloud="aws",
        warnings=warnings,
        missing=missing,
    )
    assert "role lacks ec2:DescribeInstances" in warnings[0]
    assert "add it to the read-only policy" in warnings[0]
    assert missing == [{"cloud": "aws", "permission": "ec2:DescribeInstances", "resource_type": "EC2 instances"}]

    # Generic error → plain warning, NO missing_permissions entry.
    aws_inventory.record_discovery_failure(
        exc=RuntimeError("transient 500"),
        resource_type="S3 buckets",
        permission="s3:ListAllMyBuckets",
        cloud="aws",
        warnings=warnings,
        missing=missing,
    )
    assert any("Could not list S3 buckets" in w for w in warnings)
    assert len(missing) == 1  # unchanged


def test_dedupe_missing_permissions_is_sorted_and_idempotent() -> None:
    raw = [
        {"cloud": "aws", "permission": "s3:ListAllMyBuckets", "resource_type": "S3 buckets"},
        {"cloud": "aws", "permission": "ec2:DescribeInstances", "resource_type": "EC2 instances"},
        {"cloud": "aws", "permission": "ec2:DescribeInstances", "resource_type": "EC2 instances"},
    ]
    out = aws_inventory.dedupe_missing_permissions(raw)
    assert out == [
        {"cloud": "aws", "permission": "ec2:DescribeInstances", "resource_type": "EC2 instances"},
        {"cloud": "aws", "permission": "s3:ListAllMyBuckets", "resource_type": "S3 buckets"},
    ]
    assert aws_inventory.dedupe_missing_permissions(out) == out  # idempotent


def test_aws_permission_denied_degrades_with_guidance(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(aws_inventory.INVENTORY_ENV_FLAG, "1")

    def _denied(self: Any) -> dict[str, Any]:
        raise _ClientError("AccessDenied")

    monkeypatch.setattr(_FakeS3, "list_buckets", _denied)
    with _install_fake_boto3():
        payload = aws_inventory.discover_inventory(region="us-east-1")

    assert payload["status"] == "ok"
    # S3 skipped, but the rest of the estate still enumerated.
    assert payload["buckets"] == []
    assert payload["instances"]  # EC2 still discovered
    actionable = [w for w in payload["warnings"] if "role lacks s3:ListAllMyBuckets" in w]
    assert actionable, payload["warnings"]
    assert payload["missing_permissions"] == [{"cloud": "aws", "permission": "s3:ListAllMyBuckets", "resource_type": "S3 buckets"}]


# ---------------------------------------------------------------------------
# IAM groups + group-based access (identity/RBAC depth)
# ---------------------------------------------------------------------------


class _FakeIAMGroups:
    """IAM client where `alice` is admin ONLY through the `admins` group."""

    def get_paginator(self, op: str) -> _FakePaginator:
        if op == "list_roles":
            return _FakePaginator([{"Roles": []}])
        if op == "list_users":
            return _FakePaginator([{"Users": [{"UserName": "alice", "Arn": "arn:aws:iam::111122223333:user/alice", "Path": "/"}]}])
        if op == "list_groups":
            return _FakePaginator([{"Groups": [{"GroupName": "admins", "Arn": "arn:aws:iam::111122223333:group/admins", "Path": "/"}]}])
        if op == "get_group":
            return _FakePaginator([{"Users": [{"UserName": "alice", "Arn": "arn:aws:iam::111122223333:user/alice"}]}])
        if op == "list_groups_for_user":
            return _FakePaginator([{"Groups": [{"GroupName": "admins"}]}])
        if op == "list_attached_group_policies":
            return _FakePaginator(
                [{"AttachedPolicies": [{"PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess", "PolicyName": "AdministratorAccess"}]}]
            )
        # All other attached/inline list ops resolve to empty.
        return _FakePaginator([{"AttachedPolicies": [], "PolicyNames": []}])


def test_discover_iam_enumerates_groups_and_memberships() -> None:
    class _Sess:
        def client(self, name: str, **_kwargs: Any) -> Any:
            return _FakeIAMGroups()

    roles, users, groups = aws_inventory._discover_iam(_Sess(), account_id="111122223333", warnings=[])
    assert roles == []
    by_name = {g["name"]: g for g in groups}
    assert "admins" in by_name
    admins = by_name["admins"]
    assert admins["privilege_level"] == "admin"
    assert admins["members"][0]["id"] == "arn:aws:iam::111122223333:user/alice"
    assert admins["members"][0]["type"] == "user"
    # The user itself has NO direct privilege but records its group membership.
    alice = {u["name"]: u for u in users}["alice"]
    assert alice["privilege_level"] == "unknown"
    assert alice["groups"] == ["admins"]


def test_graph_user_admin_via_group_surfaces_effective_permission() -> None:
    from agent_bom.graph.types import EntityType, RelationshipType

    payload = {
        "provider": "aws",
        "status": "ok",
        "account_id": "111122223333",
        "region": "us-east-1",
        "buckets": [{"name": "prod-bucket", "arn": "arn:bucket", "publicly_accessible": False, "location": "us-east-1"}],
        "roles": [],
        "users": [
            {
                "principal_type": "user",
                "name": "alice",
                "arn": "arn:aws:iam::111122223333:user/alice",
                "policies": [],
                "groups": ["admins"],
                "privilege_level": "unknown",
            }
        ],
        "groups": [
            {
                "principal_type": "group",
                "name": "admins",
                "arn": "arn:aws:iam::111122223333:group/admins",
                "policies": [
                    {
                        "policy_id": "arn:aws:iam::aws:policy/AdministratorAccess",
                        "policy_name": "AdministratorAccess",
                        "privilege_level": "admin",
                    }
                ],
                "members": [{"id": "arn:aws:iam::111122223333:user/alice", "name": "alice", "type": "user"}],
                "privilege_level": "admin",
            }
        ],
    }
    graph = _build_graph_from_inventory(payload)
    nodes = graph.nodes

    group_node = "group:aws:arn:aws:iam::111122223333:group/admins"
    user_node = "user:aws:arn:aws:iam::111122223333:user/alice"
    policy_node = "policy:aws:arn:aws:iam::aws:policy/AdministratorAccess"
    assert nodes[group_node].entity_type == EntityType.GROUP
    # Group + membership + group policy are all in the graph.
    assert any(e.relationship == RelationshipType.MEMBER_OF and e.source == user_node and e.target == group_node for e in graph.edges)
    assert any(e.relationship == RelationshipType.ATTACHED and e.source == group_node and e.target == policy_node for e in graph.edges)
    # The user is admin ONLY via the group, yet surfaces effective access to the
    # bucket, marked as group-inherited (not a privilege escalation).
    bucket_node = "cloud_resource:aws:s3:bucket:prod-bucket"
    user_perms = {
        e.target: e.evidence.get("access")
        for e in graph.edges
        if e.relationship == RelationshipType.HAS_PERMISSION and e.source == user_node
    }
    assert user_perms.get(bucket_node) == "group"
    assert nodes[user_node].attributes.get("can_escalate_privilege") is None
