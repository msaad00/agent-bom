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
