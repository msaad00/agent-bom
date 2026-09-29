# ruff: noqa: N803  — fake boto3 client methods mirror boto3's PascalCase kwargs.
"""Characterization golden for ``agent_bom.cloud.aws_inventory``.

Drives the public discovery entrypoints (``discover_inventory``,
``discover_inventory_all_regions``, ``discover_all_account_inventories``)
against a fake boto3 session covering every resource family and every
success / AccessDenied / throttling / empty / pagination branch, and pins the
complete payload, the warning order, the emitted log records, and the boto3
call order to a golden file.

Normalized (genuinely volatile) values only:

- ``collected_at`` — wall-clock timestamp stamped by the IAM usage collector.
- Account fan-out payload order and threaded call order — ``as_completed``
  completion order; payloads are sorted by ``account_id`` and threaded calls
  are sorted.

Regenerate with ``UPDATE_CLOUD_GOLDEN=1 pytest tests/test_aws_inventory_characterization.py``.
"""

from __future__ import annotations

import copy
import datetime
import json
import logging
import os
import sys
import types
from collections.abc import Callable, Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

from agent_bom.cloud import aws_inventory

GOLDEN = Path(__file__).parent / "fixtures" / "cloud_characterization" / "aws_inventory.json"
ACCOUNT = "111122223333"
DT = datetime.datetime(2026, 1, 2, 3, 4, 5, tzinfo=datetime.timezone.utc)
DT_OLD = datetime.datetime(2025, 6, 1, tzinfo=datetime.timezone.utc)


class NoCredentialsError(Exception):
    pass


class FakeError(Exception):
    """botocore ``ClientError``-shaped failure."""

    def __init__(self, code: str, message: str = "", status: int | None = None) -> None:
        super().__init__(f"An error occurred ({code}): {message or code}")
        self.response: dict[str, Any] = {"Error": {"Code": code, "Message": message or code}}
        if status is not None:
            self.response["ResponseMetadata"] = {"HTTPStatusCode": status}


def _denied() -> FakeError:
    return FakeError("AccessDenied", "User is not authorized to perform this action")


def _throttled() -> FakeError:
    return FakeError("Throttling", "Rate exceeded")


def _resolve(value: Any, kwargs: dict[str, Any]) -> Any:
    if isinstance(value, BaseException):
        raise value
    if callable(value):
        return value(**kwargs)
    return copy.deepcopy(value)


class FakePaginator:
    def __init__(self, value: Any, record: Callable[[dict[str, Any]], None]) -> None:
        self._value = value
        self._record = record

    def paginate(self, **kwargs: Any) -> Any:
        self._record(kwargs)
        return _resolve(self._value, kwargs)


class FakeClient:
    def __init__(self, service: str, region: str | None, spec: dict[str, Any], calls: list[str]) -> None:
        self._service = service
        self._region = region
        self._spec = spec
        self._calls = calls

    def _record(self, name: str, kwargs: dict[str, Any]) -> None:
        self._calls.append(f"{self._service}@{self._region}:{name}:{json.dumps(kwargs, sort_keys=True, default=str)}")

    def _lookup(self, key: str) -> Any:
        if key in self._spec:
            return self._spec[key]
        if "__default__" in self._spec:
            return self._spec["__default__"]
        return [{}] if key.startswith("page:") else {}

    def get_paginator(self, op: str) -> FakePaginator:
        value = self._lookup(f"page:{op}")
        return FakePaginator(value, lambda kw: self._record(f"paginate:{op}", kw))

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)

        def _call(**kwargs: Any) -> Any:
            self._record(name, kwargs)
            return _resolve(self._lookup(name), kwargs)

        return _call


class FakeSession:
    def __init__(self, spec: dict[str, Any], calls: list[str], region_name: str | None = "us-east-1", tag: str = "") -> None:
        self._spec = spec
        self._calls = calls
        self.region_name = region_name
        self._tag = tag

    def client(self, name: str, region_name: str | None = None, **_kwargs: Any) -> FakeClient:
        service_spec = self._spec.get(f"{name}@{region_name}", self._spec.get(name, self._spec.get("*", {})))
        creation = service_spec.get("__client__") if isinstance(service_spec, dict) else None
        if isinstance(creation, BaseException):
            raise creation
        return FakeClient(f"{self._tag}{name}", region_name, service_spec, self._calls)

    def __repr__(self) -> str:
        return f"FakeSession({self._tag or 'default'})"


def _by(key: str, table: dict[str, Any], default: Any = None) -> Callable[..., Any]:
    def _fn(**kwargs: Any) -> Any:
        value = table.get(kwargs.get(key), default if default is not None else {})
        return _resolve(value, kwargs)

    return _fn


# ---------------------------------------------------------------------------
# Full-estate spec: every family populated with its edge cases
# ---------------------------------------------------------------------------


def _full_spec() -> dict[str, Any]:
    admin_doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    write_doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": "*"}]}
    return {
        "sts": {"get_caller_identity": {"Account": ACCOUNT}},
        "s3": {
            "list_buckets": {
                "Buckets": [
                    {"Name": "pub-policy", "CreationDate": DT},
                    {"Name": "pub-acl-blocked"},
                    {"Name": "private"},
                    {"Name": ""},
                    {"Name": "err-bucket"},
                ]
            },
            "get_bucket_location": _by(
                "Bucket",
                {
                    "pub-policy": {"LocationConstraint": None},
                    "pub-acl-blocked": {"LocationConstraint": "us-west-2"},
                    "private": {"LocationConstraint": "eu-west-1"},
                    "err-bucket": _denied(),
                },
            ),
            "get_bucket_policy_status": _by(
                "Bucket",
                {
                    "pub-policy": {"PolicyStatus": {"IsPublic": True}},
                    "pub-acl-blocked": {"PolicyStatus": {"IsPublic": False}},
                    "private": FakeError("NoSuchBucketPolicy"),
                    "err-bucket": _throttled(),
                },
            ),
            "get_bucket_acl": _by(
                "Bucket",
                {
                    "pub-acl-blocked": {"Grants": [{"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}}]},
                    "private": {"Grants": [{"Grantee": {"ID": "owner"}}, "bad"]},
                    "err-bucket": _denied(),
                },
                default={"Grants": []},
            ),
            "get_public_access_block": _by(
                "Bucket",
                {"pub-policy": FakeError("NoSuchPublicAccessBlock"), "pub-acl-blocked": FakeError("InternalError")},
            ),
            "get_bucket_tagging": _by(
                "Bucket",
                {"pub-policy": {"TagSet": [{"Key": "env", "Value": "prod"}, {"Key": "", "Value": "x"}]}},
                default=FakeError("NoSuchTagSet"),
            ),
        },
        "s3control": {"get_public_access_block": {"PublicAccessBlockConfiguration": {"IgnorePublicAcls": True}}},
        "ec2": {
            "page:describe_instances": [
                {
                    "Reservations": [
                        {
                            "Instances": [
                                {
                                    "InstanceId": "i-1",
                                    "Tags": [{"Key": "Name", "Value": "web"}, {"Key": "", "Value": "x"}],
                                    "SecurityGroups": [{"GroupId": "sg-1"}, {"GroupId": "sg-1"}, "bad"],
                                    "State": {"Name": "running"},
                                    "LaunchTime": DT,
                                    "IamInstanceProfile": {"Arn": f"arn:aws:iam::{ACCOUNT}:instance-profile/web"},
                                    "PublicIpAddress": "203.0.113.5",
                                    "PrivateIpAddress": "10.0.0.5",
                                    "VpcId": "vpc-1",
                                    "SubnetId": "subnet-a",
                                    "InstanceType": "t3.micro",
                                    "ImageId": "ami-1",
                                }
                            ]
                        }
                    ]
                },
                {"Reservations": [{"Instances": [{"InstanceId": "i-2", "State": "weird"}]}]},
            ],
            "page:describe_security_groups": [
                {
                    "SecurityGroups": [
                        {
                            "GroupId": "sg-1",
                            "GroupName": "web-sg",
                            "Description": "web",
                            "VpcId": "vpc-1",
                            "IpPermissions": [
                                {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                                {"FromPort": 443, "ToPort": 443, "Ipv6Ranges": [{"CidrIpv6": "::/0"}], "IpRanges": ["bad"]},
                                {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]},
                                "bad",
                            ],
                        },
                        {"GroupId": "sg-2"},
                    ]
                }
            ],
            "describe_vpcs": {
                "Vpcs": [
                    {"VpcId": "vpc-1", "CidrBlock": "10.0.0.0/16", "IsDefault": True, "Tags": [{"Key": "Name", "Value": "main"}]},
                    {"VpcId": "vpc-2"},
                    {"VpcId": ""},
                ]
            },
            "page:describe_route_tables": [
                {
                    "RouteTables": [
                        {
                            "RouteTableId": "rt-1",
                            "VpcId": "vpc-1",
                            "Routes": [{"GatewayId": "igw-1", "DestinationCidrBlock": "0.0.0.0/0"}, "bad"],
                            "Associations": [{"Main": True}, {"SubnetId": "subnet-a"}, "bad"],
                        },
                        {
                            "RouteTableId": "rt-2",
                            "VpcId": "vpc-2",
                            "Routes": [{"NatGatewayId": "nat-1", "DestinationCidrBlock": "0.0.0.0/0"}],
                            "Associations": [{"SubnetId": "subnet-c"}],
                        },
                        {"RouteTableId": ""},
                    ]
                }
            ],
            "page:describe_subnets": [
                {
                    "Subnets": [
                        {"SubnetId": "subnet-a", "VpcId": "vpc-1", "CidrBlock": "10.0.1.0/24", "AvailabilityZone": "us-east-1a"},
                        {"SubnetId": "subnet-b", "VpcId": "vpc-1", "MapPublicIpOnLaunch": True, "Tags": [{"Key": "Name", "Value": "b"}]},
                        {"SubnetId": "subnet-c", "VpcId": "vpc-2", "MapPublicIpOnLaunch": True},
                        {"SubnetId": ""},
                    ]
                }
            ],
            "page:describe_network_interfaces": [
                {
                    "NetworkInterfaces": [
                        {
                            "NetworkInterfaceId": "eni-1",
                            "Groups": [{"GroupId": "sg-1"}, {"GroupName": "x"}, "bad"],
                            "Attachment": {"InstanceId": "i-1"},
                            "Association": {"PublicIp": "203.0.113.10"},
                            "SubnetId": "subnet-a",
                            "VpcId": "vpc-1",
                            "PrivateIpAddress": "10.0.1.10",
                        },
                        {"NetworkInterfaceId": "eni-2", "Association": {"PublicIp": "203.0.113.20"}},
                        {"NetworkInterfaceId": "eni-3"},
                        {"NetworkInterfaceId": ""},
                    ]
                }
            ],
            "page:describe_nat_gateways": [
                {"NatGateways": [{"NatGatewayId": "nat-1", "VpcId": "vpc-2", "SubnetId": "subnet-a"}, {"NatGatewayId": ""}]},
                {"NatGateways": [{"NatGatewayId": "nat-2", "ConnectivityType": "private"}]},
            ],
            "describe_internet_gateways": {
                "InternetGateways": [
                    {"InternetGatewayId": "igw-1", "Attachments": [{"VpcId": "vpc-1"}, "bad"]},
                    {"InternetGatewayId": "igw-2"},
                    {"InternetGatewayId": ""},
                ]
            },
            "describe_egress_only_internet_gateways": _denied(),
            "page:describe_vpc_endpoints": [
                {
                    "VpcEndpoints": [
                        {"VpcEndpointId": "vpce-1", "ServiceName": "com.amazonaws.us-east-1.s3", "VpcId": "vpc-1", "VpcEndpointType": "Gateway"},
                        {"VpcEndpointId": "vpce-2"},
                        {"VpcEndpointId": ""},
                    ]
                }
            ],
            "page:describe_network_acls": [
                {
                    "NetworkAcls": [
                        {
                            "NetworkAclId": "acl-1",
                            "VpcId": "vpc-1",
                            "IsDefault": True,
                            "Entries": [{"RuleAction": "allow", "CidrBlock": "0.0.0.0/0", "Protocol": "-1"}],
                            "Associations": [{"SubnetId": "subnet-b"}],
                        },
                        {
                            "NetworkAclId": "acl-2",
                            "VpcId": "vpc-2",
                            "Entries": [
                                {"Egress": True, "RuleAction": "allow", "CidrBlock": "0.0.0.0/0"},
                                {"RuleAction": "deny", "CidrBlock": "0.0.0.0/0"},
                                {"RuleAction": "allow", "CidrBlock": "10.0.0.0/8"},
                                {"RuleAction": "ALLOW", "CidrBlock": "0.0.0.0/0", "Protocol": "6", "PortRange": {"From": 22, "To": 22}},
                                {"RuleAction": "allow", "Ipv6CidrBlock": "::/0", "Protocol": "6", "PortRange": "bad"},
                                "bad",
                            ],
                            "Associations": [{"SubnetId": "subnet-c"}, {"SubnetId": "subnet-a"}, {"SubnetId": "subnet-a"}, "bad"],
                        },
                        {"NetworkAclId": "acl-3", "Entries": [{"RuleAction": "allow", "CidrBlock": "10.1.0.0/16"}]},
                        {"NetworkAclId": ""},
                    ]
                }
            ],
            "describe_addresses": {
                "Addresses": [
                    {"PublicIp": "203.0.113.20", "InstanceId": "i-1", "AllocationId": "eipalloc-1"},
                    {"PublicIp": "203.0.113.20", "NetworkInterfaceId": "eni-2"},
                    {"PublicIp": "203.0.113.30", "NetworkInterfaceId": "eni-9"},
                    {"PublicIp": ""},
                ]
            },
            "describe_regions": {"Regions": [{"RegionName": "us-west-2"}, {"RegionName": "us-east-1"}, {"RegionName": ""}, {}]},
        },
        "iam": {
            "page:list_roles": [
                {
                    "Roles": [
                        {
                            "RoleName": "role-admin",
                            "Arn": f"arn:aws:iam::{ACCOUNT}:role/role-admin",
                            "Path": "/",
                            "CreateDate": DT,
                            "AssumeRolePolicyDocument": {
                                "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]
                            },
                        },
                        "bad",
                    ]
                },
                {
                    "Roles": [
                        {
                            "RoleName": "role-ro",
                            "Arn": f"arn:aws:iam::{ACCOUNT}:role/role-ro",
                            "AssumeRolePolicyDocument": {
                                "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:root"}}]
                            },
                            "RoleLastUsed": {"LastUsedDate": DT_OLD, "Region": "eu-west-1"},
                        },
                        {"Arn": "arn:aws:iam::444455556666:role/nameless"},
                    ]
                },
            ],
            "page:list_attached_role_policies": _by(
                "RoleName",
                {
                    "role-admin": [
                        {"AttachedPolicies": [{"PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess", "PolicyName": "AdministratorAccess"}]}
                    ],
                    "role-ro": [
                        {
                            "AttachedPolicies": [
                                {"PolicyArn": f"arn:aws:iam::{ACCOUNT}:policy/custom-rw", "PolicyName": "custom-rw"},
                                {"PolicyArn": "arn:aws:iam::aws:policy/AmazonS3FullAccess", "PolicyName": "AmazonS3FullAccess"},
                                {"PolicyArn": "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess", "PolicyName": "AmazonEC2ReadOnlyAccess"},
                                {"PolicyArn": "arn:aws:iam::aws:policy/AWSSupportAccess", "PolicyName": "AWSSupportAccess"},
                                {"PolicyArn": "", "PolicyName": ""},
                            ]
                        }
                    ],
                },
                default=[{}],
            ),
            "get_policy": _by(
                "PolicyArn",
                {f"arn:aws:iam::{ACCOUNT}:policy/custom-rw": {"Policy": {"DefaultVersionId": "v2"}}},
                default=_denied(),
            ),
            "get_policy_version": {"PolicyVersion": {"Document": write_doc}},
            "page:list_role_policies": _by("RoleName", {"role-admin": [{"PolicyNames": ["inline-star", ""]}]}, default=_throttled()),
            "get_role_policy": {"PolicyDocument": admin_doc},
            "generate_service_last_accessed_details": _by(
                "Arn",
                {f"arn:aws:iam::{ACCOUNT}:role/role-admin": {"JobId": "job-1"}},
                default=_denied(),
            ),
            "get_service_last_accessed_details": lambda **kw: (
                {
                    "JobStatus": "COMPLETED",
                    "ServicesLastAccessed": [{"ServiceNamespace": "ec2"}, "bad", {"ServiceNamespace": ""}],
                }
                if kw.get("Marker")
                else {
                    "JobStatus": "COMPLETED",
                    "IsTruncated": True,
                    "Marker": "m1",
                    "ServicesLastAccessed": [{"ServiceNamespace": "s3", "LastAuthenticated": DT, "LastAuthenticatedRegion": "us-east-1"}],
                }
            ),
            "get_role": {"Role": {"RoleLastUsed": {"LastUsedDate": DT, "Region": "us-east-1"}}},
            "page:list_groups": [
                {"Groups": [{"GroupName": "devs", "Arn": f"arn:aws:iam::{ACCOUNT}:group/devs", "Path": "/", "CreateDate": DT}]},
                {"Groups": [{"GroupName": "broken", "Arn": f"arn:aws:iam::{ACCOUNT}:group/broken"}]},
            ],
            "page:list_attached_group_policies": _by(
                "GroupName",
                {"devs": [{"AttachedPolicies": [{"PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess", "PolicyName": "ReadOnlyAccess"}]}]},
                default=[{}],
            ),
            "page:get_group": _by(
                "GroupName",
                {
                    "devs": [
                        {
                            "Users": [
                                {"Arn": f"arn:aws:iam::{ACCOUNT}:user/alice", "UserName": "alice"},
                                {"UserName": "carol"},
                                {"UserName": "", "Arn": ""},
                            ]
                        }
                    ]
                },
                default=_denied(),
            ),
            "page:list_users": [
                {
                    "Users": [
                        {"UserName": "alice", "Arn": f"arn:aws:iam::{ACCOUNT}:user/alice", "Path": "/", "CreateDate": DT},
                        {"UserName": "bob", "Arn": f"arn:aws:iam::{ACCOUNT}:user/bob"},
                    ]
                }
            ],
            "page:list_attached_user_policies": _by(
                "UserName",
                {
                    "alice": [
                        {"AttachedPolicies": [{"PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess", "PolicyName": "ReadOnlyAccess"}]}
                    ],
                },
                default=_throttled(),
            ),
            "page:list_user_policies": _by("UserName", {"alice": [{"PolicyNames": ["u-inline"]}]}, default=[{}]),
            "get_user_policy": _denied(),
            "page:list_groups_for_user": _by(
                "UserName", {"alice": [{"Groups": [{"GroupName": "devs"}, {"GroupName": ""}]}]}, default=_denied()
            ),
        },
        "rds": {
            "page:describe_db_instances": [
                {
                    "DBInstances": [
                        {
                            "DBInstanceIdentifier": "db-1",
                            "DBInstanceArn": f"arn:aws:rds:us-east-1:{ACCOUNT}:db:db-1",
                            "Engine": "postgres",
                            "PubliclyAccessible": True,
                            "StorageEncrypted": False,
                            "Endpoint": {"Address": "db-1.example.invalid"},
                        },
                        {"DBInstanceIdentifier": "db-2", "Endpoint": None},
                        {"DBInstanceIdentifier": ""},
                    ]
                }
            ]
        },
        "lambda": {
            "page:list_functions": [
                {
                    "Functions": [
                        {
                            "FunctionName": "fn-ai",
                            "FunctionArn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:fn-ai",
                            "Runtime": "python3.11",
                            "Role": f"arn:aws:iam::{ACCOUNT}:role/role-admin",
                        },
                        {
                            "FunctionName": "fn-ai-empty",
                            "FunctionArn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:fn-ai-empty",
                            "Runtime": "python3.11",
                        },
                        {"FunctionName": "fn-noarn", "Runtime": "python3.11"},
                        {"FunctionName": "fn-node", "Runtime": "nodejs20.x", "VpcConfig": {"VpcId": "vpc-1"}},
                        {"FunctionName": ""},
                    ]
                }
            ]
        },
        "dynamodb": {
            "page:list_tables": [{"TableNames": ["t1", "t2", ""]}],
            "describe_table": _by(
                "TableName",
                {
                    "t1": {
                        "Table": {
                            "TableArn": f"arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/t1",
                            "SSEDescription": {"Status": "ENABLED"},
                            "ItemCount": 42,
                        }
                    },
                    "t2": _throttled(),
                },
            ),
        },
        "eks": {
            "page:list_clusters": [{"clusters": ["c1"]}, {"clusters": ["c2"]}],
            "describe_cluster": lambda **kw: (
                {
                    "cluster": {
                        "name": "c1",
                        "arn": f"arn:aws:eks:us-east-1:{ACCOUNT}:cluster/c1",
                        "version": "1.30",
                        "resourcesVpcConfig": {"endpointPublicAccess": True},
                    }
                }
                if kw["name"] == "c1"
                else _raise(_denied())
            ),
        },
        "elbv2": {
            "page:describe_load_balancers": [
                {
                    "LoadBalancers": [
                        {
                            "LoadBalancerName": "alb-1",
                            "LoadBalancerArn": f"arn:aws:elasticloadbalancing:us-east-1:{ACCOUNT}:loadbalancer/app/alb-1/1",
                            "Scheme": "Internet-Facing",
                            "Type": "application",
                            "DNSName": "alb-1.example.invalid",
                            "VpcId": "vpc-1",
                        },
                        {"LoadBalancerName": "nlb-1", "Scheme": "internal", "Type": "network"},
                        {"LoadBalancerName": ""},
                    ]
                }
            ]
        },
        "kms": {
            "page:list_keys": [
                {
                    "Keys": [
                        {"KeyId": "k-cust", "KeyArn": f"arn:aws:kms:us-east-1:{ACCOUNT}:key/k-cust"},
                        {"KeyId": "k-aws"},
                        {"KeyId": "k-rot-err"},
                        {"KeyId": "k-desc-err"},
                        {"KeyId": ""},
                    ]
                }
            ],
            "describe_key": _by(
                "KeyId",
                {
                    "k-cust": {"KeyMetadata": {"KeyManager": "CUSTOMER", "Enabled": True}},
                    "k-aws": {"KeyMetadata": {"KeyManager": "AWS"}},
                    "k-rot-err": {"KeyMetadata": {"KeyManager": "CUSTOMER", "Enabled": False}},
                    "k-desc-err": _denied(),
                },
            ),
            "get_key_rotation_status": _by("KeyId", {"k-cust": {"KeyRotationEnabled": True}}, default=_throttled()),
        },
        "secretsmanager": {
            "page:list_secrets": [
                {
                    "SecretList": [
                        {"Name": "db-password", "ARN": f"arn:aws:secretsmanager:us-east-1:{ACCOUNT}:secret:db", "RotationEnabled": True, "LastChangedDate": DT},
                        {"Name": "api-token"},
                        {"Name": ""},
                    ]
                }
            ]
        },
        "cloudfront": {
            "page:list_distributions": [
                {
                    "DistributionList": {
                        "Items": [
                            {
                                "Id": "E1",
                                "ARN": f"arn:aws:cloudfront::{ACCOUNT}:distribution/E1",
                                "DomainName": "d1.cloudfront.invalid",
                                "Enabled": True,
                                "Origins": {"Items": [{"DomainName": "origin.example.invalid"}]},
                            },
                            {"Id": ""},
                        ]
                    }
                },
                {"DistributionList": None},
            ]
        },
        "ecr": {
            "page:describe_repositories": [
                {
                    "repositories": [
                        {
                            "repositoryName": "repo-a",
                            "repositoryArn": f"arn:aws:ecr:us-east-1:{ACCOUNT}:repository/repo-a",
                            "repositoryUri": f"{ACCOUNT}.dkr.ecr.us-east-1.amazonaws.com/repo-a",
                            "imageScanningConfiguration": {"scanOnPush": True},
                            "imageTagMutability": "IMMUTABLE",
                        },
                        {"repositoryName": "repo-b", "repositoryUri": "registry.invalid/repo-b"},
                        {"repositoryName": "repo-c", "repositoryUri": "registry.invalid/repo-c"},
                        {"repositoryName": ""},
                    ]
                }
            ],
            "page:describe_images": _by(
                "repositoryName",
                {
                    "repo-a": [
                        {
                            "imageDetails": [
                                {"imageTags": ["v1", "latest"], "imagePushedAt": DT_OLD},
                                {"imageTags": [], "imagePushedAt": DT},
                                {"imageTags": ["v2"], "imagePushedAt": DT},
                            ]
                        },
                        {"imageDetails": [{"imageTags": ["v0"], "imagePushedAt": DT_OLD}]},
                    ],
                    "repo-b": [{"imageDetails": [{"imageTags": ["b1"], "imagePushedAt": "not-a-date"}]}],
                    "repo-c": _denied(),
                },
            ),
        },
        "redshift": {
            "page:describe_clusters": [
                {
                    "Clusters": [
                        {
                            "ClusterIdentifier": "rs-1",
                            "PubliclyAccessible": True,
                            "Encrypted": True,
                            "Endpoint": {"Address": "rs-1.example.invalid"},
                            "NodeType": "ra3.xlplus",
                        },
                        {"ClusterIdentifier": ""},
                    ]
                }
            ]
        },
        "sns": {
            "page:list_topics": [
                {"Topics": [{"TopicArn": f"arn:aws:sns:us-east-1:{ACCOUNT}:alerts"}, {"TopicArn": ""}]},
            ]
        },
        "sqs": {
            "page:list_queues": [
                {"QueueUrls": [f"https://sqs.us-east-1.amazonaws.com/{ACCOUNT}/jobs", "https://sqs.invalid/"]},
                {},
            ]
        },
        "wafv2": {
            "list_web_acls": lambda **kw: {
                ("REGIONAL", None): {
                    "WebACLs": [{"Name": "acl-a", "Id": "a", "ARN": "arn:aws:wafv2:us-east-1:1:regional/webacl/acl-a/a"}, {"Name": ""}],
                    "NextMarker": "n1",
                },
                ("REGIONAL", "n1"): {"WebACLs": [{"Name": "acl-b", "ARN": "arn:aws:wafv2:us-east-1:1:regional/webacl/acl-b/b"}, {"ARN": "arn:x/acl-c"}]},
                ("CLOUDFRONT", None): {"WebACLs": [{"Name": "acl-cf", "Id": "cf", "ARN": "arn:aws:wafv2:us-east-1:1:global/webacl/acl-cf/cf"}]},
            }[(kw["Scope"], kw.get("NextMarker"))],
            "list_resources_for_web_acl": lambda **kw: (
                {"ResourceArns": ["arn:alb-1", ""], "NextMarker": "r1"}
                if kw["WebACLArn"].endswith("acl-a/a") and not kw.get("NextMarker")
                else {"ResourceArns": ["arn:apigw-1"]}
                if kw["WebACLArn"].endswith("acl-a/a")
                else {}
                if kw["WebACLArn"] == "arn:x/acl-c"
                else _raise(_throttled())
            ),
        },
        "apigateway": {
            "page:get_rest_apis": [
                {
                    "items": [
                        {"id": "r1", "name": "public-api", "endpointConfiguration": {"types": ["EDGE"]}},
                        {"id": "r2", "endpointConfiguration": {"types": ["PRIVATE"]}},
                        {"id": ""},
                    ]
                }
            ],
            "get_stages": _by("restApiId", {"r1": {"item": [{"stageName": "prod"}, {"stageName": ""}]}}, default=_denied()),
        },
        "apigatewayv2": {
            "get_apis": lambda **kw: (
                {"Items": [{"ApiId": "ws1", "Name": "sock", "ProtocolType": "WEBSOCKET"}, {"ApiId": ""}]}
                if kw.get("NextToken")
                else {"Items": [{"ApiId": "h1", "ApiEndpoint": "https://h1.invalid"}], "NextToken": "t"}
            ),
        },
    }


def _raise(exc: BaseException) -> Any:
    raise exc


def _failing_spec(make: Callable[[], BaseException]) -> dict[str, Any]:
    spec: dict[str, Any] = {"*": {"__default__": make()}, "sts": {"get_caller_identity": {"Account": ACCOUNT}}}
    return spec


def _project_state_spec() -> dict[str, Any]:
    spec = _failing_spec(_throttled)
    spec["rds"] = {"__default__": FakeError("BILLING_DISABLED", "requires billing to be enabled")}
    spec["sns"] = {"__default__": FakeError("SERVICE_DISABLED", "API is not enabled")}
    spec["kms"] = {"__default__": FakeError("Weird", "", status=403)}
    spec["sqs"] = {"__default__": PermissionError("permission denied for queue")}
    return spec


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


def _fake_boto3(spec: dict[str, Any], calls: list[str], *, session_error: BaseException | None = None) -> Any:
    boto3_mod = types.ModuleType("boto3")

    def _session(**kwargs: Any) -> FakeSession:
        calls.append(f"boto3.Session:{json.dumps(kwargs, sort_keys=True)}")
        if session_error is not None:
            raise session_error
        return FakeSession(spec, calls, region_name=kwargs.get("region_name", "us-east-1"))

    boto3_mod.Session = _session  # type: ignore[attr-defined]
    botocore_mod = types.ModuleType("botocore")
    exc_mod = types.ModuleType("botocore.exceptions")
    exc_mod.NoCredentialsError = NoCredentialsError  # type: ignore[attr-defined]
    botocore_mod.exceptions = exc_mod  # type: ignore[attr-defined]
    return patch.dict(sys.modules, {"boto3": boto3_mod, "botocore": botocore_mod, "botocore.exceptions": exc_mod})


def _fake_lambda_packages(session: Any, arn: str, region: str, warnings: list[str]) -> list[Any]:
    if arn.endswith("fn-ai"):
        warnings.append(f"lambda package note for {arn.rsplit(':', 1)[-1]}")
        return [SimpleNamespace(name="requests", version="2.31.0", ecosystem="pypi")]
    return []


def _fake_sbom(kind: str, image_ref: str, *, region: str) -> Any:
    if "repo-b" in image_ref:
        raise RuntimeError("registry unreachable")
    return SimpleNamespace(
        packages=[{"name": "openssl", "version": "3.0.0"}],
        vulnerabilities=[{"id": "CVE-2099-0001"}],
        warnings=[f"{kind} sbom partial for {region}"],
    )


class _FakeClassification:
    def __init__(self, name: str) -> None:
        self._name = name

    def to_dict(self) -> dict[str, Any]:
        return {"bucket": self._name, "labels": ["pii"]}


def _fake_classify(s3: Any, name: str) -> _FakeClassification:
    if name == "private":
        raise RuntimeError("sample read denied")
    return _FakeClassification(name)


@pytest.fixture
def harness(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> Iterator[Any]:
    for var in (
        aws_inventory.INVENTORY_ENV_FLAG,
        aws_inventory.INVENTORY_ENV_FLAG_LEGACY,
        aws_inventory.ALL_REGIONS_ENV_FLAG,
        aws_inventory.REGIONS_ENV_VAR,
        "AWS_DEFAULT_REGION",
        "AGENT_BOM_S3_SAMPLING",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr("agent_bom.cloud.aws._extract_lambda_packages", _fake_lambda_packages)
    monkeypatch.setattr("agent_bom.cloud.sbom_pull.pull_cloud_sbom", _fake_sbom)
    monkeypatch.setattr("agent_bom.cloud.s3_data_classifier.s3_sampling_enabled", lambda: False)
    monkeypatch.setattr("agent_bom.cloud.s3_data_classifier.classify_s3_bucket", _fake_classify)
    caplog.set_level(logging.DEBUG, logger="agent_bom.cloud")
    yield SimpleNamespace(monkeypatch=monkeypatch, caplog=caplog)


def _normalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: ("<collected_at>" if k == "collected_at" and v else _normalize(v)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize(v) for v in value]
    return value


def _logs(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [f"{r.levelname}:{r.name}:{r.getMessage()}" for r in caplog.records if r.name.startswith("agent_bom.cloud")]


def _jsonable(value: Any) -> Any:
    return json.loads(json.dumps(value, default=repr))


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------


def _single(h: Any, spec: dict[str, Any], *, session_error: BaseException | None = None, **kwargs: Any) -> dict[str, Any]:
    calls: list[str] = []
    with _fake_boto3(spec, calls, session_error=session_error):
        result = aws_inventory.discover_inventory(**kwargs)
    return {"result": _normalize(_jsonable(result)), "calls": calls, "logs": _logs(h.caplog)}


def _scenarios_single(h: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    h.caplog.clear()
    out["single_disabled"] = _single(h, _full_spec())
    h.caplog.clear()
    with patch.dict(sys.modules, {"boto3": None}):
        out["single_boto3_missing"] = {
            "result": _jsonable(aws_inventory.discover_inventory(region="us-east-1", force=True)),
            "logs": _logs(h.caplog),
        }
    h.caplog.clear()
    out["single_session_error"] = _single(
        h, _full_spec(), session_error=FakeError("ProfileNotFound", "profile secret-profile not found"), region="eu-west-1", profile="dev", force=True
    )
    h.caplog.clear()
    no_creds = _full_spec()
    no_creds["s3"] = {"__client__": NoCredentialsError("Unable to locate credentials")}
    out["single_no_credentials"] = _single(h, no_creds, force=True)
    h.caplog.clear()
    out["single_full"] = _single(h, _full_spec(), force=True)
    h.caplog.clear()
    h.monkeypatch.setattr("agent_bom.cloud.s3_data_classifier.s3_sampling_enabled", lambda: True)
    out["single_full_sampling_eu"] = _single(h, _full_spec(), region="eu-west-1", force=True)
    h.monkeypatch.setattr("agent_bom.cloud.s3_data_classifier.s3_sampling_enabled", lambda: False)
    h.caplog.clear()
    empty_spec: dict[str, Any] = {"sts": {"get_caller_identity": {"Account": ""}}}
    out["single_empty_no_account"] = _single(h, empty_spec, force=True)
    h.caplog.clear()
    sts_denied = {"sts": {"get_caller_identity": _denied()}, "s3": {"list_buckets": {"Buckets": [{"Name": "b"}]}}}
    out["single_sts_denied"] = _single(h, sts_denied, force=True, include_ec2=False, include_iam=False)
    h.caplog.clear()
    out["single_access_denied"] = _single(h, _failing_spec(_denied), force=True)
    h.caplog.clear()
    out["single_throttled"] = _single(h, _failing_spec(_throttled), force=True)
    h.caplog.clear()
    out["single_project_state"] = _single(h, _project_state_spec(), region="ap-south-1", force=True)
    h.caplog.clear()
    out["single_partial_includes"] = _single(
        h, _full_spec(), force=True, include_s3=False, include_iam=False, include_compute=False, include_network=False
    )
    h.caplog.clear()
    h.monkeypatch.setenv(aws_inventory.INVENTORY_ENV_FLAG_LEGACY, "yes")
    h.monkeypatch.setattr(aws_inventory, "_legacy_flag_warned", False)
    out["single_legacy_flag"] = _single(h, {"sts": {"get_caller_identity": {"Account": ACCOUNT}}, "*": {}}, include_iam=False)
    h.monkeypatch.delenv(aws_inventory.INVENTORY_ENV_FLAG_LEGACY)
    h.caplog.clear()
    h.monkeypatch.setenv(aws_inventory.INVENTORY_ENV_FLAG, "On")
    session_calls: list[str] = []
    injected = FakeSession(_full_spec(), session_calls, region_name="eu-central-1")
    result = aws_inventory.discover_inventory(session=injected, include_iam=False)
    out["single_injected_session_flag_on"] = {"result": _normalize(_jsonable(result)), "calls": session_calls, "logs": _logs(h.caplog)}
    h.monkeypatch.delenv(aws_inventory.INVENTORY_ENV_FLAG)
    return out


def _multi(h: Any, spec: dict[str, Any], *, session_error: BaseException | None = None, **kwargs: Any) -> dict[str, Any]:
    calls: list[str] = []
    with _fake_boto3(spec, calls, session_error=session_error):
        result = aws_inventory.discover_inventory_all_regions(**kwargs)
    return {"result": _normalize(_jsonable(result)), "calls": sorted(calls), "logs": sorted(_logs(h.caplog))}


def _scenarios_multi(h: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    h.caplog.clear()
    out["multi_disabled"] = _multi(h, _full_spec())
    h.caplog.clear()
    with patch.dict(sys.modules, {"boto3": None}):
        out["multi_boto3_missing"] = {"result": _jsonable(aws_inventory.discover_inventory_all_regions(force=True))}
    h.caplog.clear()
    out["multi_session_error"] = _multi(h, _full_spec(), session_error=FakeError("ProfileNotFound"), profile="dev", force=True)
    h.caplog.clear()
    out["multi_explicit_regions"] = _multi(h, _full_spec(), regions=["us-east-1", " eu-west-1 ", "us-east-1", ""], force=True)
    h.caplog.clear()
    out["multi_describe_regions"] = _multi(h, _full_spec(), force=True, include_iam=False, include_compute=False)
    h.caplog.clear()
    regions_fail = _full_spec()
    regions_fail["ec2"] = dict(regions_fail["ec2"], describe_regions=_denied())
    out["multi_describe_regions_fail"] = _multi(h, regions_fail, force=True, include_s3=False, include_iam=False, include_data=False)
    h.caplog.clear()
    h.monkeypatch.setenv(aws_inventory.REGIONS_ENV_VAR, "sa-east-1, ,ca-central-1,sa-east-1")
    out["multi_env_regions"] = _multi(
        h, _full_spec(), force=True, include_s3=False, include_iam=False, include_data=False, include_compute=False
    )
    h.monkeypatch.delenv(aws_inventory.REGIONS_ENV_VAR)
    h.caplog.clear()
    many = [f"xx-region-{i:02d}" for i in range(34)]
    out["multi_capped"] = _multi(
        h,
        {"sts": {"get_caller_identity": {"Account": ACCOUNT}}},
        regions=many,
        force=True,
        include_s3=False,
        include_ec2=False,
        include_iam=False,
        include_data=False,
        include_compute=False,
        include_network=False,
    )
    h.caplog.clear()
    broken = _full_spec()
    broken["ec2@eu-west-1"] = {"__client__": RuntimeError("endpoint resolution failed for token=abc123")}
    broken["rds@us-west-2"] = {"__default__": _denied()}
    out["multi_region_failure"] = _multi(h, broken, regions=["us-east-1", "eu-west-1", "us-west-2"], force=True)
    h.caplog.clear()
    no_creds = _full_spec()
    no_creds["s3"] = {"__client__": NoCredentialsError("Unable to locate credentials")}
    out["multi_global_no_credentials"] = _multi(h, no_creds, regions=["eu-west-1"], force=True)
    h.caplog.clear()
    h.monkeypatch.setenv(aws_inventory.INVENTORY_ENV_FLAG, "1")
    calls: list[str] = []
    injected = FakeSession(_full_spec(), calls, region_name=None)
    result = aws_inventory.discover_inventory_all_regions(session=injected, regions=["us-west-2"])
    out["multi_injected_session_default_region_missing"] = {"result": _normalize(_jsonable(result)), "calls": sorted(calls)}
    h.monkeypatch.delenv(aws_inventory.INVENTORY_ENV_FLAG)
    return out


def _accounts(h: Any, **kwargs: Any) -> dict[str, Any]:
    calls: list[str] = []
    with _fake_boto3(_full_spec(), calls):
        payloads = aws_inventory.discover_all_account_inventories(**kwargs)
    ordered = sorted((_normalize(_jsonable(p)) for p in payloads), key=lambda p: str(p.get("account_id")))
    return {"result": ordered, "calls": sorted(calls), "logs": sorted(_logs(h.caplog))}


def _scenarios_accounts(h: Any) -> dict[str, Any]:
    from agent_bom.cloud import aws_organizations

    out: dict[str, Any] = {}
    h.caplog.clear()
    out["accounts_disabled"] = {"result": aws_inventory.discover_all_account_inventories()}
    with patch.dict(sys.modules, {"boto3": None}):
        out["accounts_boto3_missing"] = {"result": _jsonable(aws_inventory.discover_all_account_inventories(force=True))}

    def _list_raises(*_a: Any, **_k: Any) -> list[str]:
        raise FakeError("AWSOrganizationsNotInUseException", "no org")

    h.monkeypatch.setattr(aws_organizations, "list_member_account_ids", _list_raises)
    h.caplog.clear()
    out["accounts_org_enumeration_error"] = _accounts(h, force=True, region="eu-west-1")

    h.monkeypatch.setattr(aws_organizations, "list_member_account_ids", lambda *_a, **_k: [])
    h.caplog.clear()
    out["accounts_standalone"] = _accounts(h, force=True)

    member_ids = ["222233334444", "333344445555", "444455556666", "555566667777"]
    seen_assume: list[str] = []

    def _assume(account_id: str, **kwargs: Any) -> Any:
        seen_assume.append(f"{account_id}:{json.dumps({k: repr(v) for k, v in kwargs.items()}, sort_keys=True)}")
        if account_id == "333344445555":
            raise _denied()
        spec = _full_spec() if account_id != "444455556666" else {"sts": {"get_caller_identity": {"Account": account_id}}}
        spec["sts"] = {"get_caller_identity": {"Account": account_id}}
        if account_id == "555566667777":
            spec["ec2"] = {"__client__": RuntimeError("member ec2 endpoint broken")}
        return FakeSession(spec, [], region_name="us-east-1", tag=f"{account_id}/")

    h.monkeypatch.setattr(aws_organizations, "list_member_account_ids", lambda *_a, **_k: list(member_ids) + ["666677778888"])
    h.monkeypatch.setattr(aws_organizations, "max_accounts", lambda: 4)
    h.monkeypatch.setattr(aws_organizations, "assume_account_session", _assume)
    h.caplog.clear()
    out["accounts_fanout"] = _accounts(h, force=True, region="us-east-1", external_id="ext-1", role_name="AuditRole", profile="mgmt")
    out["accounts_fanout"]["assume_calls"] = sorted(seen_assume)
    return out


def _build_golden(h: Any) -> dict[str, Any]:
    golden: dict[str, Any] = {}
    golden.update(_scenarios_single(h))
    golden.update(_scenarios_multi(h))
    golden.update(_scenarios_accounts(h))
    return golden


def test_aws_inventory_golden(harness: Any) -> None:
    actual = json.loads(json.dumps(_build_golden(harness), sort_keys=False, default=repr))
    if os.environ.get("UPDATE_CLOUD_GOLDEN") == "1":
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN.write_text(json.dumps(actual, indent=1, sort_keys=False) + "\n")
    expected = json.loads(GOLDEN.read_text())
    assert list(actual) == list(expected)
    for name in expected:
        assert actual[name] == expected[name], name
        # Key order is part of the payload contract the graph builder consumes.
        if isinstance(expected[name].get("result"), dict):
            assert list(actual[name]["result"]) == list(expected[name]["result"]), name


# ---------------------------------------------------------------------------
# Patch points: patching the facade attribute must steer the discovery path
# ---------------------------------------------------------------------------


def _run_full(**kwargs: Any) -> dict[str, Any]:
    calls: list[str] = []
    with _fake_boto3(_full_spec(), calls):
        return aws_inventory.discover_inventory(force=True, **kwargs)


_FAMILY_ONLY = {"include_s3": False, "include_ec2": False, "include_iam": False, "include_data": False, "include_compute": False}


@pytest.mark.parametrize(
    ("name", "replacement", "kwargs", "check"),
    [
        ("_bucket_location", lambda *_a, **_k: "patched-loc", {}, lambda r: {b["location"] for b in r["buckets"]} == {"patched-loc"}),
        ("_bucket_public", lambda *_a, **_k: True, {}, lambda r: all(b["publicly_accessible"] for b in r["buckets"])),
        ("_bucket_tags", lambda *_a, **_k: {"patched": "1"}, {}, lambda r: all(b["tags"] == {"patched": "1"} for b in r["buckets"])),
        (
            "_latest_ecr_image_ref",
            lambda *_a, **_k: None,
            {},
            lambda r: all("sbom_image_ref" not in e for e in r["ecr_repositories"]),
        ),
        ("_MAX_IAM_USAGE_ROLES", 0, {}, lambda r: all(x["usage_evidence"]["usage_state"] == "unavailable" for x in r["roles"])),
        ("_normalize_role", lambda *_a, **_k: {"name": "patched-role"}, {}, lambda r: r["roles"][0]["name"] == "patched-role"),
        ("_discover_ec2", lambda *_a, **_k: ([{"instance_id": "p"}], []), {}, lambda r: r["instances"] == [{"instance_id": "p"}]),
        ("_discover_iam", lambda *_a, **_k: ([], [{"name": "p"}], []), {}, lambda r: r["users"] == [{"name": "p"}]),
        ("_discover_s3_buckets", lambda *_a, **_k: [{"name": "p"}], {}, lambda r: r["buckets"] == [{"name": "p"}]),
        ("_discover_rds", lambda *_a, **_k: [{"name": "p"}], {}, lambda r: r["rds_instances"] == [{"name": "p"}]),
        ("_discover_dynamodb", lambda *_a, **_k: [{"name": "p"}], {}, lambda r: r["dynamodb_tables"] == [{"name": "p"}]),
        ("_discover_kms", lambda *_a, **_k: [{"name": "p"}], {}, lambda r: r["kms_keys"] == [{"name": "p"}]),
        ("_discover_secrets", lambda *_a, **_k: [{"name": "p"}], {}, lambda r: r["secrets"] == [{"name": "p"}]),
        ("_discover_redshift", lambda *_a, **_k: [{"name": "p"}], {}, lambda r: r["redshift_clusters"] == [{"name": "p"}]),
        ("_discover_lambda", lambda *_a, **_k: [{"name": "p"}], {}, lambda r: r["lambda_functions"] == [{"name": "p"}]),
        ("_discover_eks", lambda *_a, **_k: [{"name": "p"}], {}, lambda r: r["eks_clusters"] == [{"name": "p"}]),
        ("_discover_ecr", lambda *_a, **_k: [{"name": "p"}], {}, lambda r: r["ecr_repositories"] == [{"name": "p"}]),
        ("_discover_elb", lambda *_a, **_k: [{"name": "p"}], _FAMILY_ONLY, lambda r: r["elb_load_balancers"] == [{"name": "p"}]),
        ("_discover_vpcs", lambda *_a, **_k: [{"name": "p"}], _FAMILY_ONLY, lambda r: r["vpcs"] == [{"name": "p"}]),
        ("_discover_cloudfront", lambda *_a, **_k: [{"name": "p"}], _FAMILY_ONLY, lambda r: r["cloudfront_distributions"] == [{"name": "p"}]),
        ("_discover_messaging", lambda *_a, **_k: [{"name": "p"}], _FAMILY_ONLY, lambda r: r["messaging"] == [{"name": "p"}]),
        ("_discover_waf", lambda *_a, **_k: [{"name": "p"}], _FAMILY_ONLY, lambda r: r["web_acls"] == [{"name": "p"}]),
        ("_discover_api_gateways", lambda *_a, **_k: [{"name": "p"}], _FAMILY_ONLY, lambda r: r["api_gateways"] == [{"name": "p"}]),
        ("_discover_ip_addresses", lambda *_a, **_k: [{"address": "p"}], _FAMILY_ONLY, lambda r: r["ip_addresses"] == [{"address": "p"}]),
        (
            "_discover_network_edge",
            lambda *_a, **_k: {
                k: [{"id": k}]
                for k in ("network_interfaces", "subnets", "nat_gateways", "internet_gateways", "vpc_endpoints", "route_tables", "network_acls")
            },
            _FAMILY_ONLY,
            lambda r: r["subnets"] == [{"id": "subnets"}] and r["network_acls"] == [{"id": "network_acls"}],
        ),
    ],
)
def test_facade_patch_points_steer_discovery(
    harness: Any, name: str, replacement: Any, kwargs: dict[str, Any], check: Callable[[dict[str, Any]], bool]
) -> None:
    assert not check(_run_full(**kwargs)), f"{name}: unpatched run already satisfies the patched expectation"
    harness.monkeypatch.setattr(aws_inventory, name, replacement)
    assert check(_run_full(**kwargs)), name


def test_facade_patch_points_steer_fanout(harness: Any) -> None:
    harness.monkeypatch.setattr(aws_inventory, "_resolve_region_list", lambda *_a, **_k: ["zz-patched-1"])
    seen: list[str | None] = []

    def _fake_discover(**kwargs: Any) -> dict[str, Any]:
        seen.append(kwargs.get("region"))
        return {**aws_inventory._empty_payload(region=kwargs.get("region") or ""), "status": "ok"}

    harness.monkeypatch.setattr(aws_inventory, "discover_inventory", _fake_discover)
    harness.monkeypatch.setattr(aws_inventory, "inventory_enabled", lambda: True)
    with _fake_boto3(_full_spec(), []):
        multi = aws_inventory.discover_inventory_all_regions()
        accounts = aws_inventory.discover_all_account_inventories()
    assert multi["regions"] == ["zz-patched-1"]
    assert sorted(str(r) for r in seen) == ["None", "zz-patched-1", "zz-patched-1"]
    assert accounts[0]["status"] == "ok"
