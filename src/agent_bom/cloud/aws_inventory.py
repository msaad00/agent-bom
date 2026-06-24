"""AWS general cloud-asset inventory — estate-wide, read-only, agentless.

Unlike :mod:`agent_bom.cloud.aws` (which discovers *AI* runtimes: Bedrock
agents, Lambda action groups, SageMaker endpoints), this module enumerates the
general cloud estate so that a resource with **no** CIS finding, IaC target, or
discovered AI runtime still becomes a first-class graph node. That feeds the
CNAPP exposure overlay, the CIEM effective-permissions overlay, and the DSPM
tiers, which were previously starved of inventory input.

Three resource classes are enumerated estate-wide (NOT filtered to findings):

1. **S3 buckets**            → emitted as ``DATA_STORE`` so the DSPM /
   ``STORES`` / ``EXPOSED_TO`` overlays apply.
2. **EC2 instances + security groups** → emitted as ``CLOUD_RESOURCE``.
3. **IAM roles + users**    → emitted as identity principals with a
   ``HAS_PERMISSION``-ready policy structure.

This scanner is **opt-in** and **default OFF**. It runs only when
``AGENT_BOM_CLOUD_INVENTORY`` is truthy, mirroring the platform's other
optional-feature gates (e.g. ``AGENT_BOM_ENABLE_EXTENSION_ENTRYPOINTS``,
``AGENT_BOM_DISTRIBUTED_SCANS``).

Trust posture: read-only (``ScanMode.CLOUD_READ_ONLY``), reference-only, and
agentless. Only ``List*`` / ``Describe*`` / ``Get*Policy*`` APIs are called — no
write APIs, no object-content reads, no credential exfiltration. Boto3 absence
or missing credentials degrades to an empty inventory plus a clear status,
never a crash.

Requires ``boto3``. Install with::

    pip install 'agent-bom[aws]'
"""

from __future__ import annotations

import logging
import os
from typing import Any

from agent_bom.discovery_envelope import DiscoveryEnvelope, RedactionStatus, ScanMode

from .aws import (
    _account_id_from_arn,
    _classify_policy_actions,
    _extract_trust_principals,
    _policy_actions_from_document,
    _resolve_account_id,
)
from .normalization import sanitize_discovery_warning

logger = logging.getLogger(__name__)

# Opt-in env flag. Default OFF — estate-wide enumeration must be explicitly
# requested by an operator. Mirrors the other AGENT_BOM_* feature gates.
INVENTORY_ENV_FLAG = "AGENT_BOM_CLOUD_INVENTORY"

_TRUTHY = {"1", "true", "yes", "on"}

# Read-only IAM actions this scanner is allowed to exercise, by resource class.
# Kept here so the per-run discovery envelope `permissions_used` stays honest:
# the producer owns the catalog, not external docs.
_AWS_S3_PERMISSIONS: tuple[str, ...] = (
    "s3:ListAllMyBuckets",
    "s3:GetBucketLocation",
    "s3:GetBucketPolicyStatus",
    "s3:GetBucketPublicAccessBlock",
    "s3:GetBucketTagging",
)
_AWS_EC2_PERMISSIONS: tuple[str, ...] = (
    "ec2:DescribeInstances",
    "ec2:DescribeSecurityGroups",
)
_AWS_IAM_PERMISSIONS: tuple[str, ...] = (
    "iam:ListRoles",
    "iam:ListUsers",
    "iam:ListAttachedRolePolicies",
    "iam:ListAttachedUserPolicies",
    "iam:GetPolicy",
    "iam:GetPolicyVersion",
)
_AWS_DATA_PERMISSIONS: tuple[str, ...] = (
    "rds:DescribeDBInstances",
    "dynamodb:ListTables",
    "dynamodb:DescribeTable",
)
_AWS_COMPUTE_PERMISSIONS: tuple[str, ...] = (
    "lambda:ListFunctions",
    "eks:ListClusters",
    "eks:DescribeCluster",
)
_AWS_BASELINE_PERMISSIONS: tuple[str, ...] = ("sts:GetCallerIdentity",)

# Open-to-the-world CIDR / ipv6 ranges that mark a security-group ingress rule
# as internet-facing. The CNAPP overlay keys off this `network_exposure` shape.
_INTERNET_CIDRS = {"0.0.0.0/0"}
_INTERNET_IPV6 = {"::/0"}


def inventory_enabled() -> bool:
    """Return whether estate-wide inventory enumeration is opted in.

    Default OFF. Operators enable it by setting ``AGENT_BOM_CLOUD_INVENTORY``
    to a truthy value (``1`` / ``true`` / ``yes`` / ``on``).
    """
    return os.environ.get(INVENTORY_ENV_FLAG, "").strip().lower() in _TRUTHY


def discover_inventory(
    region: str | None = None,
    profile: str | None = None,
    *,
    include_s3: bool = True,
    include_ec2: bool = True,
    include_iam: bool = True,
    include_data: bool = True,
    include_compute: bool = True,
    force: bool = False,
) -> dict[str, Any]:
    """Enumerate the general AWS estate (S3, EC2 + security groups, IAM).

    Returns a JSON-serialisable inventory payload destined for
    ``report_json["cloud_inventory"]``; the graph builder turns it into nodes.

    The payload always carries a ``status`` string so callers can surface a
    clear reason when nothing was enumerated:

    - ``"disabled"``        — the feature flag is off and ``force`` was not set.
    - ``"boto3_missing"``   — boto3 is not installed.
    - ``"no_credentials"``  — no AWS credentials resolved.
    - ``"ok"``              — enumeration ran (possibly with per-service warnings).

    Never raises: boto3 absence, missing credentials, and per-service access
    denials all degrade to an empty (or partial) inventory plus warnings.
    """
    empty: dict[str, Any] = {
        "provider": "aws",
        "status": "disabled",
        "account_id": None,
        "region": region or "",
        "buckets": [],
        "instances": [],
        "security_groups": [],
        "roles": [],
        "users": [],
        "rds_instances": [],
        "lambda_functions": [],
        "dynamodb_tables": [],
        "eks_clusters": [],
        "warnings": [],
        "discovery_envelope": None,
    }

    if not force and not inventory_enabled():
        return empty

    try:
        import boto3  # noqa: F401
        from botocore.exceptions import NoCredentialsError
    except ImportError:
        return {
            **empty,
            "status": "boto3_missing",
            "warnings": ["boto3 is required for AWS inventory. Install with: pip install 'agent-bom[aws]'"],
        }

    session_kwargs: dict[str, Any] = {}
    if region:
        session_kwargs["region_name"] = region
    if profile:
        session_kwargs["profile_name"] = profile

    try:
        session = boto3.Session(**session_kwargs)
    except Exception as exc:  # noqa: BLE001 — boto profile/config errors must not crash a scan
        return {**empty, "status": "no_credentials", "warnings": [sanitize_discovery_warning(exc)]}

    resolved_region = session.region_name or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
    account_id = _resolve_account_id(session)

    warnings: list[str] = []
    buckets: list[dict[str, Any]] = []
    instances: list[dict[str, Any]] = []
    security_groups: list[dict[str, Any]] = []
    roles: list[dict[str, Any]] = []
    users: list[dict[str, Any]] = []
    rds_instances: list[dict[str, Any]] = []
    lambda_functions: list[dict[str, Any]] = []
    dynamodb_tables: list[dict[str, Any]] = []
    eks_clusters: list[dict[str, Any]] = []

    try:
        if include_s3:
            buckets = _discover_s3_buckets(session, account_id=account_id, warnings=warnings)
        if include_ec2:
            instances, security_groups = _discover_ec2(session, resolved_region, account_id=account_id, warnings=warnings)
        if include_iam:
            roles, users = _discover_iam(session, account_id=account_id, warnings=warnings)
        if include_data:
            rds_instances = _discover_rds(session, resolved_region, account_id=account_id, warnings=warnings)
            dynamodb_tables = _discover_dynamodb(session, resolved_region, account_id=account_id, warnings=warnings)
        if include_compute:
            lambda_functions = _discover_lambda(session, resolved_region, account_id=account_id, warnings=warnings)
            eks_clusters = _discover_eks(session, resolved_region, account_id=account_id, warnings=warnings)
    except NoCredentialsError:
        return {
            **empty,
            "status": "no_credentials",
            "warnings": ["AWS credentials not found. Configure via env vars, ~/.aws/credentials, IAM role, or SSO."],
        }

    permissions_used: list[str] = list(_AWS_BASELINE_PERMISSIONS)
    if include_s3:
        permissions_used.extend(_AWS_S3_PERMISSIONS)
    if include_ec2:
        permissions_used.extend(_AWS_EC2_PERMISSIONS)
    if include_iam:
        permissions_used.extend(_AWS_IAM_PERMISSIONS)
    if include_data:
        permissions_used.extend(_AWS_DATA_PERMISSIONS)
    if include_compute:
        permissions_used.extend(_AWS_COMPUTE_PERMISSIONS)

    discovery_scope: list[str] = []
    if account_id:
        discovery_scope.append(f"aws:account/{account_id}")
    if resolved_region:
        discovery_scope.append(f"aws:region/{resolved_region}")

    envelope = DiscoveryEnvelope(
        scan_mode=ScanMode.CLOUD_READ_ONLY,
        discovery_scope=tuple(discovery_scope),
        permissions_used=tuple(sorted(set(permissions_used))),
        redaction_status=RedactionStatus.CENTRAL_SANITIZER_APPLIED,
    )

    return {
        "provider": "aws",
        "status": "ok",
        "account_id": account_id,
        "region": resolved_region,
        "buckets": buckets,
        "instances": instances,
        "security_groups": security_groups,
        "roles": roles,
        "users": users,
        "rds_instances": rds_instances,
        "lambda_functions": lambda_functions,
        "dynamodb_tables": dynamodb_tables,
        "eks_clusters": eks_clusters,
        "warnings": warnings,
        "discovery_envelope": envelope.to_dict(),
    }


# ---------------------------------------------------------------------------
# S3 buckets (estate-wide ListBuckets)
# ---------------------------------------------------------------------------


def _discover_s3_buckets(session: Any, *, account_id: str | None, warnings: list[str]) -> list[dict[str, Any]]:
    """Enumerate every S3 bucket in the account (read-only).

    Public-access posture is read from the bucket's PublicAccessBlock and
    PolicyStatus — never from object contents. Buckets become ``DATA_STORE``
    nodes so DSPM and exposure overlays apply.
    """
    s3 = session.client("s3")
    buckets: list[dict[str, Any]] = []

    try:
        listed = s3.list_buckets().get("Buckets", [])
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list S3 buckets: {sanitize_discovery_warning(exc)}")
        return buckets

    for bucket in listed:
        name = str(bucket.get("Name", "") or "").strip()
        if not name:
            continue
        arn = f"arn:aws:s3:::{name}"
        location = _bucket_location(s3, name, warnings)
        publicly_accessible = _bucket_public(s3, name, warnings)
        tags = _bucket_tags(s3, name, warnings)
        buckets.append(
            {
                "name": name,
                "arn": arn,
                "location": location,
                "publicly_accessible": publicly_accessible,
                "tags": tags,
                "account_id": account_id or "",
                "created_at": _iso(bucket.get("CreationDate")),
            }
        )
    return buckets


def _bucket_location(s3: Any, name: str, warnings: list[str]) -> str:
    try:
        constraint = s3.get_bucket_location(Bucket=name).get("LocationConstraint")
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not read location for S3 bucket {name}: {sanitize_discovery_warning(exc)}")
        return ""
    # us-east-1 reports a null LocationConstraint by AWS convention.
    return str(constraint or "us-east-1")


def _bucket_public(s3: Any, name: str, warnings: list[str]) -> bool:
    """Best-effort public-access determination from posture APIs only.

    A bucket is treated as publicly accessible when its PolicyStatus is public
    OR its PublicAccessBlock does not fully block public access. Errors degrade
    to ``False`` (unknown) with a warning — never a guess that inflates risk.
    """
    try:
        status = s3.get_bucket_policy_status(Bucket=name).get("PolicyStatus", {})
        if bool(status.get("IsPublic")):
            return True
    except Exception as exc:  # noqa: BLE001
        # NoSuchBucketPolicy is normal (no policy attached) — only warn otherwise.
        if "NoSuchBucketPolicy" not in str(exc):
            warnings.append(f"Could not read policy status for S3 bucket {name}: {sanitize_discovery_warning(exc)}")

    try:
        block = s3.get_public_access_block(Bucket=name).get("PublicAccessBlockConfiguration", {})
    except Exception as exc:  # noqa: BLE001
        if "NoSuchPublicAccessBlock" not in str(exc):
            warnings.append(f"Could not read public-access block for S3 bucket {name}: {sanitize_discovery_warning(exc)}")
        return False
    fully_blocked = all(
        bool(block.get(key)) for key in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
    )
    return not fully_blocked


def _bucket_tags(s3: Any, name: str, warnings: list[str]) -> dict[str, str]:
    try:
        tag_set = s3.get_bucket_tagging(Bucket=name).get("TagSet", [])
    except Exception:  # noqa: BLE001
        # NoSuchTagSet is normal (no tags) — silently skip.
        return {}
    return {str(t.get("Key", "")): str(t.get("Value", "")) for t in tag_set if t.get("Key")}


# ---------------------------------------------------------------------------
# EC2 instances + security groups (estate-wide Describe*)
# ---------------------------------------------------------------------------


def _discover_ec2(
    session: Any,
    region: str,
    *,
    account_id: str | None,
    warnings: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Enumerate all EC2 instances and security groups in *region* (read-only).

    Unlike :func:`agent_bom.cloud.aws._discover_ec2_instances`, this is NOT
    tag-filtered — it captures the whole estate so resources with no CIS finding
    still enter the graph.
    """
    ec2 = session.client("ec2", region_name=region)
    instances: list[dict[str, Any]] = []
    security_groups: list[dict[str, Any]] = []

    try:
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    instances.append(_normalize_instance(instance, region=region, account_id=account_id))
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not describe EC2 instances: {sanitize_discovery_warning(exc)}")

    try:
        sg_paginator = ec2.get_paginator("describe_security_groups")
        for page in sg_paginator.paginate():
            for group in page.get("SecurityGroups", []):
                security_groups.append(_normalize_security_group(group, region=region, account_id=account_id))
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not describe EC2 security groups: {sanitize_discovery_warning(exc)}")

    return instances, security_groups


def _normalize_instance(instance: dict[str, Any], *, region: str, account_id: str | None) -> dict[str, Any]:
    instance_id = str(instance.get("InstanceId", "") or "")
    tags = {str(t.get("Key", "")): str(t.get("Value", "")) for t in instance.get("Tags", []) if t.get("Key")}
    sg_ids: list[str] = []
    for group in instance.get("SecurityGroups", []) or []:
        gid = group.get("GroupId") if isinstance(group, dict) else None
        if gid and gid not in sg_ids:
            sg_ids.append(str(gid))
    state = instance.get("State", {})
    return {
        "instance_id": instance_id,
        "name": tags.get("Name", instance_id),
        "instance_type": str(instance.get("InstanceType", "") or ""),
        "image_id": str(instance.get("ImageId", "") or ""),
        "state": str(state.get("Name", "") or "") if isinstance(state, dict) else "",
        "region": region,
        "account_id": account_id or "",
        "vpc_id": str(instance.get("VpcId", "") or ""),
        "subnet_id": str(instance.get("SubnetId", "") or ""),
        "public_ip": str(instance.get("PublicIpAddress", "") or ""),
        "private_ip": str(instance.get("PrivateIpAddress", "") or ""),
        "iam_instance_profile": str((instance.get("IamInstanceProfile") or {}).get("Arn", "") or ""),
        "security_group_ids": sg_ids,
        "tags": tags,
        "launched_at": _iso(instance.get("LaunchTime")),
    }


def _normalize_security_group(group: dict[str, Any], *, region: str, account_id: str | None) -> dict[str, Any]:
    group_id = str(group.get("GroupId", "") or "")
    exposure = _security_group_internet_exposure(group)
    return {
        "group_id": group_id,
        "name": str(group.get("GroupName", "") or group_id),
        "description": str(group.get("Description", "") or ""),
        "vpc_id": str(group.get("VpcId", "") or ""),
        "region": region,
        "account_id": account_id or "",
        "internet_exposed": bool(exposure),
        "network_exposure": exposure,
    }


def _security_group_internet_exposure(group: dict[str, Any]) -> list[dict[str, Any]]:
    """Return internet-facing ingress rules in the CNAPP overlay's shape.

    Each entry is ``{"scope": "internet", "from_port", "to_port", "protocol"}``
    so :func:`agent_bom.graph.cnapp_overlay.apply_cnapp_overlay` can attach
    structured exposure without keyword-matching free text.
    """
    exposure: list[dict[str, Any]] = []
    for rule in group.get("IpPermissions", []) or []:
        if not isinstance(rule, dict):
            continue
        open_to_world = any(
            str(r.get("CidrIp", "")) in _INTERNET_CIDRS for r in rule.get("IpRanges", []) or [] if isinstance(r, dict)
        ) or any(str(r.get("CidrIpv6", "")) in _INTERNET_IPV6 for r in rule.get("Ipv6Ranges", []) or [] if isinstance(r, dict))
        if not open_to_world:
            continue
        exposure.append(
            {
                "scope": "internet",
                "from_port": rule.get("FromPort"),
                "to_port": rule.get("ToPort"),
                "protocol": str(rule.get("IpProtocol", "") or "tcp"),
            }
        )
    return exposure


# ---------------------------------------------------------------------------
# IAM roles + users (estate-wide ListRoles / ListUsers)
# ---------------------------------------------------------------------------


def _discover_iam(
    session: Any,
    *,
    account_id: str | None,
    warnings: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Enumerate all IAM roles and users in the account (read-only).

    Each principal carries attached managed-policy metadata classified to a
    privilege level (admin/write/read) so the effective-permissions overlay can
    consume it without an additional fetch. Roles also carry their trust
    principals from the AssumeRole policy document.
    """
    iam = session.client("iam")
    roles: list[dict[str, Any]] = []
    users: list[dict[str, Any]] = []

    try:
        role_paginator = iam.get_paginator("list_roles")
        for page in role_paginator.paginate():
            for role in page.get("Roles", []):
                roles.append(_normalize_role(iam, role, account_id=account_id, warnings=warnings))
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list IAM roles: {sanitize_discovery_warning(exc)}")

    try:
        user_paginator = iam.get_paginator("list_users")
        for page in user_paginator.paginate():
            for user in page.get("Users", []):
                users.append(_normalize_user(iam, user, account_id=account_id, warnings=warnings))
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list IAM users: {sanitize_discovery_warning(exc)}")

    return roles, users


def _normalize_role(iam: Any, role: dict[str, Any], *, account_id: str | None, warnings: list[str]) -> dict[str, Any]:
    role_name = str(role.get("RoleName", "") or "")
    role_arn = str(role.get("Arn", "") or "")
    policies = _attached_policies(iam, "role", role_name, warnings=warnings)
    trust_principals = _extract_trust_principals(
        role.get("AssumeRolePolicyDocument"),
        account_id=account_id or _account_id_from_arn(role_arn),
    )
    return {
        "principal_type": "iam-role",
        "name": role_name,
        "arn": role_arn,
        "account_id": account_id or _account_id_from_arn(role_arn),
        "path": str(role.get("Path", "") or ""),
        "policies": policies,
        "trust_principals": trust_principals,
        "privilege_level": _highest_privilege(policies),
        "created_at": _iso(role.get("CreateDate")),
    }


def _normalize_user(iam: Any, user: dict[str, Any], *, account_id: str | None, warnings: list[str]) -> dict[str, Any]:
    user_name = str(user.get("UserName", "") or "")
    user_arn = str(user.get("Arn", "") or "")
    policies = _attached_policies(iam, "user", user_name, warnings=warnings)
    return {
        "principal_type": "user",
        "name": user_name,
        "arn": user_arn,
        "account_id": account_id or _account_id_from_arn(user_arn),
        "path": str(user.get("Path", "") or ""),
        "policies": policies,
        "privilege_level": _highest_privilege(policies),
        "created_at": _iso(user.get("CreateDate")),
    }


def _attached_policies(iam: Any, principal_kind: str, principal_name: str, *, warnings: list[str]) -> list[dict[str, Any]]:
    """Return attached managed policies with a classified privilege level."""
    if not principal_name:
        return []
    paginator_name = "list_attached_role_policies" if principal_kind == "role" else "list_attached_user_policies"
    kwarg = "RoleName" if principal_kind == "role" else "UserName"
    policies: list[dict[str, Any]] = []
    try:
        paginator = iam.get_paginator(paginator_name)
        for page in paginator.paginate(**{kwarg: principal_name}):
            for policy in page.get("AttachedPolicies", []):
                policy_arn = str(policy.get("PolicyArn", "") or "")
                policy_name = str(policy.get("PolicyName", "") or policy_arn)
                if not (policy_arn or policy_name):
                    continue
                policies.append(
                    {
                        "policy_id": policy_arn,
                        "policy_name": policy_name,
                        "attachment_type": "managed",
                        "privilege_level": _policy_privilege(iam, policy_arn, policy_name, warnings=warnings),
                        "source_field": f"ListAttached{principal_kind.capitalize()}Policies.AttachedPolicies",
                    }
                )
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"IAM policy enumeration skipped for {principal_kind} {principal_name}: {sanitize_discovery_warning(exc)}")
    return policies


# Canonical AWS-managed policy name → privilege level (no fetch needed). Mirrors
# the table in :mod:`agent_bom.cloud.aws`.
_AWS_MANAGED_PRIVILEGE: dict[str, str] = {
    "administratoraccess": "admin",
    "iamfullaccess": "admin",
    "poweruseraccess": "write",
    "readonlyaccess": "read",
    "viewonlyaccess": "read",
    "securityaudit": "read",
}


def _policy_privilege(iam: Any, policy_arn: str, policy_name: str, *, warnings: list[str]) -> str:
    """Classify an attached policy as admin / write / read / unknown.

    AWS-managed policies are classified by canonical name (no API call).
    Customer-managed policies are fetched and classified by their Allow actions.
    Degrades to ``"unknown"`` on any error — never blocks enumeration.
    """
    name_key = (policy_name or policy_arn).rsplit("/", 1)[-1].lower()
    if ":aws:policy/" in policy_arn and name_key in _AWS_MANAGED_PRIVILEGE:
        return _AWS_MANAGED_PRIVILEGE[name_key]
    if ":aws:policy/" in policy_arn:
        if "fullaccess" in name_key or "admin" in name_key:
            return "admin"
        if "readonly" in name_key or "viewonly" in name_key:
            return "read"
    try:
        version_id = iam.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
        document = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)["PolicyVersion"]["Document"]
        return _classify_policy_actions(_policy_actions_from_document(document))
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"IAM policy action lookup skipped for {policy_name or policy_arn}: {sanitize_discovery_warning(exc)}")
        return "unknown"


_PRIVILEGE_RANK = {"admin": 3, "write": 2, "read": 1, "unknown": 0}


def _highest_privilege(policies: list[dict[str, Any]]) -> str:
    """Return the most-privileged level across a principal's attached policies."""
    best = "unknown"
    for policy in policies:
        level = str(policy.get("privilege_level", "unknown"))
        if _PRIVILEGE_RANK.get(level, 0) > _PRIVILEGE_RANK.get(best, 0):
            best = level
    return best


def _discover_rds(session: Any, region: str, *, account_id: str | None, warnings: list[str]) -> list[dict[str, Any]]:
    """Enumerate RDS database instances (read-only). Become ``DATABASE`` data stores."""
    out: list[dict[str, Any]] = []
    try:
        client = session.client("rds", region_name=region)
        paginator = client.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page.get("DBInstances", []):
                name = str(db.get("DBInstanceIdentifier", "") or "")
                if not name:
                    continue
                out.append(
                    {
                        "name": name,
                        "arn": str(db.get("DBInstanceArn", "") or ""),
                        "engine": str(db.get("Engine", "") or ""),
                        "publicly_accessible": bool(db.get("PubliclyAccessible")),
                        "encrypted": bool(db.get("StorageEncrypted")),
                        "endpoint": str((db.get("Endpoint") or {}).get("Address", "") or ""),
                        "account_id": account_id or "",
                        "location": region,
                    }
                )
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list RDS instances: {sanitize_discovery_warning(exc)}")
    return out


def _discover_lambda(session: Any, region: str, *, account_id: str | None, warnings: list[str]) -> list[dict[str, Any]]:
    """Enumerate Lambda functions (read-only). Become ``SERVERLESS_FUNCTION`` resources."""
    out: list[dict[str, Any]] = []
    try:
        client = session.client("lambda", region_name=region)
        paginator = client.get_paginator("list_functions")
        for page in paginator.paginate():
            for fn in page.get("Functions", []):
                name = str(fn.get("FunctionName", "") or "")
                if not name:
                    continue
                vpc = fn.get("VpcConfig") or {}
                out.append(
                    {
                        "name": name,
                        "arn": str(fn.get("FunctionArn", "") or ""),
                        "runtime": str(fn.get("Runtime", "") or ""),
                        "role": str(fn.get("Role", "") or ""),
                        "in_vpc": bool(vpc.get("VpcId")),
                        "account_id": account_id or "",
                        "location": region,
                    }
                )
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list Lambda functions: {sanitize_discovery_warning(exc)}")
    return out


def _discover_dynamodb(session: Any, region: str, *, account_id: str | None, warnings: list[str]) -> list[dict[str, Any]]:
    """Enumerate DynamoDB tables (read-only). Become ``DATABASE`` data stores."""
    out: list[dict[str, Any]] = []
    try:
        client = session.client("dynamodb", region_name=region)
        paginator = client.get_paginator("list_tables")
        for page in paginator.paginate():
            for name in page.get("TableNames", []):
                if not name:
                    continue
                encrypted = False
                try:
                    desc = client.describe_table(TableName=name).get("Table", {})
                    encrypted = bool((desc.get("SSEDescription") or {}).get("Status") == "ENABLED")
                except Exception:  # noqa: BLE001 — table metadata is best-effort
                    desc = {}
                out.append(
                    {
                        "name": str(name),
                        "arn": str(desc.get("TableArn", "") or f"arn:aws:dynamodb:{region}:{account_id or ''}:table/{name}"),
                        "encrypted": encrypted,
                        "item_count": int(desc.get("ItemCount", 0) or 0),
                        "account_id": account_id or "",
                        "location": region,
                    }
                )
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list DynamoDB tables: {sanitize_discovery_warning(exc)}")
    return out


def _discover_eks(session: Any, region: str, *, account_id: str | None, warnings: list[str]) -> list[dict[str, Any]]:
    """Enumerate EKS clusters (read-only). Become ``CONTAINER_CLUSTER`` resources."""
    out: list[dict[str, Any]] = []
    try:
        client = session.client("eks", region_name=region)
        names: list[str] = []
        paginator = client.get_paginator("list_clusters")
        for page in paginator.paginate():
            names.extend(page.get("clusters", []))
        for name in names:
            try:
                c = client.describe_cluster(name=name).get("cluster", {})
            except Exception:  # noqa: BLE001
                c = {"name": name}
            endpoint_public = bool((c.get("resourcesVpcConfig") or {}).get("endpointPublicAccess"))
            out.append(
                {
                    "name": str(c.get("name", name) or name),
                    "arn": str(c.get("arn", "") or ""),
                    "version": str(c.get("version", "") or ""),
                    "endpoint_public": endpoint_public,
                    "internet_exposed": endpoint_public,
                    "account_id": account_id or "",
                    "location": region,
                }
            )
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list EKS clusters: {sanitize_discovery_warning(exc)}")
    return out


def _iso(value: Any) -> str:
    """Render a boto3 datetime (or string) as an ISO-8601 string, else ''."""
    if value in ("", None):
        return ""
    isoformat = getattr(value, "isoformat", None)
    if callable(isoformat):
        return str(isoformat())
    return str(value)


__all__ = [
    "INVENTORY_ENV_FLAG",
    "discover_inventory",
    "inventory_enabled",
]
