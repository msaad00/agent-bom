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
from concurrent.futures import ThreadPoolExecutor, as_completed
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
# requested by an operator. Symmetric with the other providers'
# AGENT_BOM_<PROVIDER>_INVENTORY gates (AZURE / GCP / SNOWFLAKE).
INVENTORY_ENV_FLAG = "AGENT_BOM_AWS_INVENTORY"
# Deprecated original name. Still honoured (with a one-time warning) so existing
# automation keeps working; remove in a future release.
INVENTORY_ENV_FLAG_LEGACY = "AGENT_BOM_CLOUD_INVENTORY"

# Multi-region fan-out gate. Default OFF — single-region remains the default so
# existing single-region automation is unchanged. Symmetric with Azure's
# AGENT_BOM_AZURE_ALL_SUBSCRIPTIONS tenant-wide fan-out gate.
ALL_REGIONS_ENV_FLAG = "AGENT_BOM_AWS_ALL_REGIONS"
# Optional explicit region list (comma-separated). When set, it overrides
# describe_regions enumeration so an operator can scope a multi-region scan.
REGIONS_ENV_VAR = "AGENT_BOM_AWS_REGIONS"
# Defensive cap so an account with a large enabled-region set can't fan out
# unbounded without an operator opting into a larger budget.
_MAX_REGIONS = int(os.environ.get("AGENT_BOM_AWS_MAX_REGIONS", "32") or "32")

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
    "iam:ListGroups",
    "iam:GetGroup",
    "iam:ListGroupsForUser",
    "iam:ListAttachedRolePolicies",
    "iam:ListAttachedUserPolicies",
    "iam:ListAttachedGroupPolicies",
    "iam:ListRolePolicies",
    "iam:ListUserPolicies",
    "iam:ListGroupPolicies",
    "iam:GetRolePolicy",
    "iam:GetUserPolicy",
    "iam:GetGroupPolicy",
    "iam:GetPolicy",
    "iam:GetPolicyVersion",
)
_AWS_DATA_PERMISSIONS: tuple[str, ...] = (
    "rds:DescribeDBInstances",
    "dynamodb:ListTables",
    "dynamodb:DescribeTable",
    "redshift:DescribeClusters",
)
_AWS_COMPUTE_PERMISSIONS: tuple[str, ...] = (
    "lambda:ListFunctions",
    "eks:ListClusters",
    "eks:DescribeCluster",
    "ecr:DescribeRepositories",
)
_AWS_NETWORK_PERMISSIONS: tuple[str, ...] = (
    "elasticloadbalancing:DescribeLoadBalancers",
    "ec2:DescribeVpcs",
    "cloudfront:ListDistributions",
    "sns:ListTopics",
    "sqs:ListQueues",
)
_AWS_SECURITY_PERMISSIONS: tuple[str, ...] = (
    "kms:ListKeys",
    "kms:DescribeKey",
    "kms:GetKeyRotationStatus",
    "secretsmanager:ListSecrets",
)
# Network-edge read-only actions: WAF, API Gateway, and the VPC plumbing
# (ENIs, NAT/internet gateways, subnets, route tables, network ACLs, VPC
# endpoints) plus IP enumeration (Elastic IPs). All inside SecurityAudit /
# ViewOnlyAccess; no new grant.
_AWS_EDGE_PERMISSIONS: tuple[str, ...] = (
    "wafv2:ListWebACLs",
    "wafv2:ListResourcesForWebACL",
    "wafv2:GetWebACLForResource",
    "apigateway:GET",
    "ec2:DescribeNetworkInterfaces",
    "ec2:DescribeNatGateways",
    "ec2:DescribeInternetGateways",
    "ec2:DescribeEgressOnlyInternetGateways",
    "ec2:DescribeVpcEndpoints",
    "ec2:DescribeSubnets",
    "ec2:DescribeRouteTables",
    "ec2:DescribeNetworkAcls",
    "ec2:DescribeAddresses",
)
_AWS_BASELINE_PERMISSIONS: tuple[str, ...] = ("sts:GetCallerIdentity",)

# Open-to-the-world CIDR / ipv6 ranges that mark a security-group ingress rule
# as internet-facing. The CNAPP overlay keys off this `network_exposure` shape.
_INTERNET_CIDRS = {"0.0.0.0/0"}
_INTERNET_IPV6 = {"::/0"}


# ---------------------------------------------------------------------------
# Cross-cloud degrade-don't-crash helpers
#
# These are the single source of truth for turning a failed discovery call into
# (a) a user-facing warning and (b) — when the failure is an access/permission
# error — a SPECIFIC, actionable warning plus a structured `missing_permissions`
# entry the product can render as "here is exactly what to grant".
#
# Azure and GCP inventory import these so all three providers degrade to the same
# bar: one failed discoverer -> one warning + (when access-denied) one
# missing_permissions entry -> `continue`, never an abort, never a silent empty
# result. Keep secrets out of every message by routing through
# sanitize_discovery_warning.
# ---------------------------------------------------------------------------

# Substrings that mark an exception as an access/permission failure, matched
# case-insensitively against the SDK error code / message. Covers AWS botocore
# (AccessDenied / UnauthorizedOperation / AccessDeniedException), Azure
# (AuthorizationFailed / Forbidden / 403), and GCP (PermissionDenied / 403).
_ACCESS_DENIED_MARKERS: tuple[str, ...] = (
    "accessdenied",
    "access denied",
    "unauthorizedoperation",
    "authorizationfailed",
    "permissiondenied",
    "permission denied",
    "forbidden",
    "notauthorized",
    "not authorized",
    "insufficient permission",
    "insufficient_permission",
    "iam.serviceaccounts.actas",
)


def _error_code(exc: BaseException) -> str:
    """Best-effort SDK error code extraction across botocore / Azure / GCP.

    - botocore ``ClientError`` exposes ``response["Error"]["Code"]``.
    - Azure ``HttpResponseError`` exposes ``.error.code`` and ``.status_code``.
    - GCP ``GoogleAPICallError`` exposes ``.code`` (a grpc status or int).

    Never raises — a provider that does not expose these attributes returns "".
    """
    code = ""
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        err = response.get("Error")
        if isinstance(err, dict):
            code = str(err.get("Code", "") or "")
    if not code:
        inner = getattr(exc, "error", None)
        inner_code = getattr(inner, "code", None)
        if inner_code is not None:
            code = str(inner_code)
    if not code:
        direct = getattr(exc, "code", None)
        if direct is not None:
            code = str(direct)
    return code


def _status_code(exc: BaseException) -> int | None:
    """Best-effort HTTP status extraction (Azure ``status_code`` / botocore 403)."""
    status = getattr(exc, "status_code", None)
    if isinstance(status, int):
        return status
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        meta = response.get("ResponseMetadata")
        if isinstance(meta, dict):
            http_status = meta.get("HTTPStatusCode")
            if isinstance(http_status, int):
                return http_status
    return None


def is_access_denied_error(exc: BaseException) -> bool:
    """Return whether *exc* is an access/permission failure (any cloud SDK).

    Detection is layered so it works without importing every provider SDK:
    a 401/403 HTTP status, a known error code, or an access-denied marker in the
    error code / message text. Type name is also checked so SDK-specific
    permission exceptions (e.g. GCP ``PermissionDenied`` / ``Forbidden``) are
    caught even when the message text is sparse.
    """
    status = _status_code(exc)
    if status in (401, 403):
        return True
    haystacks = [
        _error_code(exc).lower(),
        type(exc).__name__.lower(),
        str(exc).lower(),
    ]
    return any(marker in field for field in haystacks for marker in _ACCESS_DENIED_MARKERS)


def build_missing_permission(*, cloud: str, permission: str, resource_type: str) -> dict[str, str]:
    """Return one structured ``missing_permissions`` entry.

    The tuple ``(cloud, permission, resource_type)`` is the dedup key so the same
    grant surfaced from two regions/subscriptions collapses to a single row.
    """
    return {
        "cloud": cloud,
        "permission": permission,
        "resource_type": resource_type,
    }


def dedupe_missing_permissions(items: list[dict[str, str]]) -> list[dict[str, str]]:
    """Return a sorted, de-duplicated ``missing_permissions`` list.

    Deterministic + idempotent: same failures (in any order) always produce the
    same set of rows, sorted by (cloud, resource_type, permission), so report
    output is byte-stable across runs.
    """
    seen: set[tuple[str, str, str]] = set()
    unique: list[dict[str, str]] = []
    for item in items:
        key = (
            str(item.get("cloud", "") or ""),
            str(item.get("permission", "") or ""),
            str(item.get("resource_type", "") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append({"cloud": key[0], "permission": key[1], "resource_type": key[2]})
    unique.sort(key=lambda row: (row["cloud"], row["resource_type"], row["permission"]))
    return unique


def record_discovery_failure(
    *,
    exc: BaseException,
    resource_type: str,
    permission: str,
    cloud: str,
    warnings: list[str],
    missing: list[dict[str, str]] | None = None,
) -> None:
    """Translate a failed discovery call into operator-facing diagnostics.

    On an access/permission error this emits a SPECIFIC, actionable warning that
    names the missing permission and the resource type being skipped, and records
    a structured ``missing_permissions`` entry (when *missing* is provided). On
    any other failure it emits a generic, sanitized warning. Either way the
    skipped resource type ALWAYS produces a warning — never a silent empty
    result. Secrets are stripped via ``sanitize_discovery_warning``.
    """
    detail = sanitize_discovery_warning(exc)
    if is_access_denied_error(exc):
        warnings.append(
            f"Skipped {resource_type}: role lacks {permission} — add it to the read-only policy to cover this resource type. ({detail})"
        )
        if missing is not None:
            missing.append(build_missing_permission(cloud=cloud, permission=permission, resource_type=resource_type))
    else:
        warnings.append(f"Could not list {resource_type}: {detail}")


_legacy_flag_warned = False


def inventory_enabled() -> bool:
    """Return whether estate-wide AWS inventory enumeration is opted in.

    Default OFF. Operators enable it by setting ``AGENT_BOM_AWS_INVENTORY`` to a
    truthy value (``1`` / ``true`` / ``yes`` / ``on``). The original
    ``AGENT_BOM_CLOUD_INVENTORY`` name is still honoured for one release and
    emits a one-time deprecation warning.
    """
    global _legacy_flag_warned
    if os.environ.get(INVENTORY_ENV_FLAG, "").strip().lower() in _TRUTHY:
        return True
    if os.environ.get(INVENTORY_ENV_FLAG_LEGACY, "").strip().lower() in _TRUTHY:
        if not _legacy_flag_warned:
            logger.warning(
                "%s is deprecated; set %s instead.",
                INVENTORY_ENV_FLAG_LEGACY,
                INVENTORY_ENV_FLAG,
            )
            _legacy_flag_warned = True
        return True
    return False


def all_regions_enabled() -> bool:
    """Whether to fan a single scan across every enabled region in the account.

    Default OFF. Operators opt in by setting ``AGENT_BOM_AWS_ALL_REGIONS`` truthy
    (or by passing an explicit ``regions`` list to
    :func:`discover_inventory_all_regions`). Mirrors Azure's all-subscriptions
    gate so the single-region path stays the default.
    """
    return os.environ.get(ALL_REGIONS_ENV_FLAG, "").strip().lower() in _TRUTHY


def _empty_payload(*, region: str) -> dict[str, Any]:
    """Return a fully-populated empty inventory payload (every list key present).

    Shared by the single-region and multi-region paths so the payload shape the
    graph builder consumes is defined in exactly one place.
    """
    return {
        "provider": "aws",
        "status": "disabled",
        "account_id": None,
        "region": region,
        "buckets": [],
        "instances": [],
        "security_groups": [],
        "roles": [],
        "users": [],
        "groups": [],
        "rds_instances": [],
        "lambda_functions": [],
        "dynamodb_tables": [],
        "eks_clusters": [],
        "elb_load_balancers": [],
        "vpcs": [],
        "kms_keys": [],
        "secrets": [],
        "cloudfront_distributions": [],
        "ecr_repositories": [],
        "redshift_clusters": [],
        "messaging": [],
        "web_acls": [],
        "api_gateways": [],
        "network_interfaces": [],
        "subnets": [],
        "nat_gateways": [],
        "internet_gateways": [],
        "vpc_endpoints": [],
        "route_tables": [],
        "network_acls": [],
        "ip_addresses": [],
        "warnings": [],
        "missing_permissions": [],
        "discovery_envelope": None,
    }


# Region-scoped resource lists. These are concatenated across regions: each
# item already carries its own ``location``/``region`` so the merge is a simple
# extend, never a dedupe.
_REGION_SCOPED_KEYS: tuple[str, ...] = (
    "instances",
    "security_groups",
    "rds_instances",
    "lambda_functions",
    "dynamodb_tables",
    "eks_clusters",
    "elb_load_balancers",
    "vpcs",
    "kms_keys",
    "secrets",
    "ecr_repositories",
    "redshift_clusters",
    "messaging",
    "web_acls",
    "api_gateways",
    "network_interfaces",
    "subnets",
    "nat_gateways",
    "internet_gateways",
    "vpc_endpoints",
    "route_tables",
    "network_acls",
    "ip_addresses",
)


def _enabled_regions(session: Any, default_region: str, warnings: list[str]) -> list[str]:
    """Resolve the region list to fan out over (read-only ``describe_regions``).

    Resolution order: explicit ``AGENT_BOM_AWS_REGIONS`` env override (handled by
    the caller) → enumerate enabled regions via ``ec2:DescribeRegions`` → fall
    back to the single default region. Never raises: a failed enumeration
    degrades to the single default region plus a warning.
    """
    try:
        client = session.client("ec2", region_name=default_region)
        resp = client.describe_regions(AllRegions=False)
        regions = [
            str(r.get("RegionName", "") or "").strip() for r in resp.get("Regions", []) or [] if str(r.get("RegionName", "") or "").strip()
        ]
        if regions:
            return sorted(set(regions))
    except Exception as exc:  # noqa: BLE001 — region enumeration must never sink a scan
        warnings.append(f"Could not enumerate enabled AWS regions; scanning {default_region} only: {sanitize_discovery_warning(exc)}")
    return [default_region]


def _resolve_region_list(
    session: Any,
    default_region: str,
    *,
    regions: list[str] | None,
    warnings: list[str],
) -> list[str]:
    """Return the (capped, deduped) ordered region list for a multi-region scan."""
    if regions:
        candidates = [str(r).strip() for r in regions if str(r).strip()]
    else:
        env_regions = os.environ.get(REGIONS_ENV_VAR, "").strip()
        if env_regions:
            candidates = [r.strip() for r in env_regions.split(",") if r.strip()]
        else:
            candidates = _enabled_regions(session, default_region, warnings)

    ordered: list[str] = []
    for region in candidates:
        if region not in ordered:
            ordered.append(region)
    if not ordered:
        ordered = [default_region]
    if len(ordered) > _MAX_REGIONS:
        warnings.append(f"Multi-region scan capped at {_MAX_REGIONS} of {len(ordered)} regions (set AGENT_BOM_AWS_MAX_REGIONS to raise).")
        ordered = ordered[:_MAX_REGIONS]
    return ordered


def discover_inventory_all_regions(
    profile: str | None = None,
    *,
    regions: list[str] | None = None,
    include_s3: bool = True,
    include_ec2: bool = True,
    include_iam: bool = True,
    include_data: bool = True,
    include_compute: bool = True,
    include_network: bool = True,
    force: bool = False,
) -> dict[str, Any]:
    """Estate-wide multi-region AWS inventory: fan out per region, merge once.

    The AWS counterpart of Azure's all-subscriptions fan-out. Region-scoped
    resources (EC2, RDS, DynamoDB, Lambda, EKS, ELB, VPC, KMS, Secrets, ECR,
    Redshift, SNS/SQS) are discovered concurrently across the resolved region set
    and **concatenated** (each item already carries its own ``location``).

    Global resources (S3 buckets, IAM roles/users, CloudFront) are region-
    agnostic, so they are enumerated **once** (against the default region) and
    **deduped** by ARN/id — a multi-region scan never inflates the identity or
    DSPM graph.

    Returns the SAME payload shape as :func:`discover_inventory` so the graph
    builder consumes it unchanged, with ``region`` set to ``"multi:<r1,r2,...>"``.

    Crash-safe: a failing region degrades to a warning and contributes nothing,
    never sinking the whole scan. boto3 absence / missing credentials degrade
    exactly as the single-region path does.
    """
    if not force and not inventory_enabled():
        return {**_empty_payload(region=""), "status": "disabled"}

    try:
        import boto3  # noqa: F401
    except ImportError:
        return {
            **_empty_payload(region=""),
            "status": "boto3_missing",
            "warnings": ["boto3 is required for AWS inventory. Install with: pip install 'agent-bom[aws]'"],
        }

    session_kwargs: dict[str, Any] = {}
    if profile:
        session_kwargs["profile_name"] = profile
    try:
        session = boto3.Session(**session_kwargs)
    except Exception as exc:  # noqa: BLE001 — boto profile/config errors must not crash a scan
        return {**_empty_payload(region=""), "status": "no_credentials", "warnings": [sanitize_discovery_warning(exc)]}

    default_region = session.region_name or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")

    warnings: list[str] = []
    region_list = _resolve_region_list(session, default_region, regions=regions, warnings=warnings)

    # Global (region-agnostic) resources are enumerated ONCE against the default
    # region: S3 buckets + IAM principals. CloudFront is global too but is
    # enumerated directly below so the global pass doesn't pull regional
    # ELB/VPC/messaging (those come from the per-region fan-out). Suppressing
    # ec2/data/compute/network here is what prevents the identity/DSPM graph from
    # inflating across regions.
    global_region = region_list[0] if default_region not in region_list else default_region
    global_payload = discover_inventory(
        region=global_region,
        profile=profile,
        include_s3=include_s3,
        include_ec2=False,
        include_iam=include_iam,
        include_data=False,
        include_compute=False,
        include_network=False,
        force=True,
    )
    if global_payload.get("status") in {"boto3_missing", "no_credentials"}:
        return {**global_payload, "region": global_region}
    warnings.extend(global_payload.get("warnings", []))

    missing: list[dict[str, str]] = list(global_payload.get("missing_permissions", []) or [])

    account_id = global_payload.get("account_id")

    merged: dict[str, list[dict[str, Any]]] = {key: [] for key in _REGION_SCOPED_KEYS}

    def _scan(region: str) -> dict[str, Any]:
        return discover_inventory(
            region=region,
            profile=profile,
            include_s3=False,
            include_ec2=include_ec2,
            include_iam=False,
            include_data=include_data,
            include_compute=include_compute,
            include_network=include_network,
            force=True,
        )

    region_payloads: dict[str, dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=min(8, max(1, len(region_list)))) as executor:
        future_to_region = {executor.submit(_scan, region): region for region in region_list}
        for future in as_completed(future_to_region):
            region = future_to_region[future]
            try:
                region_payloads[region] = future.result()
            except Exception as exc:  # noqa: BLE001 — one bad region must not sink the scan
                warnings.append(f"Region {region} skipped: {sanitize_discovery_warning(exc)}")

    # CloudFront is global but is enumerated by each per-region scan (it rides on
    # include_network); collect across regions, then dedupe by name below.
    cloudfront_seen: list[dict[str, Any]] = []
    for region in region_list:
        payload = region_payloads.get(region)
        if payload is None:
            continue
        for warning in payload.get("warnings", []):
            warnings.append(f"[{region}] {warning}")
        missing.extend(payload.get("missing_permissions", []) or [])
        if payload.get("status") != "ok":
            # A degraded region surfaces its warnings (above) but contributes no
            # resources — it must never abort the merge.
            continue
        for key in _REGION_SCOPED_KEYS:
            merged[key].extend(payload.get(key, []) or [])
        cloudfront_seen.extend(payload.get("cloudfront_distributions", []) or [])

    def _dedupe(items: list[dict[str, Any]], field: str) -> list[dict[str, Any]]:
        seen: set[str] = set()
        unique: list[dict[str, Any]] = []
        for item in items:
            ident = str(item.get(field, "") or "") or str(item.get("name", "") or "")
            if ident and ident in seen:
                continue
            if ident:
                seen.add(ident)
            unique.append(item)
        return unique

    deduped_globals: dict[str, list[dict[str, Any]]] = {
        "buckets": _dedupe(global_payload.get("buckets", []) or [], "arn"),
        "roles": _dedupe(global_payload.get("roles", []) or [], "arn"),
        "users": _dedupe(global_payload.get("users", []) or [], "arn"),
        "groups": _dedupe(global_payload.get("groups", []) or [], "arn"),
        "cloudfront_distributions": _dedupe(cloudfront_seen, "name"),
    }

    region_label = f"multi:{','.join(region_list)}"
    discovery_scope: list[str] = []
    if account_id:
        discovery_scope.append(f"aws:account/{account_id}")
    for region in region_list:
        discovery_scope.append(f"aws:region/{region}")

    permissions_used: list[str] = list(_AWS_BASELINE_PERMISSIONS) + ["ec2:DescribeRegions"]
    if include_s3:
        permissions_used.extend(_AWS_S3_PERMISSIONS)
    if include_ec2:
        permissions_used.extend(_AWS_EC2_PERMISSIONS)
    if include_iam:
        permissions_used.extend(_AWS_IAM_PERMISSIONS)
    if include_data:
        permissions_used.extend(_AWS_DATA_PERMISSIONS)
        permissions_used.extend(_AWS_SECURITY_PERMISSIONS)
    if include_compute:
        permissions_used.extend(_AWS_COMPUTE_PERMISSIONS)
    if include_network:
        permissions_used.extend(_AWS_NETWORK_PERMISSIONS)
        permissions_used.extend(_AWS_EDGE_PERMISSIONS)

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
        "region": region_label,
        "regions": region_list,
        "buckets": deduped_globals.get("buckets", []),
        "instances": merged["instances"],
        "security_groups": merged["security_groups"],
        "roles": deduped_globals.get("roles", []),
        "users": deduped_globals.get("users", []),
        "groups": deduped_globals.get("groups", []),
        "rds_instances": merged["rds_instances"],
        "lambda_functions": merged["lambda_functions"],
        "dynamodb_tables": merged["dynamodb_tables"],
        "eks_clusters": merged["eks_clusters"],
        "elb_load_balancers": merged["elb_load_balancers"],
        "vpcs": merged["vpcs"],
        "kms_keys": merged["kms_keys"],
        "secrets": merged["secrets"],
        "cloudfront_distributions": deduped_globals.get("cloudfront_distributions", []),
        "ecr_repositories": merged["ecr_repositories"],
        "redshift_clusters": merged["redshift_clusters"],
        "messaging": merged["messaging"],
        "web_acls": merged["web_acls"],
        "api_gateways": merged["api_gateways"],
        "network_interfaces": merged["network_interfaces"],
        "subnets": merged["subnets"],
        "nat_gateways": merged["nat_gateways"],
        "internet_gateways": merged["internet_gateways"],
        "vpc_endpoints": merged["vpc_endpoints"],
        "route_tables": merged["route_tables"],
        "network_acls": merged["network_acls"],
        "ip_addresses": merged["ip_addresses"],
        "warnings": warnings,
        "missing_permissions": dedupe_missing_permissions(missing),
        "discovery_envelope": envelope.to_dict(),
    }


def discover_inventory(
    region: str | None = None,
    profile: str | None = None,
    *,
    include_s3: bool = True,
    include_ec2: bool = True,
    include_iam: bool = True,
    include_data: bool = True,
    include_compute: bool = True,
    include_network: bool = True,
    force: bool = False,
    session: Any = None,
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

    When ``session`` is supplied (e.g. the read-only session the credential
    broker assumes from a stored connection), it is used as-is and the
    ``region`` / ``profile`` arguments are ignored — the same read-only code path
    runs against the brokered credentials instead of the local default chain.

    Never raises: boto3 absence, missing credentials, and per-service access
    denials all degrade to an empty (or partial) inventory plus warnings.
    """
    empty = _empty_payload(region=region or "")

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

    if session is None:
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
    missing: list[dict[str, str]] = []
    buckets: list[dict[str, Any]] = []
    instances: list[dict[str, Any]] = []
    security_groups: list[dict[str, Any]] = []
    roles: list[dict[str, Any]] = []
    users: list[dict[str, Any]] = []
    groups: list[dict[str, Any]] = []
    rds_instances: list[dict[str, Any]] = []
    lambda_functions: list[dict[str, Any]] = []
    dynamodb_tables: list[dict[str, Any]] = []
    eks_clusters: list[dict[str, Any]] = []
    elb_load_balancers: list[dict[str, Any]] = []
    vpcs: list[dict[str, Any]] = []
    kms_keys: list[dict[str, Any]] = []
    secrets: list[dict[str, Any]] = []
    cloudfront_distributions: list[dict[str, Any]] = []
    ecr_repositories: list[dict[str, Any]] = []
    redshift_clusters: list[dict[str, Any]] = []
    messaging: list[dict[str, Any]] = []
    web_acls: list[dict[str, Any]] = []
    api_gateways: list[dict[str, Any]] = []
    network_interfaces: list[dict[str, Any]] = []
    subnets: list[dict[str, Any]] = []
    nat_gateways: list[dict[str, Any]] = []
    internet_gateways: list[dict[str, Any]] = []
    vpc_endpoints: list[dict[str, Any]] = []
    route_tables: list[dict[str, Any]] = []
    network_acls: list[dict[str, Any]] = []
    ip_addresses: list[dict[str, Any]] = []

    try:
        if include_s3:
            buckets = _discover_s3_buckets(session, account_id=account_id, warnings=warnings, missing=missing)
        if include_ec2:
            instances, security_groups = _discover_ec2(session, resolved_region, account_id=account_id, warnings=warnings, missing=missing)
        if include_iam:
            roles, users, groups = _discover_iam(session, account_id=account_id, warnings=warnings, missing=missing)
        if include_data:
            rds_instances = _discover_rds(session, resolved_region, account_id=account_id, warnings=warnings, missing=missing)
            dynamodb_tables = _discover_dynamodb(session, resolved_region, account_id=account_id, warnings=warnings, missing=missing)
            kms_keys = _discover_kms(session, resolved_region, account_id=account_id, warnings=warnings, missing=missing)
            secrets = _discover_secrets(session, resolved_region, account_id=account_id, warnings=warnings, missing=missing)
            redshift_clusters = _discover_redshift(session, resolved_region, account_id=account_id, warnings=warnings, missing=missing)
        if include_compute:
            lambda_functions = _discover_lambda(session, resolved_region, account_id=account_id, warnings=warnings, missing=missing)
            eks_clusters = _discover_eks(session, resolved_region, account_id=account_id, warnings=warnings, missing=missing)
            ecr_repositories = _discover_ecr(session, resolved_region, account_id=account_id, warnings=warnings, missing=missing)
        if include_network:
            elb_load_balancers = _discover_elb(session, resolved_region, account_id=account_id, warnings=warnings, missing=missing)
            vpcs = _discover_vpcs(session, resolved_region, account_id=account_id, warnings=warnings, missing=missing)
            cloudfront_distributions = _discover_cloudfront(session, account_id=account_id, warnings=warnings, missing=missing)
            messaging = _discover_messaging(session, resolved_region, account_id=account_id, warnings=warnings, missing=missing)
            web_acls = _discover_waf(session, resolved_region, account_id=account_id, warnings=warnings, missing=missing)
            api_gateways = _discover_api_gateways(session, resolved_region, account_id=account_id, warnings=warnings, missing=missing)
            edge = _discover_network_edge(session, resolved_region, account_id=account_id, warnings=warnings, missing=missing)
            network_interfaces = edge["network_interfaces"]
            subnets = edge["subnets"]
            nat_gateways = edge["nat_gateways"]
            internet_gateways = edge["internet_gateways"]
            vpc_endpoints = edge["vpc_endpoints"]
            route_tables = edge["route_tables"]
            network_acls = edge["network_acls"]
            ip_addresses = _discover_ip_addresses(
                session, resolved_region, account_id=account_id, network_interfaces=network_interfaces, warnings=warnings, missing=missing
            )
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
    if include_data:
        permissions_used.extend(_AWS_SECURITY_PERMISSIONS)
    if include_network:
        permissions_used.extend(_AWS_NETWORK_PERMISSIONS)
        permissions_used.extend(_AWS_EDGE_PERMISSIONS)

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
        "groups": groups,
        "rds_instances": rds_instances,
        "lambda_functions": lambda_functions,
        "dynamodb_tables": dynamodb_tables,
        "eks_clusters": eks_clusters,
        "elb_load_balancers": elb_load_balancers,
        "vpcs": vpcs,
        "kms_keys": kms_keys,
        "secrets": secrets,
        "cloudfront_distributions": cloudfront_distributions,
        "ecr_repositories": ecr_repositories,
        "redshift_clusters": redshift_clusters,
        "messaging": messaging,
        "web_acls": web_acls,
        "api_gateways": api_gateways,
        "network_interfaces": network_interfaces,
        "subnets": subnets,
        "nat_gateways": nat_gateways,
        "internet_gateways": internet_gateways,
        "vpc_endpoints": vpc_endpoints,
        "route_tables": route_tables,
        "network_acls": network_acls,
        "ip_addresses": ip_addresses,
        "warnings": warnings,
        "missing_permissions": dedupe_missing_permissions(missing),
        "discovery_envelope": envelope.to_dict(),
    }


# ---------------------------------------------------------------------------
# S3 buckets (estate-wide ListBuckets)
# ---------------------------------------------------------------------------


def _discover_s3_buckets(
    session: Any, *, account_id: str | None, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate every S3 bucket in the account (read-only).

    Public-access posture is read from the bucket's PublicAccessBlock and
    PolicyStatus — never from object contents. Buckets become ``DATA_STORE``
    nodes so DSPM and exposure overlays apply.
    """
    s3 = session.client("s3")
    buckets: list[dict[str, Any]] = []

    try:
        listed = s3.list_buckets().get("Buckets", [])
    except Exception as exc:  # noqa: BLE001 — one failed S3 list must not sink the scan
        record_discovery_failure(
            exc=exc, resource_type="S3 buckets", permission="s3:ListAllMyBuckets", cloud="aws", warnings=warnings, missing=missing
        )
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
    missing: list[dict[str, str]] | None = None,
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
    except Exception as exc:  # noqa: BLE001 — one failed EC2 describe must not sink the scan
        record_discovery_failure(
            exc=exc, resource_type="EC2 instances", permission="ec2:DescribeInstances", cloud="aws", warnings=warnings, missing=missing
        )

    try:
        sg_paginator = ec2.get_paginator("describe_security_groups")
        for page in sg_paginator.paginate():
            for group in page.get("SecurityGroups", []):
                security_groups.append(_normalize_security_group(group, region=region, account_id=account_id))
    except Exception as exc:  # noqa: BLE001 — one failed SG describe must not sink the scan
        record_discovery_failure(
            exc=exc,
            resource_type="EC2 security groups",
            permission="ec2:DescribeSecurityGroups",
            cloud="aws",
            warnings=warnings,
            missing=missing,
        )

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
    missing: list[dict[str, str]] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Enumerate all IAM roles, users, and groups in the account (read-only).

    Each principal carries attached managed-policy metadata classified to a
    privilege level (admin/write/read) so the effective-permissions overlay can
    consume it without an additional fetch. Roles also carry their trust
    principals from the AssumeRole policy document. Groups carry their attached
    and inline policies plus their member users; each user carries the names of
    the groups it belongs to so the graph can attribute group-granted access to
    the member — group-based access is one of the most common privilege paths.
    """
    iam = session.client("iam")
    roles: list[dict[str, Any]] = []
    users: list[dict[str, Any]] = []
    groups: list[dict[str, Any]] = []

    try:
        role_paginator = iam.get_paginator("list_roles")
        for page in role_paginator.paginate():
            for role in page.get("Roles", []):
                roles.append(_normalize_role(iam, role, account_id=account_id, warnings=warnings))
    except Exception as exc:  # noqa: BLE001 — one failed IAM list must not sink the scan
        record_discovery_failure(
            exc=exc, resource_type="IAM roles", permission="iam:ListRoles", cloud="aws", warnings=warnings, missing=missing
        )

    try:
        group_paginator = iam.get_paginator("list_groups")
        for page in group_paginator.paginate():
            for group in page.get("Groups", []):
                groups.append(_normalize_group(iam, group, account_id=account_id, warnings=warnings))
    except Exception as exc:  # noqa: BLE001 — one failed IAM list must not sink the scan
        record_discovery_failure(
            exc=exc, resource_type="IAM groups", permission="iam:ListGroups", cloud="aws", warnings=warnings, missing=missing
        )

    try:
        user_paginator = iam.get_paginator("list_users")
        for page in user_paginator.paginate():
            for user in page.get("Users", []):
                users.append(_normalize_user(iam, user, account_id=account_id, warnings=warnings))
    except Exception as exc:  # noqa: BLE001 — one failed IAM list must not sink the scan
        record_discovery_failure(
            exc=exc, resource_type="IAM users", permission="iam:ListUsers", cloud="aws", warnings=warnings, missing=missing
        )

    return roles, users, groups


def _normalize_role(iam: Any, role: dict[str, Any], *, account_id: str | None, warnings: list[str]) -> dict[str, Any]:
    role_name = str(role.get("RoleName", "") or "")
    role_arn = str(role.get("Arn", "") or "")
    policies = _attached_policies(iam, "role", role_name, warnings=warnings)
    policies += _inline_policies(iam, "role", role_name, warnings=warnings)
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
    policies += _inline_policies(iam, "user", user_name, warnings=warnings)
    return {
        "principal_type": "user",
        "name": user_name,
        "arn": user_arn,
        "account_id": account_id or _account_id_from_arn(user_arn),
        "path": str(user.get("Path", "") or ""),
        "policies": policies,
        "groups": _groups_for_user(iam, user_name, warnings=warnings),
        "privilege_level": _highest_privilege(policies),
        "created_at": _iso(user.get("CreateDate")),
    }


def _normalize_group(iam: Any, group: dict[str, Any], *, account_id: str | None, warnings: list[str]) -> dict[str, Any]:
    """Normalize one IAM group with its attached + inline policies and members.

    A group's attached/inline policies grant every member their access, so the
    group carries the same policy shape as a user/role (classified to a privilege
    level) plus the list of member users. The graph builder turns the group into
    a ``GROUP`` node, attaches its policies, and wires ``MEMBER_OF`` edges from
    each member so the effective-permissions overlay attributes group-granted
    access to the member.
    """
    group_name = str(group.get("GroupName", "") or "")
    group_arn = str(group.get("Arn", "") or "")
    policies = _attached_policies(iam, "group", group_name, warnings=warnings)
    policies += _inline_policies(iam, "group", group_name, warnings=warnings)
    return {
        "principal_type": "group",
        "name": group_name,
        "arn": group_arn,
        "account_id": account_id or _account_id_from_arn(group_arn),
        "path": str(group.get("Path", "") or ""),
        "policies": policies,
        "members": _group_members(iam, group_name, warnings=warnings),
        "privilege_level": _highest_privilege(policies),
        "created_at": _iso(group.get("CreateDate")),
    }


def _group_members(iam: Any, group_name: str, *, warnings: list[str]) -> list[dict[str, str]]:
    """Return the member users of an IAM group (read-only ``GetGroup``).

    Each member is recorded by ARN + name + ``user`` type so the builder can wire
    a ``MEMBER_OF`` edge to the existing user node. Degrades to an empty list plus
    a warning on error; never blocks enumeration.
    """
    if not group_name:
        return []
    members: list[dict[str, str]] = []
    try:
        paginator = iam.get_paginator("get_group")
        for page in paginator.paginate(GroupName=group_name):
            for user in page.get("Users", []) or []:
                arn = str(user.get("Arn", "") or "")
                name = str(user.get("UserName", "") or "")
                ident = arn or name
                if ident:
                    members.append({"id": ident, "name": name or ident, "type": "user"})
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"IAM group membership enumeration skipped for {group_name}: {sanitize_discovery_warning(exc)}")
    return members


def _groups_for_user(iam: Any, user_name: str, *, warnings: list[str]) -> list[str]:
    """Return the names of the IAM groups a user belongs to (read-only).

    Group membership is the link that carries a group's policies to the member,
    so capturing it lets the graph attribute group-granted access to each user.
    Degrades to an empty list plus a warning on error; never blocks enumeration.
    """
    if not user_name:
        return []
    names: list[str] = []
    try:
        paginator = iam.get_paginator("list_groups_for_user")
        for page in paginator.paginate(UserName=user_name):
            for group in page.get("Groups", []) or []:
                name = str(group.get("GroupName", "") or "")
                if name:
                    names.append(name)
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"IAM group-membership lookup skipped for user {user_name}: {sanitize_discovery_warning(exc)}")
    return names


def _attached_policies(iam: Any, principal_kind: str, principal_name: str, *, warnings: list[str]) -> list[dict[str, Any]]:
    """Return attached managed policies with a classified privilege level."""
    if not principal_name:
        return []
    paginator_name = f"list_attached_{principal_kind}_policies"
    kwarg = {"role": "RoleName", "user": "UserName", "group": "GroupName"}[principal_kind]
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


def _inline_policies(iam: Any, principal_kind: str, principal_name: str, *, warnings: list[str]) -> list[dict[str, Any]]:
    """Return inline policies with a classified privilege level (read-only).

    Inline policies attach directly to a single principal and never appear in
    ``list_attached_*`` — yet they can silently grant admin, so a posture scan
    must read them. Lists the inline names, fetches each document, and classifies
    by Allow actions. Degrades to a warning on error; never blocks enumeration.
    """
    if not principal_name:
        return []
    list_op = f"list_{principal_kind}_policies"
    kwarg = {"role": "RoleName", "user": "UserName", "group": "GroupName"}[principal_kind]
    policies: list[dict[str, Any]] = []
    try:
        get_doc = getattr(iam, {"role": "get_role_policy", "user": "get_user_policy", "group": "get_group_policy"}[principal_kind])
        paginator = iam.get_paginator(list_op)
        for page in paginator.paginate(**{kwarg: principal_name}):
            for name in page.get("PolicyNames", []):
                if not name:
                    continue
                privilege = "unknown"
                try:
                    document = get_doc(**{kwarg: principal_name, "PolicyName": name}).get("PolicyDocument")
                    privilege = _classify_policy_actions(_policy_actions_from_document(document))
                except Exception as exc:  # noqa: BLE001
                    short = sanitize_discovery_warning(exc)
                    warnings.append(f"IAM inline policy doc skipped for {principal_kind} {principal_name}/{name}: {short}")
                policies.append(
                    {
                        "policy_id": f"{principal_name}/{name}",
                        "policy_name": str(name),
                        "attachment_type": "inline",
                        "privilege_level": privilege,
                        "source_field": f"List{principal_kind.capitalize()}Policies.PolicyNames",
                    }
                )
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"IAM inline policy enumeration skipped for {principal_kind} {principal_name}: {sanitize_discovery_warning(exc)}")
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


def _discover_rds(
    session: Any, region: str, *, account_id: str | None, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
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
    except Exception as exc:  # noqa: BLE001 — one failed RDS list must not sink the scan
        record_discovery_failure(
            exc=exc, resource_type="RDS instances", permission="rds:DescribeDBInstances", cloud="aws", warnings=warnings, missing=missing
        )
    return out


def _discover_lambda(
    session: Any, region: str, *, account_id: str | None, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
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
    except Exception as exc:  # noqa: BLE001 — one failed Lambda list must not sink the scan
        record_discovery_failure(
            exc=exc, resource_type="Lambda functions", permission="lambda:ListFunctions", cloud="aws", warnings=warnings, missing=missing
        )
    return out


def _discover_dynamodb(
    session: Any, region: str, *, account_id: str | None, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
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
    except Exception as exc:  # noqa: BLE001 — one failed DynamoDB list must not sink the scan
        record_discovery_failure(
            exc=exc, resource_type="DynamoDB tables", permission="dynamodb:ListTables", cloud="aws", warnings=warnings, missing=missing
        )
    return out


def _discover_eks(
    session: Any, region: str, *, account_id: str | None, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
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
    except Exception as exc:  # noqa: BLE001 — one failed EKS list must not sink the scan
        record_discovery_failure(
            exc=exc, resource_type="EKS clusters", permission="eks:ListClusters", cloud="aws", warnings=warnings, missing=missing
        )
    return out


def _discover_elb(
    session: Any, region: str, *, account_id: str | None, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate ALB/NLB load balancers (read-only). Internet-facing scheme = exposed."""
    out: list[dict[str, Any]] = []
    try:
        client = session.client("elbv2", region_name=region)
        paginator = client.get_paginator("describe_load_balancers")
        for page in paginator.paginate():
            for lb in page.get("LoadBalancers", []):
                name = str(lb.get("LoadBalancerName", "") or "")
                if not name:
                    continue
                out.append(
                    {
                        "name": name,
                        "arn": str(lb.get("LoadBalancerArn", "") or ""),
                        "scheme": str(lb.get("Scheme", "") or ""),
                        "lb_type": str(lb.get("Type", "") or ""),
                        "internet_exposed": str(lb.get("Scheme", "")).lower() == "internet-facing",
                        "dns_name": str(lb.get("DNSName", "") or ""),
                        "vpc_id": str(lb.get("VpcId", "") or ""),
                        "account_id": account_id or "",
                        "location": region,
                    }
                )
    except Exception as exc:  # noqa: BLE001 — one failed ELB list must not sink the scan
        record_discovery_failure(
            exc=exc,
            resource_type="load balancers",
            permission="elasticloadbalancing:DescribeLoadBalancers",
            cloud="aws",
            warnings=warnings,
            missing=missing,
        )
    return out


def _discover_vpcs(
    session: Any, region: str, *, account_id: str | None, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate VPCs (read-only). Become ``CLOUD_RESOURCE`` network nodes."""
    out: list[dict[str, Any]] = []
    try:
        client = session.client("ec2", region_name=region)
        for vpc in client.describe_vpcs().get("Vpcs", []):
            vpc_id = str(vpc.get("VpcId", "") or "")
            if not vpc_id:
                continue
            tags = {str(t.get("Key", "")): str(t.get("Value", "")) for t in vpc.get("Tags", []) if t.get("Key")}
            out.append(
                {
                    # vpc_id is the stable node identifier; the Name tag is display-only.
                    "name": vpc_id,
                    "display_name": tags.get("Name") or vpc_id,
                    "vpc_id": vpc_id,
                    "cidr": str(vpc.get("CidrBlock", "") or ""),
                    "is_default": bool(vpc.get("IsDefault")),
                    "tags": tags,
                    "account_id": account_id or "",
                    "location": region,
                }
            )
    except Exception as exc:  # noqa: BLE001 — one failed VPC list must not sink the scan
        record_discovery_failure(
            exc=exc, resource_type="VPCs", permission="ec2:DescribeVpcs", cloud="aws", warnings=warnings, missing=missing
        )
    return out


def _discover_kms(
    session: Any, region: str, *, account_id: str | None, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate customer-managed KMS keys (read-only). Metadata only, never key material."""
    out: list[dict[str, Any]] = []
    try:
        client = session.client("kms", region_name=region)
        paginator = client.get_paginator("list_keys")
        for page in paginator.paginate():
            for key in page.get("Keys", []):
                key_id = str(key.get("KeyId", "") or "")
                if not key_id:
                    continue
                manager, enabled, rotation = "", True, None
                try:
                    meta = client.describe_key(KeyId=key_id).get("KeyMetadata", {})
                    manager = str(meta.get("KeyManager", "") or "")
                    enabled = bool(meta.get("Enabled", True))
                    if manager == "AWS":  # skip AWS-managed keys — not customer's responsibility
                        continue
                    try:
                        rotation = bool(client.get_key_rotation_status(KeyId=key_id).get("KeyRotationEnabled"))
                    except Exception:  # noqa: BLE001
                        rotation = None
                except Exception:  # noqa: BLE001
                    meta = {}
                out.append(
                    {
                        "name": key_id,
                        "arn": str(key.get("KeyArn", "") or ""),
                        "enabled": enabled,
                        "rotation_enabled": rotation,
                        "account_id": account_id or "",
                        "location": region,
                    }
                )
    except Exception as exc:  # noqa: BLE001 — one failed KMS list must not sink the scan
        record_discovery_failure(
            exc=exc, resource_type="KMS keys", permission="kms:ListKeys", cloud="aws", warnings=warnings, missing=missing
        )
    return out


def _discover_secrets(
    session: Any, region: str, *, account_id: str | None, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate Secrets Manager secrets (read-only). Metadata only — never secret values."""
    out: list[dict[str, Any]] = []
    try:
        client = session.client("secretsmanager", region_name=region)
        paginator = client.get_paginator("list_secrets")
        for page in paginator.paginate():
            for sec in page.get("SecretList", []):
                name = str(sec.get("Name", "") or "")
                if not name:
                    continue
                out.append(
                    {
                        "name": name,
                        "arn": str(sec.get("ARN", "") or ""),
                        "rotation_enabled": bool(sec.get("RotationEnabled")),
                        "last_changed": _iso(sec.get("LastChangedDate")),
                        "account_id": account_id or "",
                        "location": region,
                    }
                )
    except Exception as exc:  # noqa: BLE001 — one failed Secrets list must not sink the scan
        record_discovery_failure(
            exc=exc,
            resource_type="Secrets Manager secrets",
            permission="secretsmanager:ListSecrets",
            cloud="aws",
            warnings=warnings,
            missing=missing,
        )
    return out


def _discover_cloudfront(
    session: Any, *, account_id: str | None, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate CloudFront CDN distributions (read-only, global). Internet-facing edge."""
    out: list[dict[str, Any]] = []
    try:
        client = session.client("cloudfront")
        paginator = client.get_paginator("list_distributions")
        for page in paginator.paginate():
            for dist in (page.get("DistributionList", {}) or {}).get("Items", []) or []:
                dist_id = str(dist.get("Id", "") or "")
                if not dist_id:
                    continue
                origins = [str(o.get("DomainName", "")) for o in (dist.get("Origins", {}) or {}).get("Items", []) or []]
                out.append(
                    {
                        "name": dist_id,
                        "arn": str(dist.get("ARN", "") or ""),
                        "domain_name": str(dist.get("DomainName", "") or ""),
                        "enabled": bool(dist.get("Enabled")),
                        "internet_exposed": True,  # a CDN distribution is internet-facing by definition
                        "origins": origins,
                        "account_id": account_id or "",
                        "location": "global",
                    }
                )
    except Exception as exc:  # noqa: BLE001 — one failed CloudFront list must not sink the scan
        record_discovery_failure(
            exc=exc,
            resource_type="CloudFront distributions",
            permission="cloudfront:ListDistributions",
            cloud="aws",
            warnings=warnings,
            missing=missing,
        )
    return out


def _discover_ecr(
    session: Any, region: str, *, account_id: str | None, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate ECR container registries (read-only). Become container-registry resources."""
    out: list[dict[str, Any]] = []
    try:
        client = session.client("ecr", region_name=region)
        paginator = client.get_paginator("describe_repositories")
        for page in paginator.paginate():
            for repo in page.get("repositories", []):
                name = str(repo.get("repositoryName", "") or "")
                if not name:
                    continue
                out.append(
                    {
                        "name": name,
                        "arn": str(repo.get("repositoryArn", "") or ""),
                        "uri": str(repo.get("repositoryUri", "") or ""),
                        "scan_on_push": bool((repo.get("imageScanningConfiguration") or {}).get("scanOnPush")),
                        "tag_immutable": str(repo.get("imageTagMutability", "")) == "IMMUTABLE",
                        "account_id": account_id or "",
                        "location": region,
                    }
                )
    except Exception as exc:  # noqa: BLE001 — one failed ECR list must not sink the scan
        record_discovery_failure(
            exc=exc,
            resource_type="ECR repositories",
            permission="ecr:DescribeRepositories",
            cloud="aws",
            warnings=warnings,
            missing=missing,
        )
    return out


def _discover_redshift(
    session: Any, region: str, *, account_id: str | None, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate Redshift clusters (read-only). Data warehouses → ``DATA_STORE``."""
    out: list[dict[str, Any]] = []
    try:
        client = session.client("redshift", region_name=region)
        paginator = client.get_paginator("describe_clusters")
        for page in paginator.paginate():
            for c in page.get("Clusters", []):
                name = str(c.get("ClusterIdentifier", "") or "")
                if not name:
                    continue
                out.append(
                    {
                        "name": name,
                        "engine": "redshift",
                        "publicly_accessible": bool(c.get("PubliclyAccessible")),
                        "encrypted": bool(c.get("Encrypted")),
                        "endpoint": str((c.get("Endpoint") or {}).get("Address", "") or ""),
                        "node_type": str(c.get("NodeType", "") or ""),
                        "account_id": account_id or "",
                        "location": region,
                    }
                )
    except Exception as exc:  # noqa: BLE001 — one failed Redshift list must not sink the scan
        record_discovery_failure(
            exc=exc,
            resource_type="Redshift clusters",
            permission="redshift:DescribeClusters",
            cloud="aws",
            warnings=warnings,
            missing=missing,
        )
    return out


def _discover_messaging(
    session: Any, region: str, *, account_id: str | None, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate SNS topics + SQS queues (read-only). Become messaging resources."""
    out: list[dict[str, Any]] = []
    try:
        sns = session.client("sns", region_name=region)
        paginator = sns.get_paginator("list_topics")
        for page in paginator.paginate():
            for topic in page.get("Topics", []):
                arn = str(topic.get("TopicArn", "") or "")
                if not arn:
                    continue
                out.append(
                    {
                        "name": arn.rsplit(":", 1)[-1],
                        "arn": arn,
                        "messaging_type": "sns-topic",
                        "account_id": account_id or "",
                        "location": region,
                    }
                )
    except Exception as exc:  # noqa: BLE001 — one failed SNS list must not sink the scan
        record_discovery_failure(
            exc=exc, resource_type="SNS topics", permission="sns:ListTopics", cloud="aws", warnings=warnings, missing=missing
        )
    try:
        sqs = session.client("sqs", region_name=region)
        paginator = sqs.get_paginator("list_queues")
        for page in paginator.paginate():
            for url in page.get("QueueUrls", []) or []:
                name = str(url).rsplit("/", 1)[-1]
                if not name:
                    continue
                out.append(
                    {
                        "name": name,
                        "arn": f"arn:aws:sqs:{region}:{account_id or ''}:{name}",
                        "messaging_type": "sqs-queue",
                        "url": str(url),
                        "account_id": account_id or "",
                        "location": region,
                    }
                )
    except Exception as exc:  # noqa: BLE001 — one failed SQS list must not sink the scan
        record_discovery_failure(
            exc=exc, resource_type="SQS queues", permission="sqs:ListQueues", cloud="aws", warnings=warnings, missing=missing
        )
    return out


# ---------------------------------------------------------------------------
# Network edge: WAF, API Gateway, ENIs, NAT/IGW, subnets, route tables, IPs
# ---------------------------------------------------------------------------


def _discover_waf(
    session: Any, region: str, *, account_id: str | None, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate WAFv2 web ACLs and the resources they front (read-only).

    Both scopes are covered: ``REGIONAL`` (ALB / API Gateway / AppSync in the
    region) and ``CLOUDFRONT`` (global edge, enumerated only from us-east-1 so a
    multi-region scan does not duplicate it). ``protected_targets`` carries the
    ARNs of the resources each web ACL is associated with, which the graph turns
    into ``PROTECTS`` edges that refine the fronted resource's exposure verdict.
    """
    out: list[dict[str, Any]] = []
    scopes = ["REGIONAL"]
    if region == "us-east-1":
        scopes.append("CLOUDFRONT")
    for scope in scopes:
        try:
            client = session.client("wafv2", region_name="us-east-1" if scope == "CLOUDFRONT" else region)
            resp = client.list_web_acls(Scope=scope)
        except Exception as exc:  # noqa: BLE001 — one failed WAF list must not sink the scan
            record_discovery_failure(
                exc=exc,
                resource_type=f"WAF web ACLs ({scope})",
                permission="wafv2:ListWebACLs",
                cloud="aws",
                warnings=warnings,
                missing=missing,
            )
            continue
        for acl in resp.get("WebACLs", []) or []:
            name = str(acl.get("Name", "") or "")
            arn = str(acl.get("ARN", "") or "")
            if not (name or arn):
                continue
            targets: list[str] = []
            # Regional web ACLs expose their associated resources directly;
            # CloudFront associations are read from the distribution side and are
            # left empty here to avoid a per-distribution describe storm.
            if scope == "REGIONAL" and arn:
                try:
                    assoc = client.list_resources_for_web_acl(WebACLArn=arn)
                    targets = [str(r) for r in assoc.get("ResourceArns", []) or [] if r]
                except Exception as exc:  # noqa: BLE001 — association read is best-effort
                    warnings.append(f"Could not list resources for WAF {name}: {sanitize_discovery_warning(exc)}")
            out.append(
                {
                    "name": name or arn.rsplit("/", 1)[-1],
                    "id": str(acl.get("Id", "") or ""),
                    "arn": arn,
                    "scope": scope.lower(),
                    "protected_targets": targets,
                    "location": "global" if scope == "CLOUDFRONT" else region,
                    "account_id": account_id or "",
                }
            )
    return out


def _discover_api_gateways(
    session: Any, region: str, *, account_id: str | None, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate REST (apigateway) and HTTP/WebSocket (apigatewayv2) APIs (read-only).

    Each API is internet-facing by default, so it becomes an ``API_GATEWAY``
    graph node in the API_GATEWAY semantic layer; ``stages`` carries the deployed
    stage names (non-secret) for context.
    """
    out: list[dict[str, Any]] = []
    try:
        rest = session.client("apigateway", region_name=region)
        paginator = rest.get_paginator("get_rest_apis")
        for page in paginator.paginate():
            for api in page.get("items", []) or []:
                api_id = str(api.get("id", "") or "")
                if not api_id:
                    continue
                stages: list[str] = []
                try:
                    for stage in rest.get_stages(restApiId=api_id).get("item", []) or []:
                        stage_name = str(stage.get("stageName", "") or "")
                        if stage_name:
                            stages.append(stage_name)
                except Exception:  # noqa: BLE001 — stage read is best-effort
                    stages = []
                endpoint_types = [str(t) for t in ((api.get("endpointConfiguration") or {}).get("types") or [])]
                out.append(
                    {
                        "name": str(api.get("name", "") or api_id),
                        "id": api_id,
                        "arn": "",
                        "protocol": "REST",
                        "endpoint": ",".join(endpoint_types),
                        "internet_exposed": "PRIVATE" not in endpoint_types,
                        "stages": stages,
                        "protected_targets": [],
                        "location": region,
                        "account_id": account_id or "",
                    }
                )
    except Exception as exc:  # noqa: BLE001 — one failed API Gateway list must not sink the scan
        record_discovery_failure(
            exc=exc, resource_type="API Gateway REST APIs", permission="apigateway:GET", cloud="aws", warnings=warnings, missing=missing
        )

    try:
        v2 = session.client("apigatewayv2", region_name=region)
        next_token: str | None = None
        while True:
            resp = v2.get_apis(NextToken=next_token) if next_token else v2.get_apis()
            for api in resp.get("Items", []) or []:
                api_id = str(api.get("ApiId", "") or "")
                if not api_id:
                    continue
                out.append(
                    {
                        "name": str(api.get("Name", "") or api_id),
                        "id": api_id,
                        "arn": "",
                        "protocol": str(api.get("ProtocolType", "") or "HTTP"),
                        "endpoint": str(api.get("ApiEndpoint", "") or ""),
                        "internet_exposed": True,
                        "stages": [],
                        "protected_targets": [],
                        "location": region,
                        "account_id": account_id or "",
                    }
                )
            next_token = resp.get("NextToken")
            if not next_token:
                break
    except Exception as exc:  # noqa: BLE001 — one failed API Gateway v2 list must not sink the scan
        record_discovery_failure(
            exc=exc, resource_type="API Gateway HTTP/WS APIs", permission="apigateway:GET", cloud="aws", warnings=warnings, missing=missing
        )
    return out


def _discover_network_edge(
    session: Any, region: str, *, account_id: str | None, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> dict[str, list[dict[str, Any]]]:
    """Enumerate VPC plumbing (read-only): ENIs, NAT/internet gateways, VPC
    endpoints, subnets, route tables, and network ACLs.

    A subnet is marked ``is_public`` when a route table associated with it routes
    ``0.0.0.0/0`` to an internet gateway — the same internet-reachability
    classifier the GCP firewall path uses, applied to the AWS network fabric.
    """
    out: dict[str, list[dict[str, Any]]] = {
        "network_interfaces": [],
        "subnets": [],
        "nat_gateways": [],
        "internet_gateways": [],
        "vpc_endpoints": [],
        "route_tables": [],
        "network_acls": [],
    }
    ec2 = session.client("ec2", region_name=region)

    # Route tables first so subnet public/private classification can use them.
    public_subnet_ids: set[str] = set()
    vpc_default_public: set[str] = set()
    try:
        paginator = ec2.get_paginator("describe_route_tables")
        for page in paginator.paginate():
            for rt in page.get("RouteTables", []) or []:
                rt_id = str(rt.get("RouteTableId", "") or "")
                if not rt_id:
                    continue
                vpc_id = str(rt.get("VpcId", "") or "")
                has_igw_route = any(
                    str(r.get("GatewayId", "") or "").startswith("igw-") and str(r.get("DestinationCidrBlock", "")) in _INTERNET_CIDRS
                    for r in rt.get("Routes", []) or []
                    if isinstance(r, dict)
                )
                assocs = rt.get("Associations", []) or []
                main = any(bool(a.get("Main")) for a in assocs if isinstance(a, dict))
                if has_igw_route:
                    if main and vpc_id:
                        vpc_default_public.add(vpc_id)
                    for a in assocs:
                        sid = str(a.get("SubnetId", "") or "") if isinstance(a, dict) else ""
                        if sid:
                            public_subnet_ids.add(sid)
                out["route_tables"].append(
                    {
                        "id": rt_id,
                        "name": rt_id,
                        "vpc_id": vpc_id,
                        "has_internet_route": has_igw_route,
                        "location": region,
                        "account_id": account_id or "",
                    }
                )
    except Exception as exc:  # noqa: BLE001
        record_discovery_failure(
            exc=exc, resource_type="route tables", permission="ec2:DescribeRouteTables", cloud="aws", warnings=warnings, missing=missing
        )

    try:
        paginator = ec2.get_paginator("describe_subnets")
        for page in paginator.paginate():
            for sn in page.get("Subnets", []) or []:
                sn_id = str(sn.get("SubnetId", "") or "")
                if not sn_id:
                    continue
                vpc_id = str(sn.get("VpcId", "") or "")
                tags = {str(t.get("Key", "")): str(t.get("Value", "")) for t in sn.get("Tags", []) if t.get("Key")}
                # Explicit public route-table association wins; otherwise a subnet
                # that auto-assigns public IPs in an internet-routed VPC is public.
                is_public = sn_id in public_subnet_ids or (bool(sn.get("MapPublicIpOnLaunch")) and vpc_id in vpc_default_public)
                out["subnets"].append(
                    {
                        "id": sn_id,
                        "name": tags.get("Name", sn_id),
                        "vpc_id": vpc_id,
                        "cidr": str(sn.get("CidrBlock", "") or ""),
                        "is_public": is_public,
                        "location": str(sn.get("AvailabilityZone", "") or region),
                        "account_id": account_id or "",
                    }
                )
    except Exception as exc:  # noqa: BLE001
        record_discovery_failure(
            exc=exc, resource_type="subnets", permission="ec2:DescribeSubnets", cloud="aws", warnings=warnings, missing=missing
        )

    try:
        paginator = ec2.get_paginator("describe_network_interfaces")
        for page in paginator.paginate():
            for eni in page.get("NetworkInterfaces", []) or []:
                eni_id = str(eni.get("NetworkInterfaceId", "") or "")
                if not eni_id:
                    continue
                sg_ids = [str(g.get("GroupId", "")) for g in eni.get("Groups", []) or [] if isinstance(g, dict) and g.get("GroupId")]
                attachment = eni.get("Attachment") or {}
                association = eni.get("Association") or {}
                out["network_interfaces"].append(
                    {
                        "id": eni_id,
                        "name": eni_id,
                        "instance_id": str(attachment.get("InstanceId", "") or ""),
                        "subnet_id": str(eni.get("SubnetId", "") or ""),
                        "vpc_id": str(eni.get("VpcId", "") or ""),
                        "security_group_ids": sg_ids,
                        "private_ip": str(eni.get("PrivateIpAddress", "") or ""),
                        "public_ip": str(association.get("PublicIp", "") or ""),
                        "location": region,
                        "account_id": account_id or "",
                    }
                )
    except Exception as exc:  # noqa: BLE001
        record_discovery_failure(
            exc=exc,
            resource_type="network interfaces",
            permission="ec2:DescribeNetworkInterfaces",
            cloud="aws",
            warnings=warnings,
            missing=missing,
        )

    try:
        paginator = ec2.get_paginator("describe_nat_gateways")
        for page in paginator.paginate():
            for nat in page.get("NatGateways", []) or []:
                nat_id = str(nat.get("NatGatewayId", "") or "")
                if not nat_id:
                    continue
                out["nat_gateways"].append(
                    {
                        "id": nat_id,
                        "name": nat_id,
                        "vpc_id": str(nat.get("VpcId", "") or ""),
                        "subnet_id": str(nat.get("SubnetId", "") or ""),
                        "connectivity": str(nat.get("ConnectivityType", "") or "public"),
                        "location": region,
                        "account_id": account_id or "",
                    }
                )
    except Exception as exc:  # noqa: BLE001
        record_discovery_failure(
            exc=exc, resource_type="NAT gateways", permission="ec2:DescribeNatGateways", cloud="aws", warnings=warnings, missing=missing
        )

    try:
        for igw in ec2.describe_internet_gateways().get("InternetGateways", []) or []:
            igw_id = str(igw.get("InternetGatewayId", "") or "")
            if not igw_id:
                continue
            vpc_ids = [str(a.get("VpcId", "")) for a in igw.get("Attachments", []) or [] if isinstance(a, dict) and a.get("VpcId")]
            out["internet_gateways"].append(
                {
                    "id": igw_id,
                    "name": igw_id,
                    "vpc_id": vpc_ids[0] if vpc_ids else "",
                    "kind": "internet-gateway",
                    "location": region,
                    "account_id": account_id or "",
                }
            )
    except Exception as exc:  # noqa: BLE001
        record_discovery_failure(
            exc=exc,
            resource_type="internet gateways",
            permission="ec2:DescribeInternetGateways",
            cloud="aws",
            warnings=warnings,
            missing=missing,
        )

    try:
        for eigw in ec2.describe_egress_only_internet_gateways().get("EgressOnlyInternetGateways", []) or []:
            eigw_id = str(eigw.get("EgressOnlyInternetGatewayId", "") or "")
            if not eigw_id:
                continue
            vpc_ids = [str(a.get("VpcId", "")) for a in eigw.get("Attachments", []) or [] if isinstance(a, dict) and a.get("VpcId")]
            out["internet_gateways"].append(
                {
                    "id": eigw_id,
                    "name": eigw_id,
                    "vpc_id": vpc_ids[0] if vpc_ids else "",
                    "kind": "egress-only-internet-gateway",
                    "location": region,
                    "account_id": account_id or "",
                }
            )
    except Exception as exc:  # noqa: BLE001
        record_discovery_failure(
            exc=exc,
            resource_type="egress-only internet gateways",
            permission="ec2:DescribeEgressOnlyInternetGateways",
            cloud="aws",
            warnings=warnings,
            missing=missing,
        )

    try:
        paginator = ec2.get_paginator("describe_vpc_endpoints")
        for page in paginator.paginate():
            for vpe in page.get("VpcEndpoints", []) or []:
                vpe_id = str(vpe.get("VpcEndpointId", "") or "")
                if not vpe_id:
                    continue
                out["vpc_endpoints"].append(
                    {
                        "id": vpe_id,
                        "name": str(vpe.get("ServiceName", "") or vpe_id),
                        "vpc_id": str(vpe.get("VpcId", "") or ""),
                        "endpoint_type": str(vpe.get("VpcEndpointType", "") or ""),
                        "location": region,
                        "account_id": account_id or "",
                    }
                )
    except Exception as exc:  # noqa: BLE001
        record_discovery_failure(
            exc=exc, resource_type="VPC endpoints", permission="ec2:DescribeVpcEndpoints", cloud="aws", warnings=warnings, missing=missing
        )

    try:
        paginator = ec2.get_paginator("describe_network_acls")
        for page in paginator.paginate():
            for acl in page.get("NetworkAcls", []) or []:
                acl_id = str(acl.get("NetworkAclId", "") or "")
                if not acl_id:
                    continue
                out["network_acls"].append(
                    {
                        "id": acl_id,
                        "name": acl_id,
                        "vpc_id": str(acl.get("VpcId", "") or ""),
                        "is_default": bool(acl.get("IsDefault")),
                        "location": region,
                        "account_id": account_id or "",
                    }
                )
    except Exception as exc:  # noqa: BLE001
        record_discovery_failure(
            exc=exc, resource_type="network ACLs", permission="ec2:DescribeNetworkAcls", cloud="aws", warnings=warnings, missing=missing
        )

    return out


def _discover_ip_addresses(
    session: Any,
    region: str,
    *,
    account_id: str | None,
    network_interfaces: list[dict[str, Any]],
    warnings: list[str],
    missing: list[dict[str, str]] | None = None,
) -> list[dict[str, Any]]:
    """Enumerate Elastic IPs plus the public IPs bound to ENIs (read-only).

    Every internet-facing address is inventoried and attributable so an exposed
    address can be tied back to the resource it fronts. Elastic IPs come from
    ``describe_addresses``; ephemeral public IPs are read from the already-
    discovered ENIs (no extra call).
    """
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    try:
        ec2 = session.client("ec2", region_name=region)
        for addr in ec2.describe_addresses().get("Addresses", []) or []:
            ip = str(addr.get("PublicIp", "") or "")
            if not ip or ip in seen:
                continue
            seen.add(ip)
            attached = str(addr.get("InstanceId", "") or addr.get("NetworkInterfaceId", "") or "")
            out.append(
                {
                    "address": ip,
                    "kind": "elastic",
                    "attached_to": attached,
                    "allocation_id": str(addr.get("AllocationId", "") or ""),
                    "location": region,
                    "account_id": account_id or "",
                }
            )
    except Exception as exc:  # noqa: BLE001
        record_discovery_failure(
            exc=exc, resource_type="Elastic IPs", permission="ec2:DescribeAddresses", cloud="aws", warnings=warnings, missing=missing
        )

    for eni in network_interfaces:
        ip = str(eni.get("public_ip", "") or "")
        if not ip or ip in seen:
            continue
        seen.add(ip)
        out.append(
            {
                "address": ip,
                "kind": "public",
                "attached_to": str(eni.get("instance_id", "") or eni.get("id", "") or ""),
                "location": region,
                "account_id": account_id or "",
            }
        )
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
    "ALL_REGIONS_ENV_FLAG",
    "INVENTORY_ENV_FLAG",
    "REGIONS_ENV_VAR",
    "all_regions_enabled",
    "discover_inventory",
    "discover_inventory_all_regions",
    "inventory_enabled",
]
