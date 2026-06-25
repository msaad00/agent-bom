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
    "iam:ListAttachedRolePolicies",
    "iam:ListAttachedUserPolicies",
    "iam:ListRolePolicies",
    "iam:ListUserPolicies",
    "iam:GetRolePolicy",
    "iam:GetUserPolicy",
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
_AWS_BASELINE_PERMISSIONS: tuple[str, ...] = ("sts:GetCallerIdentity",)

# Open-to-the-world CIDR / ipv6 ranges that mark a security-group ingress rule
# as internet-facing. The CNAPP overlay keys off this `network_exposure` shape.
_INTERNET_CIDRS = {"0.0.0.0/0"}
_INTERNET_IPV6 = {"::/0"}


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
        "warnings": [],
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
        "warnings": warnings,
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
    elb_load_balancers: list[dict[str, Any]] = []
    vpcs: list[dict[str, Any]] = []
    kms_keys: list[dict[str, Any]] = []
    secrets: list[dict[str, Any]] = []
    cloudfront_distributions: list[dict[str, Any]] = []
    ecr_repositories: list[dict[str, Any]] = []
    redshift_clusters: list[dict[str, Any]] = []
    messaging: list[dict[str, Any]] = []

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
            kms_keys = _discover_kms(session, resolved_region, account_id=account_id, warnings=warnings)
            secrets = _discover_secrets(session, resolved_region, account_id=account_id, warnings=warnings)
            redshift_clusters = _discover_redshift(session, resolved_region, account_id=account_id, warnings=warnings)
        if include_compute:
            lambda_functions = _discover_lambda(session, resolved_region, account_id=account_id, warnings=warnings)
            eks_clusters = _discover_eks(session, resolved_region, account_id=account_id, warnings=warnings)
            ecr_repositories = _discover_ecr(session, resolved_region, account_id=account_id, warnings=warnings)
        if include_network:
            elb_load_balancers = _discover_elb(session, resolved_region, account_id=account_id, warnings=warnings)
            vpcs = _discover_vpcs(session, resolved_region, account_id=account_id, warnings=warnings)
            cloudfront_distributions = _discover_cloudfront(session, account_id=account_id, warnings=warnings)
            messaging = _discover_messaging(session, resolved_region, account_id=account_id, warnings=warnings)
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
        "elb_load_balancers": elb_load_balancers,
        "vpcs": vpcs,
        "kms_keys": kms_keys,
        "secrets": secrets,
        "cloudfront_distributions": cloudfront_distributions,
        "ecr_repositories": ecr_repositories,
        "redshift_clusters": redshift_clusters,
        "messaging": messaging,
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


def _inline_policies(iam: Any, principal_kind: str, principal_name: str, *, warnings: list[str]) -> list[dict[str, Any]]:
    """Return inline policies with a classified privilege level (read-only).

    Inline policies attach directly to a single principal and never appear in
    ``list_attached_*`` — yet they can silently grant admin, so a posture scan
    must read them. Lists the inline names, fetches each document, and classifies
    by Allow actions. Degrades to a warning on error; never blocks enumeration.
    """
    if not principal_name:
        return []
    list_op = "list_role_policies" if principal_kind == "role" else "list_user_policies"
    kwarg = "RoleName" if principal_kind == "role" else "UserName"
    policies: list[dict[str, Any]] = []
    try:
        get_doc = iam.get_role_policy if principal_kind == "role" else iam.get_user_policy
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


def _discover_elb(session: Any, region: str, *, account_id: str | None, warnings: list[str]) -> list[dict[str, Any]]:
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
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list load balancers: {sanitize_discovery_warning(exc)}")
    return out


def _discover_vpcs(session: Any, region: str, *, account_id: str | None, warnings: list[str]) -> list[dict[str, Any]]:
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
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list VPCs: {sanitize_discovery_warning(exc)}")
    return out


def _discover_kms(session: Any, region: str, *, account_id: str | None, warnings: list[str]) -> list[dict[str, Any]]:
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
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list KMS keys: {sanitize_discovery_warning(exc)}")
    return out


def _discover_secrets(session: Any, region: str, *, account_id: str | None, warnings: list[str]) -> list[dict[str, Any]]:
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
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list Secrets Manager secrets: {sanitize_discovery_warning(exc)}")
    return out


def _discover_cloudfront(session: Any, *, account_id: str | None, warnings: list[str]) -> list[dict[str, Any]]:
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
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list CloudFront distributions: {sanitize_discovery_warning(exc)}")
    return out


def _discover_ecr(session: Any, region: str, *, account_id: str | None, warnings: list[str]) -> list[dict[str, Any]]:
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
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list ECR repositories: {sanitize_discovery_warning(exc)}")
    return out


def _discover_redshift(session: Any, region: str, *, account_id: str | None, warnings: list[str]) -> list[dict[str, Any]]:
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
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list Redshift clusters: {sanitize_discovery_warning(exc)}")
    return out


def _discover_messaging(session: Any, region: str, *, account_id: str | None, warnings: list[str]) -> list[dict[str, Any]]:
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
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list SNS topics: {sanitize_discovery_warning(exc)}")
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
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list SQS queues: {sanitize_discovery_warning(exc)}")
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
