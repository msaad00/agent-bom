"""CIS AWS 2.x — S3, EBS, RDS and KMS storage checks."""

from __future__ import annotations

from typing import Any

from agent_bom.security import sanitize_text

from ..aws_inventory import is_access_denied_error
from ._base import CheckStatus, CISCheckResult, finalize_read_coverage, logger

# ---------------------------------------------------------------------------
# Individual checks — CIS 2.x (Storage / S3)
# ---------------------------------------------------------------------------

_STORAGE_SECTION = "2 - Storage"


def _check_2_1_1(s3control_client: Any, account_id: str) -> CISCheckResult:
    """CIS 2.1.1 — S3 account-level public access block configured."""
    result = CISCheckResult(
        check_id="2.1.1",
        title="S3 account-level public access block configured",
        status=CheckStatus.PASS,
        severity="high",
        cis_section=_STORAGE_SECTION,
        recommendation="Enable all four S3 public access block settings at the account level.",
    )
    try:
        config = s3control_client.get_public_access_block(AccountId=account_id)["PublicAccessBlockConfiguration"]
        required = ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]
        missing = [k for k in required if not config.get(k, False)]
        if missing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Account public access block missing: {', '.join(missing)}."
        else:
            result.evidence = "All four S3 account-level public access block settings enabled."
    except Exception as exc:
        error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        if error_code == "NoSuchPublicAccessBlockConfiguration":
            result.status = CheckStatus.FAIL
            result.evidence = "No account-level S3 public access block is configured."
        else:
            raise
    return result


def _check_2_1_2(s3_client: Any) -> CISCheckResult:
    """CIS 2.1.2 — S3 bucket server-side encryption enabled."""
    result = CISCheckResult(
        check_id="2.1.2",
        title="S3 bucket server-side encryption enabled",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_STORAGE_SECTION,
        recommendation="Enable default encryption (SSE-S3 or SSE-KMS) on all S3 buckets.",
    )
    buckets = s3_client.list_buckets().get("Buckets", [])
    unencrypted = []
    inspected = 0
    denied: list[str] = []
    for bucket in buckets:
        name = bucket["Name"]
        try:
            s3_client.get_bucket_encryption(Bucket=name)
            inspected += 1
        except Exception as exc:
            error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            if error_code == "ServerSideEncryptionConfigurationNotFoundError":
                # Successful determination: bucket has no default encryption.
                unencrypted.append(name)
                inspected += 1
            elif is_access_denied_error(exc):
                denied.append(name)
            else:
                # Skip buckets we can't access (cross-region, deleted, etc.)
                logger.debug("Could not check encryption for bucket %s: %s", name, sanitize_text(exc))

    if unencrypted:
        result.status = CheckStatus.FAIL
        result.evidence = f"{len(unencrypted)} bucket(s) without encryption: {', '.join(unencrypted[:5])}"
        if len(unencrypted) > 5:
            result.evidence += f" (+{len(unencrypted) - 5} more)"
        result.resource_ids = [f"arn:aws:s3:::{b}" for b in unencrypted]
    else:
        finalize_read_coverage(
            result,
            inspected=inspected,
            denied=denied,
            permission="s3:GetEncryptionConfiguration",
            resource_kind="bucket",
            pass_evidence=f"All {len(buckets)} bucket(s) have server-side encryption enabled.",
        )
    return result


def _check_2_1_3(s3_client: Any) -> CISCheckResult:
    """CIS 2.1.3 — S3 bucket MFA Delete enabled."""
    result = CISCheckResult(
        check_id="2.1.3",
        title="S3 bucket MFA Delete enabled",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_STORAGE_SECTION,
        recommendation="Enable MFA Delete on S3 bucket versioning configuration.",
    )
    buckets = s3_client.list_buckets().get("Buckets", [])
    no_mfa_delete: list[str] = []
    inspected = 0
    denied: list[str] = []
    for bucket in buckets:
        name = bucket["Name"]
        try:
            versioning = s3_client.get_bucket_versioning(Bucket=name)
            inspected += 1
            if versioning.get("MFADelete") != "Enabled":
                no_mfa_delete.append(name)
        except Exception as exc:
            if is_access_denied_error(exc):
                denied.append(name)
            logger.debug("Could not check MFA Delete for bucket %s: %s", name, sanitize_text(exc))

    if no_mfa_delete:
        result.status = CheckStatus.FAIL
        result.evidence = f"{len(no_mfa_delete)} bucket(s) without MFA Delete: {', '.join(no_mfa_delete[:5])}"
        if len(no_mfa_delete) > 5:
            result.evidence += f" (+{len(no_mfa_delete) - 5} more)"
        result.resource_ids = [f"arn:aws:s3:::{b}" for b in no_mfa_delete]
    else:
        finalize_read_coverage(
            result,
            inspected=inspected,
            denied=denied,
            permission="s3:GetBucketVersioning",
            resource_kind="bucket",
            pass_evidence=f"All {len(buckets)} bucket(s) have MFA Delete enabled.",
        )
    return result


def _check_2_1_4(s3_client: Any) -> CISCheckResult:
    """CIS 2.1.4 — S3 bucket versioning enabled."""
    result = CISCheckResult(
        check_id="2.1.4",
        title="S3 bucket versioning enabled",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_STORAGE_SECTION,
        recommendation="Enable versioning on all S3 buckets for data protection.",
    )
    buckets = s3_client.list_buckets().get("Buckets", [])
    unversioned = []
    inspected = 0
    denied: list[str] = []
    for bucket in buckets:
        name = bucket["Name"]
        try:
            versioning = s3_client.get_bucket_versioning(Bucket=name)
            inspected += 1
            if versioning.get("Status") != "Enabled":
                unversioned.append(name)
        except Exception as exc:
            # Skip inaccessible buckets (permissions, deleted, etc.)
            if is_access_denied_error(exc):
                denied.append(name)
            logger.debug("Could not check versioning for bucket %s: %s", name, sanitize_text(exc))

    if unversioned:
        result.status = CheckStatus.FAIL
        result.evidence = f"{len(unversioned)} bucket(s) without versioning: {', '.join(unversioned[:5])}"
        if len(unversioned) > 5:
            result.evidence += f" (+{len(unversioned) - 5} more)"
        result.resource_ids = [f"arn:aws:s3:::{b}" for b in unversioned]
    else:
        finalize_read_coverage(
            result,
            inspected=inspected,
            denied=denied,
            permission="s3:GetBucketVersioning",
            resource_kind="bucket",
            pass_evidence=f"All {len(buckets)} bucket(s) have versioning enabled.",
        )
    return result


def _check_2_2_1(ec2_client: Any) -> CISCheckResult:
    """CIS 2.2.1 — EBS default volume encryption enabled."""
    result = CISCheckResult(
        check_id="2.2.1",
        title="EBS default volume encryption enabled",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_STORAGE_SECTION,
        recommendation="Enable EBS encryption by default via EC2 > Settings > EBS encryption.",
    )
    try:
        resp = ec2_client.get_ebs_encryption_by_default()
        if not resp.get("EbsEncryptionByDefault", False):
            result.status = CheckStatus.FAIL
            result.evidence = "EBS volume encryption is not enabled by default."
        else:
            result.evidence = "EBS volume encryption is enabled by default."
    except Exception as exc:
        error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        logger.debug("Could not check EBS default encryption: %s (%s)", sanitize_text(exc), error_code)
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check EBS encryption default: {error_code or exc}"
    return result


def _check_2_3_1(rds_client: Any) -> CISCheckResult:
    """CIS 2.3.1 — RDS encryption at rest enabled."""
    result = CISCheckResult(
        check_id="2.3.1",
        title="RDS encryption at rest enabled",
        status=CheckStatus.PASS,
        severity="high",
        cis_section=_STORAGE_SECTION,
        recommendation="Enable encryption at rest when creating RDS instances (cannot be changed post-creation).",
    )
    paginator = rds_client.get_paginator("describe_db_instances")
    unencrypted: list[str] = []

    for page in paginator.paginate():
        for db in page["DBInstances"]:
            if not db.get("StorageEncrypted", False):
                unencrypted.append(db["DBInstanceIdentifier"])

    if unencrypted:
        result.status = CheckStatus.FAIL
        result.evidence = f"{len(unencrypted)} RDS instance(s) without encryption: {', '.join(unencrypted[:5])}"
        if len(unencrypted) > 5:
            result.evidence += f" (+{len(unencrypted) - 5} more)"
        result.resource_ids = unencrypted[:20]
    elif not unencrypted:
        result.evidence = "All RDS instances have encryption at rest enabled (or no instances found)."
    return result


def _check_2_3_2(rds_client: Any) -> CISCheckResult:
    """CIS 2.3.2 — RDS auto minor version upgrade enabled."""
    result = CISCheckResult(
        check_id="2.3.2",
        title="RDS auto minor version upgrade enabled",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_STORAGE_SECTION,
        recommendation="Enable auto minor version upgrade on all RDS instances.",
    )
    paginator = rds_client.get_paginator("describe_db_instances")
    no_auto_upgrade: list[str] = []

    for page in paginator.paginate():
        for db in page["DBInstances"]:
            if not db.get("AutoMinorVersionUpgrade", False):
                no_auto_upgrade.append(db["DBInstanceIdentifier"])

    if no_auto_upgrade:
        result.status = CheckStatus.FAIL
        result.evidence = f"{len(no_auto_upgrade)} RDS instance(s) without auto minor version upgrade: {', '.join(no_auto_upgrade[:5])}"
        if len(no_auto_upgrade) > 5:
            result.evidence += f" (+{len(no_auto_upgrade) - 5} more)"
        result.resource_ids = no_auto_upgrade[:20]
    else:
        result.evidence = "All RDS instances have auto minor version upgrade enabled (or no instances found)."
    return result


def _check_2_4_1(kms_client: Any) -> CISCheckResult:
    """CIS 2.4.1 — Customer-managed KMS key rotation enabled."""
    result = CISCheckResult(
        check_id="2.4.1",
        title="Customer-managed KMS key rotation enabled",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_STORAGE_SECTION,
        recommendation="Enable automatic key rotation for all customer-managed KMS keys.",
    )
    paginator = kms_client.get_paginator("list_keys")
    no_rotation: list[str] = []
    inspected = 0
    denied: list[str] = []

    for page in paginator.paginate():
        for key in page["Keys"]:
            key_id = key["KeyId"]
            try:
                # Only check customer-managed keys (skip AWS-managed and AWS-owned)
                desc = kms_client.describe_key(KeyId=key_id)["KeyMetadata"]
                inspected += 1
                if desc.get("KeyManager") != "CUSTOMER":
                    continue
                if desc.get("KeyState") != "Enabled":
                    continue
                rotation = kms_client.get_key_rotation_status(KeyId=key_id)
                if not rotation.get("KeyRotationEnabled", False):
                    no_rotation.append(key_id)
            except Exception as exc:
                error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
                if error_code == "NotFoundException":
                    # Key was deleted between list and read — legitimate skip.
                    continue
                if is_access_denied_error(exc):
                    denied.append(key_id)
                    continue
                logger.debug("Could not check rotation for key %s: %s", key_id, sanitize_text(exc))

    if no_rotation:
        result.status = CheckStatus.FAIL
        result.evidence = f"{len(no_rotation)} customer-managed key(s) without rotation: {', '.join(no_rotation[:5])}"
        if len(no_rotation) > 5:
            result.evidence += f" (+{len(no_rotation) - 5} more)"
        result.resource_ids = no_rotation[:20]
    else:
        finalize_read_coverage(
            result,
            inspected=inspected,
            denied=denied,
            permission="kms:GetKeyRotationStatus",
            resource_kind="KMS key",
            pass_evidence="All customer-managed KMS keys have rotation enabled (or no keys found).",
        )
    return result
