"""Terraform security rules for AWS object and block storage (S3, EBS, DynamoDB)."""

from __future__ import annotations

import re

from agent_bom.iac.models import IaCFinding
from agent_bom.iac.terraform_security_common import PITR_ENABLED_RE, TfResource, extract_block

_PUBLIC_ACL_RE = re.compile(r'acl\s*=\s*"(public-read|public-read-write)"', re.IGNORECASE)
_ENCRYPTION_CONFIG_RE = re.compile(r"server_side_encryption_configuration\s*\{", re.IGNORECASE)

# TF-SEC-008: S3 bucket encryption (separate resource in TF AWS provider v4+)
_S3_SSE_BLOCK_RE = re.compile(r"server_side_encryption_configuration\s*\{", re.IGNORECASE)

# TF-SEC-018: DynamoDB PITR
_PITR_RE = re.compile(r"point_in_time_recovery\s*\{", re.IGNORECASE)

# TF-SEC-021: S3 bucket versioning
_VERSIONING_RE = re.compile(r"versioning\s*\{", re.IGNORECASE)
_VERSIONING_ENABLED_RE = re.compile(r"enabled\s*=\s*true", re.IGNORECASE)

# TF-SEC-022: S3 public access block
_PUBLIC_ACCESS_BLOCK_RE = re.compile(r"aws_s3_bucket_public_access_block", re.IGNORECASE)

# TF-SEC-023: S3 bucket logging
_S3_LOGGING_RE = re.compile(r"logging\s*\{", re.IGNORECASE)

# TF-SEC-027/028: EBS encryption
_EBS_ENCRYPTED_TRUE_RE = re.compile(r"encrypted\s*=\s*true", re.IGNORECASE)


def tf_sec_001_002(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-001 + TF-SEC-002: S3 bucket checks."""
    rname, block, block_start_line, rel_path = res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
    if not _ENCRYPTION_CONFIG_RE.search(block):
        findings.append(
            IaCFinding(
                rule_id="TF-SEC-001",
                severity="high",
                title="S3 bucket without encryption",
                message=(
                    f"S3 bucket '{rname}' does not have "
                    "server_side_encryption_configuration. Enable SSE-S3 "
                    "or SSE-KMS to encrypt data at rest."
                ),
                file_path=rel_path,
                line_number=block_start_line,
                category="terraform",
                compliance=["CIS-AWS-2.1.1", "NIST-SC-28"],
            )
        )

    acl_m = _PUBLIC_ACL_RE.search(block)
    if acl_m:
        findings.append(
            IaCFinding(
                rule_id="TF-SEC-002",
                severity="critical",
                title="S3 bucket with public ACL",
                message=(
                    f"S3 bucket '{rname}' has acl = \"{acl_m.group(1)}\". "
                    "Public S3 buckets are a top cloud breach vector. "
                    "Use private ACL and bucket policies instead."
                ),
                file_path=rel_path,
                line_number=block_start_line,
                category="terraform",
                compliance=["CIS-AWS-2.1.2", "NIST-AC-3"],
            )
        )
    return findings


def tf_sec_008(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-008: S3 bucket without server-side encryption."""
    rname, block, block_start_line, rel_path = res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
    if not _S3_SSE_BLOCK_RE.search(block):
        findings.append(
            IaCFinding(
                rule_id="TF-SEC-008",
                severity="high",
                title="S3 bucket without server-side encryption",
                message=(
                    f"S3 bucket '{rname}' does not have "
                    "server_side_encryption_configuration. Enable SSE-S3 "
                    "or SSE-KMS to encrypt data at rest."
                ),
                file_path=rel_path,
                line_number=block_start_line,
                category="terraform",
                compliance=["CIS-AWS-2.1.1", "NIST-SC-28"],
            )
        )
    return findings


def tf_sec_018(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-018: DynamoDB without point-in-time recovery."""
    rname, block, block_start_line, rel_path = res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
    pitr_m = _PITR_RE.search(block)
    if pitr_m:
        pitr_block = extract_block(block, pitr_m.end())
        if not PITR_ENABLED_RE.search(pitr_block):
            findings.append(
                IaCFinding(
                    rule_id="TF-SEC-018",
                    severity="medium",
                    title="DynamoDB without point-in-time recovery",
                    message=(
                        f"DynamoDB table '{rname}' has point_in_time_recovery "
                        "but enabled is not set to true. Enable PITR for "
                        "continuous backups and disaster recovery."
                    ),
                    file_path=rel_path,
                    line_number=block_start_line,
                    category="terraform",
                    compliance=["CIS-AWS-2.4", "NIST-CP-9"],
                )
            )
    else:
        findings.append(
            IaCFinding(
                rule_id="TF-SEC-018",
                severity="medium",
                title="DynamoDB without point-in-time recovery",
                message=(
                    f"DynamoDB table '{rname}' does not have a "
                    "point_in_time_recovery block. Enable PITR for "
                    "continuous backups and disaster recovery."
                ),
                file_path=rel_path,
                line_number=block_start_line,
                category="terraform",
                compliance=["CIS-AWS-2.4", "NIST-CP-9"],
            )
        )
    return findings


def tf_sec_021(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-021: S3 bucket versioning not enabled."""
    rname, block, block_start_line, rel_path = res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
    versioning_m = _VERSIONING_RE.search(block)
    if versioning_m:
        v_block = extract_block(block, versioning_m.end())
        if not _VERSIONING_ENABLED_RE.search(v_block):
            findings.append(
                IaCFinding(
                    rule_id="TF-SEC-021",
                    severity="medium",
                    title="S3 bucket versioning not enabled",
                    message=(
                        f"S3 bucket '{rname}' has a versioning block but "
                        "enabled is not set to true. Enable versioning to "
                        "protect against accidental deletion."
                    ),
                    file_path=rel_path,
                    line_number=block_start_line,
                    category="terraform",
                    compliance=["CIS-AWS-2.1.3", "NIST-CP-9"],
                )
            )
    else:
        findings.append(
            IaCFinding(
                rule_id="TF-SEC-021",
                severity="medium",
                title="S3 bucket versioning not enabled",
                message=(
                    f"S3 bucket '{rname}' does not have a versioning block. "
                    "Enable versioning to protect against accidental "
                    "deletion and enable recovery."
                ),
                file_path=rel_path,
                line_number=block_start_line,
                category="terraform",
                compliance=["CIS-AWS-2.1.3", "NIST-CP-9"],
            )
        )
    return findings


def tf_sec_022(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-022: S3 bucket public access block missing."""
    rname, block_start_line, rel_path, content = res.rname, res.block_start_line, res.rel_path, res.content
    findings: list[IaCFinding] = []
    if not _PUBLIC_ACCESS_BLOCK_RE.search(content):
        findings.append(
            IaCFinding(
                rule_id="TF-SEC-022",
                severity="high",
                title="S3 bucket public access block missing",
                message=(
                    f"S3 bucket '{rname}' does not have an associated "
                    "aws_s3_bucket_public_access_block resource in this "
                    "file. Add a public access block to prevent public "
                    "bucket exposure."
                ),
                file_path=rel_path,
                line_number=block_start_line,
                category="terraform",
                compliance=["CIS-AWS-2.1.5", "NIST-AC-3"],
            )
        )
    return findings


def tf_sec_023(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-023: S3 bucket logging not enabled."""
    rname, block, block_start_line, rel_path = res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
    if not _S3_LOGGING_RE.search(block):
        findings.append(
            IaCFinding(
                rule_id="TF-SEC-023",
                severity="medium",
                title="S3 bucket logging not enabled",
                message=(
                    f"S3 bucket '{rname}' does not have a logging block. "
                    "Enable server access logging to track requests for "
                    "security auditing."
                ),
                file_path=rel_path,
                line_number=block_start_line,
                category="terraform",
                compliance=["CIS-AWS-3.6", "NIST-AU-2"],
            )
        )
    return findings


def tf_sec_027(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-027: EBS volume not encrypted."""
    rname, block, block_start_line, rel_path = res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
    if not _EBS_ENCRYPTED_TRUE_RE.search(block):
        findings.append(
            IaCFinding(
                rule_id="TF-SEC-027",
                severity="high",
                title="EBS volume not encrypted",
                message=(
                    f"EBS volume '{rname}' does not have encrypted = true. "
                    "Enable encryption at rest for EBS volumes to protect "
                    "sensitive data."
                ),
                file_path=rel_path,
                line_number=block_start_line,
                category="terraform",
                compliance=["CIS-AWS-2.2.1", "NIST-SC-28"],
            )
        )
    return findings


def tf_sec_028(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-028: EBS snapshot not encrypted."""
    rname, block, block_start_line, rel_path = res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
    if not _EBS_ENCRYPTED_TRUE_RE.search(block):
        findings.append(
            IaCFinding(
                rule_id="TF-SEC-028",
                severity="high",
                title="EBS snapshot not encrypted",
                message=(
                    f"EBS snapshot '{rname}' is not encrypted. Ensure the "
                    "source EBS volume is encrypted or copy the snapshot "
                    "with encryption enabled."
                ),
                file_path=rel_path,
                line_number=block_start_line,
                category="terraform",
                compliance=["NIST-SC-28"],
            )
        )
    return findings
