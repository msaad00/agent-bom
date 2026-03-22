"""Terraform security misconfiguration scanner.

Complements the existing ``terraform.py`` AI resource discovery module by
adding **security-focused** misconfig rules for AWS/cloud resources against
**cloud provider official documentation and best practices**:

- AWS Well-Architected Framework (Security Pillar)
- AWS Security Best Practices (SEC01-SEC11)
- CIS AWS Foundations Benchmark v2.0

Rules are mapped to applicable compliance frameworks (CIS-AWS, NIST SP 800-53)
where the mapping is well-established.  Uses regex-based scanning of ``.tf``
files — same approach as ``terraform.py``, no HCL parser needed.

Rules
-----
TF-SEC-001  S3 bucket without encryption (AWS SEC08, CIS 2.1.1)
TF-SEC-002  S3 bucket with public ACL (AWS SEC01, CIS 2.1.2)
TF-SEC-003  Security group with 0.0.0.0/0 ingress on non-443/80 port (CIS 5.2)
TF-SEC-004  IAM policy with Action: * or Resource: * (AWS SEC03, CIS 1.16)
TF-SEC-005  RDS without encryption (AWS SEC08, CIS 2.3.1)
TF-SEC-006  CloudWatch logging not enabled (AWS SEC04, CIS 3.1)
TF-SEC-007  SSH key hardcoded in resource (AWS SEC02, CIS 1.14)
TF-SEC-008  S3 bucket without server-side encryption (AWS SEC08, CIS 2.1.1)
TF-SEC-009  Security group rule with 0.0.0.0/0 (CIS 5.2)
TF-SEC-010  IAM policy with wildcards (AWS SEC03, CIS 1.16)
TF-SEC-011  RDS without storage encryption (AWS SEC08, CIS 2.3.1)
TF-SEC-012  EC2 instance without IMDSv2 (AWS SEC01, CIS 5.6)
TF-SEC-013  CloudWatch log group without retention (AWS SEC04, CIS 3.1)
TF-SEC-014  VPC without flow logs (AWS SEC04, CIS 3.9)
TF-SEC-015  EKS cluster without envelope encryption (AWS SEC08)
TF-SEC-016  Lambda without dead letter queue (AWS SEC05)
TF-SEC-017  ElastiCache without encryption in transit (AWS SEC08)
TF-SEC-018  DynamoDB without point-in-time recovery (AWS SEC08, CIS 2.4)
TF-SEC-019  API Gateway without access logging (AWS SEC04)
TF-SEC-020  KMS key without rotation (AWS SEC08, CIS 3.8)
TF-SEC-021  S3 bucket versioning not enabled (AWS SEC08, CIS 2.1.3)
TF-SEC-022  S3 bucket public access block missing (AWS SEC01, CIS 2.1.5)
TF-SEC-023  S3 bucket logging not enabled (AWS SEC04, CIS 3.6)
TF-SEC-024  RDS public accessibility enabled (AWS SEC01, CIS 2.3.2)
TF-SEC-025  RDS backup retention period < 7 days (AWS SEC08, CIS 2.3.3)
TF-SEC-026  RDS multi-AZ not enabled (AWS SEC08)
TF-SEC-027  EBS volume not encrypted (AWS SEC08, CIS 2.2.1)
TF-SEC-028  EBS snapshot not encrypted (AWS SEC08)
TF-SEC-029  ALB/ELB access logging not enabled (AWS SEC04, CIS 3.10)
TF-SEC-030  ALB/NLB deletion protection disabled (AWS SEC05)
TF-SEC-031  CloudTrail not enabled for all regions (AWS SEC04, CIS 3.1)
TF-SEC-032  CloudTrail log file validation disabled (AWS SEC04, CIS 3.2)
TF-SEC-033  SNS topic not encrypted (AWS SEC08, CIS 2.5)
TF-SEC-034  SQS queue not encrypted (AWS SEC08, CIS 2.6)
TF-SEC-035  ECR repository scan on push disabled (AWS SEC01)
TF-SEC-036  ECR repository image tag mutability enabled (AWS SEC01)
TF-SEC-037  ECS task definition with host networking (AWS SEC01)
TF-SEC-038  ECS task definition running as root (AWS SEC03)
TF-SEC-039  Secrets Manager secret without KMS encryption (AWS SEC08)
TF-SEC-040  SSM Parameter with plaintext SecureString (AWS SEC08)
TF-SEC-041  VPC default security group allows traffic (AWS SEC01, CIS 5.3)
TF-SEC-042  RDS instance without deletion protection (AWS SEC05)
TF-SEC-043  Elasticsearch/OpenSearch without encryption at rest (AWS SEC08)
TF-SEC-044  Elasticsearch/OpenSearch without node-to-node encryption (AWS SEC08)
TF-SEC-045  Lambda function without VPC configuration (AWS SEC01)
TF-SEC-046  Lambda environment variables with sensitive values (AWS SEC02)
TF-SEC-047  Redshift cluster without encryption (AWS SEC08, CIS 2.7)
TF-SEC-048  Redshift cluster publicly accessible (AWS SEC01)
TF-SEC-049  WAF not associated with ALB/CloudFront (AWS SEC05)
TF-SEC-050  GuardDuty not enabled (AWS SEC04, CIS 4.1)
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_bom.iac.models import IaCFinding

# ─── Block extraction ─────────────────────────────────────────────────────────

_RESOURCE_RE = re.compile(r'^resource\s+"([a-zA-Z][a-zA-Z0-9_]+)"\s+"([^"]+)"', re.MULTILINE)

# ─── Rule patterns ────────────────────────────────────────────────────────────

_PUBLIC_ACL_RE = re.compile(r'acl\s*=\s*"(public-read|public-read-write)"', re.IGNORECASE)
_ENCRYPTION_CONFIG_RE = re.compile(r"server_side_encryption_configuration\s*\{", re.IGNORECASE)
_CIDR_ALL_RE = re.compile(r'cidr_blocks\s*=\s*\[.*?"0\.0\.0\.0/0".*?\]', re.DOTALL)
_FROM_PORT_RE = re.compile(r"from_port\s*=\s*(\d+)")
_TO_PORT_RE = re.compile(r"to_port\s*=\s*(\d+)")
_IAM_STAR_ACTION_RE = re.compile(r'"Action"\s*:\s*"\*"')
_IAM_STAR_RESOURCE_RE = re.compile(r'"Resource"\s*:\s*"\*"')
_STORAGE_ENCRYPTED_FALSE_RE = re.compile(r"storage_encrypted\s*=\s*false", re.IGNORECASE)
_STORAGE_ENCRYPTED_TRUE_RE = re.compile(r"storage_encrypted\s*=\s*true", re.IGNORECASE)
_CLOUDWATCH_LOG_RE = re.compile(
    r"(?:enabled_cloudwatch_logs_exports|logging\s*\{|aws_cloudwatch_log_group)",
    re.IGNORECASE,
)
_SSH_KEY_INLINE_RE = re.compile(
    r"(?:public_key|private_key|ssh_key|key_material)\s*=\s*"
    r'"(ssh-rsa\s|ssh-ed25519\s|-----BEGIN)',
    re.IGNORECASE,
)

# TF-SEC-008: S3 bucket encryption (separate resource in TF AWS provider v4+)
_S3_SSE_BLOCK_RE = re.compile(r"server_side_encryption_configuration\s*\{", re.IGNORECASE)

# TF-SEC-009: Security group rule with 0.0.0.0/0
_CIDR_IPV6_ALL_RE = re.compile(r'ipv6_cidr_blocks\s*=\s*\[.*?"::/0".*?\]', re.DOTALL)

# TF-SEC-010: IAM wildcard patterns (HCL-style)
_IAM_HCL_STAR_RE = re.compile(r'(?:actions|resources)\s*=\s*\[.*?"\*".*?\]', re.DOTALL | re.IGNORECASE)

# TF-SEC-011: RDS storage encryption
_STORAGE_ENCRYPTED_RE = re.compile(r"storage_encrypted\s*=\s*(true|false)", re.IGNORECASE)

# TF-SEC-012: EC2 IMDSv2
_METADATA_OPTIONS_RE = re.compile(r"metadata_options\s*\{", re.IGNORECASE)
_HTTP_TOKENS_REQUIRED_RE = re.compile(r'http_tokens\s*=\s*"required"', re.IGNORECASE)

# TF-SEC-013: CloudWatch log group retention
_RETENTION_RE = re.compile(r"retention_in_days\s*=\s*(\d+)", re.IGNORECASE)

# TF-SEC-014: VPC flow logs
_FLOW_LOG_RE = re.compile(r"aws_flow_log", re.IGNORECASE)

# TF-SEC-015: EKS encryption config
_ENCRYPTION_CONFIG_BLOCK_RE = re.compile(r"encryption_config\s*\{", re.IGNORECASE)

# TF-SEC-016: Lambda dead letter config
_DEAD_LETTER_CONFIG_RE = re.compile(r"dead_letter_config\s*\{", re.IGNORECASE)

# TF-SEC-017: ElastiCache transit encryption
_TRANSIT_ENCRYPTION_RE = re.compile(r"transit_encryption_enabled\s*=\s*true", re.IGNORECASE)

# TF-SEC-018: DynamoDB PITR
_PITR_RE = re.compile(r"point_in_time_recovery\s*\{", re.IGNORECASE)
_PITR_ENABLED_RE = re.compile(r"enabled\s*=\s*true", re.IGNORECASE)

# TF-SEC-019: API Gateway access logging
_ACCESS_LOG_SETTINGS_RE = re.compile(r"access_log_settings\s*\{", re.IGNORECASE)

# TF-SEC-020: KMS key rotation
_KEY_ROTATION_RE = re.compile(r"enable_key_rotation\s*=\s*true", re.IGNORECASE)

# TF-SEC-021: S3 bucket versioning
_VERSIONING_RE = re.compile(r"versioning\s*\{", re.IGNORECASE)
_VERSIONING_ENABLED_RE = re.compile(r"enabled\s*=\s*true", re.IGNORECASE)

# TF-SEC-022: S3 public access block
_PUBLIC_ACCESS_BLOCK_RE = re.compile(r"aws_s3_bucket_public_access_block", re.IGNORECASE)

# TF-SEC-023: S3 bucket logging
_S3_LOGGING_RE = re.compile(r"logging\s*\{", re.IGNORECASE)

# TF-SEC-024: RDS public accessibility
_PUBLICLY_ACCESSIBLE_TRUE_RE = re.compile(r"publicly_accessible\s*=\s*true", re.IGNORECASE)

# TF-SEC-025: RDS backup retention
_BACKUP_RETENTION_RE = re.compile(r"backup_retention_period\s*=\s*(\d+)", re.IGNORECASE)

# TF-SEC-026: RDS multi-AZ
_MULTI_AZ_TRUE_RE = re.compile(r"multi_az\s*=\s*true", re.IGNORECASE)

# TF-SEC-027/028: EBS encryption
_EBS_ENCRYPTED_TRUE_RE = re.compile(r"encrypted\s*=\s*true", re.IGNORECASE)

# TF-SEC-029: ALB/ELB access logging
_LB_ACCESS_LOGS_RE = re.compile(r"access_logs\s*\{", re.IGNORECASE)
_LB_ACCESS_LOGS_ENABLED_RE = re.compile(r"enabled\s*=\s*true", re.IGNORECASE)

# TF-SEC-030: ALB/NLB deletion protection
_DELETION_PROTECTION_TRUE_RE = re.compile(r"enable_deletion_protection\s*=\s*true", re.IGNORECASE)

# TF-SEC-031: CloudTrail multi-region
_IS_MULTI_REGION_RE = re.compile(r"is_multi_region_trail\s*=\s*true", re.IGNORECASE)

# TF-SEC-032: CloudTrail log file validation
_LOG_FILE_VALIDATION_RE = re.compile(r"enable_log_file_validation\s*=\s*true", re.IGNORECASE)

# TF-SEC-033/034: SNS/SQS encryption
_KMS_MASTER_KEY_RE = re.compile(r"kms_master_key_id\s*=", re.IGNORECASE)

# TF-SEC-035: ECR scan on push
_SCAN_ON_PUSH_RE = re.compile(r"scan_on_push\s*=\s*true", re.IGNORECASE)
_IMAGE_SCANNING_RE = re.compile(r"image_scanning_configuration\s*\{", re.IGNORECASE)

# TF-SEC-036: ECR image tag mutability
_TAG_IMMUTABLE_RE = re.compile(r'image_tag_mutability\s*=\s*"IMMUTABLE"', re.IGNORECASE)

# TF-SEC-037: ECS host networking
_NETWORK_MODE_HOST_RE = re.compile(r'network_mode\s*=\s*"host"', re.IGNORECASE)

# TF-SEC-038: ECS running as root (user not set or user = root)
_USER_NONROOT_RE = re.compile(r'user\s*=\s*"(?!root)[^"]+', re.IGNORECASE)

# TF-SEC-039: Secrets Manager KMS
_SECRETS_KMS_RE = re.compile(r"kms_key_id\s*=", re.IGNORECASE)

# TF-SEC-040: SSM SecureString plaintext
_SSM_VALUE_RE = re.compile(r'type\s*=\s*"SecureString"', re.IGNORECASE)
_SSM_KEY_ID_RE = re.compile(r"key_id\s*=", re.IGNORECASE)

# TF-SEC-041: VPC default security group
_DEFAULT_SG_INGRESS_RE = re.compile(r"ingress\s*\{", re.IGNORECASE)
_DEFAULT_SG_EGRESS_RE = re.compile(r"egress\s*\{", re.IGNORECASE)

# TF-SEC-042: RDS deletion protection
_RDS_DELETION_PROTECTION_RE = re.compile(r"deletion_protection\s*=\s*true", re.IGNORECASE)

# TF-SEC-043: Elasticsearch/OpenSearch encryption at rest
_ENCRYPT_AT_REST_RE = re.compile(r"encrypt_at_rest\s*\{", re.IGNORECASE)
_ENCRYPT_AT_REST_ENABLED_RE = re.compile(r"enabled\s*=\s*true", re.IGNORECASE)

# TF-SEC-044: Elasticsearch/OpenSearch node-to-node encryption
_NODE_TO_NODE_RE = re.compile(r"node_to_node_encryption\s*\{", re.IGNORECASE)

# TF-SEC-045: Lambda VPC config
_VPC_CONFIG_RE = re.compile(r"vpc_config\s*\{", re.IGNORECASE)

# TF-SEC-046: Lambda sensitive env vars
_ENV_SENSITIVE_RE = re.compile(
    r'(?:password|secret|api_key|access_key|token|credential)\s*=\s*"[^"]+',
    re.IGNORECASE,
)

# TF-SEC-047: Redshift encryption
_REDSHIFT_ENCRYPTED_RE = re.compile(r"encrypted\s*=\s*true", re.IGNORECASE)

# TF-SEC-048: Redshift public access
_REDSHIFT_PUBLIC_RE = re.compile(r"publicly_accessible\s*=\s*true", re.IGNORECASE)

# TF-SEC-049: WAF association (file-level check)
_WAF_ASSOC_RE = re.compile(r"aws_wafv2_web_acl_association", re.IGNORECASE)

# TF-SEC-050: GuardDuty (file-level check)
_GUARDDUTY_RE = re.compile(r"aws_guardduty_detector", re.IGNORECASE)

# Non-standard ports (80 and 443 are typically fine for web traffic)
_WEB_PORTS = frozenset({80, 443})


def _extract_block(content: str, start: int) -> str:
    """Extract the body of a brace-delimited block starting at ``start`` (after ``{``)."""
    depth = 1
    pos = start
    while pos < len(content) and depth > 0:
        if content[pos] == "{":
            depth += 1
        elif content[pos] == "}":
            depth -= 1
        pos += 1
    return content[start : pos - 1]


def _line_number(content: str, pos: int) -> int:
    """Convert a character offset to a 1-based line number."""
    return content[:pos].count("\n") + 1


def scan_terraform_security(file_path: str | Path) -> list[IaCFinding]:
    """Scan a single .tf file for security misconfigurations.

    Parameters
    ----------
    file_path:
        Path to a Terraform file.

    Returns
    -------
    list[IaCFinding]
        Detected security misconfigurations.
    """
    path = Path(file_path)
    if not path.is_file() or path.suffix != ".tf":
        return []

    raw_content = path.read_text(encoding="utf-8", errors="replace")
    # Neutralise HCL comments to prevent false positives from commented-out
    # blocks.  We blank the comment text (rather than deleting it) so that
    # character offsets — and therefore _line_number() results — stay correct.
    # Multi-line: /* ... */  →  replace with same number of newlines
    def _blank_block_comment(m: re.Match[str]) -> str:
        return "\n" * m.group(0).count("\n")

    content = re.sub(r"/\*.*?\*/", _blank_block_comment, raw_content, flags=re.DOTALL)
    # Single-line: # ... or // ...  →  blank the line content but keep the newline
    content = re.sub(r"(?m)#.*$", "", content)
    content = re.sub(r"(?m)//.*$", "", content)
    rel_path = str(path)
    findings: list[IaCFinding] = []

    for m in _RESOURCE_RE.finditer(content):
        rtype = m.group(1)
        rname = m.group(2)
        # Find the opening brace after the resource declaration
        brace_pos = content.find("{", m.end())
        if brace_pos == -1:
            continue
        block = _extract_block(content, brace_pos + 1)
        block_start_line = _line_number(content, m.start())

        # TF-SEC-001 + TF-SEC-002: S3 bucket checks
        if rtype == "aws_s3_bucket":
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

        # TF-SEC-003: Security group with 0.0.0.0/0 on non-web ports
        if rtype == "aws_security_group":
            # Find ingress blocks within the security group
            for ingress_m in re.finditer(r"ingress\s*\{", block):
                ingress_block = _extract_block(block, ingress_m.end())
                if _CIDR_ALL_RE.search(ingress_block):
                    from_port_m = _FROM_PORT_RE.search(ingress_block)
                    to_port_m = _TO_PORT_RE.search(ingress_block)
                    from_port = int(from_port_m.group(1)) if from_port_m else 0
                    to_port = int(to_port_m.group(1)) if to_port_m else 65535
                    # If any non-web port in the range, flag it
                    port_range = set(range(from_port, to_port + 1))
                    if not port_range.issubset(_WEB_PORTS):
                        findings.append(
                            IaCFinding(
                                rule_id="TF-SEC-003",
                                severity="high",
                                title="Security group open to 0.0.0.0/0",
                                message=(
                                    f"Security group '{rname}' allows ingress from "
                                    f"0.0.0.0/0 on ports {from_port}-{to_port}. "
                                    "Restrict CIDR blocks to known IP ranges."
                                ),
                                file_path=rel_path,
                                line_number=block_start_line,
                                category="terraform",
                                compliance=["CIS-AWS-5.2", "NIST-AC-4"],
                            )
                        )

        # TF-SEC-004: IAM policy with wildcard
        if rtype in ("aws_iam_policy", "aws_iam_role_policy"):
            if _IAM_STAR_ACTION_RE.search(block):
                findings.append(
                    IaCFinding(
                        rule_id="TF-SEC-004",
                        severity="high",
                        title='IAM policy with Action: "*"',
                        message=(
                            f"IAM policy '{rname}' grants Action: \"*\". "
                            "Follow least-privilege: scope actions to specific "
                            "services and operations."
                        ),
                        file_path=rel_path,
                        line_number=block_start_line,
                        category="terraform",
                        compliance=["CIS-AWS-1.16", "NIST-AC-6"],
                    )
                )
            if _IAM_STAR_RESOURCE_RE.search(block):
                findings.append(
                    IaCFinding(
                        rule_id="TF-SEC-004",
                        severity="high",
                        title='IAM policy with Resource: "*"',
                        message=(f"IAM policy '{rname}' grants Resource: \"*\". Scope resources to specific ARNs."),
                        file_path=rel_path,
                        line_number=block_start_line,
                        category="terraform",
                        compliance=["CIS-AWS-1.16", "NIST-AC-6"],
                    )
                )

        # TF-SEC-005: RDS without encryption
        if rtype in ("aws_db_instance", "aws_rds_cluster"):
            if _STORAGE_ENCRYPTED_FALSE_RE.search(block):
                findings.append(
                    IaCFinding(
                        rule_id="TF-SEC-005",
                        severity="medium",
                        title="RDS without encryption",
                        message=(f"RDS instance '{rname}' has storage_encrypted = false. Enable encryption at rest for database storage."),
                        file_path=rel_path,
                        line_number=block_start_line,
                        category="terraform",
                        compliance=["CIS-AWS-2.3.1", "NIST-SC-28"],
                    )
                )
            elif not _STORAGE_ENCRYPTED_TRUE_RE.search(block):
                findings.append(
                    IaCFinding(
                        rule_id="TF-SEC-005",
                        severity="medium",
                        title="RDS encryption not configured",
                        message=(
                            f"RDS instance '{rname}' does not set storage_encrypted. Add storage_encrypted = true to encrypt data at rest."
                        ),
                        file_path=rel_path,
                        line_number=block_start_line,
                        category="terraform",
                        compliance=["CIS-AWS-2.3.1", "NIST-SC-28"],
                    )
                )

        # TF-SEC-006: CloudWatch logging
        if rtype in ("aws_db_instance", "aws_rds_cluster", "aws_elasticsearch_domain"):
            if not _CLOUDWATCH_LOG_RE.search(block):
                findings.append(
                    IaCFinding(
                        rule_id="TF-SEC-006",
                        severity="medium",
                        title="CloudWatch logging not enabled",
                        message=(
                            f"Resource '{rname}' ({rtype}) does not configure "
                            "CloudWatch log exports. Enable logging for audit "
                            "and incident response."
                        ),
                        file_path=rel_path,
                        line_number=block_start_line,
                        category="terraform",
                        compliance=["CIS-AWS-3.1", "NIST-AU-2"],
                    )
                )

        # TF-SEC-007: Hardcoded SSH key
        ssh_m = _SSH_KEY_INLINE_RE.search(block)
        if ssh_m:
            findings.append(
                IaCFinding(
                    rule_id="TF-SEC-007",
                    severity="high",
                    title="Hardcoded SSH key",
                    message=(
                        f"Resource '{rname}' ({rtype}) contains a hardcoded SSH key. "
                        "Store keys in a secrets manager or use file() with a "
                        "gitignored key file."
                    ),
                    file_path=rel_path,
                    line_number=block_start_line,
                    category="terraform",
                    compliance=["CIS-AWS-1.14", "NIST-IA-5"],
                )
            )

        # TF-SEC-008: S3 bucket without server-side encryption
        if rtype == "aws_s3_bucket":
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

        # TF-SEC-009: Security group rule with 0.0.0.0/0
        if rtype == "aws_security_group_rule":
            if _CIDR_ALL_RE.search(block) or _CIDR_IPV6_ALL_RE.search(block):
                findings.append(
                    IaCFinding(
                        rule_id="TF-SEC-009",
                        severity="high",
                        title="Security group rule with 0.0.0.0/0",
                        message=(
                            f"Security group rule '{rname}' allows traffic from 0.0.0.0/0 or ::/0. Restrict CIDR blocks to known IP ranges."
                        ),
                        file_path=rel_path,
                        line_number=block_start_line,
                        category="terraform",
                        compliance=["CIS-AWS-5.2", "NIST-AC-4"],
                    )
                )

        # TF-SEC-010: IAM policy with wildcards
        if rtype in ("aws_iam_policy", "aws_iam_role_policy", "aws_iam_group_policy", "aws_iam_user_policy"):
            if _IAM_STAR_ACTION_RE.search(block) or _IAM_STAR_RESOURCE_RE.search(block) or _IAM_HCL_STAR_RE.search(block):
                findings.append(
                    IaCFinding(
                        rule_id="TF-SEC-010",
                        severity="high",
                        title="IAM policy with wildcards",
                        message=(
                            f"IAM policy '{rname}' contains wildcard permissions. "
                            "Follow least-privilege: scope actions and resources "
                            "to specific services and ARNs."
                        ),
                        file_path=rel_path,
                        line_number=block_start_line,
                        category="terraform",
                        compliance=["CIS-AWS-1.16", "NIST-AC-6"],
                    )
                )

        # TF-SEC-011: RDS without storage encryption
        if rtype in ("aws_db_instance", "aws_rds_cluster"):
            enc_m = _STORAGE_ENCRYPTED_RE.search(block)
            if not enc_m or enc_m.group(1).lower() == "false":
                findings.append(
                    IaCFinding(
                        rule_id="TF-SEC-011",
                        severity="high",
                        title="RDS without storage encryption",
                        message=(
                            f"RDS resource '{rname}' ({rtype}) does not have "
                            "storage_encrypted = true. Enable encryption at rest "
                            "for database storage."
                        ),
                        file_path=rel_path,
                        line_number=block_start_line,
                        category="terraform",
                        compliance=["CIS-AWS-2.3.1", "NIST-SC-28"],
                    )
                )

        # TF-SEC-012: EC2 instance without IMDSv2
        if rtype == "aws_instance":
            metadata_m = _METADATA_OPTIONS_RE.search(block)
            if metadata_m:
                metadata_block = _extract_block(block, metadata_m.end())
                if not _HTTP_TOKENS_REQUIRED_RE.search(metadata_block):
                    findings.append(
                        IaCFinding(
                            rule_id="TF-SEC-012",
                            severity="high",
                            title="EC2 instance without IMDSv2",
                            message=(
                                f"EC2 instance '{rname}' does not enforce IMDSv2 "
                                '(http_tokens = "required"). IMDSv1 is vulnerable to '
                                'SSRF attacks. Set http_tokens = "required".'
                            ),
                            file_path=rel_path,
                            line_number=block_start_line,
                            category="terraform",
                            compliance=["CIS-AWS-5.6", "NIST-AC-3"],
                        )
                    )
            else:
                findings.append(
                    IaCFinding(
                        rule_id="TF-SEC-012",
                        severity="high",
                        title="EC2 instance without IMDSv2",
                        message=(
                            f"EC2 instance '{rname}' has no metadata_options block. "
                            'Add metadata_options with http_tokens = "required" '
                            "to enforce IMDSv2."
                        ),
                        file_path=rel_path,
                        line_number=block_start_line,
                        category="terraform",
                        compliance=["CIS-AWS-5.6", "NIST-AC-3"],
                    )
                )

        # TF-SEC-013: CloudWatch log group without retention
        if rtype == "aws_cloudwatch_log_group":
            retention_m = _RETENTION_RE.search(block)
            if not retention_m:
                findings.append(
                    IaCFinding(
                        rule_id="TF-SEC-013",
                        severity="medium",
                        title="CloudWatch log group without retention",
                        message=(
                            f"CloudWatch log group '{rname}' does not set "
                            "retention_in_days. Logs will be retained indefinitely, "
                            "increasing costs. Set a retention period."
                        ),
                        file_path=rel_path,
                        line_number=block_start_line,
                        category="terraform",
                        compliance=["CIS-AWS-3.1", "NIST-AU-11"],
                    )
                )

        # TF-SEC-014: VPC without flow logs
        if rtype == "aws_vpc":
            # Check if there's a corresponding aws_flow_log resource in the file
            if not _FLOW_LOG_RE.search(content):
                findings.append(
                    IaCFinding(
                        rule_id="TF-SEC-014",
                        severity="medium",
                        title="VPC without flow logs",
                        message=(
                            f"VPC '{rname}' does not have an associated "
                            "aws_flow_log resource in this file. Enable VPC Flow "
                            "Logs for network traffic monitoring."
                        ),
                        file_path=rel_path,
                        line_number=block_start_line,
                        category="terraform",
                        compliance=["CIS-AWS-3.9", "NIST-AU-2", "NIST-SI-4"],
                    )
                )

        # TF-SEC-015: EKS cluster without envelope encryption
        if rtype == "aws_eks_cluster":
            if not _ENCRYPTION_CONFIG_BLOCK_RE.search(block):
                findings.append(
                    IaCFinding(
                        rule_id="TF-SEC-015",
                        severity="high",
                        title="EKS cluster without envelope encryption",
                        message=(
                            f"EKS cluster '{rname}' does not have an "
                            "encryption_config block. Enable envelope encryption "
                            "of Kubernetes secrets with a KMS key."
                        ),
                        file_path=rel_path,
                        line_number=block_start_line,
                        category="terraform",
                        compliance=["NIST-SC-28", "NIST-SC-12"],
                    )
                )

        # TF-SEC-016: Lambda without dead letter queue
        if rtype == "aws_lambda_function":
            if not _DEAD_LETTER_CONFIG_RE.search(block):
                findings.append(
                    IaCFinding(
                        rule_id="TF-SEC-016",
                        severity="medium",
                        title="Lambda without dead letter queue",
                        message=(
                            f"Lambda function '{rname}' does not have a "
                            "dead_letter_config block. Configure a dead letter "
                            "queue (SQS/SNS) to capture failed invocations."
                        ),
                        file_path=rel_path,
                        line_number=block_start_line,
                        category="terraform",
                        compliance=["NIST-SI-11"],
                    )
                )

        # TF-SEC-017: ElastiCache without encryption in transit
        if rtype in ("aws_elasticache_replication_group", "aws_elasticache_cluster"):
            if not _TRANSIT_ENCRYPTION_RE.search(block):
                findings.append(
                    IaCFinding(
                        rule_id="TF-SEC-017",
                        severity="high",
                        title="ElastiCache without encryption in transit",
                        message=(
                            f"ElastiCache resource '{rname}' ({rtype}) does not set "
                            "transit_encryption_enabled = true. Enable encryption "
                            "in transit to protect data on the wire."
                        ),
                        file_path=rel_path,
                        line_number=block_start_line,
                        category="terraform",
                        compliance=["NIST-SC-8", "NIST-SC-28"],
                    )
                )

        # TF-SEC-018: DynamoDB without point-in-time recovery
        if rtype == "aws_dynamodb_table":
            pitr_m = _PITR_RE.search(block)
            if pitr_m:
                pitr_block = _extract_block(block, pitr_m.end())
                if not _PITR_ENABLED_RE.search(pitr_block):
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

        # TF-SEC-019: API Gateway without access logging
        if rtype in ("aws_api_gateway_stage", "aws_apigatewayv2_stage"):
            if not _ACCESS_LOG_SETTINGS_RE.search(block):
                findings.append(
                    IaCFinding(
                        rule_id="TF-SEC-019",
                        severity="medium",
                        title="API Gateway without access logging",
                        message=(
                            f"API Gateway stage '{rname}' ({rtype}) does not have "
                            "an access_log_settings block. Enable access logging "
                            "for API monitoring and compliance."
                        ),
                        file_path=rel_path,
                        line_number=block_start_line,
                        category="terraform",
                        compliance=["NIST-AU-2", "NIST-SI-4"],
                    )
                )

        # TF-SEC-020: KMS key without rotation
        if rtype == "aws_kms_key":
            if not _KEY_ROTATION_RE.search(block):
                findings.append(
                    IaCFinding(
                        rule_id="TF-SEC-020",
                        severity="medium",
                        title="KMS key without rotation",
                        message=(
                            f"KMS key '{rname}' does not set "
                            "enable_key_rotation = true. Enable automatic key "
                            "rotation to reduce risk of key compromise."
                        ),
                        file_path=rel_path,
                        line_number=block_start_line,
                        category="terraform",
                        compliance=["CIS-AWS-3.8", "NIST-SC-12"],
                    )
                )

        # TF-SEC-021: S3 bucket versioning not enabled
        if rtype == "aws_s3_bucket":
            versioning_m = _VERSIONING_RE.search(block)
            if versioning_m:
                v_block = _extract_block(block, versioning_m.end())
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

        # TF-SEC-022: S3 bucket public access block missing
        if rtype == "aws_s3_bucket":
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

        # TF-SEC-023: S3 bucket logging not enabled
        if rtype == "aws_s3_bucket":
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

        # TF-SEC-024: RDS public accessibility enabled
        if rtype in ("aws_db_instance", "aws_rds_cluster"):
            if _PUBLICLY_ACCESSIBLE_TRUE_RE.search(block):
                findings.append(
                    IaCFinding(
                        rule_id="TF-SEC-024",
                        severity="critical",
                        title="RDS public accessibility enabled",
                        message=(
                            f"RDS instance '{rname}' has publicly_accessible = true. "
                            "Databases should not be directly accessible from the "
                            "internet. Set publicly_accessible = false."
                        ),
                        file_path=rel_path,
                        line_number=block_start_line,
                        category="terraform",
                        compliance=["CIS-AWS-2.3.2", "NIST-AC-4"],
                    )
                )

        # TF-SEC-025: RDS backup retention period < 7 days
        if rtype in ("aws_db_instance", "aws_rds_cluster"):
            retention_m = _BACKUP_RETENTION_RE.search(block)
            if retention_m:
                days = int(retention_m.group(1))
                if days < 7:
                    findings.append(
                        IaCFinding(
                            rule_id="TF-SEC-025",
                            severity="medium",
                            title="RDS backup retention period too short",
                            message=(
                                f"RDS instance '{rname}' has "
                                f"backup_retention_period = {days}. Set to at least "
                                "7 days for adequate disaster recovery."
                            ),
                            file_path=rel_path,
                            line_number=block_start_line,
                            category="terraform",
                            compliance=["CIS-AWS-2.3.3", "NIST-CP-9"],
                        )
                    )
            else:
                findings.append(
                    IaCFinding(
                        rule_id="TF-SEC-025",
                        severity="medium",
                        title="RDS backup retention period not configured",
                        message=(
                            f"RDS instance '{rname}' does not set "
                            "backup_retention_period. Default may be 0 (no "
                            "backups). Set to at least 7 days."
                        ),
                        file_path=rel_path,
                        line_number=block_start_line,
                        category="terraform",
                        compliance=["CIS-AWS-2.3.3", "NIST-CP-9"],
                    )
                )

        # TF-SEC-026: RDS multi-AZ not enabled
        if rtype == "aws_db_instance":
            if not _MULTI_AZ_TRUE_RE.search(block):
                findings.append(
                    IaCFinding(
                        rule_id="TF-SEC-026",
                        severity="medium",
                        title="RDS multi-AZ not enabled",
                        message=(
                            f"RDS instance '{rname}' does not have multi_az = true. "
                            "Enable multi-AZ deployment for high availability and "
                            "automatic failover."
                        ),
                        file_path=rel_path,
                        line_number=block_start_line,
                        category="terraform",
                        compliance=["NIST-CP-10", "NIST-SC-36"],
                    )
                )

        # TF-SEC-027: EBS volume not encrypted
        if rtype == "aws_ebs_volume":
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

        # TF-SEC-028: EBS snapshot not encrypted
        if rtype == "aws_ebs_snapshot":
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

        # TF-SEC-029: ALB/ELB access logging not enabled
        if rtype in ("aws_lb", "aws_alb", "aws_elb"):
            al_m = _LB_ACCESS_LOGS_RE.search(block)
            if al_m:
                al_block = _extract_block(block, al_m.end())
                if not _LB_ACCESS_LOGS_ENABLED_RE.search(al_block):
                    findings.append(
                        IaCFinding(
                            rule_id="TF-SEC-029",
                            severity="medium",
                            title="Load balancer access logging not enabled",
                            message=(
                                f"Load balancer '{rname}' has access_logs block but "
                                "enabled is not true. Enable access logging for "
                                "security monitoring and compliance."
                            ),
                            file_path=rel_path,
                            line_number=block_start_line,
                            category="terraform",
                            compliance=["CIS-AWS-3.10", "NIST-AU-2"],
                        )
                    )
            else:
                findings.append(
                    IaCFinding(
                        rule_id="TF-SEC-029",
                        severity="medium",
                        title="Load balancer access logging not enabled",
                        message=(
                            f"Load balancer '{rname}' ({rtype}) does not have an "
                            "access_logs block. Enable access logging for security "
                            "monitoring and compliance."
                        ),
                        file_path=rel_path,
                        line_number=block_start_line,
                        category="terraform",
                        compliance=["CIS-AWS-3.10", "NIST-AU-2"],
                    )
                )

        # TF-SEC-030: ALB/NLB deletion protection disabled
        if rtype in ("aws_lb", "aws_alb"):
            if not _DELETION_PROTECTION_TRUE_RE.search(block):
                findings.append(
                    IaCFinding(
                        rule_id="TF-SEC-030",
                        severity="medium",
                        title="Load balancer deletion protection disabled",
                        message=(
                            f"Load balancer '{rname}' does not have "
                            "enable_deletion_protection = true. Enable deletion "
                            "protection to prevent accidental removal."
                        ),
                        file_path=rel_path,
                        line_number=block_start_line,
                        category="terraform",
                        compliance=["NIST-CP-9"],
                    )
                )

        # TF-SEC-031: CloudTrail not enabled for all regions
        if rtype == "aws_cloudtrail":
            if not _IS_MULTI_REGION_RE.search(block):
                findings.append(
                    IaCFinding(
                        rule_id="TF-SEC-031",
                        severity="high",
                        title="CloudTrail not enabled for all regions",
                        message=(
                            f"CloudTrail '{rname}' does not have "
                            "is_multi_region_trail = true. Enable multi-region "
                            "trailing to capture API calls in all AWS regions."
                        ),
                        file_path=rel_path,
                        line_number=block_start_line,
                        category="terraform",
                        compliance=["CIS-AWS-3.1", "NIST-AU-2"],
                    )
                )

        # TF-SEC-032: CloudTrail log file validation disabled
        if rtype == "aws_cloudtrail":
            if not _LOG_FILE_VALIDATION_RE.search(block):
                findings.append(
                    IaCFinding(
                        rule_id="TF-SEC-032",
                        severity="medium",
                        title="CloudTrail log file validation disabled",
                        message=(
                            f"CloudTrail '{rname}' does not have "
                            "enable_log_file_validation = true. Enable log file "
                            "validation to detect tampering of log files."
                        ),
                        file_path=rel_path,
                        line_number=block_start_line,
                        category="terraform",
                        compliance=["CIS-AWS-3.2", "NIST-AU-9"],
                    )
                )

        # TF-SEC-033: SNS topic not encrypted
        if rtype == "aws_sns_topic":
            if not _KMS_MASTER_KEY_RE.search(block):
                findings.append(
                    IaCFinding(
                        rule_id="TF-SEC-033",
                        severity="medium",
                        title="SNS topic not encrypted",
                        message=(
                            f"SNS topic '{rname}' does not have "
                            "kms_master_key_id set. Enable server-side encryption "
                            "with a KMS key to protect messages at rest."
                        ),
                        file_path=rel_path,
                        line_number=block_start_line,
                        category="terraform",
                        compliance=["CIS-AWS-2.5", "NIST-SC-28"],
                    )
                )

        # TF-SEC-034: SQS queue not encrypted
        if rtype == "aws_sqs_queue":
            if not _KMS_MASTER_KEY_RE.search(block):
                findings.append(
                    IaCFinding(
                        rule_id="TF-SEC-034",
                        severity="medium",
                        title="SQS queue not encrypted",
                        message=(
                            f"SQS queue '{rname}' does not have "
                            "kms_master_key_id set. Enable server-side encryption "
                            "with a KMS key to protect messages at rest."
                        ),
                        file_path=rel_path,
                        line_number=block_start_line,
                        category="terraform",
                        compliance=["CIS-AWS-2.6", "NIST-SC-28"],
                    )
                )

        # TF-SEC-035: ECR repository scan on push disabled
        if rtype == "aws_ecr_repository":
            scan_m = _IMAGE_SCANNING_RE.search(block)
            if scan_m:
                scan_block = _extract_block(block, scan_m.end())
                if not _SCAN_ON_PUSH_RE.search(scan_block):
                    findings.append(
                        IaCFinding(
                            rule_id="TF-SEC-035",
                            severity="medium",
                            title="ECR scan on push disabled",
                            message=(
                                f"ECR repository '{rname}' has "
                                "image_scanning_configuration but scan_on_push is "
                                "not true. Enable scan on push to detect "
                                "vulnerabilities in container images."
                            ),
                            file_path=rel_path,
                            line_number=block_start_line,
                            category="terraform",
                            compliance=["NIST-RA-5", "NIST-SI-2"],
                        )
                    )
            else:
                findings.append(
                    IaCFinding(
                        rule_id="TF-SEC-035",
                        severity="medium",
                        title="ECR scan on push disabled",
                        message=(
                            f"ECR repository '{rname}' does not have an "
                            "image_scanning_configuration block. Enable scan on "
                            "push to detect vulnerabilities in container images."
                        ),
                        file_path=rel_path,
                        line_number=block_start_line,
                        category="terraform",
                        compliance=["NIST-RA-5", "NIST-SI-2"],
                    )
                )

        # TF-SEC-036: ECR image tag mutability enabled
        if rtype == "aws_ecr_repository":
            if not _TAG_IMMUTABLE_RE.search(block):
                findings.append(
                    IaCFinding(
                        rule_id="TF-SEC-036",
                        severity="medium",
                        title="ECR image tag mutability enabled",
                        message=(
                            f"ECR repository '{rname}' does not set "
                            'image_tag_mutability = "IMMUTABLE". Mutable tags '
                            "allow image replacement, which can introduce supply "
                            "chain risks."
                        ),
                        file_path=rel_path,
                        line_number=block_start_line,
                        category="terraform",
                        compliance=["NIST-SI-7", "NIST-SA-10"],
                    )
                )

        # TF-SEC-037: ECS task definition with host networking
        if rtype == "aws_ecs_task_definition":
            if _NETWORK_MODE_HOST_RE.search(block):
                findings.append(
                    IaCFinding(
                        rule_id="TF-SEC-037",
                        severity="high",
                        title="ECS task definition with host networking",
                        message=(
                            f"ECS task definition '{rname}' uses "
                            'network_mode = "host". Host networking bypasses '
                            "container network isolation. Use awsvpc or bridge "
                            "mode instead."
                        ),
                        file_path=rel_path,
                        line_number=block_start_line,
                        category="terraform",
                        compliance=["NIST-AC-4", "NIST-SC-7"],
                    )
                )

        # TF-SEC-038: ECS task definition running as root
        if rtype == "aws_ecs_task_definition":
            # Check container definitions for user field
            if not _USER_NONROOT_RE.search(block):
                findings.append(
                    IaCFinding(
                        rule_id="TF-SEC-038",
                        severity="high",
                        title="ECS task definition running as root",
                        message=(
                            f"ECS task definition '{rname}' does not specify a "
                            "non-root user. Running containers as root increases "
                            "the blast radius of container escapes. Set a non-root "
                            "user in the container definition."
                        ),
                        file_path=rel_path,
                        line_number=block_start_line,
                        category="terraform",
                        compliance=["NIST-AC-6", "NIST-CM-7"],
                    )
                )

        # TF-SEC-039: Secrets Manager secret without KMS encryption
        if rtype == "aws_secretsmanager_secret":
            if not _SECRETS_KMS_RE.search(block):
                findings.append(
                    IaCFinding(
                        rule_id="TF-SEC-039",
                        severity="medium",
                        title="Secrets Manager secret without KMS encryption",
                        message=(
                            f"Secrets Manager secret '{rname}' does not set "
                            "kms_key_id. Without a customer-managed KMS key, "
                            "the secret is encrypted with the default AWS key. "
                            "Use a CMK for better key management and audit trail."
                        ),
                        file_path=rel_path,
                        line_number=block_start_line,
                        category="terraform",
                        compliance=["NIST-SC-12", "NIST-SC-28"],
                    )
                )

        # TF-SEC-040: SSM Parameter with plaintext SecureString
        if rtype == "aws_ssm_parameter":
            if _SSM_VALUE_RE.search(block) and not _SSM_KEY_ID_RE.search(block):
                findings.append(
                    IaCFinding(
                        rule_id="TF-SEC-040",
                        severity="medium",
                        title="SSM SecureString without CMK encryption",
                        message=(
                            f"SSM parameter '{rname}' is a SecureString but does "
                            "not specify key_id for a customer-managed KMS key. "
                            "Use a CMK for enhanced encryption control."
                        ),
                        file_path=rel_path,
                        line_number=block_start_line,
                        category="terraform",
                        compliance=["NIST-SC-12", "NIST-SC-28"],
                    )
                )

        # TF-SEC-041: VPC default security group allows traffic
        if rtype == "aws_default_security_group":
            if _DEFAULT_SG_INGRESS_RE.search(block) or _DEFAULT_SG_EGRESS_RE.search(block):
                findings.append(
                    IaCFinding(
                        rule_id="TF-SEC-041",
                        severity="high",
                        title="VPC default security group allows traffic",
                        message=(
                            f"Default security group '{rname}' has ingress or "
                            "egress rules defined. The VPC default security group "
                            "should have no rules to ensure all traffic goes "
                            "through explicitly managed security groups."
                        ),
                        file_path=rel_path,
                        line_number=block_start_line,
                        category="terraform",
                        compliance=["CIS-AWS-5.3", "NIST-AC-4"],
                    )
                )

        # TF-SEC-042: RDS instance without deletion protection
        if rtype in ("aws_db_instance", "aws_rds_cluster"):
            if not _RDS_DELETION_PROTECTION_RE.search(block):
                findings.append(
                    IaCFinding(
                        rule_id="TF-SEC-042",
                        severity="medium",
                        title="RDS instance without deletion protection",
                        message=(
                            f"RDS resource '{rname}' does not have "
                            "deletion_protection = true. Enable deletion "
                            "protection to prevent accidental database removal."
                        ),
                        file_path=rel_path,
                        line_number=block_start_line,
                        category="terraform",
                        compliance=["NIST-CP-9", "NIST-SC-28"],
                    )
                )

        # TF-SEC-043: Elasticsearch/OpenSearch without encryption at rest
        if rtype in ("aws_elasticsearch_domain", "aws_opensearch_domain"):
            enc_m = _ENCRYPT_AT_REST_RE.search(block)
            if enc_m:
                enc_block = _extract_block(block, enc_m.end())
                if not _ENCRYPT_AT_REST_ENABLED_RE.search(enc_block):
                    findings.append(
                        IaCFinding(
                            rule_id="TF-SEC-043",
                            severity="high",
                            title="Elasticsearch/OpenSearch without encryption at rest",
                            message=(
                                f"Domain '{rname}' ({rtype}) has encrypt_at_rest "
                                "block but enabled is not true. Enable encryption "
                                "at rest to protect stored data."
                            ),
                            file_path=rel_path,
                            line_number=block_start_line,
                            category="terraform",
                            compliance=["NIST-SC-28"],
                        )
                    )
            else:
                findings.append(
                    IaCFinding(
                        rule_id="TF-SEC-043",
                        severity="high",
                        title="Elasticsearch/OpenSearch without encryption at rest",
                        message=(
                            f"Domain '{rname}' ({rtype}) does not have an "
                            "encrypt_at_rest block. Enable encryption at rest "
                            "to protect stored data."
                        ),
                        file_path=rel_path,
                        line_number=block_start_line,
                        category="terraform",
                        compliance=["NIST-SC-28"],
                    )
                )

        # TF-SEC-044: Elasticsearch/OpenSearch without node-to-node encryption
        if rtype in ("aws_elasticsearch_domain", "aws_opensearch_domain"):
            n2n_m = _NODE_TO_NODE_RE.search(block)
            if n2n_m:
                n2n_block = _extract_block(block, n2n_m.end())
                if not _PITR_ENABLED_RE.search(n2n_block):  # reuse enabled=true check
                    findings.append(
                        IaCFinding(
                            rule_id="TF-SEC-044",
                            severity="high",
                            title="Elasticsearch/OpenSearch without node-to-node encryption",
                            message=(
                                f"Domain '{rname}' ({rtype}) has "
                                "node_to_node_encryption block but enabled is not "
                                "true. Enable node-to-node encryption to protect "
                                "data in transit between nodes."
                            ),
                            file_path=rel_path,
                            line_number=block_start_line,
                            category="terraform",
                            compliance=["NIST-SC-8"],
                        )
                    )
            else:
                findings.append(
                    IaCFinding(
                        rule_id="TF-SEC-044",
                        severity="high",
                        title="Elasticsearch/OpenSearch without node-to-node encryption",
                        message=(
                            f"Domain '{rname}' ({rtype}) does not have a "
                            "node_to_node_encryption block. Enable node-to-node "
                            "encryption to protect data in transit between nodes."
                        ),
                        file_path=rel_path,
                        line_number=block_start_line,
                        category="terraform",
                        compliance=["NIST-SC-8"],
                    )
                )

        # TF-SEC-045: Lambda function without VPC configuration
        if rtype == "aws_lambda_function":
            if not _VPC_CONFIG_RE.search(block):
                findings.append(
                    IaCFinding(
                        rule_id="TF-SEC-045",
                        severity="low",
                        title="Lambda function without VPC configuration",
                        message=(
                            f"Lambda function '{rname}' does not have a "
                            "vpc_config block. Consider placing the function in "
                            "a VPC if it accesses private resources."
                        ),
                        file_path=rel_path,
                        line_number=block_start_line,
                        category="terraform",
                        compliance=["NIST-AC-4", "NIST-SC-7"],
                    )
                )

        # TF-SEC-046: Lambda environment variables with sensitive values
        if rtype == "aws_lambda_function":
            if _ENV_SENSITIVE_RE.search(block):
                findings.append(
                    IaCFinding(
                        rule_id="TF-SEC-046",
                        severity="critical",
                        title="Lambda environment variables with sensitive values",
                        message=(
                            f"Lambda function '{rname}' appears to have sensitive "
                            "values (password, secret, api_key, token) in "
                            "environment variables. Use AWS Secrets Manager or "
                            "SSM Parameter Store instead."
                        ),
                        file_path=rel_path,
                        line_number=block_start_line,
                        category="terraform",
                        compliance=["NIST-IA-5", "NIST-SC-28"],
                    )
                )

        # TF-SEC-047: Redshift cluster without encryption
        if rtype == "aws_redshift_cluster":
            if not _REDSHIFT_ENCRYPTED_RE.search(block):
                findings.append(
                    IaCFinding(
                        rule_id="TF-SEC-047",
                        severity="high",
                        title="Redshift cluster without encryption",
                        message=(
                            f"Redshift cluster '{rname}' does not have "
                            "encrypted = true. Enable encryption at rest to "
                            "protect data warehouse contents."
                        ),
                        file_path=rel_path,
                        line_number=block_start_line,
                        category="terraform",
                        compliance=["CIS-AWS-2.7", "NIST-SC-28"],
                    )
                )

        # TF-SEC-048: Redshift cluster publicly accessible
        if rtype == "aws_redshift_cluster":
            if _REDSHIFT_PUBLIC_RE.search(block):
                findings.append(
                    IaCFinding(
                        rule_id="TF-SEC-048",
                        severity="critical",
                        title="Redshift cluster publicly accessible",
                        message=(
                            f"Redshift cluster '{rname}' has "
                            "publicly_accessible = true. Data warehouses should "
                            "not be directly accessible from the internet. Set "
                            "publicly_accessible = false."
                        ),
                        file_path=rel_path,
                        line_number=block_start_line,
                        category="terraform",
                        compliance=["NIST-AC-4", "NIST-SC-7"],
                    )
                )

        # TF-SEC-049: WAF not associated with ALB/CloudFront
        if rtype in ("aws_lb", "aws_alb", "aws_cloudfront_distribution"):
            if not _WAF_ASSOC_RE.search(content):
                findings.append(
                    IaCFinding(
                        rule_id="TF-SEC-049",
                        severity="medium",
                        title="WAF not associated with resource",
                        message=(
                            f"Resource '{rname}' ({rtype}) does not have an "
                            "associated aws_wafv2_web_acl_association in this "
                            "file. Attach a WAF web ACL to protect against "
                            "common web exploits."
                        ),
                        file_path=rel_path,
                        line_number=block_start_line,
                        category="terraform",
                        compliance=["NIST-SC-7", "NIST-SI-4"],
                    )
                )

        # TF-SEC-050: GuardDuty not enabled
        if rtype == "aws_guardduty_detector":
            # Check if enable is explicitly set to false
            enable_false_m = re.search(r"enable\s*=\s*false", block, re.IGNORECASE)
            if enable_false_m:
                findings.append(
                    IaCFinding(
                        rule_id="TF-SEC-050",
                        severity="high",
                        title="GuardDuty detector disabled",
                        message=(
                            f"GuardDuty detector '{rname}' has enable = false. "
                            "Enable GuardDuty for continuous threat detection "
                            "and monitoring of malicious activity."
                        ),
                        file_path=rel_path,
                        line_number=block_start_line,
                        category="terraform",
                        compliance=["CIS-AWS-4.1", "NIST-SI-4"],
                    )
                )

    return findings
