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

    content = path.read_text(encoding="utf-8", errors="replace")
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

    return findings
