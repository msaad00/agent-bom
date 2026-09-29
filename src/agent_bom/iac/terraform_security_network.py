"""Terraform security rules for AWS network and compute (security groups, EC2, VPC, load balancers, Lambda, ECS, ECR, EKS)."""

from __future__ import annotations

import re

from agent_bom.iac.models import IaCFinding
from agent_bom.iac.terraform_security_common import TfResource, extract_block

_CIDR_ALL_RE = re.compile(r'cidr_blocks\s*=\s*\[.*?"0\.0\.0\.0/0".*?\]', re.DOTALL)
_FROM_PORT_RE = re.compile(r"from_port\s*=\s*(\d+)")
_TO_PORT_RE = re.compile(r"to_port\s*=\s*(\d+)")

# TF-SEC-009: Security group rule with 0.0.0.0/0
_CIDR_IPV6_ALL_RE = re.compile(r'ipv6_cidr_blocks\s*=\s*\[.*?"::/0".*?\]', re.DOTALL)

# TF-SEC-012: EC2 IMDSv2
_METADATA_OPTIONS_RE = re.compile(r"metadata_options\s*\{", re.IGNORECASE)
_HTTP_TOKENS_REQUIRED_RE = re.compile(r'http_tokens\s*=\s*"required"', re.IGNORECASE)

# TF-SEC-014: VPC flow logs
_FLOW_LOG_RE = re.compile(r"aws_flow_log", re.IGNORECASE)

# TF-SEC-015: EKS encryption config
_ENCRYPTION_CONFIG_BLOCK_RE = re.compile(r"encryption_config\s*\{", re.IGNORECASE)

# TF-SEC-016: Lambda dead letter config
_DEAD_LETTER_CONFIG_RE = re.compile(r"dead_letter_config\s*\{", re.IGNORECASE)

# TF-SEC-029: ALB/ELB access logging
_LB_ACCESS_LOGS_RE = re.compile(r"access_logs\s*\{", re.IGNORECASE)
_LB_ACCESS_LOGS_ENABLED_RE = re.compile(r"enabled\s*=\s*true", re.IGNORECASE)

# TF-SEC-030: ALB/NLB deletion protection
_DELETION_PROTECTION_TRUE_RE = re.compile(r"enable_deletion_protection\s*=\s*true", re.IGNORECASE)

# TF-SEC-035: ECR scan on push
_SCAN_ON_PUSH_RE = re.compile(r"scan_on_push\s*=\s*true", re.IGNORECASE)
_IMAGE_SCANNING_RE = re.compile(r"image_scanning_configuration\s*\{", re.IGNORECASE)

# TF-SEC-036: ECR image tag mutability
_TAG_IMMUTABLE_RE = re.compile(r'image_tag_mutability\s*=\s*"IMMUTABLE"', re.IGNORECASE)

# TF-SEC-037: ECS host networking
_NETWORK_MODE_HOST_RE = re.compile(r'network_mode\s*=\s*"host"', re.IGNORECASE)

# TF-SEC-038: ECS running as root (user not set or user = root)
_USER_NONROOT_RE = re.compile(r'user\s*=\s*"(?!root)[^"]+', re.IGNORECASE)

# TF-SEC-041: VPC default security group
_DEFAULT_SG_INGRESS_RE = re.compile(r"ingress\s*\{", re.IGNORECASE)
_DEFAULT_SG_EGRESS_RE = re.compile(r"egress\s*\{", re.IGNORECASE)

# TF-SEC-045: Lambda VPC config
_VPC_CONFIG_RE = re.compile(r"vpc_config\s*\{", re.IGNORECASE)

# TF-SEC-046: Lambda sensitive env vars
_ENV_SENSITIVE_RE = re.compile(
    r'(?:password|secret|api_key|access_key|token|credential)\s*=\s*"[^"]+',
    re.IGNORECASE,
)

# TF-SEC-049: WAF association (file-level check)
_WAF_ASSOC_RE = re.compile(r"aws_wafv2_web_acl_association", re.IGNORECASE)

# Non-standard ports (80 and 443 are typically fine for web traffic)
_WEB_PORTS = frozenset({80, 443})


def tf_sec_003(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-003: Security group with 0.0.0.0/0 on non-web ports."""
    rname, block, block_start_line, rel_path = res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
    # Find ingress blocks within the security group
    for ingress_m in re.finditer(r"ingress\s*\{", block):
        ingress_block = extract_block(block, ingress_m.end())
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
    return findings


def tf_sec_009(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-009: Security group rule with 0.0.0.0/0."""
    rname, block, block_start_line, rel_path = res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
    if _CIDR_ALL_RE.search(block) or _CIDR_IPV6_ALL_RE.search(block):
        findings.append(
            IaCFinding(
                rule_id="TF-SEC-009",
                severity="high",
                title="Security group rule with 0.0.0.0/0",
                message=(f"Security group rule '{rname}' allows traffic from 0.0.0.0/0 or ::/0. Restrict CIDR blocks to known IP ranges."),
                file_path=rel_path,
                line_number=block_start_line,
                category="terraform",
                compliance=["CIS-AWS-5.2", "NIST-AC-4"],
            )
        )
    return findings


def tf_sec_012(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-012: EC2 instance without IMDSv2."""
    rname, block, block_start_line, rel_path = res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
    metadata_m = _METADATA_OPTIONS_RE.search(block)
    if metadata_m:
        metadata_block = extract_block(block, metadata_m.end())
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
    return findings


def tf_sec_014(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-014: VPC without flow logs."""
    rname, block_start_line, rel_path, content = res.rname, res.block_start_line, res.rel_path, res.content
    findings: list[IaCFinding] = []
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
    return findings


def tf_sec_015(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-015: EKS cluster without envelope encryption."""
    rname, block, block_start_line, rel_path = res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
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
    return findings


def tf_sec_016(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-016: Lambda without dead letter queue."""
    rname, block, block_start_line, rel_path = res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
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
    return findings


def tf_sec_029(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-029: ALB/ELB access logging not enabled."""
    rtype, rname, block, block_start_line, rel_path = res.rtype, res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
    al_m = _LB_ACCESS_LOGS_RE.search(block)
    if al_m:
        al_block = extract_block(block, al_m.end())
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
    return findings


def tf_sec_030(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-030: ALB/NLB deletion protection disabled."""
    rname, block, block_start_line, rel_path = res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
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
    return findings


def tf_sec_035(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-035: ECR repository scan on push disabled."""
    rname, block, block_start_line, rel_path = res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
    scan_m = _IMAGE_SCANNING_RE.search(block)
    if scan_m:
        scan_block = extract_block(block, scan_m.end())
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
    return findings


def tf_sec_036(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-036: ECR image tag mutability enabled."""
    rname, block, block_start_line, rel_path = res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
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
    return findings


def tf_sec_037(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-037: ECS task definition with host networking."""
    rname, block, block_start_line, rel_path = res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
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
    return findings


def tf_sec_038(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-038: ECS task definition running as root."""
    rname, block, block_start_line, rel_path = res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
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
    return findings


def tf_sec_041(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-041: VPC default security group allows traffic."""
    rname, block, block_start_line, rel_path = res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
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
    return findings


def tf_sec_045(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-045: Lambda function without VPC configuration."""
    rname, block, block_start_line, rel_path = res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
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
    return findings


def tf_sec_046(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-046: Lambda environment variables with sensitive values."""
    rname, block, block_start_line, rel_path = res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
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
    return findings


def tf_sec_049(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-049: WAF not associated with ALB/CloudFront."""
    rtype, rname, block_start_line, rel_path, content = res.rtype, res.rname, res.block_start_line, res.rel_path, res.content
    findings: list[IaCFinding] = []
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
    return findings
