"""CloudFormation rule checks.

Each ``cfn_NNN`` function evaluates one rule against a single resource and
returns its findings. ``scan_cloudformation`` runs them in rule order for the
resource types each rule applies to (see ``CFN_RULES``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from agent_bom.iac.cloudformation_input import input_mapping, mapping_sequence, policy_statements
from agent_bom.iac.models import IaCFinding

# Secret patterns in parameter defaults
_SECRET_PATTERNS = re.compile(
    r"(api[_-]?key|secret|password|token|credential|auth|private[_-]?key)",
    re.IGNORECASE,
)


def _find_line(content: str, needle: str) -> int:
    """Find the 1-based line number of a string in content."""
    for i, line in enumerate(content.splitlines(), 1):
        if needle in line:
            return i
    return 1


@dataclass(frozen=True)
class CfnResource:
    """One ``Resources`` entry as the rule checks see it."""

    logical_id: Any
    props: dict[str, Any]
    file_str: str
    line: int


def cfn_001(res: CfnResource) -> list[IaCFinding]:
    """CFN-001: S3 without encryption."""
    findings: list[IaCFinding] = []
    enc = res.props.get("BucketEncryption")
    if not enc:
        findings.append(
            IaCFinding(
                rule_id="CFN-001",
                severity="high",
                title="S3 bucket without encryption",
                message=f"Resource '{res.logical_id}' has no BucketEncryption. Add SSE-S3 or SSE-KMS encryption.",
                file_path=res.file_str,
                line_number=res.line,
                category="cloudformation",
                compliance=["CIS-AWS-2.1.1", "NIST-SC-28"],
            )
        )
    return findings


def cfn_002(res: CfnResource) -> list[IaCFinding]:
    """CFN-002: S3 with public ACL."""
    findings: list[IaCFinding] = []
    acl = res.props.get("AccessControl", "")
    if isinstance(acl, str) and acl.lower() in ("publicread", "publicreadwrite"):
        findings.append(
            IaCFinding(
                rule_id="CFN-002",
                severity="critical",
                title="S3 bucket with public ACL",
                message=f"Resource '{res.logical_id}' uses AccessControl '{acl}'. Use private ACL with bucket policies.",
                file_path=res.file_str,
                line_number=res.line,
                category="cloudformation",
                compliance=["CIS-AWS-2.1.2", "NIST-AC-3"],
            )
        )
    return findings


def cfn_003(res: CfnResource) -> list[IaCFinding]:
    """CFN-003: Security group with 0.0.0.0/0 on non-standard ports."""
    findings: list[IaCFinding] = []
    for rule in mapping_sequence(res.props.get("SecurityGroupIngress", []), res.file_str):
        if not isinstance(rule, dict):
            continue
        cidr = rule.get("CidrIp", "")
        cidr6 = rule.get("CidrIpv6", "")
        from_port = rule.get("FromPort", 0)
        to_port = rule.get("ToPort", 0)
        if cidr == "0.0.0.0/0" or cidr6 == "::/0":
            try:
                fp, tp = int(from_port), int(to_port)
            except (ValueError, TypeError):
                fp, tp = 0, 65535
            standard = {80, 443}
            if not (fp in standard and tp in standard):
                findings.append(
                    IaCFinding(
                        rule_id="CFN-003",
                        severity="high",
                        title="Security group open to 0.0.0.0/0",
                        message=f"Resource '{res.logical_id}' allows ingress from 0.0.0.0/0 on ports {fp}-{tp}.",
                        file_path=res.file_str,
                        line_number=res.line,
                        category="cloudformation",
                        compliance=["CIS-AWS-5.2", "NIST-AC-3", "NIST-SC-7"],
                    )
                )
    return findings


def cfn_004(res: CfnResource) -> list[IaCFinding]:
    """CFN-004: IAM policy with wildcard."""
    findings: list[IaCFinding] = []
    for statements in policy_statements(res.props, res.file_str):
        for stmt in statements:
            if not isinstance(stmt, dict):
                continue
            action = stmt.get("Action", "")
            resource = stmt.get("Resource", "")
            actions = [action] if isinstance(action, str) else (action if isinstance(action, list) else [])
            resources = [resource] if isinstance(resource, str) else (resource if isinstance(resource, list) else [])
            if "*" in actions or "*" in resources:
                findings.append(
                    IaCFinding(
                        rule_id="CFN-004",
                        severity="high",
                        title="IAM policy with wildcard permissions",
                        message=f"Resource '{res.logical_id}' has overly permissive IAM policy (Action:* or Resource:*).",
                        file_path=res.file_str,
                        line_number=res.line,
                        category="cloudformation",
                        compliance=["CIS-AWS-1.16", "NIST-AC-6"],
                    )
                )
                break  # one finding per resource
    return findings


def cfn_005(res: CfnResource) -> list[IaCFinding]:
    """CFN-005: RDS without encryption."""
    findings: list[IaCFinding] = []
    encrypted = res.props.get("StorageEncrypted", False)
    if not encrypted:
        findings.append(
            IaCFinding(
                rule_id="CFN-005",
                severity="high",
                title="RDS instance without encryption",
                message=f"Resource '{res.logical_id}' has StorageEncrypted=false or missing. Enable encryption at rest.",
                file_path=res.file_str,
                line_number=res.line,
                category="cloudformation",
                compliance=["CIS-AWS-2.3.1", "NIST-SC-28"],
            )
        )
    return findings


def cfn_006(res: CfnResource) -> list[IaCFinding]:
    """CFN-006: EC2 without IAM profile."""
    findings: list[IaCFinding] = []
    if not res.props.get("IamInstanceProfile"):
        findings.append(
            IaCFinding(
                rule_id="CFN-006",
                severity="medium",
                title="EC2 instance without IAM instance profile",
                message=f"Resource '{res.logical_id}' has no IamInstanceProfile. Use IAM roles instead of hardcoded credentials.",
                file_path=res.file_str,
                line_number=res.line,
                category="cloudformation",
                compliance=["CIS-AWS-1.14", "NIST-AC-6"],
            )
        )
    return findings


def cfn_008(res: CfnResource) -> list[IaCFinding]:
    """CFN-008: CloudTrail not multi-region."""
    findings: list[IaCFinding] = []
    if not res.props.get("IsMultiRegionTrail", False):
        findings.append(
            IaCFinding(
                rule_id="CFN-008",
                severity="medium",
                title="CloudTrail not multi-region",
                message=f"Resource '{res.logical_id}' has IsMultiRegionTrail=false. Enable multi-region for full coverage.",
                file_path=res.file_str,
                line_number=res.line,
                category="cloudformation",
                compliance=["CIS-AWS-3.1", "NIST-AU-2"],
            )
        )
    return findings


def cfn_009(res: CfnResource) -> list[IaCFinding]:
    """CFN-009: EBS volume not encrypted."""
    findings: list[IaCFinding] = []
    if not res.props.get("Encrypted", False):
        findings.append(
            IaCFinding(
                rule_id="CFN-009",
                severity="high",
                title="EBS volume not encrypted",
                message=f"Resource '{res.logical_id}' has Encrypted=false or missing. Enable encryption.",
                file_path=res.file_str,
                line_number=res.line,
                category="cloudformation",
                compliance=["CIS-AWS-2.2.1", "NIST-SC-28"],
            )
        )
    return findings


def cfn_010(res: CfnResource) -> list[IaCFinding]:
    """CFN-010: Lambda without VPC config."""
    findings: list[IaCFinding] = []
    if not res.props.get("VpcConfig"):
        findings.append(
            IaCFinding(
                rule_id="CFN-010",
                severity="medium",
                title="Lambda function without VPC configuration",
                message=f"Resource '{res.logical_id}' has no VpcConfig. Deploy in VPC for network isolation.",
                file_path=res.file_str,
                line_number=res.line,
                category="cloudformation",
                compliance=["NIST-SC-7"],
            )
        )
    return findings


def cfn_011(res: CfnResource) -> list[IaCFinding]:
    """CFN-011: S3 bucket without versioning enabled."""
    findings: list[IaCFinding] = []
    versioning = input_mapping(res.props.get("VersioningConfiguration", {}), res.file_str)
    if versioning is None:
        return []
    status = versioning.get("Status", "")
    if not isinstance(status, str) or status.lower() != "enabled":
        findings.append(
            IaCFinding(
                rule_id="CFN-011",
                severity="medium",
                title="S3 bucket without versioning enabled",
                message=(
                    f"Resource '{res.logical_id}' does not have "
                    "VersioningConfiguration.Status set to 'Enabled'. "
                    "Enable versioning for data protection and recovery."
                ),
                file_path=res.file_str,
                line_number=res.line,
                category="cloudformation",
                compliance=["CIS-AWS-2.1.3", "NIST-CP-9"],
            )
        )
    return findings


def cfn_012(res: CfnResource) -> list[IaCFinding]:
    """CFN-012: RDS instance without encryption."""
    findings: list[IaCFinding] = []
    if not res.props.get("StorageEncrypted", False):
        findings.append(
            IaCFinding(
                rule_id="CFN-012",
                severity="high",
                title="RDS instance without encryption",
                message=f"Resource '{res.logical_id}' has StorageEncrypted=false or missing. Enable encryption at rest.",
                file_path=res.file_str,
                line_number=res.line,
                category="cloudformation",
                compliance=["CIS-AWS-2.3.1", "NIST-SC-28"],
            )
        )
    return findings


def cfn_013(res: CfnResource) -> list[IaCFinding]:
    """CFN-013: Security group with 0.0.0.0/0 on non-HTTP port."""
    findings: list[IaCFinding] = []
    for rule in mapping_sequence(res.props.get("SecurityGroupIngress", []), res.file_str):
        if not isinstance(rule, dict):
            continue
        cidr = rule.get("CidrIp", "")
        cidr6 = rule.get("CidrIpv6", "")
        from_port = rule.get("FromPort", 0)
        to_port = rule.get("ToPort", 0)
        if cidr == "0.0.0.0/0" or cidr6 == "::/0":
            try:
                fp, tp = int(from_port), int(to_port)
            except (ValueError, TypeError):
                fp, tp = 0, 65535
            http_ports = {80, 443}
            if not (fp in http_ports and tp in http_ports):
                findings.append(
                    IaCFinding(
                        rule_id="CFN-013",
                        severity="high",
                        title="Security group with 0.0.0.0/0 ingress on non-HTTP port",
                        message=(
                            f"Resource '{res.logical_id}' allows ingress "
                            f"from 0.0.0.0/0 on ports {fp}-{tp}. "
                            "Restrict to HTTP/HTTPS ports only."
                        ),
                        file_path=res.file_str,
                        line_number=res.line,
                        category="cloudformation",
                        compliance=["CIS-AWS-5.2", "NIST-AC-4", "NIST-SC-7"],
                    )
                )
    return findings


def cfn_014(res: CfnResource) -> list[IaCFinding]:
    """CFN-014: IAM policy with Action: "*"."""
    findings: list[IaCFinding] = []
    for statements in policy_statements(res.props, res.file_str):
        for stmt in statements:
            if not isinstance(stmt, dict):
                continue
            action = stmt.get("Action", "")
            actions = [action] if isinstance(action, str) else (action if isinstance(action, list) else [])
            if "*" in actions:
                findings.append(
                    IaCFinding(
                        rule_id="CFN-014",
                        severity="critical",
                        title="IAM policy with Action: * (overly permissive)",
                        message=(
                            f"Resource '{res.logical_id}' has an IAM "
                            "statement with Action: '*'. Follow "
                            "least-privilege: scope actions to "
                            "specific services."
                        ),
                        file_path=res.file_str,
                        line_number=res.line,
                        category="cloudformation",
                        compliance=["CIS-AWS-1.16", "NIST-AC-6"],
                    )
                )
                break  # one finding per resource
    return findings


def cfn_015(res: CfnResource) -> list[IaCFinding]:
    """CFN-015: Lambda function without VPC configuration."""
    findings: list[IaCFinding] = []
    if not res.props.get("VpcConfig"):
        findings.append(
            IaCFinding(
                rule_id="CFN-015",
                severity="medium",
                title="Lambda function without VPC configuration",
                message=(f"Resource '{res.logical_id}' has no VpcConfig. Deploy Lambda in a VPC for network isolation and access control."),
                file_path=res.file_str,
                line_number=res.line,
                category="cloudformation",
                compliance=["NIST-SC-7", "NIST-AC-4"],
            )
        )
    return findings


def cfn_016(res: CfnResource) -> list[IaCFinding]:
    """CFN-016: ELB without access logging."""
    findings: list[IaCFinding] = []
    access_log = res.props.get("AccessLoggingPolicy") or res.props.get("LoadBalancerAttributes", [])
    has_logging = False
    if isinstance(access_log, dict) and access_log.get("Enabled"):
        has_logging = True
    elif isinstance(access_log, list):
        for attr in access_log:
            if isinstance(attr, dict) and attr.get("Key") == "access_logs.s3.enabled" and str(attr.get("Value", "")).lower() == "true":
                has_logging = True
                break
    if not has_logging:
        findings.append(
            IaCFinding(
                rule_id="CFN-016",
                severity="medium",
                title="ELB without access logging",
                message=(
                    f"Resource '{res.logical_id}' does not have access "
                    "logging enabled. Enable access logs for security "
                    "monitoring and compliance."
                ),
                file_path=res.file_str,
                line_number=res.line,
                category="cloudformation",
                compliance=["CIS-AWS-2.6", "NIST-AU-2"],
            )
        )
    return findings


def cfn_017(res: CfnResource) -> list[IaCFinding]:
    """CFN-017: CloudTrail without log file validation."""
    findings: list[IaCFinding] = []
    if not res.props.get("EnableLogFileValidation", False):
        findings.append(
            IaCFinding(
                rule_id="CFN-017",
                severity="medium",
                title="CloudTrail without log file validation",
                message=(
                    f"Resource '{res.logical_id}' has "
                    "EnableLogFileValidation=false or missing. Enable "
                    "log file validation to detect tampering."
                ),
                file_path=res.file_str,
                line_number=res.line,
                category="cloudformation",
                compliance=["CIS-AWS-3.2", "NIST-AU-3"],
            )
        )
    return findings


def cfn_018(res: CfnResource) -> list[IaCFinding]:
    """CFN-018: SNS topic without encryption."""
    findings: list[IaCFinding] = []
    if not res.props.get("KmsMasterKeyId"):
        findings.append(
            IaCFinding(
                rule_id="CFN-018",
                severity="medium",
                title="SNS topic without encryption",
                message=(
                    f"Resource '{res.logical_id}' does not have KmsMasterKeyId set. Enable server-side encryption with KMS for SNS topics."
                ),
                file_path=res.file_str,
                line_number=res.line,
                category="cloudformation",
                compliance=["NIST-SC-28"],
            )
        )
    return findings


def cfn_019(res: CfnResource) -> list[IaCFinding]:
    """CFN-019: EBS volume without encryption."""
    findings: list[IaCFinding] = []
    if not res.props.get("Encrypted", False):
        findings.append(
            IaCFinding(
                rule_id="CFN-019",
                severity="high",
                title="EBS volume without encryption",
                message=f"Resource '{res.logical_id}' has Encrypted=false or missing. Enable encryption for EBS volumes.",
                file_path=res.file_str,
                line_number=res.line,
                category="cloudformation",
                compliance=["CIS-AWS-2.2.1", "NIST-SC-28"],
            )
        )
    return findings


def cfn_020(res: CfnResource) -> list[IaCFinding]:
    """CFN-020: RDS instance publicly accessible."""
    findings: list[IaCFinding] = []
    if res.props.get("PubliclyAccessible", False):
        findings.append(
            IaCFinding(
                rule_id="CFN-020",
                severity="critical",
                title="RDS instance publicly accessible",
                message=(
                    f"Resource '{res.logical_id}' has "
                    "PubliclyAccessible=true. RDS instances should not "
                    "be publicly accessible. Use private subnets and "
                    "VPC security groups."
                ),
                file_path=res.file_str,
                line_number=res.line,
                category="cloudformation",
                compliance=["CIS-AWS-2.3.2", "NIST-AC-3", "NIST-SC-7"],
            )
        )
    return findings


def cfn_007(parameters: Any, content: str, file_str: str) -> list[IaCFinding]:
    """CFN-007: Hardcoded secrets in Parameters."""
    findings: list[IaCFinding] = []
    for param_name, value in parameters.items():
        param_def = input_mapping(value, file_str)
        if param_def is None:
            continue
        default = param_def.get("Default", "")
        if isinstance(default, str) and default and _SECRET_PATTERNS.search(param_name):
            # Has a default value for a secret-looking parameter
            if not default.startswith("{{") and default not in ("", "CHANGE_ME", "PLACEHOLDER"):
                findings.append(
                    IaCFinding(
                        rule_id="CFN-007",
                        severity="critical",
                        title="Hardcoded secret in parameter default",
                        message=f"Parameter '{param_name}' has a non-empty Default value. Use NoEcho and SSM/Secrets Manager.",
                        file_path=file_str,
                        line_number=_find_line(content, param_name),
                        category="cloudformation",
                        compliance=["CIS-AWS-1.4", "NIST-IA-5", "NIST-SC-28"],
                    )
                )
    return findings
