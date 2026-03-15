"""CloudFormation security misconfiguration scanner.

Scans AWS CloudFormation templates (JSON/YAML) for common security
misconfigurations against **AWS official documentation and best practices**:

- AWS Well-Architected Framework (Security Pillar)
- AWS Security Best Practices (SEC01-SEC11)
- CIS AWS Foundations Benchmark v2.0

Rules are mapped to applicable compliance frameworks (CIS-AWS, NIST SP 800-53)
where the mapping is well-established.  Uses ``yaml.safe_load`` for parsing —
no external tools required.

Rules
-----
CFN-001  S3 bucket without encryption (AWS SEC08, CIS 2.1.1)
CFN-002  S3 bucket with public ACL (AWS SEC01, CIS 2.1.2)
CFN-003  Security group with 0.0.0.0/0 ingress on non-443/80 port (CIS 5.2)
CFN-004  IAM policy with Action: * or Resource: * (AWS SEC03, CIS 1.16)
CFN-005  RDS instance without encryption (CIS 2.3.1)
CFN-006  EC2 instance with no IAM profile (CIS 1.14)
CFN-007  Hardcoded secrets in Parameters default values (AWS SEC02, CIS 1.4)
CFN-008  CloudTrail logging not multi-region (AWS SEC04, CIS 3.1)
CFN-009  EBS volume not encrypted (CIS 2.2.1)
CFN-010  Lambda function without VPC config (AWS SEC05)
CFN-011  S3 bucket without versioning enabled (AWS SEC08, CIS 2.1.3)
CFN-012  RDS instance without encryption (AWS SEC08, CIS 2.3.1)
CFN-013  Security group with 0.0.0.0/0 ingress on non-HTTP port (CIS 5.2)
CFN-014  IAM policy with Action: "*" (AWS SEC03, CIS 1.16)
CFN-015  Lambda function without VPC configuration (AWS SEC05)
CFN-016  ELB without access logging (AWS SEC04, CIS 2.6)
CFN-017  CloudTrail without log file validation (AWS SEC04, CIS 3.2)
CFN-018  SNS topic without encryption (AWS SEC08)
CFN-019  EBS volume without encryption (AWS SEC08, CIS 2.2.1)
CFN-020  RDS instance publicly accessible (AWS SEC01, CIS 2.3.2)
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from agent_bom.iac.models import IaCFinding

logger = logging.getLogger(__name__)

# Secret patterns in parameter defaults
_SECRET_PATTERNS = re.compile(
    r"(api[_-]?key|secret|password|token|credential|auth|private[_-]?key)",
    re.IGNORECASE,
)


def _load_template(path: Path) -> dict[str, Any] | None:
    """Load a CloudFormation template from JSON or YAML."""
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    # Try JSON first
    if path.suffix == ".json":
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return None

    # YAML
    try:
        import yaml  # type: ignore[import-untyped]

        return yaml.safe_load(content)
    except Exception:
        return None


def _is_cloudformation(path: Path) -> bool:
    """Check if a file looks like a CloudFormation template."""
    if path.suffix not in (".json", ".yaml", ".yml", ".template"):
        return False
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:3000]
    except OSError:
        return False
    # CFN markers
    return "AWSTemplateFormatVersion" in head or '"Resources"' in head or "Resources:" in head


def _find_line(content: str, needle: str) -> int:
    """Find the 1-based line number of a string in content."""
    for i, line in enumerate(content.splitlines(), 1):
        if needle in line:
            return i
    return 1


def scan_cloudformation(path: Path) -> list[IaCFinding]:
    """Scan a CloudFormation template for security misconfigurations.

    Parameters
    ----------
    path:
        Path to a ``.json``, ``.yaml``, or ``.yml`` CloudFormation template.

    Returns
    -------
    list[IaCFinding]
        Findings with rule IDs ``CFN-001`` through ``CFN-020``.
    """
    template = _load_template(path)
    if template is None:
        return []

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    file_str = str(path)
    findings: list[IaCFinding] = []
    resources = template.get("Resources", {}) or {}

    for logical_id, resource in resources.items():
        rtype = resource.get("Type", "")
        props = resource.get("Properties", {}) or {}
        line = _find_line(content, logical_id)

        # ── CFN-001: S3 without encryption ───────────────────────────
        if rtype == "AWS::S3::Bucket":
            enc = props.get("BucketEncryption")
            if not enc:
                findings.append(
                    IaCFinding(
                        rule_id="CFN-001",
                        severity="high",
                        title="S3 bucket without encryption",
                        message=f"Resource '{logical_id}' has no BucketEncryption. Add SSE-S3 or SSE-KMS encryption.",
                        file_path=file_str,
                        line_number=line,
                        category="cloudformation",
                        compliance=["CIS-AWS-2.1.1", "NIST-SC-28"],
                    )
                )

        # ── CFN-002: S3 with public ACL ──────────────────────────────
        if rtype == "AWS::S3::Bucket":
            acl = props.get("AccessControl", "")
            if isinstance(acl, str) and acl.lower() in ("publicread", "publicreadwrite"):
                findings.append(
                    IaCFinding(
                        rule_id="CFN-002",
                        severity="critical",
                        title="S3 bucket with public ACL",
                        message=f"Resource '{logical_id}' uses AccessControl '{acl}'. Use private ACL with bucket policies.",
                        file_path=file_str,
                        line_number=line,
                        category="cloudformation",
                        compliance=["CIS-AWS-2.1.2", "NIST-AC-3"],
                    )
                )

        # ── CFN-003: Security group with 0.0.0.0/0 on non-standard ports
        if rtype == "AWS::EC2::SecurityGroup":
            for rule in props.get("SecurityGroupIngress", []):
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
                                message=f"Resource '{logical_id}' allows ingress from 0.0.0.0/0 on ports {fp}-{tp}.",
                                file_path=file_str,
                                line_number=line,
                                category="cloudformation",
                                compliance=["CIS-AWS-5.2", "NIST-AC-3", "NIST-SC-7"],
                            )
                        )

        # ── CFN-004: IAM policy with wildcard ────────────────────────
        if rtype in ("AWS::IAM::Policy", "AWS::IAM::ManagedPolicy", "AWS::IAM::Role"):
            policy_doc = props.get("PolicyDocument") or {}
            policies = props.get("Policies", [])
            docs = [policy_doc] if policy_doc else []
            for p in policies:
                if isinstance(p, dict) and p.get("PolicyDocument"):
                    docs.append(p["PolicyDocument"])

            for doc in docs:
                for stmt in doc.get("Statement", []):
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
                                message=f"Resource '{logical_id}' has overly permissive IAM policy (Action:* or Resource:*).",
                                file_path=file_str,
                                line_number=line,
                                category="cloudformation",
                                compliance=["CIS-AWS-1.16", "NIST-AC-6"],
                            )
                        )
                        break  # one finding per resource

        # ── CFN-005: RDS without encryption ──────────────────────────
        if rtype == "AWS::RDS::DBInstance":
            encrypted = props.get("StorageEncrypted", False)
            if not encrypted:
                findings.append(
                    IaCFinding(
                        rule_id="CFN-005",
                        severity="high",
                        title="RDS instance without encryption",
                        message=f"Resource '{logical_id}' has StorageEncrypted=false or missing. Enable encryption at rest.",
                        file_path=file_str,
                        line_number=line,
                        category="cloudformation",
                        compliance=["CIS-AWS-2.3.1", "NIST-SC-28"],
                    )
                )

        # ── CFN-006: EC2 without IAM profile ─────────────────────────
        if rtype == "AWS::EC2::Instance":
            if not props.get("IamInstanceProfile"):
                findings.append(
                    IaCFinding(
                        rule_id="CFN-006",
                        severity="medium",
                        title="EC2 instance without IAM instance profile",
                        message=f"Resource '{logical_id}' has no IamInstanceProfile. Use IAM roles instead of hardcoded credentials.",
                        file_path=file_str,
                        line_number=line,
                        category="cloudformation",
                        compliance=["CIS-AWS-1.14", "NIST-AC-6"],
                    )
                )

        # ── CFN-008: CloudTrail not multi-region ─────────────────────
        if rtype == "AWS::CloudTrail::Trail":
            if not props.get("IsMultiRegionTrail", False):
                findings.append(
                    IaCFinding(
                        rule_id="CFN-008",
                        severity="medium",
                        title="CloudTrail not multi-region",
                        message=f"Resource '{logical_id}' has IsMultiRegionTrail=false. Enable multi-region for full coverage.",
                        file_path=file_str,
                        line_number=line,
                        category="cloudformation",
                        compliance=["CIS-AWS-3.1", "NIST-AU-2"],
                    )
                )

        # ── CFN-009: EBS volume not encrypted ────────────────────────
        if rtype == "AWS::EC2::Volume":
            if not props.get("Encrypted", False):
                findings.append(
                    IaCFinding(
                        rule_id="CFN-009",
                        severity="high",
                        title="EBS volume not encrypted",
                        message=f"Resource '{logical_id}' has Encrypted=false or missing. Enable encryption.",
                        file_path=file_str,
                        line_number=line,
                        category="cloudformation",
                        compliance=["CIS-AWS-2.2.1", "NIST-SC-28"],
                    )
                )

        # ── CFN-010: Lambda without VPC config ───────────────────────
        if rtype == "AWS::Lambda::Function":
            if not props.get("VpcConfig"):
                findings.append(
                    IaCFinding(
                        rule_id="CFN-010",
                        severity="medium",
                        title="Lambda function without VPC configuration",
                        message=f"Resource '{logical_id}' has no VpcConfig. Deploy in VPC for network isolation.",
                        file_path=file_str,
                        line_number=line,
                        category="cloudformation",
                        compliance=["NIST-SC-7"],
                    )
                )

        # ── CFN-011: S3 bucket without versioning enabled ────────────
        if rtype == "AWS::S3::Bucket":
            versioning = props.get("VersioningConfiguration", {}) or {}
            status = versioning.get("Status", "")
            if not isinstance(status, str) or status.lower() != "enabled":
                findings.append(
                    IaCFinding(
                        rule_id="CFN-011",
                        severity="medium",
                        title="S3 bucket without versioning enabled",
                        message=(
                            f"Resource '{logical_id}' does not have "
                            "VersioningConfiguration.Status set to 'Enabled'. "
                            "Enable versioning for data protection and recovery."
                        ),
                        file_path=file_str,
                        line_number=line,
                        category="cloudformation",
                        compliance=["CIS-AWS-2.1.3", "NIST-CP-9"],
                    )
                )

        # ── CFN-012: RDS instance without encryption ─────────────────
        if rtype == "AWS::RDS::DBInstance":
            if not props.get("StorageEncrypted", False):
                findings.append(
                    IaCFinding(
                        rule_id="CFN-012",
                        severity="high",
                        title="RDS instance without encryption",
                        message=f"Resource '{logical_id}' has StorageEncrypted=false or missing. Enable encryption at rest.",
                        file_path=file_str,
                        line_number=line,
                        category="cloudformation",
                        compliance=["CIS-AWS-2.3.1", "NIST-SC-28"],
                    )
                )

        # ── CFN-013: Security group with 0.0.0.0/0 on non-HTTP port ─
        if rtype == "AWS::EC2::SecurityGroup":
            for rule in props.get("SecurityGroupIngress", []):
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
                                    f"Resource '{logical_id}' allows ingress "
                                    f"from 0.0.0.0/0 on ports {fp}-{tp}. "
                                    "Restrict to HTTP/HTTPS ports only."
                                ),
                                file_path=file_str,
                                line_number=line,
                                category="cloudformation",
                                compliance=["CIS-AWS-5.2", "NIST-AC-4", "NIST-SC-7"],
                            )
                        )

        # ── CFN-014: IAM policy with Action: "*" ─────────────────────
        if rtype in ("AWS::IAM::Policy", "AWS::IAM::ManagedPolicy", "AWS::IAM::Role"):
            policy_doc = props.get("PolicyDocument") or {}
            policies = props.get("Policies", [])
            docs = [policy_doc] if policy_doc else []
            for p in policies:
                if isinstance(p, dict) and p.get("PolicyDocument"):
                    docs.append(p["PolicyDocument"])

            for doc in docs:
                for stmt in doc.get("Statement", []):
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
                                    f"Resource '{logical_id}' has an IAM "
                                    "statement with Action: '*'. Follow "
                                    "least-privilege: scope actions to "
                                    "specific services."
                                ),
                                file_path=file_str,
                                line_number=line,
                                category="cloudformation",
                                compliance=["CIS-AWS-1.16", "NIST-AC-6"],
                            )
                        )
                        break  # one finding per resource

        # ── CFN-015: Lambda function without VPC configuration ───────
        if rtype == "AWS::Lambda::Function":
            if not props.get("VpcConfig"):
                findings.append(
                    IaCFinding(
                        rule_id="CFN-015",
                        severity="medium",
                        title="Lambda function without VPC configuration",
                        message=(
                            f"Resource '{logical_id}' has no VpcConfig. Deploy Lambda in a VPC for network isolation and access control."
                        ),
                        file_path=file_str,
                        line_number=line,
                        category="cloudformation",
                        compliance=["NIST-SC-7", "NIST-AC-4"],
                    )
                )

        # ── CFN-016: ELB without access logging ─────────────────────
        if rtype in ("AWS::ElasticLoadBalancing::LoadBalancer", "AWS::ElasticLoadBalancingV2::LoadBalancer"):
            access_log = props.get("AccessLoggingPolicy") or props.get("LoadBalancerAttributes", [])
            has_logging = False
            if isinstance(access_log, dict) and access_log.get("Enabled"):
                has_logging = True
            elif isinstance(access_log, list):
                for attr in access_log:
                    if (
                        isinstance(attr, dict)
                        and attr.get("Key") == "access_logs.s3.enabled"
                        and str(attr.get("Value", "")).lower() == "true"
                    ):
                        has_logging = True
                        break
            if not has_logging:
                findings.append(
                    IaCFinding(
                        rule_id="CFN-016",
                        severity="medium",
                        title="ELB without access logging",
                        message=(
                            f"Resource '{logical_id}' does not have access "
                            "logging enabled. Enable access logs for security "
                            "monitoring and compliance."
                        ),
                        file_path=file_str,
                        line_number=line,
                        category="cloudformation",
                        compliance=["CIS-AWS-2.6", "NIST-AU-2"],
                    )
                )

        # ── CFN-017: CloudTrail without log file validation ──────────
        if rtype == "AWS::CloudTrail::Trail":
            if not props.get("EnableLogFileValidation", False):
                findings.append(
                    IaCFinding(
                        rule_id="CFN-017",
                        severity="medium",
                        title="CloudTrail without log file validation",
                        message=(
                            f"Resource '{logical_id}' has "
                            "EnableLogFileValidation=false or missing. Enable "
                            "log file validation to detect tampering."
                        ),
                        file_path=file_str,
                        line_number=line,
                        category="cloudformation",
                        compliance=["CIS-AWS-3.2", "NIST-AU-3"],
                    )
                )

        # ── CFN-018: SNS topic without encryption ────────────────────
        if rtype == "AWS::SNS::Topic":
            if not props.get("KmsMasterKeyId"):
                findings.append(
                    IaCFinding(
                        rule_id="CFN-018",
                        severity="medium",
                        title="SNS topic without encryption",
                        message=(
                            f"Resource '{logical_id}' does not have "
                            "KmsMasterKeyId set. Enable server-side encryption "
                            "with KMS for SNS topics."
                        ),
                        file_path=file_str,
                        line_number=line,
                        category="cloudformation",
                        compliance=["NIST-SC-28"],
                    )
                )

        # ── CFN-019: EBS volume without encryption ───────────────────
        if rtype == "AWS::EC2::Volume":
            if not props.get("Encrypted", False):
                findings.append(
                    IaCFinding(
                        rule_id="CFN-019",
                        severity="high",
                        title="EBS volume without encryption",
                        message=f"Resource '{logical_id}' has Encrypted=false or missing. Enable encryption for EBS volumes.",
                        file_path=file_str,
                        line_number=line,
                        category="cloudformation",
                        compliance=["CIS-AWS-2.2.1", "NIST-SC-28"],
                    )
                )

        # ── CFN-020: RDS instance publicly accessible ────────────────
        if rtype == "AWS::RDS::DBInstance":
            if props.get("PubliclyAccessible", False):
                findings.append(
                    IaCFinding(
                        rule_id="CFN-020",
                        severity="critical",
                        title="RDS instance publicly accessible",
                        message=(
                            f"Resource '{logical_id}' has "
                            "PubliclyAccessible=true. RDS instances should not "
                            "be publicly accessible. Use private subnets and "
                            "VPC security groups."
                        ),
                        file_path=file_str,
                        line_number=line,
                        category="cloudformation",
                        compliance=["CIS-AWS-2.3.2", "NIST-AC-3", "NIST-SC-7"],
                    )
                )

    # ── CFN-007: Hardcoded secrets in Parameters ─────────────────────
    parameters = template.get("Parameters", {}) or {}
    for param_name, param_def in parameters.items():
        if not isinstance(param_def, dict):
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
