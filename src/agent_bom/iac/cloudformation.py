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
from collections.abc import Callable
from pathlib import Path
from typing import Any

from agent_bom.iac.cloudformation_rules import (
    _SECRET_PATTERNS,
    CfnResource,
    _find_line,
    cfn_001,
    cfn_002,
    cfn_003,
    cfn_004,
    cfn_005,
    cfn_006,
    cfn_007,
    cfn_008,
    cfn_009,
    cfn_010,
    cfn_011,
    cfn_012,
    cfn_013,
    cfn_014,
    cfn_015,
    cfn_016,
    cfn_017,
    cfn_018,
    cfn_019,
    cfn_020,
)
from agent_bom.iac.models import IaCFinding

__all__ = ["_SECRET_PATTERNS", "_find_line", "_is_cloudformation", "_load_template", "scan_cloudformation"]

logger = logging.getLogger(__name__)

CfnCheck = Callable[[CfnResource], list[IaCFinding]]

# Resource-level rules in evaluation order; CFN-007 (Parameters) runs after all resources.
CFN_RULES: tuple[tuple[tuple[str, ...], CfnCheck], ...] = (
    (("AWS::S3::Bucket",), cfn_001),
    (("AWS::S3::Bucket",), cfn_002),
    (("AWS::EC2::SecurityGroup",), cfn_003),
    (("AWS::IAM::Policy", "AWS::IAM::ManagedPolicy", "AWS::IAM::Role"), cfn_004),
    (("AWS::RDS::DBInstance",), cfn_005),
    (("AWS::EC2::Instance",), cfn_006),
    (("AWS::CloudTrail::Trail",), cfn_008),
    (("AWS::EC2::Volume",), cfn_009),
    (("AWS::Lambda::Function",), cfn_010),
    (("AWS::S3::Bucket",), cfn_011),
    (("AWS::RDS::DBInstance",), cfn_012),
    (("AWS::EC2::SecurityGroup",), cfn_013),
    (("AWS::IAM::Policy", "AWS::IAM::ManagedPolicy", "AWS::IAM::Role"), cfn_014),
    (("AWS::Lambda::Function",), cfn_015),
    (("AWS::ElasticLoadBalancing::LoadBalancer", "AWS::ElasticLoadBalancingV2::LoadBalancer"), cfn_016),
    (("AWS::CloudTrail::Trail",), cfn_017),
    (("AWS::SNS::Topic",), cfn_018),
    (("AWS::EC2::Volume",), cfn_019),
    (("AWS::RDS::DBInstance",), cfn_020),
)


def _checks_by_type() -> dict[str, tuple[CfnCheck, ...]]:
    by_type: dict[str, list[CfnCheck]] = {}
    for rtypes, check in CFN_RULES:
        for rtype in rtypes:
            by_type.setdefault(rtype, []).append(check)
    return {rtype: tuple(checks) for rtype, checks in by_type.items()}


_CHECKS_BY_TYPE = _checks_by_type()


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
        checks = _CHECKS_BY_TYPE.get(rtype, ()) if isinstance(rtype, str) else ()
        res = CfnResource(logical_id=logical_id, props=props, file_str=file_str, line=line)
        for check in checks:
            findings.extend(check(res))

    parameters = template.get("Parameters", {}) or {}
    findings.extend(cfn_007(parameters, content, file_str))

    return findings
