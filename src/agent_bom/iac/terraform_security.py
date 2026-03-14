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

    return findings
