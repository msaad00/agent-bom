"""Terraform security rules for AWS managed databases (RDS, ElastiCache, OpenSearch, Redshift)."""

from __future__ import annotations

import re

from agent_bom.iac.models import IaCFinding
from agent_bom.iac.terraform_security_common import PITR_ENABLED_RE, TfResource, extract_block

_STORAGE_ENCRYPTED_FALSE_RE = re.compile(r"storage_encrypted\s*=\s*false", re.IGNORECASE)
_STORAGE_ENCRYPTED_TRUE_RE = re.compile(r"storage_encrypted\s*=\s*true", re.IGNORECASE)

# TF-SEC-011: RDS storage encryption
_STORAGE_ENCRYPTED_RE = re.compile(r"storage_encrypted\s*=\s*(true|false)", re.IGNORECASE)

# TF-SEC-017: ElastiCache transit encryption
_TRANSIT_ENCRYPTION_RE = re.compile(r"transit_encryption_enabled\s*=\s*true", re.IGNORECASE)

# TF-SEC-024: RDS public accessibility
_PUBLICLY_ACCESSIBLE_TRUE_RE = re.compile(r"publicly_accessible\s*=\s*true", re.IGNORECASE)

# TF-SEC-025: RDS backup retention
_BACKUP_RETENTION_RE = re.compile(r"backup_retention_period\s*=\s*(\d+)", re.IGNORECASE)

# TF-SEC-026: RDS multi-AZ
_MULTI_AZ_TRUE_RE = re.compile(r"multi_az\s*=\s*true", re.IGNORECASE)

# TF-SEC-042: RDS deletion protection
_RDS_DELETION_PROTECTION_RE = re.compile(r"deletion_protection\s*=\s*true", re.IGNORECASE)

# TF-SEC-043: Elasticsearch/OpenSearch encryption at rest
_ENCRYPT_AT_REST_RE = re.compile(r"encrypt_at_rest\s*\{", re.IGNORECASE)
_ENCRYPT_AT_REST_ENABLED_RE = re.compile(r"enabled\s*=\s*true", re.IGNORECASE)

# TF-SEC-044: Elasticsearch/OpenSearch node-to-node encryption
_NODE_TO_NODE_RE = re.compile(r"node_to_node_encryption\s*\{", re.IGNORECASE)

# TF-SEC-047: Redshift encryption
_REDSHIFT_ENCRYPTED_RE = re.compile(r"encrypted\s*=\s*true", re.IGNORECASE)

# TF-SEC-048: Redshift public access
_REDSHIFT_PUBLIC_RE = re.compile(r"publicly_accessible\s*=\s*true", re.IGNORECASE)


def tf_sec_005(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-005: RDS without encryption."""
    rname, block, block_start_line, rel_path = res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
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
                message=(f"RDS instance '{rname}' does not set storage_encrypted. Add storage_encrypted = true to encrypt data at rest."),
                file_path=rel_path,
                line_number=block_start_line,
                category="terraform",
                compliance=["CIS-AWS-2.3.1", "NIST-SC-28"],
            )
        )
    return findings


def tf_sec_011(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-011: RDS without storage encryption."""
    rtype, rname, block, block_start_line, rel_path = res.rtype, res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
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
    return findings


def tf_sec_017(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-017: ElastiCache without encryption in transit."""
    rtype, rname, block, block_start_line, rel_path = res.rtype, res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
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
    return findings


def tf_sec_024(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-024: RDS public accessibility enabled."""
    rname, block, block_start_line, rel_path = res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
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
    return findings


def tf_sec_025(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-025: RDS backup retention period < 7 days."""
    rname, block, block_start_line, rel_path = res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
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
                    f"RDS instance '{rname}' does not set backup_retention_period. Default may be 0 (no backups). Set to at least 7 days."
                ),
                file_path=rel_path,
                line_number=block_start_line,
                category="terraform",
                compliance=["CIS-AWS-2.3.3", "NIST-CP-9"],
            )
        )
    return findings


def tf_sec_026(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-026: RDS multi-AZ not enabled."""
    rname, block, block_start_line, rel_path = res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
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
    return findings


def tf_sec_042(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-042: RDS instance without deletion protection."""
    rname, block, block_start_line, rel_path = res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
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
    return findings


def tf_sec_043(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-043: Elasticsearch/OpenSearch without encryption at rest."""
    rtype, rname, block, block_start_line, rel_path = res.rtype, res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
    enc_m = _ENCRYPT_AT_REST_RE.search(block)
    if enc_m:
        enc_block = extract_block(block, enc_m.end())
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
                    f"Domain '{rname}' ({rtype}) does not have an encrypt_at_rest block. Enable encryption at rest to protect stored data."
                ),
                file_path=rel_path,
                line_number=block_start_line,
                category="terraform",
                compliance=["NIST-SC-28"],
            )
        )
    return findings


def tf_sec_044(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-044: Elasticsearch/OpenSearch without node-to-node encryption."""
    rtype, rname, block, block_start_line, rel_path = res.rtype, res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
    n2n_m = _NODE_TO_NODE_RE.search(block)
    if n2n_m:
        n2n_block = extract_block(block, n2n_m.end())
        if not PITR_ENABLED_RE.search(n2n_block):  # reuse enabled=true check
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
    return findings


def tf_sec_047(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-047: Redshift cluster without encryption."""
    rname, block, block_start_line, rel_path = res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
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
    return findings


def tf_sec_048(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-048: Redshift cluster publicly accessible."""
    rname, block, block_start_line, rel_path = res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
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
    return findings
