"""MITRE ATT&CK Enterprise — map cloud and AI infrastructure findings to T-codes.

Maps CIS benchmark failures (AWS, Azure, GCP, Snowflake) and model provenance
findings to MITRE ATT&CK Enterprise techniques. Only tags FAILED checks — a
passing check does not indicate an active technique.

Scope: cloud misconfigurations, infrastructure findings, model provenance.
AI/agent-specific findings (blast radius, tool abuse) are mapped by MITRE ATLAS
(see atlas.py) which was purpose-built for that domain.

Reference: https://attack.mitre.org/
"""

from __future__ import annotations

# ─── Catalog ──────────────────────────────────────────────────────────────────

ATTACK_TECHNIQUES: dict[str, str] = {
    "T1021": "Remote Services",
    "T1021.001": "Remote Services: Remote Desktop Protocol",
    "T1021.004": "Remote Services: SSH",
    "T1070": "Indicator Removal",
    "T1078": "Valid Accounts",
    "T1078.004": "Valid Accounts: Cloud Accounts",
    "T1098": "Account Manipulation",
    "T1098.001": "Account Manipulation: Additional Cloud Credentials",
    "T1485": "Data Destruction",
    "T1530": "Data from Cloud Storage",
    "T1537": "Transfer Data to Cloud Account",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1548.005": "Temporary Elevated Cloud Access",
    "T1552": "Unsecured Credentials",
    "T1556": "Modify Authentication Process",
    "T1562": "Impair Defenses",
    "T1562.008": "Impair Defenses: Disable or Modify Cloud Logs",
}

# ─── Section keyword → base T-codes ───────────────────────────────────────────

_SECTION_RULES: list[tuple[tuple[str, ...], list[str]]] = [
    # IAM / identity / authentication
    (("identity", "access management", "iam", "authentication", "auth"), ["T1078", "T1078.004"]),
    # Logging / audit / monitoring
    (("logging", "cloudtrail", "audit", "monitoring"), ["T1562", "T1562.008"]),
    # Storage / data
    (("storage", "s3", "blob", "bucket", "data protection"), ["T1530"]),
    # Networking
    (("network",), ["T1021"]),
    # Access control / privilege
    (("access control", "privilege"), ["T1548", "T1098"]),
]

# ─── Per check_id refinements (added on top of section mapping) ────────────────

_CHECK_OVERRIDES: dict[str, list[str]] = {
    # MFA / auth controls
    "1.1": ["T1556"],  # Security defaults / MFA disabled
    "1.2": ["T1556"],  # MFA for all users
    "1.5": ["T1556"],  # MFA on AWS root
    "1.6": ["T1556"],  # Hardware MFA on root
    # Stale / unsecured credentials
    "1.4": ["T1552"],  # Root access key exists
    "1.7": ["T1552"],  # Service account key rotation
    "1.14": ["T1552"],  # AWS access key rotation
    # Privilege escalation
    "1.16": ["T1548.005"],  # Full admin policies attached
    # Logging
    "2.1": ["T1562.008"],  # Audit/CloudTrail disabled
    "2.2": ["T1070"],  # Log file validation off → indicator removal
    # Public storage
    "3.1": ["T1537"],  # Public storage bucket/blob
    "3.2": ["T1537"],  # Public access block off
    "3.7": ["T1537"],  # Public blob containers (Azure)
    "5.1": ["T1537"],  # GCP public bucket
    # Data destruction
    "3.3": ["T1485"],  # No versioning / MFA delete disabled
    # Remote access exposure
    "4.1": ["T1021.004"],  # SSH from 0.0.0.0/0
    "4.2": ["T1021.001"],  # RDP from 0.0.0.0/0
    "3.6": ["T1021.004"],  # GCP SSH firewall rule
    "3.7_net": ["T1021.001"],  # GCP RDP firewall rule (key collision avoided by cis_section)
    "6.1": ["T1021.001"],  # Azure RDP from internet
    "6.2": ["T1021.004"],  # Azure SSH from internet
    # Key / secret hygiene
    "8.1": ["T1552"],  # Key Vault keys without expiry
    "8.2": ["T1552"],  # Key Vault secrets without expiry
}


# ─── Public API ───────────────────────────────────────────────────────────────


def tag_cis_check(check: object) -> list[str]:
    """Return sorted MITRE ATT&CK Enterprise technique IDs for a failed CIS check.

    Only FAILED checks are tagged. A passing check means the control is
    effective — no technique mapping is warranted.

    Args:
        check: A CISCheckResult-compatible object with .status, .check_id,
               and .cis_section attributes.

    Returns:
        Sorted list of ATT&CK technique IDs, e.g. ['T1021.001', 'T1078.004'].
        Empty list if the check passed or errored.
    """
    # Lazy import to avoid circular dependency — CISCheckResult lives in cloud/
    from agent_bom.cloud.aws_cis_benchmark import CheckStatus

    status = getattr(check, "status", None)
    if status != CheckStatus.FAIL:
        return []

    tags: set[str] = set()
    section_lower = (getattr(check, "cis_section", "") or "").lower()
    check_id = getattr(check, "check_id", "") or ""

    # Section-based tagging
    for keywords, t_codes in _SECTION_RULES:
        if any(kw in section_lower for kw in keywords):
            tags.update(t_codes)

    # Check-ID refinements
    # Special case: check_id "3.7" is used for both Azure blob public access
    # (storage section) and GCP RDP firewall (network section) — disambiguate
    # by section keyword.
    if check_id == "3.7":
        if "network" in section_lower or "firewall" in section_lower:
            tags.update(["T1021.001"])  # GCP RDP
        else:
            tags.update(_CHECK_OVERRIDES.get("3.7", []))
    else:
        for tid in _CHECK_OVERRIDES.get(check_id, []):
            tags.add(tid)

    return sorted(tags)


def tag_provenance_finding(finding: dict) -> list[str]:
    """Return ATT&CK technique IDs for a model provenance finding.

    Args:
        finding: Dict with keys like 'risk_flags' (list of str), 'format',
                 'source' (hf/ollama).

    Returns:
        Sorted list of ATT&CK technique IDs.
    """
    tags: set[str] = set()
    risk_flags: list[str] = finding.get("risk_flags", [])

    for flag in risk_flags:
        # Unsafe serialization format — code execution risk (pickle, pt)
        if "unsafe_format" in flag:
            tags.update(["T1195", "T1072"])  # Supply chain / software deployment tools
        # No digest — integrity not verifiable → supply chain
        if "no_digest" in flag:
            tags.add("T1195.002")  # Compromise Software Supply Chain
        # Public ungated model with large size — exfiltration surface
        if "public_large" in flag:
            tags.add("T1530")  # Data from Cloud Storage

    return sorted(tags)


def attack_label(technique_id: str) -> str:
    """Return human-readable label, e.g. 'T1078.004 Valid Accounts: Cloud Accounts'."""
    name = ATTACK_TECHNIQUES.get(technique_id, "Unknown")
    return f"{technique_id} {name}"


def attack_labels(technique_ids: list[str]) -> list[str]:
    """Return human-readable labels for a list of ATT&CK technique IDs."""
    return [attack_label(t) for t in technique_ids]
