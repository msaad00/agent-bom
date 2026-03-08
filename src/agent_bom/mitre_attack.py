"""MITRE ATT&CK Enterprise — map cloud and AI infrastructure findings to T-codes.

Maps three finding types to MITRE ATT&CK Enterprise techniques:

1. **CIS benchmark failures** (AWS, Azure, GCP, Snowflake) — misconfigurations.
2. **Model provenance findings** — supply chain and serialisation risks.
3. **CVE blast radius** — vulnerability findings enriched with CWE IDs; maps
   weakness class to the most relevant ATT&CK technique(s).

Only FAILED/applicable findings are tagged. A passing check or clean package
does not produce any technique mapping.

Scope: cloud misconfigurations, infrastructure findings, model provenance, and
CVE-level blast radius. AI/agent-specific findings (prompt injection, tool
abuse) are separately mapped by MITRE ATLAS (see atlas.py).

Reference: https://attack.mitre.org/
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent_bom.models import BlastRadius

# ─── Catalog ──────────────────────────────────────────────────────────────────

ATTACK_TECHNIQUES: dict[str, str] = {
    # Remote access
    "T1021": "Remote Services",
    "T1021.001": "Remote Services: Remote Desktop Protocol",
    "T1021.004": "Remote Services: SSH",
    # Log tampering
    "T1070": "Indicator Removal",
    # Credential / account abuse
    "T1078": "Valid Accounts",
    "T1078.004": "Valid Accounts: Cloud Accounts",
    "T1098": "Account Manipulation",
    "T1098.001": "Account Manipulation: Additional Cloud Credentials",
    # Execution
    "T1059": "Command and Scripting Interpreter",
    "T1059.004": "Command and Scripting Interpreter: Unix Shell",
    "T1072": "Software Deployment Tools",
    # Data collection / exfil
    "T1005": "Data from Local System",
    "T1040": "Network Sniffing",
    "T1083": "File and Directory Discovery",
    "T1485": "Data Destruction",
    "T1530": "Data from Cloud Storage",
    "T1537": "Transfer Data to Cloud Account",
    # Initial access
    "T1185": "Browser Session Hijacking",
    "T1189": "Drive-by Compromise",
    "T1190": "Exploit Public-Facing Application",
    "T1195": "Supply Chain Compromise",
    "T1195.002": "Supply Chain Compromise: Compromise Software Supply Chain",
    # Privilege escalation / defence evasion
    "T1548": "Abuse Elevation Control Mechanism",
    "T1548.005": "Temporary Elevated Cloud Access",
    "T1600": "Weaken Encryption",
    # Credential access
    "T1552": "Unsecured Credentials",
    "T1556": "Modify Authentication Process",
    # Defence impairment
    "T1562": "Impair Defenses",
    "T1562.008": "Impair Defenses: Disable or Modify Cloud Logs",
    # Impact
    "T1499": "Endpoint Denial of Service",
    # Proxy / C2
    "T1090": "Proxy",
}

# ─── CWE weakness class → ATT&CK technique(s) ───────────────────────────────
#
# Mapped to the most specific applicable technique. Multiple entries per CWE
# are intentional when the weakness enables more than one distinct technique.

_CWE_TO_ATTACK: dict[str, list[str]] = {
    # Injection / execution
    "CWE-78": ["T1059", "T1059.004"],  # OS Command Injection
    "CWE-94": ["T1059"],  # Code Injection
    "CWE-502": ["T1059", "T1190"],  # Deserialization of Untrusted Data
    # Path / file access
    "CWE-22": ["T1083"],  # Path Traversal
    "CWE-73": ["T1083"],  # External Control of File Name/Path
    "CWE-611": ["T1083", "T1190"],  # XXE Injection
    # Web / session
    "CWE-79": ["T1189", "T1185"],  # Cross-site Scripting
    "CWE-352": ["T1185"],  # CSRF
    "CWE-601": ["T1189"],  # Open Redirect
    # Application exploitation
    "CWE-89": ["T1190"],  # SQL Injection
    "CWE-90": ["T1190"],  # LDAP Injection
    "CWE-918": ["T1090"],  # SSRF
    # Authentication / authorisation
    "CWE-287": ["T1078"],  # Improper Authentication
    "CWE-306": ["T1078"],  # Missing Authentication for Critical Function
    "CWE-269": ["T1548"],  # Improper Privilege Management
    "CWE-732": ["T1548"],  # Incorrect Permission Assignment
    # Credential exposure
    "CWE-798": ["T1552"],  # Use of Hard-coded Credentials
    "CWE-255": ["T1552"],  # Credentials Management Errors
    "CWE-321": ["T1552"],  # Use of Hard-coded Cryptographic Key
    # Cryptographic weaknesses
    "CWE-326": ["T1600"],  # Inadequate Encryption Strength
    "CWE-327": ["T1600"],  # Use of Broken / Risky Cryptographic Algorithm
    "CWE-330": ["T1600"],  # Use of Insufficiently Random Values
    "CWE-319": ["T1040"],  # Cleartext Transmission of Sensitive Information
    # Information disclosure
    "CWE-200": ["T1005"],  # Exposure of Sensitive Information
    "CWE-209": ["T1005"],  # Information Exposure Through Error Messages
    # Memory safety / DoS
    "CWE-125": ["T1499"],  # Out-of-bounds Read
    "CWE-787": ["T1499"],  # Out-of-bounds Write
    "CWE-416": ["T1499"],  # Use After Free
    "CWE-400": ["T1499"],  # Uncontrolled Resource Consumption
    "CWE-770": ["T1499"],  # Allocation of Resources Without Limits
    "CWE-1333": ["T1499"],  # ReDoS
    # Supply chain
    "CWE-494": ["T1195.002"],  # Download Without Integrity Check
    "CWE-829": ["T1195.002"],  # Inclusion of Functionality from Untrusted Control Sphere
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


def tag_blast_radius(br: BlastRadius) -> list[str]:
    """Return sorted MITRE ATT&CK Enterprise technique IDs for a CVE blast radius.

    Combines two signal sources:

    1. **CWE-based**: maps each CWE weakness ID on the vulnerability to one or
       more ATT&CK techniques using the :data:`_CWE_TO_ATTACK` table.
    2. **Context-based**: adds techniques based on blast-radius characteristics
       (exposed credentials, reachable exec tools, CISA KEV status, severity).

    Only MITRE ATT&CK Enterprise techniques (T-codes) are returned here.
    MITRE ATLAS techniques (AML.T-codes) are handled by :func:`atlas.tag_blast_radius`.

    Args:
        br: A :class:`~agent_bom.models.BlastRadius` instance.

    Returns:
        Sorted list of ATT&CK technique IDs, e.g. ``['T1059', 'T1190', 'T1552']``.
    """
    tags: set[str] = set()

    # 1. CWE → ATT&CK
    for cwe in br.vulnerability.cwe_ids:
        # Normalise: accept "CWE-78", "78", "cwe-78"
        cwe_norm = cwe.strip().upper()
        if not cwe_norm.startswith("CWE-"):
            cwe_norm = f"CWE-{cwe_norm}"
        for t in _CWE_TO_ATTACK.get(cwe_norm, []):
            tags.add(t)

    # 2. Context-based signals
    from agent_bom.constants import high_risk_severities
    from agent_bom.risk_analyzer import ToolCapability, classify_tool

    high_risk = high_risk_severities()
    is_high = br.vulnerability.severity in high_risk

    # Exposed credentials → unsecured credentials technique
    if br.exposed_credentials:
        tags.add("T1552")

    # KEV or CRITICAL severity → exploitation of public-facing application
    if br.vulnerability.is_kev or br.vulnerability.severity.value == "critical":
        tags.add("T1190")

    # Reachable exec tools → command and scripting interpreter
    for tool in br.exposed_tools:
        caps = classify_tool(tool.name, tool.description)
        if ToolCapability.EXECUTE in caps:
            tags.add("T1059")
            break

    # HIGH+ with >3 exposed tools and no CWE → supply chain exploitation baseline
    if is_high and not br.vulnerability.cwe_ids:
        tags.add("T1195.002")

    return sorted(tags)


def attack_label(technique_id: str) -> str:
    """Return human-readable label, e.g. 'T1078.004 Valid Accounts: Cloud Accounts'."""
    name = ATTACK_TECHNIQUES.get(technique_id, "Unknown")
    return f"{technique_id} {name}"


def attack_labels(technique_ids: list[str]) -> list[str]:
    """Return human-readable labels for a list of ATT&CK technique IDs."""
    return [attack_label(t) for t in technique_ids]
