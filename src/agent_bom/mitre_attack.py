"""MITRE ATT&CK Enterprise — map findings to T-codes via official MITRE data.

Maps three finding types to MITRE ATT&CK Enterprise techniques.  All technique
IDs, names, and CWE mappings are loaded from MITRE's published data — nothing
is hardcoded in this module.

Data source: :mod:`agent_bom.mitre_fetch` (bundled normalized ATT&CK/CAPEC
catalog by default, with optional explicit refresh from upstream STIX).

Finding types:

1. **CIS benchmark failures** — cloud misconfigurations (AWS/Azure/GCP/Snowflake).
2. **Model provenance findings** — supply chain and serialisation risks.
3. **CVE blast radius** — vulnerabilities with CWE IDs; CWE → ATT&CK mapping
   derived from MITRE CAPEC official data (CWE → CAPEC → ATT&CK).

Context signals (exposed credentials, reachable exec tools, CISA KEV status)
are applied on top of CWE mappings and resolve to ATT&CK techniques that are
already in the fetched catalog — never to invented identifiers.

Scope: cloud misconfigurations, infrastructure findings, model provenance, and
CVE-level blast radius. AI/agent-specific findings (prompt injection, tool
abuse) are separately mapped by MITRE ATLAS (see atlas.py).

Reference: https://attack.mitre.org/
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent_bom.models import BlastRadius

logger = logging.getLogger(__name__)

# ─── Public catalog accessors — always from the active MITRE catalog ──────────


def get_attack_techniques() -> dict[str, str]:
    """Return ``{technique_id: name}`` from the active ATT&CK catalog."""
    from agent_bom.mitre_fetch import get_techniques

    return {tid: meta["name"] for tid, meta in get_techniques().items()}


# Legacy alias kept for callers that import ATTACK_TECHNIQUES directly from
# this module.  Evaluated lazily to avoid a network call on import.
class _LazyTechniquesProxy:
    """Behaves like a dict but loads data on first access."""

    _data: dict[str, str] | None = None

    def _load(self) -> dict[str, str]:
        if self._data is None:
            self._data = get_attack_techniques()
        return self._data

    def __getitem__(self, key: str) -> str:
        return self._load()[key]

    def __contains__(self, key: object) -> bool:
        return key in self._load()

    def get(self, key: str, default: str = "") -> str:
        return self._load().get(key, default)

    def keys(self):  # noqa: ANN201
        return self._load().keys()

    def items(self):  # noqa: ANN201
        return self._load().items()

    def __len__(self) -> int:
        return len(self._load())


ATTACK_TECHNIQUES = _LazyTechniquesProxy()

# ─── Section keyword → tactic phase names ────────────────────────────────────
#
# Maps CIS benchmark section keywords to ATT&CK *tactic phase names* (not
# hardcoded T-codes).  The actual techniques are resolved at runtime from the
# fetched catalog by looking up which techniques belong to each tactic.

_SECTION_TO_TACTICS: list[tuple[tuple[str, ...], list[str]]] = [
    # IAM / identity / authentication → Credential Access + Privilege Escalation
    (
        ("identity", "access management", "iam", "authentication", "auth"),
        ["credential-access", "privilege-escalation"],
    ),
    # Logging / audit / monitoring → Defense Evasion (disable logs)
    (
        ("logging", "cloudtrail", "audit", "monitoring"),
        ["defense-evasion"],
    ),
    # Storage / data → Collection + Exfiltration
    (
        ("storage", "s3", "blob", "bucket", "data protection"),
        ["collection", "exfiltration"],
    ),
    # Networking → Command and Control
    (
        ("network",),
        ["command-and-control"],
    ),
    # Access control / privilege → Privilege Escalation
    (
        ("access control", "privilege"),
        ["privilege-escalation"],
    ),
]

# ─── Per-check keyword refinements for CIS checks ────────────────────────────
#
# Maps keywords found in CIS check titles/evidence to specific tactic phases.
# The tactic phase is then resolved to techniques from the catalog at runtime.

_CHECK_KEYWORD_TACTICS: list[tuple[tuple[str, ...], list[str]]] = [
    (("mfa", "multi-factor"), ["credential-access"]),
    (("access key", "secret key", "api key", "credential rotation", "key rotation"), ["credential-access"]),
    (("public", "open", "unrestricted"), ["collection", "exfiltration"]),
    (("admin", "full access", "root", "privilege"), ["privilege-escalation"]),
    (("audit", "log", "trail", "monitoring"), ["defense-evasion"]),
    (("versioning", "delete", "destroy"), ["impact"]),
    (("ssh", "port 22", "rdp", "port 3389", "remote access"), ["command-and-control"]),
    (("encryption", "kms", "tls", "ssl", "crypto"), ["credential-access"]),
]


def _techniques_for_tactics(tactic_phases: list[str]) -> list[str]:
    """Return technique IDs from the catalog that belong to any of the given tactic phases."""
    from agent_bom.mitre_fetch import get_techniques

    all_techniques = get_techniques()
    result: list[str] = []
    for tid, meta in all_techniques.items():
        if any(t in tactic_phases for t in meta.get("tactics", [])):
            result.append(tid)
    return result


# ─── Public API ───────────────────────────────────────────────────────────────


def tag_cis_check(check: object) -> list[str]:
    """Return MITRE ATT&CK Enterprise technique IDs for a failed CIS check.

    Resolves techniques from the active ATT&CK catalog by
    mapping the check's section keywords and title keywords to tactic phases,
    then returning all techniques in those tactics.

    Only FAILED checks are tagged.  Passing/error checks produce no output.

    Args:
        check: A CISCheckResult-compatible object with ``.status``,
               ``.cis_section``, and ``.title`` attributes.

    Returns:
        Sorted list of ATT&CK technique IDs (from live catalog).
        Empty list when check passed or errored.
    """
    from agent_bom.cloud.aws_cis_benchmark import CheckStatus

    status = getattr(check, "status", None)
    if status != CheckStatus.FAIL:
        return []

    tactic_phases: set[str] = set()
    section_lower = (getattr(check, "cis_section", "") or "").lower()
    title_lower = (getattr(check, "title", "") or "").lower()
    combined = f"{section_lower} {title_lower}"

    # Section-based tactic mapping
    for keywords, tactics in _SECTION_TO_TACTICS:
        if any(kw in section_lower for kw in keywords):
            tactic_phases.update(tactics)

    # Check title / content keyword refinements
    for keywords, tactics in _CHECK_KEYWORD_TACTICS:
        if any(kw in combined for kw in keywords):
            tactic_phases.update(tactics)

    if not tactic_phases:
        # Default: any failed check is at minimum an initial-access signal
        tactic_phases.add("initial-access")

    return sorted(set(_techniques_for_tactics(list(tactic_phases))))


def tag_provenance_finding(finding: dict) -> list[str]:
    """Return ATT&CK technique IDs for a model provenance finding.

    Maps ``risk_flags`` from model provenance analysis to tactic phases, then
    resolves to techniques from the live catalog.

    Args:
        finding: Dict with keys like ``risk_flags`` (list of str), ``format``,
                 ``source`` (hf/ollama).

    Returns:
        Sorted list of ATT&CK technique IDs.
    """
    risk_flags: list[str] = finding.get("risk_flags", [])
    if not risk_flags:
        return []

    tactic_phases: set[str] = set()
    for flag in risk_flags:
        # Unsafe serialization — code execution risk (pickle, .pt)
        if "unsafe_format" in flag:
            tactic_phases.update(["execution", "initial-access"])
        # No digest — integrity not verifiable → supply chain (initial-access)
        if "no_digest" in flag:
            tactic_phases.add("initial-access")
        # Public ungated large model — exfiltration surface
        if "public_large" in flag:
            tactic_phases.update(["collection", "exfiltration"])

    return sorted(set(_techniques_for_tactics(list(tactic_phases))))


def tag_blast_radius(br: BlastRadius) -> list[str]:
    """Return MITRE ATT&CK Enterprise technique IDs for a CVE blast radius.

    Combines two signal sources — all resolved against the shipped MITRE
    ATT&CK catalog and STIX-derived mappings bundled with agent-bom:

    1. **CWE-based**: maps each CWE weakness ID on the vulnerability to
       ATT&CK techniques via the official CAPEC bridge
       (CWE → CAPEC → ATT&CK, derived from MITRE's STIX data).
    2. **Context-based**: maps blast-radius characteristics (exposed credentials,
       reachable exec tools, CISA KEV status, severity) to tactic phases, then
       resolves those phases to catalog techniques.

    The scan path does not fetch framework catalogs at runtime. Catalog refreshes
    happen out of band so scans remain deterministic and offline-friendly.

    Only MITRE ATT&CK Enterprise techniques (T-codes) are returned here.
    MITRE ATLAS techniques (AML.T-codes) are handled by :func:`atlas.tag_blast_radius`.

    Args:
        br: A :class:`~agent_bom.models.BlastRadius` instance.

    Returns:
        Sorted list of ATT&CK technique IDs from the pinned local catalog.
        Empty list when no CWE or context signals apply.
    """
    from agent_bom.constants import high_risk_severities
    from agent_bom.mitre_fetch import get_cwe_to_attack
    from agent_bom.risk_analyzer import ToolCapability, classify_tool

    cwe_map = get_cwe_to_attack()
    techniques: set[str] = set()
    mapped_from_cwe = False

    # 1. CWE → ATT&CK via CAPEC official data
    for cwe in br.vulnerability.cwe_ids:
        # Normalise: accept "CWE-78", "78", "cwe-78"
        cwe_norm = cwe.strip().upper()
        if not cwe_norm.startswith("CWE-"):
            cwe_norm = f"CWE-{cwe_norm}"
        direct_mappings = cwe_map.get(cwe_norm, [])
        if direct_mappings:
            mapped_from_cwe = True
        for tech in direct_mappings:
            techniques.add(tech)

    # 2. Context-based signals → tactic phases → catalog techniques
    high_risk = high_risk_severities()
    is_high = br.vulnerability.severity in high_risk

    tactic_phases: set[str] = set()

    # Exposed credentials → credential-access tactic
    if br.exposed_credentials:
        tactic_phases.add("credential-access")

    # CISA KEV or CRITICAL severity → direct exploitation (initial-access)
    if br.vulnerability.is_kev or br.vulnerability.severity.value == "critical":
        tactic_phases.add("initial-access")

    # Reachable exec tools → execution tactic
    for tool in br.exposed_tools:
        caps = classify_tool(tool.name, tool.description)
        if ToolCapability.EXECUTE in caps:
            tactic_phases.add("execution")
            break

    # HIGH+ with no CWE IDs → initial-access is the baseline tactic
    if is_high and not mapped_from_cwe:
        tactic_phases.add("initial-access")

    # Resolve tactic phases to catalog techniques
    for tech in _techniques_for_tactics(list(tactic_phases)):
        techniques.add(tech)

    return sorted(techniques)


def attack_label(technique_id: str) -> str:
    """Return human-readable label, e.g. ``'T1078 Valid Accounts'``."""
    name = ATTACK_TECHNIQUES.get(technique_id, "Unknown")
    return f"{technique_id} {name}"


def attack_labels(technique_ids: list[str]) -> list[str]:
    """Return human-readable labels for a list of ATT&CK technique IDs."""
    return [attack_label(t) for t in technique_ids]
