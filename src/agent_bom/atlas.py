"""MITRE ATLAS — map blast radius findings to AI/ML adversarial techniques.

MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems)
catalogs adversary tactics, techniques, and procedures (TTPs) targeting AI/ML
systems. We map agent-bom findings to the most relevant ATLAS techniques so
security teams can prioritize remediation using a familiar framework.

Curation rationale
------------------
The ``ATLAS_TECHNIQUES`` dict below is a deliberately curated 65-technique
subset of the full upstream catalog (170 techniques as of ATLAS 5.6.0, see
``data/mitre_atlas_catalog.json``). The curation rules are:

- **Include** every technique that is observable from static, agentless
  signals: package metadata, IaC manifests, MCP tool capability, exposed
  credentials, severity, and CVE category. These are the techniques the
  blast-radius tagger in :func:`tag_blast_radius` can light up with high
  precision and zero runtime model introspection.
- **Exclude** techniques that fundamentally require runtime model probing,
  inference-time observation, training-pipeline telemetry, or red-team
  campaign data. Tagging those from a static SBOM-style scan would produce
  noise and false positives. Examples: live model extraction probes, online
  evasion attempts, deployed-model poisoning detection, runtime adversarial
  example crafting.
- **Keep the curated set load-bearing for tagging.** The bundled JSON catalog
  (``mitre_atlas_catalog.json``) is reference data only — it powers
  "X of N upstream techniques covered" rollups in the dashboard and SARIF
  metadata, but the tag surface stays at 65 to preserve precision.

Reference: https://atlas.mitre.org/
Upstream source: https://github.com/mitre-atlas/atlas-data
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from agent_bom.constants import AI_PACKAGES as _AI_PACKAGES
from agent_bom.constants import high_risk_severities
from agent_bom.risk_analyzer import ToolCapability, classify_mcp_tool

if TYPE_CHECKING:
    from agent_bom.models import BlastRadius


# ─── Catalog (curated tagging surface — see module docstring for rationale) ───
# 65 techniques chosen for static-signal observability. The full upstream
# catalog ships in ``data/mitre_atlas_catalog.json`` for reference.

ATLAS_TECHNIQUES: dict[str, str] = {
    # Reconnaissance
    "AML.T0000": "Search Open Technical Databases",
    "AML.T0001": "Search Open AI Vulnerability Analysis",
    "AML.T0004": "Search Application Repositories",
    "AML.T0006": "Active Scanning",
    "AML.T0007": "Discover AI Artifacts",
    # Resource Development
    "AML.T0008": "Acquire Infrastructure",
    "AML.T0016": "Obtain Capabilities",
    "AML.T0017": "Develop Capabilities",
    # Initial Access
    "AML.T0010": "AI Supply Chain Compromise",
    "AML.T0010.001": "AI Software",
    "AML.T0010.002": "Data",
    "AML.T0010.003": "Model",
    "AML.T0010.004": "Container Registry",
    "AML.T0011": "User Execution",
    "AML.T0011.001": "Malicious Package",
    "AML.T0012": "Valid Accounts",
    "AML.T0049": "Exploit Public-Facing Application",
    # Execution
    "AML.T0050": "Command and Scripting Interpreter",
    "AML.T0053": "AI Agent Tool Invocation",
    # Persistence / Defense Evasion
    "AML.T0018": "Manipulate AI Model",
    "AML.T0018.000": "Poison AI Model",
    "AML.T0018.001": "Modify AI Model Architecture",
    "AML.T0018.002": "Embed Malware",
    "AML.T0074": "Masquerading",
    # Credential Access
    "AML.T0055": "Unsecured Credentials",
    # Discovery
    "AML.T0013": "Discover AI Model Ontology",
    "AML.T0014": "Discover AI Model Family",
    "AML.T0040": "AI Model Inference API Access",
    "AML.T0063": "Discover AI Model Outputs",
    "AML.T0064": "Gather RAG-Indexed Targets",
    "AML.T0069": "Discover LLM System Information",
    # Collection
    "AML.T0035": "AI Artifact Collection",
    "AML.T0036": "Data from Information Repositories",
    "AML.T0037": "Data from Local System",
    # ML Attack Staging
    "AML.T0002": "Acquire Public AI Artifacts",
    "AML.T0005": "Create Proxy AI Model",
    "AML.T0015": "Evade AI Model",
    "AML.T0019": "Publish Poisoned Datasets",
    "AML.T0020": "Poison Training Data",
    "AML.T0043": "Craft Adversarial Data",
    "AML.T0043.004": "Insert Backdoor Trigger",
    "AML.T0070": "RAG Poisoning",
    "AML.T0071": "False RAG Entry Injection",
    # LLM / AI Agent Exploitation
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0051.000": "Direct Prompt Injection",
    "AML.T0051.001": "Indirect Prompt Injection",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0056": "Extract LLM System Prompt",
    "AML.T0057": "LLM Data Leakage",
    "AML.T0065": "LLM Prompt Crafting",
    "AML.T0066": "Retrieval Content Crafting",
    "AML.T0067": "LLM Trusted Output Components Manipulation",
    "AML.T0068": "LLM Prompt Obfuscation",
    # Exfiltration
    "AML.T0024": "Exfiltration via AI Inference API",
    "AML.T0024.001": "Invert AI Model",
    "AML.T0024.002": "Extract AI Model",
    "AML.T0025": "Exfiltration via Cyber Means",
    # Impact
    "AML.T0029": "Denial of AI Service",
    "AML.T0031": "Erode AI Model Integrity",
    "AML.T0034": "Cost Harvesting",
    "AML.T0046": "Spamming AI System with Chaff Data",
    "AML.T0048": "External Harms",
    # Social Engineering
    "AML.T0052": "Phishing",
    "AML.T0052.000": "Spearphishing via Social Engineering LLM",
    "AML.T0073": "Impersonation",
}

_HIGH_RISK = high_risk_severities()


# ─── Tagger ───────────────────────────────────────────────────────────────────


def tag_blast_radius(br: BlastRadius) -> list[str]:
    """Return sorted MITRE ATLAS technique IDs applicable to this blast radius.

    Maps 30+ ATLAS techniques based on observable signals: tool capabilities,
    credential exposure, AI package context, severity, and vulnerability type.
    Techniques that require runtime introspection (model ontology discovery,
    inference probing) are only tagged when relevant signals are present.
    """
    tags: set[str] = set()

    # ── Initial Access ────────────────────────────────────────────────────
    tags.add("AML.T0010")  # AI Supply Chain Compromise — always
    tags.add("AML.T0010.001")  # AI Software sub-technique — always

    is_ai_pkg = br.package.name.lower() in _AI_PACKAGES
    is_high = br.vulnerability.severity in _HIGH_RISK
    has_creds = bool(br.exposed_credentials)
    has_exec = False
    has_read = False
    has_write = False

    for tool in br.exposed_tools:
        caps = classify_mcp_tool(tool)
        if ToolCapability.EXECUTE in caps:
            has_exec = True
        if ToolCapability.READ in caps:
            has_read = True
        if ToolCapability.WRITE in caps:
            has_write = True

    # Malicious package detection (from OSV MAL- IDs)
    vuln_id = br.vulnerability.id
    if vuln_id.startswith("MAL-") or "malicious" in br.vulnerability.summary.lower():
        tags.add("AML.T0011")  # User Execution
        tags.add("AML.T0011.001")  # Malicious Package

    # Valid accounts (credential exposure)
    if has_creds:
        tags.add("AML.T0012")  # Valid Accounts
        tags.add("AML.T0055")  # Unsecured Credentials

    # Public-facing app exploit (HIGH+ CVE in web-exposed package)
    if is_high:
        tags.add("AML.T0049")  # Exploit Public-Facing Application

    # ── Execution ─────────────────────────────────────────────────────────
    if has_exec:
        tags.add("AML.T0050")  # Command and Scripting Interpreter
        tags.add("AML.T0043")  # Craft Adversarial Data
        tags.add("AML.T0043.004")  # Insert Backdoor Trigger (exec + AI pkg)

    if br.exposed_tools:
        tags.add("AML.T0053")  # AI Agent Tool Invocation

    # ── Persistence / Defense Evasion ─────────────────────────────────────
    if is_ai_pkg and has_write:
        tags.add("AML.T0018")  # Manipulate AI Model
        tags.add("AML.T0018.000")  # Poison AI Model
        tags.add("AML.T0018.002")  # Embed Malware (write + exec)

    if is_ai_pkg and is_high:
        tags.add("AML.T0074")  # Masquerading (compromised AI component)

    # ── Discovery ─────────────────────────────────────────────────────────
    if is_ai_pkg and has_read:
        tags.add("AML.T0013")  # Discover AI Model Ontology
        tags.add("AML.T0014")  # Discover AI Model Family
        tags.add("AML.T0063")  # Discover AI Model Outputs
        tags.add("AML.T0069")  # Discover LLM System Information

    if is_ai_pkg and has_creds:
        tags.add("AML.T0040")  # AI Model Inference API Access

    # ── LLM / AI Agent Exploitation ───────────────────────────────────────
    if has_read:
        tags.add("AML.T0051")  # LLM Prompt Injection
        tags.add("AML.T0051.001")  # Indirect Prompt Injection (via tools)
        tags.add("AML.T0056")  # Extract LLM System Prompt
        tags.add("AML.T0065")  # LLM Prompt Crafting

    if has_read and has_write:
        tags.add("AML.T0066")  # Retrieval Content Crafting
        tags.add("AML.T0064")  # Gather RAG-Indexed Targets
        tags.add("AML.T0070")  # RAG Poisoning
        tags.add("AML.T0071")  # False RAG Entry Injection

    if has_creds and has_read:
        tags.add("AML.T0057")  # LLM Data Leakage
        tags.add("AML.T0067")  # LLM Trusted Output Components Manipulation

    if has_exec and has_read:
        tags.add("AML.T0054")  # LLM Jailbreak (exec enables bypass)
        tags.add("AML.T0068")  # LLM Prompt Obfuscation

    # ── Collection ────────────────────────────────────────────────────────
    if has_read:
        tags.add("AML.T0035")  # AI Artifact Collection
        tags.add("AML.T0036")  # Data from Information Repositories
        tags.add("AML.T0037")  # Data from Local System

    # ── ML Attack Staging ─────────────────────────────────────────────────
    if is_ai_pkg and is_high:
        tags.add("AML.T0020")  # Poison Training Data
        tags.add("AML.T0019")  # Publish Poisoned Datasets (supply chain)

    # ── Exfiltration ──────────────────────────────────────────────────────
    if is_ai_pkg and has_creds:
        tags.add("AML.T0024")  # Exfiltration via AI Inference API

    if has_creds and has_exec:
        tags.add("AML.T0025")  # Exfiltration via Cyber Means

    # ── Impact ────────────────────────────────────────────────────────────
    if is_high and br.exposed_tools:
        tags.add("AML.T0029")  # Denial of AI Service
        tags.add("AML.T0034")  # Cost Harvesting

    if is_ai_pkg and is_high:
        tags.add("AML.T0031")  # Erode AI Model Integrity

    if has_exec and has_creds:
        tags.add("AML.T0048")  # External Harms

    # ── Social Engineering ────────────────────────────────────────────────
    if has_read and has_exec:
        tags.add("AML.T0052")  # Phishing (tool chain enables)
        tags.add("AML.T0052.000")  # Spearphishing via Social Engineering LLM

    return sorted(tags)


def atlas_label(technique_id: str) -> str:
    """Return human-readable label, e.g. 'AML.T0010 AI Supply Chain Compromise'."""
    name = ATLAS_TECHNIQUES.get(technique_id, "Unknown")
    return f"{technique_id} {name}"


def atlas_labels(technique_ids: list[str]) -> list[str]:
    """Return human-readable labels for a list of ATLAS technique IDs."""
    return [atlas_label(t) for t in technique_ids]


def upstream_catalog() -> dict:
    """Return the bundled (or synced) full upstream ATLAS catalog.

    Used by dashboard / SARIF surfaces to show coverage as
    "curated X of N upstream techniques". The tagging surface in
    :data:`ATLAS_TECHNIQUES` stays at the curated subset; this function
    exposes the broader reference catalog without widening the tag map.
    """
    from agent_bom.atlas_fetch import load_catalog

    return load_catalog()


def upstream_total() -> int:
    """Return the count of techniques in the upstream ATLAS reference catalog."""
    return len(upstream_catalog().get("techniques", {}))


def curated_total() -> int:
    """Return the count of techniques in the curated tag surface."""
    return len(ATLAS_TECHNIQUES)
