"""MITRE ATLAS — map blast radius findings to AI/ML adversarial techniques.

MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems)
catalogs adversary tactics, techniques, and procedures (TTPs) targeting AI/ML
systems. We map agent-bom findings to the most relevant ATLAS techniques so
security teams can prioritize remediation using a familiar framework.

Reference: https://atlas.mitre.org/
Catalog version: as published at github.com/mitre-atlas/atlas-data (March 2026)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from agent_bom.constants import AI_PACKAGES as _AI_PACKAGES
from agent_bom.constants import high_risk_severities
from agent_bom.risk_analyzer import ToolCapability, classify_tool

if TYPE_CHECKING:
    from agent_bom.models import BlastRadius


# ─── Catalog (current as of ATLAS March 2026 release) ─────────────────────────
# Only the techniques relevant to AI/ML supply chain risk and agent security
# are included; the full catalog has 75+ entries.

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

    Rules:
    - AML.T0010: Always — any package CVE in an AI agent is supply chain compromise.
    - AML.T0010.001: Always (AI Software sub-technique).
    - AML.T0055: Credential env vars exposed → unsecured credentials.
    - AML.T0053: Reachable agent tools → AI Agent Tool Invocation.
    - AML.T0051: Reachable tools can read prompts/context → prompt injection surface.
    - AML.T0056: Reachable tools can read files/resources → extract system prompt.
    - AML.T0057: Credential exposure + read tools → LLM data leakage risk.
    - AML.T0043: Reachable tools have exec/shell capability → craft adversarial data.
    - AML.T0020: AI/ML framework package with HIGH+ CVE → poison training data.
    - AML.T0024: AI/ML framework + credentials → exfiltration via inference API.
    """
    tags: set[str] = {"AML.T0010", "AML.T0010.001"}  # always — AI supply chain

    # AML.T0055 — unsecured credentials
    if br.exposed_credentials:
        tags.add("AML.T0055")

    has_exec = False
    has_read = False

    for tool in br.exposed_tools:
        caps = classify_tool(tool.name, tool.description)
        if ToolCapability.EXECUTE in caps:
            has_exec = True
        if ToolCapability.READ in caps:
            has_read = True

    # AML.T0053 — AI agent tool invocation (any reachable tools)
    if br.exposed_tools:
        tags.add("AML.T0053")

    # AML.T0051 — LLM prompt injection (read tools reachable — can access context)
    if has_read:
        tags.add("AML.T0051")

    # AML.T0056 — extract LLM system prompt (read tools)
    if has_read:
        tags.add("AML.T0056")

    # AML.T0057 — LLM data leakage (credentials + read access)
    if br.exposed_credentials and has_read:
        tags.add("AML.T0057")

    # AML.T0043 — craft adversarial data (exec tools)
    if has_exec:
        tags.add("AML.T0043")

    is_ai_pkg = br.package.name.lower() in _AI_PACKAGES
    is_high = br.vulnerability.severity in _HIGH_RISK

    # AML.T0020 — poison training data (AI framework + HIGH+ CVE)
    if is_ai_pkg and is_high:
        tags.add("AML.T0020")

    # AML.T0024 — exfiltration via AI inference API (AI + creds)
    if is_ai_pkg and br.exposed_credentials:
        tags.add("AML.T0024")

    return sorted(tags)


def atlas_label(technique_id: str) -> str:
    """Return human-readable label, e.g. 'AML.T0010 AI Supply Chain Compromise'."""
    name = ATLAS_TECHNIQUES.get(technique_id, "Unknown")
    return f"{technique_id} {name}"


def atlas_labels(technique_ids: list[str]) -> list[str]:
    """Return human-readable labels for a list of ATLAS technique IDs."""
    return [atlas_label(t) for t in technique_ids]
