"""CVE-level compliance framework tagging.

Tags individual vulnerabilities with framework codes using only CVE-intrinsic
properties (severity, is_kev, epss_score, cwe_ids, fixed_version, package type).

Context-dependent tags (credentials, tools, agents) remain at the BlastRadius
level in each framework's ``tag_blast_radius()`` function.
"""

from __future__ import annotations

from agent_bom.constants import AI_PACKAGES, SAST_CWE_MAP, TRAINING_DATA_PACKAGES
from agent_bom.models import Package, Severity, Vulnerability

_HIGH_RISK = frozenset({Severity.CRITICAL, Severity.HIGH})


def tag_vulnerability(vuln: Vulnerability, package: Package) -> dict[str, list[str]]:
    """Tag a CVE with compliance framework codes based on intrinsic properties.

    Returns a dict mapping framework key → list of tag strings.
    Only uses CVE-intrinsic properties — no deployment context.
    """
    is_high = vuln.severity in _HIGH_RISK
    is_kev = vuln.is_kev
    has_fix = vuln.fixed_version is not None
    pkg_lower = package.name.lower()
    is_ai = pkg_lower in AI_PACKAGES
    is_training = pkg_lower in TRAINING_DATA_PACKAGES
    is_malicious = package.is_malicious
    is_sast = package.ecosystem == "sast"
    cwe_ids = vuln.cwe_ids

    tags: dict[str, list[str]] = {}

    # ── OWASP Top 10 for LLM Applications ──────────────────────────────
    owasp_llm: list[str] = []
    if is_ai:
        owasp_llm.append("LLM05")
    if is_training:
        owasp_llm.append("LLM03")
    if is_ai and is_high:
        owasp_llm.append("LLM04")
    if is_sast and cwe_ids:
        for cwe in cwe_ids:
            for t in SAST_CWE_MAP.get(cwe, {}).get("owasp_llm", []):
                if t not in owasp_llm:
                    owasp_llm.append(t)
    if owasp_llm:
        tags["owasp_llm"] = sorted(set(owasp_llm))

    # ── MITRE ATLAS ─────────────────────────────────────────────────────
    atlas: list[str] = []
    # AML.T0010 (Supply Chain Compromise) — only for actual supply chain vulns
    if is_malicious or (is_ai and is_high) or is_kev:
        atlas.append("AML.T0010")
    if is_ai and is_high:
        atlas.append("AML.T0043")  # Craft Adversarial Data
    if is_training:
        atlas.append("AML.T0020")  # Poison Training Data
    if atlas:
        tags["atlas"] = sorted(set(atlas))

    # ── NIST AI RMF ─────────────────────────────────────────────────────
    nist_rmf: list[str] = ["GOVERN-1.7", "MAP-3.5"]
    if is_ai and is_high:
        nist_rmf.append("MEASURE-2.5")
    if has_fix:
        nist_rmf.append("MEASURE-2.9")
    if is_kev:
        nist_rmf.append("MANAGE-1.3")
    tags["nist_ai_rmf"] = sorted(set(nist_rmf))

    # ── NIST CSF 2.0 ───────────────────────────────────────────────────
    nist_csf: list[str] = ["DE.CM-09", "GV.SC-05", "GV.SC-07", "ID.RA-01"]
    if is_high:
        nist_csf.append("ID.RA-05")
    if is_ai:
        nist_csf.append("ID.AM-05")
    if is_kev or (vuln.epss_score is not None and vuln.epss_score > 0):
        nist_csf.append("ID.RA-02")
    if has_fix:
        nist_csf.append("RS.AN-03")
    if is_kev:
        nist_csf.append("RS.MI-02")
    if is_sast and cwe_ids:
        for cwe in cwe_ids:
            for t in SAST_CWE_MAP.get(cwe, {}).get("nist_csf", []):
                if t not in nist_csf:
                    nist_csf.append(t)
    tags["nist_csf"] = sorted(set(nist_csf))

    # ── CIS Controls v8 ────────────────────────────────────────────────
    cis: list[str] = ["CIS-02.1", "CIS-07.1", "CIS-07.5"]
    if is_high:
        cis.append("CIS-02.3")
    if is_ai:
        cis.append("CIS-02.7")
    if has_fix:
        cis.append("CIS-07.4")
    if is_kev:
        cis.append("CIS-16.12")
    if is_sast and cwe_ids:
        for cwe in cwe_ids:
            for t in SAST_CWE_MAP.get(cwe, {}).get("cis", []):
                if t not in cis:
                    cis.append(t)
    tags["cis"] = sorted(set(cis))

    # ── ISO 27001:2022 ──────────────────────────────────────────────────
    iso: list[str] = ["A.5.19", "A.5.21", "A.8.8"]
    if is_high:
        iso.append("A.5.20")
    if is_ai:
        iso.append("A.5.23")
    if is_kev:
        iso.append("A.5.28")
    if has_fix:
        iso.append("A.8.28")
    if is_sast and cwe_ids:
        for cwe in cwe_ids:
            for t in SAST_CWE_MAP.get(cwe, {}).get("iso_27001", []):
                if t not in iso:
                    iso.append(t)
    tags["iso_27001"] = sorted(set(iso))

    # ── SOC 2 TSC ───────────────────────────────────────────────────────
    soc2: list[str] = ["CC7.1", "CC9.1", "CC9.2"]
    if is_high:
        soc2.append("CC6.8")
    if is_ai:
        soc2.append("CC7.2")
    if is_kev:
        soc2.append("CC7.4")
    if has_fix:
        soc2.append("CC8.1")
    if is_sast and cwe_ids:
        for cwe in cwe_ids:
            for t in SAST_CWE_MAP.get(cwe, {}).get("soc2", []):
                if t not in soc2:
                    soc2.append(t)
    tags["soc2"] = sorted(set(soc2))

    # ── EU AI Act ───────────────────────────────────────────────────────
    eu: list[str] = ["ART-15", "ART-9"]
    if is_ai:
        eu.append("ART-6")
    if has_fix:
        eu.append("ART-17")
    tags["eu_ai_act"] = sorted(set(eu))

    # ── OWASP MCP Top 10 ───────────────────────────────────────────────
    mcp: list[str] = ["MCP04"]
    if is_malicious:
        mcp.append("MCP03")
    tags["owasp_mcp"] = sorted(set(mcp))

    # ── OWASP Agentic Top 10 ───────────────────────────────────────────
    agentic: list[str] = []
    # ASI04 (Supply Chain) — always relevant for dependency vulns
    agentic.append("ASI04")
    if is_ai:
        agentic.append("ASI01")  # Excessive Agency
    if is_malicious:
        agentic.append("ASI02")  # Tool Misuse
        agentic.append("ASI10")  # Rogue Agent Persistence
    if is_kev:
        agentic.append("ASI09")  # Human-Agent Trust Exploitation
    if agentic:
        tags["owasp_agentic"] = sorted(set(agentic))

    return tags
