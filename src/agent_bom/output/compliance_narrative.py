"""Compliance narrative generator — auditor-ready stories from scan data.

Produces human-readable compliance narratives from AIBOMReport data without
requiring an LLM.  Uses template strings and structured data from blast_radius
entries to generate executive summaries, per-framework stories, and
remediation-compliance bridges.

Supported frameworks (slug → display name):
    owasp-llm         OWASP Top 10 for LLM
    owasp-mcp         OWASP MCP Top 10
    atlas             MITRE ATLAS
    nist              NIST AI RMF
    owasp-agentic     OWASP Agentic Top 10
    eu-ai-act         EU AI Act
    nist-csf          NIST CSF 2.0
    iso-27001         ISO 27001:2022
    soc2              SOC 2 TSC
    cis               CIS Controls v8
    cmmc              CMMC 2.0
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent_bom.models import AIBOMReport

# ─── Catalogue lookups ────────────────────────────────────────────────────────
# Imported lazily where needed to keep top-level import cost low.


def _get_catalog(slug: str) -> tuple[dict[str, str], str, str]:
    """Return (catalog_dict, tag_field_on_blast_radius, display_name) for a framework slug."""
    from agent_bom.atlas import ATLAS_TECHNIQUES
    from agent_bom.cis_controls import CIS_CONTROLS
    from agent_bom.cmmc import CMMC_PRACTICES
    from agent_bom.eu_ai_act import EU_AI_ACT
    from agent_bom.iso_27001 import ISO_27001
    from agent_bom.nist_ai_rmf import NIST_AI_RMF
    from agent_bom.nist_csf import NIST_CSF
    from agent_bom.owasp import OWASP_LLM_TOP10
    from agent_bom.owasp_agentic import OWASP_AGENTIC_TOP10
    from agent_bom.owasp_mcp import OWASP_MCP_TOP10
    from agent_bom.soc2 import SOC2_TSC

    framework_map: dict[str, tuple[dict[str, str], str, str]] = {
        "owasp-llm": (OWASP_LLM_TOP10, "owasp_tags", "OWASP Top 10 for LLM"),
        "owasp-mcp": (OWASP_MCP_TOP10, "owasp_mcp_tags", "OWASP MCP Top 10"),
        "atlas": (ATLAS_TECHNIQUES, "atlas_tags", "MITRE ATLAS"),
        "nist": (NIST_AI_RMF, "nist_ai_rmf_tags", "NIST AI RMF"),
        "owasp-agentic": (OWASP_AGENTIC_TOP10, "owasp_agentic_tags", "OWASP Agentic Top 10"),
        "eu-ai-act": (EU_AI_ACT, "eu_ai_act_tags", "EU AI Act"),
        "nist-csf": (NIST_CSF, "nist_csf_tags", "NIST CSF 2.0"),
        "iso-27001": (ISO_27001, "iso_27001_tags", "ISO 27001:2022"),
        "soc2": (SOC2_TSC, "soc2_tags", "SOC 2 TSC"),
        "cis": (CIS_CONTROLS, "cis_tags", "CIS Controls v8"),
        "cmmc": (CMMC_PRACTICES, "cmmc_tags", "CMMC 2.0"),
    }
    entry = framework_map.get(slug)
    if entry is None:
        raise ValueError(f"Unknown framework '{slug}'. Supported: {', '.join(framework_map.keys())}")
    return entry


ALL_FRAMEWORK_SLUGS: list[str] = [
    "owasp-llm",
    "owasp-mcp",
    "atlas",
    "nist",
    "owasp-agentic",
    "eu-ai-act",
    "nist-csf",
    "iso-27001",
    "soc2",
    "cis",
    "cmmc",
]


# ─── Dataclasses ─────────────────────────────────────────────────────────────


@dataclass
class ControlNarrative:
    """Auditor-facing explanation of a single failing control."""

    control_id: str
    title: str
    status: str  # "pass" | "warning" | "fail"
    narrative: str
    affected_packages: list[str] = field(default_factory=list)
    affected_agents: list[str] = field(default_factory=list)
    remediation_steps: list[str] = field(default_factory=list)


@dataclass
class FrameworkNarrative:
    """Per-framework compliance story."""

    framework: str  # display name, e.g. "OWASP Top 10 for LLM"
    slug: str  # e.g. "owasp-llm"
    status: str  # "passing" | "at_risk" | "failing"
    score: int  # 0-100
    narrative: str  # 2-3 sentences
    failing_controls: list[ControlNarrative] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)


@dataclass
class RemediationImpact:
    """How a single package upgrade maps to compliance controls."""

    package: str
    current_version: str
    fix_version: str  # empty string when no fix is available
    controls_fixed: list[str]  # control codes, e.g. ["LLM05", "MCP04"]
    frameworks_impacted: list[str]  # framework display names
    narrative: str  # "Upgrading X from Y to Z fixes controls A, B, C"


@dataclass
class ComplianceNarrative:
    """Full auditor-ready compliance story from a scan."""

    executive_summary: str
    framework_narratives: list[FrameworkNarrative]
    remediation_impact: list[RemediationImpact]
    risk_narrative: str
    generated_at: str  # ISO 8601


# ─── Internal helpers ─────────────────────────────────────────────────────────


def _severity_order(sev: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(sev.lower(), 4)


def _control_status(sev_breakdown: dict[str, int]) -> str:
    if sev_breakdown.get("critical", 0) > 0 or sev_breakdown.get("high", 0) > 0:
        return "fail"
    if sev_breakdown.get("medium", 0) > 0 or sev_breakdown.get("low", 0) > 0:
        return "warning"
    return "pass"


def _control_narrative(
    control_id: str,
    control_name: str,
    findings: int,
    affected_pkgs: list[str],
    affected_agents: list[str],
    sev_breakdown: dict[str, int],
) -> str:
    """Generate a plain-English explanation for a control's status."""
    if findings == 0:
        return (
            f"Control {control_id} ({control_name}) shows no findings in this scan. "
            "All assessed packages are compliant with this requirement."
        )

    pkg_str = ", ".join(affected_pkgs[:3])
    if len(affected_pkgs) > 3:
        pkg_str += f" and {len(affected_pkgs) - 3} more"

    agent_str = ""
    if affected_agents:
        a_list = ", ".join(affected_agents[:3])
        agent_str = f" reaching agent{'s' if len(affected_agents) > 1 else ''} {a_list}"

    crit = sev_breakdown.get("critical", 0)
    high = sev_breakdown.get("high", 0)
    med = sev_breakdown.get("medium", 0)

    severity_desc = ""
    if crit:
        severity_desc = f"{crit} critical"
        if high:
            severity_desc += f" and {high} high"
    elif high:
        severity_desc = f"{high} high"
    elif med:
        severity_desc = f"{med} medium"
    else:
        severity_desc = "low"

    return (
        f"Control {control_id} ({control_name}) has {findings} finding"
        f"{'s' if findings > 1 else ''} ({severity_desc} severity) "
        f"in packages: {pkg_str}{agent_str}. "
        "Immediate remediation is required to achieve compliance."
    )


def _control_remediation_steps(
    control_id: str,
    control_name: str,
    affected_pkgs: list[str],
    sev_breakdown: dict[str, int],
) -> list[str]:
    """Generate actionable remediation steps for a failing control."""
    steps: list[str] = []
    if affected_pkgs:
        steps.append(f"Upgrade vulnerable packages: {', '.join(affected_pkgs[:5])}" + (" (and others)" if len(affected_pkgs) > 5 else ""))
    if sev_breakdown.get("critical", 0) or sev_breakdown.get("high", 0):
        steps.append("Prioritise critical and high severity findings for immediate patching — these represent active compliance failures.")
    steps.append(f"Re-run agent-bom after upgrades to verify {control_id} returns to passing status.")
    steps.append(f"Document the remediation timeline for {control_name} in your compliance evidence package.")
    return steps


def _framework_overall_narrative(
    display_name: str,
    total_controls: int,
    pass_count: int,
    fail_count: int,
    warn_count: int,
    critical_failing: list[str],
    score: int,
) -> str:
    """2-3 sentence framework-level posture narrative."""
    if fail_count == 0 and warn_count == 0:
        return (
            f"The organisation is fully compliant with {display_name}: "
            f"all {total_controls} assessed controls are passing. "
            "No immediate action is required; continue monitoring with regular scans."
        )

    if fail_count == 0:
        return (
            f"{display_name} posture is at risk with {warn_count} control"
            f"{'s' if warn_count > 1 else ''} in warning state "
            f"(overall score {score}/100). "
            "Medium and low severity findings require remediation within the next maintenance cycle "
            "to prevent status degradation."
        )

    ctrl_str = ", ".join(critical_failing[:3])
    if len(critical_failing) > 3:
        ctrl_str += f" and {len(critical_failing) - 3} others"

    return (
        f"{display_name} compliance is failing: {fail_count} control"
        f"{'s' if fail_count > 1 else ''} have critical or high severity findings "
        f"(overall score {score}/100). "
        f"Failing controls include {ctrl_str}. "
        "Immediate remediation is required — unaddressed critical findings may constitute "
        "a regulatory breach under this framework."
    )


def _framework_recommendations(
    display_name: str,
    fail_count: int,
    warn_count: int,
    failing_controls: list[ControlNarrative],
) -> list[str]:
    """Generate 2-4 actionable framework-level recommendations."""
    recs: list[str] = []
    if fail_count:
        recs.append(
            f"Address all failing {display_name} controls before the next audit window — "
            "critical/high findings represent an active compliance gap."
        )
    if warn_count:
        recs.append(f"Schedule remediation for {display_name} warning-state controls within the next sprint or maintenance cycle.")
    if failing_controls:
        top_pkgs: list[str] = []
        for ctrl in failing_controls[:3]:
            top_pkgs.extend(ctrl.affected_packages[:2])
        if top_pkgs:
            recs.append(f"Prioritise upgrades to: {', '.join(dict.fromkeys(top_pkgs))}")
    recs.append(
        f"Export a {display_name} compliance evidence bundle with "
        "`agent-bom check --framework <framework> --export zip` for auditor submission."
    )
    return recs


# ─── Per-framework builder ────────────────────────────────────────────────────


def _build_framework_narrative(
    slug: str,
    blast_radii_dicts: list[dict],
) -> FrameworkNarrative:
    """Build a FrameworkNarrative for a single framework from pre-serialised blast radius data."""
    catalog, tag_field, display_name = _get_catalog(slug)

    control_data: dict[str, dict] = {}
    for code, name in catalog.items():
        control_data[code] = {
            "name": name,
            "findings": 0,
            "severity_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "affected_pkgs": set(),
            "affected_agents": set(),
        }

    for br in blast_radii_dicts:
        tags = br.get(tag_field, [])
        sev = (br.get("severity") or "").lower()
        pkg = br.get("package", "")
        agents = br.get("affected_agents", [])
        for tag in tags:
            if tag not in control_data:
                continue
            entry = control_data[tag]
            entry["findings"] += 1
            if sev in entry["severity_breakdown"]:
                entry["severity_breakdown"][sev] += 1
            if pkg:
                entry["affected_pkgs"].add(pkg)
            for agent in agents:
                entry["affected_agents"].add(agent)

    total_controls = len(control_data)
    pass_count = 0
    warn_count = 0
    fail_count = 0
    failing_controls: list[ControlNarrative] = []
    critical_failing_ids: list[str] = []

    for code, data in sorted(control_data.items()):
        status = _control_status(data["severity_breakdown"]) if data["findings"] > 0 else "pass"
        pkgs = sorted(data["affected_pkgs"])
        agents = sorted(data["affected_agents"])

        if status == "pass":
            pass_count += 1
        elif status == "warning":
            warn_count += 1
        else:
            fail_count += 1
            critical_failing_ids.append(code)

        if status in ("warning", "fail"):
            failing_controls.append(
                ControlNarrative(
                    control_id=code,
                    title=data["name"],
                    status=status,
                    narrative=_control_narrative(code, data["name"], data["findings"], pkgs, agents, data["severity_breakdown"]),
                    affected_packages=pkgs,
                    affected_agents=agents,
                    remediation_steps=_control_remediation_steps(code, data["name"], pkgs, data["severity_breakdown"]),
                )
            )

    score = round((pass_count / total_controls) * 100) if total_controls > 0 else 100

    if fail_count > 0:
        fw_status = "failing"
    elif warn_count > 0:
        fw_status = "at_risk"
    else:
        fw_status = "passing"

    narrative = _framework_overall_narrative(display_name, total_controls, pass_count, fail_count, warn_count, critical_failing_ids, score)
    recommendations = _framework_recommendations(display_name, fail_count, warn_count, failing_controls)

    return FrameworkNarrative(
        framework=display_name,
        slug=slug,
        status=fw_status,
        score=score,
        narrative=narrative,
        failing_controls=failing_controls,
        recommendations=recommendations,
    )


# ─── Remediation-compliance bridge ───────────────────────────────────────────


def _build_remediation_impact(
    blast_radii_dicts: list[dict],
) -> list[RemediationImpact]:
    """Cross-reference fix versions with control tags to build RemediationImpact entries.

    Groups blast radius entries by (package, current_version, fix_version),
    collects all framework control codes triggered, and generates a narrative.
    """
    from agent_bom.atlas import ATLAS_TECHNIQUES
    from agent_bom.cis_controls import CIS_CONTROLS
    from agent_bom.cmmc import CMMC_PRACTICES
    from agent_bom.eu_ai_act import EU_AI_ACT
    from agent_bom.iso_27001 import ISO_27001
    from agent_bom.nist_ai_rmf import NIST_AI_RMF
    from agent_bom.nist_csf import NIST_CSF
    from agent_bom.owasp import OWASP_LLM_TOP10
    from agent_bom.owasp_agentic import OWASP_AGENTIC_TOP10
    from agent_bom.owasp_mcp import OWASP_MCP_TOP10
    from agent_bom.soc2 import SOC2_TSC

    # Map control code → framework display name for narrative generation
    control_to_framework: dict[str, str] = {}
    for code in OWASP_LLM_TOP10:
        control_to_framework[code] = "OWASP Top 10 for LLM"
    for code in OWASP_MCP_TOP10:
        control_to_framework[code] = "OWASP MCP Top 10"
    for code in ATLAS_TECHNIQUES:
        control_to_framework[code] = "MITRE ATLAS"
    for code in NIST_AI_RMF:
        control_to_framework[code] = "NIST AI RMF"
    for code in OWASP_AGENTIC_TOP10:
        control_to_framework[code] = "OWASP Agentic Top 10"
    for code in EU_AI_ACT:
        control_to_framework[code] = "EU AI Act"
    for code in NIST_CSF:
        control_to_framework[code] = "NIST CSF 2.0"
    for code in ISO_27001:
        control_to_framework[code] = "ISO 27001:2022"
    for code in SOC2_TSC:
        control_to_framework[code] = "SOC 2 TSC"
    for code in CIS_CONTROLS:
        control_to_framework[code] = "CIS Controls v8"
    for code in CMMC_PRACTICES:
        control_to_framework[code] = "CMMC 2.0"

    tag_fields = [
        "owasp_tags",
        "owasp_mcp_tags",
        "atlas_tags",
        "nist_ai_rmf_tags",
        "owasp_agentic_tags",
        "eu_ai_act_tags",
        "nist_csf_tags",
        "iso_27001_tags",
        "soc2_tags",
        "cis_tags",
        "cmmc_tags",
    ]

    # Group: key = (pkg_name_version, fix_version)
    # value = {controls: set, frameworks: set}
    groups: dict[tuple[str, str], dict] = {}

    for br in blast_radii_dicts:
        raw_pkg = br.get("package", "")  # "name@version" format from json_fmt
        fix_ver = br.get("fixed_version") or ""

        # Extract current version from "name@version" string
        if "@" in raw_pkg:
            pkg_name, current_ver = raw_pkg.rsplit("@", 1)
        else:
            pkg_name = raw_pkg
            current_ver = ""

        key = (f"{pkg_name}@{current_ver}", fix_ver)
        if key not in groups:
            groups[key] = {
                "pkg_name": pkg_name,
                "current_ver": current_ver,
                "fix_ver": fix_ver,
                "controls": set(),
                "frameworks": set(),
            }

        for tag_field in tag_fields:
            for tag in br.get(tag_field, []):
                groups[key]["controls"].add(tag)
                fw = control_to_framework.get(tag)
                if fw:
                    groups[key]["frameworks"].add(fw)

    impacts: list[RemediationImpact] = []
    for _key, data in groups.items():
        controls = sorted(data["controls"])
        frameworks = sorted(data["frameworks"])
        if not controls:
            continue  # skip entries with no compliance tags

        pkg_name = data["pkg_name"]
        current_ver = data["current_ver"]
        fix_ver = data["fix_ver"]

        if fix_ver:
            ctrl_str = ", ".join(controls[:5])
            if len(controls) > 5:
                ctrl_str += f" and {len(controls) - 5} more"
            narrative = f"Upgrading {pkg_name} from {current_ver} to {fix_ver} resolves compliance findings for controls: {ctrl_str}."
        else:
            ctrl_str = ", ".join(controls[:5])
            narrative = (
                f"{pkg_name} {current_ver} has no fix available. "
                f"Controls affected: {ctrl_str}. "
                "Consider a mitigating control or package replacement."
            )

        impacts.append(
            RemediationImpact(
                package=pkg_name,
                current_version=current_ver,
                fix_version=fix_ver,
                controls_fixed=controls,
                frameworks_impacted=frameworks,
                narrative=narrative,
            )
        )

    # Sort by number of controls fixed (most impactful first)
    impacts.sort(key=lambda x: len(x.controls_fixed), reverse=True)
    return impacts


# ─── Top-level risk narrative ─────────────────────────────────────────────────


def _build_risk_narrative(
    blast_radii_dicts: list[dict],
    total_agents: int,
    total_vulns: int,
    critical_count: int,
) -> str:
    """Plain-English top-risk explanation from scan data."""
    if not blast_radii_dicts:
        return (
            "No vulnerabilities were detected in this scan. "
            "The AI agent environment appears clean based on the packages assessed. "
            "Continue regular scanning to detect newly published vulnerabilities."
        )

    kev_entries = [br for br in blast_radii_dicts if br.get("is_kev")]
    # Find the highest-risk entry
    sorted_by_risk = sorted(
        blast_radii_dicts,
        key=lambda b: (
            -(b.get("risk_score") or 0),
            _severity_order(b.get("severity") or "low"),
        ),
    )
    top = sorted_by_risk[0] if sorted_by_risk else None

    parts: list[str] = []

    # Lead sentence
    agent_str = f"{total_agents} agent{'s' if total_agents != 1 else ''}"
    parts.append(f"This scan identified {total_vulns} vulnerabilit{'ies' if total_vulns != 1 else 'y'} across {agent_str}.")

    # KEV callout
    if kev_entries:
        kev_pkgs = list({(br.get("package") or "") for br in kev_entries})[:3]
        parts.append(
            f"{len(kev_entries)} finding{'s are' if len(kev_entries) > 1 else ' is'} "
            f"listed in the CISA Known Exploited Vulnerabilities (KEV) catalog "
            f"(packages: {', '.join(kev_pkgs)}), indicating active exploitation in the wild."
        )

    # Critical callout
    if critical_count and not kev_entries:
        parts.append(
            f"{critical_count} critical severity finding{'s require' if critical_count > 1 else ' requires'} "
            "immediate attention as they represent the highest exploitability risk."
        )

    # Top finding
    if top:
        top_pkg = top.get("package", "an affected package")
        top_vuln = top.get("vulnerability_id", "an unknown CVE")
        top_agents = top.get("affected_agents", [])
        top_creds = top.get("exposed_credentials", [])
        top_score = top.get("risk_score") or 0

        agent_exposure = ""
        if top_agents:
            agent_exposure = f", affecting agent{'s' if len(top_agents) > 1 else ''} {', '.join(top_agents[:2])}"

        cred_exposure = ""
        if top_creds:
            cred_exposure = f" with {len(top_creds)} exposed credential{'s' if len(top_creds) > 1 else ''}"

        parts.append(f"The highest-risk finding is {top_vuln} in {top_pkg} (risk score {top_score:.1f}/10{agent_exposure}{cred_exposure}).")

    return " ".join(parts)


# ─── Executive summary ────────────────────────────────────────────────────────


def _build_executive_summary(
    framework_narratives: list[FrameworkNarrative],
    total_agents: int,
    total_packages: int,
    total_vulns: int,
    critical_count: int,
    generated_at: str,
) -> str:
    """3-5 sentence executive summary for compliance stakeholders."""
    failing_fws = [fn for fn in framework_narratives if fn.status == "failing"]
    at_risk_fws = [fn for fn in framework_narratives if fn.status == "at_risk"]
    # Lead: what was scanned
    sentences: list[str] = [
        f"This AI-BOM compliance report covers {total_agents} AI agent"
        f"{'s' if total_agents != 1 else ''} "
        f"and {total_packages} package{'s' if total_packages != 1 else ''} "
        f"scanned on {generated_at[:10]}."
    ]

    # Vulnerability posture
    if total_vulns == 0:
        sentences.append("No vulnerabilities were detected; all assessed dependencies are clean.")
    elif critical_count > 0:
        sentences.append(
            f"{total_vulns} vulnerabilit{'ies were' if total_vulns > 1 else 'y was'} identified "
            f"including {critical_count} critical finding"
            f"{'s' if critical_count > 1 else ''} that require immediate remediation."
        )
    else:
        sentences.append(f"{total_vulns} vulnerabilit{'ies were' if total_vulns > 1 else 'y was'} identified across the assessed packages.")

    # Framework posture
    total_fws = len(framework_narratives)
    if failing_fws:
        fw_names = ", ".join(fn.framework for fn in failing_fws[:3])
        sentences.append(f"{len(failing_fws)} of {total_fws} assessed frameworks are failing: {fw_names}.")
    elif at_risk_fws:
        fw_names = ", ".join(fn.framework for fn in at_risk_fws[:3])
        sentences.append(
            f"All frameworks passed without critical failures; however {len(at_risk_fws)} "
            f"{'are' if len(at_risk_fws) > 1 else 'is'} at risk: {fw_names}."
        )
    else:
        sentences.append(f"All {total_fws} assessed compliance frameworks are passing with no critical findings.")

    # Closing action
    if failing_fws or at_risk_fws:
        sentences.append("Remediation of identified vulnerabilities is the highest-priority action to restore full compliance posture.")
    else:
        sentences.append("Continue regular scanning to detect newly published vulnerabilities and maintain compliance.")

    return " ".join(sentences)


# ─── Public API ───────────────────────────────────────────────────────────────


def generate_compliance_narrative(
    report: "AIBOMReport",
    framework: str | None = None,
) -> ComplianceNarrative:
    """Generate auditor-ready compliance narrative from scan results.

    Args:
        report: The AIBOMReport to analyse.
        framework: Optional framework slug to generate a single-framework
            narrative.  When None (default), all frameworks are included.
            Supported slugs: owasp-llm, owasp-mcp, atlas, nist, owasp-agentic,
            eu-ai-act, nist-csf, iso-27001, soc2, cis, cmmc.

    Returns:
        A ComplianceNarrative dataclass suitable for JSON serialisation.

    Raises:
        ValueError: If an unknown framework slug is provided.
    """
    # Validate slug early so we fail fast before any computation
    if framework is not None:
        _get_catalog(framework)  # raises ValueError for unknown slugs

    # Build a lightweight list-of-dicts from blast_radii (avoids re-importing models)
    blast_dicts: list[dict] = []
    for br in report.blast_radii:
        blast_dicts.append(
            {
                "vulnerability_id": br.vulnerability.id,
                "severity": br.vulnerability.severity.value,
                "package": f"{br.package.name}@{br.package.version}",
                "fixed_version": br.vulnerability.fixed_version,
                "risk_score": br.risk_score,
                "is_kev": br.vulnerability.is_kev,
                "affected_agents": [a.name for a in br.affected_agents],
                "affected_servers": [s.name for s in br.affected_servers],
                "exposed_credentials": br.exposed_credentials,
                "owasp_tags": br.owasp_tags,
                "atlas_tags": br.atlas_tags,
                "nist_ai_rmf_tags": br.nist_ai_rmf_tags,
                "owasp_mcp_tags": br.owasp_mcp_tags,
                "owasp_agentic_tags": br.owasp_agentic_tags,
                "eu_ai_act_tags": br.eu_ai_act_tags,
                "nist_csf_tags": br.nist_csf_tags,
                "iso_27001_tags": br.iso_27001_tags,
                "soc2_tags": br.soc2_tags,
                "cis_tags": br.cis_tags,
                "cmmc_tags": br.cmmc_tags,
            }
        )

    slugs = [framework] if framework is not None else ALL_FRAMEWORK_SLUGS

    framework_narratives: list[FrameworkNarrative] = [_build_framework_narrative(slug, blast_dicts) for slug in slugs]

    remediation_impact = _build_remediation_impact(blast_dicts)

    total_vulns = len(blast_dicts)
    critical_count = sum(1 for b in blast_dicts if (b.get("severity") or "") == "critical")

    generated_at = datetime.now(timezone.utc).isoformat()

    risk_narrative = _build_risk_narrative(
        blast_dicts,
        total_agents=report.total_agents,
        total_vulns=total_vulns,
        critical_count=critical_count,
    )

    executive_summary = _build_executive_summary(
        framework_narratives=framework_narratives,
        total_agents=report.total_agents,
        total_packages=report.total_packages,
        total_vulns=total_vulns,
        critical_count=critical_count,
        generated_at=generated_at,
    )

    return ComplianceNarrative(
        executive_summary=executive_summary,
        framework_narratives=framework_narratives,
        remediation_impact=remediation_impact,
        risk_narrative=risk_narrative,
        generated_at=generated_at,
    )
