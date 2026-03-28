"""Compliance and posture API routes.

Endpoints:
    GET  /v1/compliance                      14-framework compliance posture
    GET  /v1/compliance/narrative            full compliance narrative (all frameworks)
    GET  /v1/compliance/narrative/{framework} single-framework narrative
    GET  /v1/compliance/{framework}          single framework (must be after /narrative)
    GET  /v1/posture                         enterprise posture scorecard
    GET  /v1/posture/counts                  severity counts for nav badges
    GET  /v1/posture/credentials             credential risk ranking
    GET  /v1/posture/incidents               agent-centric incident correlation
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, HTTPException

from agent_bom.api.models import JobStatus
from agent_bom.api.stores import _get_store

if TYPE_CHECKING:
    from agent_bom.models import AIBOMReport
    from agent_bom.output.compliance_narrative import ComplianceNarrative

router = APIRouter()


@router.get("/v1/compliance", tags=["compliance"])
async def get_compliance() -> dict:
    """Aggregate OWASP LLM Top 10, OWASP MCP Top 10, MITRE ATLAS, NIST AI RMF,
    OWASP Agentic Top 10, and EU AI Act compliance posture across all completed scans.

    Returns per-control pass/warning/fail status and an overall compliance score.
    """
    from agent_bom.atlas import ATLAS_TECHNIQUES
    from agent_bom.nist_ai_rmf import NIST_AI_RMF
    from agent_bom.owasp import OWASP_LLM_TOP10

    # Collect blast_radius entries from all completed scans
    all_blast: list[dict] = []
    latest_scan: str | None = None
    scan_count = 0
    has_mcp_context = False
    has_agent_context = False
    all_scan_sources: set[str] = set()

    for job in _get_store().list_all():
        if job.status != JobStatus.DONE or not job.result:
            continue
        scan_count += 1
        br_list = job.result.get("blast_radius", [])
        all_blast.extend(br_list)
        if latest_scan is None or (job.completed_at and job.completed_at > latest_scan):
            latest_scan = job.completed_at
        # Detect scan context from result metadata
        if job.result.get("has_mcp_context"):
            has_mcp_context = True
        if job.result.get("has_agent_context"):
            has_agent_context = True
        for src in job.result.get("scan_sources", []):
            all_scan_sources.add(src)

    def _build_controls(
        catalog: dict[str, str],
        tag_field: str,
        id_key: str,
    ) -> list[dict]:
        """Build per-control compliance entries from blast_radius data."""
        controls = []
        for code, name in sorted(catalog.items()):
            sev_breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            affected_pkgs: set[str] = set()
            affected_agents: set[str] = set()
            findings = 0

            for br in all_blast:
                tags = br.get(tag_field, [])
                if code in tags:
                    findings += 1
                    sev = (br.get("severity") or "").lower()
                    if sev in sev_breakdown:
                        sev_breakdown[sev] += 1
                    pkg = br.get("package")
                    if pkg:
                        affected_pkgs.add(pkg)
                    for agent in br.get("affected_agents", []):
                        affected_agents.add(agent)

            if findings == 0:
                status = "pass"
            elif sev_breakdown["critical"] > 0 or sev_breakdown["high"] > 0:
                status = "fail"
            else:
                status = "warning"

            controls.append(
                {
                    id_key: code,
                    "name": name,
                    "findings": findings,
                    "status": status,
                    "severity_breakdown": sev_breakdown,
                    "affected_packages": sorted(affected_pkgs),
                    "affected_agents": sorted(affected_agents),
                }
            )
        return controls

    from agent_bom.cis_controls import CIS_CONTROLS
    from agent_bom.cmmc import CMMC_PRACTICES
    from agent_bom.eu_ai_act import EU_AI_ACT
    from agent_bom.fedramp import FEDRAMP_MODERATE
    from agent_bom.iso_27001 import ISO_27001
    from agent_bom.nist_800_53 import NIST_800_53
    from agent_bom.nist_csf import NIST_CSF
    from agent_bom.owasp_agentic import OWASP_AGENTIC_TOP10
    from agent_bom.owasp_mcp import OWASP_MCP_TOP10
    from agent_bom.pci_dss import PCI_DSS_REQUIREMENTS
    from agent_bom.soc2 import SOC2_TSC

    owasp = _build_controls(OWASP_LLM_TOP10, "owasp_tags", "code")
    owasp_mcp = _build_controls(OWASP_MCP_TOP10, "owasp_mcp_tags", "code")
    atlas = _build_controls(ATLAS_TECHNIQUES, "atlas_tags", "code")
    nist = _build_controls(NIST_AI_RMF, "nist_ai_rmf_tags", "code")
    owasp_agentic = _build_controls(OWASP_AGENTIC_TOP10, "owasp_agentic_tags", "code")
    eu_ai_act = _build_controls(EU_AI_ACT, "eu_ai_act_tags", "code")
    nist_csf = _build_controls(NIST_CSF, "nist_csf_tags", "code")
    iso27001 = _build_controls(ISO_27001, "iso_27001_tags", "code")
    soc2 = _build_controls(SOC2_TSC, "soc2_tags", "code")
    cis = _build_controls(CIS_CONTROLS, "cis_tags", "code")
    cmmc = _build_controls(CMMC_PRACTICES, "cmmc_tags", "code")
    nist_800_53 = _build_controls(NIST_800_53, "nist_800_53_tags", "code")
    fedramp = _build_controls({c: c for c in FEDRAMP_MODERATE}, "fedramp_tags", "code")
    pci_dss = _build_controls(PCI_DSS_REQUIREMENTS, "pci_dss_tags", "code")

    def _count_statuses(controls: list[dict]) -> tuple[int, int, int]:
        p = sum(1 for c in controls if c["status"] == "pass")
        w = sum(1 for c in controls if c["status"] == "warning")
        f = sum(1 for c in controls if c["status"] == "fail")
        return p, w, f

    all_frameworks = [
        owasp,
        owasp_mcp,
        atlas,
        nist,
        owasp_agentic,
        eu_ai_act,
        nist_csf,
        iso27001,
        soc2,
        cis,
        cmmc,
        nist_800_53,
        fedramp,
        pci_dss,
    ]
    total_controls = sum(len(fw) for fw in all_frameworks)
    total_pass = sum(_count_statuses(fw)[0] for fw in all_frameworks)
    any_fail = any(_count_statuses(fw)[2] > 0 for fw in all_frameworks)
    any_warn = any(_count_statuses(fw)[1] > 0 for fw in all_frameworks)
    overall_score = round((total_pass / total_controls) * 100, 1) if total_controls > 0 else 100.0

    if any_fail:
        overall_status = "fail"
    elif any_warn:
        overall_status = "warning"
    else:
        overall_status = "pass"

    op, ow, of_ = _count_statuses(owasp)
    mp, mw, mf = _count_statuses(owasp_mcp)
    ap, aw, af = _count_statuses(atlas)
    np_, nw, nf = _count_statuses(nist)
    oap, oaw, oaf = _count_statuses(owasp_agentic)
    eup, euw, euf = _count_statuses(eu_ai_act)
    ncp, ncw, ncf = _count_statuses(nist_csf)
    ip, iw, if2 = _count_statuses(iso27001)
    sp, sw, sf = _count_statuses(soc2)
    cp, cw, cf = _count_statuses(cis)
    cmp, cmw, cmf = _count_statuses(cmmc)
    n8p, n8w, n8f = _count_statuses(nist_800_53)
    frp, frw, frf = _count_statuses(fedramp)
    pp, pw, pf = _count_statuses(pci_dss)

    return {
        "overall_score": overall_score,
        "overall_status": overall_status,
        "scan_count": scan_count,
        "latest_scan": latest_scan,
        "has_mcp_context": has_mcp_context,
        "has_agent_context": has_agent_context,
        "scan_sources": sorted(all_scan_sources),
        "owasp_llm_top10": owasp,
        "owasp_mcp_top10": owasp_mcp,
        "mitre_atlas": atlas,
        "nist_ai_rmf": nist,
        "owasp_agentic_top10": owasp_agentic,
        "eu_ai_act": eu_ai_act,
        "nist_csf": nist_csf,
        "iso_27001": iso27001,
        "soc2": soc2,
        "cis_controls": cis,
        "cmmc": cmmc,
        "nist_800_53": nist_800_53,
        "fedramp": fedramp,
        "pci_dss": pci_dss,
        "summary": {
            "owasp_pass": op,
            "owasp_warn": ow,
            "owasp_fail": of_,
            "owasp_mcp_pass": mp,
            "owasp_mcp_warn": mw,
            "owasp_mcp_fail": mf,
            "atlas_pass": ap,
            "atlas_warn": aw,
            "atlas_fail": af,
            "nist_pass": np_,
            "nist_warn": nw,
            "nist_fail": nf,
            "owasp_agentic_pass": oap,
            "owasp_agentic_warn": oaw,
            "owasp_agentic_fail": oaf,
            "eu_ai_act_pass": eup,
            "eu_ai_act_warn": euw,
            "eu_ai_act_fail": euf,
            "nist_csf_pass": ncp,
            "nist_csf_warn": ncw,
            "nist_csf_fail": ncf,
            "iso_27001_pass": ip,
            "iso_27001_warn": iw,
            "iso_27001_fail": if2,
            "soc2_pass": sp,
            "soc2_warn": sw,
            "soc2_fail": sf,
            "cis_pass": cp,
            "cis_warn": cw,
            "cis_fail": cf,
            "cmmc_pass": cmp,
            "cmmc_warn": cmw,
            "cmmc_fail": cmf,
            "nist_800_53_pass": n8p,
            "nist_800_53_warn": n8w,
            "nist_800_53_fail": n8f,
            "fedramp_pass": frp,
            "fedramp_warn": frw,
            "fedramp_fail": frf,
            "pci_dss_pass": pp,
            "pci_dss_warn": pw,
            "pci_dss_fail": pf,
        },
    }


# ─── Compliance Narrative ─────────────────────────────────────────────────


def _latest_report() -> "AIBOMReport | None":
    """Return a synthetic AIBOMReport built from the latest completed scan result.

    The narrative generator expects a real ``AIBOMReport`` model object, but the
    API layer stores scan results as plain dicts (the JSON-serialised output).
    We reconstruct a minimal report with only the fields the narrative generator
    reads (``blast_radii``, ``agents``, ``total_packages``, ``total_agents``).
    """
    from agent_bom.models import (
        Agent,
        AgentType,
        AIBOMReport,
        BlastRadius,
        MCPServer,
        Package,
        Severity,
        Vulnerability,
    )

    # Merge blast_radius entries from ALL completed scans (same as /v1/compliance)
    all_blast_dicts: list[dict] = []
    total_agents_count = 0
    total_packages_count = 0

    for job in _get_store().list_all():
        if job.status != JobStatus.DONE or not job.result:
            continue
        all_blast_dicts.extend(job.result.get("blast_radius", []))
        summary = job.result.get("summary", {})
        total_agents_count += summary.get("total_agents", 0)
        total_packages_count += summary.get("total_packages", 0)

    if not all_blast_dicts and total_agents_count == 0:
        return None

    # Build minimal BlastRadius objects the narrative module can read
    blast_radii: list[BlastRadius] = []
    for bd in all_blast_dicts:
        raw_pkg = bd.get("package", "unknown@0.0")
        if "@" in raw_pkg:
            pkg_name, pkg_ver = raw_pkg.rsplit("@", 1)
        else:
            pkg_name, pkg_ver = raw_pkg, "0.0"

        sev_str = (bd.get("severity") or "unknown").upper()
        try:
            sev = Severity(sev_str.lower())
        except ValueError:
            sev = Severity.UNKNOWN

        vuln = Vulnerability(
            id=bd.get("vulnerability_id", "UNKNOWN"),
            summary="",
            severity=sev,
            fixed_version=bd.get("fixed_version"),
            is_kev=bool(bd.get("is_kev") or bd.get("cisa_kev")),
        )
        pkg = Package(name=pkg_name, version=pkg_ver, ecosystem=bd.get("ecosystem", ""))

        # Minimal affected agents (name only)
        agents = [Agent(name=n, agent_type=AgentType.CUSTOM, config_path="") for n in bd.get("affected_agents", [])]
        servers = [MCPServer(name=n) for n in bd.get("affected_servers", [])]

        br = BlastRadius(
            vulnerability=vuln,
            package=pkg,
            affected_servers=servers,
            affected_agents=agents,
            exposed_credentials=bd.get("exposed_credentials", []),
            exposed_tools=[],
            risk_score=float(bd.get("risk_score") or 0),
            owasp_tags=bd.get("owasp_tags", []),
            atlas_tags=bd.get("atlas_tags", []),
            nist_ai_rmf_tags=bd.get("nist_ai_rmf_tags", []),
            owasp_mcp_tags=bd.get("owasp_mcp_tags", []),
            owasp_agentic_tags=bd.get("owasp_agentic_tags", []),
            eu_ai_act_tags=bd.get("eu_ai_act_tags", []),
            nist_csf_tags=bd.get("nist_csf_tags", []),
            iso_27001_tags=bd.get("iso_27001_tags", []),
            soc2_tags=bd.get("soc2_tags", []),
            cis_tags=bd.get("cis_tags", []),
            cmmc_tags=bd.get("cmmc_tags", []),
        )
        blast_radii.append(br)

    # Pad agents list to match counts from scan summaries (narrative uses len(agents))
    agents_list = [Agent(name=f"agent-{i}", agent_type=AgentType.CUSTOM, config_path="") for i in range(total_agents_count)]
    # Pad packages via a synthetic server on the first agent
    if agents_list and total_packages_count > 0:
        dummy_pkgs = [Package(name=f"pkg-{i}", version="0.0", ecosystem="unknown") for i in range(total_packages_count)]
        agents_list[0].mcp_servers.append(MCPServer(name="__summary__", packages=dummy_pkgs))

    report = AIBOMReport(agents=agents_list, blast_radii=blast_radii)
    return report


def _narrative_to_dict(narrative: "ComplianceNarrative") -> dict:
    """Serialise a ComplianceNarrative dataclass to a JSON-safe dict."""
    return {
        "executive_summary": narrative.executive_summary,
        "risk_narrative": narrative.risk_narrative,
        "generated_at": narrative.generated_at,
        "framework_narratives": [
            {
                "framework": fn.framework,
                "slug": fn.slug,
                "status": fn.status,
                "score": fn.score,
                "narrative": fn.narrative,
                "recommendations": fn.recommendations,
                "failing_controls": [
                    {
                        "control_id": cn.control_id,
                        "title": cn.title,
                        "status": cn.status,
                        "narrative": cn.narrative,
                        "affected_packages": cn.affected_packages,
                        "affected_agents": cn.affected_agents,
                        "remediation_steps": cn.remediation_steps,
                    }
                    for cn in fn.failing_controls
                ],
            }
            for fn in narrative.framework_narratives
        ],
        "remediation_impact": [
            {
                "package": ri.package,
                "current_version": ri.current_version,
                "fix_version": ri.fix_version,
                "controls_fixed": ri.controls_fixed,
                "frameworks_impacted": ri.frameworks_impacted,
                "narrative": ri.narrative,
            }
            for ri in narrative.remediation_impact
        ],
    }


@router.get("/v1/compliance/narrative", tags=["compliance"])
async def get_compliance_narrative() -> dict:
    """Generate an auditor-ready compliance narrative from all completed scans.

    Produces human-readable stories for all 11 supported frameworks, a
    cross-framework executive summary, and a remediation-compliance bridge
    showing which package upgrades resolve which controls.

    No LLM is required — narratives are generated from template strings
    and the structured blast radius data in completed scan results.
    """
    from agent_bom.output.compliance_narrative import (
        generate_compliance_narrative,
    )

    report = _latest_report()
    if report is None:
        return {
            "executive_summary": "No completed scans available. Run agent-bom scan first.",
            "framework_narratives": [],
            "remediation_impact": [],
            "risk_narrative": "No scan data available.",
            "generated_at": "",
        }

    narrative: ComplianceNarrative = generate_compliance_narrative(report)
    return _narrative_to_dict(narrative)


@router.get("/v1/compliance/narrative/{framework}", tags=["compliance"])
async def get_compliance_narrative_by_framework(framework: str) -> dict:
    """Generate a single-framework compliance narrative.

    Supported framework slugs: owasp-llm, owasp-mcp, atlas, nist,
    owasp-agentic, eu-ai-act, nist-csf, iso-27001, soc2, cis, cmmc.

    Returns the same structure as GET /v1/compliance/narrative but scoped
    to a single framework's controls.
    """
    from agent_bom.output.compliance_narrative import (
        ALL_FRAMEWORK_SLUGS,
        generate_compliance_narrative,
    )

    if framework.lower() not in ALL_FRAMEWORK_SLUGS:
        raise HTTPException(
            status_code=400,
            detail=(f"Unknown framework '{framework}'. Supported: {', '.join(ALL_FRAMEWORK_SLUGS)}"),
        )

    report = _latest_report()
    if report is None:
        return {
            "executive_summary": "No completed scans available. Run agent-bom scan first.",
            "framework_narratives": [],
            "remediation_impact": [],
            "risk_narrative": "No scan data available.",
            "generated_at": "",
        }

    narrative: ComplianceNarrative = generate_compliance_narrative(report, framework=framework.lower())
    return _narrative_to_dict(narrative)


@router.get("/v1/compliance/{framework}", tags=["compliance"])
async def get_compliance_by_framework(framework: str) -> dict:
    """Get compliance posture for a single framework.

    Supported frameworks: owasp-llm, owasp-mcp, atlas, nist, owasp-agentic, eu-ai-act,
    nist-csf, iso-27001, soc2, cis, cmmc
    """
    full = await get_compliance()

    framework_map = {
        "owasp-llm": "owasp_llm_top10",
        "owasp-mcp": "owasp_mcp_top10",
        "atlas": "mitre_atlas",
        "nist": "nist_ai_rmf",
        "owasp-agentic": "owasp_agentic_top10",
        "eu-ai-act": "eu_ai_act",
        "nist-csf": "nist_csf",
        "iso-27001": "iso_27001",
        "soc2": "soc2",
        "cis": "cis_controls",
        "cmmc": "cmmc",
        "nist-800-53": "nist_800_53",
        "fedramp": "fedramp",
        "pci-dss": "pci_dss",
    }

    key = framework_map.get(framework.lower())
    if not key:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown framework '{framework}'. Supported: {', '.join(framework_map.keys())}",
        )

    controls = full.get(key, [])
    pass_count = sum(1 for c in controls if c["status"] == "pass")
    warn_count = sum(1 for c in controls if c["status"] == "warning")
    fail_count = sum(1 for c in controls if c["status"] == "fail")

    return {
        "framework": framework,
        "controls": controls,
        "summary": {"pass": pass_count, "warning": warn_count, "fail": fail_count},
        "score": round((pass_count / len(controls)) * 100, 1) if controls else 100.0,
    }


# ─── Posture Scorecard ─────────────────────────────────────────────────────


@router.get("/v1/posture", tags=["compliance"])
async def get_posture_scorecard() -> dict:
    """Compute enterprise posture scorecard from the latest completed scan.

    Returns a letter grade (A-F), numeric score (0-100), and per-dimension
    breakdown covering vulnerability posture, credential hygiene, supply
    chain quality, compliance coverage, active exploitation, and configuration.
    """
    latest_result = None
    for job in _get_store().list_all():
        if job.status != JobStatus.DONE or not job.result:
            continue
        latest_result = job.result
        break  # list_all returns newest first

    if latest_result is None:
        return {
            "grade": "N/A",
            "score": 0,
            "summary": "No completed scans available",
            "dimensions": {},
        }

    scorecard = latest_result.get("posture_scorecard")
    if scorecard:
        return scorecard

    return {
        "grade": "N/A",
        "score": 0,
        "summary": "Scorecard not computed for this scan",
        "dimensions": {},
    }


@router.get("/v1/posture/counts", tags=["compliance"])
async def get_posture_counts() -> dict:
    """Aggregate vulnerability counts across all completed scans.

    Lightweight endpoint used by the dashboard nav to show Critical/High
    badges without loading full scan payloads.

    Returns:
        {critical, high, medium, low, total, kev, compound_issues}
    """
    counts: dict[str, Any] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "total": 0,
        "kev": 0,
        "compound_issues": 0,
    }
    seen_ids: set[str] = set()
    has_mcp_context = False
    has_agent_context = False
    all_scan_sources: set[str] = set()
    scan_count = 0

    for job in _get_store().list_all():
        if job.status != JobStatus.DONE or not job.result:
            continue
        scan_count += 1

        # Aggregate context metadata from scan results
        if job.result.get("has_mcp_context"):
            has_mcp_context = True
        if job.result.get("has_agent_context"):
            has_agent_context = True
        for src in job.result.get("scan_sources", []):
            all_scan_sources.add(src)

        blast_list = job.result.get("blast_radius", [])
        for b in blast_list:
            vid = b.get("vulnerability_id", "")
            if vid in seen_ids:
                continue
            seen_ids.add(vid)
            sev = (b.get("severity") or "").lower()
            if sev in counts:
                counts[sev] += 1
            counts["total"] += 1
            if b.get("cisa_kev") or b.get("is_kev"):
                counts["kev"] += 1
            # Compound issue: KEV + reachable tool, or KEV + exposed cred
            if (b.get("cisa_kev") or b.get("is_kev")) and (b.get("reachable_tools") or b.get("exposed_credentials")):
                counts["compound_issues"] += 1
            elif (b.get("epss_score") or 0) >= 0.3 and (b.get("cvss_score") or 0) >= 7:
                counts["compound_issues"] += 1

    counts["has_mcp_context"] = has_mcp_context
    counts["has_agent_context"] = has_agent_context
    counts["scan_sources"] = sorted(all_scan_sources)
    counts["scan_count"] = scan_count
    return counts


@router.get("/v1/posture/credentials", tags=["compliance"])
async def get_credential_risk_ranking() -> dict:
    """Rank credentials by blast radius exposure from the latest scan.

    Returns credentials sorted by risk tier (critical to low) with
    associated vulnerability counts and affected agents.
    """
    latest_result = None
    for job in _get_store().list_all():
        if job.status != JobStatus.DONE or not job.result:
            continue
        latest_result = job.result
        break

    if latest_result is None:
        return {"credentials": [], "count": 0}

    ranking = latest_result.get("credential_risk_ranking", [])
    return {"credentials": ranking, "count": len(ranking)}


@router.get("/v1/posture/incidents", tags=["compliance"])
async def get_incident_correlation() -> dict:
    """Group vulnerabilities by agent for SOC incident correlation.

    Returns agent-centric incident summaries with priority (P1-P4),
    severity counts, credential exposure, and recommended actions.
    """
    latest_result = None
    for job in _get_store().list_all():
        if job.status != JobStatus.DONE or not job.result:
            continue
        latest_result = job.result
        break

    if latest_result is None:
        return {"incidents": [], "count": 0}

    incidents = latest_result.get("incident_correlation", [])
    return {"incidents": incidents, "count": len(incidents)}
