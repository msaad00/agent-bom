"""Compliance posture, framework-specific, posture scorecard, and malicious check endpoints."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException

from agent_bom.api.models import JobStatus
from agent_bom.api.stores import _get_store

router = APIRouter()
_logger = logging.getLogger(__name__)


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
    from agent_bom.eu_ai_act import EU_AI_ACT
    from agent_bom.iso_27001 import ISO_27001
    from agent_bom.nist_csf import NIST_CSF
    from agent_bom.owasp_agentic import OWASP_AGENTIC_TOP10
    from agent_bom.owasp_mcp import OWASP_MCP_TOP10
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

    def _count_statuses(controls: list[dict]) -> tuple[int, int, int]:
        p = sum(1 for c in controls if c["status"] == "pass")
        w = sum(1 for c in controls if c["status"] == "warning")
        f = sum(1 for c in controls if c["status"] == "fail")
        return p, w, f

    all_frameworks = [owasp, owasp_mcp, atlas, nist, owasp_agentic, eu_ai_act, nist_csf, iso27001, soc2, cis]
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
        },
    }


@router.get("/v1/compliance/{framework}", tags=["compliance"])
async def get_compliance_by_framework(framework: str) -> dict:
    """Get compliance posture for a single framework.

    Supported frameworks: owasp-llm, owasp-mcp, atlas, nist, owasp-agentic, eu-ai-act,
    nist-csf, iso-27001, soc2, cis
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


@router.get("/v1/posture", tags=["compliance"])
async def get_posture_scorecard() -> dict:
    """Compute enterprise posture scorecard from the latest completed scan."""
    latest_result = None
    for job in _get_store().list_all():
        if job.status != JobStatus.DONE or not job.result:
            continue
        latest_result = job.result
        break

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
    """Aggregate vulnerability counts across all completed scans."""
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
    """Rank credentials by blast radius exposure from the latest scan."""
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
    """Group vulnerabilities by agent for SOC incident correlation."""
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


@router.get("/v1/malicious/check", tags=["security"])
async def check_malicious(name: str, ecosystem: str = "npm") -> dict:
    """Check if a package name is a known malicious package or typosquat."""
    from agent_bom.malicious import check_typosquat

    typosquat_target = check_typosquat(name, ecosystem)
    return {
        "package": name,
        "ecosystem": ecosystem,
        "is_typosquat": typosquat_target is not None,
        "typosquat_target": typosquat_target,
    }


@router.get("/v1/scorecard/{ecosystem}/{package:path}", tags=["security"])
async def scorecard_lookup(ecosystem: str, package: str) -> dict:
    """Look up OpenSSF Scorecard for a package."""
    import re as _re_local

    from agent_bom.scorecard import extract_github_repo, fetch_scorecard

    if not _re_local.match(r"^[A-Za-z0-9._@/:-]+$", package):
        raise HTTPException(status_code=400, detail="Invalid package name")

    repo = None

    if "/" in package:
        repo = package

    if not repo:
        if ecosystem == "npm":
            clean = package.lstrip("@").replace("/", "/")
            repo = clean
        elif ecosystem == "pypi":
            repo = None
        elif ecosystem == "go":
            repo_match = extract_github_repo(f"https://{package}")
            if repo_match:
                repo = repo_match

    if not repo:
        return {
            "package": package,
            "ecosystem": ecosystem,
            "scorecard": None,
            "error": "Could not resolve GitHub repository for this package. "
            "Try providing the GitHub owner/repo directly (e.g., /v1/scorecard/github/expressjs/express).",
        }

    data = await fetch_scorecard(repo)
    if data is None:
        return {
            "package": package,
            "ecosystem": ecosystem,
            "repo": repo,
            "scorecard": None,
            "error": f"No scorecard found for github.com/{repo}",
        }

    return {
        "package": package,
        "ecosystem": ecosystem,
        "repo": repo,
        "scorecard": data,
    }
