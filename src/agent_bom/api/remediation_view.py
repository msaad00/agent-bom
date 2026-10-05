"""Project the canonical current finding queue into package upgrade actions."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from agent_bom.output.json_fmt import remediation_json


class CurrentRemediationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["remediation.current.v1"] = "remediation.current.v1"
    remediation_plan: list[dict[str, Any]]
    source_findings: int
    truncated: bool
    warnings: list[str]


def _strings(value: Any) -> list[str]:
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


def _package_finding(row: dict[str, Any]) -> Finding | None:
    advisory = row.get("cve_id") or row.get("vulnerability_id")
    if not advisory or row.get("suppressed"):
        return None
    evidence = dict(row["evidence"]) if isinstance(row.get("evidence"), dict) else {}
    name = str(row.get("package_name") or row.get("package") or evidence.get("package_name") or "")
    version = str(row.get("package_version") or evidence.get("package_version") or "")
    if "@" in name and name.rsplit("@", 1)[0]:
        name, reported_version = name.rsplit("@", 1)
        version = version or reported_version
    if not name:
        return None
    evidence.update(package_name=name, package_version=version, ecosystem=row.get("ecosystem") or evidence.get("ecosystem", ""))
    evidence["references"] = _strings(row.get("references") or evidence.get("references"))
    finding = Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.SBOM,
        asset=Asset(name=name, asset_type="package"),
        severity=str(row.get("severity") or "unknown"),
        title=str(row.get("title") or advisory),
        cve_id=str(advisory),
        fixed_version=row.get("fixed_version") or evidence.get("fixed_version"),
        evidence=evidence,
        is_kev=bool(row.get("is_kev")),
        risk_score=float(row.get("risk_score") or 0),
    )
    for field in (
        "affected_agents",
        "exposed_credentials",
        "exposed_tools",
        "owasp_tags",
        "atlas_tags",
        "nist_ai_rmf_tags",
        "owasp_mcp_tags",
        "owasp_agentic_tags",
        "eu_ai_act_tags",
        "nist_csf_tags",
        "iso_27001_tags",
        "soc2_tags",
        "cis_tags",
    ):
        setattr(finding, field, _strings(row.get(field)))
    return finding


def current_remediation_response(snapshot: dict[str, Any]) -> CurrentRemediationResponse:
    rows = snapshot.get("findings", [])
    findings = [finding for row in rows if isinstance(row, dict) and (finding := _package_finding(row)) is not None]
    return CurrentRemediationResponse(
        remediation_plan=remediation_json(findings),
        source_findings=len(rows),
        truncated=snapshot.get("completeness", {}).get("status") != "complete",
        warnings=_strings(snapshot.get("warnings")),
    )
