"""Compliance evidence bundle export for local CLI scans."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import zipfile
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from agent_bom.compliance_coverage import TAG_MAPPED_FRAMEWORKS, ComplianceFrameworkMetadata
from agent_bom.compliance_utils import effective_blast_radius_tags, framework_qualified_finding_tags
from agent_bom.models import AIBOMReport
from agent_bom.output.cyclonedx_fmt import to_cyclonedx
from agent_bom.output.finding_views import cve_findings, package_name, package_version, severity_value

_FRAMEWORKS_BY_SLUG: dict[str, ComplianceFrameworkMetadata] = {framework.slug: framework for framework in TAG_MAPPED_FRAMEWORKS}
_FRAMEWORK_ALIASES: dict[str, str] = {
    "nist-ai-rmf": "nist",
    "nist_ai_rmf": "nist",
    "nist-rmf": "nist",
    "nist-cybersecurity-framework": "nist-csf",
    "nist-csf-2": "nist-csf",
    "nist-sp-800-53": "nist-800-53",
    "iso27001": "iso-27001",
    "iso-27001-2022": "iso-27001",
    "pci": "pci-dss",
    "pcidss": "pci-dss",
    "owasp": "owasp-llm",
    "owasp-llm-top10": "owasp-llm",
    "owasp-mcp-top10": "owasp-mcp",
}
_HIGH_SEVERITIES = {"critical", "high"}


@dataclass(frozen=True)
class _EvidenceRow:
    finding_id: str
    source: str
    control: str
    severity: str
    package: str
    version: str
    risk_score: float | None
    affected_agents: list[str]
    affected_servers: list[str]

    def as_json(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "source": self.source,
            "control": self.control,
            "severity": self.severity,
            "package": self.package,
            "version": self.version,
            "risk_score": self.risk_score,
            "affected_agents": self.affected_agents,
            "affected_servers": self.affected_servers,
        }


def _canonical_framework(framework: str) -> ComplianceFrameworkMetadata:
    slug = framework.strip().lower().replace("_", "-")
    slug = _FRAMEWORK_ALIASES.get(slug, slug)
    try:
        return _FRAMEWORKS_BY_SLUG[slug]
    except KeyError as exc:
        supported = ", ".join(sorted(_FRAMEWORKS_BY_SLUG))
        raise ValueError(f"unsupported compliance framework {framework!r}; supported frameworks: {supported}") from exc


def _control_key(tag: str, catalog: Mapping[str, str]) -> str | None:
    value = tag.strip()
    if value in catalog:
        return value
    for prefix in ("FedRAMP-", "CMMC-", "NIST-", "ISO-", "SOC2-", "CIS-", "PCI-"):
        if value.startswith(prefix) and value.removeprefix(prefix) in catalog:
            return value.removeprefix(prefix)
    return None


def _severity_from_blast_radius(br: object) -> str:
    severity = getattr(getattr(br, "vulnerability", None), "severity", "")
    value = getattr(severity, "value", severity)
    return str(value or "unknown").lower()


def _blast_radius_evidence(report: AIBOMReport, metadata: ComplianceFrameworkMetadata) -> dict[str, list[_EvidenceRow]]:
    evidence: dict[str, list[_EvidenceRow]] = {}
    for index, br in enumerate(report.blast_radii, start=1):
        for tag in effective_blast_radius_tags(br).get(metadata.tag_field, []):
            control = _control_key(tag, metadata.catalog)
            if control is None:
                continue
            row = _EvidenceRow(
                finding_id=getattr(br.vulnerability, "id", "") or f"blast-radius-{index}",
                source="blast_radius",
                control=control,
                severity=_severity_from_blast_radius(br),
                package=br.package.name,
                version=br.package.version,
                risk_score=br.risk_score,
                affected_agents=[agent.name for agent in br.affected_agents],
                affected_servers=[server.name for server in br.affected_servers],
            )
            evidence.setdefault(control, []).append(row)
    return evidence


def _finding_evidence(report: AIBOMReport, metadata: ComplianceFrameworkMetadata) -> dict[str, list[_EvidenceRow]]:
    accepted_frameworks = {
        metadata.output_key,
        metadata.summary_prefix,
        metadata.slug.replace("-", "_"),
    }
    evidence: dict[str, list[_EvidenceRow]] = {}
    for finding in cve_findings(report):
        for qualified_tag in framework_qualified_finding_tags(finding):
            framework_key, _, control_value = qualified_tag.partition(":")
            if framework_key not in accepted_frameworks:
                continue
            control = _control_key(control_value, metadata.catalog)
            if control is None:
                continue
            row = _EvidenceRow(
                finding_id=finding.cve_id or finding.id,
                source="unified_finding",
                control=control,
                severity=severity_value(finding).lower(),
                package=package_name(finding),
                version=package_version(finding),
                risk_score=finding.risk_score,
                affected_agents=list(finding.affected_agents),
                affected_servers=list(finding.affected_servers),
            )
            evidence.setdefault(control, []).append(row)
    return evidence


def _merged_evidence(report: AIBOMReport, metadata: ComplianceFrameworkMetadata) -> dict[str, list[_EvidenceRow]]:
    merged = _blast_radius_evidence(report, metadata)
    for control, rows in _finding_evidence(report, metadata).items():
        merged.setdefault(control, []).extend(rows)
    for control, rows in list(merged.items()):
        seen: set[tuple[str, str, str, str]] = set()
        unique_rows: list[_EvidenceRow] = []
        for row in rows:
            key = (row.control, row.finding_id, row.package, row.version)
            if key in seen:
                continue
            seen.add(key)
            unique_rows.append(row)
        merged[control] = unique_rows
    return merged


def _bundle_completeness(report: AIBOMReport, mapped_evidence_count: int) -> str:
    has_scan_input = any(
        (
            report.total_agents,
            report.total_servers,
            report.total_packages,
            report.total_vulnerabilities,
            len(report.blast_radii),
            len(cve_findings(report)),
        )
    )
    if not has_scan_input:
        return "incomplete"
    if mapped_evidence_count == 0:
        return "not_evaluated"
    return "complete"


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, indent=2, sort_keys=True, default=str).encode("utf-8")


def export_compliance_bundle(
    report: AIBOMReport,
    framework: str,
    output_path: str,
) -> str:
    """Export a local compliance evidence bundle as ZIP.

    Returns the path to the written ZIP file.
    """
    metadata = _canonical_framework(framework)

    # Build SBOM (CycloneDX)
    sbom_data = to_cyclonedx(report)

    # Build vulnerability report
    vuln_entries = []
    cve_rows = cve_findings(report)
    for finding in cve_rows:
        vuln_entries.append(
            {
                "id": finding.cve_id or finding.id,
                "severity": severity_value(finding),
                "package": package_name(finding),
                "version": package_version(finding),
                "fixed_version": finding.fixed_version,
                "risk_score": finding.risk_score,
                "affected_agents": list(finding.affected_agents),
                "affected_servers": list(finding.affected_servers),
            }
        )

    # Build policy results
    mapped_evidence = _merged_evidence(report, metadata)
    mapped_evidence_count = sum(len(rows) for rows in mapped_evidence.values())
    evidence_completeness = _bundle_completeness(report, mapped_evidence_count)
    policy_results = {
        "framework": metadata.slug,
        "framework_label": metadata.report_label,
        "scan_date": report.generated_at.isoformat(),
        "tool_version": report.tool_version,
        "evidence_completeness": evidence_completeness,
        "mapped_evidence_count": mapped_evidence_count,
        "total_agents": report.total_agents,
        "total_servers": report.total_servers,
        "total_packages": report.total_packages,
        "total_vulnerabilities": report.total_vulnerabilities,
        "critical_count": len(report.critical_vulns),
    }

    # Build control mapping
    control_mapping = {}
    for ctrl_id, ctrl_desc in metadata.catalog.items():
        evidence_rows = mapped_evidence.get(ctrl_id, [])
        status = "not_evaluated"
        if evidence_rows:
            status = "fail" if any(row.severity in _HIGH_SEVERITIES for row in evidence_rows) else "review"
        control_mapping[ctrl_id] = {
            "description": ctrl_desc,
            "status": status,
            "evidence_count": len(evidence_rows),
            "evidence": [row.as_json() for row in evidence_rows],
        }

    # Executive summary text
    summary_lines = [
        f"Compliance Evidence Bundle — {metadata.report_label}",
        f"Generated: {report.generated_at.isoformat()}",
        f"Tool: agent-bom v{report.tool_version}",
        f"Evidence completeness: {evidence_completeness}",
        "",
        f"Agents scanned: {report.total_agents}",
        f"MCP servers: {report.total_servers}",
        f"Packages inventoried: {report.total_packages}",
        f"Vulnerabilities found: {report.total_vulnerabilities}",
        f"Critical findings: {len(report.critical_vulns)}",
        "",
        "Controls mapped: " + ", ".join(metadata.catalog.keys()),
        "",
        "Note: this local CLI bundle is evidence-backed but unsigned unless AGENT_BOM_AUDIT_HMAC_KEY is set. "
        "For tenant-scoped signed reports, use the API compliance report endpoint.",
    ]

    artifacts = {
        "sbom.cdx.json": _json_bytes(sbom_data),
        "vulnerability_report.json": _json_bytes(vuln_entries),
        "policy_results.json": _json_bytes(policy_results),
        "compliance_mapping.json": _json_bytes(control_mapping),
        "summary.txt": "\n".join(summary_lines).encode("utf-8"),
    }
    from agent_bom.api.secret_source import resolve_secret

    signature_key = resolve_secret("AGENT_BOM_AUDIT_HMAC_KEY")
    signature_status = "signed" if signature_key else "unsigned_local_bundle"
    manifest = {
        "schema_version": "agent-bom.compliance_cli_bundle/v1",
        "framework": metadata.slug,
        "framework_label": metadata.report_label,
        "generated_at": report.generated_at.isoformat(),
        "tool_version": report.tool_version,
        "evidence_completeness": evidence_completeness,
        "mapped_evidence_count": mapped_evidence_count,
        "input_summary": {
            "agents": report.total_agents,
            "servers": report.total_servers,
            "packages": report.total_packages,
            "vulnerabilities": report.total_vulnerabilities,
            "findings": len(cve_rows),
        },
        "files": {name: {"sha256": _digest(payload), "bytes": len(payload)} for name, payload in artifacts.items()},
        "signature": {
            "status": signature_status,
            "algorithm": "HMAC-SHA256" if signature_key else None,
            "signed_payload": "manifest.json" if signature_key else None,
        },
    }
    manifest_bytes = _json_bytes(manifest)
    artifacts["manifest.json"] = manifest_bytes
    if signature_key:
        signature = hmac.new(signature_key.encode("utf-8"), manifest_bytes, hashlib.sha256).hexdigest()
        artifacts["signature.json"] = _json_bytes(
            {
                "algorithm": "HMAC-SHA256",
                "manifest_sha256": _digest(manifest_bytes),
                "signature": signature,
            }
        )

    zip_path = output_path if output_path.endswith(".zip") else output_path + ".zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, payload in artifacts.items():
            zf.writestr(name, payload)

    return zip_path
