"""AWS Security Hub importer (ASFF from ``aws securityhub get-findings``).

Accepts the CLI/API response object ``{"Findings": [...]}`` or a bare list of
ASFF findings. Security Hub aggregates many producers, so each finding keeps
its own ``ProductName``/``ProductArn`` as provenance. Findings that carry
``Vulnerabilities[]`` become one CVE finding per vulnerability on the affected
resource; every other finding becomes a cloud posture finding.
"""

from __future__ import annotations

import re
from dataclasses import replace
from typing import Any

from agent_bom.finding import Finding, FindingType
from agent_bom.parsers.importers._common import (
    MAX_RESOURCES_PER_RECORD,
    CloudRecord,
    mapping,
    records,
    skipped_notice,
    text,
    to_finding,
    vendor_controls,
)
from agent_bom.parsers.importers.base import ExternalScanImport, ImporterManifest

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_MAX_VULNERABILITIES_PER_RECORD = 100
_SKIPPED_WORKFLOW = frozenset({"SUPPRESSED", "RESOLVED"})
_NOT_EVALUATED = FindingType.CLOUD_BEST_PRACTICE_ERROR


def _is_asff(row: object) -> bool:
    return isinstance(row, dict) and "SchemaVersion" in row and "ProductArn" in row and "AwsAccountId" in row


def _severity(row: dict[str, Any]) -> str:
    severity = mapping(row.get("Severity"))
    label = text(severity.get("Label"), 40)
    if label:
        return label
    normalized = severity.get("Normalized")
    if isinstance(normalized, bool) or not isinstance(normalized, (int, float)):
        return "unknown"
    for floor, band in ((90, "critical"), (70, "high"), (40, "medium"), (1, "low")):
        if normalized >= floor:
            return band
    return "info"


def _skip_reason(row: dict[str, Any]) -> str | None:
    if text(row.get("RecordState"), 20).upper() == "ARCHIVED":
        return "archived finding(s)"
    if text(mapping(row.get("Workflow")).get("Status"), 20).upper() in _SKIPPED_WORKFLOW:
        return "suppressed or resolved finding(s)"
    if text(mapping(row.get("Compliance")).get("Status"), 20).upper() == "PASSED":
        return "PASSED control result(s)"
    return None


def _base_record(row: dict[str, Any]) -> CloudRecord:
    raw_resources = row.get("Resources")
    resources = [item for item in raw_resources if isinstance(item, dict)] if isinstance(raw_resources, list) else []
    primary = resources[0] if resources else {}
    compliance = mapping(row.get("Compliance"))
    recommendation = mapping(mapping(row.get("Remediation")).get("Recommendation"))
    remediation = " ".join(part for part in (text(recommendation.get("Text"), 2000), text(recommendation.get("Url"), 500)) if part)
    controls, requirements = vendor_controls(compliance.get("RelatedRequirements"), tool="aws-securityhub")
    compliance_status = text(compliance.get("Status"), 20).upper()
    raw_types = row.get("Types")
    return CloudRecord(
        tool="aws-securityhub",
        native_id=text(row.get("Id"), 1024),
        title=text(row.get("Title"), 300),
        severity=_severity(row),
        provider="aws",
        finding_type=_NOT_EVALUATED if compliance_status == "NOT_AVAILABLE" else FindingType.CLOUD_BEST_PRACTICE_FAIL,
        description=text(row.get("Description"), 2000),
        account=text(row.get("AwsAccountId"), 64),
        region=text(primary.get("Region"), 64) or text(row.get("Region"), 64),
        resource_id=text(primary.get("Id"), 512),
        resource_type=text(primary.get("Type"), 128),
        remediation=remediation,
        controls=controls,
        evidence={
            "product_name": text(row.get("ProductName"), 120),
            "product_arn": text(row.get("ProductArn"), 300),
            "company_name": text(row.get("CompanyName"), 120),
            "generator_id": text(row.get("GeneratorId"), 300),
            "control_id": text(compliance.get("SecurityControlId"), 80),
            "compliance_status": compliance_status,
            "workflow_status": text(mapping(row.get("Workflow")).get("Status"), 20).upper(),
            "finding_types": [text(item, 200) for item in raw_types[:10]] if isinstance(raw_types, list) else [],
            "compliance": requirements,
            "additional_resource_ids": [text(item.get("Id"), 512) for item in resources[1:MAX_RESOURCES_PER_RECORD]],
        },
    )


def _cvss(vuln: dict[str, Any]) -> tuple[float | None, str]:
    entries = vuln.get("Cvss")
    first = mapping(entries[0]) if isinstance(entries, list) and entries else {}
    score = first.get("BaseScore")
    if isinstance(score, bool) or not isinstance(score, (int, float)) or not 0 <= score <= 10:
        return None, text(first.get("BaseVector"), 200)
    return float(score), text(first.get("BaseVector"), 200)


def _vulnerability_findings(base: CloudRecord, vulnerabilities: list[Any]) -> list[Finding]:
    findings: list[Finding] = []
    for vuln in vulnerabilities[:_MAX_VULNERABILITIES_PER_RECORD]:
        if not isinstance(vuln, dict) or not text(vuln.get("Id"), 80):
            continue
        vuln_id = text(vuln.get("Id"), 80)
        packages = vuln.get("VulnerablePackages")
        package = mapping(packages[0]) if isinstance(packages, list) and packages else {}
        score, vector = _cvss(vuln)
        package_name = text(package.get("Name"), 200)
        record = replace(
            base,
            finding_type=FindingType.CVE,
            cve_id=vuln_id.upper() if _CVE_RE.match(vuln_id) else None,
            title=f"{vuln_id} in {package_name}" if package_name else (base.title or vuln_id),
            cvss_score=score,
            fixed_version=text(package.get("FixedInVersion"), 120) or None,
            key_parts=(vuln_id, package_name),
            evidence={
                **base.evidence,
                "vulnerability_id": vuln_id,
                "package_name": package_name,
                "package_version": text(package.get("Version"), 120),
                "package_manager": text(package.get("PackageManager"), 40),
                "cvss_vector": vector,
                "fix_available": text(vuln.get("FixAvailable"), 20),
            },
        )
        findings.append(to_finding(record))
    return findings


class SecurityHubImporter:
    """Built-in importer for AWS Security Hub ASFF findings."""

    manifest = ImporterManifest(
        name="securityhub",
        display_name="AWS Security Hub (ASFF)",
        tool="aws-securityhub",
        formats=("asff",),
        detection='JSON object with a "Findings" list, or a JSON list, whose entries carry SchemaVersion, ProductArn and AwsAccountId.',
        data_retained=(
            "finding Id, product name/ARN, generator id, title, description, severity label, account, region, "
            "resource id/type, compliance status and related requirements, workflow status, remediation text/URL, "
            "vulnerability id, package name/version/fixed version and CVSS score."
        ),
        default_filters="ARCHIVED records, SUPPRESSED or RESOLVED workflow states, and PASSED control results are skipped.",
    )

    def sniff(self, data: object) -> bool:
        if isinstance(data, dict):
            rows = data.get("Findings")
            return isinstance(rows, list) and (not rows or _is_asff(rows[0]))
        return isinstance(data, list) and bool(data) and all(_is_asff(row) for row in data[:5])

    def parse(self, data: object) -> ExternalScanImport:
        rows = records(data.get("Findings") if isinstance(data, dict) else data, label="Security Hub")
        skipped: dict[str, int] = {}
        imported = ExternalScanImport(format="securityhub")
        seen: set[str] = set()
        for row in rows:
            if not _is_asff(row) or not text(row.get("Id"), 1024):
                skipped["record(s) that are not ASFF findings"] = skipped.get("record(s) that are not ASFF findings", 0) + 1
                continue
            reason = _skip_reason(row)
            if reason:
                skipped[reason] = skipped.get(reason, 0) + 1
                continue
            base = _base_record(row)
            vulnerabilities = row.get("Vulnerabilities")
            produced = _vulnerability_findings(base, vulnerabilities) if isinstance(vulnerabilities, list) and vulnerabilities else []
            for finding in produced or [to_finding(base)]:
                if finding.id not in seen:
                    seen.add(finding.id)
                    imported.findings.append(finding)
            product = base.evidence.get("product_name") or "Security Hub"
            if product not in imported.tool_names:
                imported.tool_names.append(product)
        imported.notices.extend(skipped_notice("Security Hub", skipped))
        return imported
