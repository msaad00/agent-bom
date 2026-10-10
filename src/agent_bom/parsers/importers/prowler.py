"""Prowler JSON-OCSF importer (``prowler <provider> --output-formats json-ocsf``).

Prowler v4/v5 writes an array of OCSF Detection Finding objects (class 2004).
FAIL results become cloud posture findings; MANUAL results become
"not evaluated" findings so they stay visible without being counted as
failures. PASS and muted results are skipped and counted in a notice.
"""

from __future__ import annotations

from typing import Any

from agent_bom.core.severity import ocsf_to_severity
from agent_bom.finding import FindingType
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

_OCSF_DETECTION_FINDING = 2004
_IMPORTED_STATUS = {"FAIL": FindingType.CLOUD_BEST_PRACTICE_FAIL, "MANUAL": FindingType.CLOUD_BEST_PRACTICE_ERROR}


def _is_prowler_row(row: object) -> bool:
    if not isinstance(row, dict) or not isinstance(row.get("finding_info"), dict):
        return False
    product = mapping(mapping(row.get("metadata")).get("product"))
    names = f"{product.get('name', '')} {product.get('vendor_name', '')}".lower()
    return "prowler" in names and (row.get("class_uid") in (None, _OCSF_DETECTION_FINDING)) and "status_code" in row


def _severity(row: dict[str, Any]) -> str:
    label = text(row.get("severity"), 40)
    if label:
        return label
    severity_id = row.get("severity_id")
    return ocsf_to_severity(severity_id) if isinstance(severity_id, int) and not isinstance(severity_id, bool) else "unknown"


def _remediation(row: dict[str, Any]) -> tuple[str, list[str]]:
    remediation = mapping(row.get("remediation"))
    references = remediation.get("references")
    refs = [text(ref, 500) for ref in references[:10]] if isinstance(references, list) else []
    return text(remediation.get("desc"), 2000), [ref for ref in refs if ref]


def _is_muted(row: dict[str, Any]) -> bool:
    return text(row.get("status"), 40).lower() == "suppressed" or mapping(row.get("unmapped")).get("muted") is True


def _record(row: dict[str, Any], status: str, version: str) -> CloudRecord:
    info = mapping(row.get("finding_info"))
    cloud = mapping(row.get("cloud"))
    raw_resources = row.get("resources")
    resources = [item for item in raw_resources if isinstance(item, dict)] if isinstance(raw_resources, list) else []
    primary = resources[0] if resources else {}
    check_id = text(mapping(row.get("metadata")).get("event_code"), 200)
    resource_id = text(primary.get("uid"), 512)
    native_id = text(info.get("uid"), 512) or f"{check_id}:{resource_id}"
    remediation, references = _remediation(row)
    controls, compliance = vendor_controls(mapping(row.get("unmapped")).get("compliance"), tool="prowler")
    return CloudRecord(
        tool="prowler",
        native_id=native_id,
        title=text(info.get("title"), 300) or check_id,
        severity=_severity(row),
        provider=text(cloud.get("provider"), 40).lower(),
        finding_type=_IMPORTED_STATUS[status],
        description=text(row.get("status_detail"), 2000) or text(info.get("desc"), 2000),
        account=text(mapping(cloud.get("account")).get("uid"), 128),
        region=text(primary.get("region"), 64) or text(cloud.get("region"), 64),
        resource_id=resource_id,
        resource_type=text(primary.get("type"), 128),
        remediation=remediation,
        controls=controls,
        evidence={
            "external_tool_version": version or None,
            "check_id": check_id,
            "status": status,
            "risk": text(row.get("risk_details"), 1000),
            "references": references,
            "compliance": compliance,
            "additional_resource_ids": [text(item.get("uid"), 512) for item in resources[1:MAX_RESOURCES_PER_RECORD]],
        },
    )


class ProwlerImporter:
    """Built-in importer for Prowler JSON-OCSF output."""

    manifest = ImporterManifest(
        name="prowler",
        display_name="Prowler (JSON-OCSF)",
        tool="prowler",
        formats=("json-ocsf",),
        detection="JSON array of OCSF Detection Findings (class_uid 2004) whose metadata.product.name is Prowler.",
        data_retained=(
            "check id, finding uid, title, status detail, severity, cloud provider/account/region, resource uid/type, "
            "remediation text and references, vendor compliance mappings, Prowler version."
        ),
        default_filters="PASS and muted results are skipped; MANUAL results are kept as not-evaluated findings.",
    )

    def sniff(self, data: object) -> bool:
        if not isinstance(data, list) or not data:
            return False
        head = data[:5]
        return all(_is_prowler_row(row) for row in head)

    def parse(self, data: object) -> ExternalScanImport:
        rows = records(data, label="Prowler")
        skipped = {"PASS result(s)": 0, "muted result(s)": 0, "result(s) with an unknown status_code": 0}
        imported = ExternalScanImport(format="prowler", tool_names=["prowler"])
        seen: set[str] = set()
        for row in rows:
            status = text(row.get("status_code"), 20).upper()
            if status == "PASS":
                skipped["PASS result(s)"] += 1
                continue
            if status not in _IMPORTED_STATUS:
                skipped["result(s) with an unknown status_code"] += 1
                continue
            if _is_muted(row):
                skipped["muted result(s)"] += 1
                continue
            version = text(mapping(mapping(row.get("metadata")).get("product")).get("version"), 40)
            finding = to_finding(_record(row, status, version))
            if finding.id not in seen:
                seen.add(finding.id)
                imported.findings.append(finding)
        imported.notices.extend(skipped_notice("Prowler", skipped))
        return imported
