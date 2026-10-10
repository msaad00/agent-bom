"""Shared, bounded helpers for cloud-posture report importers."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from agent_bom.compliance_hub import apply_hub_classification
from agent_bom.finding import EXTERNAL_SOURCE_PREFIX, Asset, ControlTag, Finding, FindingSource, FindingType, stable_id
from agent_bom.finding_scope import account_ref_from_arn, normalize_account_ref, region_from_arn
from agent_bom.security import sanitize_text

# A report larger than this is split upstream; parsing it in one pass would
# hold every finding in memory at once. The byte limit is enforced by the
# caller's bounded file read (``parsers.file_limits``).
MAX_IMPORT_RECORDS = 100_000
MAX_RESOURCES_PER_RECORD = 20
MAX_CONTROLS_PER_RECORD = 64
_FRAMEWORK_SLUG_RE = re.compile(r"[^a-z0-9]+")


def text(value: object, max_len: int = 1000) -> str:
    """Return a redacted, length-bounded string for a scalar field, else ``""``."""
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        return ""
    return sanitize_text(str(value), max_len=max_len).strip()


def mapping(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def records(value: object, *, label: str) -> list[dict[str, Any]]:
    """Return the dict records of a report list, enforcing the record cap."""
    if not isinstance(value, list):
        raise ValueError(f"{label} report must contain a list of findings")
    if len(value) > MAX_IMPORT_RECORDS:
        raise ValueError(f"{label} report has {len(value)} records; split it into files of at most {MAX_IMPORT_RECORDS}")
    return [row for row in value if isinstance(row, dict)]


def source_label(tool: str) -> str:
    return f"{EXTERNAL_SOURCE_PREFIX}{tool}"


def vendor_controls(compliance: object, *, tool: str) -> tuple[list[ControlTag], dict[str, list[str]]]:
    """Type vendor-asserted compliance references without claiming a crosswalk.

    Accepts ``{"Framework": ["control", ...]}`` (Prowler) or a flat list of
    ``"Framework control"`` strings (Security Hub ``RelatedRequirements``).
    Frameworks are namespaced under the tool so they never merge into the
    bundled framework catalog by name alone.
    """
    pairs: list[tuple[str, str]] = []
    if isinstance(compliance, dict):
        for key, controls in compliance.items():
            values = controls if isinstance(controls, list) else [controls]
            pairs.extend((text(key, 120), text(control, 120)) for control in values)
    elif isinstance(compliance, list):
        for entry in compliance:
            framework, _, control = text(entry, 240).rpartition(" ")
            pairs.append((framework or tool, control))
    evidence: dict[str, list[str]] = {}
    tags: list[ControlTag] = []
    for framework, control in pairs[:MAX_CONTROLS_PER_RECORD]:
        slug = _FRAMEWORK_SLUG_RE.sub("_", framework.lower()).strip("_")[:64]
        if not slug or not control:
            continue
        evidence.setdefault(framework, []).append(control)
        tags.append(ControlTag(framework=f"{tool}:{slug}", control=control, source=source_label(tool), via="vendor-asserted"))
    return tags, evidence


@dataclass
class CloudRecord:
    """Normalized fields of one imported cloud finding, before projection."""

    tool: str
    native_id: str
    title: str
    severity: str
    provider: str
    finding_type: FindingType = FindingType.CLOUD_BEST_PRACTICE_FAIL
    description: str = ""
    account: str = ""
    region: str = ""
    resource_id: str = ""
    resource_type: str = ""
    remediation: str = ""
    controls: list[ControlTag] = field(default_factory=list)
    cve_id: str | None = None
    cvss_score: float | None = None
    fixed_version: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    key_parts: tuple[str, ...] = ()


def to_finding(record: CloudRecord) -> Finding:
    """Project a normalized record onto the unified ``Finding`` model.

    Posture results use ``CLOUD_SECURITY`` (vendor-authored cloud best
    practice, routed to the CSPM lane); vulnerability results stay
    ``EXTERNAL``. Both carry ``external:<tool>`` provenance in ``sources``.
    """
    resource = record.resource_id or f"{record.provider or 'cloud'}-account"
    account = record.account or account_ref_from_arn(record.resource_id) or ""
    account_ref = normalize_account_ref(record.provider, account)
    region = record.region or region_from_arn(record.resource_id) or None
    evidence = {
        "external_tool": record.tool,
        "source_finding_id": record.native_id,
        "resource_id": record.resource_id or None,
        "resource_type": record.resource_type or None,
        **record.evidence,
    }
    finding = Finding(
        finding_type=record.finding_type,
        source=FindingSource.EXTERNAL if record.finding_type == FindingType.CVE else FindingSource.CLOUD_SECURITY,
        asset=Asset(name=resource, asset_type="cloud_resource", identifier=resource, location=record.provider or None),
        severity=record.severity,
        vendor_severity=record.severity,
        provider=record.provider or None,
        account_ref=account_ref,
        region=region,
        title=record.title or record.native_id,
        description=record.description,
        cve_id=record.cve_id,
        cvss_score=record.cvss_score,
        fixed_version=record.fixed_version,
        remediation_guidance=record.remediation or None,
        controls=list(record.controls),
        evidence={key: value for key, value in evidence.items() if value not in (None, "", [], {})},
        sources=[source_label(record.tool)],
        id=stable_id(record.tool, record.native_id, *record.key_parts),
    )
    return apply_hub_classification(finding)


def skipped_notice(label: str, skipped: dict[str, int]) -> list[str]:
    """Return one transparency notice naming every default skip rule that fired."""
    parts = [f"{count} {reason}" for reason, count in skipped.items() if count]
    return [f"{label}: skipped {', '.join(parts)} by default import rules."] if parts else []
