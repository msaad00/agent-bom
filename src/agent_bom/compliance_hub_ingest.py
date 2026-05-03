"""External-source ingestion for the Compliance Hub (#1044 PR B).

Reads findings from external scanner outputs (SARIF today; CycloneDX,
CSV, and JSON in PR C) and produces unified ``Finding`` objects with
framework classification populated by ``compliance_hub.apply_hub_classification``.

The contract is uniform: every external finding carries
``FindingSource.EXTERNAL`` plus the original tool name in ``evidence``.
The hub maps that to the union of all tag-mapped frameworks; ingestion
adapters can refine via ``finding_type`` so downstream consumers see the
right framework set without each adapter re-implementing the mapping.

PR B ships the SARIF adapter — the most common external format for SAST,
secret scanners, IaC scanners, and container vuln scanners. Other formats
land in PR C alongside the API ingestion endpoint that consumes them.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent_bom.compliance_hub import apply_hub_classification
from agent_bom.finding import Asset, Finding, FindingSource, FindingType

# SARIF level → severity. SARIF only defines four levels; we map none/note
# down to "info" so they don't masquerade as low-severity bugs.
_SARIF_LEVEL_TO_SEVERITY = {
    "error": "high",
    "warning": "medium",
    "note": "info",
    "none": "info",
}


def _coerce_severity(level: str | None, security_severity: float | None) -> str:
    """Pick the best severity signal from a SARIF result.

    SARIF 2.1.0 defines `level` (note/warning/error) and `properties.security-severity`
    (CVSS-style 0–10 score). We prefer the security-severity score when present
    because it carries more signal; otherwise fall back to the level.
    """
    if security_severity is not None:
        if security_severity >= 9.0:
            return "critical"
        if security_severity >= 7.0:
            return "high"
        if security_severity >= 4.0:
            return "medium"
        if security_severity > 0:
            return "low"
        return "info"
    return _SARIF_LEVEL_TO_SEVERITY.get((level or "warning").lower(), "medium")


def _pick_finding_type(
    rule_id: str | None,
    rule_tags: list[str],
    message: str,
) -> FindingType:
    """Best-effort finding-type inference from rule metadata.

    Drives the hub's finding-type refinements (e.g. INJECTION pulls in AI
    frameworks even when source is EXTERNAL). The defaults are conservative
    — when in doubt, fall back to SAST so the hub assigns the broadest
    enterprise framework set.
    """
    haystack = " ".join(filter(None, [rule_id or "", " ".join(rule_tags), message])).lower()
    if "secret" in haystack or "credential" in haystack or "password" in haystack or "token" in haystack:
        return FindingType.CREDENTIAL_EXPOSURE
    if "injection" in haystack or "prompt-injection" in haystack or "sqli" in haystack or "xss" in haystack:
        return FindingType.INJECTION
    if "exfil" in haystack or "data-exfiltration" in haystack:
        return FindingType.EXFILTRATION
    if "license" in haystack:
        return FindingType.LICENSE
    if "cve-" in haystack or "ghsa-" in haystack:
        return FindingType.CVE
    if "cis-" in haystack or "benchmark" in haystack:
        return FindingType.CIS_FAIL
    return FindingType.SAST


def _rule_tags(rule: dict) -> list[str]:
    props = rule.get("properties") or {}
    tags = props.get("tags") or []
    return [str(t) for t in tags]


def _result_location(result: dict) -> tuple[str, str | None]:
    """Return (display_name, file_path) for a SARIF result.

    SARIF locations carry a `physicalLocation.artifactLocation.uri`. We use
    that as both the asset name and location so findings can be deduped by
    file path across rules.
    """
    locations = result.get("locations") or []
    if not locations:
        return ("unknown", None)
    physical = locations[0].get("physicalLocation") or {}
    artifact = physical.get("artifactLocation") or {}
    uri = artifact.get("uri")
    if not uri:
        return ("unknown", None)
    region = physical.get("region") or {}
    line = region.get("startLine")
    name = f"{uri}:{line}" if line else uri
    return (str(name), str(uri))


def _build_rule_index(run: dict) -> dict[str, dict]:
    """Index `rules[]` by id so we can fetch metadata for each result."""
    tool = run.get("tool") or {}
    driver = tool.get("driver") or {}
    rules = driver.get("rules") or []
    return {str(rule.get("id") or ""): rule for rule in rules if rule.get("id")}


def _tool_name(run: dict) -> str:
    tool = run.get("tool") or {}
    driver = tool.get("driver") or {}
    return str(driver.get("name") or "external")


def ingest_sarif_findings(path: str | Path) -> list[Finding]:
    """Parse a SARIF 2.1.0 file into hub-classified ``Finding`` objects.

    Every finding carries ``FindingSource.EXTERNAL`` plus the originating
    tool name (and rule id) in ``evidence``. Framework classification runs
    through ``apply_hub_classification`` so the same matrix applies as
    native scanners — no adapter-specific mapping table.

    Returns an empty list (rather than raising) on missing or malformed
    files so callers can ingest a directory of SARIF files without one
    bad apple aborting the batch. The caller can detect "nothing parsed"
    by checking the returned length.
    """
    sarif_path = Path(path)
    if not sarif_path.is_file():
        return []
    try:
        sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return []
    if not isinstance(sarif, dict):
        return []

    runs = sarif.get("runs") or []
    findings: list[Finding] = []
    for run in runs:
        if not isinstance(run, dict):
            continue
        tool_name = _tool_name(run)
        rule_index = _build_rule_index(run)
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            findings.append(_sarif_result_to_finding(result, rule_index, tool_name))
    return findings


def _sarif_result_to_finding(result: dict, rule_index: dict[str, dict], tool_name: str) -> Finding:
    rule_id = str(result.get("ruleId") or "")
    rule = rule_index.get(rule_id, {})
    rule_tags = _rule_tags(rule)

    message_text = ((result.get("message") or {}).get("text") or "").strip()
    rule_short = ((rule.get("shortDescription") or {}).get("text") or "").strip()
    rule_full = ((rule.get("fullDescription") or {}).get("text") or "").strip()
    description = message_text or rule_full or rule_short or rule_id

    level = result.get("level")
    properties = result.get("properties") or {}
    sec_severity_raw = properties.get("security-severity") or (rule.get("properties") or {}).get("security-severity")
    sec_severity: float | None
    try:
        sec_severity = float(sec_severity_raw) if sec_severity_raw is not None else None
    except (TypeError, ValueError):
        sec_severity = None

    severity = _coerce_severity(level, sec_severity)

    asset_name, location = _result_location(result)
    finding_type = _pick_finding_type(rule_id, rule_tags, description)

    cwe_ids = [tag.upper() for tag in rule_tags if tag.lower().startswith("cwe-")]

    evidence: dict[str, Any] = {
        "external_tool": tool_name,
        "rule_id": rule_id,
        "rule_tags": rule_tags,
        "sarif_level": level,
    }
    if sec_severity is not None:
        evidence["sarif_security_severity"] = sec_severity

    title = rule_short or rule_id or message_text[:100] or "External finding"

    finding = Finding(
        finding_type=finding_type,
        source=FindingSource.EXTERNAL,
        asset=Asset(
            name=asset_name,
            asset_type="file" if location else "external",
            identifier=rule_id or None,
            location=location,
        ),
        severity=severity,
        title=title,
        description=description,
        cwe_ids=cwe_ids,
        cvss_score=sec_severity,
        evidence=evidence,
    )
    return apply_hub_classification(finding)
