"""External-source ingestion for the Compliance Hub (#1044 PR B + C).

Reads findings from external scanner outputs and produces unified
``Finding`` objects with framework classification populated by
``compliance_hub.apply_hub_classification``.

Supported formats:
- SARIF 2.1.0 (PR B) — Semgrep, Gitleaks, Trivy, custom SAST
- CycloneDX vulnerabilities[] (PR C) — Syft+Grype, Trivy, Snyk SBOMs
- Generic CSV (PR C) — column-mapped row → Finding
- Generic JSON (PR C) — list-of-finding-shaped dicts

The contract is uniform: every external finding carries
``FindingSource.EXTERNAL`` plus the original tool name in ``evidence``.
Ingestion adapters refine via ``finding_type`` so downstream consumers
see the right framework set without each adapter re-implementing the
mapping.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any, Iterable

from agent_bom.compliance_hub import apply_hub_classification
from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from agent_bom.graph.severity import normalize_severity
from agent_bom.parsers.sarif import (
    NormalizedSarifResult,
    SarifValidationError,
    normalize_sarif_document,
)

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
    if "cis_error" in haystack or "cis-error" in haystack:
        return FindingType.CIS_ERROR
    if "cloud_best_practice_error" in haystack:
        return FindingType.CLOUD_BEST_PRACTICE_ERROR
    if "cloud_best_practice_fail" in haystack or "databricks best practice" in haystack:
        return FindingType.CLOUD_BEST_PRACTICE_FAIL
    if "cis-" in haystack or "benchmark" in haystack:
        return FindingType.CIS_FAIL
    return FindingType.SAST


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
    try:
        return parse_sarif_document(sarif)
    except SarifValidationError:
        return []


def parse_sarif_document(sarif: dict) -> list[Finding]:
    """Parse an in-memory SARIF 2.1.0 document into hub-classified findings."""
    document = normalize_sarif_document(sarif)
    return [_normalized_sarif_result_to_finding(result) for result in document.results]


def _normalized_sarif_result_to_finding(result: NormalizedSarifResult) -> Finding:
    rule_id = result.rule_id
    rule_tags = list(result.rule_tags)
    description = result.message or result.rule_full_description or result.rule_short_description or rule_id
    severity = _coerce_severity(result.level, result.security_severity)
    location = result.location
    if location is None:
        asset_name, file_path = "unknown", None
    else:
        file_path = location.uri
        asset_name = f"{file_path}:{location.start_line}" if location.start_line else file_path
    finding_type = _pick_finding_type(rule_id, rule_tags, description)
    cwe_ids = [tag.upper() for tag in rule_tags if tag.lower().startswith("cwe-")]

    evidence: dict[str, Any] = {
        "external_tool": result.tool_name,
        "rule_id": rule_id,
        "rule_tags": rule_tags,
        "sarif_level": result.level,
    }
    if result.security_severity is not None:
        evidence["sarif_security_severity"] = result.security_severity
    if result.fingerprints:
        evidence["sarif_fingerprints"] = dict(result.fingerprints)
    if result.partial_fingerprints:
        evidence["sarif_partial_fingerprints"] = dict(result.partial_fingerprints)

    title = result.rule_short_description or rule_id or result.message[:100] or "External finding"
    finding = Finding(
        finding_type=finding_type,
        source=FindingSource.EXTERNAL,
        asset=Asset(
            name=asset_name,
            asset_type="file" if file_path else "external",
            identifier=rule_id or None,
            location=file_path,
        ),
        severity=severity,
        title=title,
        description=description,
        cwe_ids=cwe_ids,
        cvss_score=result.security_severity,
        evidence=evidence,
    )
    return apply_hub_classification(finding)


# ─── CycloneDX vulnerabilities[] ────────────────────────────────────────────


_CYCLONEDX_SEVERITY_VALUES = {"critical", "high", "medium", "low", "info", "none", "unknown"}


def _cyclonedx_severity(vuln: dict) -> tuple[str, float | None]:
    """Pick severity + cvss score from a CycloneDX vulnerability entry.

    CycloneDX `ratings[]` carries `severity` (string) and `score`
    (CVSS-style float). Take the first rating with a recognised severity;
    if score is set, surface it as cvss_score for downstream risk math.
    """
    severity = "unknown"
    cvss_score: float | None = None
    for rating in vuln.get("ratings") or []:
        if not isinstance(rating, dict):
            continue
        sev_raw = str(rating.get("severity") or "").lower()
        if sev_raw in _CYCLONEDX_SEVERITY_VALUES:
            severity = sev_raw
        score = rating.get("score")
        if score is not None:
            try:
                cvss_score = float(score)
            except (TypeError, ValueError):
                pass
        if severity != "unknown":
            break
    return severity, cvss_score


def _cyclonedx_affected_purl(vuln: dict, components: dict[str, dict]) -> str | None:
    """Resolve `affects[].ref` -> bom-ref -> component purl."""
    for affect in vuln.get("affects") or []:
        if not isinstance(affect, dict):
            continue
        ref = str(affect.get("ref") or "")
        comp = components.get(ref)
        if comp is None:
            continue
        purl = comp.get("purl")
        if purl:
            return str(purl)
        name = comp.get("name") or ""
        version = comp.get("version") or ""
        if name:
            return f"{name}@{version}" if version else name
    return None


def ingest_cyclonedx_vulnerabilities(path: str | Path) -> list[Finding]:
    """Parse CycloneDX vulnerabilities[] into hub-classified Finding objects.

    Maps to ``FindingSource.SBOM`` (not EXTERNAL): CycloneDX vuln data
    comes from a known supply-chain context, so the hub's SBOM baseline
    (NIST CSF / SOC 2 / PCI DSS) applies cleanly. CVE finding-type
    refinement isn't a hub addition — CVEs already pull SBOM frameworks
    by source.
    """
    sbom_path = Path(path)
    if not sbom_path.is_file():
        return []
    try:
        sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return []
    if not isinstance(sbom, dict):
        return []

    components_by_ref: dict[str, dict] = {}
    for comp in sbom.get("components") or []:
        if isinstance(comp, dict):
            ref = comp.get("bom-ref")
            if ref:
                components_by_ref[str(ref)] = comp

    findings: list[Finding] = []
    for vuln in sbom.get("vulnerabilities") or []:
        if not isinstance(vuln, dict):
            continue
        vuln_id = str(vuln.get("id") or "").strip()
        if not vuln_id:
            continue
        summary = str(vuln.get("description") or vuln.get("detail") or "")
        severity, cvss = _cyclonedx_severity(vuln)
        purl = _cyclonedx_affected_purl(vuln, components_by_ref)

        asset_name = purl or vuln_id
        finding = Finding(
            finding_type=FindingType.CVE,
            source=FindingSource.SBOM,
            asset=Asset(
                name=asset_name,
                asset_type="package",
                identifier=purl,
            ),
            severity=severity,
            title=f"{vuln_id}: {asset_name}",
            description=summary,
            cve_id=vuln_id,
            cvss_score=cvss,
            evidence={
                "external_format": "cyclonedx",
                "vuln_id": vuln_id,
            },
        )
        findings.append(apply_hub_classification(finding))

    return findings


# ─── Generic CSV ─────────────────────────────────────────────────────────────


# Default header → field mapping. Callers can override per file.
_CSV_DEFAULT_MAPPING = {
    "title": ("title", "rule", "rule_id", "name", "summary"),
    "severity": ("severity", "level", "priority"),
    "description": ("description", "message", "detail"),
    "asset_name": ("file", "path", "asset", "resource", "location", "target"),
    "cve_id": ("cve", "cve_id", "cwe", "id", "vuln_id"),
}


def _resolve_csv_field(row: dict[str, str], candidates: tuple[str, ...]) -> str:
    for key in candidates:
        for header in row:
            if header.lower().replace(" ", "_") == key:
                value = row[header]
                if value:
                    return str(value).strip()
    return ""


def _normalise_csv_severity(value: str) -> str:
    lowered = value.lower().strip()
    aliases = {
        "crit": "critical",
        "h": "high",
        "med": "medium",
        "moderate": "medium",
        "m": "medium",
        "l": "low",
        "note": "info",
        "informational": "info",
    }
    return normalize_severity(aliases.get(lowered, lowered) if lowered else None)


def ingest_csv_findings(path: str | Path) -> list[Finding]:
    """Parse a generic CSV of findings into Finding objects.

    Headers are matched case-insensitively against ``_CSV_DEFAULT_MAPPING``.
    Rows missing both title and CVE id are skipped — there's nothing
    actionable to render.
    """
    csv_path = Path(path)
    if not csv_path.is_file():
        return []
    try:
        text = csv_path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return []

    findings: list[Finding] = []
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        if not row:
            continue
        title = _resolve_csv_field(row, _CSV_DEFAULT_MAPPING["title"])
        cve_id = _resolve_csv_field(row, _CSV_DEFAULT_MAPPING["cve_id"])
        if not title and not cve_id:
            continue
        severity = _normalise_csv_severity(_resolve_csv_field(row, _CSV_DEFAULT_MAPPING["severity"]))
        description = _resolve_csv_field(row, _CSV_DEFAULT_MAPPING["description"])
        asset_name = _resolve_csv_field(row, _CSV_DEFAULT_MAPPING["asset_name"]) or title or cve_id

        if cve_id and cve_id.upper().startswith(("CVE-", "GHSA-")):
            finding_type = FindingType.CVE
        else:
            finding_type = _pick_finding_type(title, [], description or title)
        asset_type = "package" if finding_type == FindingType.CVE else "file"

        finding = Finding(
            finding_type=finding_type,
            source=FindingSource.EXTERNAL,
            asset=Asset(name=asset_name, asset_type=asset_type, location=asset_name if asset_type == "file" else None),
            severity=severity,
            title=title or cve_id,
            description=description,
            cve_id=cve_id or None,
            evidence={
                "external_format": "csv",
                "row_keys": sorted(row.keys()),
            },
        )
        findings.append(apply_hub_classification(finding))
    return findings


# ─── Generic JSON list ───────────────────────────────────────────────────────


_JSON_FINDING_KEYS = ("title", "severity", "description", "cve_id", "asset_name", "asset_type", "finding_type")


def ingest_json_findings(path: str | Path) -> list[Finding]:
    """Parse a generic JSON list of finding-shaped dicts into Findings.

    Accepts either a top-level list of dicts or a dict with a "findings" key
    holding the list. Each dict can carry any subset of: title, severity,
    description, cve_id, asset_name, asset_type, finding_type, location,
    evidence. Unknown keys are passed through into evidence so nothing
    is lost.
    """
    json_path = Path(path)
    if not json_path.is_file():
        return []
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return []
    if isinstance(data, dict):
        rows: Iterable[Any] = data.get("findings") or []
    elif isinstance(data, list):
        rows = data
    else:
        return []

    findings: list[Finding] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        title = str(row.get("title") or row.get("name") or row.get("rule_id") or "").strip()
        cve_id = str(row.get("cve_id") or row.get("cve") or "").strip() or None
        if not title and not cve_id:
            continue
        severity = _normalise_csv_severity(str(row.get("severity") or row.get("level") or ""))
        description = str(row.get("description") or row.get("message") or "")
        asset_name = str(row.get("asset_name") or row.get("file") or row.get("location") or "") or title or (cve_id or "")
        asset_type_raw = str(row.get("asset_type") or "").strip().lower()
        if asset_type_raw not in {"file", "package", "mcp_server", "agent", "tool", "container", "cloud_resource", "skill", "external"}:
            asset_type_raw = "package" if cve_id else "external"

        ft_raw = str(row.get("finding_type") or "").strip().upper()
        try:
            finding_type = FindingType(ft_raw) if ft_raw else (FindingType.CVE if cve_id else FindingType.SAST)
        except ValueError:
            finding_type = FindingType.CVE if cve_id else FindingType.SAST

        evidence: dict[str, Any] = {"external_format": "json"}
        passthrough = {k: v for k, v in row.items() if k not in _JSON_FINDING_KEYS and k not in {"location", "evidence"}}
        if passthrough:
            evidence["passthrough"] = passthrough
        if isinstance(row.get("evidence"), dict):
            evidence.update(row["evidence"])

        finding = Finding(
            finding_type=finding_type,
            source=FindingSource.EXTERNAL,
            asset=Asset(
                name=asset_name,
                asset_type=asset_type_raw,
                location=str(row.get("location") or "") or None,
            ),
            severity=severity,
            title=title or (cve_id or "External finding"),
            description=description,
            cve_id=cve_id,
            evidence=evidence,
        )
        findings.append(apply_hub_classification(finding))
    return findings


# ─── Format dispatch ─────────────────────────────────────────────────────────


def ingest_findings(path: str | Path, *, fmt: str | None = None) -> list[Finding]:
    """Ingest findings from a file, auto-detecting format from extension.

    ``fmt`` overrides extension detection: "sarif", "cyclonedx", "csv", "json".
    """
    p = Path(path)
    chosen = (fmt or "").lower()
    if not chosen:
        suffix = p.suffix.lower().lstrip(".")
        if suffix == "sarif":
            chosen = "sarif"
        elif suffix == "csv":
            chosen = "csv"
        elif suffix == "json":
            try:
                head = p.read_text(encoding="utf-8")[:512]
            except (UnicodeDecodeError, OSError):
                return []
            if '"$schema"' in head and "sarif" in head.lower():
                chosen = "sarif"
            elif '"bomFormat"' in head or '"specVersion"' in head:
                chosen = "cyclonedx"
            else:
                chosen = "json"
        else:
            return []

    if chosen == "sarif":
        return ingest_sarif_findings(p)
    if chosen == "cyclonedx":
        return ingest_cyclonedx_vulnerabilities(p)
    if chosen == "csv":
        return ingest_csv_findings(p)
    if chosen == "json":
        return ingest_json_findings(p)
    return []
