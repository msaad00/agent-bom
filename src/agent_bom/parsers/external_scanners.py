"""Ingest external scanner reports (SARIF, SBOM, scanner JSON) into agent-bom models."""

from __future__ import annotations

import logging
import re
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

from agent_bom.models import Package, Severity, Vulnerability, compute_confidence
from agent_bom.parsers.file_limits import read_json_limited
from agent_bom.parsers.importers import ExternalScanImport, import_registered_report

if TYPE_CHECKING:
    from agent_bom.finding import Finding
    from agent_bom.parsers.sarif import NormalizedSarifResult

logger = logging.getLogger(__name__)

# ── Ecosystem mappings ────────────────────────────────────────────────────────

_TRIVY_ECOSYSTEM_MAP: dict[str, str] = {
    "pip": "pypi",
    "npm": "npm",
    "go": "go",
    "cargo": "cargo",
    "maven": "maven",
    "nuget": "nuget",
}

_GRYPE_ECOSYSTEM_MAP: dict[str, str] = {
    "python": "pypi",
    "npm": "npm",
    "go-module": "go",
    "rust-crate": "cargo",
    "java-archive": "maven",
    "dotnet": "nuget",
}

_SYFT_ECOSYSTEM_MAP: dict[str, str] = {
    "python": "pypi",
    "npm": "npm",
    "go-module": "go",
    "rust-crate": "cargo",
    "java-archive": "maven",
    "dotnet": "nuget",
}


def _map_severity(raw: str) -> Severity:
    """Normalize a severity string to our Severity enum."""
    mapping = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "moderate": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.LOW,
        "informational": Severity.LOW,
        "none": Severity.NONE,
        "negligible": Severity.NONE,
        "unknown": Severity.UNKNOWN,
    }
    return mapping.get(raw.lower(), Severity.UNKNOWN)


def _trivy_cvss_score(cvss_block: dict) -> float | None:
    """Extract the best available CVSS v3 score from a Trivy CVSS block."""
    preferred_sources = ("nvd", "ghsa", "redhat", "amazon", "oracle", "bitnami")
    for source in preferred_sources:
        payload = cvss_block.get(source)
        if not isinstance(payload, dict):
            continue
        score_val = payload.get("V3Score")
        if score_val is None:
            continue
        try:
            return float(score_val)
        except (TypeError, ValueError):
            continue
    for payload in cvss_block.values():
        if not isinstance(payload, dict):
            continue
        score_val = payload.get("V3Score")
        if score_val is None:
            continue
        try:
            return float(score_val)
        except (TypeError, ValueError):
            continue
    return None


def _string_list(values: Any) -> list[str]:
    """Return non-empty string values while preserving input order."""
    if not isinstance(values, list):
        return []
    return [value for value in values if isinstance(value, str) and value]


def _cwe_ids(values: Any) -> list[str]:
    return [value for value in _string_list(values) if value.upper().startswith("CWE-")]


def _aliases(primary_id: str, *sources: Any) -> list[str]:
    seen: set[str] = {primary_id}
    aliases: list[str] = []
    for source in sources:
        for value in _string_list(source):
            if value in seen:
                continue
            seen.add(value)
            aliases.append(value)
    return aliases


def _trivy_advisory_source(vuln: dict[str, Any]) -> str | None:
    data_source = vuln.get("DataSource") or {}
    if isinstance(data_source, dict):
        source_id = data_source.get("ID")
        if isinstance(source_id, str) and source_id:
            return source_id
        source_name = data_source.get("Name")
        if isinstance(source_name, str) and source_name:
            return source_name
    severity_source = vuln.get("SeveritySource")
    return severity_source if isinstance(severity_source, str) and severity_source else None


def _grype_advisory_source(vuln: dict[str, Any]) -> str | None:
    namespace = vuln.get("namespace")
    if isinstance(namespace, str) and namespace:
        return namespace
    data_source = vuln.get("dataSource")
    return data_source if isinstance(data_source, str) and data_source else None


def _grype_related_aliases(vuln: dict[str, Any]) -> list[str]:
    related = vuln.get("relatedVulnerabilities") or []
    if not isinstance(related, list):
        return []
    aliases: list[str] = []
    for item in related:
        if not isinstance(item, dict):
            continue
        item_id = item.get("id")
        if isinstance(item_id, str) and item_id:
            aliases.append(item_id)
    return aliases


# ── Trivy parser ─────────────────────────────────────────────────────────────


def parse_trivy_json(data: dict[str, Any]) -> list[Package]:
    """Parse a Trivy JSON report (``trivy fs --format json``) into Package objects.

    Groups vulnerabilities by PkgName+InstalledVersion within each Result target.
    CVSS score is extracted from ``CVSS.nvd.V3Score`` with fallback to
    ``CVSS.ghsa.V3Score``.  Ecosystem is normalized via the Trivy type field.
    """
    results = data.get("Results") or []
    # pkg_key -> (Package, set_of_vuln_ids) — dedup across targets
    pkg_map: dict[tuple[str, str, str], Package] = {}

    for result in results:
        raw_type = result.get("Type", "")
        ecosystem = _TRIVY_ECOSYSTEM_MAP.get(raw_type, raw_type.lower() if raw_type else "unknown")
        vulns: list[dict] = result.get("Vulnerabilities") or []

        for vuln in vulns:
            pkg_name = vuln.get("PkgName", "")
            pkg_version = vuln.get("InstalledVersion", "")
            if not pkg_name:
                continue

            key = (pkg_name, pkg_version, ecosystem)
            if key not in pkg_map:
                pkg_map[key] = Package(name=pkg_name, version=pkg_version, ecosystem=ecosystem)

            pkg = pkg_map[key]

            cvss_block: dict = vuln.get("CVSS") or {}
            cvss_score = _trivy_cvss_score(cvss_block)

            references: list[str] = vuln.get("References") or []
            vuln_id = vuln.get("VulnerabilityID", "")
            advisory_source = _trivy_advisory_source(vuln)

            vuln_obj = Vulnerability(
                id=vuln_id,
                summary=vuln.get("Title") or vuln.get("Description") or "",
                severity=_map_severity(vuln.get("Severity", "")),
                severity_source=vuln.get("SeveritySource") or None,
                cvss_score=cvss_score,
                fixed_version=vuln.get("FixedVersion") or None,
                references=list(references),
                published_at=vuln.get("PublishedDate") or None,
                modified_at=vuln.get("LastModifiedDate") or None,
                aliases=_aliases(vuln_id, vuln.get("VendorIDs"), vuln.get("Aliases")),
                cwe_ids=_cwe_ids(vuln.get("CweIDs")),
                advisory_sources=[advisory_source] if advisory_source else [],
            )
            vuln_obj.confidence = compute_confidence(vuln_obj)
            # Avoid duplicate vuln IDs on the same package
            existing_ids = {v.id for v in pkg.vulnerabilities}
            if vuln_obj.id not in existing_ids:
                pkg.vulnerabilities.append(vuln_obj)

    return list(pkg_map.values())


# ── Grype parser ─────────────────────────────────────────────────────────────


def parse_grype_json(data: dict[str, Any]) -> list[Package]:
    """Parse a Grype JSON report (``grype --output json``) into Package objects.

    Each match contains a vulnerability + artifact pair.  Packages are grouped
    by name+version+ecosystem.  CVSS score is extracted from the first element
    of ``vulnerability.cvss[].metrics.baseScore``.  Fixed version is taken from
    ``vulnerability.fix.versions[0]`` when ``fix.state == "fixed"``.
    """
    matches: list[dict] = data.get("matches") or []
    pkg_map: dict[tuple[str, str, str], Package] = {}

    for match in matches:
        artifact: dict = match.get("artifact") or {}
        vuln_data: dict = match.get("vulnerability") or {}

        pkg_name = artifact.get("name", "")
        pkg_version = artifact.get("version", "")
        raw_type = artifact.get("type", "")
        ecosystem = _GRYPE_ECOSYSTEM_MAP.get(raw_type, raw_type.lower() if raw_type else "unknown")

        if not pkg_name:
            continue

        key = (pkg_name, pkg_version, ecosystem)
        if key not in pkg_map:
            pkg_map[key] = Package(name=pkg_name, version=pkg_version, ecosystem=ecosystem)

        pkg = pkg_map[key]

        # Extract CVSS score from first cvss entry
        cvss_list: list[dict] = vuln_data.get("cvss") or []
        cvss_score: float | None = None
        if cvss_list:
            try:
                cvss_score = float(cvss_list[0].get("metrics", {}).get("baseScore", 0) or 0) or None
            except (TypeError, ValueError):
                cvss_score = None

        # Extract fixed version
        fix_block: dict = vuln_data.get("fix") or {}
        fixed_version: str | None = None
        if fix_block.get("state") == "fixed":
            fix_versions: list[str] = fix_block.get("versions") or []
            fixed_version = fix_versions[0] if fix_versions else None

        references: list[str] = vuln_data.get("urls") or []
        vuln_id = vuln_data.get("id", "")
        related_aliases = _grype_related_aliases(vuln_data)
        advisory_source = _grype_advisory_source(vuln_data)

        vuln_obj = Vulnerability(
            id=vuln_id,
            summary=vuln_data.get("description") or "",
            severity=_map_severity(vuln_data.get("severity", "")),
            severity_source=vuln_data.get("namespace") or None,
            cvss_score=cvss_score,
            fixed_version=fixed_version,
            references=list(references),
            published_at=vuln_data.get("publishedDate") or vuln_data.get("published") or None,
            modified_at=vuln_data.get("modifiedDate") or vuln_data.get("modified") or None,
            aliases=_aliases(vuln_id, vuln_data.get("aliases"), related_aliases),
            cwe_ids=_cwe_ids(vuln_data.get("cwes")),
            advisory_sources=[advisory_source] if advisory_source else [],
        )
        vuln_obj.confidence = compute_confidence(vuln_obj)
        existing_ids = {v.id for v in pkg.vulnerabilities}
        if vuln_obj.id not in existing_ids:
            pkg.vulnerabilities.append(vuln_obj)

    return list(pkg_map.values())


# ── Syft parser ───────────────────────────────────────────────────────────────


def parse_syft_json(data: dict[str, Any]) -> list[Package]:
    """Parse a Syft SBOM JSON report (``syft --output syft-json``) into Package objects.

    Syft produces an inventory only — no vulnerability data is attached.
    Callers can subsequently run an OSV scan on the returned packages.
    License is extracted from ``licenses[0].value`` if present.
    Author and description are extracted from ``metadata``.
    """
    artifacts: list[dict] = data.get("artifacts") or []
    packages: list[Package] = []

    for artifact in artifacts:
        pkg_name = artifact.get("name", "")
        pkg_version = artifact.get("version", "")
        raw_type = artifact.get("type", "")
        ecosystem = _SYFT_ECOSYSTEM_MAP.get(raw_type, raw_type.lower() if raw_type else "unknown")

        if not pkg_name:
            continue

        # License: first entry in the licenses list
        licenses_list: list[dict] = artifact.get("licenses") or []
        license_value: str | None = None
        if licenses_list:
            license_value = licenses_list[0].get("value") or None

        # Author / description from metadata block
        metadata: dict = artifact.get("metadata") or {}
        author: str | None = metadata.get("author") or None
        description: str | None = metadata.get("summary") or None

        pkg = Package(
            name=pkg_name,
            version=pkg_version,
            ecosystem=ecosystem,
            license=license_value,
            author=author,
            description=description,
        )
        packages.append(pkg)

    return packages


# ── Auto-detect ───────────────────────────────────────────────────────────────


def is_sarif_document(data: dict[str, Any]) -> bool:
    """Return True when *data* looks like a SARIF 2.x document."""
    if not isinstance(data, dict):
        return False
    runs = data.get("runs")
    if not isinstance(runs, list):
        return False
    version = str(data.get("version") or "")
    if version.startswith("2."):
        return True
    schema = data.get("$schema")
    return isinstance(schema, str) and "sarif" in schema.lower()


def _severity_from_label(label: str) -> Severity:
    try:
        return Severity(label.lower())
    except ValueError:
        return Severity.UNKNOWN


def _sarif_hub_findings_to_packages(findings: list["Finding"]) -> list[Package]:
    """Group hub-classified SARIF findings into synthetic sast packages."""
    from agent_bom.finding import Finding

    file_findings: dict[str, list[Finding]] = {}
    for item in findings:
        if not isinstance(item, Finding):
            continue
        file_path = item.asset.location or item.asset.name.split(":", 1)[0]
        file_findings.setdefault(file_path or "unknown", []).append(item)

    packages: list[Package] = []
    for file_path, rows in file_findings.items():
        vulns: list[Vulnerability] = []
        seen: set[str] = set()
        for finding in rows:
            evidence = finding.evidence or {}
            rule_id = str(evidence.get("rule_id") or finding.title or "sarif-rule")
            line_token = ""
            if finding.asset.name and ":" in finding.asset.name:
                line_token = finding.asset.name.rsplit(":", 1)[-1]
            dedup_key = f"{rule_id}:{line_token}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            vulns.append(
                Vulnerability(
                    id=rule_id,
                    summary=finding.description or finding.title,
                    severity=_severity_from_label(finding.severity),
                    cwe_ids=list(finding.cwe_ids),
                    cvss_score=finding.cvss_score,
                    references=[],
                )
            )
        if vulns:
            tool_name = str((rows[0].evidence or {}).get("external_tool") or "sarif")
            packages.append(
                Package(
                    name=file_path,
                    version="0.0.0",
                    ecosystem="sast",
                    vulnerabilities=vulns,
                    description=f"SARIF findings from {tool_name}",
                )
            )
    return packages


def parse_sarif_json(data: dict[str, Any]) -> list[Package]:
    """Parse a SARIF 2.x document into synthetic per-file sast packages."""
    from agent_bom.compliance_hub_ingest import parse_sarif_document

    if not is_sarif_document(data):
        raise ValueError("payload is not a SARIF document")
    findings = parse_sarif_document(data)
    return _sarif_hub_findings_to_packages(findings)


# ── Structured import (scan path) ─────────────────────────────────────────

# Formats ``ingest_external_report`` parses directly (the ``format`` it records).
# Prowler, Security Hub and plugin importers are listed by the importer registry.
BUILTIN_REPORT_FORMATS: tuple[str, ...] = ("sarif", "cyclonedx", "spdx", "trivy", "grype", "syft")

SUPPORTED_FORMATS_HINT = (
    "SARIF 2.x, CycloneDX JSON, SPDX JSON, Trivy JSON, Grype JSON, Syft JSON, Prowler JSON-OCSF, or AWS Security Hub ASFF"
)

# Advisory identifiers that mark a SARIF result as a dependency (SCA) result
# rather than a code-level rule hit.
_ADVISORY_ID_RE = re.compile(
    r"\b(CVE-\d{4}-\d{4,}|GHSA(?:-[0-9a-z]{4}){3}|PYSEC-\d{4}-\d+|RUSTSEC-\d{4}-\d{4}|GO-\d{4}-\d{4,}"
    r"|OSV-\d{4}-\d+|GMS-\d{4}-\d+|MAL-\d{4}-\d+)\b",
    re.IGNORECASE,
)
_PURL_RE = re.compile(r"pkg:[A-Za-z0-9.+-]+/[^\s\"'<>]+@[^\s\"'<>?#]+")
_MESSAGE_PACKAGE_RE = re.compile(r"(?im)^\s*(?:package|package name|pkgname)\s*:\s*(\S+)\s*$")
_MESSAGE_VERSION_RE = re.compile(r"(?im)^\s*(?:installed version|current version|version)\s*:\s*(\S+)\s*$")
_MESSAGE_FIXED_RE = re.compile(r"(?im)^\s*fixed version\s*:\s*(\S+)\s*$")
_NAME_AT_VERSION_RE = re.compile(r"^(@?[A-Za-z0-9][\w.\-/]*)@(v?\d[\w.\-+]*)$")
_CWE_RE = re.compile(r"\bCWE-(\d+)\b", re.IGNORECASE)

_PACKAGE_NAME_KEYS = ("packageName", "package_name", "pkgName", "package", "componentName", "dependency")
_PACKAGE_VERSION_KEYS = ("packageVersion", "package_version", "installedVersion", "installed_version", "pkgVersion", "version")
_PURL_KEYS = ("purl", "packageUrl", "package_url", "purls")
_FIXED_VERSION_KEYS = ("fixedVersion", "fixed_version", "fixVersion")

_MANIFEST_ECOSYSTEMS: dict[str, str] = {
    "requirements.txt": "pypi",
    "pyproject.toml": "pypi",
    "poetry.lock": "pypi",
    "pipfile": "pypi",
    "pipfile.lock": "pypi",
    "uv.lock": "pypi",
    "setup.py": "pypi",
    "setup.cfg": "pypi",
    "package.json": "npm",
    "package-lock.json": "npm",
    "npm-shrinkwrap.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    "go.mod": "go",
    "go.sum": "go",
    "cargo.toml": "cargo",
    "cargo.lock": "cargo",
    "pom.xml": "maven",
    "build.gradle": "maven",
    "build.gradle.kts": "maven",
    "gradle.lockfile": "maven",
    "gemfile": "rubygems",
    "gemfile.lock": "rubygems",
    "composer.json": "composer",
    "composer.lock": "composer",
    "packages.lock.json": "nuget",
}


def external_source_label(tool_name: str | None) -> str:
    """Return the provenance label for evidence produced by an external tool."""
    from agent_bom.finding import EXTERNAL_SOURCE_PREFIX
    from agent_bom.security import sanitize_text

    tool = sanitize_text(tool_name or "", max_len=80).strip()
    return f"{EXTERNAL_SOURCE_PREFIX}{tool}" if tool else "external"


def manifest_ecosystem(uri: str | None) -> str:
    """Return the package ecosystem implied by a manifest/lockfile path, or ``""``."""
    if not uri:
        return ""
    return _MANIFEST_ECOSYSTEMS.get(PurePosixPath(uri.replace("\\", "/")).name.lower(), "")


def _purl_coordinates(purl: str) -> tuple[str, str, str] | None:
    from agent_bom.intel_lookup import parse_purl
    from agent_bom.sbom import _ecosystem_from_purl

    try:
        parsed = parse_purl(purl)
    except ValueError:
        return None
    if not parsed.get("name"):
        return None
    return parsed["name"], parsed.get("version", ""), _ecosystem_from_purl(purl)


def _first_string(mapping: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, list):
            value = next((item for item in value if isinstance(item, str) and item), None)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _sarif_package_identity(result: "NormalizedSarifResult") -> tuple[str, str, str, str]:
    """Return ``(name, version, ecosystem, fixed_version)`` for a dependency result.

    Sources, strongest first: an explicit purl (result properties, logical
    locations, message), explicit package properties, ``name@version`` logical
    locations, then ``Package:`` / ``Installed Version:`` message lines.
    """
    props = result.result_properties or {}
    message = result.message or ""
    fixed = _first_string(props, _FIXED_VERSION_KEYS)
    fixed_match = _MESSAGE_FIXED_RE.search(message)
    if not fixed and fixed_match:
        fixed = fixed_match.group(1)
    location_eco = manifest_ecosystem(result.location.uri if result.location else None)

    purl_candidates = [_first_string(props, _PURL_KEYS), *result.logical_locations, *_PURL_RE.findall(message)]
    for candidate in purl_candidates:
        if candidate.startswith("pkg:"):
            coords = _purl_coordinates(candidate)
            if coords:
                name, version, eco = coords
                return name, version, eco or location_eco, fixed

    name = _first_string(props, _PACKAGE_NAME_KEYS)
    version = _first_string(props, _PACKAGE_VERSION_KEYS)
    if not name:
        for logical in result.logical_locations:
            match = _NAME_AT_VERSION_RE.match(logical.strip())
            if match:
                name, version = match.group(1), version or match.group(2)
                break
    if not name:
        name_match = _MESSAGE_PACKAGE_RE.search(message)
        if name_match:
            name = name_match.group(1)
    if name and not version:
        version_match = _MESSAGE_VERSION_RE.search(message)
        if version_match:
            version = version_match.group(1)
    return name, version, location_eco if name else "", fixed


def _sarif_advisory_id(result: "NormalizedSarifResult") -> str | None:
    match = _ADVISORY_ID_RE.fullmatch(result.rule_id.strip()) if result.rule_id else None
    if match is None:
        return None
    advisory_id = match.group(1)
    return advisory_id if advisory_id.upper().startswith("GHSA") else advisory_id.upper()


def normalized_cwe_ids(tags: tuple[str, ...] | list[str]) -> list[str]:
    """Extract ``CWE-<n>`` identifiers from free-form rule tags (``"CWE-78: OS …"``)."""
    cwes: list[str] = []
    for tag in tags:
        for number in _CWE_RE.findall(str(tag)):
            cwe = f"CWE-{int(number)}"
            if cwe not in cwes:
                cwes.append(cwe)
    return cwes


def _sarif_dependency_vulnerability(result: "NormalizedSarifResult", advisory_id: str, fixed: str) -> Vulnerability:
    from agent_bom.compliance_hub_ingest import _coerce_severity

    summary = result.rule_short_description or result.message or advisory_id
    aliases = [alias for alias in dict.fromkeys(m.upper() for m in _ADVISORY_ID_RE.findall(result.message or "")) if alias != advisory_id]
    vuln = Vulnerability(
        id=advisory_id,
        summary=summary[:500],
        severity=_severity_from_label(_coerce_severity(result.level, result.security_severity)),
        cvss_score=result.security_severity,
        fixed_version=fixed or None,
        references=[result.rule_url] if result.rule_url else [],
        aliases=aliases,
        cwe_ids=normalized_cwe_ids(result.rule_tags),
        advisory_sources=[external_source_label(result.tool_name)],
    )
    vuln.confidence = compute_confidence(vuln)
    return vuln


def _sarif_result_finding(result: "NormalizedSarifResult", *, dependency_id: str | None) -> "Finding":
    """Build an EXTERNAL finding for a code result or an unresolved dependency result."""
    from agent_bom.compliance_hub import apply_hub_classification
    from agent_bom.compliance_hub_ingest import _coerce_severity
    from agent_bom.finding import Asset, Finding, FindingSource, FindingType, stable_id

    location = result.location
    file_path = location.uri if location else None
    line = location.start_line if location and location.start_line else None
    evidence: dict[str, Any] = {
        "external_tool": result.tool_name,
        "rule_id": result.rule_id,
        "rule_tags": list(result.rule_tags),
        "sarif_level": result.level,
        "file": file_path,
        "line": line,
    }
    if result.security_severity is not None:
        evidence["sarif_security_severity"] = result.security_severity
    if result.partial_fingerprints:
        evidence["sarif_partial_fingerprints"] = dict(result.partial_fingerprints)
    location_label = f"{file_path}:{line}" if file_path and line else (file_path or "unknown location")
    if dependency_id:
        finding_type = FindingType.CVE
        evidence["package_resolution"] = "unresolved"
        title = f"{dependency_id}: unresolved package in {location_label}"
        asset_type = "manifest_file" if manifest_ecosystem(file_path) else "file"
    else:
        finding_type = FindingType.SAST
        title = result.rule_short_description or result.rule_id or (result.message or "External finding")[:100]
        asset_type = "source_file"
    finding = Finding(
        finding_type=finding_type,
        source=FindingSource.EXTERNAL,
        asset=Asset(
            name=location_label,
            asset_type=asset_type if file_path else "external",
            identifier=file_path or result.rule_id or None,
            location=file_path,
        ),
        severity=_coerce_severity(result.level, result.security_severity),
        title=title,
        description=result.message or result.rule_full_description or result.rule_short_description or result.rule_id,
        cve_id=dependency_id,
        cwe_ids=normalized_cwe_ids(result.rule_tags),
        cvss_score=result.security_severity,
        evidence=evidence,
        sources=[external_source_label(result.tool_name)],
        id=stable_id("sarif", result.tool_name, result.rule_id, file_path or "", str(line or ""), result.message),
    )
    return apply_hub_classification(finding)


def _ingest_sarif(data: dict[str, Any]) -> ExternalScanImport:
    from agent_bom.package_utils import canonical_package_key
    from agent_bom.parsers.sarif import SarifValidationError, normalize_sarif_document

    try:
        document = normalize_sarif_document(data)
    except SarifValidationError as exc:
        raise ValueError(f"invalid SARIF document: {exc}") from exc

    imported = ExternalScanImport(format="sarif", tool_names=list(document.tool_names))
    packages: dict[tuple[str, str], Package] = {}
    for result in document.results:
        advisory_id = _sarif_advisory_id(result)
        if advisory_id is None:
            imported.findings.append(_sarif_result_finding(result, dependency_id=None))
            continue
        name, version, ecosystem, fixed = _sarif_package_identity(result)
        if not name or not ecosystem:
            imported.findings.append(_sarif_result_finding(result, dependency_id=advisory_id))
            continue
        manifest = result.location.uri if result.location and manifest_ecosystem(result.location.uri) else ""
        key = (canonical_package_key(name, version, ecosystem), "" if version else manifest)
        pkg = packages.get(key)
        if pkg is None:
            pkg = Package(name=name, version=version, ecosystem=ecosystem, version_source="external_report")
            if manifest:
                pkg.version_evidence.append(
                    {
                        "type": "external_report",
                        "source_file": manifest,
                        "line": result.location.start_line if result.location else 0,
                        "tool": result.tool_name,
                    }
                )
            packages[key] = pkg
        if any(existing.id == advisory_id for existing in pkg.vulnerabilities):
            continue
        pkg.vulnerabilities.append(_sarif_dependency_vulnerability(result, advisory_id, fixed))
    imported.packages = list(packages.values())
    unresolved = [f.cve_id for f in imported.findings if f.cve_id]
    if unresolved:
        imported.notices.append(
            f"{len(unresolved)} SARIF dependency result(s) named no package identity ({', '.join(unresolved[:5])}"
            f"{', …' if len(unresolved) > 5 else ''}); kept as unresolved external findings, not attached to any package."
        )
    return imported


def _sbom_tool_names(data: dict[str, Any]) -> list[str]:
    names: list[str] = []
    metadata = data.get("metadata")
    tools: Any = metadata.get("tools") if isinstance(metadata, dict) else None
    if isinstance(tools, dict):
        tools = tools.get("components")
    for tool in tools if isinstance(tools, list) else []:
        if isinstance(tool, dict) and isinstance(tool.get("name"), str):
            names.append(tool["name"].strip())
    creation = data.get("creationInfo")
    creators = creation.get("creators") if isinstance(creation, dict) else None
    for creator in creators if isinstance(creators, list) else []:
        if isinstance(creator, str) and creator.startswith("Tool:"):
            names.append(creator.split(":", 1)[1].strip())
    return list(dict.fromkeys(name for name in names if name))


def _label_packages(packages: list[Package], label: str) -> list[Package]:
    for pkg in packages:
        for vuln in pkg.vulnerabilities:
            if label not in vuln.advisory_sources:
                vuln.advisory_sources = [*vuln.advisory_sources, label]
    return packages


def _ingest_sbom(data: dict[str, Any]) -> ExternalScanImport:
    from agent_bom.sbom import parse_sbom_document

    packages, _format_name, _resource = parse_sbom_document(data, source_name="external scan report")
    fmt = "cyclonedx" if data.get("bomFormat") == "CycloneDX" else "spdx"
    tool_names = _sbom_tool_names(data)
    _label_packages(packages, external_source_label(tool_names[0] if tool_names else fmt))
    has_vulns = any(pkg.vulnerabilities for pkg in packages)
    imported = ExternalScanImport(format=fmt, packages=packages, tool_names=tool_names, is_sbom=not has_vulns)
    if not has_vulns:
        display = "CycloneDX" if fmt == "cyclonedx" else "SPDX"
        imported.notices.append(
            f"--external-scan input is a {display} SBOM without vulnerability data; ingested it as an SBOM "
            "inventory (same as --sbom <file>) and scanned its packages for vulnerabilities."
        )
    return imported


def ingest_external_report(data: dict[str, Any] | list[Any]) -> ExternalScanImport:
    """Parse any supported external report into packages plus findings.

    SARIF results are routed by rule type: advisory-id rules (CVE/GHSA/…)
    become dependency evidence on the real ``package@version`` the result
    names; every other rule stays a code-level finding with file + line.
    CycloneDX/SPDX documents go through the canonical SBOM parser. Any other
    shape (including a top-level list) goes to the importer registry
    (:mod:`agent_bom.parsers.importers`): Prowler, Security Hub, plugins.

    Raises:
        ValueError: if the format cannot be identified.
    """
    if not isinstance(data, dict):
        return import_registered_report(data, supported_hint=SUPPORTED_FORMATS_HINT)
    if is_sarif_document(data):
        return _ingest_sarif(data)
    if data.get("bomFormat") == "CycloneDX" or str(data.get("spdxVersion") or "").startswith("SPDX-"):
        return _ingest_sbom(data)
    # Trivy format: Results may be empty; presence of the list is enough.
    if isinstance(data.get("Results"), list):
        return ExternalScanImport(format="trivy", packages=_label_packages(parse_trivy_json(data), external_source_label("trivy")))
    if "matches" in data:
        return ExternalScanImport(format="grype", packages=_label_packages(parse_grype_json(data), external_source_label("grype")))
    if "artifacts" in data and "schema" in data:
        return ExternalScanImport(format="syft", packages=parse_syft_json(data), is_sbom=True)
    return import_registered_report(data, supported_hint=SUPPORTED_FORMATS_HINT)


def load_external_report(path: str | Path) -> ExternalScanImport:
    """Read a report with the shared parser size limit, then ingest it."""
    return ingest_external_report(read_json_limited(Path(path)))


def detect_and_parse(data: dict[str, Any]) -> list[Package]:
    """Auto-detect the scanner JSON format and parse into Package objects.

    Package-only view of :func:`ingest_external_report` for callers that do
    not carry findings. SARIF dependency results resolve to real packages;
    code results and unresolvable dependency results keep the per-file
    ``sast`` projection so no result is silently dropped.

    Raises:
        ValueError: if the format cannot be identified.
    """
    imported = ingest_external_report(data)
    if imported.format != "sarif":
        return imported.packages
    return [*imported.packages, *_sarif_hub_findings_to_packages(imported.findings)]
