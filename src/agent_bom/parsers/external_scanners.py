"""Ingest Trivy, Grype, and Syft JSON reports into agent-bom models."""

from __future__ import annotations

import logging
from typing import Any

from agent_bom.models import Package, Severity, Vulnerability

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
        "none": Severity.NONE,
        "negligible": Severity.NONE,
        "unknown": Severity.NONE,
    }
    return mapping.get(raw.lower(), Severity.NONE)


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

            # Extract CVSS score
            cvss_block: dict = vuln.get("CVSS") or {}
            cvss_score: float | None = None
            for source in ("nvd", "ghsa"):
                score_val = cvss_block.get(source, {}).get("V3Score")
                if score_val is not None:
                    try:
                        cvss_score = float(score_val)
                    except (TypeError, ValueError):
                        pass
                    break

            references: list[str] = vuln.get("References") or []

            vuln_obj = Vulnerability(
                id=vuln.get("VulnerabilityID", ""),
                summary=vuln.get("Title") or vuln.get("Description") or "",
                severity=_map_severity(vuln.get("Severity", "")),
                cvss_score=cvss_score,
                fixed_version=vuln.get("FixedVersion") or None,
                references=list(references),
            )
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

        vuln_obj = Vulnerability(
            id=vuln_data.get("id", ""),
            summary=vuln_data.get("description") or "",
            severity=_map_severity(vuln_data.get("severity", "")),
            cvss_score=cvss_score,
            fixed_version=fixed_version,
            references=list(references),
        )
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


def detect_and_parse(data: dict[str, Any]) -> list[Package]:
    """Auto-detect the scanner JSON format and parse into Package objects.

    Detection rules (checked in order):
    - ``Results`` key present and at least one result has ``Vulnerabilities`` → Trivy
    - ``matches`` key present → Grype
    - ``artifacts`` key present and ``schema`` key present → Syft

    Raises:
        ValueError: if the format cannot be identified.
    """
    if "Results" in data:
        results = data["Results"]
        if isinstance(results, list):
            # Trivy format: Results may be empty; presence of the key is enough
            return parse_trivy_json(data)

    if "matches" in data:
        return parse_grype_json(data)

    if "artifacts" in data and "schema" in data:
        return parse_syft_json(data)

    raise ValueError("Unrecognized scanner JSON format")
