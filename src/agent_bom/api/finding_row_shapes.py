"""Finding row identity keys and builders for the legacy scan-result shapes.

A completed scan can describe one vulnerability in up to three shapes: the
unified finding stream, blast-radius entries and package vulnerabilities.
These helpers read identity consistently across all three and build list rows
from the two legacy shapes.
"""

from __future__ import annotations

from typing import Any

from agent_bom.api.models import ScanJob


def _scan_source_labels(job: ScanJob) -> list[str]:
    labels: list[str] = []
    req = job.request
    labels.extend(req.images)
    if req.inventory:
        labels.append("inventory")
    if req.k8s:
        labels.append("kubernetes")
    if req.sbom:
        labels.append("sbom-import")
    if req.external_scan:
        labels.append("external_scan")
    if req.repo_url and str(req.repo_url).strip():
        labels.append(str(req.repo_url).strip())
    labels.extend(req.connectors)
    labels.extend(req.filesystem_paths)
    labels.extend(req.agent_projects)
    return labels or ["local-agents"]


def _finding_key(finding: dict[str, Any]) -> str:
    vuln_id = finding.get("vulnerability_id") or finding.get("cve_id") or finding.get("id") or finding.get("title") or ""
    raw_asset = finding.get("asset")
    asset = raw_asset if isinstance(raw_asset, dict) else {}
    package = finding.get("package") or finding.get("package_name") or asset.get("name", "")
    return f"{vuln_id}:{package}"


def _row_vuln_id(finding: dict[str, Any]) -> str:
    """Return the CVE/advisory identifier for a finding, source-agnostic.

    The unified stream carries it under ``cve_id`` while the blast-radius and
    package-vulnerability representations carry the same value under
    ``vulnerability_id`` — normalizing here lets the three collapse together.
    """
    return str(finding.get("cve_id") or finding.get("vulnerability_id") or "").strip()


def _package_identity(finding: dict[str, Any]) -> tuple[str, str, str]:
    """Read package identity across unified, blast-radius and nested projections."""
    evidence = finding.get("evidence")
    evidence = evidence if isinstance(evidence, dict) else {}
    package = str(finding.get("package") or finding.get("package_name") or evidence.get("package_name") or "").strip()
    if not package:
        title = str(finding.get("title") or "")
        if ": " in title:
            package = title.split(": ", 1)[1].strip()
    version = str(finding.get("package_version") or evidence.get("package_version") or "").strip()
    # npm scoped names start with @; only a later @ separates the version.
    if "@" in package[1:]:
        package, suffix = package.rsplit("@", 1)
        version = version or suffix
    ecosystem = str(finding.get("ecosystem") or evidence.get("ecosystem") or "").strip().lower()
    return package.lower(), version, ecosystem


def _package_base_name(finding: dict[str, Any]) -> str:
    return _package_identity(finding)[0]


_EMPTY_FIELD_VALUES: tuple[Any, ...] = (None, "", [], {})

# Descriptive/structural fields safe to backfill from the supplementary
# (blast-radius / package-vulnerability) representations onto the authoritative
# unified finding. Reachability and VEX verdicts are deliberately excluded: the
# unified stream is the source of truth for those and must not be overridden by
# a coarser blast-radius projection (see the unified-stream-wins contract).
_SUPPLEMENTARY_BACKFILL_FIELDS: tuple[str, ...] = (
    "package",
    "package_name",
    "package_version",
    "ecosystem",
    "summary",
    "description",
    "cvss_score",
    "cvss_vector",
    "attack_vector",
    "attack_complexity",
    "privileges_required",
    "user_interaction",
    "network_exploitable",
    "references",
    "fixed_version",
    "epss_score",
    "upstream_ids",
    "epss_cve_id",
    "kev_cve_id",
    "affected_agents",
    "affected_servers",
    "exposed_credentials",
    "exposed_tools",
    "phantom_tools",
)


def _backfill_supplementary_fields(base: dict[str, Any], incoming: dict[str, Any]) -> None:
    """Fill only empty descriptive fields on ``base`` from ``incoming``.

    Never overrides a value the authoritative row already carries, so the
    unified finding's identifiers and reachability stay intact while
    package/CVE metadata from the supplementary representations is preserved.
    """
    for field in _SUPPLEMENTARY_BACKFILL_FIELDS:
        value = incoming.get(field)
        if value in _EMPTY_FIELD_VALUES:
            continue
        if base.get(field) in _EMPTY_FIELD_VALUES:
            base[field] = value


def _normalize_finding_identifiers(finding: dict[str, Any]) -> dict[str, Any]:
    """Guarantee every list row carries ``cve_id``/``title``/``finding_type``.

    Blast-radius and package-vulnerability rows carry the identifier only under
    ``vulnerability_id`` and omit ``title``/``finding_type``; normalize those so
    no row surfaces null identifiers regardless of which representation seeded it.
    """
    vuln = finding.get("cve_id") or finding.get("vulnerability_id")
    if vuln:
        if not finding.get("cve_id"):
            finding["cve_id"] = vuln
        if not finding.get("vulnerability_id"):
            finding["vulnerability_id"] = vuln
    if not finding.get("title"):
        package = finding.get("package") or finding.get("package_name") or ""
        # Never fall back to summary/description here: those are replay-only,
        # redacted-on-read fields, and the title is not redacted — deriving it
        # from them would leak sensitive free-text past _redact_finding_page.
        if vuln and package:
            finding["title"] = f"{vuln}: {package}"
        elif vuln:
            finding["title"] = str(vuln)
        elif package:
            finding["title"] = f"Vulnerability in {package}"
        else:
            finding["title"] = str(finding.get("finding_type") or "Finding")
    if not finding.get("finding_type"):
        finding["finding_type"] = "CVE" if vuln else "VULNERABILITY"
    return finding


def _iter_package_findings(job: ScanJob) -> list[dict[str, Any]]:
    result = job.result or {}
    findings: list[dict[str, Any]] = []
    scan_sources = _scan_source_labels(job)
    for agent in result.get("agents", []) or []:
        if not isinstance(agent, dict):
            continue
        agent_name = str(agent.get("name") or "")
        for server in agent.get("mcp_servers", []) or []:
            if not isinstance(server, dict):
                continue
            server_name = str(server.get("name") or "")
            for package in server.get("packages", []) or []:
                if not isinstance(package, dict):
                    continue
                package_name = str(package.get("name") or "")
                for vuln in package.get("vulnerabilities", []) or []:
                    if not isinstance(vuln, dict):
                        continue
                    vuln_id = str(vuln.get("id") or vuln.get("vulnerability_id") or "")
                    findings.append(
                        {
                            "id": vuln_id,
                            "vulnerability_id": vuln_id,
                            "package": package_name,
                            "package_version": package.get("version"),
                            "ecosystem": package.get("ecosystem"),
                            "severity": str(vuln.get("severity") or "unknown").lower(),
                            "summary": vuln.get("summary") or vuln.get("description"),
                            "source": "package_vulnerability",
                            "scan_id": str((job.result or {}).get("scan_id") or job.job_id),
                            "scan_sources": scan_sources,
                            "affected_agents": [agent_name] if agent_name else [],
                            "affected_servers": [server_name] if server_name else [],
                            "cvss_score": vuln.get("cvss_score"),
                            "cvss_vector": vuln.get("cvss_vector"),
                            "attack_vector": vuln.get("attack_vector"),
                            "attack_complexity": vuln.get("attack_complexity"),
                            "privileges_required": vuln.get("privileges_required"),
                            "user_interaction": vuln.get("user_interaction"),
                            "network_exploitable": bool(vuln.get("network_exploitable")),
                            "epss_score": vuln.get("epss_score"),
                            "upstream_ids": vuln.get("upstream_ids"),
                            "epss_cve_id": vuln.get("epss_cve_id"),
                            "kev_cve_id": vuln.get("kev_cve_id"),
                            "fixed_version": vuln.get("fixed_version"),
                            "is_kev": bool(vuln.get("is_kev")),
                            "references": vuln.get("references", []),
                        }
                    )
    return findings
