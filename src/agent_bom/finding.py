"""Unified Finding model — single stream for all finding types.

Phase 1 (issue #566): core dataclasses + BlastRadius migration shim.
Later phases will add cloud CIS, proxy alerts, SAST, and skill findings.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

# Stable namespace for agent-bom deterministic UUIDs
# Using a fixed UUID so IDs are reproducible across machines and versions
_AGENT_BOM_NS = uuid.UUID("7f3e4b2a-9c1d-5f8e-a0b4-12c3d4e5f6a7")


def _stable_id(*parts: str) -> str:
    """Compute a deterministic UUID v5 from content parts.

    Same inputs always produce the same UUID. Use this for asset IDs
    and finding IDs so the same entity is tracked consistently across scans.
    """
    fingerprint = ":".join(p.lower().strip() for p in parts if p)
    return str(uuid.uuid5(_AGENT_BOM_NS, fingerprint))


def stable_id(*parts: str) -> str:
    """Public alias for _stable_id — importable for use across modules."""
    return _stable_id(*parts)


class FindingType(str, Enum):
    """What category of issue this finding represents."""

    CVE = "CVE"  # Software vulnerability (from OSV/GHSA/NVIDIA)
    CIS_FAIL = "CIS_FAIL"  # CIS benchmark control failure
    CREDENTIAL_EXPOSURE = "CREDENTIAL_EXPOSURE"  # Credential found in environment/config
    TOOL_DRIFT = "TOOL_DRIFT"  # MCP tool description changed (rug pull)
    INJECTION = "INJECTION"  # Prompt/argument injection in MCP tool
    EXFILTRATION = "EXFILTRATION"  # Data exfiltration pattern detected by proxy
    CLOAKING = "CLOAKING"  # Invisible chars / SVG cloaking in response
    SAST = "SAST"  # Static analysis finding (CWE-mapped)
    SKILL_RISK = "SKILL_RISK"  # Behavioral risk in AI skill file
    BROWSER_EXT = "BROWSER_EXT"  # Suspicious browser extension
    LICENSE = "LICENSE"  # License compliance violation
    RATE_LIMIT = "RATE_LIMIT"  # Rate limit abuse by MCP tool


class FindingSource(str, Enum):
    """Which scanner or subsystem produced this finding."""

    MCP_SCAN = "MCP_SCAN"  # agent discovery + CVE scanner
    CONTAINER = "CONTAINER"  # container image scan (Syft/Grype/Trivy ingestion)
    SBOM = "SBOM"  # SBOM ingest (CycloneDX / SPDX)
    CLOUD_CIS = "CLOUD_CIS"  # cloud CIS benchmark (AWS/Azure/GCP/Snowflake)
    PROXY = "PROXY"  # runtime proxy detector
    SAST = "SAST"  # static analysis (Semgrep)
    SKILL = "SKILL"  # skill file auditor
    BROWSER_EXT = "BROWSER_EXT"  # browser extension scanner
    EXTERNAL = "EXTERNAL"  # ingested from external scanner (Trivy/Grype/Syft JSON)
    FILESYSTEM = "FILESYSTEM"  # filesystem mount scan


@dataclass
class Asset:
    """What is affected by this finding."""

    name: str  # human-readable name (server name, package name, cloud resource ID)
    asset_type: str  # "mcp_server" | "package" | "container" | "cloud_resource" | "agent"
    identifier: Optional[str] = None  # purl, ARN, image digest, etc.
    location: Optional[str] = None  # file path, URL, cloud region

    @property
    def stable_id(self) -> str:
        """Deterministic UUID derived from asset content.

        Same asset type + identifier always produces the same ID across scans.
        This enables tracking: first seen, last seen, resolved, re-emerged.
        """
        identifier = self.identifier or f"{self.name}:{self.location or ''}"
        return _stable_id(self.asset_type, identifier)


@dataclass
class Finding:
    """Unified finding — one model for all issue types across all sources.

    Phase 1 covers CVE findings (migrated from BlastRadius).
    Phase 2 will add cloud CIS, proxy, SAST, skill findings.
    """

    # Core identity
    finding_type: FindingType
    source: FindingSource
    asset: Asset
    severity: str  # mirrors Severity enum value; str for forward-compat

    # Vendor severity (from source scanner) vs normalised CVSS severity
    vendor_severity: Optional[str] = None  # severity as reported by vendor/scanner
    cvss_severity: Optional[str] = None  # normalised from CVSS base score

    # Finding content
    title: str = ""
    description: str = ""
    cve_id: Optional[str] = None  # e.g. "CVE-2024-1234"
    cwe_ids: list[str] = field(default_factory=list)  # e.g. ["CWE-79"]
    cvss_score: Optional[float] = None
    epss_score: Optional[float] = None
    is_kev: bool = False  # CISA Known Exploited Vulnerability

    # Remediation
    fixed_version: Optional[str] = None
    remediation_guidance: Optional[str] = None

    # Compliance mappings (same tags as BlastRadius for parity)
    compliance_tags: list[str] = field(default_factory=list)  # all framework tags combined
    owasp_tags: list[str] = field(default_factory=list)
    atlas_tags: list[str] = field(default_factory=list)
    attack_tags: list[str] = field(default_factory=list)
    nist_ai_rmf_tags: list[str] = field(default_factory=list)
    owasp_mcp_tags: list[str] = field(default_factory=list)
    owasp_agentic_tags: list[str] = field(default_factory=list)
    eu_ai_act_tags: list[str] = field(default_factory=list)
    nist_csf_tags: list[str] = field(default_factory=list)
    iso_27001_tags: list[str] = field(default_factory=list)
    soc2_tags: list[str] = field(default_factory=list)
    cis_tags: list[str] = field(default_factory=list)

    # Graph / correlation
    related_findings: list[str] = field(default_factory=list)  # IDs of related findings
    evidence: dict = field(default_factory=dict)  # raw evidence payload

    # Risk
    risk_score: float = 0.0  # 0-10 unified risk score

    # Unique ID — deterministic UUID v5 based on content (computed in __post_init__)
    # Pass an explicit id= to override (e.g. when ingesting from external scanner)
    id: str = field(default="")

    def __post_init__(self) -> None:
        """Compute stable ID from finding content if not explicitly set."""
        if not self.id:
            # Deterministic ID: same CVE on same asset always same ID
            cve_part = self.cve_id or self.title
            pkg_name = ""
            pkg_version = ""
            if self.asset.asset_type == "package" and self.asset.identifier:
                # purl like "pkg:pypi/torch@2.3.0" — extract name/version
                purl = self.asset.identifier
                pkg_part = purl.split("/")[-1] if "/" in purl else purl
                if "@" in pkg_part:
                    pkg_name, pkg_version = pkg_part.rsplit("@", 1)
            self.id = _stable_id(
                self.asset.stable_id,
                cve_part,
                pkg_name,
                pkg_version,
            )

    def all_compliance_tags(self) -> list[str]:
        """Return deduplicated union of all compliance tag lists."""
        seen: set[str] = set()
        result: list[str] = []
        for tag in (
            self.compliance_tags
            + self.owasp_tags
            + self.atlas_tags
            + self.attack_tags
            + self.nist_ai_rmf_tags
            + self.owasp_mcp_tags
            + self.owasp_agentic_tags
            + self.eu_ai_act_tags
            + self.nist_csf_tags
            + self.iso_27001_tags
            + self.soc2_tags
            + self.cis_tags
        ):
            if tag not in seen:
                seen.add(tag)
                result.append(tag)
        return result

    def effective_severity(self) -> str:
        """Return the best severity value: vendor > cvss > base severity."""
        return self.vendor_severity or self.cvss_severity or self.severity


def blast_radius_to_finding(br: object) -> "Finding":
    """Convert a BlastRadius instance to a unified Finding.

    This is the Phase 1 migration shim. BlastRadius objects remain the primary
    output format; this produces a parallel Finding for the unified stream.
    """
    from agent_bom.models import BlastRadius  # local import to avoid circular deps

    if not isinstance(br, BlastRadius):
        raise TypeError(f"Expected BlastRadius, got {type(br)}")

    vuln = br.vulnerability
    pkg = br.package

    # Asset: primary server or package
    if br.affected_servers:
        primary_server = br.affected_servers[0]
        asset = Asset(
            name=primary_server.name,
            asset_type="mcp_server",
            identifier=None,
            location=primary_server.command or None,
        )
    else:
        asset = Asset(
            name=pkg.name,
            asset_type="package",
            identifier=f"pkg:{pkg.ecosystem}/{pkg.name}@{pkg.version}" if pkg.version else None,
        )

    # Collect evidence
    evidence: dict = {
        "package_name": pkg.name,
        "package_version": pkg.version,
        "ecosystem": pkg.ecosystem,
        "affected_server_count": len(br.affected_servers),
        "exposed_credential_count": len(br.exposed_credentials),
        "exposed_tool_count": len(br.exposed_tools),
    }
    if vuln.references:
        evidence["references"] = vuln.references[:5]

    sev = vuln.severity.value if hasattr(vuln.severity, "value") else str(vuln.severity)

    return Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.MCP_SCAN,
        asset=asset,
        severity=sev,
        vendor_severity=getattr(vuln, "vendor_severity", None),
        cvss_severity=getattr(vuln, "cvss_severity", None),
        title=f"{vuln.id}: {pkg.name}@{pkg.version or 'unknown'}",
        description=vuln.summary or "",
        cve_id=vuln.id,  # Vulnerability.id is the CVE/OSV ID
        cwe_ids=list(getattr(vuln, "cwe_ids", []) or []),
        cvss_score=vuln.cvss_score,
        epss_score=vuln.epss_score,
        is_kev=bool(vuln.is_kev),
        fixed_version=vuln.fixed_version,
        remediation_guidance=getattr(vuln, "remediation", None),
        owasp_tags=list(br.owasp_tags),
        atlas_tags=list(br.atlas_tags),
        attack_tags=list(br.attack_tags),
        nist_ai_rmf_tags=list(br.nist_ai_rmf_tags),
        owasp_mcp_tags=list(br.owasp_mcp_tags),
        owasp_agentic_tags=list(br.owasp_agentic_tags),
        eu_ai_act_tags=list(br.eu_ai_act_tags),
        nist_csf_tags=list(br.nist_csf_tags),
        iso_27001_tags=list(br.iso_27001_tags),
        soc2_tags=list(br.soc2_tags),
        cis_tags=list(br.cis_tags),
        evidence=evidence,
        risk_score=br.risk_score,
    )
