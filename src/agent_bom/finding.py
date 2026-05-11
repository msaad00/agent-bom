"""Unified Finding model — single stream for all finding types.

Phase 1 (issue #566): core dataclasses + BlastRadius migration shim.
Later phases will add cloud CIS, proxy alerts, SAST, and skill findings.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

# Stable namespace for agent-bom deterministic UUIDs
# Using a fixed UUID so IDs are reproducible across machines and versions
_AGENT_BOM_NS = uuid.UUID("7f3e4b2a-9c1d-5f8e-a0b4-12c3d4e5f6a7")
FINDING_SCHEMA_VERSION = "1"


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
    MCP_BLOCKLIST = "MCP_BLOCKLIST"  # Curated malicious/suspicious MCP server match


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


@dataclass(frozen=True)
class ControlTag:
    """Normalized framework control attached to a finding.

    Legacy finding payloads expose framework-specific arrays such as
    ``owasp_tags`` and ``soc2_tags``. ``ControlTag`` gives new consumers one
    structured list while those legacy arrays remain serialized for backward
    compatibility.
    """

    framework: str
    control: str
    version: Optional[str] = None
    confidence: Optional[float] = None
    source: Optional[str] = None
    via: Optional[str] = None

    def to_dict(self) -> dict[str, object]:
        return {
            "framework": self.framework,
            "control": self.control,
            "version": self.version,
            "confidence": self.confidence,
            "source": self.source,
            "via": self.via,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> "ControlTag":
        raw_confidence = payload.get("confidence")
        confidence: Optional[float] = None
        if isinstance(raw_confidence, (int, float, str)):
            try:
                confidence = float(raw_confidence)
            except ValueError:
                confidence = None
        raw_source = payload.get("source") or payload.get("via")
        raw_via = payload.get("via")

        return cls(
            framework=str(payload.get("framework") or ""),
            control=str(payload.get("control") or ""),
            version=str(payload["version"]) if payload.get("version") is not None else None,
            confidence=confidence,
            source=str(raw_source) if raw_source else None,
            via=str(raw_via) if raw_via else None,
        )


LEGACY_CONTROL_FIELDS: tuple[tuple[str, str], ...] = (
    ("compliance_tags", "generic"),
    ("owasp_tags", "owasp_llm"),
    ("atlas_tags", "mitre_atlas"),
    ("attack_tags", "mitre_attack"),
    ("nist_ai_rmf_tags", "nist_ai_rmf"),
    ("owasp_mcp_tags", "owasp_mcp"),
    ("owasp_agentic_tags", "owasp_agentic"),
    ("eu_ai_act_tags", "eu_ai_act"),
    ("nist_csf_tags", "nist_csf"),
    ("iso_27001_tags", "iso_27001"),
    ("soc2_tags", "soc2"),
    ("cis_tags", "cis"),
    ("cmmc_tags", "cmmc"),
    ("nist_800_53_tags", "nist_800_53"),
    ("fedramp_tags", "fedramp"),
    ("pci_dss_tags", "pci_dss"),
)

_LEGACY_CONTROL_VERSION_BY_FRAMEWORK: dict[str, str] = {
    "generic": "legacy",
    "owasp_llm": "2025",
    "mitre_atlas": "bundled",
    "mitre_attack": "enterprise-bundled",
    "nist_ai_rmf": "1.0",
    "owasp_mcp": "2025",
    "owasp_agentic": "2026",
    "eu_ai_act": "2024",
    "nist_csf": "2.0",
    "iso_27001": "2022",
    "soc2": "2017",
    "cis": "v8",
    "cmmc": "2.0",
    "nist_800_53": "rev5",
    "fedramp": "moderate",
    "pci_dss": "4.0",
}


def _dedupe_control_tags(tags: list[ControlTag]) -> list[ControlTag]:
    seen: set[tuple[str, str]] = set()
    out: list[ControlTag] = []
    for tag in tags:
        if not tag.framework or not tag.control:
            continue
        key = (tag.framework, tag.control)
        if key in seen:
            continue
        seen.add(key)
        out.append(tag)
    return out


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
    # Framework slugs that govern this finding (set by compliance_hub.apply_hub_classification).
    # Distinct from the per-framework `*_tags` fields below, which hold control codes.
    applicable_frameworks: list[str] = field(default_factory=list)
    controls: list[ControlTag] = field(default_factory=list)
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
    cmmc_tags: list[str] = field(default_factory=list)
    nist_800_53_tags: list[str] = field(default_factory=list)
    fedramp_tags: list[str] = field(default_factory=list)
    pci_dss_tags: list[str] = field(default_factory=list)

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
        self.controls = _dedupe_control_tags(
            [
                *(tag if isinstance(tag, ControlTag) else ControlTag.from_dict(tag) for tag in self.controls),
                *self._legacy_control_tags(),
            ]
        )
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

    def _legacy_control_tags(self) -> list[ControlTag]:
        """Return normalized controls derived from legacy tag arrays."""
        tags: list[ControlTag] = []
        for field_name, framework in LEGACY_CONTROL_FIELDS:
            values = getattr(self, field_name)
            for value in values:
                if value:
                    tags.append(
                        ControlTag(
                            framework=framework,
                            control=str(value),
                            version=_LEGACY_CONTROL_VERSION_BY_FRAMEWORK.get(framework, "legacy"),
                            confidence=0.75,
                            source=f"legacy:{field_name}",
                            via=field_name,
                        )
                    )
        return tags

    def normalized_controls(self) -> list[ControlTag]:
        """Return deduplicated structured controls for this finding."""
        return _dedupe_control_tags([*self.controls, *self._legacy_control_tags()])

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
            + self.cmmc_tags
            + self.nist_800_53_tags
            + self.fedramp_tags
            + self.pci_dss_tags
            + [tag.control for tag in self.normalized_controls()]
        ):
            if tag not in seen:
                seen.add(tag)
                result.append(tag)
        return result

    def effective_severity(self) -> str:
        """Return the best severity value: vendor > cvss > base severity."""
        return self.vendor_severity or self.cvss_severity or self.severity

    def to_dict(self) -> dict:
        """Return a JSON-serializable finding payload."""
        return {
            "schema_version": FINDING_SCHEMA_VERSION,
            "id": self.id,
            "finding_type": self.finding_type.value,
            "source": self.source.value,
            "asset": {
                "name": self.asset.name,
                "asset_type": self.asset.asset_type,
                "identifier": self.asset.identifier,
                "location": self.asset.location,
                "stable_id": self.asset.stable_id,
            },
            "severity": self.severity,
            "effective_severity": self.effective_severity(),
            "vendor_severity": self.vendor_severity,
            "cvss_severity": self.cvss_severity,
            "title": self.title,
            "description": self.description,
            "cve_id": self.cve_id,
            "cwe_ids": self.cwe_ids,
            "cvss_score": self.cvss_score,
            "epss_score": self.epss_score,
            "is_kev": self.is_kev,
            "fixed_version": self.fixed_version,
            "remediation_guidance": self.remediation_guidance,
            "compliance_tags": self.all_compliance_tags(),
            "applicable_frameworks": list(self.applicable_frameworks),
            "controls": [tag.to_dict() for tag in self.normalized_controls()],
            "owasp_tags": self.owasp_tags,
            "atlas_tags": self.atlas_tags,
            "attack_tags": self.attack_tags,
            "nist_ai_rmf_tags": self.nist_ai_rmf_tags,
            "owasp_mcp_tags": self.owasp_mcp_tags,
            "owasp_agentic_tags": self.owasp_agentic_tags,
            "eu_ai_act_tags": self.eu_ai_act_tags,
            "nist_csf_tags": self.nist_csf_tags,
            "iso_27001_tags": self.iso_27001_tags,
            "soc2_tags": self.soc2_tags,
            "cis_tags": self.cis_tags,
            "cmmc_tags": self.cmmc_tags,
            "nist_800_53_tags": self.nist_800_53_tags,
            "fedramp_tags": self.fedramp_tags,
            "pci_dss_tags": self.pci_dss_tags,
            "related_findings": self.related_findings,
            "evidence": self.evidence,
            "risk_score": self.risk_score,
        }


def _package_occurrence_evidence(occurrence: object) -> dict[str, object]:
    """Return layer/package provenance in a stable dict shape."""
    if hasattr(occurrence, "to_dict"):
        raw = occurrence.to_dict()
        if isinstance(raw, dict):
            return raw
    return {
        "layer_index": getattr(occurrence, "layer_index", None),
        "layer_id": getattr(occurrence, "layer_id", None),
        "layer_path": getattr(occurrence, "layer_path", None),
        "package_path": getattr(occurrence, "package_path", None),
        "created_by": getattr(occurrence, "created_by", None),
        "dockerfile_instruction": getattr(occurrence, "dockerfile_instruction", None),
    }


def _evidence_payload(value: object) -> object:
    """Normalize common model objects before recursive evidence sanitization."""
    if isinstance(value, dict):
        return {str(key): _evidence_payload(child) for key, child in value.items()}
    if isinstance(value, list | tuple | set):
        return [_evidence_payload(item) for item in value]
    if hasattr(value, "to_dict"):
        raw = value.to_dict()
        if isinstance(raw, dict):
            return _evidence_payload(raw)
    if hasattr(value, "name"):
        payload: dict[str, object] = {"name": getattr(value, "name", None)}
        for attr in ("version", "ecosystem", "hop", "id", "transport", "url", "command", "args"):
            if hasattr(value, attr):
                payload[attr] = getattr(value, attr)
        return payload
    return value


def _evidence_key_looks_sensitive(key: object | None) -> bool:
    if key is None:
        return False
    from agent_bom.security import SENSITIVE_PATTERNS

    return any(re.search(pattern, str(key).lower()) for pattern in SENSITIVE_PATTERNS)


def _evidence_key_looks_like_url(key: object | None) -> bool:
    if key is None:
        return False
    key_text = str(key).lower()
    return key_text in {"url", "uri", "endpoint", "webhook"} or key_text.endswith(("_url", "_uri", "_endpoint", "_webhook"))


def _evidence_key_looks_like_path(key: object | None) -> bool:
    if key is None:
        return False
    key_text = str(key).lower()
    return (
        "path" in key_text
        or key_text in {"cwd", "workspace", "dir", "directory"}
        or key_text.endswith(("_dir", "_directory", "_cwd", "_workspace"))
    )


def _sanitized_evidence_value(value: object, *, key: object | None = None, depth: int = 0) -> object:
    from agent_bom.security import sanitize_path_label, sanitize_sensitive_payload, sanitize_text, sanitize_url

    if depth >= 8:
        return "[truncated]"
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        if _evidence_key_looks_sensitive(key):
            return "***REDACTED***"
        if _evidence_key_looks_like_url(key):
            return sanitize_url(value)
        if _evidence_key_looks_like_path(key):
            return sanitize_path_label(value)
        return sanitize_text(value)
    if isinstance(value, dict):
        sanitized: dict[str, object] = {}
        for raw_key, raw_value in value.items():
            clean_key = sanitize_text(raw_key, max_len=200)
            sanitized[clean_key] = _sanitized_evidence_value(raw_value, key=clean_key, depth=depth + 1)
        return sanitized
    if isinstance(value, list | tuple | set):
        return [_sanitized_evidence_value(item, key=key, depth=depth + 1) for item in list(value)]
    return sanitize_sensitive_payload(value)


def _sanitized_evidence_field(value: object) -> object:
    return _sanitized_evidence_value(_evidence_payload(value))


def _source_for_blast_radius(br: object) -> FindingSource:
    """Derive finding source from the actual affected surface.

    Generic package/image/SBOM findings should not inherit MCP/AI framework
    applicability just because they flowed through the blast-radius shim.
    """
    surfaces = [getattr(server, "surface", None) for server in getattr(br, "affected_servers", []) or []]
    surface_values = {getattr(surface, "value", str(surface)) for surface in surfaces if surface is not None}
    if any(getattr(server, "is_mcp_surface", False) for server in getattr(br, "affected_servers", []) or []):
        return FindingSource.MCP_SCAN
    if {"container-image", "oci-tarball"} & surface_values:
        return FindingSource.CONTAINER
    if "filesystem" in surface_values:
        return FindingSource.FILESYSTEM
    if "external-scan" in surface_values:
        return FindingSource.EXTERNAL
    if "sast" in surface_values:
        return FindingSource.SAST
    if {"sbom", "os-packages"} & surface_values:
        return FindingSource.SBOM
    return FindingSource.SBOM


def blast_radius_to_finding(br: object) -> "Finding":
    """Convert a BlastRadius instance to a unified Finding.

    This is the Phase 1 migration shim. BlastRadius objects remain the primary
    output format; this produces a parallel Finding for the unified stream.
    """
    from agent_bom.models import BlastRadius  # local import to avoid circular deps

    if not isinstance(br, BlastRadius):
        raise TypeError(f"Expected BlastRadius, got {type(br)}")

    from agent_bom.asset_provenance import package_discovery_provenance, package_version_provenance

    vuln = br.vulnerability
    pkg = br.package

    # Asset: primary server or package
    if br.affected_servers:
        primary_server = br.affected_servers[0]
        from agent_bom.security import sanitize_launch_command

        asset = Asset(
            name=primary_server.name,
            asset_type="mcp_server",
            identifier=None,
            location=sanitize_launch_command(primary_server.command, primary_server.args) or None,
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
        "package_is_direct": pkg.is_direct,
        "package_parent": pkg.parent_package,
        "package_dependency_depth": pkg.dependency_depth,
        "package_dependency_scope": pkg.dependency_scope,
        "package_reachability_evidence": pkg.reachability_evidence,
        "affected_server_count": len(br.affected_servers),
        "exposed_credential_count": len(br.exposed_credentials),
        "exposed_tool_count": len(br.exposed_tools),
        "hop_depth": getattr(br, "hop_depth", 1),
        "delegation_chain": _sanitized_evidence_field(getattr(br, "delegation_chain", [])),
        "transitive_agents": _sanitized_evidence_field(getattr(br, "transitive_agents", [])),
        "transitive_servers": _sanitized_evidence_field(getattr(br, "transitive_servers", [])),
        "transitive_packages": _sanitized_evidence_field(getattr(br, "transitive_packages", [])),
        "transitive_credential_count": len(getattr(br, "transitive_credentials", []) or []),
        "transitive_risk_score": getattr(br, "transitive_risk_score", 0.0),
        "graph_reachable": getattr(br, "graph_reachable", None),
        "graph_min_hop_distance": getattr(br, "graph_min_hop_distance", None),
        "graph_reachable_from_agents": _sanitized_evidence_field(getattr(br, "graph_reachable_from_agents", [])),
        "layer_attribution": _sanitized_evidence_field([_package_occurrence_evidence(occ) for occ in br.layer_attribution]),
    }
    package_provenance = package_discovery_provenance(pkg)
    if package_provenance:
        evidence["package_discovery_provenance"] = package_provenance
    evidence["package_version_provenance"] = package_version_provenance(pkg)
    if vuln.references:
        evidence["references"] = _sanitized_evidence_field(vuln.references[:5])

    sev = vuln.severity.value if hasattr(vuln.severity, "value") else str(vuln.severity)

    from agent_bom.compliance_hub import apply_hub_classification

    finding = Finding(
        finding_type=FindingType.CVE,
        source=_source_for_blast_radius(br),
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
        cmmc_tags=list(getattr(br, "cmmc_tags", [])),
        nist_800_53_tags=list(getattr(br, "nist_800_53_tags", [])),
        fedramp_tags=list(getattr(br, "fedramp_tags", [])),
        pci_dss_tags=list(getattr(br, "pci_dss_tags", [])),
        evidence=evidence,
        risk_score=br.risk_score,
    )
    return apply_hub_classification(finding)
