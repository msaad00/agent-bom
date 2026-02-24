"""ClawHub-style trust assessment for SKILL.md files.

Evaluates skill files across 5 trust categories and produces an overall
verdict with confidence level and actionable recommendations.

Categories:
    1. Purpose & Capability — name/description, required binaries, network consistency
    2. Instruction Scope — file reads bounded, justification, data handling
    3. Install Mechanism — install methods, source, provenance/signing
    4. Credentials — proportionate, documented, scoped
    5. Persistence & Privilege — no persistence, no escalation, no telemetry

Usage:
    from agent_bom.parsers.trust_assessment import assess_trust
    result = assess_trust(scan_result, audit_result)
    print(result.verdict, result.confidence)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent_bom.parsers.skill_audit import SkillAuditResult
    from agent_bom.parsers.skills import SkillMetadata, SkillScanResult


# ── Enums ────────────────────────────────────────────────────────────────────


class TrustLevel(str, Enum):
    """Assessment status for each trust category."""

    PASS = "pass"
    INFO = "info"
    WARN = "warn"
    FAIL = "fail"


class Verdict(str, Enum):
    """Overall trust verdict."""

    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class Confidence(str, Enum):
    """Confidence level in the verdict."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# ── Data structures ──────────────────────────────────────────────────────────


@dataclass
class TrustCategoryResult:
    """Assessment result for a single trust category."""

    name: str
    key: str
    level: TrustLevel
    summary: str
    details: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)


@dataclass
class TrustAssessmentResult:
    """Complete trust assessment across all 5 categories."""

    categories: list[TrustCategoryResult] = field(default_factory=list)
    verdict: Verdict = Verdict.BENIGN
    confidence: Confidence = Confidence.LOW
    recommendations: list[str] = field(default_factory=list)
    skill_name: str = ""
    source_file: str = ""

    @property
    def worst_level(self) -> TrustLevel:
        """Return the worst trust level across all categories."""
        for level in (TrustLevel.FAIL, TrustLevel.WARN, TrustLevel.INFO, TrustLevel.PASS):
            if any(c.level == level for c in self.categories):
                return level
        return TrustLevel.PASS

    def to_dict(self) -> dict:
        """Serialize to a JSON-compatible dict."""
        return {
            "skill_name": self.skill_name,
            "source_file": self.source_file,
            "verdict": self.verdict.value,
            "confidence": self.confidence.value,
            "categories": [
                {
                    "name": c.name,
                    "key": c.key,
                    "level": c.level.value,
                    "summary": c.summary,
                    "details": c.details,
                    "evidence": c.evidence,
                }
                for c in self.categories
            ],
            "recommendations": self.recommendations,
        }


# ── Frontmatter helpers ─────────────────────────────────────────────────────


def _fm_has(raw: str, field_name: str) -> bool:
    """Check if a YAML field exists in raw frontmatter text."""
    return bool(re.search(rf"^\s*{re.escape(field_name)}\s*:", raw, re.MULTILINE))


def _fm_value(raw: str, field_name: str) -> str | None:
    """Extract a simple scalar value from raw frontmatter."""
    match = re.search(rf"^\s*{re.escape(field_name)}\s*:\s*(.+)$", raw, re.MULTILINE)
    return match.group(1).strip().strip("'\"") if match else None


def _fm_list(raw: str, field_name: str) -> list[str]:
    """Extract list items under a YAML field from raw frontmatter."""
    section = re.search(
        rf"^\s*{re.escape(field_name)}\s*:\s*\n((?:\s+-\s+.+\n?)+)", raw, re.MULTILINE
    )
    if not section:
        return []
    return re.findall(r"^\s+-\s+(.+)$", section.group(1), re.MULTILINE)


def _audit_has_category(audit: SkillAuditResult, *categories: str) -> bool:
    """Check if audit has any finding in the given categories."""
    return any(f.category in categories for f in audit.findings)


def _audit_findings_for(audit: SkillAuditResult, *categories: str) -> list:
    """Get findings matching given categories."""
    return [f for f in audit.findings if f.category in categories]


# ── Category assessors ───────────────────────────────────────────────────────


def _assess_purpose_capability(
    meta: SkillMetadata | None,
    scan: SkillScanResult,
    audit: SkillAuditResult,
) -> TrustCategoryResult:
    """Category 1: Purpose & Capability."""
    details: list[str] = []
    evidence: list[str] = []

    has_name = bool(meta and meta.name)
    has_desc = bool(meta and meta.description)
    has_bins = bool(meta and meta.required_bins)

    if has_name:
        details.append(f"Name declared: {meta.name}")
    if has_desc:
        details.append("Description provided")
    if has_bins:
        details.append(f"Required binaries: {', '.join(meta.required_bins)}")
        evidence.append(f"bins: {meta.required_bins}")

    # Check for undocumented shell/exec access
    shell_findings = _audit_findings_for(audit, "shell_access", "dangerous_tool")
    if shell_findings:
        details.append(f"{len(shell_findings)} shell/exec access pattern(s) detected")
        for f in shell_findings[:3]:
            evidence.append(f"{f.category}: {f.title}")

    # Check for undocumented network
    raw = (meta.raw_frontmatter if meta else "")
    has_network_docs = _fm_has(raw, "network_endpoints")

    if shell_findings:
        return TrustCategoryResult(
            name="Purpose & Capability",
            key="purpose_capability",
            level=TrustLevel.FAIL,
            summary="Shell/exec access detected — inconsistent with typical scanning tool",
            details=details,
            evidence=evidence,
        )

    if not has_name or not has_desc:
        return TrustCategoryResult(
            name="Purpose & Capability",
            key="purpose_capability",
            level=TrustLevel.WARN,
            summary="Missing name or description in metadata",
            details=details,
            evidence=evidence,
        )

    if not has_bins:
        return TrustCategoryResult(
            name="Purpose & Capability",
            key="purpose_capability",
            level=TrustLevel.INFO,
            summary="Name and description present but no required binaries declared",
            details=details,
            evidence=evidence,
        )

    return TrustCategoryResult(
        name="Purpose & Capability",
        key="purpose_capability",
        level=TrustLevel.PASS,
        summary="Name, description, and required binaries declared" + (
            "; network endpoints documented" if has_network_docs else ""
        ),
        details=details,
        evidence=evidence,
    )


def _assess_instruction_scope(
    meta: SkillMetadata | None,
    scan: SkillScanResult,
    audit: SkillAuditResult,
) -> TrustCategoryResult:
    """Category 2: Instruction Scope."""
    details: list[str] = []
    evidence: list[str] = []

    raw = (meta.raw_frontmatter if meta else "")
    has_file_reads = _fm_has(raw, "file_reads")
    has_justification = _fm_has(raw, "file_reads_justification")
    has_data_handling = _fm_has(raw, "sensitive_data_handling")
    has_file_writes = _fm_has(raw, "file_writes")

    if has_file_reads:
        file_reads = _fm_list(raw, "file_reads")
        details.append(f"File reads enumerated: {len(file_reads)} path(s)")
    if has_justification:
        details.append("File reads justification provided")
    if has_data_handling:
        details.append("Sensitive data handling documented")
    if has_file_writes:
        writes = _fm_list(raw, "file_writes")
        if not writes:
            details.append("No file writes declared (read-only)")
        else:
            details.append(f"File writes declared: {len(writes)} path(s)")
            evidence.append(f"file_writes: {writes}")

    # Check for credential file access or data exfiltration
    dangerous_scope = _audit_findings_for(
        audit, "credential_file_access", "data_exfiltration", "memory_poisoning"
    )
    if dangerous_scope:
        for f in dangerous_scope[:3]:
            details.append(f"Behavioral finding: {f.title}")
            evidence.append(f"{f.category}: {f.detail[:100]}")

    if dangerous_scope:
        return TrustCategoryResult(
            name="Instruction Scope",
            key="instruction_scope",
            level=TrustLevel.FAIL,
            summary="Credential file access or data exfiltration pattern detected",
            details=details,
            evidence=evidence,
        )

    if not has_file_reads and not raw:
        return TrustCategoryResult(
            name="Instruction Scope",
            key="instruction_scope",
            level=TrustLevel.WARN,
            summary="No metadata — cannot verify instruction scope",
            details=details,
            evidence=evidence,
        )

    if not has_file_reads:
        return TrustCategoryResult(
            name="Instruction Scope",
            key="instruction_scope",
            level=TrustLevel.WARN,
            summary="No file_reads declared — scope unclear",
            details=details,
            evidence=evidence,
        )

    if has_file_reads and not has_justification:
        return TrustCategoryResult(
            name="Instruction Scope",
            key="instruction_scope",
            level=TrustLevel.INFO,
            summary="File reads listed but no justification provided",
            details=details,
            evidence=evidence,
        )

    return TrustCategoryResult(
        name="Instruction Scope",
        key="instruction_scope",
        level=TrustLevel.PASS,
        summary="File reads bounded and justified" + (
            "; data handling documented" if has_data_handling else ""
        ),
        details=details,
        evidence=evidence,
    )


def _assess_install_mechanism(
    meta: SkillMetadata | None,
    scan: SkillScanResult,
    audit: SkillAuditResult,
) -> TrustCategoryResult:
    """Category 3: Install Mechanism."""
    details: list[str] = []
    evidence: list[str] = []

    raw = (meta.raw_frontmatter if meta else "")
    has_source = bool(meta and meta.source)
    has_homepage = bool(meta and meta.homepage)
    install_methods = meta.install_methods if meta else []

    if install_methods:
        details.append(f"Install methods: {', '.join(install_methods)}")
    if has_source:
        details.append(f"Source: {meta.source}")
        evidence.append(f"source: {meta.source}")
    if has_homepage:
        details.append(f"Homepage: {meta.homepage}")

    # Check for verification/signing references
    has_signing = bool(
        re.search(r"(?:sigstore|cosign|checksum|sha256|provenance|slsa)", raw, re.IGNORECASE)
    )
    if has_signing:
        details.append("Signing/provenance references found in metadata")

    if not install_methods and not has_source:
        return TrustCategoryResult(
            name="Install Mechanism",
            key="install_mechanism",
            level=TrustLevel.FAIL,
            summary="No install methods and no source URL — cannot verify provenance",
            details=details,
            evidence=evidence,
        )

    if not has_source:
        return TrustCategoryResult(
            name="Install Mechanism",
            key="install_mechanism",
            level=TrustLevel.WARN,
            summary="No source URL provided — cannot audit code",
            details=details,
            evidence=evidence,
        )

    if len(install_methods) < 2 and not has_signing:
        return TrustCategoryResult(
            name="Install Mechanism",
            key="install_mechanism",
            level=TrustLevel.INFO,
            summary="Source available but limited install methods or no signing references",
            details=details,
            evidence=evidence,
        )

    return TrustCategoryResult(
        name="Install Mechanism",
        key="install_mechanism",
        level=TrustLevel.PASS,
        summary=f"{len(install_methods)} install method(s), source available" + (
            ", signed" if has_signing else ""
        ),
        details=details,
        evidence=evidence,
    )


def _assess_credentials(
    meta: SkillMetadata | None,
    scan: SkillScanResult,
    audit: SkillAuditResult,
) -> TrustCategoryResult:
    """Category 4: Credentials."""
    details: list[str] = []
    evidence: list[str] = []

    raw = (meta.raw_frontmatter if meta else "")
    cred_count = len(scan.credential_env_vars)
    has_optional_env = _fm_has(raw, "optional_env")
    has_required_env = _fm_has(raw, "env")
    has_sent_only_to = "sent_only_to" in raw if raw else False

    # Check what's declared
    required_env_list = _fm_list(raw, "env")
    env_empty = _fm_value(raw, "env")  # check for "env: []"

    if cred_count == 0:
        details.append("No credential env vars referenced")
    else:
        details.append(f"{cred_count} credential env var(s) referenced")
        evidence.append(f"credentials: {scan.credential_env_vars[:5]}")

    if has_optional_env:
        details.append("Optional env vars documented")
    if has_sent_only_to:
        details.append("Credential scope documented (sent_only_to)")

    # Excessive credentials from audit
    excessive = _audit_findings_for(audit, "excessive_permissions")
    bypass = _audit_findings_for(audit, "confirmation_bypass")

    if bypass and cred_count > 0:
        return TrustCategoryResult(
            name="Credentials",
            key="credentials",
            level=TrustLevel.FAIL,
            summary="Safety bypass patterns combined with credential access",
            details=details,
            evidence=evidence,
        )

    if excessive and not (has_optional_env and has_sent_only_to):
        details.append("Excessive credential exposure detected")
        return TrustCategoryResult(
            name="Credentials",
            key="credentials",
            level=TrustLevel.WARN,
            summary=f"Excessive credentials ({cred_count} env vars) — review scope",
            details=details,
            evidence=evidence,
        )

    if cred_count > 0 and not has_optional_env and not required_env_list:
        return TrustCategoryResult(
            name="Credentials",
            key="credentials",
            level=TrustLevel.INFO,
            summary=f"{cred_count} credential(s) referenced but not documented in metadata",
            details=details,
            evidence=evidence,
        )

    return TrustCategoryResult(
        name="Credentials",
        key="credentials",
        level=TrustLevel.PASS,
        summary="No required credentials" + (
            f"; {cred_count} optional, documented" if cred_count > 0 and has_optional_env
            else ""
        ),
        details=details,
        evidence=evidence,
    )


def _assess_persistence_privilege(
    meta: SkillMetadata | None,
    scan: SkillScanResult,
    audit: SkillAuditResult,
) -> TrustCategoryResult:
    """Category 5: Persistence & Privilege."""
    details: list[str] = []
    evidence: list[str] = []

    raw = (meta.raw_frontmatter if meta else "")

    # Check frontmatter declarations
    persistence_val = _fm_value(raw, "persistence")
    telemetry_val = _fm_value(raw, "telemetry")
    priv_esc_val = _fm_value(raw, "privilege_escalation")

    if persistence_val is not None:
        details.append(f"persistence: {persistence_val}")
    if telemetry_val is not None:
        details.append(f"telemetry: {telemetry_val}")
    if priv_esc_val is not None:
        details.append(f"privilege_escalation: {priv_esc_val}")

    # Check audit behavioral findings
    priv_findings = _audit_findings_for(
        audit, "persistence_mechanism", "privilege_escalation", "confirmation_bypass"
    )
    if priv_findings:
        for f in priv_findings[:3]:
            details.append(f"Behavioral finding: {f.title}")
            evidence.append(f"{f.category}: {f.detail[:100]}")

    if priv_findings:
        return TrustCategoryResult(
            name="Persistence & Privilege",
            key="persistence_privilege",
            level=TrustLevel.FAIL,
            summary="Privilege escalation or persistence mechanism detected",
            details=details,
            evidence=evidence,
        )

    # No frontmatter at all → cannot verify
    if not raw:
        return TrustCategoryResult(
            name="Persistence & Privilege",
            key="persistence_privilege",
            level=TrustLevel.WARN,
            summary="No metadata — cannot verify persistence or privilege claims",
            details=details,
            evidence=evidence,
        )

    # Frontmatter exists but missing key fields
    missing = []
    if persistence_val is None:
        missing.append("persistence")
    if telemetry_val is None:
        missing.append("telemetry")
    if priv_esc_val is None:
        missing.append("privilege_escalation")

    if missing:
        return TrustCategoryResult(
            name="Persistence & Privilege",
            key="persistence_privilege",
            level=TrustLevel.INFO,
            summary=f"Missing field(s): {', '.join(missing)} — cannot fully verify",
            details=details,
            evidence=evidence,
        )

    # All declared as false → best case
    all_false = (
        persistence_val and persistence_val.lower() == "false"
        and telemetry_val and telemetry_val.lower() == "false"
        and priv_esc_val and priv_esc_val.lower() == "false"
    )

    if all_false:
        return TrustCategoryResult(
            name="Persistence & Privilege",
            key="persistence_privilege",
            level=TrustLevel.PASS,
            summary="No persistence, no telemetry, no privilege escalation declared",
            details=details,
            evidence=evidence,
        )

    return TrustCategoryResult(
        name="Persistence & Privilege",
        key="persistence_privilege",
        level=TrustLevel.INFO,
        summary="Persistence/telemetry/privilege fields present but not all false",
        details=details,
        evidence=evidence,
    )


# ── Verdict computation ──────────────────────────────────────────────────────


def _compute_verdict(
    categories: list[TrustCategoryResult],
) -> tuple[Verdict, Confidence]:
    """Compute overall verdict and confidence from category results."""
    fail_count = sum(1 for c in categories if c.level == TrustLevel.FAIL)
    warn_count = sum(1 for c in categories if c.level == TrustLevel.WARN)
    pass_count = sum(1 for c in categories if c.level == TrustLevel.PASS)
    info_count = sum(1 for c in categories if c.level == TrustLevel.INFO)

    if fail_count >= 2:
        return Verdict.MALICIOUS, Confidence.HIGH
    if fail_count == 1 and warn_count >= 2:
        return Verdict.MALICIOUS, Confidence.MEDIUM
    if fail_count == 1:
        return Verdict.SUSPICIOUS, Confidence.MEDIUM
    if warn_count >= 3:
        return Verdict.SUSPICIOUS, Confidence.MEDIUM
    if warn_count >= 1:
        return Verdict.SUSPICIOUS, Confidence.LOW
    if pass_count == len(categories):
        return Verdict.BENIGN, Confidence.HIGH
    if pass_count + info_count == len(categories):
        return Verdict.BENIGN, Confidence.MEDIUM
    return Verdict.BENIGN, Confidence.LOW


# ── Recommendations ──────────────────────────────────────────────────────────


def _generate_recommendations(categories: list[TrustCategoryResult]) -> list[str]:
    """Generate actionable recommendations based on category results."""
    recs: list[str] = []

    for cat in categories:
        if cat.level == TrustLevel.PASS:
            continue

        if cat.key == "purpose_capability":
            if cat.level == TrustLevel.FAIL:
                recs.append("Remove shell/exec access or document why it is needed")
            elif cat.level == TrustLevel.WARN:
                recs.append("Add name and description to YAML frontmatter")
            else:
                recs.append("Declare required binaries in requires.bins")

        elif cat.key == "instruction_scope":
            if cat.level == TrustLevel.FAIL:
                recs.append("Remove credential file access patterns or isolate the tool")
            elif cat.level == TrustLevel.WARN:
                recs.append("Add file_reads list to enumerate all config paths accessed")
            else:
                recs.append("Add file_reads_justification explaining why each path is needed")

        elif cat.key == "install_mechanism":
            if cat.level == TrustLevel.FAIL:
                recs.append("Provide at least one install method and a source URL")
            elif cat.level == TrustLevel.WARN:
                recs.append("Add source URL to metadata for code audit")
            else:
                recs.append("Add Sigstore/cosign signing or provide multiple install methods")

        elif cat.key == "credentials":
            if cat.level == TrustLevel.FAIL:
                recs.append("Remove safety bypass patterns or revoke credential access")
            elif cat.level == TrustLevel.WARN:
                recs.append("Reduce credential count or scope with sent_only_to")
            else:
                recs.append("Document credentials in optional_env with sent_only_to scope")

        elif cat.key == "persistence_privilege":
            if cat.level == TrustLevel.FAIL:
                recs.append("Remove privilege escalation or persistence mechanisms")
            elif cat.level == TrustLevel.WARN:
                recs.append("Add persistence, telemetry, and privilege_escalation fields to metadata")
            else:
                recs.append("Set persistence: false, telemetry: false, and privilege_escalation: false")

    return recs


# ── Main entry point ─────────────────────────────────────────────────────────


def assess_trust(
    scan: SkillScanResult,
    audit: SkillAuditResult,
) -> TrustAssessmentResult:
    """Run ClawHub-style trust assessment on a parsed skill file.

    Requires the skill to have been parsed (scan_skill_files) and audited
    (audit_skill_result) first. Evaluates 5 trust categories and returns
    an overall verdict with confidence and recommendations.
    """
    meta = scan.metadata
    source_file = scan.source_files[0] if scan.source_files else "unknown"

    categories = [
        _assess_purpose_capability(meta, scan, audit),
        _assess_instruction_scope(meta, scan, audit),
        _assess_install_mechanism(meta, scan, audit),
        _assess_credentials(meta, scan, audit),
        _assess_persistence_privilege(meta, scan, audit),
    ]

    verdict, confidence = _compute_verdict(categories)
    recommendations = _generate_recommendations(categories)

    return TrustAssessmentResult(
        categories=categories,
        verdict=verdict,
        confidence=confidence,
        recommendations=recommendations,
        skill_name=meta.name if meta else "",
        source_file=source_file,
    )
