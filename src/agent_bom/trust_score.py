"""Evidence-based MCP server trust scoring with CVE citations.

Computes a 0-100 trust score for each MCP server by aggregating multiple
security signals. Every deduction is backed by specific evidence (CVE IDs,
credential names, tool names, etc.) so operators can understand exactly
why a server scored the way it did.

Score categories (max deduction from 100):
- CVE/Vulnerability posture:  -35 max
- Credential exposure:        -15 max
- Tool capability risk:       -15 max
- Registry risk level:        -10 max
- Drift detection:            -10 max
- OpenSSF Scorecard:          -15 max

A score of 100 means no evidence of risk was found.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from agent_bom.models import MCPServer, Severity

logger = logging.getLogger(__name__)

# Severity weights for CVE deductions
_CVE_SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.CRITICAL: 8.0,
    Severity.HIGH: 5.0,
    Severity.MEDIUM: 2.0,
    Severity.LOW: 0.5,
}

# Maximum deduction caps per category
_MAX_CVE_DEDUCTION = 35.0
_MAX_CREDENTIAL_DEDUCTION = 15.0
_MAX_CAPABILITY_DEDUCTION = 15.0
_MAX_REGISTRY_DEDUCTION = 10.0
_MAX_DRIFT_DEDUCTION = 10.0
_MAX_SCORECARD_DEDUCTION = 15.0


@dataclass
class TrustEvidence:
    """A single piece of evidence that affects the trust score."""

    category: str  # cve, credential, capability, registry, drift, scorecard
    description: str
    deduction: float  # Points deducted (positive number)
    severity: str = "info"  # critical, high, medium, low, info
    cve_id: Optional[str] = None
    package_name: Optional[str] = None
    package_version: Optional[str] = None
    tool_name: Optional[str] = None

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        result = {
            "category": self.category,
            "description": self.description,
            "deduction": self.deduction,
            "severity": self.severity,
        }
        if self.cve_id:
            result["cve_id"] = self.cve_id
        if self.package_name:
            result["package_name"] = self.package_name
        if self.package_version:
            result["package_version"] = self.package_version
        if self.tool_name:
            result["tool_name"] = self.tool_name
        return result


@dataclass
class CategoryScore:
    """Score breakdown for a single category."""

    category: str
    max_deduction: float
    actual_deduction: float
    score: float  # max_deduction - actual_deduction (clamped to 0)
    evidence: list[TrustEvidence] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "category": self.category,
            "max_points": self.max_deduction,
            "deduction": round(self.actual_deduction, 1),
            "score": round(self.score, 1),
            "evidence_count": len(self.evidence),
            "evidence": [e.to_dict() for e in self.evidence],
        }


@dataclass
class TrustScoreResult:
    """Complete trust score result for an MCP server."""

    server_name: str
    overall_score: float  # 0-100
    grade: str  # A, B, C, D, F
    categories: list[CategoryScore] = field(default_factory=list)
    evidence: list[TrustEvidence] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "server_name": self.server_name,
            "overall_score": round(self.overall_score, 1),
            "grade": self.grade,
            "summary": self.summary,
            "categories": [c.to_dict() for c in self.categories],
            "evidence_count": len(self.evidence),
            "evidence": [e.to_dict() for e in self.evidence],
        }


def _score_to_grade(score: float) -> str:
    """Convert numeric score to letter grade."""
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def _score_cves(server: MCPServer) -> CategoryScore:
    """Score CVE/vulnerability posture.

    Each CVE deducts points based on severity. CRITICAL CVEs deduct the most.
    Actively exploited CVEs (KEV or high EPSS) get an additional penalty.
    """
    evidence: list[TrustEvidence] = []
    total_deduction = 0.0

    for pkg in server.packages:
        for vuln in pkg.vulnerabilities:
            weight = _CVE_SEVERITY_WEIGHTS.get(vuln.severity, 0.5)

            # Bonus penalty for actively exploited vulnerabilities
            if vuln.is_kev:
                weight += 3.0
            elif vuln.epss_score is not None and vuln.epss_score > 0.5:
                weight += 2.0

            deduction = min(weight, _MAX_CVE_DEDUCTION - total_deduction)
            if deduction <= 0:
                break

            total_deduction += deduction

            fixed_info = ""
            if vuln.fixed_version:
                fixed_info = f" (fix available: {vuln.fixed_version})"

            kev_info = ""
            if vuln.is_kev:
                kev_info = " [CISA KEV: actively exploited]"
            elif vuln.epss_score is not None and vuln.epss_score > 0.5:
                kev_info = f" [EPSS: {vuln.epss_score:.1%} exploit probability]"

            evidence.append(
                TrustEvidence(
                    category="cve",
                    description=(f"{vuln.id} ({vuln.severity.value.upper()}) in {pkg.name}@{pkg.version}{fixed_info}{kev_info}"),
                    deduction=round(deduction, 1),
                    severity=vuln.severity.value,
                    cve_id=vuln.id,
                    package_name=pkg.name,
                    package_version=pkg.version,
                )
            )
        if total_deduction >= _MAX_CVE_DEDUCTION:
            break

    actual = min(total_deduction, _MAX_CVE_DEDUCTION)
    return CategoryScore(
        category="cve",
        max_deduction=_MAX_CVE_DEDUCTION,
        actual_deduction=actual,
        score=_MAX_CVE_DEDUCTION - actual,
        evidence=evidence,
    )


def _score_credentials(server: MCPServer) -> CategoryScore:
    """Score credential exposure.

    Servers with hardcoded credentials in env vars are penalized.
    More credentials = higher risk.
    """
    evidence: list[TrustEvidence] = []
    cred_names = server.credential_names

    if not cred_names:
        return CategoryScore(
            category="credential",
            max_deduction=_MAX_CREDENTIAL_DEDUCTION,
            actual_deduction=0.0,
            score=_MAX_CREDENTIAL_DEDUCTION,
            evidence=[],
        )

    # Each credential deducts 5 points, capped at max
    total_deduction = 0.0
    for name in cred_names:
        deduction = min(5.0, _MAX_CREDENTIAL_DEDUCTION - total_deduction)
        if deduction <= 0:
            break
        total_deduction += deduction
        evidence.append(
            TrustEvidence(
                category="credential",
                description=f"Credential environment variable exposed: {name}",
                deduction=deduction,
                severity="high",
            )
        )

    actual = min(total_deduction, _MAX_CREDENTIAL_DEDUCTION)
    return CategoryScore(
        category="credential",
        max_deduction=_MAX_CREDENTIAL_DEDUCTION,
        actual_deduction=actual,
        score=_MAX_CREDENTIAL_DEDUCTION - actual,
        evidence=evidence,
    )


def _score_capabilities(server: MCPServer) -> CategoryScore:
    """Score tool capability risk.

    Uses risk_analyzer to classify tools and detect dangerous combinations.
    """
    from agent_bom.risk_analyzer import (
        DANGEROUS_COMBOS,
        ToolCapability,
        get_capabilities,
    )

    evidence: list[TrustEvidence] = []
    total_deduction = 0.0

    if not server.tools:
        return CategoryScore(
            category="capability",
            max_deduction=_MAX_CAPABILITY_DEDUCTION,
            actual_deduction=0.0,
            score=_MAX_CAPABILITY_DEDUCTION,
            evidence=[],
        )

    cap_map = get_capabilities(server.tools)
    present_caps: set[ToolCapability] = set(cap_map.keys())

    # High-risk capabilities deduct points
    high_risk_caps = {
        ToolCapability.EXECUTE: 4.0,
        ToolCapability.DELETE: 3.0,
        ToolCapability.ADMIN: 3.0,
        ToolCapability.AUTH: 2.0,
    }

    for cap, penalty in high_risk_caps.items():
        if cap in present_caps:
            tool_names = cap_map[cap]
            deduction = min(penalty, _MAX_CAPABILITY_DEDUCTION - total_deduction)
            if deduction <= 0:
                break
            total_deduction += deduction
            evidence.append(
                TrustEvidence(
                    category="capability",
                    description=(
                        f"{cap.value.upper()} capability via tool(s): "
                        f"{', '.join(tool_names[:3])}" + (f" (+{len(tool_names) - 3} more)" if len(tool_names) > 3 else "")
                    ),
                    deduction=deduction,
                    severity="medium",
                    tool_name=tool_names[0] if tool_names else None,
                )
            )

    # Dangerous combinations add extra penalty
    for combo_set, description in DANGEROUS_COMBOS:
        if combo_set.issubset(present_caps):
            deduction = min(3.0, _MAX_CAPABILITY_DEDUCTION - total_deduction)
            if deduction <= 0:
                break
            total_deduction += deduction
            evidence.append(
                TrustEvidence(
                    category="capability",
                    description=f"Dangerous combination: {description}",
                    deduction=deduction,
                    severity="high",
                )
            )

    actual = min(total_deduction, _MAX_CAPABILITY_DEDUCTION)
    return CategoryScore(
        category="capability",
        max_deduction=_MAX_CAPABILITY_DEDUCTION,
        actual_deduction=actual,
        score=_MAX_CAPABILITY_DEDUCTION - actual,
        evidence=evidence,
    )


def _score_registry(
    server: MCPServer,
    registry_entry: Optional[dict] = None,
) -> CategoryScore:
    """Score based on registry risk level.

    Servers with known high-risk registry entries are penalized.
    Unverified servers get a moderate penalty.
    """
    evidence: list[TrustEvidence] = []
    total_deduction = 0.0

    if not server.registry_verified:
        total_deduction = 5.0
        evidence.append(
            TrustEvidence(
                category="registry",
                description="Server not verified in MCP registry",
                deduction=5.0,
                severity="medium",
            )
        )

    if registry_entry:
        risk_level = registry_entry.get("risk_level", "")
        if risk_level == "high":
            deduction = min(10.0, _MAX_REGISTRY_DEDUCTION - total_deduction)
            total_deduction += deduction
            justification = registry_entry.get("risk_justification", "High-risk category")
            evidence.append(
                TrustEvidence(
                    category="registry",
                    description=f"Registry risk level: HIGH - {justification}",
                    deduction=deduction,
                    severity="high",
                )
            )
        elif risk_level == "medium":
            deduction = min(5.0, _MAX_REGISTRY_DEDUCTION - total_deduction)
            total_deduction += deduction
            justification = registry_entry.get("risk_justification", "Medium-risk category")
            evidence.append(
                TrustEvidence(
                    category="registry",
                    description=f"Registry risk level: MEDIUM - {justification}",
                    deduction=deduction,
                    severity="medium",
                )
            )

    actual = min(total_deduction, _MAX_REGISTRY_DEDUCTION)
    return CategoryScore(
        category="registry",
        max_deduction=_MAX_REGISTRY_DEDUCTION,
        actual_deduction=actual,
        score=_MAX_REGISTRY_DEDUCTION - actual,
        evidence=evidence,
    )


def _score_drift(
    server: MCPServer,
    enforcement_findings: Optional[list] = None,
) -> CategoryScore:
    """Score based on drift detection and enforcement findings.

    Drift findings (undeclared tools, description changes) indicate
    potential tampering or rug-pull attacks.
    """
    evidence: list[TrustEvidence] = []
    total_deduction = 0.0

    if not enforcement_findings:
        return CategoryScore(
            category="drift",
            max_deduction=_MAX_DRIFT_DEDUCTION,
            actual_deduction=0.0,
            score=_MAX_DRIFT_DEDUCTION,
            evidence=[],
        )

    for finding in enforcement_findings:
        if finding.server_name != server.name:
            continue

        if finding.category in ("drift", "description_drift"):
            severity_weight = {"critical": 5.0, "high": 4.0, "medium": 2.0, "low": 1.0}
            weight = severity_weight.get(finding.severity, 1.0)
            deduction = min(weight, _MAX_DRIFT_DEDUCTION - total_deduction)
            if deduction <= 0:
                break
            total_deduction += deduction
            evidence.append(
                TrustEvidence(
                    category="drift",
                    description=finding.reason,
                    deduction=deduction,
                    severity=finding.severity,
                    tool_name=finding.tool_name,
                )
            )
        elif finding.category in ("injection", "schema_injection"):
            deduction = min(5.0, _MAX_DRIFT_DEDUCTION - total_deduction)
            if deduction <= 0:
                break
            total_deduction += deduction
            evidence.append(
                TrustEvidence(
                    category="drift",
                    description=finding.reason,
                    deduction=deduction,
                    severity=finding.severity,
                    tool_name=finding.tool_name,
                )
            )

    actual = min(total_deduction, _MAX_DRIFT_DEDUCTION)
    return CategoryScore(
        category="drift",
        max_deduction=_MAX_DRIFT_DEDUCTION,
        actual_deduction=actual,
        score=_MAX_DRIFT_DEDUCTION - actual,
        evidence=evidence,
    )


def _score_scorecard(server: MCPServer) -> CategoryScore:
    """Score based on OpenSSF Scorecard data.

    Packages with low scorecard scores indicate poorly-maintained
    dependencies, which increases supply chain risk.
    """
    evidence: list[TrustEvidence] = []
    total_deduction = 0.0

    scored_packages = [pkg for pkg in server.packages if pkg.scorecard_score is not None]

    if not scored_packages:
        return CategoryScore(
            category="scorecard",
            max_deduction=_MAX_SCORECARD_DEDUCTION,
            actual_deduction=0.0,
            score=_MAX_SCORECARD_DEDUCTION,
            evidence=[],
        )

    for pkg in scored_packages:
        score = pkg.scorecard_score
        if score is None:
            continue

        if score < 3.0:
            deduction = min(5.0, _MAX_SCORECARD_DEDUCTION - total_deduction)
            severity = "high"
            label = "poorly maintained"
        elif score < 5.0:
            deduction = min(3.0, _MAX_SCORECARD_DEDUCTION - total_deduction)
            severity = "medium"
            label = "below average maintenance"
        elif score < 7.0:
            deduction = min(1.0, _MAX_SCORECARD_DEDUCTION - total_deduction)
            severity = "low"
            label = "moderate maintenance"
        else:
            continue  # Good score, no deduction

        if deduction <= 0:
            break

        total_deduction += deduction
        evidence.append(
            TrustEvidence(
                category="scorecard",
                description=(f"OpenSSF Scorecard {score:.1f}/10 for {pkg.name}@{pkg.version} ({label})"),
                deduction=deduction,
                severity=severity,
                package_name=pkg.name,
                package_version=pkg.version,
            )
        )

    actual = min(total_deduction, _MAX_SCORECARD_DEDUCTION)
    return CategoryScore(
        category="scorecard",
        max_deduction=_MAX_SCORECARD_DEDUCTION,
        actual_deduction=actual,
        score=_MAX_SCORECARD_DEDUCTION - actual,
        evidence=evidence,
    )


def _generate_summary(result: TrustScoreResult) -> str:
    """Generate a human-readable summary of the trust score."""
    parts: list[str] = []

    parts.append(f"Trust score: {result.overall_score:.0f}/100 (Grade {result.grade}).")

    # Highlight critical evidence
    critical_evidence = [e for e in result.evidence if e.severity == "critical"]
    high_evidence = [e for e in result.evidence if e.severity == "high"]

    if critical_evidence:
        cve_citations = [e.cve_id for e in critical_evidence if e.cve_id]
        if cve_citations:
            parts.append(
                f"Critical CVEs: {', '.join(cve_citations[:5])}"
                + (f" (+{len(cve_citations) - 5} more)" if len(cve_citations) > 5 else "")
                + "."
            )
        non_cve_critical = [e for e in critical_evidence if not e.cve_id]
        if non_cve_critical:
            parts.append(f"{len(non_cve_critical)} critical non-CVE finding(s).")

    if high_evidence:
        cve_citations = [e.cve_id for e in high_evidence if e.cve_id]
        cred_count = sum(1 for e in high_evidence if e.category == "credential")
        if cve_citations:
            parts.append(
                f"High-severity CVEs: {', '.join(cve_citations[:3])}"
                + (f" (+{len(cve_citations) - 3} more)" if len(cve_citations) > 3 else "")
                + "."
            )
        if cred_count:
            parts.append(f"{cred_count} exposed credential(s).")

    # Category summary for low scores
    low_categories = [c for c in result.categories if c.score < c.max_deduction * 0.5]
    if low_categories:
        weak_names = [c.category for c in low_categories]
        parts.append(f"Weakest areas: {', '.join(weak_names)}.")

    if not critical_evidence and not high_evidence:
        parts.append("No critical or high-severity issues found.")

    return " ".join(parts)


def calculate_trust_score(
    server: MCPServer,
    registry_entry: Optional[dict] = None,
    enforcement_findings: Optional[list] = None,
) -> TrustScoreResult:
    """Calculate evidence-based trust score for an MCP server.

    Aggregates multiple security signals into a 0-100 trust score.
    Each deduction is backed by specific evidence (CVE IDs, credential
    names, tool names) so operators can understand exactly why a server
    scored the way it did.

    Args:
        server: MCP server to score.
        registry_entry: Optional registry entry dict for this server.
        enforcement_findings: Optional list of EnforcementFinding objects
            from a prior enforcement scan.

    Returns:
        TrustScoreResult with overall score, per-category breakdown,
        and evidence citations.
    """
    categories: list[CategoryScore] = []

    # Score each category
    categories.append(_score_cves(server))
    categories.append(_score_credentials(server))
    categories.append(_score_capabilities(server))
    categories.append(_score_registry(server, registry_entry))
    categories.append(_score_drift(server, enforcement_findings))
    categories.append(_score_scorecard(server))

    # Calculate overall score: start at 100, subtract deductions
    total_deduction = sum(c.actual_deduction for c in categories)
    overall_score = max(100.0 - total_deduction, 0.0)

    # Collect all evidence
    all_evidence: list[TrustEvidence] = []
    for cat in categories:
        all_evidence.extend(cat.evidence)

    # Sort evidence by deduction (most impactful first)
    all_evidence.sort(key=lambda e: e.deduction, reverse=True)

    result = TrustScoreResult(
        server_name=server.name,
        overall_score=overall_score,
        grade=_score_to_grade(overall_score),
        categories=categories,
        evidence=all_evidence,
    )

    result.summary = _generate_summary(result)

    return result


def calculate_trust_scores(
    servers: list[MCPServer],
    registry: Optional[dict] = None,
    enforcement_findings: Optional[list] = None,
) -> list[TrustScoreResult]:
    """Calculate trust scores for multiple MCP servers.

    Args:
        servers: List of MCP servers to score.
        registry: Optional registry dict (server_name -> entry).
        enforcement_findings: Optional list of EnforcementFinding objects.

    Returns:
        List of TrustScoreResult objects, one per server.
    """
    registry = registry or {}
    results: list[TrustScoreResult] = []

    for server in servers:
        reg_entry = registry.get(server.name) or registry.get(server.registry_id or "")
        result = calculate_trust_score(
            server=server,
            registry_entry=reg_entry,
            enforcement_findings=enforcement_findings,
        )
        results.append(result)

    return results
