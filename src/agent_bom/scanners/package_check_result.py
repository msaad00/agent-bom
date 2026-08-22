"""Canonical package-check verdict shared by CLI, MCP, and REST projectors."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agent_bom.canonical_ids import canonical_package_id

_CANONICAL_VERDICTS = {
    "unsafe": "vulnerable",
    "vulnerable": "vulnerable",
    "skipped": "incomplete",
}


@dataclass(frozen=True)
class PackageCheckResult:
    """Surface-neutral package verdict and its evidence."""

    package: str
    version: str
    ecosystems: tuple[str, ...]
    verdict: str
    message: str
    lookup_mode: str
    vulnerabilities: tuple[dict[str, Any], ...] = ()
    warnings: tuple[str, ...] = ()
    purl: str | None = None
    is_malicious: bool = False
    malicious_reason: str | None = None
    exit_code: int = 0
    source_context: dict[str, Any] = field(default_factory=dict)

    @property
    def canonical_verdict(self) -> str:
        return _CANONICAL_VERDICTS.get(self.verdict, self.verdict)

    @property
    def package_canonical_id(self) -> str:
        ecosystem = self.ecosystems[0] if self.ecosystems else "unknown"
        return canonical_package_id(self.package, self.version, ecosystem, self.purl)

    def contract(self) -> dict[str, Any]:
        """Return fields whose meaning is identical on every public surface."""
        ecosystem = self.ecosystems[0] if len(self.ecosystems) == 1 else None
        return {
            "package": self.package,
            "version": self.version,
            "ecosystem": ecosystem,
            "ecosystems": list(self.ecosystems),
            "package_canonical_id": self.package_canonical_id,
            "purl": self.purl,
            "canonical_verdict": self.canonical_verdict,
            "message": self.message,
            "lookup_mode": self.lookup_mode,
            "is_malicious": self.is_malicious,
            "malicious_reason": self.malicious_reason,
            "vulnerability_count": len(self.vulnerabilities),
            "vulnerability_details": list(self.vulnerabilities),
            "scan_warnings": list(self.warnings),
            **self.source_context,
        }

    def cli_payload(
        self,
        *,
        legacy_verdict: str,
        exit_zero: bool = False,
        fail_on_severity: str | None = None,
        fail_on_severity_count: int | None = None,
    ) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "document_type": "PACKAGE-CHECK",
            "spec_version": "1.0",
            **self.contract(),
            "verdict": legacy_verdict,
            "exit_code": self.exit_code,
            "exit_zero": exit_zero,
            "fail_on_severity": fail_on_severity,
            "fail_on_severity_count": fail_on_severity_count,
            # Backward-compatible list alias used by existing CLI consumers.
            "vulnerabilities": list(self.vulnerabilities),
        }

    def service_payload(self, *, legacy_status: str | None = None) -> dict[str, Any]:
        return {
            **self.contract(),
            "status": legacy_status or self.canonical_verdict,
            # Backward-compatible MCP/REST aliases.
            "vulnerabilities": len(self.vulnerabilities),
            "details": list(self.vulnerabilities),
        }


def serialize_vulnerability(vulnerability: Any) -> dict[str, Any]:
    """Serialize the common vulnerability evidence without surface drift."""
    severity = getattr(vulnerability, "severity", None)
    severity_value = getattr(severity, "value", severity)
    return {
        "id": getattr(vulnerability, "id", None),
        "summary": getattr(vulnerability, "summary", None),
        "severity": severity_value,
        "fixed_version": getattr(vulnerability, "fixed_version", None),
        "is_kev": bool(getattr(vulnerability, "is_kev", False)),
        "kev_date_added": getattr(vulnerability, "kev_date_added", None),
        "kev_due_date": getattr(vulnerability, "kev_due_date", None),
        "cvss_score": getattr(vulnerability, "cvss_score", None),
        "cvss_vector": getattr(vulnerability, "cvss_vector", None),
        "attack_vector": getattr(vulnerability, "attack_vector", None),
        "attack_complexity": getattr(vulnerability, "attack_complexity", None),
        "privileges_required": getattr(vulnerability, "privileges_required", None),
        "user_interaction": getattr(vulnerability, "user_interaction", None),
        "network_exploitable": bool(getattr(vulnerability, "network_exploitable", False)),
        "epss_score": getattr(vulnerability, "epss_score", None),
        "epss_percentile": getattr(vulnerability, "epss_percentile", None),
        "nvd_status": getattr(vulnerability, "nvd_status", None),
        "published_at": getattr(vulnerability, "published_at", None),
        "modified_at": getattr(vulnerability, "modified_at", None),
        "cwe_ids": list(getattr(vulnerability, "cwe_ids", []) or []),
        "aliases": list(getattr(vulnerability, "aliases", []) or []),
        "references": list(getattr(vulnerability, "references", []) or []),
        "advisory_sources": list(getattr(vulnerability, "advisory_sources", []) or []),
        "compliance_tags": dict(getattr(vulnerability, "compliance_tags", {}) or {}),
    }
