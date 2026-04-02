"""Shared skill scanning and provenance services for CLI and MCP surfaces."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from agent_bom.integrity import verify_instruction_file
from agent_bom.parsers.skill_audit import SkillAuditResult, audit_skill_result
from agent_bom.parsers.skills import SkillScanResult, discover_skill_files, parse_skill_file
from agent_bom.parsers.trust_assessment import TrustAssessmentResult, assess_trust
from agent_bom.skill_bundles import SkillBundle, build_skill_bundle

_SKILL_DISCOVERY_SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__"}


@dataclass
class SkillFileReport:
    """End-to-end scan, audit, trust, and provenance report for one file."""

    path: Path
    scan: SkillScanResult
    audit: SkillAuditResult
    trust: TrustAssessmentResult
    provenance: dict[str, object]
    bundle: SkillBundle

    def to_dict(self) -> dict:
        """Serialize the file report to JSON-compatible data."""
        return {
            "path": str(self.path),
            "bundle": self.bundle.to_dict(),
            "packages": [
                {
                    "name": pkg.name,
                    "version": pkg.version,
                    "ecosystem": pkg.ecosystem,
                }
                for pkg in self.scan.packages
            ],
            "servers": [
                {
                    "name": server.name,
                    "command": server.command,
                    "args": list(server.args),
                    "transport": server.transport.value,
                }
                for server in self.scan.servers
            ],
            "credential_env_vars": list(self.scan.credential_env_vars),
            "audit": {
                "passed": self.audit.passed,
                "packages_checked": self.audit.packages_checked,
                "servers_checked": self.audit.servers_checked,
                "credentials_checked": self.audit.credentials_checked,
                "findings": [
                    {
                        "severity": finding.severity,
                        "category": finding.category,
                        "title": finding.title,
                        "detail": finding.detail,
                        "source_file": finding.source_file,
                        "package": finding.package,
                        "server": finding.server,
                        "recommendation": finding.recommendation,
                        "context": finding.context,
                    }
                    for finding in self.audit.findings
                ],
            },
            "trust": self.trust.to_dict(),
            "provenance": self.provenance,
        }


@dataclass
class SkillsScanReport:
    """Aggregated report across one or more skill/instruction files."""

    files: list[SkillFileReport] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Serialize the aggregated scan report."""
        serialized_files = [report.to_dict() for report in self.files]
        package_keys = {(pkg["name"].lower(), pkg["ecosystem"]) for report in serialized_files for pkg in report["packages"]}
        server_names = {server["name"] for report in serialized_files for server in report["servers"]}
        credential_names = {cred for report in self.files for cred in report.scan.credential_env_vars}
        bundle_ids = {report.bundle.stable_id for report in self.files}
        bundled_paths = {entry["path"] for report in serialized_files for entry in report["bundle"]["files"]}

        suspicious = sum(1 for report in self.files if report.trust.verdict.value == "suspicious")
        malicious = sum(1 for report in self.files if report.trust.verdict.value == "malicious")
        verified = sum(1 for report in self.files if report.provenance.get("status") == "verified")

        return {
            "summary": {
                "files_scanned": len(self.files),
                "bundles": len(bundle_ids),
                "bundled_files": len(bundled_paths),
                "packages_found": len(package_keys),
                "servers_found": len(server_names),
                "credential_env_vars": len(credential_names),
                "findings": sum(len(report.audit.findings) for report in self.files),
                "verified_files": verified,
                "suspicious_files": suspicious,
                "malicious_files": malicious,
            },
            "files": serialized_files,
        }


def _looks_like_instruction_surface(path: Path, *, allow_docs_skills: bool = False) -> bool:
    """Return True when a file path looks like a real skill/instruction surface."""
    if any(part in _SKILL_DISCOVERY_SKIP_DIRS for part in path.parts):
        return False
    if not allow_docs_skills and "docs" in path.parts and "skills" in path.parts:
        return False

    name = path.name

    if name in {"CLAUDE.md", "AGENTS.md", "SKILL.md", "skill.md", ".cursorrules", ".windsurfrules"}:
        return True

    if name == "copilot-instructions.md" and any(parent.name == ".github" for parent in path.parents):
        return True

    if path.suffix.lower() != ".md":
        return False

    if any(parent.name == "skills" for parent in path.parents):
        return True

    if any(parent.name == "rules" and parent.parent.name == ".cursor" for parent in path.parents if parent.parent != parent):
        return True

    return False


def _discover_explicit_skill_files(directory: Path) -> list[Path]:
    """Discover skill-like files inside a directory explicitly requested by the user."""
    found: list[Path] = []
    seen: set[Path] = set()
    allow_docs_skills = "docs" in directory.parts and "skills" in directory.parts
    for path in sorted(directory.rglob("*")):
        if not path.is_file():
            continue
        if not _looks_like_instruction_surface(path, allow_docs_skills=allow_docs_skills):
            continue
        resolved = path.resolve()
        if resolved not in seen:
            seen.add(resolved)
            found.append(resolved)
    return found


def resolve_skill_targets(paths: Iterable[str | Path] | None = None, *, cwd: Path | None = None) -> list[Path]:
    """Resolve files/directories to concrete skill/instruction files."""
    base_dir = cwd or Path.cwd()
    requested = list(paths) if paths is not None else [base_dir]
    explicit_paths = bool(requested)
    resolved: list[Path] = []
    seen: set[Path] = set()

    for raw_path in requested:
        path = raw_path if isinstance(raw_path, Path) else Path(raw_path)
        candidate = path if path.is_absolute() else (base_dir / path)
        candidate = candidate.resolve()

        discovered: list[Path]
        if candidate.is_dir():
            discovered = _discover_explicit_skill_files(candidate) if explicit_paths else discover_skill_files(candidate)
        elif candidate.is_file():
            discovered = [candidate]
        else:
            continue

        for file_path in discovered:
            normalized = file_path.resolve()
            if normalized not in seen:
                seen.add(normalized)
                resolved.append(normalized)

    return sorted(resolved)


def _provenance_to_dict(path: Path) -> dict[str, object]:
    """Convert instruction-file verification to stable JSON output."""
    verification = verify_instruction_file(path)
    if verification.verified:
        status = "verified"
    elif verification.has_sigstore_bundle:
        status = "bundle_found_but_invalid"
    elif verification.reason == "file_not_found":
        status = "missing"
    else:
        status = "unsigned"

    return {
        "status": status,
        "reason": verification.reason,
        "sha256": verification.sha256,
        "signer": verification.signer_identity,
        "rekor_log_index": verification.rekor_log_index,
        "has_sigstore_bundle": verification.has_sigstore_bundle,
    }


def scan_skill_targets(paths: Iterable[str | Path] | None = None, *, cwd: Path | None = None) -> SkillsScanReport:
    """Scan one or more skill targets and return aggregate results."""
    reports: list[SkillFileReport] = []
    for path in resolve_skill_targets(paths, cwd=cwd):
        scan = parse_skill_file(path)
        audit = audit_skill_result(scan)
        trust = assess_trust(scan, audit)
        reports.append(
            SkillFileReport(
                path=path,
                scan=scan,
                audit=audit,
                trust=trust,
                provenance=_provenance_to_dict(path),
                bundle=build_skill_bundle(path),
            )
        )
    return SkillsScanReport(files=reports)


def verify_skill_targets(paths: Iterable[str | Path] | None = None, *, cwd: Path | None = None) -> list[dict[str, object]]:
    """Verify provenance for one or more skill targets."""
    return [
        {
            "path": str(path),
            **_provenance_to_dict(path),
        }
        for path in resolve_skill_targets(paths, cwd=cwd)
    ]
