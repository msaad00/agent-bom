"""Shared skill scanning and provenance services for CLI and MCP surfaces."""

from __future__ import annotations

import asyncio
import concurrent.futures
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from agent_bom.integrity import verify_instruction_file
from agent_bom.parsers.skill_audit import SkillAuditResult, audit_skill_result
from agent_bom.parsers.skills import SkillScanResult, discover_skill_files, parse_skill_file
from agent_bom.parsers.trust_assessment import TrustAssessmentResult, assess_trust
from agent_bom.security import sanitize_command_args
from agent_bom.skill_bundles import SkillBundle, build_skill_bundle
from agent_bom.skill_intel import ThreatIntelResult, ThreatIntelStatus, lookup_bundle_threat_intel
from agent_bom.skills_catalog import catalog_scan_timestamp, load_skills_catalog, save_skills_catalog

_SKILL_DISCOVERY_SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__"}
_SKILLS_SCAN_CONCURRENCY = max(1, int(os.environ.get("AGENT_BOM_SKILLS_SCAN_CONCURRENCY", "8")))
_SKILLS_SCAN_SCHEMA_VERSION = "1"
_SKILLS_SCAN_SCHEMA_ID = "https://agent-bom.github.io/schemas/skills-scan/v1"
_SKILLS_RESCAN_SCHEMA_VERSION = "1"
_SKILLS_RESCAN_SCHEMA_ID = "https://agent-bom.github.io/schemas/skills-rescan/v1"


def _generated_at() -> str:
    """Return an ISO 8601 UTC timestamp for structured output."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass
class SkillFileReport:
    """End-to-end scan, audit, trust, and provenance report for one file."""

    path: Path
    scan: SkillScanResult
    audit: SkillAuditResult
    trust: TrustAssessmentResult
    provenance: dict[str, object]
    bundle: SkillBundle
    threat_intel: ThreatIntelResult | None = None
    status: str = ThreatIntelStatus.CLEAN.value

    def to_dict(self) -> dict:
        """Serialize the file report to JSON-compatible data."""
        return {
            "path": str(self.path),
            "status": self.status,
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
                    "args": sanitize_command_args(server.args),
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
                "behavioral_summary": self.audit.behavioral_summary,
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
            "threat_intel": self.threat_intel.to_dict() if self.threat_intel else None,
        }


@dataclass
class SkillsScanReport:
    """Aggregated report across one or more skill/instruction files."""

    files: list[SkillFileReport] = field(default_factory=list)
    catalog_path: str | None = None

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
        status_counts = {status.value: 0 for status in ThreatIntelStatus}
        for report in self.files:
            status_counts[report.status] = status_counts.get(report.status, 0) + 1

        return {
            "$schema": _SKILLS_SCAN_SCHEMA_ID,
            "schema_version": _SKILLS_SCAN_SCHEMA_VERSION,
            "report_type": "skills_scan",
            "generated_at": _generated_at(),
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
                "blocked_files": sum(1 for report in self.files if report.trust.review_verdict.value == "blocked"),
                "high_risk_files": sum(1 for report in self.files if report.trust.review_verdict.value == "high_risk"),
                "clean_files": status_counts.get("clean", 0),
                "suspicious_status_files": status_counts.get("suspicious", 0),
                "malicious_status_files": status_counts.get("malicious", 0),
                "pending_status_files": status_counts.get("pending", 0),
                "unavailable_status_files": status_counts.get("unavailable", 0),
            },
            **({"catalog_path": self.catalog_path} if self.catalog_path else {}),
            "files": serialized_files,
        }


@dataclass
class SkillsRescanReport:
    """Rescan report for previously cataloged skills."""

    catalog_path: str
    entries: list[dict[str, object]] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        """Serialize the rescan report."""
        summary = {
            "catalog_entries": len(self.entries),
            "rescanned": sum(1 for entry in self.entries if entry.get("rescanned")),
            "missing": sum(1 for entry in self.entries if entry.get("exists") is False),
            "clean": sum(1 for entry in self.entries if entry.get("status") == ThreatIntelStatus.CLEAN.value),
            "suspicious": sum(1 for entry in self.entries if entry.get("status") == ThreatIntelStatus.SUSPICIOUS.value),
            "malicious": sum(1 for entry in self.entries if entry.get("status") == ThreatIntelStatus.MALICIOUS.value),
            "pending": sum(1 for entry in self.entries if entry.get("status") == ThreatIntelStatus.PENDING.value),
            "unavailable": sum(1 for entry in self.entries if entry.get("status") == ThreatIntelStatus.UNAVAILABLE.value),
        }
        return {
            "$schema": _SKILLS_RESCAN_SCHEMA_ID,
            "schema_version": _SKILLS_RESCAN_SCHEMA_VERSION,
            "report_type": "skills_rescan",
            "generated_at": _generated_at(),
            "catalog_path": self.catalog_path,
            "summary": summary,
            "entries": self.entries,
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


def _review_to_status(report: SkillFileReport) -> ThreatIntelStatus:
    """Map local trust verdicts to a stable rescan status."""
    if report.threat_intel is not None:
        return report.threat_intel.status
    verdict = report.trust.review_verdict.value
    if verdict == "trusted":
        return ThreatIntelStatus.CLEAN
    if verdict == "blocked":
        return ThreatIntelStatus.MALICIOUS
    return ThreatIntelStatus.SUSPICIOUS


def _build_skill_report(path: Path, *, intel_source: str | None = None) -> SkillFileReport:
    """Build the end-to-end report for one concrete instruction/skill file."""
    scan = parse_skill_file(path)
    audit = audit_skill_result(scan)
    trust = assess_trust(scan, audit)
    bundle = build_skill_bundle(path)
    threat_intel = lookup_bundle_threat_intel(bundle, intel_source)
    report = SkillFileReport(
        path=path,
        scan=scan,
        audit=audit,
        trust=trust,
        provenance=_provenance_to_dict(path),
        bundle=bundle,
        threat_intel=threat_intel,
    )
    report.status = _review_to_status(report).value
    return report


async def _build_skill_report_async(path: Path, *, intel_source: str | None = None) -> SkillFileReport:
    """Build one skill report off the event loop."""
    return await asyncio.to_thread(_build_skill_report, path, intel_source=intel_source)


def _catalog_entry_for_report(report: SkillFileReport) -> dict[str, object]:
    """Convert a file report into a persistent catalog entry."""
    timestamp = catalog_scan_timestamp()
    return {
        "path": str(report.path),
        "bundle": report.bundle.to_dict(),
        "status": report.status,
        "trust_verdict": report.trust.verdict.value,
        "review_verdict": report.trust.review_verdict.value,
        "provenance_status": report.provenance.get("status"),
        "findings": len(report.audit.findings),
        "threat_intel": report.threat_intel.to_dict() if report.threat_intel else None,
        "updated_at": timestamp,
        "last_seen": timestamp,
    }


def _persist_catalog(reports: list[SkillFileReport], catalog_path: str | Path | None) -> str | None:
    """Persist current scan state to the local skills catalog."""
    if not reports or catalog_path is None:
        return None
    catalog = load_skills_catalog(catalog_path)
    entries_obj = catalog.get("entries")
    entries = entries_obj if isinstance(entries_obj, dict) else {}
    for report in reports:
        stable_id = report.bundle.stable_id
        prior = entries.get(stable_id)
        prior_dict = prior if isinstance(prior, dict) else {}
        current = _catalog_entry_for_report(report)
        current["first_seen"] = prior_dict.get("first_seen") or current["last_seen"]
        entries[stable_id] = current
    catalog["entries"] = entries
    return str(save_skills_catalog(catalog, catalog_path))


def _run_async_sync(awaitable):
    """Run async work from sync callers, even when already inside an event loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(awaitable)

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(asyncio.run, awaitable)
        return future.result()


async def _scan_skill_targets_async(
    paths: Iterable[str | Path] | None = None,
    *,
    cwd: Path | None = None,
    intel_source: str | None = None,
    catalog_path: str | Path | None = None,
) -> SkillsScanReport:
    """Async implementation for scanning skill targets with bounded concurrency."""
    targets = resolve_skill_targets(paths, cwd=cwd)
    if not targets:
        return SkillsScanReport(files=[], catalog_path=None)

    sem = asyncio.Semaphore(_SKILLS_SCAN_CONCURRENCY)

    async def _scan_one(path: Path) -> SkillFileReport:
        async with sem:
            return await _build_skill_report_async(path, intel_source=intel_source)

    reports = await asyncio.gather(*[_scan_one(path) for path in targets])
    return SkillsScanReport(files=list(reports), catalog_path=_persist_catalog(list(reports), catalog_path))


def scan_skill_targets(
    paths: Iterable[str | Path] | None = None,
    *,
    cwd: Path | None = None,
    intel_source: str | None = None,
    catalog_path: str | Path | None = None,
) -> SkillsScanReport:
    """Scan one or more skill targets and return aggregate results."""
    return _run_async_sync(
        _scan_skill_targets_async(
            paths,
            cwd=cwd,
            intel_source=intel_source,
            catalog_path=catalog_path,
        )
    )


async def _rescan_skill_catalog_async(
    *,
    catalog_path: str | Path | None = None,
    intel_source: str | None = None,
) -> SkillsRescanReport:
    """Async implementation for rescanning cataloged skill bundles."""
    catalog = load_skills_catalog(catalog_path)
    entries_obj = catalog.get("entries")
    entries = entries_obj if isinstance(entries_obj, dict) else {}
    serialized: list[dict[str, object]] = []
    updated_entries: dict[str, object] = {}
    sem = asyncio.Semaphore(_SKILLS_SCAN_CONCURRENCY)

    async def _rescan_existing(
        stable_id: str, entry: dict[str, object], path: Path, path_str: str
    ) -> tuple[str, dict[str, object], dict[str, object]]:
        async with sem:
            report = await _build_skill_report_async(path, intel_source=intel_source)
        updated = _catalog_entry_for_report(report)
        updated["first_seen"] = entry.get("first_seen") or updated["last_seen"]
        serialized_entry = {
            "bundle_stable_id": stable_id,
            "path": path_str,
            "exists": True,
            "rescanned": True,
            "status": report.status,
            "trust_verdict": report.trust.verdict.value,
            "review_verdict": report.trust.review_verdict.value,
            "provenance_status": report.provenance.get("status"),
            "threat_intel": report.threat_intel.to_dict() if report.threat_intel else None,
            "findings": len(report.audit.findings),
            "last_seen": updated["last_seen"],
        }
        return stable_id, updated, serialized_entry

    pending: list[asyncio.Task[tuple[str, dict[str, object], dict[str, object]]]] = []
    for stable_id, raw_entry in sorted(entries.items()):
        entry = raw_entry if isinstance(raw_entry, dict) else {}
        path_str = str(entry.get("path") or "")
        path = Path(path_str)
        if path_str and path.exists():
            pending.append(asyncio.create_task(_rescan_existing(stable_id, entry, path, path_str)))
            continue

        status = ThreatIntelStatus.UNAVAILABLE.value
        updated = dict(entry)
        updated["status"] = status
        updated["last_seen"] = catalog_scan_timestamp()
        updated_entries[stable_id] = updated
        serialized.append(
            {
                "bundle_stable_id": stable_id,
                "path": path_str,
                "exists": False,
                "rescanned": False,
                "status": status,
                "trust_verdict": entry.get("trust_verdict"),
                "review_verdict": entry.get("review_verdict"),
                "provenance_status": entry.get("provenance_status"),
                "threat_intel": entry.get("threat_intel"),
                "findings": entry.get("findings", 0),
                "last_seen": updated["last_seen"],
                "error": "file not found",
            }
        )

    for stable_id, updated, serialized_entry in await asyncio.gather(*pending):
        updated_entries[stable_id] = updated
        serialized.append(serialized_entry)

    catalog["entries"] = updated_entries
    persisted = str(save_skills_catalog(catalog, catalog_path))
    return SkillsRescanReport(catalog_path=persisted, entries=serialized)


def rescan_skill_catalog(
    *,
    catalog_path: str | Path | None = None,
    intel_source: str | None = None,
) -> SkillsRescanReport:
    """Re-scan skill bundles tracked in the local catalog."""
    return _run_async_sync(_rescan_skill_catalog_async(catalog_path=catalog_path, intel_source=intel_source))


def verify_skill_targets(paths: Iterable[str | Path] | None = None, *, cwd: Path | None = None) -> list[dict[str, object]]:
    """Verify provenance for one or more skill targets."""
    return [
        {
            "path": str(path),
            **_provenance_to_dict(path),
        }
        for path in resolve_skill_targets(paths, cwd=cwd)
    ]
