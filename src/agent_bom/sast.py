"""SAST scanning via Semgrep or SARIF import for source code.

Runs Semgrep with SARIF output, normalizes findings into the agent-bom
data model (Package + Vulnerability objects), and provides structured
results for detailed file-level reporting.

Pattern mirrors ``image.py`` (Grype wrapper): subprocess → JSON parse →
normalize to internal data model → flow through standard pipeline.

Usage::

    from agent_bom.sast import scan_code, SASTScanError
    packages, sast_result = scan_code("/path/to/project")

If Semgrep is not installed, direct scans raise SASTScanError with install
guidance. Existing SARIF files can be imported without Semgrep.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

from agent_bom.models import Package, Severity, Vulnerability
from agent_bom.parsers.sarif import SarifValidationError, normalize_sarif_document

_logger = logging.getLogger(__name__)

_LOCAL_SAST_CONFIG_CANDIDATES = (
    ".agent-bom/rules",
    ".agent-bom/rules.yaml",
    ".agent-bom/rules.yml",
    ".agent-bom/sast-rules",
    ".agent-bom/sast-rules.yaml",
    ".agent-bom/sast-rules.yml",
    ".semgrep",
    ".semgrep.yaml",
    ".semgrep.yml",
)


class SASTExecutionStatus(str, Enum):
    """Typed outcome persisted for every SAST execution attempt."""

    FINDINGS = "findings"
    CLEAN = "clean"
    SKIPPED = "skipped"
    FAILED = "failed"


class SASTScanError(Exception):
    """Raised when SAST scanning cannot produce a complete result."""

    def __init__(
        self,
        message: str,
        *,
        execution_status: SASTExecutionStatus = SASTExecutionStatus.FAILED,
        reason_code: str = "scan_failed",
    ) -> None:
        super().__init__(message)
        self.execution_status = execution_status
        self.reason_code = reason_code


# ── Data models ─────────────────────────────────────────────────────────────


@dataclass
class SASTFinding:
    """A single SAST finding with file location metadata."""

    rule_id: str
    message: str
    severity: Severity
    file_path: str
    start_line: int
    end_line: int
    start_col: int = 0
    end_col: int = 0
    cwe_ids: list[str] = field(default_factory=list)
    owasp_ids: list[str] = field(default_factory=list)
    rule_url: Optional[str] = None
    snippet: Optional[str] = None
    tool_name: str = "external"
    security_severity: float | None = None
    fingerprints: dict[str, str] = field(default_factory=dict)
    partial_fingerprints: dict[str, str] = field(default_factory=dict)


@dataclass
class SASTResult:
    """Aggregated SAST scan results."""

    findings: list[SASTFinding] = field(default_factory=list)
    files_scanned: int = 0
    rules_loaded: int = 0
    scan_time_seconds: float = 0.0
    semgrep_version: Optional[str] = None
    config_used: str = "auto"
    execution_status: SASTExecutionStatus | None = None
    status_reason: str | None = None
    status_detail: str | None = None
    scanner_driver_id: str = "sast-semgrep"

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    def to_dict(self) -> dict:
        """Serialize for AIBOMReport.sast_data."""
        execution_status = self.execution_status or (SASTExecutionStatus.FINDINGS if self.findings else SASTExecutionStatus.CLEAN)
        return {
            "scanner_driver_id": self.scanner_driver_id,
            "execution_status": execution_status.value,
            "status_reason": self.status_reason,
            "status_detail": self.status_detail,
            "total_findings": self.total_findings,
            "files_scanned": self.files_scanned,
            "rules_loaded": self.rules_loaded,
            "scan_time_seconds": self.scan_time_seconds,
            "semgrep_version": self.semgrep_version,
            "config_used": self.config_used,
            "severity_counts": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": sum(1 for f in self.findings if f.severity == Severity.MEDIUM),
                "low": sum(1 for f in self.findings if f.severity == Severity.LOW),
            },
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "message": f.message,
                    "severity": f.severity.value,
                    "file_path": f.file_path,
                    "start_line": f.start_line,
                    "end_line": f.end_line,
                    "cwe_ids": f.cwe_ids,
                    "owasp_ids": f.owasp_ids,
                    "rule_url": f.rule_url,
                    "snippet": f.snippet,
                    "tool_name": f.tool_name,
                    "security_severity": f.security_severity,
                    "fingerprints": f.fingerprints,
                    "partial_fingerprints": f.partial_fingerprints,
                }
                for f in self.findings
            ],
        }


# ── Semgrep severity mapping ───────────────────────────────────────────────

_SARIF_LEVEL_MAP: dict[str, Severity] = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.NONE,
}


# ── Internal helpers ────────────────────────────────────────────────────────


def _semgrep_available() -> bool:
    return shutil.which("semgrep") is not None


def _is_sarif_input(path: Path) -> bool:
    name = path.name.lower()
    return name.endswith(".sarif") or name.endswith(".sarif.json")


def _get_semgrep_version() -> Optional[str]:
    try:
        result = subprocess.run(
            ["semgrep", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except Exception:  # noqa: BLE001
        _logger.debug("Could not determine Semgrep version")
        return None


def _discover_local_sast_configs(scan_root: Path) -> list[str]:
    search_roots = [scan_root]
    home_root = Path.home()
    if home_root not in search_roots:
        search_roots.append(home_root)

    discovered: list[str] = []
    seen: set[Path] = set()
    for root in search_roots:
        for candidate in _LOCAL_SAST_CONFIG_CANDIDATES:
            path = (root / candidate).expanduser()
            if not path.exists():
                continue
            resolved = path.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            discovered.append(str(resolved))
    return discovered


def _offline_config_error(*, no_local_config: bool = False) -> SASTScanError:
    reason_code = "offline_no_local_config" if no_local_config else "offline_remote_config"
    return SASTScanError(
        "Offline SAST requires an explicit local Semgrep rule file or directory.",
        execution_status=SASTExecutionStatus.SKIPPED,
        reason_code=reason_code,
    )


def _resolve_sast_configs(scan_target: Path, config: str, *, offline: bool = False) -> list[str]:
    project_root = scan_target if scan_target.is_dir() else scan_target.parent
    normalized = config.strip()

    if normalized in {"default", ""}:
        local_configs = _discover_local_sast_configs(project_root)
        if offline:
            if not local_configs:
                raise _offline_config_error(no_local_config=True)
            return local_configs
        return [*local_configs, "auto"] if local_configs else ["auto"]
    if normalized == "auto":
        if offline:
            raise _offline_config_error()
        return ["auto"]

    resolved_configs: list[str] = []
    for raw_part in normalized.split(","):
        part = raw_part.strip()
        if not part:
            continue
        if part.startswith(("http://", "https://", "ftp://")):
            raise SASTScanError(
                "Remote semgrep config URLs are not allowed. Use 'auto', 'default', "
                "'p/<ruleset>', a local file path, or ~/.agent-bom/rules/."
            )
        if part == "default":
            resolved_configs.extend(_resolve_sast_configs(scan_target, "default", offline=offline))
            continue
        if part == "auto" or part.startswith("p/"):
            if offline:
                raise _offline_config_error()
            resolved_configs.append(part)
            continue

        config_path = Path(part).expanduser()
        if not config_path.is_absolute():
            project_relative = (project_root / config_path).resolve()
            cwd_relative = (Path.cwd() / config_path).resolve()
            if project_relative.exists():
                config_path = project_relative
            elif cwd_relative.exists():
                config_path = cwd_relative
        if config_path.exists():
            resolved_configs.append(str(config_path.resolve()))
            continue

        raise SASTScanError(f"SAST config does not exist: {part}")

    deduped: list[str] = []
    seen_parts: set[str] = set()
    for part in resolved_configs:
        if part in seen_parts:
            continue
        seen_parts.add(part)
        deduped.append(part)
    if not deduped and offline:
        raise _offline_config_error(no_local_config=True)
    return deduped or ["auto"]


def _parse_sarif_findings(sarif: dict) -> tuple[list[SASTFinding], int, int]:
    """Project canonical SARIF records into SASTFinding objects.

    Returns (findings, rules_loaded, files_scanned).
    """
    document = normalize_sarif_document(sarif)
    findings: list[SASTFinding] = []
    for result in document.results:
        location = result.location
        level_severity = _SARIF_LEVEL_MAP.get(result.level or "warning", Severity.UNKNOWN)
        if result.security_severity is None:
            severity = level_severity
        elif result.security_severity >= 9.0:
            severity = Severity.CRITICAL
        elif result.security_severity >= 7.0:
            severity = Severity.HIGH
        elif result.security_severity >= 4.0:
            severity = Severity.MEDIUM
        elif result.security_severity > 0:
            severity = Severity.LOW
        else:
            severity = Severity.NONE
        findings.append(
            SASTFinding(
                rule_id=result.rule_id or "unknown",
                message=(result.message or result.rule_full_description or result.rule_short_description)[:500],
                severity=severity,
                file_path=location.uri if location is not None else "unknown",
                start_line=location.start_line if location is not None else 0,
                end_line=location.end_line if location is not None else 0,
                start_col=location.start_column if location is not None else 0,
                end_col=location.end_column if location is not None else 0,
                cwe_ids=[tag for tag in result.rule_tags if tag.upper().startswith("CWE-")],
                owasp_ids=[tag for tag in result.rule_tags if ":" in tag and tag.startswith("A")],
                rule_url=result.rule_url,
                snippet=(location.snippet[:200] if location and location.snippet else None),
                tool_name=result.tool_name,
                security_severity=result.security_severity,
                fingerprints=dict(result.fingerprints),
                partial_fingerprints=dict(result.partial_fingerprints),
            )
        )

    return findings, document.rules_loaded, document.files_scanned


def _findings_to_packages(findings: list[SASTFinding]) -> list[Package]:
    """Convert SAST findings into Package objects for the standard pipeline.

    Groups findings by file path.  Each unique file becomes a synthetic
    ``Package(ecosystem="sast")``, and each finding becomes a ``Vulnerability``
    on that package.  This allows SAST findings to flow through the standard
    ``scan_agents → BlastRadius → compliance tagging`` pipeline.
    """
    file_findings: dict[str, list[SASTFinding]] = {}
    for f in findings:
        file_findings.setdefault(f.file_path, []).append(f)

    packages: list[Package] = []
    for file_path, file_finds in file_findings.items():
        vulns: list[Vulnerability] = []
        seen_ids: set[str] = set()
        for finding in file_finds:
            vid = f"{finding.tool_name}:{finding.rule_id}:{finding.start_line}"
            if vid in seen_ids:
                continue
            seen_ids.add(vid)

            vulns.append(
                Vulnerability(
                    id=finding.rule_id,
                    summary=finding.message,
                    severity=finding.severity,
                    cwe_ids=finding.cwe_ids,
                    cvss_score=finding.security_severity,
                    references=[finding.rule_url] if finding.rule_url else [],
                )
            )

        if vulns:
            packages.append(
                Package(
                    name=file_path,
                    version="0.0.0",
                    ecosystem="sast",
                    vulnerabilities=vulns,
                    is_direct=True,
                )
            )

    return packages


def _import_sarif(path: Path) -> tuple[list[Package], SASTResult]:
    start = time.monotonic()
    try:
        sarif = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise SASTScanError(f"could not read SARIF file {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise SASTScanError(f"invalid SARIF file {path}") from exc

    try:
        findings, rules_loaded, files_scanned = _parse_sarif_findings(sarif)
    except SarifValidationError as exc:
        raise SASTScanError(f"invalid SARIF file {path}") from exc
    packages = _findings_to_packages(findings)
    result = SASTResult(
        findings=findings,
        files_scanned=files_scanned,
        rules_loaded=rules_loaded,
        scan_time_seconds=round(time.monotonic() - start, 2),
        semgrep_version=None,
        config_used="sarif-import",
    )
    _logger.info(
        "Imported SARIF SAST results: %d finding(s) in %d file(s) from %s",
        result.total_findings,
        files_scanned,
        path,
    )
    return packages, result


# ── Public API ──────────────────────────────────────────────────────────────


def scan_code(
    path: str,
    config: str = "auto",
    timeout: int = 600,
    *,
    offline: bool = False,
) -> tuple[list[Package], SASTResult]:
    """Run Semgrep SAST scan on source code or import a SARIF file.

    Args:
        path: Directory or file to scan, or an existing ``.sarif`` / ``.sarif.json`` file.
        config: Semgrep config selection. ``"auto"`` uses the Semgrep registry.
                ``"default"`` prefers local rule bundles when present and falls
                back to ``auto``. Can also be a local file/directory, a
                ``p/<ruleset>`` registry ref, or a comma-separated list.
        timeout: Subprocess timeout in seconds.
        offline: Require local Semgrep rules and prohibit registry-backed
                 ``auto`` / ``p/<ruleset>`` configurations.

    Returns:
        Tuple of (packages_with_vulns, structured_sast_result).

    Raises:
        SASTScanError: If Semgrep is not installed or scan fails.
    """
    resolved = Path(path).resolve()
    if _is_sarif_input(resolved):
        if not resolved.exists():
            raise SASTScanError(f"Path does not exist: {path}")
        return _import_sarif(resolved)

    if not _semgrep_available():
        raise SASTScanError(
            "semgrep not found on PATH. Install with: pip install semgrep (or see https://semgrep.dev/docs/getting-started/)",
            execution_status=SASTExecutionStatus.SKIPPED,
            reason_code="semgrep_unavailable",
        )

    if not resolved.exists():
        raise SASTScanError(f"Path does not exist: {path}")

    resolved_configs = _resolve_sast_configs(resolved, config, offline=offline)

    start = time.monotonic()

    cmd = ["semgrep", "--sarif"]
    for resolved_config in resolved_configs:
        cmd.extend(["--config", resolved_config])
    cmd.extend(["--quiet", str(resolved)])

    _logger.info("Running SAST scan: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        raise SASTScanError("semgrep not found on PATH")
    except subprocess.TimeoutExpired:
        raise SASTScanError(f"semgrep timed out after {timeout}s scanning {path}")

    # Semgrep exit codes: 0 = clean, 1 = findings found (both are success)
    # Exit code 2+ = actual error
    if result.returncode > 1:
        _logger.warning("Semgrep exited with a scanner error (code %d)", result.returncode)
        raise SASTScanError(
            f"semgrep exited {result.returncode}",
            reason_code="semgrep_failed",
        )

    try:
        sarif = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise SASTScanError(
            "semgrep produced invalid SARIF output",
            reason_code="invalid_semgrep_output",
        ) from exc

    elapsed = time.monotonic() - start

    try:
        findings, rules_loaded, files_scanned = _parse_sarif_findings(sarif)
    except SarifValidationError as exc:
        raise SASTScanError(
            "semgrep produced structurally invalid SARIF output",
            reason_code="invalid_semgrep_output",
        ) from exc
    packages = _findings_to_packages(findings)

    sast_result = SASTResult(
        findings=findings,
        files_scanned=files_scanned,
        rules_loaded=rules_loaded,
        scan_time_seconds=round(elapsed, 2),
        semgrep_version=_get_semgrep_version(),
        config_used=",".join(resolved_configs),
    )

    _logger.info(
        "SAST scan complete: %d finding(s) in %d file(s) (%d rules, %.1fs)",
        sast_result.total_findings,
        files_scanned,
        rules_loaded,
        elapsed,
    )

    return packages, sast_result
