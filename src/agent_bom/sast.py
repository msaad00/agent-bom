"""SAST scanning via Semgrep — static analysis for source code.

Runs Semgrep with SARIF output, normalizes findings into the agent-bom
data model (Package + Vulnerability objects), and provides structured
results for detailed file-level reporting.

Pattern mirrors ``image.py`` (Grype wrapper): subprocess → JSON parse →
normalize to internal data model → flow through standard pipeline.

Usage::

    from agent_bom.sast import scan_code, SASTScanError
    packages, sast_result = scan_code("/path/to/project")

If Semgrep is not installed, raises SASTScanError with install guidance.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from agent_bom.models import Package, Severity, Vulnerability

_logger = logging.getLogger(__name__)


class SASTScanError(Exception):
    """Raised when SAST scanning fails."""


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


@dataclass
class SASTResult:
    """Aggregated SAST scan results."""

    findings: list[SASTFinding] = field(default_factory=list)
    files_scanned: int = 0
    rules_loaded: int = 0
    scan_time_seconds: float = 0.0
    semgrep_version: Optional[str] = None
    config_used: str = "auto"

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
        return {
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


def _get_semgrep_version() -> Optional[str]:
    try:
        result = subprocess.run(
            ["semgrep", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except Exception:
        return None


def _parse_sarif_findings(sarif: dict) -> tuple[list[SASTFinding], int, int]:
    """Parse Semgrep SARIF output into SASTFinding objects.

    Returns (findings, rules_loaded, files_scanned).
    """
    findings: list[SASTFinding] = []
    files_seen: set[str] = set()
    rules_loaded = 0

    for run in sarif.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        rules = {r["id"]: r for r in driver.get("rules", [])}
        rules_loaded = max(rules_loaded, len(rules))

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            level = result.get("level", "warning")
            message = result.get("message", {}).get("text", "")

            # Extract location
            locations = result.get("locations", [])
            if not locations:
                continue
            loc = locations[0].get("physicalLocation", {})
            artifact = loc.get("artifactLocation", {}).get("uri", "")
            region = loc.get("region", {})
            start_line = region.get("startLine", 0)
            end_line = region.get("endLine", start_line)
            start_col = region.get("startColumn", 0)
            end_col = region.get("endColumn", 0)
            snippet_obj = region.get("snippet", {})
            snippet = snippet_obj.get("text") if snippet_obj else None

            files_seen.add(artifact)

            severity = _SARIF_LEVEL_MAP.get(level, Severity.MEDIUM)

            # Extract CWE IDs and OWASP tags from rule metadata
            rule_meta = rules.get(rule_id, {})
            rule_props = rule_meta.get("properties", {})
            tags = rule_props.get("tags", [])
            cwe_ids = [t for t in tags if t.upper().startswith("CWE-")]
            owasp_ids = [t for t in tags if ":" in t and t[0] == "A"]

            rule_url = rule_meta.get("helpUri")

            findings.append(
                SASTFinding(
                    rule_id=rule_id,
                    message=message[:500],
                    severity=severity,
                    file_path=artifact,
                    start_line=start_line,
                    end_line=end_line,
                    start_col=start_col,
                    end_col=end_col,
                    cwe_ids=cwe_ids,
                    owasp_ids=owasp_ids,
                    rule_url=rule_url,
                    snippet=snippet[:200] if snippet else None,
                )
            )

    return findings, rules_loaded, len(files_seen)


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
            vid = f"{finding.rule_id}:{finding.start_line}"
            if vid in seen_ids:
                continue
            seen_ids.add(vid)

            vulns.append(
                Vulnerability(
                    id=finding.rule_id,
                    summary=finding.message,
                    severity=finding.severity,
                    cwe_ids=finding.cwe_ids,
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


# ── Public API ──────────────────────────────────────────────────────────────


def scan_code(
    path: str,
    config: str = "auto",
    timeout: int = 600,
) -> tuple[list[Package], SASTResult]:
    """Run Semgrep SAST scan on source code.

    Args:
        path: Directory or file to scan.
        config: Semgrep config (default ``"auto"`` = Semgrep Registry).
                Can be a path to custom rules YAML or registry string.
        timeout: Subprocess timeout in seconds.

    Returns:
        Tuple of (packages_with_vulns, structured_sast_result).

    Raises:
        SASTScanError: If Semgrep is not installed or scan fails.
    """
    if not _semgrep_available():
        raise SASTScanError(
            "semgrep not found on PATH. Install with: pip install semgrep (or see https://semgrep.dev/docs/getting-started/)"
        )

    resolved = Path(path).resolve()
    if not resolved.exists():
        raise SASTScanError(f"Path does not exist: {path}")

    # Validate config: only allow safe values (no URLs that could exfiltrate code)
    if config.startswith(("http://", "https://", "ftp://")):
        raise SASTScanError("Remote semgrep config URLs are not allowed. Use 'auto', 'p/<ruleset>', or a local file path.")

    start = time.monotonic()

    cmd = [
        "semgrep",
        "--sarif",
        "--config",
        config,
        "--quiet",
        str(resolved),
    ]

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
        stderr = result.stderr.strip()
        raise SASTScanError(f"semgrep exited {result.returncode}: {stderr[:300]}")

    try:
        sarif = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise SASTScanError(f"semgrep produced invalid SARIF output: {e}")

    elapsed = time.monotonic() - start

    findings, rules_loaded, files_scanned = _parse_sarif_findings(sarif)
    packages = _findings_to_packages(findings)

    sast_result = SASTResult(
        findings=findings,
        files_scanned=files_scanned,
        rules_loaded=rules_loaded,
        scan_time_seconds=round(elapsed, 2),
        semgrep_version=_get_semgrep_version(),
        config_used=config,
    )

    _logger.info(
        "SAST scan complete: %d finding(s) in %d file(s) (%d rules, %.1fs)",
        sast_result.total_findings,
        files_scanned,
        rules_loaded,
        elapsed,
    )

    return packages, sast_result
