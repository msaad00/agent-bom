"""Secret findings and explicit collection coverage receipts."""

from __future__ import annotations

from dataclasses import dataclass, field

from agent_bom.scanners.credential_validation import ValidationStatus


@dataclass
class SecretFinding:
    """A hardcoded secret found in a source/config file."""

    file_path: str
    line_number: int
    secret_type: str  # "AWS Access Key", "Email Address", etc.
    severity: str  # "critical", "high", "medium"
    matched_preview: str  # redacted evidence label; never includes matched bytes
    category: str  # "credential", "pii", "secret"
    validation_status: ValidationStatus | None = None

    def to_dict(self) -> dict:
        return {
            "file": self.file_path,
            "line": self.line_number,
            "type": self.secret_type,
            "severity": self.severity,
            "preview": self.matched_preview,
            "category": self.category,
            **({"validation_status": self.validation_status} if self.validation_status is not None else {}),
        }


@dataclass
class SecretScanResult:
    """Complete secret scan results for a project."""

    findings: list[SecretFinding] = field(default_factory=list)
    files_scanned: int = 0
    warnings: list[str] = field(default_factory=list)
    exclusions: list[str] = field(default_factory=list)
    # Paths excluded by repository ignore rules. Skipping is a coverage claim,
    # so it is counted and reported rather than silently dropped.
    ignored_paths: int = 0
    pruned_directories: int = 0

    @property
    def total(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    def to_dict(self) -> dict:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "files_scanned": self.files_scanned,
            "ignored_paths": self.ignored_paths,
            "pruned_directories": self.pruned_directories,
            "total": self.total,
            "critical": self.critical_count,
            "by_type": _group_by(self.findings, "secret_type"),
            "by_category": _group_by(self.findings, "category"),
            # A refused path or a file-capped walk both report ``total: 0``.
            # Without the warnings that reads as "this tree holds no secrets"
            # instead of "we did not finish looking".
            "warnings": list(self.warnings),
            "exclusions": list(self.exclusions),
            "complete": not self.warnings,
        }

    def record_exclusions(self, ignored_paths: int, unsafe_pruned: int) -> None:
        """Expose scope boundaries separately from failures inside that scope."""
        self.ignored_paths = ignored_paths
        intentional = self.pruned_directories - unsafe_pruned
        if intentional:
            self.exclusions.append(
                f"Excluded {intentional} directory subtree(s) by scanner policy or duplicate-worktree rules; "
                "their contents were outside the configured scope. Scan an excluded root explicitly to inspect it."
            )
        if ignored_paths:
            self.exclusions.append(f"Excluded {ignored_paths} path(s) by repository ignore rules.")
        if unsafe_pruned:
            self.warnings.append(f"Skipped {unsafe_pruned} directory symlink(s); their contents were not inspected.")


def _group_by(findings: list[SecretFinding], attr: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        key = getattr(f, attr)
        counts[key] = counts.get(key, 0) + 1
    return counts
