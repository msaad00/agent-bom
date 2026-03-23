"""General-purpose secret scanner — beyond MCP config credential detection.

Scans source files, config files, and environment files for hardcoded
secrets using the same 31 credential patterns + 11 PII patterns from
the runtime detector library.

This extends agent-bom's secret detection from MCP configs (where it
looks at env var names) to actual file contents (where it finds values).

Usage::

    from agent_bom.secret_scanner import scan_secrets

    findings = scan_secrets("/path/to/project")
    for f in findings:
        print(f"{f['file']}:{f['line']} [{f['severity']}] {f['type']}")

Compliance:
- OWASP LLM01 — hardcoded credentials enable account takeover
- CIS Controls 16.4 — encrypt or remove hardcoded secrets
- SOC 2 CC6.1 — logical access security
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from agent_bom.runtime.patterns import CREDENTIAL_PATTERNS, PII_PATTERNS

# ── Config ───────────────────────────────────────────────────────────────────

_SKIP_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        "env",
        "dist",
        "build",
        "site-packages",
        ".tox",
        ".eggs",
        ".mypy_cache",
        "tests",
        "test",
        "testing",
        "fixtures",
        "fuzz",
        ".claude",  # Claude Code worktrees
        ".codex",  # Codex worktrees
    }
)

# Files that contain pattern definitions or test data — skip to avoid FP
_SKIP_FILES = frozenset(
    {
        "patterns.py",
        "conftest.py",
    }
)

_SCAN_EXTENSIONS = frozenset(
    {
        ".py",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".go",
        ".rs",
        ".java",
        ".rb",
        ".php",
        ".yaml",
        ".yml",
        ".json",
        ".toml",
        ".ini",
        ".cfg",
        ".env",
        ".conf",
        ".properties",
        ".tf",
        ".hcl",
        ".sh",
        ".bash",
        ".zsh",
        ".ps1",
        ".md",
        ".txt",
    }
)

# Files to always scan regardless of extension
_SCAN_FILENAMES = frozenset(
    {
        ".env",
        ".env.local",
        ".env.production",
        ".env.development",
        "Dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        ".npmrc",
        ".pypirc",
        ".netrc",
        ".gitconfig",
    }
)

_MAX_FILE_SIZE = 1024 * 1024  # 1MB
_MAX_FILES = 1000

# Additional patterns specific to file scanning (not in runtime patterns)
_FILE_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("Hardcoded password", re.compile(r'(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\']{8,}["\']', re.IGNORECASE)),
    ("Hardcoded secret", re.compile(r'(?:secret|secret_key)\s*[=:]\s*["\'][^"\']{8,}["\']', re.IGNORECASE)),
    (
        ".env password",
        re.compile(r"^(?:DB_PASSWORD|DATABASE_PASSWORD|REDIS_PASSWORD|MYSQL_PASSWORD)\s*=\s*\S+", re.MULTILINE | re.IGNORECASE),
    ),
    (".env token", re.compile(r"^(?:AUTH_TOKEN|ACCESS_TOKEN|REFRESH_TOKEN|SESSION_SECRET)\s*=\s*\S+", re.MULTILINE | re.IGNORECASE)),
]


# ── Data model ───────────────────────────────────────────────────────────────


@dataclass
class SecretFinding:
    """A hardcoded secret found in a source/config file."""

    file_path: str
    line_number: int
    secret_type: str  # "AWS Access Key", "Email Address", etc.
    severity: str  # "critical", "high", "medium"
    matched_preview: str  # First 8 chars + "..." (never the full secret)
    category: str  # "credential", "pii", "secret"

    def to_dict(self) -> dict:
        return {
            "file": self.file_path,
            "line": self.line_number,
            "type": self.secret_type,
            "severity": self.severity,
            "preview": self.matched_preview,
            "category": self.category,
        }


@dataclass
class SecretScanResult:
    """Complete secret scan results for a project."""

    findings: list[SecretFinding] = field(default_factory=list)
    files_scanned: int = 0
    warnings: list[str] = field(default_factory=list)

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
            "total": self.total,
            "critical": self.critical_count,
            "by_type": _group_by(self.findings, "secret_type"),
            "by_category": _group_by(self.findings, "category"),
        }


def _group_by(findings: list[SecretFinding], attr: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        key = getattr(f, attr)
        counts[key] = counts.get(key, 0) + 1
    return counts


# ── Scanner ──────────────────────────────────────────────────────────────────


def _should_scan(path: Path) -> bool:
    """Check if a file should be scanned."""
    if any(part in _SKIP_DIRS for part in path.parts):
        return False
    # Skip pattern definition files and test fixtures
    if path.name in _SKIP_FILES:
        return False
    if path.name.startswith("test_") or path.name.endswith("_test.py"):
        return False
    if path.name in _SCAN_FILENAMES:
        return True
    return path.suffix.lower() in _SCAN_EXTENSIONS


def _scan_file(file_path: Path, rel_path: str) -> list[SecretFinding]:
    """Scan a single file for secrets."""
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    if len(content) > _MAX_FILE_SIZE:
        return []

    findings: list[SecretFinding] = []
    lines = content.split("\n")

    # Check each line against all patterns
    for line_num, line in enumerate(lines, 1):
        # Skip comments
        stripped = line.strip()
        if stripped.startswith(("#", "//", "/*", "*")):
            continue

        # Credential patterns (CRITICAL)
        for name, pattern in CREDENTIAL_PATTERNS:
            if pattern.search(line):
                match = pattern.search(line)
                preview = match.group(0)[:8] + "..." if match else "..."
                findings.append(
                    SecretFinding(
                        file_path=rel_path,
                        line_number=line_num,
                        secret_type=name,
                        severity="critical",
                        matched_preview=preview,
                        category="credential",
                    )
                )
                break  # One finding per line for credentials

        # File-specific secret patterns (HIGH)
        for name, pattern in _FILE_SECRET_PATTERNS:
            if pattern.search(line):
                findings.append(
                    SecretFinding(
                        file_path=rel_path,
                        line_number=line_num,
                        secret_type=name,
                        severity="high",
                        matched_preview="***",
                        category="secret",
                    )
                )
                break

        # PII patterns (MEDIUM) — only in non-code files
        if file_path.suffix in (".env", ".yaml", ".yml", ".json", ".txt", ".md", ".conf"):
            for name, pattern in PII_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        SecretFinding(
                            file_path=rel_path,
                            line_number=line_num,
                            secret_type=name,
                            severity="medium",
                            matched_preview="[PII]",
                            category="pii",
                        )
                    )
                    break

    return findings


def scan_secrets(project_path: str | Path) -> SecretScanResult:
    """Scan a project directory for hardcoded secrets and PII.

    Uses the same 31 credential + 11 PII patterns from the runtime
    detector library, plus 4 file-specific patterns for .env files
    and hardcoded passwords.

    Args:
        project_path: Root directory to scan.

    Returns:
        SecretScanResult with findings, file count, and statistics.
    """
    project = Path(project_path)
    if not project.is_dir():
        return SecretScanResult(warnings=[f"{project_path} is not a directory"])

    result = SecretScanResult()
    file_count = 0

    for f in sorted(project.rglob("*")):
        if not f.is_file():
            continue
        if not _should_scan(f):
            continue
        if file_count >= _MAX_FILES:
            result.warnings.append(f"Stopped at {_MAX_FILES} files")
            break

        file_count += 1
        rel = str(f.relative_to(project))
        findings = _scan_file(f, rel)
        result.findings.extend(findings)

    result.files_scanned = file_count
    return result
