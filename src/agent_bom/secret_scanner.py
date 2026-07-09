"""General-purpose secret scanner — beyond MCP config credential detection.

Scans source files, config files, and environment files for hardcoded
secrets using the same 34 credential patterns + 11 PII patterns from
the runtime detector library.

This extends agent-bom's secret detection from MCP configs (where it
looks at env var names) to actual file contents (where it finds values).

Usage::

    from agent_bom.secret_scanner import scan_secrets

    findings = scan_secrets("/path/to/project")
    for f in findings:
        line = f"{f['file']}:{f['line']} [{f['severity']}] {f['type']}"

Compliance:
- OWASP LLM01 — hardcoded credentials enable account takeover
- CIS Controls 16.4 — encrypt or remove hardcoded secrets
- SOC 2 CC6.1 — logical access security
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from agent_bom.runtime.patterns import CODE_CALL_ASSIGNMENT, CREDENTIAL_PATTERNS, PII_PATTERNS

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

_PII_SCAN_EXTENSIONS = frozenset({".env", ".yaml", ".yml", ".json", ".conf"})
_PII_CODE_EXTENSIONS = frozenset(
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
        ".toml",
        ".ini",
        ".cfg",
        ".properties",
        ".tf",
        ".hcl",
        ".sh",
        ".bash",
        ".zsh",
        ".ps1",
    }
)
_PII_CONTEXT_RE = re.compile(
    r"(?:=|:|\b(?:addr|address|allowlist|bind|database|endpoint|host|ip|listen|proxy|redis|server|url|uri)\b)",
    re.IGNORECASE,
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

# ── Entropy detection (opt-in) ───────────────────────────────────────────────
# The named patterns above catch known credential *formats*. Entropy detection
# catches novel/unknown secrets — a high-randomness value assigned to a
# secret-suggesting key — that no fixed pattern names. Opt-in (--detect-entropy)
# because, even constrained to secret-named keys, it can surface false positives
# (hashes, UUIDs, build IDs) that a baseline/allowlist would otherwise suppress.
import math  # noqa: E402

_ENTROPY_MIN_LEN = 20
_ENTROPY_THRESHOLD = 3.5  # bits/char; base64-ish secrets score ~4.5-6, prose ~3
# key suggests a secret, then capture the assigned value (quoted or bare).
_ENTROPY_ASSIGN_RE = re.compile(
    r"""(?ix)
    (?:secret|token|password|passwd|pwd|api[_-]?key|access[_-]?key|
       client[_-]?secret|auth|credential|private[_-]?key|apikey|bearer)
    \w* \s* [=:] \s*
    ['"]? ([A-Za-z0-9+/=_\-\.]{%d,}) ['"]?
    """
    % _ENTROPY_MIN_LEN
)
# Obvious non-secrets to skip even when assigned to a secret-named key.
_ENTROPY_PLACEHOLDER_RE = re.compile(
    r"(?i)^(?:your[_-]|xxx|placeholder|example|changeme|none|null|true|false|enabled|disabled|"
    r"\$\{|\{\{|<[a-z]|/[a-z]|https?://|[a-z]+(?:[._-][a-z]+)+$)"
)


def _shannon_entropy(value: str) -> float:
    """Shannon entropy in bits/char — high for random tokens, low for words."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _entropy_findings(line: str, rel_path: str, line_num: int) -> list[SecretFinding]:
    """Flag a high-entropy value assigned to a secret-suggesting key."""
    out: list[SecretFinding] = []
    for match in _ENTROPY_ASSIGN_RE.finditer(line):
        value = match.group(1)
        if len(value) < _ENTROPY_MIN_LEN or _ENTROPY_PLACEHOLDER_RE.search(value):
            continue
        if _shannon_entropy(value) < _ENTROPY_THRESHOLD:
            continue
        out.append(
            SecretFinding(
                file_path=rel_path,
                line_number=line_num,
                secret_type="High-entropy secret",
                severity="high",
                matched_preview="[ENTROPY_REDACTED]",
                category="entropy",
            )
        )
        break  # one entropy finding per line is enough
    return out


# ── Data model ───────────────────────────────────────────────────────────────


@dataclass
class SecretFinding:
    """A hardcoded secret found in a source/config file."""

    file_path: str
    line_number: int
    secret_type: str  # "AWS Access Key", "Email Address", etc.
    severity: str  # "critical", "high", "medium"
    matched_preview: str  # redacted evidence label; never includes matched bytes
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


def _is_agent_bom_report(content: str) -> bool:
    """Return True when *content* is one of agent-bom's own machine reports.

    Re-scanning a previously written report (JSON AI-BOM, SARIF, or the CSV
    finding export) for secrets flags the report's own numeric payload — scan
    ids, CVSS scores, timestamps — as PII/credentials, inflating and
    destabilizing finding counts on repeat scans of a directory that holds prior
    output. Our own output is never a secret source, so skip it.
    """
    head = content[:4096]
    if '"document_type": "AI-BOM"' in head or '"document_type":"AI-BOM"' in head:
        return True
    if '"$schema"' in head and "sarif" in head.lower() and '"runs"' in head:
        return True
    return head.startswith("cve_id,package,version,ecosystem,severity") or head.startswith(
        "﻿cve_id,package,version,ecosystem,severity"
    )


def _scan_file(file_path: Path, rel_path: str, *, detect_entropy: bool = False) -> list[SecretFinding]:
    """Scan a single file for secrets."""
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    if len(content) > _MAX_FILE_SIZE:
        return []

    if _is_agent_bom_report(content):
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
            match = pattern.search(line)
            if match:
                # A secret-named variable assigned to a function/method call
                # (e.g. OAuth token minting:
                # `access_token = self.signing_key.sign(claims)`) is derived
                # code, not a hardcoded literal. The generic patterns capture
                # the value as an identifier/attribute chain; if it is
                # immediately called, suppress the false positive. A real
                # literal passed as a call argument (e.g. `k = load("AKIA...")`)
                # still matches on the literal itself, whose match is not
                # call-shaped here, so it is preserved.
                if line[match.end() :].lstrip().startswith("(") and CODE_CALL_ASSIGNMENT.search(line):
                    break
                findings.append(
                    SecretFinding(
                        file_path=rel_path,
                        line_number=line_num,
                        secret_type=name,
                        severity="critical",
                        matched_preview="[CREDENTIAL_REDACTED]",
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
                        matched_preview="[SECRET_REDACTED]",
                        category="secret",
                    )
                )
                break

        # PII patterns (MEDIUM) stay limited to structured config/secrets
        # surfaces and config-like code lines. Markdown/plain-text docs are
        # still scanned for credentials above, but generic emails/IPs there
        # are usually examples or contacts.
        if _should_scan_pii_line(file_path, line):
            for name, pattern in PII_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        SecretFinding(
                            file_path=rel_path,
                            line_number=line_num,
                            secret_type=name,
                            severity="medium",
                            matched_preview="[PII_REDACTED]",
                            category="pii",
                        )
                    )
                    break

        # Entropy detection runs only on lines no named pattern already flagged,
        # so it adds coverage for novel secrets instead of duplicating findings.
        if detect_entropy and not any(f.line_number == line_num for f in findings):
            findings.extend(_entropy_findings(line, rel_path, line_num))

    return findings


def _should_scan_pii_line(file_path: Path, line: str) -> bool:
    """Limit generic PII checks to structured or config-like file content."""
    suffix = file_path.suffix.lower()
    if suffix in _PII_SCAN_EXTENSIONS or file_path.name in _SCAN_FILENAMES:
        return True
    return suffix in _PII_CODE_EXTENSIONS and bool(_PII_CONTEXT_RE.search(line))


def scan_secrets(project_path: str | Path, *, detect_entropy: bool = False) -> SecretScanResult:
    """Scan a project directory for hardcoded secrets and PII.

    Uses the same 31 credential + 11 PII patterns from the runtime
    detector library, plus 4 file-specific patterns for .env files
    and hardcoded passwords.

    Args:
        project_path: Root directory to scan.
        detect_entropy: Also flag high-entropy values assigned to
            secret-suggesting keys (novel/unknown secrets no fixed pattern
            names). Opt-in — higher recall, some false positives.

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
        findings = _scan_file(f, rel, detect_entropy=detect_entropy)
        result.findings.extend(findings)

    result.files_scanned = file_count
    return result
