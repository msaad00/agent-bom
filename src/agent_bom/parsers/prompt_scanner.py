"""Prompt template and system prompt file scanner.

Discovers and analyzes prompt template files for security risks:
- Credential/secret leakage in prompt text
- Prompt injection vectors (jailbreak patterns, role overrides)
- Unsafe instructions (shell access, file write, network exfil)
- Hardcoded API keys, tokens, passwords in prompt content
- Excessive permission grants in system prompts
- Data exfiltration instructions (send data to URLs, webhooks)

Supported file types:
  .prompt, .promptfile, .system-prompt, .jinja2, .j2, .hbs, .mustache
  system_prompt.txt, system_prompt.md, system_prompt.yaml, system_prompt.json
  prompt.yaml, prompt.json, prompts/, prompt_templates/
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# ── File discovery patterns ──────────────────────────────────────────────────

PROMPT_FILE_EXTENSIONS = {
    ".prompt", ".promptfile", ".system-prompt",
    ".jinja2", ".j2", ".hbs", ".mustache",
}

PROMPT_FILE_NAMES = {
    "system_prompt.txt", "system_prompt.md",
    "system_prompt.yaml", "system_prompt.yml", "system_prompt.json",
    "prompt.yaml", "prompt.yml", "prompt.json",
    "user_prompt.txt", "user_prompt.md",
    "agent_prompt.txt", "agent_prompt.md",
    "instructions.txt", "instructions.md",
}

PROMPT_DIR_NAMES = {
    "prompts", "prompt_templates", "prompt-templates",
    "system_prompts", "system-prompts",
}

# Directories to skip during scanning
_SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    ".tox", ".mypy_cache", ".ruff_cache", "dist", "build",
    ".eggs", "*.egg-info",
}


# ── Data structures ──────────────────────────────────────────────────────────


@dataclass
class PromptFinding:
    """A single security finding from prompt template analysis."""

    severity: str  # "critical" | "high" | "medium" | "low"
    category: str
    title: str
    detail: str
    source_file: str
    line_number: int | None = None
    matched_text: str = ""
    recommendation: str = ""


@dataclass
class PromptScanResult:
    """Aggregated result of prompt template scanning."""

    files_scanned: int = 0
    findings: list[PromptFinding] = field(default_factory=list)
    prompt_files: list[str] = field(default_factory=list)
    passed: bool = True  # no critical/high findings


# ── Security patterns ────────────────────────────────────────────────────────

# Hardcoded secrets (critical)
_SECRET_PATTERNS = [
    (
        re.compile(r"""(?:api[_-]?key|apikey)\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?""", re.IGNORECASE),
        "Hardcoded API key",
    ),
    (
        re.compile(r"""(?:secret|password|passwd|pwd)\s*[:=]\s*['"]?([^\s'"]{8,})['"]?""", re.IGNORECASE),
        "Hardcoded secret/password",
    ),
    (
        re.compile(r"""(?:token)\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?""", re.IGNORECASE),
        "Hardcoded token",
    ),
    (
        re.compile(r"""sk-[A-Za-z0-9]{20,}"""),
        "OpenAI API key pattern",
    ),
    (
        re.compile(r"""ghp_[A-Za-z0-9]{36}"""),
        "GitHub personal access token",
    ),
    (
        re.compile(r"""gho_[A-Za-z0-9]{36}"""),
        "GitHub OAuth token",
    ),
    (
        re.compile(r"""xox[bporas]-[A-Za-z0-9\-]{10,}"""),
        "Slack token",
    ),
    (
        re.compile(r"""AKIA[A-Z0-9]{16}"""),
        "AWS access key ID",
    ),
    (
        re.compile(r"""-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----"""),
        "Private key in prompt",
    ),
]

# Prompt injection / jailbreak patterns (high)
_INJECTION_PATTERNS = [
    (
        re.compile(
            r"""ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?|constraints?)""",
            re.IGNORECASE,
        ),
        "Prompt injection: ignore previous instructions",
    ),
    (
        re.compile(
            r"""you\s+are\s+now\s+(DAN|unrestricted|jailbroken|evil)""",
            re.IGNORECASE,
        ),
        "Jailbreak pattern: role override",
    ),
    (
        re.compile(
            r"""(?:system\s+)?prompt\s*[:=]\s*['"]?override""",
            re.IGNORECASE,
        ),
        "Prompt override instruction",
    ),
    (
        re.compile(
            r"""forget\s+(everything|all|your)\s+(you|instructions?|training)""",
            re.IGNORECASE,
        ),
        "Memory/instruction wipe pattern",
    ),
    (
        re.compile(
            r"""do\s+not\s+follow\s+(any\s+)?safety\s+(guidelines?|rules?|policies?)""",
            re.IGNORECASE,
        ),
        "Safety bypass instruction",
    ),
    (
        re.compile(
            r"""act\s+as\s+(if\s+)?(?:you\s+have\s+)?no\s+(restrictions?|limitations?|rules?)""",
            re.IGNORECASE,
        ),
        "Restriction removal pattern",
    ),
]

# Unsafe instructions (high)
_UNSAFE_INSTRUCTION_PATTERNS = [
    (
        re.compile(
            r"""(?:execute|run|invoke)\s+(?:any\s+)?(?:shell|bash|cmd|system)\s+command""",
            re.IGNORECASE,
        ),
        "Shell execution instruction",
    ),
    (
        re.compile(
            r"""(?:send|post|upload|exfiltrate)\s+(?:data|results?|output)\s+to\s+(?:https?://|webhook)""",
            re.IGNORECASE,
        ),
        "Data exfiltration instruction",
    ),
    (
        re.compile(
            r"""(?:write|create|modify|delete)\s+(?:any\s+)?(?:file|directory)""",
            re.IGNORECASE,
        ),
        "Filesystem write instruction",
    ),
    (
        re.compile(
            r"""(?:curl|wget|fetch|request)\s+(?:https?://)\S+""",
            re.IGNORECASE,
        ),
        "External HTTP request in prompt",
    ),
    (
        re.compile(
            r"""(?:install|pip\s+install|npm\s+install|apt\s+install)\s+""",
            re.IGNORECASE,
        ),
        "Package installation instruction",
    ),
]

# Excessive permission patterns (medium)
_PERMISSION_PATTERNS = [
    (
        re.compile(
            r"""(?:you\s+(?:have|are\s+granted))\s+(?:(?:full|unrestricted|unlimited)\s+)+(?:(?:unrestricted|unlimited)\s+)?(?:access|permissions?)""",
            re.IGNORECASE,
        ),
        "Unrestricted access grant",
    ),
    (
        re.compile(
            r"""(?:no\s+(?:need\s+(?:to|for)|)\s*(?:ask|confirm|verify|check)\s+(?:before|with))""",
            re.IGNORECASE,
        ),
        "Confirmation bypass instruction",
    ),
    (
        re.compile(
            r"""(?:admin|root|superuser|elevated)\s+(?:mode|privileges?|access|permissions?)""",
            re.IGNORECASE,
        ),
        "Elevated privilege reference",
    ),
]

# Sensitive data patterns in prompt content (medium)
_SENSITIVE_DATA_PATTERNS = [
    (
        re.compile(r"""\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b"""),
        "Possible SSN pattern",
    ),
    (
        re.compile(r"""\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"""),
        "Possible credit card number",
    ),
    (
        re.compile(
            r"""(?:jdbc|mysql|postgres|mongodb|redis)://[^\s'"]+""",
            re.IGNORECASE,
        ),
        "Database connection string",
    ),
]


# ── Discovery ────────────────────────────────────────────────────────────────


def discover_prompt_files(
    root: Path,
    max_depth: int = 4,
) -> list[Path]:
    """Find prompt template files in a directory tree.

    Scans for known prompt file extensions, names, and directories.
    Limits search depth to avoid scanning huge trees.
    """
    found: list[Path] = []

    if not root.is_dir():
        return found

    def _walk(directory: Path, depth: int) -> None:
        if depth > max_depth:
            return
        try:
            entries = sorted(directory.iterdir())
        except PermissionError:
            return

        for entry in entries:
            if entry.is_dir():
                if entry.name in _SKIP_DIRS:
                    continue
                # Check if it's a prompt directory
                if entry.name.lower() in PROMPT_DIR_NAMES:
                    # Scan all files inside prompt directories
                    for f in sorted(entry.rglob("*")):
                        if f.is_file() and f.suffix in {".txt", ".md", ".yaml", ".yml", ".json", ".j2", ".jinja2", ".hbs", ".mustache", ".prompt", ".promptfile"}:
                            found.append(f)
                else:
                    _walk(entry, depth + 1)
            elif entry.is_file():
                # Match by extension
                if entry.suffix.lower() in PROMPT_FILE_EXTENSIONS:
                    found.append(entry)
                # Match by exact name
                elif entry.name.lower() in PROMPT_FILE_NAMES:
                    found.append(entry)

    _walk(root, 0)
    return found


# ── Analysis ─────────────────────────────────────────────────────────────────


def _analyze_content(
    content: str,
    source_file: str,
) -> list[PromptFinding]:
    """Analyze prompt content for security risks."""
    findings: list[PromptFinding] = []
    lines = content.split("\n")

    # Build a line-lookup for match positions
    def _find_line(pos: int) -> int:
        """Return 1-indexed line number for character position."""
        return content[:pos].count("\n") + 1

    # Critical: Hardcoded secrets
    for pattern, title in _SECRET_PATTERNS:
        for match in pattern.finditer(content):
            findings.append(PromptFinding(
                severity="critical",
                category="hardcoded_secret",
                title=title,
                detail=f"Found {title.lower()} in prompt template",
                source_file=source_file,
                line_number=_find_line(match.start()),
                matched_text=_redact(match.group(0)),
                recommendation="Remove hardcoded secrets. Use environment variables or secret managers.",
            ))

    # High: Prompt injection / jailbreak
    for pattern, title in _INJECTION_PATTERNS:
        for match in pattern.finditer(content):
            findings.append(PromptFinding(
                severity="high",
                category="prompt_injection",
                title=title,
                detail=f"Detected injection/jailbreak pattern: {match.group(0)[:80]}",
                source_file=source_file,
                line_number=_find_line(match.start()),
                matched_text=match.group(0)[:100],
                recommendation="Remove prompt injection patterns. These can compromise agent safety controls.",
            ))

    # High: Unsafe instructions
    for pattern, title in _UNSAFE_INSTRUCTION_PATTERNS:
        for match in pattern.finditer(content):
            findings.append(PromptFinding(
                severity="high",
                category="unsafe_instruction",
                title=title,
                detail=f"Prompt instructs agent to: {match.group(0)[:80]}",
                source_file=source_file,
                line_number=_find_line(match.start()),
                matched_text=match.group(0)[:100],
                recommendation="Restrict agent capabilities. Avoid granting shell access or data exfiltration paths.",
            ))

    # Medium: Excessive permissions
    for pattern, title in _PERMISSION_PATTERNS:
        for match in pattern.finditer(content):
            findings.append(PromptFinding(
                severity="medium",
                category="excessive_permission",
                title=title,
                detail=f"Prompt grants excessive permissions: {match.group(0)[:80]}",
                source_file=source_file,
                line_number=_find_line(match.start()),
                matched_text=match.group(0)[:100],
                recommendation="Apply least-privilege. Scope agent access to only what's needed.",
            ))

    # Medium: Sensitive data in prompt content
    for pattern, title in _SENSITIVE_DATA_PATTERNS:
        for match in pattern.finditer(content):
            findings.append(PromptFinding(
                severity="medium",
                category="sensitive_data",
                title=title,
                detail=f"Possible sensitive data in prompt template",
                source_file=source_file,
                line_number=_find_line(match.start()),
                matched_text=_redact(match.group(0)),
                recommendation="Remove sensitive data from prompt templates. Use parameterized inputs.",
            ))

    return findings


def _redact(text: str) -> str:
    """Redact middle portion of sensitive strings."""
    if len(text) <= 8:
        return text[:2] + "***"
    return text[:4] + "***" + text[-4:]


# ── JSON prompt file parsing ────────────────────────────────────────────────


def _extract_prompt_from_json(content: str) -> str:
    """Extract prompt text from JSON files (common in OpenAI/Anthropic configs)."""
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return content  # Not valid JSON, scan raw content

    texts: list[str] = []

    def _walk_json(obj: object, depth: int = 0) -> None:
        if depth > 10:
            return
        if isinstance(obj, str):
            texts.append(obj)
        elif isinstance(obj, list):
            for item in obj:
                _walk_json(item, depth + 1)
        elif isinstance(obj, dict):
            # Prioritize known prompt-related keys
            for key in ("prompt", "system_prompt", "system", "content",
                        "instructions", "template", "message", "text"):
                if key in obj:
                    _walk_json(obj[key], depth + 1)
            # Also walk other values
            for key, val in obj.items():
                if key not in ("prompt", "system_prompt", "system", "content",
                               "instructions", "template", "message", "text"):
                    _walk_json(val, depth + 1)

    _walk_json(data)
    return "\n".join(texts)


def _extract_prompt_from_yaml(content: str) -> str:
    """Extract prompt text from YAML-ish files without requiring PyYAML."""
    # Look for multi-line string values (common in prompt YAML)
    # Simple heuristic: grab values after prompt-related keys
    lines = content.split("\n")
    prompt_lines: list[str] = []
    capturing = False

    for line in lines:
        stripped = line.strip()
        lower = stripped.lower()

        # Check for prompt-related YAML keys
        if any(lower.startswith(k) for k in (
            "prompt:", "system_prompt:", "system:", "content:",
            "instructions:", "template:", "message:", "text:",
        )):
            # Value on same line after colon
            val = stripped.split(":", 1)[1].strip()
            if val and val not in ("|", ">", "|-", ">-"):
                prompt_lines.append(val.strip("'\""))
            capturing = True
            continue

        if capturing:
            # Multi-line YAML string continuation (indented)
            if line.startswith("  ") or line.startswith("\t"):
                prompt_lines.append(stripped)
            elif stripped == "":
                prompt_lines.append("")
            else:
                capturing = False

    return "\n".join(prompt_lines) if prompt_lines else content


# ── Main entry point ─────────────────────────────────────────────────────────


def scan_prompt_files(
    root: Path | None = None,
    paths: list[Path] | None = None,
) -> PromptScanResult:
    """Scan prompt template files for security risks.

    Args:
        root: Directory to search for prompt files.
        paths: Explicit list of prompt files to scan.

    Returns:
        PromptScanResult with findings and file list.
    """
    result = PromptScanResult()

    files: list[Path] = []
    if paths:
        files.extend(p for p in paths if p.is_file())
    if root:
        files.extend(discover_prompt_files(root))

    # Deduplicate
    seen: set[str] = set()
    unique_files: list[Path] = []
    for f in files:
        resolved = str(f.resolve())
        if resolved not in seen:
            seen.add(resolved)
            unique_files.append(f)

    for file_path in unique_files:
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            logger.warning("Could not read prompt file: %s", file_path)
            continue

        if not content.strip():
            continue

        result.files_scanned += 1
        result.prompt_files.append(str(file_path))

        # Extract prompt text from structured files
        suffix = file_path.suffix.lower()
        if suffix == ".json":
            text = _extract_prompt_from_json(content)
        elif suffix in (".yaml", ".yml"):
            text = _extract_prompt_from_yaml(content)
        else:
            text = content

        findings = _analyze_content(text, str(file_path))
        result.findings.extend(findings)

    # Determine pass/fail
    result.passed = not any(
        f.severity in ("critical", "high") for f in result.findings
    )

    return result
