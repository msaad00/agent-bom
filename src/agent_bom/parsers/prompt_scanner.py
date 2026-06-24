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

import base64
import json
import logging
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ── Obfuscation normalization ──────────────────────────────────────────────
# Adversarial prompt injections evade naive keyword matching via Unicode
# homoglyphs, zero-width separators, leetspeak, and base64 encoding. We match
# every pattern against BOTH the raw text and a normalized projection so these
# bypasses are caught. Detection only — the projection is never persisted.

# Zero-width / invisible separators an attacker inserts between letters.
_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠⁡⁢⁣⁤﻿­͏᠎"), None)
# Common Cyrillic/Greek homoglyphs → Latin (NFKC misses these script confusables).
_HOMOGLYPHS = {
    ord(src): dst
    for src, dst in {
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "х": "x",
        "у": "y",
        "ѕ": "s",
        "і": "i",
        "ј": "j",
        "ԁ": "d",
        "ո": "n",
        "һ": "h",
        "ɡ": "g",
        "ⅼ": "l",
        "α": "a",
        "ε": "e",
        "ο": "o",
        "ρ": "p",
        "ι": "i",
        "κ": "k",
        "ν": "v",
        "τ": "t",
    }.items()
}
# Leetspeak substitutions (applied to a separate projection to limit false positives).
_LEET = str.maketrans({"4": "a", "3": "e", "1": "i", "0": "o", "5": "s", "7": "t", "@": "a", "$": "s"})
_B64_RUN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def _normalize_for_matching(text: str) -> str:
    """Return a normalized projection of ``text`` for obfuscation-resistant matching.

    Folds Unicode (NFKC + homoglyphs), strips zero-width separators, de-leets, and
    appends any decoded base64 payloads — so injections hidden via homoglyph,
    zero-width, leetspeak, or base64 still match the keyword patterns. Newline
    structure is not preserved (this projection is for presence detection only;
    line numbers come from the raw pass).
    """
    folded = unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH).translate(_HOMOGLYPHS)
    decoded: list[str] = []
    for m in _B64_RUN.finditer(text):
        chunk = m.group(0)
        try:
            raw = base64.b64decode(chunk + "===", validate=False).decode("utf-8", "ignore")
        except Exception:  # noqa: BLE001
            continue
        if len(raw) > 6 and sum(c.isprintable() for c in raw) / len(raw) > 0.8:
            decoded.append(raw)
    return "\n".join([folded, folded.translate(_LEET), *decoded])


# ── File discovery patterns ──────────────────────────────────────────────────

PROMPT_FILE_EXTENSIONS = {
    ".prompt",
    ".promptfile",
    ".system-prompt",
    ".jinja2",
    ".j2",
    ".hbs",
    ".mustache",
}

PROMPT_FILE_NAMES = {
    "system_prompt.txt",
    "system_prompt.md",
    "system_prompt.yaml",
    "system_prompt.yml",
    "system_prompt.json",
    "prompt.yaml",
    "prompt.yml",
    "prompt.json",
    "user_prompt.txt",
    "user_prompt.md",
    "agent_prompt.txt",
    "agent_prompt.md",
    "instructions.txt",
    "instructions.md",
}

PROMPT_DIR_NAMES = {
    "prompts",
    "prompt_templates",
    "prompt-templates",
    "system_prompts",
    "system-prompts",
}

# Directories to skip during scanning
_SKIP_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    ".mypy_cache",
    ".ruff_cache",
    "dist",
    "build",
    ".eggs",
    "*.egg-info",
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
            r"""(?:ignore|disregard|forget|override|bypass|skip)\s+"""
            r"""(?:all\s+|the\s+|any\s+|your\s+)*"""
            r"""(?:previous|prior|above|earlier|preceding|former|original|system|these)\s+"""
            r"""(?:instructions?|rules?|constraints?|prompts?|guidelines?|directions?|commands?|context)""",
            re.IGNORECASE,
        ),
        "Prompt injection: ignore previous instructions",
    ),
    (
        # Same intent with the qualifier AFTER the noun ("the rules above").
        re.compile(
            r"""(?:ignore|disregard|forget|override|bypass|skip)\s+"""
            r"""(?:all\s+|the\s+|any\s+|your\s+)*"""
            r"""(?:instructions?|rules?|constraints?|guidelines?|directions?|prompts?)\s+"""
            r"""(?:above|below|earlier|here|given|provided|stated)""",
            re.IGNORECASE,
        ),
        "Prompt injection: ignore previous instructions",
    ),
    (
        # Indirect injection: embedded SYSTEM/ASSISTANT directives or HTML-comment
        # smuggling — the #1 vector for poisoned documents and MCP tool descriptions.
        re.compile(
            r"""(?:\[\[?\s*|<!--\s*|\{\{\s*)?\b(?:system|assistant|ai|agent)\s*[:>]\s*"""
            r"""(?:ignore|exfiltrat|send|call|execute|run|reveal|leak|transfer|delete|disregard)""",
            re.IGNORECASE,
        ),
        "Indirect prompt injection: embedded system directive",
    ),
    (
        # System-prompt / configuration disclosure attempts.
        re.compile(
            r"""(?:repeat|reveal|print|show|output|disclose|leak)\s+(?:me\s+)?(?:your\s+|the\s+|all\s+)*"""
            r"""(?:initial\s+|system\s+|original\s+|hidden\s+|above\s+)*"""
            r"""(?:prompt|instructions?|configuration|config|rules?|guidelines?|directives?)""",
            re.IGNORECASE,
        ),
        "Prompt injection: system-prompt disclosure attempt",
    ),
    (
        re.compile(
            r"""(?:developer|debug|god|admin|root|dan|jailbreak)\s+mode\s+"""
            r"""(?:enabled?|activated?|on\b|is\s+now)""",
            re.IGNORECASE,
        ),
        "Jailbreak pattern: mode-override persona",
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
            r"""(?:send|post|upload|exfiltrate|email|forward|leak|transmit|copy|deliver)\s+"""
            r"""(?:me\s+|the\s+|all\s+|your\s+|any\s+|this\s+)*"""
            r"""(?:data|results?|output|conversation|history|context|secrets?|credentials?|keys?|tokens?|files?|contents?)\s+"""
            r"""(?:to|over\s+to|via)\s+(?:https?://|webhook|[\w.+-]+@|attacker|evil|ngrok)""",
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
                        if f.is_file() and f.suffix in {
                            ".txt",
                            ".md",
                            ".yaml",
                            ".yml",
                            ".json",
                            ".j2",
                            ".jinja2",
                            ".hbs",
                            ".mustache",
                            ".prompt",
                            ".promptfile",
                        }:
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

    # Build a line-lookup for match positions
    def _find_line(pos: int) -> int:
        """Return 1-indexed line number for character position."""
        return content[:pos].count("\n") + 1

    # Critical: Hardcoded secrets
    for pattern, title in _SECRET_PATTERNS:
        for match in pattern.finditer(content):
            findings.append(
                PromptFinding(
                    severity="critical",
                    category="hardcoded_secret",
                    title=title,
                    detail=f"Found {title.lower()} in prompt template",
                    source_file=source_file,
                    line_number=_find_line(match.start()),
                    matched_text=_redact(match.group(0)),
                    recommendation="Remove hardcoded secrets. Use environment variables or secret managers.",
                )
            )

    # High: Prompt injection / jailbreak
    for pattern, title in _INJECTION_PATTERNS:
        for match in pattern.finditer(content):
            findings.append(
                PromptFinding(
                    severity="high",
                    category="prompt_injection",
                    title=title,
                    detail=f"Detected injection/jailbreak pattern: {match.group(0)[:80]}",
                    source_file=source_file,
                    line_number=_find_line(match.start()),
                    matched_text=match.group(0)[:100],
                    recommendation="Remove prompt injection patterns. These can compromise agent safety controls.",
                )
            )

    # High: Unsafe instructions
    for pattern, title in _UNSAFE_INSTRUCTION_PATTERNS:
        for match in pattern.finditer(content):
            findings.append(
                PromptFinding(
                    severity="high",
                    category="unsafe_instruction",
                    title=title,
                    detail=f"Prompt instructs agent to: {match.group(0)[:80]}",
                    source_file=source_file,
                    line_number=_find_line(match.start()),
                    matched_text=match.group(0)[:100],
                    recommendation="Restrict agent capabilities. Avoid granting shell access or data exfiltration paths.",
                )
            )

    # Medium: Excessive permissions
    for pattern, title in _PERMISSION_PATTERNS:
        for match in pattern.finditer(content):
            findings.append(
                PromptFinding(
                    severity="medium",
                    category="excessive_permission",
                    title=title,
                    detail=f"Prompt grants excessive permissions: {match.group(0)[:80]}",
                    source_file=source_file,
                    line_number=_find_line(match.start()),
                    matched_text=match.group(0)[:100],
                    recommendation="Apply least-privilege. Scope agent access to only what's needed.",
                )
            )

    # Medium: Sensitive data in prompt content
    for pattern, title in _SENSITIVE_DATA_PATTERNS:
        for match in pattern.finditer(content):
            findings.append(
                PromptFinding(
                    severity="medium",
                    category="sensitive_data",
                    title=title,
                    detail="Possible sensitive data in prompt template",
                    source_file=source_file,
                    line_number=_find_line(match.start()),
                    matched_text=_redact(match.group(0)),
                    recommendation="Remove sensitive data from prompt templates. Use parameterized inputs.",
                )
            )

    # Obfuscation-resistant pass: re-run the injection + unsafe-instruction
    # patterns against a normalized projection (homoglyph/zero-width/leet/base64
    # decoded) so an attack hidden by encoding is still caught. Findings whose
    # title was already raised in the raw pass are skipped.
    seen_titles = {f.title for f in findings}
    normalized = _normalize_for_matching(content)
    if normalized != content:
        for pattern, title in (*_INJECTION_PATTERNS, *_UNSAFE_INSTRUCTION_PATTERNS):
            nmatch = pattern.search(normalized)
            if nmatch and title not in seen_titles:
                seen_titles.add(title)
                findings.append(
                    PromptFinding(
                        severity="high",
                        category="prompt_injection",
                        title=f"{title} (obfuscated)",
                        detail="Detected only after de-obfuscation (homoglyph/zero-width/leetspeak/base64).",
                        source_file=source_file,
                        line_number=1,
                        matched_text=nmatch.group(0)[:100],
                        recommendation="An injection was hidden via text obfuscation — treat the source as hostile.",
                    )
                )

    return findings


def _redact(text: str) -> str:
    """Redact middle portion of sensitive strings."""
    if len(text) <= 8:
        return text[:2] + "***"
    return text[:4] + "***" + text[-4:]


def _risk_score(severity: str) -> float:
    return {
        "critical": 9.0,
        "high": 7.5,
        "medium": 5.0,
        "low": 2.5,
    }.get(severity.lower(), 1.0)


def _finding_type_for_category(category: str):
    from agent_bom.finding import FindingType

    normalized = category.lower()
    if "secret" in normalized or "sensitive" in normalized:
        return FindingType.CREDENTIAL_EXPOSURE
    if "exfil" in normalized:
        return FindingType.EXFILTRATION
    if "injection" in normalized or "jailbreak" in normalized:
        return FindingType.INJECTION
    return FindingType.PROMPT_SECURITY


def prompt_scan_data_to_findings(prompt_scan: dict[str, Any]):
    """Convert serialized prompt scan data into the unified Finding stream."""
    from agent_bom.finding import Asset, Finding, FindingSource

    unified = []
    for item in prompt_scan.get("findings") or []:
        if not isinstance(item, dict):
            continue
        source_file = str(item.get("source_file") or "")
        category = str(item.get("category") or "prompt_security")
        severity = str(item.get("severity") or "unknown").lower()
        title = str(item.get("title") or "Prompt security finding")
        asset_name = Path(source_file).name if source_file else "prompt"
        unified.append(
            Finding(
                finding_type=_finding_type_for_category(category),
                source=FindingSource.PROMPT_SCAN,
                asset=Asset(
                    name=asset_name,
                    asset_type="prompt_template",
                    identifier=source_file or None,
                    location=source_file or None,
                ),
                severity=severity,
                title=title,
                description=str(item.get("detail") or title),
                remediation_guidance=str(item.get("recommendation") or "") or None,
                owasp_tags=["LLM01"] if "injection" in category else [],
                nist_ai_rmf_tags=["MAP-4.1", "MEASURE-2.6"],
                evidence={
                    "category": category,
                    "line_number": item.get("line_number"),
                    "matched_text": item.get("matched_text"),
                    "scanner": "prompt_scan",
                },
                risk_score=_risk_score(severity),
            )
        )
    return unified


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
            for key in ("prompt", "system_prompt", "system", "content", "instructions", "template", "message", "text"):
                if key in obj:
                    _walk_json(obj[key], depth + 1)
            # Also walk other values
            for key, val in obj.items():
                if key not in ("prompt", "system_prompt", "system", "content", "instructions", "template", "message", "text"):
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
        if any(
            lower.startswith(k)
            for k in (
                "prompt:",
                "system_prompt:",
                "system:",
                "content:",
                "instructions:",
                "template:",
                "message:",
                "text:",
            )
        ):
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
    result.passed = not any(f.severity in ("critical", "high") for f in result.findings)

    return result
