"""AI component source scanner — regex-based detection of AI SDK usage in source code.

Walks a directory tree, matches import patterns / model references / API keys,
and produces an AIComponentReport. Zero external dependencies.

Usage::

    from agent_bom.ai_components import scan_source

    report = scan_source("/path/to/project")
    for comp in report.components:
        print(f"{comp.component_type.value}: {comp.name} in {comp.file_path}:{comp.line_number}")
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from agent_bom.ai_components.models import (
    AIComponent,
    AIComponentReport,
    AIComponentSeverity,
    AIComponentType,
)
from agent_bom.ai_components.patterns import (
    API_KEY_PATTERNS,
    DEPRECATED_MODEL_PATTERNS,
    EXTENSION_TO_LANGUAGE,
    MODEL_PATTERNS,
    SDK_PATTERNS_BY_LANGUAGE,
)

logger = logging.getLogger(__name__)

# Directories to always skip
_SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "__pycache__",
        "node_modules",
        ".venv",
        "venv",
        ".env",
        "env",
        ".tox",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        "dist",
        "build",
        ".eggs",
        "*.egg-info",
        "target",  # Rust/Java build output
        "vendor",  # Go vendor
        ".next",  # Next.js
        ".nuxt",  # Nuxt.js
        "coverage",
    }
)

# Max file size to scan (skip huge generated/minified files)
_MAX_FILE_SIZE: int = 512 * 1024  # 512 KB


def scan_source(
    *paths: str | Path,
    manifest_packages: set[str] | None = None,
) -> AIComponentReport:
    """Scan source code directories for AI component usage.

    Args:
        *paths: One or more directories or files to scan.
        manifest_packages: Optional set of normalized package names already
            declared in manifests (requirements.txt, package.json, etc.).
            When provided, SDK imports not in this set are flagged as shadow AI.

    Returns:
        AIComponentReport with all detected components.
    """
    report = AIComponentReport()
    manifest_pkgs = {_normalize(p) for p in (manifest_packages or set())}
    seen_keys: set[str] = set()  # dedup: (file_path, line_number, name)

    for path in paths:
        root = Path(path)
        report.scan_paths.append(str(root))

        if root.is_file():
            _scan_file(root, root.parent, report, manifest_pkgs, seen_keys)
        elif root.is_dir():
            _walk_directory(root, report, manifest_pkgs, seen_keys)
        else:
            report.warnings.append(f"Path not found: {root}")

    # Populate convenience lists
    report.shadow_ai = [c for c in report.components if c.is_shadow]
    report.deprecated_models = [c for c in report.components if c.component_type == AIComponentType.DEPRECATED_MODEL]
    report.api_keys = [c for c in report.components if c.component_type == AIComponentType.API_KEY]

    return report


def _walk_directory(
    root: Path,
    report: AIComponentReport,
    manifest_pkgs: set[str],
    seen_keys: set[str],
) -> None:
    """Walk directory tree, scanning source files."""
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune skip directories in-place
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.endswith(".egg-info")]

        for filename in filenames:
            filepath = Path(dirpath) / filename
            _scan_file(filepath, root, report, manifest_pkgs, seen_keys)


def _scan_file(
    filepath: Path,
    root: Path,
    report: AIComponentReport,
    manifest_pkgs: set[str],
    seen_keys: set[str],
) -> None:
    """Scan a single source file for AI components."""
    ext = filepath.suffix.lower()
    language = EXTENSION_TO_LANGUAGE.get(ext)
    if not language:
        return

    # Skip oversized files (generated/minified)
    try:
        size = filepath.stat().st_size
    except OSError:
        return
    if size > _MAX_FILE_SIZE or size == 0:
        return

    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return

    report.files_scanned += 1
    rel_path = str(filepath.relative_to(root)) if filepath.is_relative_to(root) else str(filepath)

    # 1. SDK import detection
    sdk_patterns = SDK_PATTERNS_BY_LANGUAGE.get(language, [])
    for pattern in sdk_patterns:
        for match in pattern.regex.finditer(content):
            # Line number: count newlines before the actual content (not the leading \n in the regex)
            match_text = match.group(0)
            offset = match.start() + len(match_text) - len(match_text.lstrip("\n"))
            line_num = content[:offset].count("\n") + 1
            dedup_key = f"{rel_path}:{line_num}:{pattern.name}"
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            is_shadow = bool(manifest_pkgs) and _normalize(pattern.package_name) not in manifest_pkgs
            comp = AIComponent(
                component_type=pattern.component_type,
                name=pattern.name,
                language=language,
                file_path=rel_path,
                line_number=line_num,
                matched_text=match.group(0).strip(),
                severity=AIComponentSeverity.MEDIUM if is_shadow else AIComponentSeverity.LOW,
                package_name=pattern.package_name,
                ecosystem=pattern.ecosystem,
                description=f"Shadow AI: {pattern.name} imported but not in manifest" if is_shadow else None,
                is_shadow=is_shadow,
            )
            report.components.append(comp)

    # 2. Model string references (all languages)
    for model_pat in MODEL_PATTERNS:
        for match in model_pat.regex.finditer(content):
            model_name = match.group(0)
            line_num = content[: match.start()].count("\n") + 1
            dedup_key = f"{rel_path}:{line_num}:model:{model_name}"
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            comp = AIComponent(
                component_type=AIComponentType.MODEL_REFERENCE,
                name=model_name,
                language=language,
                file_path=rel_path,
                line_number=line_num,
                matched_text=match.group(0),
                severity=model_pat.severity,
                description=f"{model_pat.provider} model reference",
            )
            report.components.append(comp)

    # 3. Deprecated model detection (all languages)
    for dep_pat in DEPRECATED_MODEL_PATTERNS:
        for match in dep_pat.regex.finditer(content):
            model_name = match.group(0)
            line_num = content[: match.start()].count("\n") + 1
            dedup_key = f"{rel_path}:{line_num}:deprecated:{model_name}"
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            comp = AIComponent(
                component_type=AIComponentType.DEPRECATED_MODEL,
                name=model_name,
                language=language,
                file_path=rel_path,
                line_number=line_num,
                matched_text=match.group(0),
                severity=dep_pat.severity,
                package_name=None,
                description=f"Deprecated {dep_pat.provider} model",
                deprecated_replacement=dep_pat.replacement,
            )
            report.components.append(comp)

    # 4. API key detection (all languages)
    for key_pat in API_KEY_PATTERNS:
        for match in key_pat.regex.finditer(content):
            key_value = match.group(1)
            line_num = content[: match.start()].count("\n") + 1
            # Mask the key for safe display
            masked = key_value[:8] + "..." + key_value[-4:] if len(key_value) > 12 else key_value[:4] + "..."
            dedup_key = f"{rel_path}:{line_num}:apikey:{key_pat.provider}"
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            comp = AIComponent(
                component_type=AIComponentType.API_KEY,
                name=masked,
                language=language,
                file_path=rel_path,
                line_number=line_num,
                matched_text=masked,  # never store full key
                severity=key_pat.severity,
                description=key_pat.description,
            )
            report.components.append(comp)


def _normalize(name: str) -> str:
    """Normalize package name for comparison (PEP 503 + lowercase)."""
    import re as _re

    return _re.sub(r"[-_.]+", "-", name).lower().strip()
