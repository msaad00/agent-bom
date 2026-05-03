"""Source-file and license-file SPDX identifier scanner.

Complements registry-based license detection in resolver.py by scanning:
  1. LICENSE / COPYING / LICENCE files — SPDX-License-Identifier tag or
     best-effort text pattern matching for the most common licenses.
  2. Source-file headers — ``SPDX-License-Identifier:`` comment in the
     first 20 lines of any .py / .js / .ts / .go / .java / .c / .cpp / .h file.

Results feed back into the license_compliance_scan MCP tool (scan_dir
argument) and the ``agent-bom scan`` pipeline so that packages whose
registry metadata lacks a license field can be enriched from local source.

Issue: #872
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# ─── SPDX identifier extraction ──────────────────────────────────────────────

_SPDX_ID_RE = re.compile(
    r"SPDX-License-Identifier:\s*([A-Za-z0-9.+\-()]+(?:\s+(?:AND|OR|WITH)\s+[A-Za-z0-9.+\-()]+)*)",
    re.IGNORECASE,
)

# Filenames that are conventionally license texts (case-insensitive stem match)
_LICENSE_STEMS: frozenset[str] = frozenset(
    {
        "license",
        "licence",
        "copying",
        "copying.lesser",
        "notice",
        "copyright",
        "unlicense",
    }
)

# Source-file extensions to scan for SPDX header comments
_SOURCE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".py",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".go",
        ".java",
        ".c",
        ".cpp",
        ".h",
        ".hpp",
        ".cs",
        ".rs",
        ".rb",
        ".sh",
        ".bash",
        ".swift",
        ".kt",
        ".scala",
    }
)

# Max lines to scan for SPDX header in source files
_HEADER_SCAN_LINES = 20

# Max file size (bytes) to attempt text pattern matching on license files
_MAX_LICENSE_FILE_SIZE = 512_000  # 512 KB

# ─── License text pattern matching ───────────────────────────────────────────
#
# Ordered by specificity — longer / more distinctive patterns first.
# Each tuple: (compiled regex, SPDX identifier)

_LICENSE_TEXT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"GNU AFFERO GENERAL PUBLIC LICENSE\s+Version 3", re.IGNORECASE), "AGPL-3.0-only"),
    (re.compile(r"GNU GENERAL PUBLIC LICENSE\s+Version 3", re.IGNORECASE), "GPL-3.0-only"),
    (re.compile(r"GNU GENERAL PUBLIC LICENSE\s+Version 2", re.IGNORECASE), "GPL-2.0-only"),
    (re.compile(r"GNU LESSER GENERAL PUBLIC LICENSE\s+Version 3", re.IGNORECASE), "LGPL-3.0-only"),
    (re.compile(r"GNU LESSER GENERAL PUBLIC LICENSE\s+Version 2\.1", re.IGNORECASE), "LGPL-2.1-only"),
    (re.compile(r"GNU LESSER GENERAL PUBLIC LICENSE\s+Version 2(?!\.1)", re.IGNORECASE), "LGPL-2.0-only"),
    (re.compile(r"Apache License[,\s]+Version 2\.0", re.IGNORECASE), "Apache-2.0"),
    (re.compile(r"MIT License", re.IGNORECASE), "MIT"),
    (re.compile(r"Permission is hereby granted,? free of charge", re.IGNORECASE), "MIT"),
    (re.compile(r"Mozilla Public License[,\s]+Version 2\.0", re.IGNORECASE), "MPL-2.0"),
    (re.compile(r"Eclipse Public License[,\s]+Version 2\.0", re.IGNORECASE), "EPL-2.0"),
    (re.compile(r"Eclipse Public License[,\s]+(?:Version )?1\.0", re.IGNORECASE), "EPL-1.0"),
    (re.compile(r"BSD 2-Clause|Simplified BSD License", re.IGNORECASE), "BSD-2-Clause"),
    (re.compile(r"BSD 3-Clause|New BSD License|Modified BSD", re.IGNORECASE), "BSD-3-Clause"),
    (re.compile(r"BSD 4-Clause|Original BSD", re.IGNORECASE), "BSD-4-Clause"),
    (re.compile(r"ISC License", re.IGNORECASE), "ISC"),
    (re.compile(r"Creative Commons.*Zero.*1\.0|CC0-1\.0", re.IGNORECASE), "CC0-1.0"),
    (re.compile(r"Creative Commons.*Attribution.*4\.0", re.IGNORECASE), "CC-BY-4.0"),
    (re.compile(r"Server Side Public License|SSPL", re.IGNORECASE), "SSPL-1.0"),
    (re.compile(r"Business Source License|BUSL-1\.1", re.IGNORECASE), "BUSL-1.1"),
    (re.compile(r"Elastic License 2\.0|ELv2", re.IGNORECASE), "Elastic-2.0"),
    (re.compile(r"European Union Public Licen[sc]e|EUPL", re.IGNORECASE), "EUPL-1.2"),
    (re.compile(r"Common Development and Distribution License|CDDL", re.IGNORECASE), "CDDL-1.0"),
    (re.compile(r"Open Software License|OSL-3\.0", re.IGNORECASE), "OSL-3.0"),
    (re.compile(r"Artistic License 2\.0", re.IGNORECASE), "Artistic-2.0"),
    (re.compile(r"The Unlicense|UNLICENSE", re.IGNORECASE), "Unlicense"),
    (re.compile(r"Do What The F.ck You Want|WTFPL", re.IGNORECASE), "WTFPL"),
    (re.compile(r"Zlib License|zlib/libpng", re.IGNORECASE), "Zlib"),
    (re.compile(r"PostgreSQL License", re.IGNORECASE), "PostgreSQL"),
    (re.compile(r"Python Software Foundation License", re.IGNORECASE), "PSF-2.0"),
]


# ─── Result dataclasses ───────────────────────────────────────────────────────


@dataclass
class LicenseFileResult:
    """A license detection result from a single file."""

    file_path: str
    spdx_id: str
    detection_method: str  # "spdx_identifier" | "text_pattern" | "source_header"
    confidence: str  # "high" | "medium" | "low"
    raw_expression: str = ""


@dataclass
class DirectoryScanResult:
    """Aggregated results from scanning a directory for license information."""

    root: str
    license_files: list[LicenseFileResult] = field(default_factory=list)
    source_headers: list[LicenseFileResult] = field(default_factory=list)

    @property
    def all_results(self) -> list[LicenseFileResult]:
        return self.license_files + self.source_headers

    @property
    def unique_spdx_ids(self) -> list[str]:
        return sorted({r.spdx_id for r in self.all_results})

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "unique_spdx_ids": self.unique_spdx_ids,
            "license_files": [
                {
                    "file_path": r.file_path,
                    "spdx_id": r.spdx_id,
                    "detection_method": r.detection_method,
                    "confidence": r.confidence,
                }
                for r in self.license_files
            ],
            "source_header_count": len(self.source_headers),
            "source_header_sample": [{"file_path": r.file_path, "spdx_id": r.spdx_id} for r in self.source_headers[:5]],
        }


# ─── Core detection functions ─────────────────────────────────────────────────


def detect_spdx_from_text(text: str) -> str | None:
    """Extract an SPDX-License-Identifier tag from arbitrary text.

    Returns the raw SPDX expression (e.g. ``"MIT OR Apache-2.0"``) or None.
    """
    m = _SPDX_ID_RE.search(text)
    if m:
        return m.group(1).strip()
    return None


def detect_spdx_from_license_text(text: str) -> str | None:
    """Heuristically identify an SPDX ID from license file body text.

    Falls back to pattern matching when no SPDX-License-Identifier tag is
    present. Returns the most specific match or None.
    """
    for pattern, spdx_id in _LICENSE_TEXT_PATTERNS:
        if pattern.search(text):
            return spdx_id
    return None


def scan_license_file(path: Path) -> LicenseFileResult | None:
    """Scan a single LICENSE/COPYING file and return a detection result.

    Returns None if the file cannot be read or no license is detected.
    """
    try:
        size = path.stat().st_size
        if size > _MAX_LICENSE_FILE_SIZE:
            logger.debug("Skipping oversized license file %s (%d bytes)", path, size)
            return None
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    # Prefer explicit SPDX tag
    spdx = detect_spdx_from_text(text)
    if spdx:
        return LicenseFileResult(
            file_path=str(path),
            spdx_id=spdx,
            detection_method="spdx_identifier",
            confidence="high",
            raw_expression=spdx,
        )

    # Fall back to text pattern matching
    spdx = detect_spdx_from_license_text(text)
    if spdx:
        return LicenseFileResult(
            file_path=str(path),
            spdx_id=spdx,
            detection_method="text_pattern",
            confidence="medium",
        )

    return None


def scan_source_header(path: Path) -> LicenseFileResult | None:
    """Scan the first N lines of a source file for an SPDX header comment.

    Returns None if no SPDX-License-Identifier is found in the header.
    """
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            header = "".join(next(fh, "") for _ in range(_HEADER_SCAN_LINES))
    except OSError:
        return None

    spdx = detect_spdx_from_text(header)
    if spdx:
        return LicenseFileResult(
            file_path=str(path),
            spdx_id=spdx,
            detection_method="source_header",
            confidence="high",
            raw_expression=spdx,
        )
    return None


def is_license_filename(path: Path) -> bool:
    """Return True when the filename looks like a license/copyright file."""
    stem = path.stem.lower()
    return stem in _LICENSE_STEMS or path.name.lower() in _LICENSE_STEMS


# ─── Directory scanner ────────────────────────────────────────────────────────


def scan_directory(
    root: Path,
    *,
    scan_source_headers: bool = True,
    max_source_files: int = 2_000,
) -> DirectoryScanResult:
    """Scan a directory tree for license information.

    Walks ``root`` recursively:
    - Every LICENSE/COPYING/NOTICE/UNLICENSE file is scanned for SPDX IDs.
    - Source files (up to ``max_source_files``) are checked for
      ``SPDX-License-Identifier:`` header comments.

    Args:
        root: Directory to scan.
        scan_source_headers: Whether to scan source file headers (default True).
        max_source_files: Safety cap on source files scanned to prevent
            runaway on very large repos.

    Returns:
        A :class:`DirectoryScanResult` with all detected licenses.
    """
    result = DirectoryScanResult(root=str(root))

    if not root.is_dir():
        logger.warning("license_file_scanner: %s is not a directory", root)
        return result

    source_scanned = 0

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue

        # Skip hidden directories (e.g. .git, .tox, node_modules)
        if any(part.startswith(".") or part == "node_modules" or part == "__pycache__" for part in path.parts):
            continue

        if is_license_filename(path):
            detection = scan_license_file(path)
            if detection:
                result.license_files.append(detection)
            continue

        if scan_source_headers and path.suffix.lower() in _SOURCE_EXTENSIONS:
            if source_scanned >= max_source_files:
                continue
            detection = scan_source_header(path)
            source_scanned += 1
            if detection:
                result.source_headers.append(detection)

    logger.debug(
        "license_file_scanner: %s — %d license files, %d source headers, %d unique SPDX IDs",
        root,
        len(result.license_files),
        len(result.source_headers),
        len(result.unique_spdx_ids),
    )
    return result
