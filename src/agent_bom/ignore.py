"""Parse ``.agent-bom-ignore`` files for lightweight CVE/package suppression.

Format (one rule per line, ``#`` comments, blank lines ignored)::

    # Suppress specific CVEs
    CVE-2024-21538
    GHSA-xxxx-xxxx-xxxx

    # Suppress all vulns for a package (ecosystem:name)
    npm:lodash
    pypi:requests

    # Suppress a CVE only for a specific package
    CVE-2024-1234:npm:express

The ignore file is loaded from the current working directory by default,
or from a path specified via ``--ignore-file``.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

_CVE_RE = re.compile(r"^(CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})$", re.IGNORECASE)


class IgnoreRules:
    """Parsed suppression rules from a ``.agent-bom-ignore`` file."""

    __slots__ = ("_cve_ids", "_packages", "_cve_package_pairs")

    def __init__(self) -> None:
        self._cve_ids: set[str] = set()
        self._packages: set[str] = set()  # "ecosystem:name"
        self._cve_package_pairs: set[str] = set()  # "CVE:ecosystem:name"

    @property
    def is_empty(self) -> bool:
        return not (self._cve_ids or self._packages or self._cve_package_pairs)

    @property
    def rule_count(self) -> int:
        return len(self._cve_ids) + len(self._packages) + len(self._cve_package_pairs)

    def should_ignore_vuln(self, vuln_id: str, ecosystem: str, package_name: str) -> bool:
        """Check if a vulnerability should be suppressed."""
        vid = vuln_id.upper()

        # Global CVE suppression
        if vid in self._cve_ids:
            return True

        # Global package suppression
        pkg_key = f"{ecosystem.lower()}:{package_name.lower()}"
        if pkg_key in self._packages:
            return True

        # CVE + package pair suppression
        pair_key = f"{vid}:{pkg_key}"
        if pair_key in self._cve_package_pairs:
            return True

        return False

    def add_cve(self, cve_id: str) -> None:
        self._cve_ids.add(cve_id.upper())

    def add_package(self, ecosystem: str, name: str) -> None:
        self._packages.add(f"{ecosystem.lower()}:{name.lower()}")

    def add_cve_package(self, cve_id: str, ecosystem: str, name: str) -> None:
        self._cve_package_pairs.add(f"{cve_id.upper()}:{ecosystem.lower()}:{name.lower()}")


def load_ignore_file(path: Path | None = None) -> IgnoreRules:
    """Load and parse an ignore file.  Returns empty rules if file not found."""
    rules = IgnoreRules()

    if path is None:
        path = Path.cwd() / ".agent-bom-ignore"

    if not path.is_file():
        return rules

    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        logger.warning("Could not read ignore file %s: %s", path, exc)
        return rules

    for lineno, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split(":")
        if len(parts) == 1:
            # Bare CVE/GHSA ID
            if _CVE_RE.match(parts[0]):
                rules.add_cve(parts[0])
            else:
                logger.warning("Ignoring unrecognised rule at %s:%d: %s", path, lineno, line)
        elif len(parts) == 2:
            # ecosystem:package
            rules.add_package(parts[0], parts[1])
        elif len(parts) == 3:
            # CVE:ecosystem:package
            if _CVE_RE.match(parts[0]):
                rules.add_cve_package(parts[0], parts[1], parts[2])
            else:
                logger.warning("Ignoring unrecognised rule at %s:%d: %s", path, lineno, line)
        else:
            logger.warning("Ignoring unrecognised rule at %s:%d: %s", path, lineno, line)

    if not rules.is_empty:
        logger.info("Loaded %d suppression rule(s) from %s", rules.rule_count, path)

    return rules


def apply_ignore_rules(packages: list, rules: IgnoreRules) -> int:
    """Remove suppressed vulnerabilities from packages in-place.  Returns count removed."""
    if rules.is_empty:
        return 0

    removed = 0
    for pkg in packages:
        if not getattr(pkg, "vulnerabilities", None):
            continue
        before = len(pkg.vulnerabilities)
        pkg.vulnerabilities = [v for v in pkg.vulnerabilities if not rules.should_ignore_vuln(v.id, pkg.ecosystem, pkg.name)]
        removed += before - len(pkg.vulnerabilities)

    return removed
