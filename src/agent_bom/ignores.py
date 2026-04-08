"""Structured ignore/allowlist support for agent-bom.

Reads ``.agent-bom-ignore.yaml`` (or a path specified via ``--ignore-file``)
and filters blast-radius findings before output.

Ignore file format::

    ignores:
      - id: CVE-2024-1234
        reason: "Not exploitable — no user input reaches affected path"
        expires: 2026-06-01

      - package: requests@<2.32.0
        reason: "Pinned, upgrade scheduled Q3"
        expires: 2026-09-01

      - package: lodash
        reason: "All lodash findings accepted — no internet-facing exposure"

      - type: credential-exposure
        path: "tests/**"
        reason: "Test fixtures with dummy credentials"

Fields
------
- ``id``      : CVE or OSV ID (exact match, case-insensitive).
- ``package`` : Package name, optionally with ``@<version-spec>``.
                A bare name matches all versions.  A ``@<spec>`` uses
                simple prefix comparison (``<``, ``<=``, ``==``).
- ``type``    : Finding type keyword (e.g. ``credential-exposure``).
- ``path``    : Glob matched against the config path of the discovering agent.
- ``expires`` : ISO date (``YYYY-MM-DD``).  Entry is ignored after this date.
- ``reason``  : Free-text (required for auditability).
"""

from __future__ import annotations

import fnmatch
import logging
from datetime import date, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agent_bom.models import BlastRadius

logger = logging.getLogger(__name__)

_DEFAULT_IGNORE_FILE = ".agent-bom-ignore.yaml"


def load_ignore_file(path: str | Path | None = None) -> list[dict[str, Any]]:
    """Load and parse an ignore file.  Returns empty list if file not found."""
    target = Path(path) if path else Path(_DEFAULT_IGNORE_FILE)
    if not target.exists():
        return []
    try:
        import yaml  # type: ignore[import]
    except ImportError:
        try:
            import tomllib as _t  # noqa: F401
        except ImportError:
            pass
        # Fall back to a minimal YAML-subset parser (key: value lines only)
        return _parse_minimal_yaml(target)

    try:
        with target.open() as fh:
            data = yaml.safe_load(fh) or {}
        entries = data.get("ignores", [])
        if not isinstance(entries, list):
            logger.warning("agent-bom-ignore: 'ignores' must be a list — skipping file")
            return []
        return entries
    except Exception as exc:
        logger.warning("agent-bom-ignore: failed to parse %s: %s", target, exc)
        return []


def _parse_minimal_yaml(path: Path) -> list[dict[str, Any]]:
    """Fallback parser for simple ignore files when PyYAML is not installed."""
    try:
        import json

        text = path.read_text()
        # Try JSON as last resort
        if text.strip().startswith("{") or text.strip().startswith("["):
            data = json.loads(text)
            return data.get("ignores", data) if isinstance(data, dict) else data
    except Exception:
        pass
    logger.warning("agent-bom-ignore: PyYAML not installed and file is not JSON — ignore file skipped. Install PyYAML: pip install pyyaml")
    return []


def _entry_is_expired(entry: dict[str, Any]) -> bool:
    """Return True if the entry has an expires field in the past."""
    expires = entry.get("expires")
    if not expires:
        return False
    try:
        exp_date = datetime.strptime(str(expires), "%Y-%m-%d").date()
        return exp_date < date.today()
    except ValueError:
        logger.warning("agent-bom-ignore: invalid expires date '%s' — treating as non-expired", expires)
        return False


def _matches_blast_radius(entry: dict[str, Any], br: "BlastRadius") -> bool:
    """Return True if this ignore entry covers the given blast-radius finding."""
    vuln = br.vulnerability
    pkg = br.package

    # CVE/OSV ID match
    cve_id = entry.get("id")
    if cve_id and vuln.id.upper() != str(cve_id).upper():
        return False
    if cve_id:
        return True  # ID match is sufficient

    # Package name / version match
    pkg_spec = entry.get("package")
    if pkg_spec:
        pkg_spec = str(pkg_spec)
        if "@" in pkg_spec:
            name_part, ver_spec = pkg_spec.split("@", 1)
        else:
            name_part, ver_spec = pkg_spec, None

        from agent_bom.package_utils import normalize_package_name

        if normalize_package_name(pkg.name) != normalize_package_name(name_part):
            return False
        if ver_spec and not _version_matches(pkg.version or "", ver_spec):
            return False

    # Finding type match (e.g. "credential-exposure")
    finding_type = entry.get("type")
    if finding_type:
        if not _matches_finding_type(finding_type, br):
            return False

    # Path-scoped match
    path_glob = entry.get("path")
    if path_glob:
        agent_paths = [a.config_path or "" for a in br.affected_agents]
        if not any(fnmatch.fnmatch(p, path_glob) for p in agent_paths):
            return False

    # If we got here with at least one filter key set, it matched
    return bool(pkg_spec or finding_type or path_glob)


def _version_matches(version: str, spec: str) -> bool:
    """Simple version spec matching: <, <=, ==, >=, >."""
    spec = spec.strip()
    for op in ("<=", ">=", "==", "<", ">"):
        if spec.startswith(op):
            target = spec[len(op) :].strip()
            try:
                from packaging.version import Version

                v = Version(version)
                t = Version(target)
                if op == "<":
                    return v < t
                if op == "<=":
                    return v <= t
                if op == "==":
                    return v == t
                if op == ">":
                    return v > t
                if op == ">=":
                    return v >= t
            except Exception:
                # Fall back to string comparison
                if op == "==":
                    return version == target
    return version == spec


def _matches_finding_type(finding_type: str, br: "BlastRadius") -> bool:
    ft = finding_type.lower().replace("-", "_").replace(" ", "_")
    if ft == "credential_exposure":
        return bool(br.exposed_credentials)
    return False


def apply_ignores(
    blast_radii: list["BlastRadius"],
    ignore_entries: list[dict[str, Any]],
) -> tuple[list["BlastRadius"], int]:
    """Filter blast radii against ignore entries.

    Returns ``(filtered_list, suppressed_count)``.
    Expired entries are skipped with a warning.
    """
    if not ignore_entries:
        return blast_radii, 0

    active_entries: list[dict[str, Any]] = []
    for entry in ignore_entries:
        if _entry_is_expired(entry):
            cve = entry.get("id") or entry.get("package") or entry.get("type", "?")
            logger.warning("agent-bom-ignore: entry for '%s' expired on %s — re-surfacing", cve, entry["expires"])
        else:
            active_entries.append(entry)

    filtered: list["BlastRadius"] = []
    suppressed = 0
    for br in blast_radii:
        suppressed_by = next((e for e in active_entries if _matches_blast_radius(e, br)), None)
        if suppressed_by:
            reason = suppressed_by.get("reason", "(no reason given)")
            logger.info(
                "agent-bom-ignore: suppressed %s in %s@%s — %s",
                br.vulnerability.id,
                br.package.name,
                br.package.version,
                reason,
            )
            suppressed += 1
        else:
            filtered.append(br)

    return filtered, suppressed
