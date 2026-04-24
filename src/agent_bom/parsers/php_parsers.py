"""PHP Composer parser — extracts packages from composer.lock.

Parses composer.lock (Composer lock file) to extract PHP package names,
versions, and source metadata.  Falls back to composer.json for direct
dependencies when no lock file is present.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from agent_bom.models import Package
from agent_bom.parsers.file_limits import read_json_limited

logger = logging.getLogger(__name__)


def parse_composer_lock(directory: str | Path) -> list[Package]:
    """Parse packages from composer.lock in *directory*.

    composer.lock contains ``packages`` (runtime deps) and
    ``packages-dev`` (dev deps) arrays.  Each entry has ``name``
    and ``version`` fields.

    Returns
    -------
    list[Package]
        Parsed packages with ecosystem ``composer``.
    """
    lockfile = Path(directory) / "composer.lock"
    if not lockfile.is_file():
        return []

    try:
        data = read_json_limited(lockfile, encoding="utf-8", errors="replace")
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Cannot read %s: %s", lockfile, exc)
        return []

    # Read direct deps from composer.json for is_direct marking
    direct_names: set[str] = set()
    composer_json = Path(directory) / "composer.json"
    if composer_json.is_file():
        try:
            cj = read_json_limited(composer_json, encoding="utf-8", errors="replace")
            for section in ("require", "require-dev"):
                for name in cj.get(section, {}):
                    # Skip PHP platform reqs (php, ext-*)
                    if name == "php" or name.startswith("ext-"):
                        continue
                    direct_names.add(name.lower())
        except (OSError, json.JSONDecodeError):
            pass

    packages: list[Package] = []
    seen: set[tuple[str, str]] = set()

    for section in ("packages", "packages-dev"):
        for pkg in data.get(section, []):
            name = pkg.get("name", "")
            version = pkg.get("version", "unknown")
            if not name:
                continue

            # Composer versions often start with "v" prefix — strip it
            clean_version = version.lstrip("v") if version.startswith("v") else version

            key = (name.lower(), clean_version)
            if key in seen:
                continue
            seen.add(key)

            is_direct = name.lower() in direct_names or not direct_names

            packages.append(
                Package(
                    name=name,
                    version=clean_version,
                    ecosystem="composer",
                    version_source="detected",
                    purl=f"pkg:composer/{name}@{clean_version}",
                    is_direct=is_direct,
                ),
            )

    if packages:
        logger.info("Parsed %d packages from %s", len(packages), lockfile)

    return packages


def parse_php_packages(directory: str | Path) -> list[Package]:
    """Parse PHP packages from a project directory.

    Prefers composer.lock (exact versions) over composer.json (version specs).

    Parameters
    ----------
    directory:
        Project root containing composer.json and/or composer.lock.

    Returns
    -------
    list[Package]
        All discovered PHP packages.
    """
    packages = parse_composer_lock(directory)
    if packages:
        return packages

    # Fallback: parse composer.json for declared dependencies
    composer_json = Path(directory) / "composer.json"
    if not composer_json.is_file():
        return []

    try:
        data = read_json_limited(composer_json, encoding="utf-8", errors="replace")
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Cannot read %s: %s", composer_json, exc)
        return []

    packages = []
    seen: set[str] = set()

    for section in ("require", "require-dev"):
        for name, version_spec in data.get(section, {}).items():
            # Skip PHP platform reqs
            if name == "php" or name.startswith("ext-"):
                continue
            if name.lower() in seen:
                continue
            seen.add(name.lower())

            # Extract version from constraint (e.g., "^5.0" -> "5.0")
            import re

            version = re.sub(r"^[~^>=<|!*\s]+", "", version_spec).strip() or "unknown"
            # Take first version if OR'd: "^5.0 || ^6.0" -> "5.0"
            version = version.split("||")[0].split("|")[0].strip()
            version = re.sub(r"^[~^>=<\s]+", "", version).strip() or "unknown"

            packages.append(
                Package(
                    name=name,
                    version=version,
                    ecosystem="composer",
                    version_source="manifest",
                    purl=f"pkg:composer/{name}@{version}",
                    is_direct=True,
                ),
            )

    if packages:
        logger.info("Parsed %d packages from %s (no lock file)", len(packages), composer_json)

    return packages
