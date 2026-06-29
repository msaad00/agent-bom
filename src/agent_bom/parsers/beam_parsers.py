"""Hex and Pub dependency parsers."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from agent_bom.models import Package

logger = logging.getLogger(__name__)

_MIX_HEX_RE = re.compile(
    r'"(?P<name>[^"]+)"\s*:\s*\{\s*:hex\s*,\s*:(?P<package>[A-Za-z0-9_.-]+)\s*,\s*"(?P<version>[^"]+)"',
    re.MULTILINE,
)


def _purl(ecosystem: str, name: str, version: str) -> str:
    return f"pkg:{ecosystem}/{name}@{version}"


def parse_hex_packages(directory: Path) -> list[Package]:
    """Parse Elixir/Erlang Hex dependencies from ``mix.lock``."""

    lockfile = directory / "mix.lock"
    if not lockfile.exists():
        return []
    try:
        text = lockfile.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:  # noqa: BLE001
        logger.debug("Could not read mix.lock at %s: %s", lockfile, exc)
        return []

    packages: list[Package] = []
    seen: set[tuple[str, str]] = set()
    for match in _MIX_HEX_RE.finditer(text):
        package = match.group("package")
        version = match.group("version")
        key = (package, version)
        if key in seen:
            continue
        seen.add(key)
        packages.append(
            Package(
                name=package,
                version=version,
                ecosystem="hex",
                purl=_purl("hex", package, version),
                is_direct=False,
                dependency_depth=1,
                dependency_scope="runtime",
                reachability_evidence="lockfile",
                version_source="detected",
            )
        )
    return packages


def _load_pubspec_lock(lockfile: Path) -> dict[str, Any]:
    try:
        import yaml

        data = yaml.safe_load(lockfile.read_text(encoding="utf-8", errors="replace"))
    except Exception as exc:  # noqa: BLE001
        logger.debug("Could not parse pubspec.lock at %s: %s", lockfile, exc)
        return {}
    return data if isinstance(data, dict) else {}


def parse_pub_packages(directory: Path) -> list[Package]:
    """Parse Dart/Flutter Pub dependencies from ``pubspec.lock``."""

    lockfile = directory / "pubspec.lock"
    if not lockfile.exists():
        return []
    data = _load_pubspec_lock(lockfile)
    raw_packages = data.get("packages")
    if not isinstance(raw_packages, dict):
        return []

    packages: list[Package] = []
    for name, metadata in sorted(raw_packages.items()):
        if not isinstance(metadata, dict):
            continue
        source = str(metadata.get("source") or "").strip().lower()
        if source and source != "hosted":
            continue
        version = str(metadata.get("version") or "").strip()
        if not version:
            continue
        dependency = str(metadata.get("dependency") or "transitive").strip().lower()
        is_direct = dependency == "direct main"
        packages.append(
            Package(
                name=str(name),
                version=version,
                ecosystem="pub",
                purl=_purl("pub", str(name), version),
                is_direct=is_direct,
                dependency_depth=0 if is_direct else 1,
                dependency_scope="runtime" if "dev" not in dependency else "dev",
                reachability_evidence="lockfile",
                version_source="detected",
            )
        )
    return packages
