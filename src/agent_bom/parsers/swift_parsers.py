"""Swift Package Manager parser — extracts packages from Package.resolved.

Parses Package.resolved (SPM lock file, v2 and v3 format) to extract
Swift package names, versions, and repository URLs.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from agent_bom.models import Package

logger = logging.getLogger(__name__)


def parse_package_resolved(directory: str | Path) -> list[Package]:
    """Parse Swift packages from Package.resolved in *directory*.

    Package.resolved v2 format::

        {
          "pins": [
            {
              "identity": "swift-argument-parser",
              "kind": "remoteSourceControl",
              "location": "https://github.com/apple/swift-argument-parser.git",
              "state": { "revision": "...", "version": "1.3.0" }
            }
          ],
          "version": 2
        }

    Package.resolved v3 format (Xcode 15.3+) uses ``originHash``
    instead of ``revision`` and adds ``packageRef``.

    Returns
    -------
    list[Package]
        Parsed packages with ecosystem ``swift``.
    """
    # Check both root and .package/ locations
    candidates = [
        Path(directory) / "Package.resolved",
        Path(directory) / ".package.resolved",
    ]
    resolved = None
    for candidate in candidates:
        if candidate.is_file():
            resolved = candidate
            break

    if resolved is None:
        return []

    try:
        data = json.loads(resolved.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Cannot read %s: %s", resolved, exc)
        return []

    packages: list[Package] = []
    seen: set[tuple[str, str]] = set()

    # v2 and v3 both use "pins" array at top level or under "object"
    pins = data.get("pins", [])
    if not pins and "object" in data:
        pins = data["object"].get("pins", [])

    for pin in pins:
        identity = pin.get("identity", "")
        location = pin.get("location", pin.get("repositoryURL", ""))
        state = pin.get("state", {})
        version = state.get("version") or "unknown"

        # Derive name from identity or location
        name = identity
        if not name and location:
            # Extract from URL: https://github.com/apple/swift-argument-parser.git
            name = location.rstrip("/").rsplit("/", 1)[-1]
            if name.endswith(".git"):
                name = name[:-4]

        if not name:
            continue

        key = (name.lower(), version)
        if key in seen:
            continue
        seen.add(key)

        packages.append(
            Package(
                name=name,
                version=version,
                ecosystem="swift",
                version_source="detected",
                purl=f"pkg:swift/{name}@{version}",
                is_direct=True,  # Package.resolved doesn't distinguish
                repository_url=location or None,
            ),
        )

    if packages:
        logger.info("Parsed %d packages from %s", len(packages), resolved)

    return packages


def parse_swift_packages(directory: str | Path) -> list[Package]:
    """Parse Swift packages from a project directory.

    Parameters
    ----------
    directory:
        Project root containing Package.resolved.

    Returns
    -------
    list[Package]
        All discovered Swift packages.
    """
    return parse_package_resolved(directory)
