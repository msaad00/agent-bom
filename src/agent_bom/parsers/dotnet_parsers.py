"""NuGet (.NET) package parsers.

Parses packages.lock.json (preferred — resolved, pinned versions) and
.csproj files (declared PackageReference elements, no resolved versions).

Relevant for .NET AI workloads using Semantic Kernel, ML.NET, and similar.
"""

from __future__ import annotations

import json
import logging
import xml.etree.ElementTree as ET
from pathlib import Path

from agent_bom.models import Package

logger = logging.getLogger(__name__)


def parse_nuget_packages(directory: Path) -> list[Package]:
    """Parse NuGet packages from packages.lock.json or .csproj files.

    Priority order:
    1. ``packages.lock.json`` — resolved, pinned versions per target framework.
    2. ``*.csproj`` — declared ``<PackageReference>`` elements (version may be
       a range or unpinned).

    packages.lock.json format::

        {
          "version": 1,
          "dependencies": {
            "net8.0": {
              "Microsoft.SemanticKernel": {
                "type": "Direct",
                "resolved": "1.14.1"
              },
              "Newtonsoft.Json": {
                "type": "Transitive",
                "resolved": "13.0.3"
              }
            }
          }
        }

    .csproj format::

        <ItemGroup>
          <PackageReference Include="Microsoft.SemanticKernel" Version="1.14.1" />
        </ItemGroup>
    """
    packages = _parse_nuget_lock_json(directory)
    if packages:
        return packages
    return _parse_csproj_files(directory)


def _parse_nuget_lock_json(directory: Path) -> list[Package]:
    """Parse packages from packages.lock.json."""
    lock_file = directory / "packages.lock.json"
    if not lock_file.exists():
        return []

    packages: list[Package] = []
    try:
        lock_data: dict = json.loads(lock_file.read_text(encoding="utf-8"))
        frameworks: dict = lock_data.get("dependencies", {})

        seen: set[tuple[str, str]] = set()
        for framework_deps in frameworks.values():
            if not isinstance(framework_deps, dict):
                continue
            for pkg_name, pkg_info in framework_deps.items():
                if not isinstance(pkg_info, dict):
                    continue
                resolved = pkg_info.get("resolved", "")
                if not resolved:
                    continue
                dep_type = pkg_info.get("type", "Transitive")
                key = (pkg_name, resolved)
                if key in seen:
                    continue
                seen.add(key)
                packages.append(
                    Package(
                        name=pkg_name,
                        version=resolved,
                        ecosystem="nuget",
                        purl=f"pkg:nuget/{pkg_name}@{resolved}",
                        is_direct=(dep_type == "Direct"),
                    )
                )
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        logger.debug("Failed to parse packages.lock.json at %s: %s", lock_file, exc)

    return packages


def _parse_csproj_files(directory: Path) -> list[Package]:
    """Parse PackageReference elements from all .csproj files in *directory*."""
    packages: list[Package] = []
    csproj_files = list(directory.glob("*.csproj"))
    if not csproj_files:
        return []

    seen: set[tuple[str, str]] = set()
    for csproj in csproj_files:
        try:
            tree = ET.parse(csproj)  # noqa: S314  # nosec B314
            root = tree.getroot()
            # ElementTree may or may not have namespace prefixes
            for ref in root.iter("PackageReference"):
                pkg_name = ref.get("Include", "").strip()
                pkg_version = ref.get("Version", "").strip()
                if not pkg_name or not pkg_version:
                    continue
                key = (pkg_name, pkg_version)
                if key in seen:
                    continue
                seen.add(key)
                packages.append(
                    Package(
                        name=pkg_name,
                        version=pkg_version,
                        ecosystem="nuget",
                        purl=f"pkg:nuget/{pkg_name}@{pkg_version}",
                        is_direct=True,
                    )
                )
        except ET.ParseError as exc:
            logger.debug("Failed to parse .csproj at %s: %s", csproj, exc)

    return packages
