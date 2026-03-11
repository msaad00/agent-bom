"""Compiled-language ecosystem package parsers.

Parses Go (go.mod/go.sum), Java/Maven (pom.xml), and Rust (Cargo.lock).
Also includes detect_uvx_package for Python uvx/uv command detection.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from agent_bom.models import MCPServer, Package

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Go
# ---------------------------------------------------------------------------


def _parse_go_mod_requires(
    go_mod: Path,
) -> tuple[dict[str, str], dict[str, str], dict[str, tuple[str, str]]]:
    """Parse go.mod and return (direct, indirect, replace_map).

    Returns:
        direct: {module_path: version} for direct requires
        indirect: {module_path: version} for ``// indirect`` requires
        replace_map: {old_module: (new_module, new_version)} for replace directives
    """
    direct: dict[str, str] = {}
    indirect: dict[str, str] = {}
    replace_map: dict[str, tuple[str, str]] = {}

    if not go_mod.exists():
        return direct, indirect, replace_map

    try:
        content = go_mod.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return direct, indirect, replace_map

    block_re = re.compile(r"require\s*\(([^)]+)\)", re.DOTALL)
    single_re = re.compile(r"^require\s+(\S+)\s+(\S+)(.*)", re.MULTILINE)
    replace_re = re.compile(r"^replace\s+(\S+)(?:\s+\S+)?\s+=>\s+(\S+)\s+(\S+)", re.MULTILINE)

    # Block-style: require ( ... )
    for block in block_re.finditer(content):
        for line in block.group(1).splitlines():
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            is_indirect = "// indirect" in line
            clean = line.split("//")[0].strip()
            parts = clean.split()
            if len(parts) >= 2:
                mod, ver = parts[0], parts[1]
                (indirect if is_indirect else direct)[mod] = ver

    # Single-line: require module version [// indirect]
    for m in single_re.finditer(content):
        mod, ver, rest = m.group(1), m.group(2), m.group(3)
        (indirect if "indirect" in rest else direct)[mod] = ver

    # Replace directives: replace old => new version
    for m in replace_re.finditer(content):
        old_mod, new_mod, new_ver = m.group(1), m.group(2), m.group(3)
        replace_map[old_mod] = (new_mod, new_ver)

    return direct, indirect, replace_map


def parse_go_packages(directory: Path) -> list[Package]:
    """Parse packages from go.mod and go.sum.

    Reads go.mod to correctly distinguish direct from indirect (transitive)
    dependencies and to apply ``replace`` directives.  Falls back to go.sum
    only when go.mod is absent, marking all packages as direct.
    """
    go_mod = directory / "go.mod"
    go_sum = directory / "go.sum"

    if not go_mod.exists() and not go_sum.exists():
        return []

    direct, indirect_mods, replace_map = _parse_go_mod_requires(go_mod)

    # Build combined module→(version, is_direct) map with replace applied
    all_mods: dict[str, tuple[str, bool]] = {}
    for source_map, is_direct in ((direct, True), (indirect_mods, False)):
        for mod, ver in source_map.items():
            if mod in replace_map:
                new_mod, new_ver = replace_map[mod]
                all_mods[new_mod] = (new_ver, is_direct)
            else:
                all_mods[mod] = (ver, is_direct)

    if all_mods:
        packages = []
        for mod, (ver, is_direct) in all_mods.items():
            clean_ver = ver[1:] if ver.startswith("v") else ver
            packages.append(
                Package(
                    name=mod,
                    version=clean_ver,
                    ecosystem="go",
                    purl=f"pkg:golang/{mod}@{ver}",
                    is_direct=is_direct,
                )
            )
        return packages

    # Fallback: go.sum only — all marked direct
    packages = []
    if go_sum.exists():
        seen: set[tuple[str, str]] = set()
        try:
            lines = go_sum.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return []
        for line in lines:
            parts = line.strip().split()
            if len(parts) >= 2:
                name = parts[0]
                raw_ver = parts[1].split("/")[0]  # strip /go.mod suffix
                clean_ver = raw_ver[1:] if raw_ver.startswith("v") else raw_ver
                key = (name, clean_ver)
                if key not in seen:
                    seen.add(key)
                    packages.append(
                        Package(
                            name=name,
                            version=clean_ver,
                            ecosystem="go",
                            purl=f"pkg:golang/{name}@{raw_ver}",
                            is_direct=True,
                        )
                    )
    return packages


# ---------------------------------------------------------------------------
# Maven / Java
# ---------------------------------------------------------------------------


def parse_maven_packages(directory: Path) -> list[Package]:
    """Parse packages from pom.xml (Maven/Java projects).

    Extracts ``<dependency>`` elements from the top-level ``<dependencies>``
    block.  Dependencies with scope ``test``, ``provided``, or ``system`` are
    included but marked ``is_direct=False`` since they are not deployed.
    Dependencies without a ``<version>`` element (version inherited via parent
    POM) are skipped — parent POM resolution requires network access.
    """
    import xml.etree.ElementTree as ET  # for ParseError type only

    from defusedxml.ElementTree import parse as safe_xml_parse  # B314

    pom = directory / "pom.xml"
    if not pom.exists():
        return []

    try:
        tree = safe_xml_parse(str(pom))
        root = tree.getroot()
    except ET.ParseError as exc:
        logger.debug("Failed to parse pom.xml in %s: %s", directory, exc)
        return []

    # Namespace may or may not be present
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"

    def _find(el: "ET.Element", tag: str) -> "ET.Element | None":
        result = el.find(f"{ns}{tag}")
        return result if result is not None else el.find(tag)

    def _findall(el: "ET.Element", tag: str) -> "list[ET.Element]":
        results = el.findall(f"{ns}{tag}")
        return results if results else el.findall(tag)

    non_direct_scopes = {"test", "provided", "system"}
    packages: list[Package] = []

    for deps_el in _findall(root, "dependencies"):
        for dep in _findall(deps_el, "dependency"):
            group_el = _find(dep, "groupId")
            artifact_el = _find(dep, "artifactId")
            version_el = _find(dep, "version")
            scope_el = _find(dep, "scope")

            if group_el is None or artifact_el is None:
                continue

            group_id = (group_el.text or "").strip()
            artifact_id = (artifact_el.text or "").strip()
            if not group_id or not artifact_id:
                continue

            # Skip unresolved property references and missing versions
            if version_el is None or not (version_el.text or "").strip():
                continue
            version = (version_el.text or "").strip()
            if version.startswith("${"):
                continue  # parent POM property — can't resolve statically

            scope = (scope_el.text or "compile").strip().lower() if scope_el is not None else "compile"
            is_direct = scope not in non_direct_scopes

            name = f"{group_id}:{artifact_id}"
            purl = f"pkg:maven/{group_id}/{artifact_id}@{version}"
            packages.append(
                Package(
                    name=name,
                    version=version,
                    ecosystem="maven",
                    purl=purl,
                    is_direct=is_direct,
                )
            )

    return packages


# ---------------------------------------------------------------------------
# Rust / Cargo
# ---------------------------------------------------------------------------


def parse_cargo_packages(directory: Path) -> list[Package]:
    """Parse packages from Cargo.lock."""
    packages = []
    cargo_lock = directory / "Cargo.lock"

    if cargo_lock.exists():
        current_name = None
        current_version = None
        for line in cargo_lock.read_text().splitlines():
            line = line.strip()
            if line.startswith('name = "'):
                current_name = line.split('"')[1]
            elif line.startswith('version = "') and current_name:
                current_version = line.split('"')[1]
                packages.append(
                    Package(
                        name=current_name,
                        version=current_version,
                        ecosystem="cargo",
                        purl=f"pkg:cargo/{current_name}@{current_version}",
                        is_direct=True,
                    )
                )
                current_name = None
                current_version = None

    return packages


# ---------------------------------------------------------------------------
# Command detection — uvx/uv (Python)
# ---------------------------------------------------------------------------


def detect_uvx_package(server: MCPServer) -> list[Package]:
    """Extract package info from uvx/uv commands."""
    packages: list[Package] = []
    if server.command not in ("uvx", "uv"):
        return packages

    args = server.args
    for i, arg in enumerate(args):
        if arg in ("run", "tool") and i + 1 < len(args):
            pkg_arg = args[i + 1]
            match = re.match(r"^([a-zA-Z0-9_.-]+)(?:==(.+))?$", pkg_arg)
            if match:
                name = match.group(1)
                version = match.group(2) or "latest"
                packages.append(
                    Package(
                        name=name,
                        version=version,
                        ecosystem="pypi",
                        purl=f"pkg:pypi/{name}@{version}",
                        is_direct=True,
                    )
                )
            break
        elif not arg.startswith("-") and arg not in ("run", "tool"):
            match = re.match(r"^([a-zA-Z0-9_.-]+)(?:==(.+))?$", arg)
            if match:
                name = match.group(1)
                version = match.group(2) or "latest"
                packages.append(
                    Package(
                        name=name,
                        version=version,
                        ecosystem="pypi",
                        purl=f"pkg:pypi/{name}@{version}",
                        is_direct=True,
                    )
                )
            break

    return packages
