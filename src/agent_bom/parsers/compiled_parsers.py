"""Go, Maven, Cargo, and uvx package parsers.

Parses go.mod/go.sum, pom.xml, Cargo.lock, and detects packages
from uvx/uv commands.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from agent_bom.models import MCPServer, Package

logger = logging.getLogger(__name__)


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


def parse_go_workspace(directory: Path) -> list[Package]:
    """Parse go.work for workspace module paths, then parse each module's go.mod.

    Supports Go 1.18+ multi-module workspaces.  Reads ``use`` directives from
    ``go.work`` and calls :func:`parse_go_packages` for each referenced module
    directory.  Deduplicates by ``(name, version)``; direct dependencies take
    priority over indirect when the same module appears in multiple modules.

    Args:
        directory: Directory containing the ``go.work`` file.

    Returns:
        Combined list of :class:`~agent_bom.models.Package` objects from all
        workspace modules.  Returns an empty list if ``go.work`` does not exist.
    """
    go_work = directory / "go.work"
    if not go_work.exists():
        return []

    try:
        content = go_work.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    # Parse "use ./module_path" directives (single-line and block forms)
    module_dirs: list[Path] = []

    # Block-style: use ( ... )
    block_re = re.compile(r"use\s*\(([^)]+)\)", re.DOTALL)
    for block in block_re.finditer(content):
        for raw in block.group(1).splitlines():
            raw = raw.strip()
            if raw and not raw.startswith("//"):
                module_dirs.append(directory / raw)

    # Single-line: use ./path
    single_re = re.compile(r"^use\s+(\S+)", re.MULTILINE)
    for m in single_re.finditer(content):
        # Avoid double-counting entries already captured by block form
        candidate = directory / m.group(1)
        if candidate not in module_dirs:
            module_dirs.append(candidate)

    if not module_dirs:
        return []

    # Parse each module and merge; prefer direct over indirect for duplicates
    seen_direct: dict[tuple[str, str], Package] = {}
    seen_indirect: dict[tuple[str, str], Package] = {}

    for mod_dir in module_dirs:
        for pkg in parse_go_packages(mod_dir):
            key = (pkg.name, pkg.version)
            if pkg.is_direct:
                seen_direct[key] = pkg
            else:
                seen_indirect.setdefault(key, pkg)

    # Merge: direct wins over indirect
    merged: dict[tuple[str, str], Package] = {**seen_indirect, **seen_direct}
    return list(merged.values())


def parse_go_packages(directory: Path) -> list[Package]:
    """Parse packages from go.mod and go.sum.

    If a ``go.work`` workspace file is present in *directory*, delegates to
    :func:`parse_go_workspace` to handle multi-module workspaces (Go 1.18+).

    Otherwise reads go.mod to correctly distinguish direct from indirect
    (transitive) dependencies and to apply ``replace`` directives.  Falls back
    to go.sum only when go.mod is absent, marking all packages as direct.
    """
    # Workspace mode takes priority
    go_work = directory / "go.work"
    if go_work.exists():
        return parse_go_workspace(directory)

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


def _parse_pom_modules(root_dir: Path, depth: int = 0) -> list[Package]:
    """Recursively parse a Maven multi-module project.

    Reads the ``pom.xml`` at *root_dir*, collects its ``<dependency>``
    elements, then follows any ``<modules>/<module>`` child paths and recurses
    (up to 3 levels deep to guard against cycles).

    Args:
        root_dir: Directory containing a ``pom.xml``.
        depth: Current recursion depth (0 = root, max 3).

    Returns:
        Flat list of :class:`~agent_bom.models.Package` objects from this POM
        and all discovered sub-module POMs.
    """
    if depth > 3:
        return []

    import xml.etree.ElementTree as ET  # for ParseError type only

    from defusedxml.ElementTree import parse as safe_xml_parse  # B314

    pom = root_dir / "pom.xml"
    if not pom.exists():
        return []

    try:
        tree = safe_xml_parse(str(pom))
        xml_root = tree.getroot()
    except ET.ParseError as exc:
        logger.debug("Failed to parse pom.xml in %s: %s", root_dir, exc)
        return []

    # Namespace may or may not be present
    ns = ""
    if xml_root.tag.startswith("{"):
        ns = xml_root.tag.split("}")[0] + "}"

    def _find(el: "ET.Element", tag: str) -> "ET.Element | None":
        result = el.find(f"{ns}{tag}")
        return result if result is not None else el.find(tag)

    def _findall(el: "ET.Element", tag: str) -> "list[ET.Element]":
        results = el.findall(f"{ns}{tag}")
        return results if results else el.findall(tag)

    non_direct_scopes = {"test", "provided", "system"}
    packages: list[Package] = []

    for deps_el in _findall(xml_root, "dependencies"):
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

    # Recurse into sub-modules declared in <modules><module>...</module></modules>
    modules_el = _find(xml_root, "modules")
    if modules_el is not None:
        for module_el in _findall(modules_el, "module"):
            module_path = (module_el.text or "").strip()
            if not module_path:
                continue
            sub_dir = root_dir / module_path
            packages.extend(_parse_pom_modules(sub_dir, depth=depth + 1))

    return packages


def parse_maven_packages(directory: Path) -> list[Package]:
    """Parse packages from pom.xml (Maven/Java projects).

    Supports multi-module Maven projects: if the root ``pom.xml`` contains a
    ``<modules>`` section, each sub-module's ``pom.xml`` is recursively parsed
    (up to 3 levels deep).  The result is deduplicated by
    ``(groupId, artifactId)``; explicit versions are preferred over entries
    from nested modules with the same coordinates.

    Dependencies with scope ``test``, ``provided``, or ``system`` are included
    but marked ``is_direct=False`` since they are not deployed at runtime.
    Dependencies without a ``<version>`` element (version inherited via parent
    POM) are skipped — parent POM resolution requires network access.
    """
    pom = directory / "pom.xml"
    if not pom.exists():
        return []

    all_packages = _parse_pom_modules(directory, depth=0)

    # Deduplicate by (name, version) — first occurrence wins (root > submodule)
    seen: set[tuple[str, str]] = set()
    unique: list[Package] = []
    for pkg in all_packages:
        key = (pkg.name, pkg.version)
        if key not in seen:
            seen.add(key)
            unique.append(pkg)

    return unique


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
