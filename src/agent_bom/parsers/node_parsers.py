"""Node.js ecosystem package parsers.

Parses package-lock.json, yarn.lock (v1 + Berry), pnpm-lock.yaml,
and detects packages from npx/npm commands.
"""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from functools import lru_cache
from itertools import islice
from pathlib import Path
from urllib.parse import quote

from agent_bom.checksums import parse_sri
from agent_bom.coverage import record_manifest_parse_warning
from agent_bom.models import MCPServer, Package
from agent_bom.parsers.file_limits import read_json_limited, read_text_limited
from agent_bom.traversal import iter_discovery_files

logger = logging.getLogger(__name__)

_WORKSPACE_PROTOCOL_PREFIXES = ("workspace:", "file:", "link:", "portal:")
_MAX_WORKSPACE_PACKAGE_JSONS = 500


def _npm_purl(name: str, version: str) -> str:
    """Build a PURL for an npm package, correctly encoding scoped names.

    Per the PURL spec, ``@scope/name`` becomes ``pkg:npm/%40scope/name@version``.
    """
    if name.startswith("@"):
        # Encode the '@' in the scope per PURL spec
        scope, _, pkg_name = name[1:].partition("/")
        return f"pkg:npm/{quote('@' + scope, safe='')}/{pkg_name}@{version}"
    return f"pkg:npm/{name}@{version}"


def _resolve_npx_cached_version(name: str) -> tuple[str, Path] | None:
    """Return an exact package version from npm's local npx cache, if present."""
    cache_root = Path(os.environ.get("npm_config_cache") or Path.home() / ".npm")
    npx_root = cache_root / "_npx"
    if not npx_root.exists():
        return None

    matches: list[tuple[float, str, Path]] = []
    for node_modules in list(npx_root.glob("*/node_modules"))[:200]:
        pkg_json = node_modules.joinpath(*name.split("/"), "package.json")
        if not pkg_json.exists():
            continue
        try:
            data = read_json_limited(pkg_json)
            version = str(data.get("version") or "").strip()
            if version:
                matches.append((pkg_json.stat().st_mtime, version, pkg_json))
        except Exception as exc:
            logger.debug("Failed to inspect npx cache package metadata at %s: %s", pkg_json, exc)
    if not matches:
        return None
    _, version, path = max(matches, key=lambda item: item[0])
    return version, path


def _coerce_workspace_patterns(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, dict):
        packages = value.get("packages")
        if isinstance(packages, list):
            return [str(item).strip() for item in packages if str(item).strip()]
    return []


def _workspace_root_for(directory: Path) -> Path | None:
    for candidate in (directory, *directory.parents):
        if (candidate / "pnpm-workspace.yaml").exists():
            return candidate
        pkg_json = candidate / "package.json"
        if pkg_json.exists():
            try:
                data = read_json_limited(pkg_json)
            except Exception:
                continue
            if _coerce_workspace_patterns(data.get("workspaces")):
                return candidate
    return None


@lru_cache(maxsize=128)
def _workspace_package_versions(root: str) -> dict[str, str]:
    workspace_root = Path(root)
    patterns: list[str] = []

    pnpm_workspace = workspace_root / "pnpm-workspace.yaml"
    if pnpm_workspace.exists():
        try:
            import yaml

            data = yaml.safe_load(read_text_limited(pnpm_workspace)) or {}
            if isinstance(data, dict):
                packages = data.get("packages")
                if isinstance(packages, list):
                    patterns.extend(str(item).strip() for item in packages if str(item).strip())
        except Exception as exc:
            logger.debug("Failed to parse pnpm workspace at %s: %s", pnpm_workspace, exc)

    root_pkg_json = workspace_root / "package.json"
    if root_pkg_json.exists():
        try:
            data = read_json_limited(root_pkg_json)
            patterns.extend(_coerce_workspace_patterns(data.get("workspaces")))
        except Exception as exc:
            logger.debug("Failed to inspect npm workspace package.json at %s: %s", root_pkg_json, exc)

    versions: dict[str, str] = {}
    seen_dirs: set[Path] = set()
    for pattern in dict.fromkeys(patterns):
        if pattern.startswith("!"):
            continue

        package_jsons: list[Path] = []
        if "**" in pattern:
            recursive_suffix = "/**"
            if pattern.endswith(recursive_suffix) and pattern.count("**") == 1:
                base = workspace_root / pattern[: -len(recursive_suffix)].rstrip("/")
                if base.is_dir():
                    package_jsons.extend(
                        islice(
                            (pkg_json for pkg_json in iter_discovery_files(base) if pkg_json.name == "package.json"),
                            _MAX_WORKSPACE_PACKAGE_JSONS,
                        )
                    )
            else:
                logger.debug("Skipping unsupported recursive workspace pattern %s in %s", pattern, workspace_root)
                continue
        else:
            package_jsons.extend(pkg_dir / "package.json" for pkg_dir in workspace_root.glob(pattern) if pkg_dir.is_dir())

        for pkg_json in package_jsons[:_MAX_WORKSPACE_PACKAGE_JSONS]:
            pkg_dir = pkg_json.parent
            if "node_modules" in pkg_dir.parts or ".git" in pkg_dir.parts or pkg_dir in seen_dirs:
                continue
            seen_dirs.add(pkg_dir)
            if not pkg_json.exists():
                continue
            try:
                data = read_json_limited(pkg_json)
            except Exception as exc:
                logger.debug("Failed to inspect workspace package %s: %s", pkg_json, exc)
                continue
            name = str(data.get("name") or "").strip()
            version = str(data.get("version") or "").strip()
            if name and version:
                versions[name] = version
    return versions


def _resolve_workspace_dependency(directory: Path, name: str, version_spec: object) -> tuple[str, str] | None:
    spec = str(version_spec or "").strip()
    root = _workspace_root_for(directory)
    if root is None:
        return None
    workspace_versions = _workspace_package_versions(str(root))
    version = workspace_versions.get(name)
    if not version:
        return None
    if spec.startswith(_WORKSPACE_PROTOCOL_PREFIXES) or spec in {"*", ""}:
        return version, spec
    return None


_DEPENDENCY_SECTION_SCOPES: tuple[tuple[str, str], ...] = (
    ("dependencies", "runtime"),
    ("optionalDependencies", "optional"),
    ("peerDependencies", "peer"),
    ("devDependencies", "dev"),
)


def _npm_lock_entry_name(lock_path: str) -> str:
    """Package name for a lockfile install path.

    ``node_modules/b/node_modules/shared`` installs *shared*, not
    ``b/shared`` — a blanket ``replace("node_modules/", "")`` mangled every
    nested (version-conflicting) install into a name no advisory feed knows.
    """
    marker = "node_modules/"
    idx = lock_path.rfind(marker)
    if idx >= 0:
        return lock_path[idx + len(marker) :]
    return lock_path.lstrip("/")


def _npm_resolve_install_path(entries: dict, from_path: str, dep_name: str) -> str | None:
    """Resolve ``dep_name`` from ``from_path`` the way node does.

    Node walks up the enclosing ``node_modules`` directories and takes the first
    copy it finds, so a nested install shadows the hoisted one for its own
    subtree. Reproducing that is what makes the introducing path correct rather
    than merely plausible.
    """
    prefix = from_path
    while True:
        candidate = f"{prefix}/node_modules/{dep_name}" if prefix else f"node_modules/{dep_name}"
        if candidate in entries:
            return candidate
        if not prefix:
            return None
        idx = prefix.rfind("/node_modules/")
        prefix = prefix[:idx] if idx >= 0 else ""


def _npm_entry_edges(info: dict) -> list[tuple[str, str]]:
    edges: list[tuple[str, str]] = []
    for section, scope in _DEPENDENCY_SECTION_SCOPES:
        declared = info.get(section)
        if not isinstance(declared, dict):
            continue
        edges.extend((str(dep_name), scope) for dep_name in declared)
    return edges


def _npm_introducing_paths(entries: dict, root_edges: list[tuple[str, str]]) -> dict[str, tuple[int, str | None, str]]:
    """Walk the lockfile's dependency edges from the root.

    Returns ``{install_path: (depth, parent_name, scope)}``. Breadth-first, so
    the first (shortest) path to a package wins — that is the one an engineer
    would act on. Runtime edges are enumerated before dev edges at every node,
    so a package reachable both ways is reported as runtime.
    """
    resolved: dict[str, tuple[int, str | None, str]] = {}
    queue: list[tuple[str, int, str | None, str]] = []

    for dep_name, scope in root_edges:
        target = _npm_resolve_install_path(entries, "", dep_name)
        if target is not None and target not in resolved:
            resolved[target] = (0, None, scope)
            queue.append((target, 0, None, scope))

    head = 0
    while head < len(queue):
        path, depth, _parent, scope = queue[head]
        head += 1
        info = entries.get(path) or {}
        if info.get("link") and isinstance(info.get("resolved"), str):
            # Workspace symlink: the real dependency edges live at the target.
            info = entries.get(info["resolved"]) or info
        parent_name = _npm_lock_entry_name(path)
        for dep_name, edge_scope in _npm_entry_edges(info):
            target = _npm_resolve_install_path(entries, path, dep_name)
            if target is None or target in resolved:
                continue  # already reached by a shorter path, or not installed
            child_scope = "dev" if scope == "dev" else edge_scope
            resolved[target] = (depth + 1, parent_name, child_scope)
            queue.append((target, depth + 1, parent_name, child_scope))
    return resolved


def _npm_v1_introducing_paths(entries: dict, root_names: list[tuple[str, str]]) -> dict[str, tuple[int, str | None, str]]:
    """Same walk for a lockfileVersion 1 tree, whose edges live in ``requires``."""
    resolved: dict[str, tuple[int, str | None, str]] = {}
    queue: list[tuple[str, int, str | None, str]] = []
    for name, scope in root_names:
        if name in entries and name not in resolved:
            resolved[name] = (0, None, scope)
            queue.append((name, 0, None, scope))

    head = 0
    while head < len(queue):
        name, depth, _parent, scope = queue[head]
        head += 1
        requires = (entries.get(name) or {}).get("requires")
        if not isinstance(requires, dict):
            continue
        for dep_name in requires:
            if dep_name not in entries or dep_name in resolved:
                continue
            resolved[dep_name] = (depth + 1, name, scope)
            queue.append((dep_name, depth + 1, name, scope))
    return resolved


def parse_npm_packages(directory: Path) -> list[Package]:
    """Parse packages from package-lock.json or node_modules."""
    packages = []

    # Try package-lock.json first (most accurate)
    lock_file = directory / "package-lock.json"
    if lock_file.exists():
        try:
            lock_data = read_json_limited(lock_file)
            has_packages_map = isinstance(lock_data.get("packages"), dict)
            lock_packages = lock_data.get("packages", lock_data.get("dependencies", {}))

            # Get direct dependencies from package.json
            pkg_json = directory / "package.json"
            direct_deps = set()
            manifest_edges: list[tuple[str, str]] = []
            if pkg_json.exists():
                pkg_data = read_json_limited(pkg_json)
                direct_deps = set(pkg_data.get("dependencies", {}).keys())
                direct_deps.update(pkg_data.get("devDependencies", {}).keys())
                manifest_edges = _npm_entry_edges(pkg_data)

            # Reconstruct which dependency introduced each transitive package.
            # Without it a lockfile finding reads "qs is vulnerable" and cannot
            # say "because express depends on it" — the actionable half.
            if has_packages_map:
                root_edges = _npm_entry_edges(lock_packages.get("", {}) or {}) or manifest_edges
                introduced_by = _npm_introducing_paths(lock_packages, root_edges)
            else:
                introduced_by = _npm_v1_introducing_paths(lock_packages, manifest_edges)

            for name, info in lock_packages.items():
                if not isinstance(info, dict):
                    continue
                clean_name = _npm_lock_entry_name(name)
                if not clean_name:
                    continue

                version = info.get("version", "unknown")
                checksums = parse_sri(str(info.get("integrity") or ""))
                depth, parent_package, scope = introduced_by.get(name, (0, None, "runtime"))
                packages.append(
                    Package(
                        name=clean_name,
                        version=version,
                        ecosystem="npm",
                        purl=_npm_purl(clean_name, version),
                        is_direct=(depth == 0 and name in introduced_by) or clean_name in direct_deps,
                        parent_package=parent_package,
                        dependency_depth=depth,
                        dependency_scope=scope,
                        checksums=checksums,
                    )
                )
        # OSError covers unreadable/oversize manifests (PermissionError and
        # ManifestTooLargeError, which subclasses OSError); UnicodeDecodeError
        # covers a binary/non-UTF8 manifest. Letting either escape aborted the
        # whole scan with no artifact written, so one bad file in a repo could
        # deny the scanner. Degrade with a named coverage warning instead.
        except (json.JSONDecodeError, KeyError, OSError, UnicodeDecodeError) as exc:
            logger.debug("Failed to parse package-lock.json in %s: %s", directory, exc)
            record_manifest_parse_warning(
                ecosystem="npm",
                path=str(lock_file),
                detail=f"package-lock.json could not be read or parsed ({exc}); npm dependencies were not scanned",
            )

    # Fallback to package.json only
    elif (directory / "package.json").exists():
        try:
            pkg_data = read_json_limited(directory / "package.json")
            for dep_type in ("dependencies", "devDependencies"):
                for name, version_spec in pkg_data.get(dep_type, {}).items():
                    declared_version = str(version_spec)
                    workspace_resolution = _resolve_workspace_dependency(directory, name, declared_version)
                    version_source = "manifest"
                    resolved_version = None
                    version_confidence = None
                    version_evidence: list[dict] = []
                    if workspace_resolution:
                        version, declared_version = workspace_resolution
                        version_source = "workspace"
                        resolved_version = version
                        version_confidence = "workspace_manifest"
                        version_evidence.append(
                            {
                                "source": "workspace_manifest",
                                "declared_version": declared_version,
                                "resolved_version": version,
                            }
                        )
                    else:
                        version = declared_version.lstrip("^~>=< ")
                        # Validate: must look like a semver (at least major.minor.patch)
                        # Otherwise mark as "latest" for resolver to handle
                        if not re.match(r"^\d+\.\d+\.\d+", version):
                            version = "latest"
                    packages.append(
                        Package(
                            name=name,
                            version=version,
                            ecosystem="npm",
                            purl=_npm_purl(name, version),
                            is_direct=True,
                            reachability_evidence="workspace_manifest" if workspace_resolution else "declaration_only",
                            version_source=version_source,
                            declared_version=declared_version,
                            resolved_version=resolved_version,
                            version_confidence=version_confidence,
                            version_evidence=version_evidence,
                        )
                    )
        # Same graceful-degradation contract as the package-lock.json branch
        # above: an unreadable, oversize, or non-UTF8 manifest is a coverage
        # gap to report, never a scan-aborting exception.
        except (json.JSONDecodeError, KeyError, OSError, UnicodeDecodeError) as exc:
            logger.debug("Failed to parse package.json in %s: %s", directory, exc)
            record_manifest_parse_warning(
                ecosystem="npm",
                path=str(directory / "package.json"),
                detail=f"package.json could not be read or parsed ({exc}); npm dependencies were not scanned",
            )

    return packages


def parse_yarn_lock(directory: Path) -> list[Package]:
    """Parse packages from yarn.lock (Classic v1 and Berry v2/v3 formats).

    yarn.lock v1 (Classic) uses a block format::

        "name@version":
          version "resolved_version"

    yarn.lock v2+ (Berry) uses a YAML-like format with ``__metadata``
    and entries like::

        "name@npm:version":
          version: "resolved_version"

    We handle both by scanning for version lines after each package header.
    """
    lock_file = directory / "yarn.lock"
    if not lock_file.exists():
        return []

    packages: list[Package] = []
    try:
        content = read_text_limited(lock_file)
        # Berry v2+ detection
        is_berry = "__metadata:" in content

        if is_berry:
            # Berry format: entries separated by blank lines, "version: x.y.z"
            current_names: list[str] = []
            seen: set[tuple[str, str]] = set()
            for line in content.splitlines():
                stripped = line.strip()
                # Package header lines: '"name@npm:version, name@npm:version":'
                if stripped.startswith('"') and stripped.endswith(":") and "@npm:" in stripped:
                    current_names = []
                    header = stripped.rstrip(":")
                    for part in header.strip('"').split(", "):
                        m = re.match(r'^"?(@?[^@]+)@', part)
                        if m:
                            current_names.append(m.group(1))
                elif stripped.startswith("version:") and current_names:
                    version = stripped.split(":", 1)[1].strip().strip('"')
                    for name in current_names:
                        key = (name, version)
                        if key not in seen:
                            seen.add(key)
                            packages.append(
                                Package(
                                    name=name,
                                    version=version,
                                    ecosystem="npm",
                                    purl=f"pkg:npm/{name}@{version}",
                                    is_direct=False,
                                )
                            )
                    current_names = []
        else:
            # Classic v1: '"name@range, name@range":\n  version "x.y.z"'
            seen = set()  # type: ignore[no-redef]
            current_names = []  # type: ignore[no-redef]
            for line in content.splitlines():
                stripped = line.strip()
                # Header: one or more "name@range" entries followed by ":"
                if stripped.endswith(":") and not stripped.startswith("#"):
                    current_names = []
                    header = stripped.rstrip(":")
                    for part in header.strip('"').split(", "):
                        m = re.match(r'^"?(@?[^@"]+)@', part.strip('"'))
                        if m:
                            current_names.append(m.group(1))
                elif stripped.startswith("version ") and current_names:
                    version = stripped.split(" ", 1)[1].strip().strip('"')
                    for name in current_names:
                        key = (name, version)
                        if key not in seen:
                            seen.add(key)
                            packages.append(
                                Package(
                                    name=name,
                                    version=version,
                                    ecosystem="npm",
                                    purl=f"pkg:npm/{name}@{version}",
                                    is_direct=False,
                                )
                            )
                    current_names = []
    except Exception as exc:
        logger.debug("Failed to parse yarn.lock at %s: %s", lock_file, exc)
        record_manifest_parse_warning(
            ecosystem="npm",
            path=str(lock_file),
            detail="yarn.lock could not be read or parsed; Yarn dependencies were not scanned",
        )

    return packages


def parse_pnpm_lock(directory: Path) -> list[Package]:
    """Parse packages from pnpm-lock.yaml.

    pnpm-lock.yaml v6+ uses a ``packages`` map with keys like
    ``/name@version`` or ``name@version``.  Earlier versions use
    ``/name/version``.  We support both.
    """
    lock_file = directory / "pnpm-lock.yaml"
    if not lock_file.exists():
        return []

    packages: list[Package] = []
    try:
        try:
            import yaml
        except ImportError:
            logger.debug("PyYAML not installed; skipping pnpm-lock.yaml parsing")
            return []

        data = yaml.safe_load(read_text_limited(lock_file)) or {}
        pkg_map = data.get("packages", {})
        for key in pkg_map:
            # key formats (pnpm v6): "/name@version", "/@scope/name@version"
            # key formats (pnpm v9): "name@version", "@scope/name@version"
            key = key.lstrip("/")
            # Handle scoped packages: @scope/name@version
            m = re.match(r"^(@[^/]+/[^@]+)@([^()\s]+)", key)
            if not m:
                # Unscoped: name@version
                m = re.match(r"^([^@][^@]*)@([^()\s]+)", key)
            if not m:
                # Fallback: name/version (old pnpm)
                parts = key.rsplit("/", 1)
                if len(parts) == 2:
                    name, version = parts[0], parts[1]
                else:
                    continue
            else:
                name, version = m.group(1), m.group(2)
            name = name.strip()
            version = version.strip()
            if name and version:
                packages.append(
                    Package(
                        name=name,
                        version=version,
                        ecosystem="npm",
                        purl=f"pkg:npm/{name}@{version}",
                        is_direct=False,  # pnpm lock is flat; all entries are resolved
                    )
                )
    except Exception as exc:
        logger.debug("Failed to parse pnpm-lock.yaml at %s: %s", lock_file, exc)
        record_manifest_parse_warning(
            ecosystem="npm",
            path=str(lock_file),
            detail="pnpm-lock.yaml could not be read or parsed; pnpm dependencies were not scanned",
        )

    return packages


def parse_bun_packages(directory: Path) -> list[Package]:
    """Parse packages from bun.lock (text format, Bun 1.2+) or fall back gracefully.

    Bun uses a binary ``bun.lockb`` that cannot be read without the Bun
    runtime.  Bun 1.2+ also writes a text ``bun.lock`` (YAML-like format)
    which we prefer.  If only the binary lock exists we log a debug message
    and return an empty list rather than crashing.

    ``bun.lock`` format::

        lockfileVersion: 0
        packages:
          "react@19.0.0":
            resolution: {integrity: sha512-...}
        dependencies:
          "react": "19.0.0"
        devDependencies:
          "@types/node": "22.0.0"

    We parse the ``dependencies`` and ``devDependencies`` sections by looking
    for quoted ``"name": "version"`` pairs.  The ``packages:`` metadata block
    is skipped.
    """
    bun_lock = directory / "bun.lock"
    bun_lockb = directory / "bun.lockb"

    if not bun_lock.exists():
        if bun_lockb.exists():
            logger.debug(
                "bun.lockb found at %s but binary format is unreadable; run 'bun install' with Bun 1.2+ to generate bun.lock",
                bun_lockb,
            )
        return []

    packages: list[Package] = []
    try:
        content = read_text_limited(bun_lock, encoding="utf-8")
        # State machine: track which top-level section we are in.
        # We only care about "dependencies" and "devDependencies".
        deps_sections = {"dependencies:", "devDependencies:"}
        skip_sections = {"packages:", "patchedDependencies:", "workspaces:"}
        in_deps = False

        for raw_line in content.splitlines():
            stripped = raw_line.strip()

            # Detect section headers (no leading whitespace on section keys)
            if not raw_line.startswith(" ") and not raw_line.startswith("\t"):
                in_deps = stripped in deps_sections
                if stripped in skip_sections:
                    in_deps = False
                continue

            if not in_deps:
                continue

            # Match: "name": "version" — both quoted
            bun_entry = re.match(r'^\s*"([^"]+)":\s*"([^"]+)"\s*$', raw_line)
            if bun_entry:
                pkg_name = bun_entry.group(1)
                pkg_version = bun_entry.group(2)
                packages.append(
                    Package(
                        name=pkg_name,
                        version=pkg_version,
                        ecosystem="npm",
                        purl=_npm_purl(pkg_name, pkg_version),
                        is_direct=True,
                    )
                )
    except Exception as exc:
        logger.debug("Failed to parse bun.lock at %s: %s", bun_lock, exc)
        record_manifest_parse_warning(
            ecosystem="npm",
            path=str(bun_lock),
            detail="bun.lock could not be read or parsed; Bun dependencies were not scanned",
        )

    return packages


def detect_npx_package(server: MCPServer) -> list[Package]:
    """Extract package info from npx/npm commands."""
    packages: list[Package] = []
    if server.command not in ("npx", "npm"):
        return packages

    for arg in server.args:
        if arg.startswith("-"):
            continue
        # Parse @scope/package@version or package@version
        match = re.match(r"^(@?[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)?)(?:@(.+))?$", arg)
        if match:
            name = match.group(1)
            pinned_version = match.group(2)
            declared_version = pinned_version or "latest"
            is_floating = declared_version in {"latest", "*"}
            cached = _resolve_npx_cached_version(name) if is_floating else None
            version = cached[0] if cached else declared_version
            pkg = Package(
                name=name,
                version=version,
                ecosystem="npm",
                purl=_npm_purl(name, version),
                is_direct=True,
            )
            pkg.declared_version = declared_version
            if not is_floating:
                pkg.resolved_version = version
                pkg.version_source = "command_pin"
                pkg.version_confidence = "exact"
                pkg.version_evidence = [{"type": "command_pin", "source_file": server.config_path or "", "parser": "npx"}]
            elif cached:
                _, evidence_path = cached
                pkg.resolved_version = version
                pkg.version_source = "tool_cache"
                pkg.version_confidence = "high"
                pkg.version_resolved_at = datetime.now(timezone.utc).isoformat()
                pkg.version_evidence = [{"type": "tool_cache", "path": str(evidence_path), "parser": "npx"}]
                pkg.floating_reference = True
                pkg.floating_reference_reason = "npx command omitted an explicit package version"
            else:
                pkg.resolved_from_registry = True
                pkg.version_source = "registry_fallback"
                pkg.registry_version = declared_version
                pkg.floating_reference = True
                pkg.floating_reference_reason = "npx command omitted an explicit package version"
            packages.append(pkg)
            break  # First non-flag arg is the package

    return packages
