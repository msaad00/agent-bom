"""Node.js ecosystem package parsers.

Parses package-lock.json, yarn.lock (v1 + Berry), pnpm-lock.yaml,
and detects packages from npx/npm commands.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from urllib.parse import quote

from agent_bom.models import MCPServer, Package

logger = logging.getLogger(__name__)


def _npm_purl(name: str, version: str) -> str:
    """Build a PURL for an npm package, correctly encoding scoped names.

    Per the PURL spec, ``@scope/name`` becomes ``pkg:npm/%40scope/name@version``.
    """
    if name.startswith("@"):
        # Encode the '@' in the scope per PURL spec
        scope, _, pkg_name = name[1:].partition("/")
        return f"pkg:npm/{quote('@' + scope, safe='')}/{pkg_name}@{version}"
    return f"pkg:npm/{name}@{version}"


def parse_npm_packages(directory: Path) -> list[Package]:
    """Parse packages from package-lock.json or node_modules."""
    packages = []

    # Try package-lock.json first (most accurate)
    lock_file = directory / "package-lock.json"
    if lock_file.exists():
        try:
            lock_data = json.loads(lock_file.read_text())
            lock_packages = lock_data.get("packages", lock_data.get("dependencies", {}))

            # Get direct dependencies from package.json
            pkg_json = directory / "package.json"
            direct_deps = set()
            if pkg_json.exists():
                pkg_data = json.loads(pkg_json.read_text())
                direct_deps = set(pkg_data.get("dependencies", {}).keys())
                direct_deps.update(pkg_data.get("devDependencies", {}).keys())

            for name, info in lock_packages.items():
                if not isinstance(info, dict):
                    continue
                # Clean package name (remove node_modules/ prefix)
                clean_name = name.replace("node_modules/", "").lstrip("/")
                if not clean_name:
                    continue

                version = info.get("version", "unknown")
                packages.append(
                    Package(
                        name=clean_name,
                        version=version,
                        ecosystem="npm",
                        purl=_npm_purl(clean_name, version),
                        is_direct=clean_name in direct_deps,
                    )
                )
        except (json.JSONDecodeError, KeyError):
            pass

    # Fallback to package.json only
    elif (directory / "package.json").exists():
        try:
            pkg_data = json.loads((directory / "package.json").read_text())
            for dep_type in ("dependencies", "devDependencies"):
                for name, version_spec in pkg_data.get(dep_type, {}).items():
                    version = version_spec.lstrip("^~>=<")
                    packages.append(
                        Package(
                            name=name,
                            version=version,
                            ecosystem="npm",
                            purl=_npm_purl(name, version),
                            is_direct=True,
                        )
                    )
        except (json.JSONDecodeError, KeyError):
            pass

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
        content = lock_file.read_text()
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

        data = yaml.safe_load(lock_file.read_text()) or {}
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
        content = bun_lock.read_text(encoding="utf-8")
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
            version = match.group(2) or "latest"
            packages.append(
                Package(
                    name=name,
                    version=version,
                    ecosystem="npm",
                    purl=_npm_purl(name, version),
                    is_direct=True,
                )
            )
            break  # First non-flag arg is the package

    return packages
